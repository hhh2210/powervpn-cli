import Foundation

public struct VICIVersionProbeReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let mode: String
  public let success: Bool
  public let responseKeyNames: [String]
  public let trace: VICIExchangeTrace
  public let secretValuesRetained: Bool
}

public struct VICIRuntimeSmokeReport: Codable, Equatable, Sendable {
  public struct ListResult: Codable, Equatable, Sendable {
    public let eventCount: Int
    public let syntheticConnectionMatches: Int
    public let traces: [VICIExchangeTrace]
  }

  public struct ClientActions: Codable, Equatable, Sendable {
    public let socketConnection: Bool
    public let credentialRead: Bool
    public let credentialSerialized: Bool
    public let initiateCalled: Bool
    public let installCalled: Bool
    public let securityAssociationMutationRequested: Bool
    public let routeMutationRequested: Bool
    public let policyMutationRequested: Bool
    public let utunMutationRequested: Bool
  }

  public let schemaVersion: Int
  public let mode: String
  public let startedAt: String
  public let completedAt: String
  public let success: Bool
  public let syntheticProfile: String
  public let version: VICIVersionProbeReport
  public let listBeforeLoad: ListResult
  public let loadConnection: VICIExchangeTrace
  public let listAfterLoad: ListResult
  public let unloadConnection: VICIExchangeTrace
  public let listAfterUnload: ListResult
  public let clientActions: ClientActions
  public let secretValuesRetained: Bool
}

public enum VICIRuntimeProbeError: Error, Equatable, CustomStringConvertible, Sendable {
  case syntheticConnectionNotObserved(matches: Int, events: Int)
  case syntheticConnectionStillPresent(matches: Int, events: Int)

  public var description: String {
    switch self {
    case .syntheticConnectionNotObserved(let matches, let events):
      return
        "VICI synthetic connection was not observed exactly once (matches=\(matches), events=\(events))"
    case .syntheticConnectionStillPresent(let matches, let events):
      return
        "VICI synthetic connection remained after unload (matches=\(matches), events=\(events))"
    }
  }
}

public enum VICIRuntimeProbe {
  public static let syntheticConnectionName = "cp7a.synthetic.invalid"

  public static func version(
    socketPath: String,
    timeoutMilliseconds: Int = 2_000
  ) throws -> VICIVersionProbeReport {
    let session = try VICISession(
      socketPath: socketPath,
      timeoutMilliseconds: timeoutMilliseconds
    )
    defer { session.close() }
    return try version(session: session)
  }

  public static func smoke(
    socketPath: String,
    timeoutMilliseconds: Int = 2_000
  ) throws -> VICIRuntimeSmokeReport {
    let session = try VICISession(
      socketPath: socketPath,
      timeoutMilliseconds: timeoutMilliseconds
    )
    defer { session.close() }
    return try smoke(session: session)
  }

  static func version(session: VICISession) throws -> VICIVersionProbeReport {
    let result = try session.version()
    return VICIVersionProbeReport(
      schemaVersion: 1,
      mode: "value_free_vici_version",
      success: true,
      responseKeyNames: result.message.topLevelNames,
      trace: result.trace,
      secretValuesRetained: false
    )
  }

  static func smoke(session: VICISession) throws -> VICIRuntimeSmokeReport {
    let startedAt = timestamp()
    let versionReport = try version(session: session)
    let baselineList = try listConnections(session: session)
    guard baselineList.syntheticConnectionMatches == 0 else {
      throw VICIRuntimeProbeError.syntheticConnectionStillPresent(
        matches: baselineList.syntheticConnectionMatches,
        events: baselineList.eventCount
      )
    }
    var loaded = false
    do {
      let load = try session.request(command: "load-conn", message: syntheticConnection())
      loaded = true
      let loadedList = try listConnections(session: session)
      guard loadedList.syntheticConnectionMatches == 1,
        loadedList.eventCount == baselineList.eventCount + 1
      else {
        throw VICIRuntimeProbeError.syntheticConnectionNotObserved(
          matches: loadedList.syntheticConnectionMatches,
          events: loadedList.eventCount
        )
      }

      let unload = try session.request(
        command: "unload-conn",
        message: VICIMessage(elements: [
          .keyValue("name", syntheticConnectionName)
        ])
      )
      loaded = false
      let unloadedList = try listConnections(session: session)
      guard unloadedList.syntheticConnectionMatches == 0,
        unloadedList.eventCount == baselineList.eventCount
      else {
        throw VICIRuntimeProbeError.syntheticConnectionStillPresent(
          matches: unloadedList.syntheticConnectionMatches,
          events: unloadedList.eventCount
        )
      }

      return VICIRuntimeSmokeReport(
        schemaVersion: 1,
        mode: "cp7a_unprivileged_synthetic_vici_runtime",
        startedAt: startedAt,
        completedAt: timestamp(),
        success: true,
        syntheticProfile: "rfc5737_no_start_action_no_credential",
        version: versionReport,
        listBeforeLoad: baselineList,
        loadConnection: load.trace,
        listAfterLoad: loadedList,
        unloadConnection: unload.trace,
        listAfterUnload: unloadedList,
        clientActions: .init(
          socketConnection: true,
          credentialRead: false,
          credentialSerialized: false,
          initiateCalled: false,
          installCalled: false,
          securityAssociationMutationRequested: false,
          routeMutationRequested: false,
          policyMutationRequested: false,
          utunMutationRequested: false
        ),
        secretValuesRetained: false
      )
    } catch {
      if loaded {
        _ = try? session.request(
          command: "unload-conn",
          message: VICIMessage(elements: [
            .keyValue("name", syntheticConnectionName)
          ])
        )
      }
      throw error
    }
  }

  private static func listConnections(session: VICISession) throws
    -> VICIRuntimeSmokeReport.ListResult
  {
    let result = try session.streamedRequest(
      command: "list-conns",
      event: "list-conn"
    )
    return .init(
      eventCount: result.events.count,
      syntheticConnectionMatches: result.events.count {
        $0.containsTopLevelSection(named: syntheticConnectionName)
      },
      traces: result.traces
    )
  }

  private static func syntheticConnection() -> VICIMessage {
    VICIMessage(elements: [
      .section(
        name: syntheticConnectionName,
        elements: [
          .keyValue("version", "1"),
          .keyValue("aggressive", "no"),
          .list("remote_addrs", ["198.51.100.1"]),
          .list("proposals", ["aes128-sha1-modp1024"]),
          .section(
            name: "local",
            elements: [
              .keyValue("auth", "psk"),
              .keyValue("id", "client.cp7a.invalid"),
            ]
          ),
          .section(
            name: "remote",
            elements: [
              .keyValue("auth", "psk"),
              .keyValue("id", "gateway.cp7a.invalid"),
            ]
          ),
          .section(
            name: "children",
            elements: [
              .section(
                name: "resource.cp7a.invalid",
                elements: [
                  .list("local_ts", ["dynamic"]),
                  .list("remote_ts", ["203.0.113.0/24"]),
                  .list("esp_proposals", ["aes128-sha1"]),
                  .keyValue("start_action", "none"),
                ]
              )
            ]
          ),
        ]
      )
    ])
  }

  private static func timestamp() -> String {
    ISO8601DateFormatter().string(from: Date())
  }
}
