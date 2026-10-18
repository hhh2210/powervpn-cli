import Darwin
import Foundation
import PowerVPNCore
import PowerVPNPortal
import PowerVPNProduct

// No packet, identity, error description from the server, credential or Portal
// response is printed. Even VICI traces (which hash credentials) are discarded.
func report(_ stage: String, _ success: Bool) {
  FileHandle.standardOutput.write(Data("{\"stage\":\"\(stage)\",\"success\":\(success)}\n".utf8))
}

func reportCount(_ stage: String, _ count: Int) {
  FileHandle.standardOutput.write(Data("{\"stage\":\"\(stage)\",\"count\":\(count)}\n".utf8))
}

func reportSAs(_ phase: String, _ result: VICIStreamResult) -> Bool {
  reportCount(phase + "_event_count", result.events.count)
  for state in [
    "CREATED", "CONNECTING", "ESTABLISHED", "REKEYING", "DELETING", "DESTROYING", "INSTALLED",
  ] {
    reportCount(
      phase + "_state_" + state.lowercased(),
      result.events.reduce(0) { $0 + countState($1.elements, state) })
  }
  return result.events.reduce(0) { $0 + countState($1.elements, "ESTABLISHED") } == 1
}

func reportFailure(_ phase: String, _ error: Error) {
  report("failed_phase_" + phase, false)
  if let error = error as? VICISessionError {
    switch error {
    case .commandFailed: report("vici_command_failed", false)
    case .commandUnknown: report("vici_command_unknown", false)
    case .eventUnknown: report("vici_event_unknown", false)
    case .unexpectedPacket, .unexpectedEvent: report("vici_protocol_error", false)
    }
  } else if let error = error as? VICITransportError {
    if case .timeout = error {
      report("transport_timed_out", false)
    } else {
      report("transport_failed", false)
    }
  } else if let error = error as? NativeTrialMaterial.Failure {
    switch error {
    case .incomplete: report("native_material_incomplete", false)
    case .unsupported: report("native_material_unsupported", false)
    case .targetOutsideResource: report("native_target_outside_resource", false)
    case .gatewayMatchesTarget: report("native_gateway_matches_target", false)
    }
  } else if let error = error as? NativeTrialPortalBridge.Failure {
    switch error {
    case .catalog(let failure):
      report("portal_catalog_" + failure.failureClass.rawValue, false)
      if let encoded = try? JSONEncoder().encode(failure) {
        FileHandle.standardOutput.write(encoded)
        FileHandle.standardOutput.write(Data([10]))
      }
    case .selectionMissing: report("portal_selection_missing", false)
    case .selectionAmbiguous(let count): reportCount("portal_selection_ambiguous", count)
    case .snapshotIncomplete(let field):
      report("portal_snapshot_incomplete_" + (field?.rawValue ?? "unknown"), false)
    case .snapshotRejected: report("portal_snapshot_rejected", false)
    }
  } else if error is NativeCoexistFailure {
    report("coexist_guard_rejected", false)
  } else if error is CancellationError {
    report("trial_cancelled", false)
  } else {
    report("unclassified_failure", false)
  }
}

func value(_ message: VICIMessage, _ key: String) -> String? {
  for element in message.elements {
    if case .keyValue(let name, let data) = element, name == key {
      return String(data: data, encoding: .utf8)
    }
  }
  return nil
}

func countState(_ elements: [VICIElement], _ expected: String) -> Int {
  elements.reduce(0) { count, element in
    switch element {
    case .keyValue(let key, let data):
      return count + ((key == "state" && data == Data(expected.utf8)) ? 1 : 0)
    case .section(_, let children): return count + countState(children, expected)
    case .list: return count
    }
  }
}

func observeControl(_ message: VICIMessage) {
  guard let line = value(message, "msg") else { return }
  let categories = [
    ("sending packet", "packet_sent"), ("received packet", "packet_received"),
    ("NO_PROPOSAL_CHOSEN", "proposal_rejected"),
    ("AUTHENTICATION_FAILED", "authentication_rejected"),
    ("no shared key", "shared_key_not_found"), ("retransmit", "retransmit"),
    ("giving up", "retransmits_exhausted"),
    ("no matching peer config", "peer_config_rejected"),
    ("no proposal found", "proposal_unavailable"),
    ("MAC mismatched", "authentication_mac_mismatch"),
    ("scoped Portal VIP preparation failed", "vip_prepare_rejected"),
  ]
  for (needle, category) in categories where line.contains(needle) { report(category, true) }
  if line.hasPrefix("IKE_SA ") && line.contains(" established between ") {
    report("ike_established_log", true)
  }
  if line.hasPrefix("authentication of ") && line.contains(" successful") {
    report("peer_authentication_success", true)
  }
  if line.hasPrefix("deleting IKE_SA ") { report("ike_deleting_log", true) }
  if line.hasPrefix("destroying IKE_SA ") { report("ike_destroying_log", true) }
  if line.contains("received DELETE for IKE_SA") { report("peer_ike_delete", true) }
  if line.contains("lifetime") && line.contains("does not match configured") {
    report("peer_lifetime_changed", true)
  }
  for (transition, category) in [
    ("CREATED => CONNECTING", "ike_state_connecting"),
    ("CONNECTING => ESTABLISHED", "ike_state_established"),
    ("ESTABLISHED => DELETING", "ike_state_deleting"),
    ("DELETING => DESTROYING", "ike_state_destroying"),
  ] where line.contains(" state change: " + transition) { report(category, true) }
}

// Window4 diagnostics: transport metadata and bounded command errors only.
func diagnosticJSON(_ stage: String, _ fields: [String: Any]) {
  var fields = fields
  fields["stage"] = stage
  if let data = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]) {
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([10]))
  }
}
func commandStderr(_ result: BoundedCommandResult) -> String {
  var data = result.stderr
  result.consumeRetainedFailureStandardError { data.append(contentsOf: $0) }
  return String(decoding: data, as: UTF8.self)
}
func childCounters(_ elements: [VICIElement]) -> [[String: UInt64]] {
  var values: [String: UInt64] = [:]
  var nested: [[String: UInt64]] = []
  for item in elements {
    switch item {
    case .keyValue(let key, let bytes):
      if ["bytes-in", "bytes-out", "packets-in", "packets-out"].contains(key),
        let count = UInt64(String(decoding: bytes, as: UTF8.self))
      {
        values[key] = count
      }
    case .section(_, let children): nested += childCounters(children)
    case .list: break
    }
  }
  if !values.isEmpty { nested.append(values) }
  return nested
}
func recordChildCounters(_ stage: String, session: VICISession, name: String) {
  do {
    let sas = try session.streamedRequest(
      command: "list-sas", event: "list-sa",
      message: VICIMessage(elements: [.keyValue("ike", name)]))
    diagnosticJSON(stage, ["children": sas.events.flatMap { childCounters($0.elements) }])
  } catch { report(stage, false) }
}
func runDiagnostic(_ stage: String, executable: String, arguments: [String], timeout: Int = 2_000)
  async -> BoundedCommandResult
{
  let start = DispatchTime.now().uptimeNanoseconds
  let result = await BoundedCommandRunner().run(
    BoundedCommandRequest(
      executable: executable, arguments: arguments, timeoutMilliseconds: timeout,
      stdoutLimitBytes: 32_768, stderrLimitBytes: 16_384,
      failureOutputPolicy: .retainStandardErrorOnNonzeroExit))
  diagnosticJSON(
    stage,
    [
      "exitCode": result.exitStatus.map { $0 as Any } ?? NSNull(),
      "outcome": result.outcome.rawValue,
      "elapsedMilliseconds": (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000,
      "stdout": String(decoding: result.stdout, as: UTF8.self), "stderr": commandStderr(result),
    ])
  return result
}
func collectChildDiagnostics(session: VICISession, name: String, allowUtun9: Bool = false) async {
  let route = await runDiagnostic(
    "route52_details", executable: "/sbin/route", arguments: ["-nv", "get", "11.11.37.52"])
  let text = String(decoding: route.stdout, as: UTF8.self)
  let iface = text.split(separator: "\n").first {
    $0.trimmingCharacters(in: .whitespaces).hasPrefix("interface:")
  }?
  .split(separator: ":").last?.trimmingCharacters(in: .whitespaces)
  if let iface, iface.range(of: "^utun[0-9]+$", options: .regularExpression) != nil,
    allowUtun9 || iface != "utun9"
  {
    _ = await runDiagnostic("native_interface", executable: "/sbin/ifconfig", arguments: [iface])
  }
  recordChildCounters("child_counters_before_nc", session: session, name: name)
  let captureStart = DispatchTime.now().uptimeNanoseconds
  if let iface, iface.range(of: "^utun[0-9]+$", options: .regularExpression) != nil,
    allowUtun9 || iface != "utun9"
  {
    try? Data((iface + "\n").utf8).write(
      to: URL(fileURLWithPath: "/var/run/powervpn-native-acceptance/control/tcpdump.request"),
      options: .atomic)
    for _ in 0..<20 {
      if FileManager.default.fileExists(
        atPath: "/var/run/powervpn-native-acceptance/evidence/tcpdump.started")
      {
        break
      }
      try? await Task.sleep(for: .milliseconds(100))
    }
  }
  _ = await runDiagnostic(
    "nc22_result", executable: "/usr/bin/nc",
    arguments: ["-G", "3", "-z", "-v", "11.11.37.52", "22"], timeout: 5_000)
  let elapsed = DispatchTime.now().uptimeNanoseconds - captureStart
  if elapsed < 5_500_000_000 {
    try? await Task.sleep(for: .nanoseconds(Int64(5_500_000_000 - elapsed)))
  }
  recordChildCounters("child_counters_after_nc", session: session, name: name)
}

struct NativeTrial {
  static func main() async {
    let cancellation = NativeTrialCancellation()
    let monitor = NativeTrialSignalMonitor(cancellation: cancellation)
    let task = Task { await execute(cancellation: cancellation) }
    cancellation.attach(task)
    await task.value
    withExtendedLifetime(monitor) {}
  }

  static func execute(cancellation: NativeTrialCancellation) async {
    #if NATIVE13_PAIRED
      await executePairedNativeTrial()
      return
    #endif
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["--coexist-vendor-qm", "com.hhh2210.qm-vendor1", "thu52"] {
      await executeVendorQMCapture()
      return
    }
    if args == ["--offline-cancel-probe"] {
      report("offline_cancel_ready", true)
      let result = await BoundedCommandRunner().run(
        BoundedCommandRequest(
          executable: "/bin/sleep", arguments: ["30"], timeoutMilliseconds: 12_000,
          stdoutLimitBytes: 128, stderrLimitBytes: 128))
      report("offline_cancelled", result.outcome == .cancelled)
      report("offline_child_reaped", result.reaped)
      exit(result.outcome == .cancelled && result.reaped ? 0 : 1)
    }
    guard args.count == 3,
      [
        "--live-base", "--live-child", "--live-private-child", "--coexist-child",
        "--exclusive-child",
      ].contains(args[0]),
      args[1].hasPrefix("/"), args[1].utf8.count <= 103
    else {
      FileHandle.standardError.write(
        Data("usage: powervpn-native-trial <trial-mode> /absolute/trial.vici target-key\n".utf8))
      exit(64)
    }
    let coexistMode = args[0] == "--coexist-child"
    let exclusiveMode = args[0] == "--exclusive-child"
    guard
      let proposalNumber = UInt8(
        ProcessInfo.processInfo.environment["POWERVPN_TRIAL_PROPOSAL"] ?? "0"),
      proposalNumber <= 1
    else {
      report("proposal_parameter_rejected", false)
      exit(64)
    }
    let baselineInterfaces = exclusiveMode ? await trialInterfaceNames() : []
    guard
      !coexistMode
        || (args[2] == "thu52" && args[1] == "/var/run/powervpn-native-acceptance/n.vici")
    else {
      report("coexist_scope_rejected", false)
      exit(64)
    }
    do {
      if coexistMode || exclusiveMode {
        try Data().write(
          to: URL(fileURLWithPath: "/var/run/powervpn-native-acceptance/control/capture-qm"))
      }
      let coexist = coexistMode ? try NativeCoexistEvidence() : nil
      var metadata = stat()
      guard lstat(args[1], &metadata) == 0, metadata.st_mode & S_IFMT == S_IFSOCK,
        metadata.st_mode & 0o007 == 0,
        metadata.st_uid == getuid() || metadata.st_uid == 0
      else {
        report("socket_owner", false)
        exit(77)
      }
      let configuration = try PowerVPNTargetsConfiguration.currentMachine()
      let target = try configuration.target(named: args[2])
      if coexistMode {
        try NativeCoexistEvidence.requireFrozenScope(
          targetHost: target.host, portalHost: configuration.portalOrigin.host)
      }
      try Task.checkCancellation()
      // Establish the scoped local control channel before acquiring credentials.
      let session = try VICISession(socketPath: args[1], timeoutMilliseconds: 25_000)
      cancellation.attachInterruption(session.interruptionHandle())
      defer { session.close() }
      _ = try session.version()
      report("daemon_version", true)
      try Task.checkCancellation()
      try coexist?.record(.beforePortal)
      let acquired = await PortalLoginRuntime.acquire(configuration: configuration)
      guard case .acquired(let lease) = acquired else {
        report("portal_acquire", false)
        try? coexist?.record(.finished, success: false)
        exit(77)
      }
      report("portal_acquire", true)
      var passed = false
      let name = "native-trial-" + UUID().uuidString.lowercased()
      var loadedShared = false
      var loadedConnection = false
      var phase = "snapshot_mapping"
      do {
        try coexist?.record(.portalAcquired)
        try Task.checkCancellation()
        let observeGateway: (String) throws -> Void = { gateway in
          try coexist?.recordGateway(
            gateway, expectedOriginHost: configuration.portalOrigin.host ?? "")
        }
        try NativeTrialPortalBridge.withRequests(
          snapshot: lease.snapshot, target: target, name: name,
          includePrivateRule: args[0] == "--live-private-child" || coexistMode || exclusiveMode,
          proposalNumber: proposalNumber,
          observeGateway: observeGateway,
          diagnosticSink: ProcessInfo.processInfo.environment["POWERVPN_CAPTURE_VIP_FIELDS"] == "1"
            ? { data in
              FileHandle.standardOutput.write(data)
              FileHandle.standardOutput.write(Data([10]))
            } : nil
        ) { shared, connection in
          try Task.checkCancellation()
          phase = "load_shared"
          _ = try session.request(command: "load-shared", message: shared)
          loadedShared = true
          report("load_shared", true)
          try Task.checkCancellation()
          phase = "load_connection"
          #if NATIVE13_NATT_START
            let trialConnection = VICIMessage(
              elements: connection.elements.map { element in
                guard case .section(let key, let fields) = element else { return element }
                return .section(
                  name: key,
                  elements: fields.map { field in
                    if case .keyValue(let key, _) = field, key == "local_port" {
                      return .keyValue("local_port", "50021")
                    }
                    return field
                  })
              })
            diagnosticJSON("native_transport", ["initialLocalPort": 50021, "natTLocalPort": 50021])
          #else
            let trialConnection = connection
          #endif
          _ = try session.request(command: "load-conn", message: trialConnection)
          loadedConnection = true
          report("load_connection", true)
        }
        let initiate = VICIMessage(elements: [
          .keyValue("ike", name), .keyValue("timeout", "15000"), .keyValue("loglevel", "2"),
        ])
        try Task.checkCancellation()
        try coexist?.record(.beforeIKE)
        phase = "initiate_ike"
        _ = try session.streamedRequest(
          command: "initiate", event: "control-log", message: initiate, observeEvent: observeControl
        )
        try Task.checkCancellation()
        phase = "list_ike"
        let sas = try session.streamedRequest(
          command: "list-sas", event: "list-sa",
          message: VICIMessage(elements: [.keyValue("ike", name)]))
        let established = reportSAs("initial", sas)
        report("ike_established", established)
        if established { try coexist?.record(.ikeEstablished) }
        passed = established
        if !established {
          let all = try session.streamedRequest(command: "list-sas", event: "list-sa")
          _ = reportSAs("unfiltered", all)
        }
        if established && args[0] == "--live-base" {
          phase = "ike_hold_15s"
          try await Task.sleep(for: .seconds(15))
          let held = try session.streamedRequest(
            command: "list-sas", event: "list-sa",
            message: VICIMessage(elements: [.keyValue("ike", name)]))
          passed = reportSAs("after_15s", held)
          report("ike_stable_15s", passed)
        }
        if established && args[0] != "--live-base" {
          try Task.checkCancellation()
          try coexist?.record(.beforeChild)
          phase = "initiate_child"
          _ = try session.streamedRequest(
            command: "initiate", event: "control-log",
            message: VICIMessage(elements: [
              .keyValue("ike", name), .keyValue("child", "selected-resource"),
              .keyValue("timeout", "15000"), .keyValue("loglevel", "2"),
            ]), observeEvent: observeControl)
          try Task.checkCancellation()
          phase = "list_child"
          let children = try session.streamedRequest(
            command: "list-sas", event: "list-sa",
            message: VICIMessage(elements: [.keyValue("ike", name)]))
          let installed =
            children.events.reduce(0) { $0 + countState($1.elements, "INSTALLED") } >= 1
          report("child_installed", installed)
          passed = installed
          if installed {
            #if NATIVE20_TIMING
              #if NATIVE20_DELAY2
                let firstTrafficDelayMilliseconds = 2000
              #else
                let firstTrafficDelayMilliseconds = 0
              #endif
              let holdStarted = DispatchTime.now().uptimeNanoseconds
              diagnosticJSON(
                "first_traffic_hold_begin",
                [
                  "epoch": Date().timeIntervalSince1970,
                  "delayMilliseconds": firstTrafficDelayMilliseconds,
                ])
              if firstTrafficDelayMilliseconds > 0 {
                try await Task.sleep(for: .milliseconds(firstTrafficDelayMilliseconds))
              }
              diagnosticJSON(
                "first_traffic_hold_released",
                [
                  "epoch": Date().timeIntervalSince1970,
                  "delayMilliseconds": firstTrafficDelayMilliseconds,
                  "elapsedMilliseconds": (DispatchTime.now().uptimeNanoseconds - holdStarted)
                    / 1_000_000,
                ])
            #endif
            try coexist?.record(.childInstalled)
            if coexistMode || exclusiveMode {
              phase = "native_target_route"
              let owned =
                exclusiveMode
                ? await waitForTrialRoute(
                  target: target.host, baselineInterfaces: baselineInterfaces)
                : ((try? await NativeCoexistEvidence.verifyNativeRoute(target: target.host))
                  ?? false)
              report("native_route_52_verified", owned)
              guard owned else { throw TrialScopeFailure.routeNotOwned }
              try coexist?.record(.nativeRouteVerified)
            }
            #if NATIVE20_UDP
              phase = "udp_probe"
              passed = await executeNative20UDP(target: target, backend: "native")
              report("native_udp_complete", passed)
            #else
              if coexistMode || exclusiveMode {
                await collectChildDiagnostics(
                  session: session, name: name, allowUtun9: exclusiveMode)
              }
              try Task.checkCancellation()
              phase = "ssh_probe"
              let isolationArguments =
                (coexistMode || exclusiveMode)
                ? [
                  "-v", "-F", "/dev/null", "-p", "22", "-o", "ForkAfterAuthentication=no",
                  "-T", "-o", "ClearAllForwardings=yes", "-o", "StrictHostKeyChecking=yes",
                ] : []
              let sshArguments =
                isolationArguments + [
                  "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
                  "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no", "-o",
                  "ControlPath=none",
                  "-o", "PermitLocalCommand=no", "-o", "ServerAliveInterval=2", "-o",
                  "ServerAliveCountMax=2",
                  target.user + "@" + target.host, "true",
                ]
              let authSocket = ProcessInfo.processInfo.environment[
                BoundedCommandRequest.sshAuthSocketEnvironmentKey]
              let sshStarted = DispatchTime.now().uptimeNanoseconds
              let ssh = await BoundedCommandRunner().run(
                BoundedCommandRequest(
                  executable: "/usr/bin/ssh", arguments: sshArguments,
                  timeoutMilliseconds: 12_000, stdoutLimitBytes: 4_096, stderrLimitBytes: 8_192,
                  environment: authSocket.map {
                    [BoundedCommandRequest.sshAuthSocketEnvironmentKey: $0]
                  } ?? [:],
                  failureOutputPolicy: .retainStandardErrorOnNonzeroExit))
              let sshError = commandStderr(ssh)
              let selectedLines = sshError.split(whereSeparator: \.isNewline).map(String.init)
                .filter { line in
                  let lower = line.lowercased()
                  return !lower.hasPrefix("debug")
                    || [
                      "connecting to", "connect to address", "connection established",
                      "authenticated", "timeout", "timed out",
                    ].contains { lower.contains($0) }
                }
              diagnosticJSON(
                "ssh_result",
                [
                  "exitCode": ssh.exitStatus.map { $0 as Any } ?? NSNull(),
                  "elapsedMilliseconds": (DispatchTime.now().uptimeNanoseconds - sshStarted)
                    / 1_000_000,
                  "stderr": selectedLines.joined(separator: "\n"), "outcome": ssh.outcome.rawValue,
                ])
              passed = ssh.succeeded
              // The requested diagnostic stderr is filtered above; Portal/VICI material is never rendered.
              report("ssh_" + ssh.outcome.rawValue, passed)
              report("ssh_reaped", ssh.reaped)
              report("ssh_true", passed)
              if (coexistMode || exclusiveMode) && passed {
                phase = "native_target_route_after_ssh"
                let owned =
                  exclusiveMode
                  ? await waitForTrialRoute(
                    target: target.host, baselineInterfaces: baselineInterfaces)
                  : ((try? await NativeCoexistEvidence.verifyNativeRoute(target: target.host))
                    ?? false)
                report("native_route_52_post_ssh_verified", owned)
              }
              try coexist?.record(.sshFinished, success: passed)
            #endif
          }
        }
      } catch {
        passed = false
        report("native_exchange", false)
        reportFailure(phase, error)
      }
      try? coexist?.record(.cleanupStarted)
      let cleanupSession: VICISession?
      if Task.isCancelled {
        session.close()
        cleanupSession = try? VICISession(socketPath: args[1], timeoutMilliseconds: 1_000)
      } else {
        cleanupSession = session
      }
      let cleanupTimeout = Task.isCancelled ? "500" : "5000"
      let cleanupLogLevel = Task.isCancelled ? "-1" : "2"
      if loadedConnection {
        do {
          guard let cleanupSession else { throw VICITransportError.timeout(.connect) }
          _ = try cleanupSession.streamedRequest(
            command: "terminate", event: "control-log",
            message: VICIMessage(elements: [
              .keyValue("ike", name), .keyValue("force", "yes"),
              .keyValue("timeout", cleanupTimeout), .keyValue("loglevel", cleanupLogLevel),
            ]), observeEvent: observeControl)
          report("terminate", true)
        } catch {
          passed = false
          report("terminate", false)
          reportFailure("terminate", error)
        }
        do {
          guard let cleanupSession else { throw VICITransportError.timeout(.connect) }
          _ = try cleanupSession.request(
            command: "unload-conn", message: VICIMessage(elements: [.keyValue("name", name)]))
          report("unload_connection", true)
        } catch {
          passed = false
          report("unload_connection", false)
        }
      }
      if loadedShared {
        do {
          guard let cleanupSession else { throw VICITransportError.timeout(.connect) }
          _ = try cleanupSession.request(
            command: "unload-shared", message: VICIMessage(elements: [.keyValue("id", name)]))
          report("unload_shared", true)
        } catch {
          passed = false
          report("unload_shared", false)
        }
      }
      let logout = await lease.logoutAndErase()
      let closed = logout.status == .accepted || logout.status == .alreadyClosed
      report("portal_closed", closed)
      try? coexist?.record(.portalClosed, success: closed)
      passed = passed && closed && !Task.isCancelled
      try? coexist?.record(.finished, success: passed)
      exit(passed ? 0 : 75)
    } catch {
      report("trial_preparation", false)
      exit(77)
    }
  }
}

// main.swift is top-level code; Swift 6.0 (Xcode 16.2) rejects @main here.
await NativeTrial.main()
