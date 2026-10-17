import Darwin
import Foundation
import PowerVPNCore
import PowerVPNPortal
import PowerVPNProduct

private func pairedChildren(_ message: VICIMessage) throws -> [VICIElement] {
  guard case .section(_, let root)? = message.elements.first,
    case .section(_, let children)? = root.first(where: {
      if case .section(let key, _) = $0 { return key == "children" }
      return false
    }),
    case .section(_, let fields)? = children.first
  else { throw TrialScopeFailure.routeNotOwned }
  return fields
}

func executePairedNativeTrial() async {
  let args = Array(CommandLine.arguments.dropFirst())
  guard args == ["--exclusive-child", "/var/run/powervpn-native-acceptance/n.vici", "thu52"],
    let first = UInt8(ProcessInfo.processInfo.environment["POWERVPN_TRIAL_PROPOSAL"] ?? "0"),
    first <= 1
  else { exit(64) }
  do {
    let baseline = await trialInterfaceNames()
    try Data().write(
      to: URL(fileURLWithPath: "/var/run/powervpn-native-acceptance/control/capture-qm"))
    let configuration = try PowerVPNTargetsConfiguration.currentMachine()
    let target = try configuration.target(named: "thu52")
    let session = try VICISession(socketPath: args[1], timeoutMilliseconds: 25_000)
    defer { session.close() }
    _ = try session.version()
    let acquired = await PortalLoginRuntime.acquire(configuration: configuration)
    guard case .acquired(let lease) = acquired else {
      report("portal_acquire", false)
      exit(77)
    }
    report("portal_acquire", true)
    let name = "paired-native-" + UUID().uuidString.lowercased()
    var loadedShared = false
    var loadedConnection = false
    var completed = 0
    var allPassed = true
    var phase = "paired_configuration"
    do {
      var base: VICIMessage?
      var children: [UInt8: [VICIElement]] = [:]
      for number: UInt8 in [0, 1] {
        try NativeTrialPortalBridge.withRequests(
          snapshot: lease.snapshot, target: target, name: name,
          includePrivateRule: true, proposalNumber: number
        ) { shared, connection in
          if !loadedShared {
            _ = try session.request(command: "load-shared", message: shared)
            loadedShared = true
          }
          if base == nil { base = connection }
          children[number] = try pairedChildren(connection)
        }
      }
      guard let base, let p0 = children[0], let p1 = children[1] else {
        throw TrialScopeFailure.routeNotOwned
      }
      let elements = base.elements.map { element -> VICIElement in
        guard case .section(let key, let fields) = element else { return element }
        return .section(
          name: key,
          elements: fields.map { field in
            #if NATIVE13_NATT_START
              if case .keyValue(let key, _) = field, key == "local_port" {
                return .keyValue("local_port", "50021")
              }
            #endif
            if case .section(let key, _) = field, key == "children" {
              return .section(
                name: key,
                elements: [
                  .section(name: "probe-p0", elements: p0),
                  .section(name: "probe-p1", elements: p1),
                ])
            }
            return field
          })
      }
      _ = try session.request(command: "load-conn", message: VICIMessage(elements: elements))
      loadedConnection = true
      #if NATIVE13_NATT_START
        diagnosticJSON("paired_transport", ["initialLocalPort": 50021, "natTLocalPort": 50021])
      #else
        diagnosticJSON("paired_transport", ["initialLocalPort": 50020, "natTLocalPort": 50021])
      #endif
      phase = "paired_ike"
      _ = try session.streamedRequest(
        command: "initiate", event: "control-log",
        message: VICIMessage(elements: [
          .keyValue("ike", name), .keyValue("timeout", "15000"), .keyValue("loglevel", "1"),
        ]), observeEvent: observeControl)
      let order: [UInt8] = [first, 1 - first, first]
      for (index, number) in order.enumerated() {
        try Task.checkCancellation()
        let child = "probe-p\(number)"
        phase = "paired_child_\(index)_p\(number)"
        diagnosticJSON(
          "paired_phase_begin",
          ["index": index, "proposal": number, "epoch": Date().timeIntervalSince1970])
        _ = try session.streamedRequest(
          command: "initiate", event: "control-log",
          message: VICIMessage(elements: [
            .keyValue("ike", name), .keyValue("child", child), .keyValue("timeout", "15000"),
            .keyValue("loglevel", "1"),
          ]), observeEvent: observeControl)
        let sas = try session.streamedRequest(
          command: "list-sas", event: "list-sa",
          message: VICIMessage(elements: [.keyValue("ike", name)]))
        guard sas.events.reduce(0, { $0 + countState($1.elements, "INSTALLED") }) == 1,
          await waitForTrialRoute(target: target.host, baselineInterfaces: baseline)
        else { throw TrialScopeFailure.routeNotOwned }
        report("child_installed", true)
        _ = await runDiagnostic(
          "paired_\(index)_nc", executable: "/usr/bin/nc",
          arguments: ["-G", "3", "-z", "-v", target.host, "22"], timeout: 5000)
        recordChildCounters("paired_\(index)_counters", session: session, name: name)
        let started = DispatchTime.now().uptimeNanoseconds
        let ssh = await BoundedCommandRunner().run(
          BoundedCommandRequest(
            executable: "/usr/bin/ssh",
            arguments: [
              "-v", "-F", "/dev/null", "-p", "22", "-T", "-o", "BatchMode=yes", "-o",
              "ConnectTimeout=5",
              "-o", "ConnectionAttempts=1", "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o",
              "ControlMaster=no",
              "-o", "ControlPath=none", "-o", "PermitLocalCommand=no", "-o",
              "ClearAllForwardings=yes",
              "-o", "StrictHostKeyChecking=yes", target.user + "@" + target.host, "true",
            ],
            timeoutMilliseconds: 12000, stdoutLimitBytes: 4096, stderrLimitBytes: 8192,
            failureOutputPolicy: .retainStandardErrorOnNonzeroExit))
        diagnosticJSON(
          "paired_phase_result",
          [
            "index": index, "proposal": number, "sshSuccess": ssh.succeeded,
            "sshExitCode": ssh.exitStatus.map { $0 as Any } ?? NSNull(),
            "epoch": Date().timeIntervalSince1970,
            "elapsedMilliseconds": (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000,
          ])
        allPassed = allPassed && ssh.succeeded
        completed += 1
        _ = try session.streamedRequest(
          command: "terminate", event: "control-log",
          message: VICIMessage(elements: [
            .keyValue("child", child), .keyValue("timeout", "5000"), .keyValue("loglevel", "1"),
          ]), observeEvent: observeControl)
        let after = try session.streamedRequest(
          command: "list-sas", event: "list-sa",
          message: VICIMessage(elements: [.keyValue("ike", name)]))
        guard after.events.reduce(0, { $0 + countState($1.elements, "ESTABLISHED") }) == 1,
          after.events.reduce(0, { $0 + countState($1.elements, "INSTALLED") }) == 0
        else { throw TrialScopeFailure.routeNotOwned }
        report("paired_child_removed_ike_retained", true)
      }
    } catch {
      reportFailure(phase, error)
      allPassed = false
    }
    if loadedConnection {
      _ = try? session.streamedRequest(
        command: "terminate", event: "control-log",
        message: VICIMessage(elements: [
          .keyValue("ike", name), .keyValue("timeout", "5000"), .keyValue("loglevel", "-1"),
        ]))
      _ = try? session.request(
        command: "unload-conn", message: VICIMessage(elements: [.keyValue("name", name)]))
    }
    if loadedShared {
      _ = try? session.request(
        command: "unload-shared", message: VICIMessage(elements: [.keyValue("id", name)]))
    }
    let logout = await lease.logoutAndErase()
    report("portal_closed", logout.status == .accepted || logout.status == .alreadyClosed)
    diagnosticJSON("paired_complete", ["phases": completed, "allSSHSuccessful": allPassed])
    exit(completed == 3 && allPassed ? 0 : 75)
  } catch {
    reportFailure("paired_preparation", error)
    exit(77)
  }
}
