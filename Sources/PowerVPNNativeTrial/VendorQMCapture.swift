import Darwin
import Dispatch
import Foundation
import PowerVPNCore
import PowerVPNPortal
import PowerVPNProduct
@preconcurrency import XPC

enum TrialScopeFailure: Error { case routeNotOwned }

func trialInterfaceNames() async -> Set<String> {
  let result = await BoundedCommandRunner().run(
    BoundedCommandRequest(
      executable: "/sbin/ifconfig", arguments: ["-l"], timeoutMilliseconds: 1000,
      stdoutLimitBytes: 4096, stderrLimitBytes: 1024))
  guard result.succeeded else { return [] }
  return Set(
    String(decoding: result.stdout, as: UTF8.self).split(whereSeparator: \.isWhitespace).map(
      String.init))
}

func waitForTrialRoute(target: String, baselineInterfaces: Set<String>) async -> Bool {
  guard !baselineInterfaces.isEmpty else { return false }
  for _ in 0..<120 {
    if Task.isCancelled { return false }
    let route = await BoundedCommandRunner().run(
      BoundedCommandRequest(
        executable: "/sbin/route", arguments: ["-n", "get", target], timeoutMilliseconds: 1000,
        stdoutLimitBytes: 4096, stderrLimitBytes: 1024))
    let lines = String(decoding: route.stdout, as: UTF8.self).split(whereSeparator: \.isNewline)
    let iface = lines.first { $0.trimmingCharacters(in: .whitespaces).hasPrefix("interface:") }?
      .split(separator: ":").last?.trimmingCharacters(in: .whitespaces)
    if let iface, iface.hasPrefix("utun"), !baselineInterfaces.contains(iface) { return true }
    try? await Task.sleep(for: .milliseconds(100))
  }
  return false
}

private final class IsolatedVendorConnection: @unchecked Sendable {
  let connection: xpc_connection_t
  private let versionReady = DispatchSemaphore(value: 0)

  init() {
    connection = xpc_connection_create_mach_service(
      "com.hhh2210.qm-vendor1",
      DispatchQueue(label: "qm-isolated-vendor"), UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
    xpc_connection_set_event_handler(connection) { [self] object in
      if xpc_get_type(object) == XPC_TYPE_DICTIONARY,
        xpc_dictionary_get_bool(object, "get_version")
      {
        versionReady.signal()
      }
    }
    xpc_connection_activate(connection)
  }

  func verifyVersion() -> Bool {
    let request = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(request, "type", "rpc")
    xpc_dictionary_set_string(request, "rpc", "get_version")
    xpc_connection_send_message_with_reply(connection, request, nil) { [self] object in
      if xpc_get_type(object) == XPC_TYPE_DICTIONARY,
        xpc_dictionary_get_bool(object, "get_version")
      {
        versionReady.signal()
      }
    }
    return versionReady.wait(timeout: .now() + 8) == .success
  }

  func submit(_ request: xpc_object_t) {
    xpc_connection_send_message_with_reply(connection, request, nil) { object in
      report("vendor_start_reply_received", xpc_get_type(object) == XPC_TYPE_DICTIONARY)
    }
  }

  func close() { xpc_connection_cancel(connection) }

  func stop(gateway: String) {
    let request = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(request, "type", "rpc")
    xpc_dictionary_set_string(request, "rpc", "stop_connection")
    let common = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(common, "gateway", gateway)
    xpc_dictionary_set_value(request, "common", common)
    xpc_connection_send_message_with_reply(connection, request, nil) { _ in }
    diagnosticJSON("vendor_stop_requested", ["epoch": Date().timeIntervalSince1970])
  }
}

func executeVendorQMCapture() async {
  guard getuid() == 502 else {
    report("vendor_capture_uid_rejected", false)
    exit(64)
  }
  let teardown = ProcessInfo.processInfo.environment["POWERVPN_VENDOR_TEARDOWN"] ?? "graceful"
  guard ["graceful", "abrupt"].contains(teardown) else { exit(64) }
  let connection = IsolatedVendorConnection()
  guard connection.verifyVersion() else {
    report("isolated_vendor_version", false)
    connection.close()
    exit(75)
  }
  report("isolated_vendor_version", true)
  do {
    let configuration = try PowerVPNTargetsConfiguration.currentMachine()
    let target = try configuration.target(named: "thu52")
    try NativeCoexistEvidence.requireFrozenScope(
      targetHost: target.host, portalHost: configuration.portalOrigin.host)
    let baselineInterfaces = await trialInterfaceNames()
    let acquired = await PortalLoginRuntime.acquire(configuration: configuration)
    guard case .acquired(let lease) = acquired else {
      report("portal_acquire", false)
      connection.close()
      exit(77)
    }
    report("portal_acquire", true)
    var passed = false
    var started = false
    var gateway = ""
    do {
      try NativeTrialPortalBridge.withVendorStartMessage(snapshot: lease.snapshot, target: target) {
        message in
        if let common = xpc_dictionary_get_value(message, "common"),
          let value = xpc_dictionary_get_string(common, "gateway")
        {
          gateway = String(cString: value)
        }
        guard gateway == "166.111.143.19" else { throw TrialScopeFailure.routeNotOwned }
        connection.submit(message)
        started = true
      }
      report("vendor_selected_resource_submitted", true)
      let routeOwned = await waitForTrialRoute(
        target: target.host, baselineInterfaces: baselineInterfaces)
      report("vendor_target_route", routeOwned)
      if routeOwned {
        #if NATIVE20_UDP
          passed = await executeNative20UDP(target: target, backend: "vendor")
        #else
          #if !NATIVE13_VENDOR_BASELINE
            _ = await runDiagnostic(
              "vendor_nc22_result", executable: "/usr/bin/nc",
              arguments: ["-G", "3", "-z", "-v", target.host, "22"], timeout: 5000)
          #endif
          let args = [
            "-v", "-F", "/dev/null", "-p", "22", "-T", "-o", "ForkAfterAuthentication=no",
            "-o", "ClearAllForwardings=yes", "-o", "StrictHostKeyChecking=yes", "-o",
            "BatchMode=yes",
            "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1", "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none", "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "PermitLocalCommand=no", target.user + "@" + target.host, "true",
          ]
          let started = DispatchTime.now().uptimeNanoseconds
          let ssh = await BoundedCommandRunner().run(
            BoundedCommandRequest(
              executable: "/usr/bin/ssh",
              arguments: args, timeoutMilliseconds: 12000, stdoutLimitBytes: 4096,
              stderrLimitBytes: 8192,
              failureOutputPolicy: .retainStandardErrorOnNonzeroExit))
          let lines = commandStderr(ssh).split(whereSeparator: \.isNewline).filter { line in
            [
              "Connecting to", "connect to address", "Connection established", "Authenticated",
              "timed out",
            ].contains { line.contains($0) }
          }
          diagnosticJSON(
            "vendor_ssh_result",
            [
              "exitCode": ssh.exitStatus.map { $0 as Any } ?? NSNull(),
              "elapsedMilliseconds": (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000,
              "stderr": lines.joined(separator: "\n"), "outcome": ssh.outcome.rawValue,
            ])
          passed = ssh.succeeded
        #endif
      }
    } catch { reportFailure("vendor_capture", error) }
    if started {
      #if NATIVE20_UDP
        diagnosticJSON(
          "vendor_udp_probe_finished",
          [
            "epoch": Date().timeIntervalSince1970,
            "probeSuccess": passed, "teardown": teardown,
          ])
      #else
        diagnosticJSON(
          "vendor_probe_finished",
          [
            "epoch": Date().timeIntervalSince1970,
            "sshSuccess": passed, "teardown": teardown,
          ])
      #endif
      try? Data().write(
        to: URL(fileURLWithPath: "/var/run/powervpn-qm-observer/control/probe.done"),
        options: .atomic)
      if teardown == "graceful" {
        connection.stop(gateway: gateway)
        try? await Task.sleep(for: .seconds(4))
      } else {
        for _ in 0..<100 {
          if FileManager.default.fileExists(atPath: "/var/run/powervpn-qm-observer/vendor.stopped")
          {
            break
          }
          try? await Task.sleep(for: .milliseconds(100))
        }
        report(
          "vendor_abrupt_stop_observed",
          FileManager.default.fileExists(atPath: "/var/run/powervpn-qm-observer/vendor.stopped"))
      }
    }
    connection.close()
    let logout = await lease.logoutAndErase()
    report("portal_closed", logout.status == .accepted || logout.status == .alreadyClosed)
    #if NATIVE20_UDP
      report("vendor_udp_complete", passed)
    #else
      report("vendor_ssh_true", passed)
    #endif
    exit(passed ? 0 : 75)
  } catch {
    connection.close()
    reportFailure("vendor_capture_preparation", error)
    exit(77)
  }
}
