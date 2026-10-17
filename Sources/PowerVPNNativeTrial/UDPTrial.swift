import Foundation
import PowerVPNCore
import PowerVPNPortal

func executeNative20UDP(target: PowerVPNTargetConfiguration, backend: String) async -> Bool {
  guard target.host == "11.11.37.52", ["native", "vendor"].contains(backend) else { return false }
  let result = await BoundedCommandRunner().run(
    BoundedCommandRequest(
      executable:
        "/Users/larry_1/.local/share/uv/python/cpython-3.13.13-macos-aarch64-none/bin/python3.13",
      arguments: [
        "/Users/larry_1/codex/2026-10-17/duy/work/native20/udp/probe.py",
        "--backend", backend, "--user", target.user,
      ],
      timeoutMilliseconds: 55_000, stdoutLimitBytes: 262_144, stderrLimitBytes: 8192,
      failureOutputPolicy: .retainStandardErrorOnNonzeroExit))
  diagnosticJSON(
    "udp_harness_result",
    [
      "success": result.succeeded,
      "exitCode": result.exitStatus.map { $0 as Any } ?? NSNull(),
      "stdout": String(decoding: result.stdout, as: UTF8.self),
      "stderr": commandStderr(result),
    ])
  return result.succeeded
}
