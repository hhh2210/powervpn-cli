import Darwin
import Foundation
import PowerVPNCore

/// `powervpn native install|uninstall|status` for Homebrew installs.
///
/// install/uninstall must run under sudo and only hand the keg's own payload
/// to the repository's install.sh/uninstall.sh; they take no paths or commands
/// from the caller. status is read-only and needs no privileges.
func runNativeCommand(
  _ arguments: [String],
  payload: NativeBundledPayload? = NativeBundledPayload.current,
  installedHome: String = NativeHelperPaths.home,
  invokedPath: String? = NativeBundledPayload.invokedExecutablePath,
  effectiveUserID: uid_t = geteuid(),
  environment: [String: String] = ProcessInfo.processInfo.environment,
  runScript: (String, [String: String]) -> Int32 = runNativeScript
) -> UserProductCommandResult {
  let usage = "usage: powervpn native install|uninstall|status"
  guard arguments.count == 2 else { return .failure(usage, exitCode: 64, next: nil) }
  guard let payload else {
    return .failure(
      "powervpn native: this powervpn was not installed by Homebrew", exitCode: 77,
      next: "from a source checkout run sudo scripts/native/install.sh")
  }
  let reinstall = NativeBundledPayload.sudoCommand("install", invokedAs: invokedPath)
  switch arguments[1] {
  case "status":
    switch payload.matchesInstalled(home: installedHome) {
    case nil:
      return .failure(
        "Native backend: not installed", exitCode: 1, next: reinstall)
    case false?:
      return .failure(
        "Native backend: installed copy differs from powervpn \(powervpnVersion)",
        exitCode: 1, next: reinstall)
    case true?:
      return .success("Native backend: up to date (powervpn \(powervpnVersion))\n")
    }
  case "install", "uninstall":
    guard effectiveUserID == 0, let sudoUID = environment["SUDO_UID"], sudoUID != "0" else {
      return .failure(
        "powervpn native: run with sudo from your own account", exitCode: 77,
        next: NativeBundledPayload.sudoCommand(arguments[1], invokedAs: invokedPath))
    }
    // install.sh resolves the owner from SUDO_UID and reads that user's
    // targets.json; nothing else from the caller's environment is passed on.
    var scriptEnvironment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SUDO_UID": sudoUID]
    let script: String
    if arguments[1] == "install" {
      script = payload.installScript
      scriptEnvironment["POWERVPN_NATIVE_RUNTIME_ARCHIVE"] = payload.runtimeArchive
      scriptEnvironment["POWERVPN_NATIVE_HELPER"] = payload.helper
    } else {
      script = payload.uninstallScript
    }
    let status = runScript(script, scriptEnvironment)
    return UserProductCommandResult(standardOutput: "", standardError: "", exitCode: status)
  default:
    return .failure(usage, exitCode: 64)
  }
}

/// Runs `/bin/sh <script>` with the terminal attached so install.sh's own
/// progress and failures reach the user unchanged.
func runNativeScript(_ script: String, _ environment: [String: String]) -> Int32 {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/bin/sh")
  process.arguments = [script]
  process.environment = environment
  do {
    try process.run()
  } catch {
    FileHandle.standardError.write(Data("powervpn native: could not start \(script)\n".utf8))
    return 1
  }
  process.waitUntilExit()
  return process.terminationStatus
}
