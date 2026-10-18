import CryptoKit
import Darwin
import Foundation

package let powervpnVersion = "0.2.0"

/// What a Homebrew keg ships beside the CLI, in `<prefix>/libexec/powervpn-native`.
///
/// The runtime travels as a tar so Homebrew's Mach-O relocation never rewrites
/// it. `sudo powervpn native install` hands these files to install.sh, which
/// copies them into the root-owned `NativeHelperPaths.home`; the daemon never
/// runs anything from the user-writable Homebrew prefix.
package struct NativeBundledPayload: Equatable, Sendable {
  package let directory: String

  package var installScript: String { directory + "/install.sh" }
  package var uninstallScript: String { directory + "/uninstall.sh" }
  package var helper: String { directory + "/powervpn-native-helper" }
  package var runtimeArchive: String { directory + "/runtime.tar" }
  /// `shasum -a 256` of every runtime file, written by build_runtime.sh.
  package var runtimeManifest: String { directory + "/runtime.sha256" }

  /// `<prefix>/bin/powervpn` → `<prefix>/libexec/powervpn-native`, after
  /// resolving the `$(brew --prefix)/bin` symlink into the keg.
  package static func locate(executablePath: String?) -> NativeBundledPayload? {
    guard let executablePath else { return nil }
    let prefix = URL(fileURLWithPath: executablePath).resolvingSymlinksInPath()
      .deletingLastPathComponent().deletingLastPathComponent()
    let payload = NativeBundledPayload(
      directory: prefix.appendingPathComponent("libexec/powervpn-native").path)
    let files = [
      payload.installScript, payload.uninstallScript, payload.helper,
      payload.runtimeArchive, payload.runtimeManifest,
    ]
    return files.allSatisfy { FileManager.default.fileExists(atPath: $0) } ? payload : nil
  }

  package static var current: NativeBundledPayload? {
    locate(executablePath: currentExecutablePath())
  }

  /// The command a `next:` line should name on this installation.
  package static var installCommand: String {
    let invoked = invokedExecutablePath
    guard locate(executablePath: invoked) != nil else { return "sudo scripts/native/install.sh" }
    return sudoCommand("install", invokedAs: invoked)
  }

  /// `sudo <cli> native <subcommand>`, naming the CLI by the absolute path it
  /// was run from (normally the stable `$(brew --prefix)/bin/powervpn`) so the
  /// line works whatever PATH sudo keeps.
  package static func sudoCommand(_ subcommand: String, invokedAs path: String?) -> String {
    guard let path, path.hasPrefix("/"), !path.contains(where: \.isWhitespace) else {
      return "sudo powervpn native \(subcommand)"
    }
    return "sudo \(path) native \(subcommand)"
  }

  /// The path this process was started as, before resolving symlinks.
  package static var invokedExecutablePath: String? { currentExecutablePath() }

  /// nil: no native backend installed. false: the installed helper or runtime
  /// differs from this keg (a `brew upgrade` changed it), so reinstall.
  package func matchesInstalled(home: String = NativeHelperPaths.home) -> Bool? {
    guard FileManager.default.fileExists(atPath: home + "/powervpn-native-helper") else {
      return nil
    }
    guard let bundledHelper = Self.sha256(ofFile: helper),
      let installedHelper = Self.sha256(ofFile: home + "/powervpn-native-helper"),
      let bundledManifest = try? String(contentsOfFile: runtimeManifest, encoding: .utf8),
      let installedManifest = try? String(
        contentsOfFile: home + "/runtime.sha256", encoding: .utf8)
    else { return false }
    return bundledHelper == installedHelper && bundledManifest == installedManifest
  }

  private static func sha256(ofFile path: String) -> String? {
    guard let data = FileManager.default.contents(atPath: path) else { return nil }
    return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  private static func currentExecutablePath() -> String? {
    var size: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &size)
    var buffer = [CChar](repeating: 0, count: Int(size) + 1)
    guard _NSGetExecutablePath(&buffer, &size) == 0 else { return nil }
    return String(cString: buffer)
  }
}
