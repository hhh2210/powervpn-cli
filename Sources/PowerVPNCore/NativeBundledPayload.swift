import CryptoKit
import Darwin
import Foundation

package let powervpnVersion = "0.2.0"

/// What a Homebrew keg ships beside the CLI, in `<prefix>/libexec/powervpn-native`.
///
/// The runtime travels as a tar so Homebrew's Mach-O relocation never rewrites
/// it. `sudo powervpn native install` hands these files to install.sh, which
/// copies them into the root-owned `NativeHelperPaths.home` before using them;
/// the installed daemon never runs anything from the user-writable keg. The
/// install step itself trusts the keg's owner, exactly like any sudo command
/// run from that user's files.
package struct NativeBundledPayload: Equatable, Sendable {
  package let directory: String

  package var installScript: String { directory + "/install.sh" }
  package var uninstallScript: String { directory + "/uninstall.sh" }
  package var helper: String { directory + "/powervpn-native-helper" }
  package var runtimeArchive: String { directory + "/runtime.tar" }

  /// Files `install` and `status` need; `uninstall` needs only its script.
  package var installFiles: [String] { [installScript, helper, runtimeArchive] }
  package var installFilesPresent: Bool {
    installFiles.allSatisfy { FileManager.default.fileExists(atPath: $0) }
  }

  /// `<prefix>/bin/powervpn` → `<prefix>/libexec/powervpn-native`, after
  /// resolving the `$(brew --prefix)/bin` symlink into the keg. A keg missing
  /// install files is still returned, so `uninstall` keeps working.
  package static func locate(executablePath: String?) -> NativeBundledPayload? {
    guard let executablePath else { return nil }
    let prefix = URL(fileURLWithPath: executablePath).resolvingSymlinksInPath()
      .deletingLastPathComponent().deletingLastPathComponent()
    let payload = NativeBundledPayload(
      directory: prefix.appendingPathComponent("libexec/powervpn-native").path)
    return FileManager.default.fileExists(atPath: payload.uninstallScript) ? payload : nil
  }

  package static var current: NativeBundledPayload? {
    locate(executablePath: invokedExecutablePath)
  }

  /// The command a `next:` line should name on this installation.
  package static var installCommand: String {
    let invoked = invokedExecutablePath
    guard locate(executablePath: invoked) != nil else { return "sudo scripts/native/install.sh" }
    return sudoCommand("install", invokedAs: invoked)
  }

  /// `sudo <cli> native <subcommand>` with the CLI named by an absolute,
  /// shell-quoted path (normally the stable `$(brew --prefix)/bin/powervpn`),
  /// so the line works whatever PATH sudo keeps and pastes safely.
  package static func sudoCommand(_ subcommand: String, invokedAs path: String?) -> String {
    let absolute: String?
    if let path, path.hasPrefix("/") {
      absolute = path
    } else if let path {
      absolute = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    } else {
      absolute = nil
    }
    return "sudo \(shellQuoted(absolute ?? "powervpn")) native \(subcommand)"
  }

  package static func shellQuoted(_ word: String) -> String {
    let safe = CharacterSet(
      charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._+-@%:,")
    if !word.isEmpty, word.unicodeScalars.allSatisfy(safe.contains) { return word }
    return "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }

  /// The path this process was started as, before resolving symlinks.
  package static var invokedExecutablePath: String? { currentExecutablePath() }

  /// What install.sh records in `installed-from`: the installer, helper and
  /// runtime archive it consumed. Any change to one of them in the keg means
  /// the root install is out of date, including modes and symlinks in the tar.
  package func expectedInstalledFrom() -> String? {
    guard let installer = Self.sha256(ofFile: installScript),
      let helper = Self.sha256(ofFile: helper),
      let archive = Self.sha256(ofFile: runtimeArchive)
    else { return nil }
    return "installer \(installer)\nhelper \(helper)\nruntime-archive \(archive)\n"
  }

  /// nil: no native backend installed. false: the root install is incomplete
  /// or was made from different files than this keg (e.g. before a `brew upgrade`).
  package func matchesInstalled(home: String = NativeHelperPaths.home) -> Bool? {
    guard FileManager.default.fileExists(atPath: home + "/powervpn-native-helper") else {
      return nil
    }
    let required = [
      "/runtime/libexec/ipsec/charon", "/strongswan.conf", "/allowed-hosts", "/owner-uid",
    ]
    guard required.allSatisfy({ FileManager.default.fileExists(atPath: home + $0) }),
      let expected = expectedInstalledFrom(),
      let installed = try? String(contentsOfFile: home + "/installed-from", encoding: .utf8)
    else { return false }
    return installed == expected
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
    let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return String(decoding: bytes, as: UTF8.self)
  }
}
