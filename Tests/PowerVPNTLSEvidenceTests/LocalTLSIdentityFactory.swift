import Foundation
import Security
import Testing

enum LocalTLSIdentityFactoryError: Error {
  case setupFailed
  case commandFailed
  case importFailed
}

enum LocalTLSIdentityFactory {
  private static let syntheticPassphrase = "powervpn-local-test"
  private static let commandTimeout: DispatchTimeInterval = .seconds(5)
  private static let cleanupTimeout: DispatchTimeInterval = .seconds(1)
  private static let fileMode = NSNumber(value: Int16(0o600))
  private static let directoryMode = NSNumber(value: Int16(0o700))

  static func make() throws -> sec_identity_t {
    let fileManager = FileManager.default
    let root = fileManager.temporaryDirectory
      .appendingPathComponent("powervpn-tls-test-\(UUID().uuidString)", isDirectory: true)
    do {
      try fileManager.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: directoryMode]
      )
    } catch {
      throw LocalTLSIdentityFactoryError.setupFailed
    }
    defer {
      try? fileManager.removeItem(at: root)
      let residueObserved = fileManager.fileExists(atPath: root.path)
      #expect(!residueObserved)
    }

    let key = root.appendingPathComponent("key.pem")
    let certificate = root.appendingPathComponent("certificate.pem")
    let archive = root.appendingPathComponent("identity.p12")
    guard
      setMode(directoryMode, on: [root]),
      createSecureFiles([key, certificate, archive]),
      runOpenSSL([
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext",
        "subjectAltName=IP:127.0.0.1", "-keyout", key.path, "-out", certificate.path,
      ]),
      setMode(fileMode, on: [key, certificate]),
      runOpenSSL([
        "pkcs12", "-export", "-passout", "pass:\(syntheticPassphrase)", "-name",
        "powervpn-localhost-test",
        "-inkey", key.path, "-in", certificate.path, "-out", archive.path,
      ]),
      setMode(fileMode, on: [archive])
    else {
      throw LocalTLSIdentityFactoryError.commandFailed
    }

    var bytes: Data
    do {
      bytes = try Data(contentsOf: archive)
    } catch {
      throw LocalTLSIdentityFactoryError.importFailed
    }
    defer { bytes.resetBytes(in: 0..<bytes.count) }
    var imported: CFArray?
    let options = [kSecImportExportPassphrase as String: syntheticPassphrase] as CFDictionary
    guard
      SecPKCS12Import(bytes as CFData, options, &imported) == errSecSuccess,
      let entries = imported as? [[String: Any]],
      let rawIdentity = entries.first?[kSecImportItemIdentity as String],
      let identity = validatedIdentity(rawIdentity),
      let protocolIdentity = sec_identity_create(identity)
    else {
      throw LocalTLSIdentityFactoryError.importFailed
    }
    return protocolIdentity
  }

  private static func validatedIdentity(_ value: Any) -> SecIdentity? {
    let object = value as CFTypeRef
    guard CFGetTypeID(object) == SecIdentityGetTypeID() else { return nil }
    return unsafeDowncast(object, to: SecIdentity.self)
  }

  private static func setMode(_ mode: NSNumber, on files: [URL]) -> Bool {
    do {
      for file in files {
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: file.path)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard (attributes[.posixPermissions] as? NSNumber) == mode else { return false }
      }
      return true
    } catch {
      return false
    }
  }

  private static func createSecureFiles(_ files: [URL]) -> Bool {
    for file in files {
      guard
        FileManager.default.createFile(
          atPath: file.path,
          contents: Data(),
          attributes: [.posixPermissions: fileMode]
        )
      else { return false }
    }
    return setMode(fileMode, on: files)
  }

  private static func runOpenSSL(_ arguments: [String]) -> Bool {
    let process = Process()
    let exited = DispatchSemaphore(value: 0)
    process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    process.arguments = arguments
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    process.terminationHandler = { _ in exited.signal() }
    do {
      try process.run()
    } catch {
      return false
    }
    guard exited.wait(timeout: .now() + commandTimeout) == .success else {
      process.terminate()
      if exited.wait(timeout: .now() + cleanupTimeout) == .timedOut {
        _ = Darwin.kill(process.processIdentifier, SIGKILL)
        _ = exited.wait(timeout: .now() + cleanupTimeout)
      }
      return false
    }
    return process.terminationStatus == 0
  }
}
