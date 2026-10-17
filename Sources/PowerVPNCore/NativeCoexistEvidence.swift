import CryptoKit
import Darwin
import Foundation

package enum NativeCoexistFailure: Error {
  case stageDirectoryRejected, stageFileRejected, stageWriteFailed
  case scopeRejected, gatewayRejected, baselineRejected, routeRejected
}

/// Only fixed, value-free phase events are written to the monitor's journal.
/// The separate gateway descriptor contains a public endpoint, never auth data.
package final class NativeCoexistEvidence: @unchecked Sendable {
  package static let frozenTargetHost = "11.11.37.52"
  package static let frozenGatewayHost = "166.111.143.19"

  package static func requireFrozenScope(targetHost: String, portalHost: String?) throws {
    guard targetHost == frozenTargetHost, portalHost == frozenGatewayHost else {
      throw NativeCoexistFailure.scopeRejected
    }
  }

  static func requireFrozenGateway(_ gateway: String, expectedOriginHost: String) throws {
    guard gateway == frozenGatewayHost, expectedOriginHost == frozenGatewayHost else {
      throw NativeCoexistFailure.gatewayRejected
    }
  }

  package static let controlDirectory = "/var/run/powervpn-native-acceptance/control"
  package static let baselinePath = "/var/run/powervpn-native-acceptance/evidence/utun.before.txt"
  package static let ownedUtunsPath =
    "/var/run/powervpn-native-acceptance/evidence/native-owned-utuns.txt"
  private let descriptor: Int32
  private let metadata: stat
  private let lock = NSLock()
  private let nonce = UUID().uuidString.lowercased()

  package enum Phase: String {
    case beforePortal = "before_portal"
    case portalAcquired = "portal_acquired"
    case gatewayObserved = "gateway_observed"
    case beforeIKE = "before_ike"
    case ikeEstablished = "ike_established"
    case beforeChild = "before_child"
    case childInstalled = "child_installed"
    case nativeRouteVerified = "native_route_verified"
    case sshFinished = "ssh_finished"
    case cleanupStarted = "cleanup_started"
    case portalClosed = "portal_closed"
    case finished
  }

  package init() throws {
    var before = stat()
    guard lstat(Self.controlDirectory, &before) == 0,
      before.st_mode & S_IFMT == S_IFDIR, before.st_uid == getuid(),
      before.st_mode & 0o7777 == 0o700
    else { throw NativeCoexistFailure.stageDirectoryRejected }
    let fd = open(Self.controlDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw NativeCoexistFailure.stageDirectoryRejected }
    var opened = stat()
    guard fstat(fd, &opened) == 0, before.st_dev == opened.st_dev, before.st_ino == opened.st_ino
    else {
      close(fd)
      throw NativeCoexistFailure.stageDirectoryRejected
    }
    descriptor = fd
    metadata = opened
  }

  deinit { close(descriptor) }

  package func record(_ phase: Phase, success: Bool = true) throws {
    try lock.withLock {
      try requireDirectoryUnchanged()
      let fd = openat(
        descriptor, "native.stages.jsonl", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
        0o600)
      guard fd >= 0 else { throw NativeCoexistFailure.stageFileRejected }
      defer { close(fd) }
      var info = stat()
      guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
        info.st_mode & 0o7777 == 0o600, info.st_nlink == 1, info.st_size <= 65_536
      else {
        throw NativeCoexistFailure.stageFileRejected
      }
      var data = try JSONSerialization.data(
        withJSONObject: [
          "schemaVersion": 1, "trialNonce": nonce, "pid": Int(getpid()),
          "target": "thu52", "phase": phase.rawValue, "success": success,
        ], options: [.sortedKeys])
      data.append(10)
      try writeAll(data, fd: fd)
    }
  }

  package func recordGateway(_ gateway: String, expectedOriginHost: String) throws {
    try Self.requireFrozenGateway(gateway, expectedOriginHost: expectedOriginHost)
    try lock.withLock {
      try requireDirectoryUnchanged()
      let name = ".native.gateway." + nonce + ".tmp"
      let fd = openat(descriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
      guard fd >= 0 else { throw NativeCoexistFailure.stageFileRejected }
      defer {
        close(fd)
        unlinkat(descriptor, name, 0)
      }
      let data = try JSONSerialization.data(
        withJSONObject: [
          "schemaVersion": 1, "trialNonce": nonce, "pid": Int(getpid()), "target": "thu52",
          "gatewayIPv4": gateway, "source": "authenticated_portal_origin",
          "routeMutationRequested": false,
          "gatewaySHA256": SHA256.hash(data: Data(gateway.utf8)).map { String(format: "%02x", $0) }
            .joined(),
        ], options: [.sortedKeys])
      try writeAll(data, fd: fd)
      guard fsync(fd) == 0 else { throw NativeCoexistFailure.stageWriteFailed }
      var old = stat()
      if fstatat(descriptor, "native.gateway.json", &old, AT_SYMLINK_NOFOLLOW) == 0 {
        guard old.st_mode & S_IFMT == S_IFREG, old.st_uid == getuid(), old.st_nlink == 1,
          old.st_mode & 0o7777 == 0o600
        else { throw NativeCoexistFailure.stageFileRejected }
      } else if errno != ENOENT {
        throw NativeCoexistFailure.stageFileRejected
      }
      guard renameat(descriptor, name, descriptor, "native.gateway.json") == 0 else {
        throw NativeCoexistFailure.stageWriteFailed
      }
    }
    try record(.gatewayObserved)
  }

  package static func verifyNativeRoute(target: String) async throws -> Bool {
    let baseline = try readBaseline()
    let result = await readRoute(target)
    guard result.succeeded else { throw NativeCoexistFailure.routeRejected }
    guard let interface = routeInterface(result.stdout, target: target, baseline: baseline) else {
      return false
    }
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while ContinuousClock.now < deadline {
      try Task.checkCancellation()
      if let ledger = try? ownedInterfaces(from: readRootFile(ownedUtunsPath, requiresFresh: true)),
        ownedRouteMatches(
          interface: interface, ledger: ledger, currentInterfaceIndex: if_nametoindex(interface))
      {
        // Ownership evidence can take one monitor tick to arrive. Re-read the
        // route after that wait so a stale route observation cannot admit SSH.
        let current = await readRoute(target)
        return current.succeeded
          && routeInterface(current.stdout, target: target, baseline: baseline) == interface
          && ownedRouteMatches(
            interface: interface, ledger: ledger, currentInterfaceIndex: if_nametoindex(interface))
      }
      try await Task.sleep(for: .milliseconds(100))
    }
    return false
  }

  private static func readRoute(_ target: String) async -> BoundedCommandResult {
    await BoundedCommandRunner().run(
      BoundedCommandRequest(
        executable: "/sbin/route", arguments: ["-n", "get", target], timeoutMilliseconds: 2_000,
        stdoutLimitBytes: 16_384, stderrLimitBytes: 4_096))
  }

  static func routeIsNewUtun(_ output: Data, target: String, baseline: Set<String>) -> Bool {
    routeInterface(output, target: target, baseline: baseline) != nil
  }

  private static func routeInterface(_ output: Data, target: String, baseline: Set<String>)
    -> String?
  {
    guard validIPv4(target), let text = String(data: output, encoding: .utf8), !output.contains(0)
    else { return nil }
    var values: [String: String] = [:]
    for raw in text.split(separator: "\n") {
      guard let colon = raw.firstIndex(of: ":") else { continue }
      let key = raw[..<colon].trimmingCharacters(in: .whitespaces)
      guard ["route to", "destination", "interface", "mask", "flags"].contains(key) else {
        continue
      }
      let value = raw[raw.index(after: colon)...].trimmingCharacters(in: .whitespaces)
      guard values.updateValue(value, forKey: key) == nil else { return nil }
    }
    guard values["route to"] == target, values["destination"] == target,
      values["mask"] == nil || values["mask"] == "255.255.255.255",
      let interface = values["interface"], exactUtun(interface), interface != "utun9",
      !baseline.contains(interface),
      let flags = values["flags"], flags.hasPrefix("<"), flags.hasSuffix(">"),
      flags.dropFirst().dropLast().split(separator: ",").contains("HOST"),
      flags.dropFirst().dropLast().split(separator: ",").contains("UP")
    else { return nil }
    return interface
  }

  static func ownedInterfaces(from data: Data) throws -> [String: UInt32] {
    guard !data.contains(0), let text = String(data: data, encoding: .utf8) else {
      throw NativeCoexistFailure.baselineRejected
    }
    var output: [String: UInt32] = [:]
    for line in text.split(separator: "\n") {
      let parts = line.split(whereSeparator: \.isWhitespace)
      guard parts.count == 2, exactUtun(String(parts[0])),
        let index = UInt32(parts[1]), index > 0,
        parts[1] == Substring(String(index)), output[String(parts[0])] == nil,
        !output.values.contains(index)
      else { throw NativeCoexistFailure.baselineRejected }
      output[String(parts[0])] = index
    }
    guard !output.isEmpty else { throw NativeCoexistFailure.baselineRejected }
    return output
  }

  static func ownedRouteMatches(
    interface: String, ledger: [String: UInt32], currentInterfaceIndex: UInt32
  ) -> Bool {
    currentInterfaceIndex > 0 && ledger[interface] == currentInterfaceIndex
  }

  private static func readBaseline() throws -> Set<String> {
    let bytes = try readRootFile(baselinePath)
    guard let text = String(data: bytes, encoding: .utf8), !bytes.contains(0) else {
      throw NativeCoexistFailure.baselineRejected
    }
    let names = text.split(whereSeparator: \.isWhitespace).map(String.init)
    guard !names.isEmpty, names.allSatisfy(exactUtun), Set(names).count == names.count,
      names.contains("utun9")
    else { throw NativeCoexistFailure.baselineRejected }
    return Set(names)
  }

  private static func readRootFile(_ path: String, requiresFresh: Bool = false) throws -> Data {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw NativeCoexistFailure.baselineRejected }
    defer { close(fd) }
    var before = stat()
    guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
      before.st_uid == 0, before.st_mode & 0o022 == 0, before.st_nlink == 1,
      before.st_size > 0, before.st_size <= 8_192
    else { throw NativeCoexistFailure.baselineRejected }
    if requiresFresh {
      let modified =
        Double(before.st_mtimespec.tv_sec) + Double(before.st_mtimespec.tv_nsec) / 1_000_000_000
      let age = Date().timeIntervalSince1970 - modified
      guard (-1...3).contains(age) else { throw NativeCoexistFailure.baselineRejected }
    }
    var bytes = [UInt8](repeating: 0, count: Int(before.st_size))
    let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
    var after = stat()
    guard count == bytes.count, fstat(fd, &after) == 0,
      before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
      before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec
    else { throw NativeCoexistFailure.baselineRejected }
    return Data(bytes)
  }

  private func requireDirectoryUnchanged() throws {
    var current = stat()
    guard lstat(Self.controlDirectory, &current) == 0, current.st_dev == metadata.st_dev,
      current.st_ino == metadata.st_ino, current.st_uid == getuid(),
      current.st_mode & 0o7777 == 0o700
    else { throw NativeCoexistFailure.stageDirectoryRejected }
  }

  private func writeAll(_ data: Data, fd: Int32) throws {
    var offset = 0
    while offset < data.count {
      let count = data.withUnsafeBytes {
        Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset)
      }
      if count > 0 {
        offset += count
      } else if count < 0 && errno == EINTR {
        continue
      } else {
        throw NativeCoexistFailure.stageWriteFailed
      }
    }
  }

  private static func exactUtun(_ name: String) -> Bool {
    name.hasPrefix("utun") && !name.dropFirst(4).isEmpty
      && name.dropFirst(4).utf8.allSatisfy { (48...57).contains($0) }
  }

  private static func validIPv4(_ text: String) -> Bool {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    return parts.count == 4
      && parts.allSatisfy { part in
        guard let byte = UInt8(part) else { return false }
        return part == Substring(String(byte))
      }
  }
}
