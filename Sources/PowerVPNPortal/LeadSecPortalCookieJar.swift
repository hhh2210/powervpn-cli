import Darwin
import Foundation

enum LeadSecPortalCookieJarError: Error, Equatable, Sendable {
  case ambiguousSetCookieFraming, erased, invalidLanguageState
  case invalidPasswordURL, invalidSetCookieBytes, missingSetCookie
  case sessionAlreadyStored, sizeOverflow, unsupportedSetCookie, writeMismatch
}

enum LeadSecSetCookieProjection: Equatable, Sendable {
  /// Foundation exposes one projected value; this does not prove that the
  /// original HTTP response contained exactly one wire header field.
  case foundationSingleValue, unavailableOrAmbiguous
}

final class LeadSecPortalCookieJar: @unchecked Sendable {
  private static let httpsPrefix = Array("https://".utf8)
  private static let passwordPath = Array(PortalWireContract.passwordPath.utf8)
  private static let sessionPrefix = Array("VSG_SESSIONID".utf8)
  private static let verifyCodePrefix = Array("verifycode".utf8)
  private static let ticketPrefix = Array("VSG_SMC_Ticket".utf8)
  private static let originPrefix = Array(" ORIGINURL=".utf8)
  private static let entrySuffix = Array("; ".utf8)
  private static let languageMarker = Array("VSG_LANGUAGE".utf8)
  private static let chineseToken = Array("VSG_LANGUAGE=zh_CN".utf8)
  private static let englishToken = Array("VSG_LANGUAGE=en_US".utf8)
  private static let chineseReplacement = Array(" VSG_LANGUAGE=zh_CN".utf8)
  private static let englishReplacement = Array(" VSG_LANGUAGE=en_US".utf8)
  private static let chineseFallback = Array(" VSG_LANGUAGE=zh_CN; ".utf8)

  private let lock = NSLock()
  private let languageIndex: Int
  private var sessionEntry: SecureBytes?
  private var isErased = false

  convenience init(profile: InstalledPortalProfile) throws {
    try self.init(languageIndex: profile.vendorLanguageIndex)
  }

  init(languageIndex: Int) throws {
    guard (0...2).contains(languageIndex) else {
      throw LeadSecPortalCookieJarError.invalidLanguageState
    }
    self.languageIndex = languageIndex
  }

  var retainedSessionByteCount: Int {
    lock.withLock { sessionEntry?.count ?? 0 }
  }

  func acceptPasswordResponse(
    setCookieHeader: SecureBytes?,
    projection: LeadSecSetCookieProjection,
    passwordURL: SecureBytes
  ) throws {
    try lock.withLock {
      guard !isErased else { throw LeadSecPortalCookieJarError.erased }
      guard projection == .foundationSingleValue else {
        throw LeadSecPortalCookieJarError.ambiguousSetCookieFraming
      }
      guard sessionEntry == nil else {
        throw LeadSecPortalCookieJarError.sessionAlreadyStored
      }
      guard let setCookieHeader else { throw LeadSecPortalCookieJarError.missingSetCookie }
      sessionEntry = try Self.makeSessionEntry(
        setCookieHeader: setCookieHeader,
        passwordURL: passwordURL
      )
    }
  }

  func makeOutgoingCookieHeader() throws -> SecureBytes {
    try lock.withLock {
      guard !isErased else { throw LeadSecPortalCookieJarError.erased }
      let sessionHasLanguage =
        try sessionEntry?.withUnsafeBytes {
          Self.contains($0, Self.languageMarker)
        } ?? false
      let appendFallback = !sessionHasLanguage
      let baseCount = try Self.adding(
        sessionEntry?.count ?? 0,
        appendFallback ? Self.chineseFallback.count : 0
      )
      let base = try SecureBytes.allocate(count: baseCount) { output in
        var writer = ByteWriter(output)
        if let sessionEntry {
          try sessionEntry.withUnsafeBytes { try writer.write($0) }
        }
        if appendFallback { try writer.write(Self.chineseFallback) }
        guard writer.remaining == 0 else { throw LeadSecPortalCookieJarError.writeMismatch }
      }
      defer { base.erase() }

      let source = languageIndex == 2 ? Self.chineseToken : Self.englishToken
      let replacement =
        languageIndex == 2
        ? Self.englishReplacement
        : Self.chineseReplacement
      return try base.withUnsafeBytes { bytes in
        let occurrences = Self.countOccurrences(of: source, in: bytes)
        let growth = try Self.multiplying(occurrences, replacement.count - source.count)
        let outputCount = try Self.adding(bytes.count, growth)
        return try SecureBytes.allocate(count: outputCount) { output in
          var writer = ByteWriter(output)
          try writer.writeReplacing(bytes, source: source, replacement: replacement)
          guard writer.remaining == 0 else {
            throw LeadSecPortalCookieJarError.writeMismatch
          }
        }
      }
    }
  }

  func erase() {
    lock.withLock {
      guard !isErased else { return }
      sessionEntry?.erase()
      sessionEntry = nil
      isErased = true
    }
  }

  deinit {
    erase()
  }

  private static func makeSessionEntry(
    setCookieHeader: SecureBytes,
    passwordURL: SecureBytes
  ) throws -> SecureBytes {
    try setCookieHeader.withUnsafeBytes { header in
      guard !header.isEmpty, header.allSatisfy({ (0x20...0x7e).contains($0) }) else {
        throw LeadSecPortalCookieJarError.invalidSetCookieBytes
      }
      guard !hasPrefix(header, verifyCodePrefix), !hasPrefix(header, ticketPrefix),
        hasPrefix(header, sessionPrefix)
      else { throw LeadSecPortalCookieJarError.unsupportedSetCookie }

      return try passwordURL.withUnsafeBytes { url in
        guard isPasswordURL(url) else {
          throw LeadSecPortalCookieJarError.invalidPasswordURL
        }
        let fixedCount = try adding(originPrefix.count, entrySuffix.count)
        let total = try adding(try adding(header.count, url.count), fixedCount)
        return try SecureBytes.allocate(count: total) { output in
          var writer = ByteWriter(output)
          try writer.write(header)
          try writer.write(originPrefix)
          try writer.write(url)
          try writer.write(entrySuffix)
          guard writer.remaining == 0 else {
            throw LeadSecPortalCookieJarError.writeMismatch
          }
        }
      }
    }
  }

  private static func isPasswordURL(_ bytes: UnsafeRawBufferPointer) -> Bool {
    guard bytes.count > httpsPrefix.count + passwordPath.count,
      bytes.allSatisfy({ (0x21...0x7e).contains($0) }),
      hasPrefix(bytes, httpsPrefix), hasSuffix(bytes, passwordPath),
      !bytes.contains(0x23), !bytes.contains(0x3f), !bytes.contains(0x40)
    else { return false }
    return true
  }

  private static func hasPrefix(_ bytes: UnsafeRawBufferPointer, _ prefix: [UInt8]) -> Bool {
    matches(bytes, prefix, at: 0)
  }

  private static func hasSuffix(_ bytes: UnsafeRawBufferPointer, _ suffix: [UInt8]) -> Bool {
    guard suffix.count <= bytes.count else { return false }
    return matches(bytes, suffix, at: bytes.count - suffix.count)
  }

  private static func contains(_ bytes: UnsafeRawBufferPointer, _ needle: [UInt8]) -> Bool {
    countOccurrences(of: needle, in: bytes) > 0
  }

  private static func countOccurrences(
    of needle: [UInt8],
    in bytes: UnsafeRawBufferPointer
  ) -> Int {
    guard !needle.isEmpty, needle.count <= bytes.count else { return 0 }
    var count = 0
    var index = 0
    while index <= bytes.count - needle.count {
      if matches(bytes, needle, at: index) {
        count += 1
        index += needle.count
      } else {
        index += 1
      }
    }
    return count
  }

  private static func matches(
    _ bytes: UnsafeRawBufferPointer,
    _ needle: [UInt8],
    at index: Int
  ) -> Bool {
    guard index >= 0, index + needle.count <= bytes.count else { return false }
    for offset in needle.indices where bytes[index + offset] != needle[offset] {
      return false
    }
    return true
  }

  private static func adding(_ lhs: Int, _ rhs: Int) throws -> Int {
    let (result, overflow) = lhs.addingReportingOverflow(rhs)
    guard !overflow else { throw LeadSecPortalCookieJarError.sizeOverflow }
    return result
  }

  private static func multiplying(_ lhs: Int, _ rhs: Int) throws -> Int {
    let (result, overflow) = lhs.multipliedReportingOverflow(by: rhs)
    guard !overflow else { throw LeadSecPortalCookieJarError.sizeOverflow }
    return result
  }

  private struct ByteWriter {
    private let output: UnsafeMutableRawBufferPointer
    private var offset = 0

    init(_ output: UnsafeMutableRawBufferPointer) {
      self.output = output
    }

    var remaining: Int { output.count - offset }

    mutating func write(_ bytes: UnsafeRawBufferPointer) throws {
      guard bytes.count <= remaining else { throw LeadSecPortalCookieJarError.writeMismatch }
      if !bytes.isEmpty {
        _ = memcpy(output.baseAddress!.advanced(by: offset), bytes.baseAddress!, bytes.count)
      }
      offset += bytes.count
    }

    mutating func write(_ bytes: [UInt8]) throws {
      try bytes.withUnsafeBytes { try write($0) }
    }

    mutating func writeReplacing(
      _ bytes: UnsafeRawBufferPointer,
      source: [UInt8],
      replacement: [UInt8]
    ) throws {
      var index = 0
      while index < bytes.count {
        if LeadSecPortalCookieJar.matches(bytes, source, at: index) {
          try write(replacement)
          index += source.count
        } else {
          guard remaining > 0 else { throw LeadSecPortalCookieJarError.writeMismatch }
          output[offset] = bytes[index]
          offset += 1
          index += 1
        }
      }
    }
  }
}
