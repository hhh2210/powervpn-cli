import Darwin
import Foundation

enum LeadSecPortalCookieJarError: Error, Equatable, Sendable {
  case ambiguousSetCookieFraming, erased, invalidLanguageState
  case invalidPasswordURL, invalidSetCookieBytes, missingSetCookie
  case generationMismatch, sessionAlreadyStored, sizeOverflow, unsupportedSetCookie, writeMismatch
}

enum LeadSecSetCookieProjection: Equatable, Sendable {
  case provenLastFieldWins(fieldCount: UInt32)
  /// Foundation may fold repeated fields, so its value cannot prove wire
  /// multiplicity and is never accepted by the compatibility profile.
  case foundationFoldedValue
  case unavailableOrAmbiguous
}

final class LeadSecPortalCookieJar: @unchecked Sendable {
  private static let httpsPrefix = Array("https://".utf8)
  private static let passwordPath = Array(PortalWireContract.passwordPath.utf8)
  private static let sessionNamePrefix = Array("VSG_SESSIONID".utf8)
  private static let sessionPrefix = Array("VSG_SESSIONID=".utf8)
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
  private var authenticationGeneration: PortalAuthenticationGeneration?
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

  func currentAuthenticationGeneration() throws -> PortalAuthenticationGeneration {
    try lock.withLock {
      guard !isErased, let authenticationGeneration,
        authenticationGeneration.isActive
      else {
        throw LeadSecPortalCookieJarError.missingSetCookie
      }
      return authenticationGeneration
    }
  }

  func acceptPasswordResponse(
    setCookieHeader: SecureBytes?,
    projection: LeadSecSetCookieProjection,
    passwordURL: SecureBytes
  ) throws {
    try lock.withLock {
      guard !isErased else { throw LeadSecPortalCookieJarError.erased }
      guard sessionEntry == nil else {
        throw LeadSecPortalCookieJarError.sessionAlreadyStored
      }
      guard let setCookieHeader else { throw LeadSecPortalCookieJarError.missingSetCookie }
      guard case .provenLastFieldWins(let fieldCount) = projection, fieldCount > 0 else {
        throw LeadSecPortalCookieJarError.ambiguousSetCookieFraming
      }
      sessionEntry = try Self.makeSessionEntry(
        setCookieHeader: setCookieHeader,
        passwordURL: passwordURL
      )
      authenticationGeneration = PortalAuthenticationGeneration()
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
        var writer = PortalCookieByteWriter(output)
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
          var writer = PortalCookieByteWriter(output)
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
      authenticationGeneration?.invalidate()
      authenticationGeneration = nil
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
        hasPrefix(header, sessionPrefix), !header.contains(0x2c),
        countOccurrences(of: sessionNamePrefix, in: header) == 1
      else { throw LeadSecPortalCookieJarError.unsupportedSetCookie }

      let sessionStart = sessionPrefix.count
      let sessionEnd = header[sessionStart...].firstIndex(of: 0x3b) ?? header.endIndex
      guard sessionStart < sessionEnd,
        header[sessionStart..<sessionEnd].allSatisfy(isCookieOctet)
      else { throw LeadSecPortalCookieJarError.unsupportedSetCookie }
      return try passwordURL.withUnsafeBytes { url in
        guard isPasswordURL(url) else {
          throw LeadSecPortalCookieJarError.invalidPasswordURL
        }
        let fixedCount = try adding(originPrefix.count, entrySuffix.count)
        let total = try adding(try adding(header.count, url.count), fixedCount)
        return try SecureBytes.allocate(count: total) { output in
          var writer = PortalCookieByteWriter(output)
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
    portalBytesMatch(bytes, prefix, at: 0)
  }

  private static func hasSuffix(_ bytes: UnsafeRawBufferPointer, _ suffix: [UInt8]) -> Bool {
    guard suffix.count <= bytes.count else { return false }
    return portalBytesMatch(bytes, suffix, at: bytes.count - suffix.count)
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
      if portalBytesMatch(bytes, needle, at: index) {
        count += 1
        index += needle.count
      } else {
        index += 1
      }
    }
    return count
  }

  private static func isCookieOctet(_ byte: UInt8) -> Bool {
    byte == 0x21 || (0x23...0x2b).contains(byte) || (0x2d...0x3a).contains(byte)
      || (0x3c...0x5b).contains(byte) || (0x5d...0x7e).contains(byte)
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

}
