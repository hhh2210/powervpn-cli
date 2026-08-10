import Foundation

enum X509SPKIError: Error, Equatable, Sendable {
  case invalidCertificate
  case sizeLimit
}

enum X509SPKIExtractor {
  static let maximumCertificateBytes = 65_536
  static let maximumSPKIBytes = 16_384

  static func extract(from certificateDER: Data) throws -> Data {
    guard !certificateDER.isEmpty,
      certificateDER.count <= maximumCertificateBytes
    else { throw X509SPKIError.sizeLimit }
    let bytes = Array(certificateDER)
    let certificate = try node(bytes, at: 0, limit: bytes.count, expectedTag: 0x30)
    guard certificate.full.upperBound == bytes.count else {
      throw X509SPKIError.invalidCertificate
    }
    let tbs = try node(
      bytes,
      at: certificate.content.lowerBound,
      limit: certificate.content.upperBound,
      expectedTag: 0x30
    )
    var cursor = tbs.content.lowerBound
    guard cursor < tbs.content.upperBound else { throw X509SPKIError.invalidCertificate }
    if bytes[cursor] == 0xa0 {
      cursor = try node(bytes, at: cursor, limit: tbs.content.upperBound).full.upperBound
    }
    for tag in [UInt8(0x02), 0x30, 0x30, 0x30, 0x30] {
      cursor = try node(
        bytes,
        at: cursor,
        limit: tbs.content.upperBound,
        expectedTag: tag
      ).full.upperBound
    }
    let spki = try node(
      bytes,
      at: cursor,
      limit: tbs.content.upperBound,
      expectedTag: 0x30
    )
    guard spki.full.count <= maximumSPKIBytes else { throw X509SPKIError.sizeLimit }
    let algorithm = try node(
      bytes,
      at: spki.content.lowerBound,
      limit: spki.content.upperBound,
      expectedTag: 0x30
    )
    let key = try node(
      bytes,
      at: algorithm.full.upperBound,
      limit: spki.content.upperBound,
      expectedTag: 0x03
    )
    guard key.full.upperBound == spki.content.upperBound, !key.content.isEmpty,
      bytes[key.content.lowerBound] <= 7
    else { throw X509SPKIError.invalidCertificate }
    return Data(bytes[spki.full])
  }

  private static func node(
    _ bytes: [UInt8],
    at offset: Int,
    limit: Int,
    expectedTag: UInt8? = nil
  ) throws -> DERNode {
    guard offset >= 0, offset < limit, limit <= bytes.count else {
      throw X509SPKIError.invalidCertificate
    }
    let tag = bytes[offset]
    guard tag & 0x1f != 0x1f, expectedTag == nil || tag == expectedTag else {
      throw X509SPKIError.invalidCertificate
    }
    let lengthOffset = offset + 1
    guard lengthOffset < limit else { throw X509SPKIError.invalidCertificate }
    let firstLength = bytes[lengthOffset]
    let contentOffset: Int
    let contentLength: Int
    if firstLength < 0x80 {
      contentOffset = lengthOffset + 1
      contentLength = Int(firstLength)
    } else {
      let lengthBytes = Int(firstLength & 0x7f)
      guard (1...4).contains(lengthBytes), lengthOffset + lengthBytes < limit,
        bytes[lengthOffset + 1] != 0
      else { throw X509SPKIError.invalidCertificate }
      var decoded = 0
      for index in 0..<lengthBytes {
        let byte = Int(bytes[lengthOffset + 1 + index])
        guard decoded <= (Int.max - byte) / 256 else {
          throw X509SPKIError.invalidCertificate
        }
        decoded = decoded * 256 + byte
      }
      guard decoded >= 0x80 else { throw X509SPKIError.invalidCertificate }
      contentOffset = lengthOffset + 1 + lengthBytes
      contentLength = decoded
    }
    guard contentLength <= limit - contentOffset else {
      throw X509SPKIError.invalidCertificate
    }
    return DERNode(
      full: offset..<(contentOffset + contentLength),
      content: contentOffset..<(contentOffset + contentLength)
    )
  }
}

private struct DERNode {
  let full: Range<Int>
  let content: Range<Int>
}
