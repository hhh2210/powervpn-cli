struct VendorAppSessionLocatedRecord {
  let root: VendorAppSessionLogNode
  let dictionaryRange: Range<Int>
}

enum VendorAppSessionRecordFraming {
  private static let maximumRecordBytes = 16_384

  private enum RPC {
    case start
    case getVersion
    case updown
    case stop
    case logout
    case missing
    case nonScalar
    case unknown
  }

  static func singleStartRecord(
    _ bytes: UnsafeRawBufferPointer
  ) throws -> VendorAppSessionLocatedRecord {
    var lineStart = 0
    var start: VendorAppSessionLocatedRecord?
    var firstProducerIdentity: Range<Int>?
    var requestCount = 0
    var startCount = 0
    var hasAmbiguousProducerSet = false
    var sawMissingRPC = false
    var sawNonScalarRPC = false
    var sawUnknownRPC = false

    while lineStart < bytes.count {
      guard let lineEnd = newline(in: bytes, from: lineStart) else {
        throw VendorAppSessionSnapshotError.incomplete
      }
      switch markerCount(in: bytes, range: lineStart..<lineEnd) {
      case .zero:
        lineStart = lineEnd + 1
        continue
      case .many:
        throw VendorAppSessionSnapshotError.recordRejected(.markerMultiplicity)
      case .one:
        break
      }
      guard let header = try recordHeader(at: lineStart, in: bytes) else {
        throw VendorAppSessionSnapshotError.recordRejected(.markerUnbalanced)
      }

      requestCount += 1
      if let firstProducerIdentity {
        if !sameProducerIdentity(bytes, firstProducerIdentity, header.producerIdentityRange) {
          hasAmbiguousProducerSet = true
        }
      } else {
        firstProducerIdentity = header.producerIdentityRange
      }

      let dictionaryStart = header.dictionaryStart
      let suffix = UnsafeRawBufferPointer(rebasing: bytes[dictionaryStart..<bytes.count])
      var parser = VendorAppSessionLogParser(bytes: suffix)
      let parsed: (VendorAppSessionLogNode, Int)
      do {
        parsed = try parser.parsePrefix()
      } catch let error as VendorAppSessionLogParserError {
        guard parser.consumedByteCount < maximumRecordBytes else {
          throw VendorAppSessionSnapshotError.recordRejected(.windowLimitReached)
        }
        switch error {
        case .incomplete:
          throw VendorAppSessionSnapshotError.incomplete
        case .invalidEncoding:
          throw VendorAppSessionSnapshotError.recordRejected(.invalidEncoding)
        case .syntax:
          throw VendorAppSessionSnapshotError.recordRejected(.dictionarySyntax)
        }
      }
      guard parsed.1 > 0 else {
        throw VendorAppSessionSnapshotError.recordRejected(.dictionaryRootShape)
      }
      guard parsed.1 <= maximumRecordBytes else {
        throw VendorAppSessionSnapshotError.recordRejected(.windowLimitReached)
      }
      let end = dictionaryStart + parsed.1
      guard end < bytes.count else {
        throw VendorAppSessionSnapshotError.incomplete
      }
      guard bytes[end] == 0x20 else {
        throw VendorAppSessionSnapshotError.recordRejected(.markerUnbalanced)
      }
      guard end + 1 < bytes.count else {
        throw VendorAppSessionSnapshotError.incomplete
      }
      guard bytes[end + 1] == 0x0A else {
        throw VendorAppSessionSnapshotError.recordRejected(.markerUnbalanced)
      }

      switch try rpc(of: parsed.0, bytes: suffix) {
      case .start:
        startCount += 1
        if start == nil {
          start = VendorAppSessionLocatedRecord(
            root: parsed.0,
            dictionaryRange: dictionaryStart..<end
          )
        }
      case .getVersion, .updown, .stop:
        break
      case .logout:
        throw VendorAppSessionSnapshotError.stale
      case .missing:
        sawMissingRPC = true
      case .nonScalar:
        sawNonScalarRPC = true
      case .unknown:
        sawUnknownRPC = true
      }
      lineStart = end + 2
    }

    if hasAmbiguousProducerSet {
      throw VendorAppSessionSnapshotError.recordRejected(.ambiguousRecordSet)
    }
    if startCount > 1 {
      throw VendorAppSessionSnapshotError.recordRejected(.duplicateStartRecord)
    }
    if sawMissingRPC {
      throw VendorAppSessionSnapshotError.recordRejected(.rpcMissing)
    }
    if sawNonScalarRPC {
      throw VendorAppSessionSnapshotError.recordRejected(.rpcNonScalar)
    }
    if sawUnknownRPC {
      throw VendorAppSessionSnapshotError.recordRejected(.rpcUnknown)
    }
    if let start { return start }
    guard requestCount > 0 else {
      throw VendorAppSessionSnapshotError.recordRejected(.markerMissing)
    }
    throw VendorAppSessionSnapshotError.recordRejected(.noStartRecord)
  }

  private static func rpc(
    of root: VendorAppSessionLogNode,
    bytes: UnsafeRawBufferPointer
  ) throws -> RPC {
    guard let dictionary = root.dictionary else {
      throw VendorAppSessionSnapshotError.recordRejected(.dictionaryRootShape)
    }
    guard let node = dictionary["rpc"] else { return .missing }
    guard let range = node.scalarRange,
      range.lowerBound >= 0,
      range.upperBound <= bytes.count
    else { return .nonScalar }
    if equal(bytes, range, "start_connection") { return .start }
    if equal(bytes, range, "get_version") { return .getVersion }
    if equal(bytes, range, "updown_nc") { return .updown }
    if equal(bytes, range, "stop_connection") { return .stop }
    if equal(bytes, range, "logout") { return .logout }
    return .unknown
  }

  private static func equal(
    _ bytes: UnsafeRawBufferPointer,
    _ range: Range<Int>,
    _ text: StaticString
  ) -> Bool {
    text.withUTF8Buffer { expected in
      range.count == expected.count
        && zip(range, expected).allSatisfy { bytes[$0.0] == $0.1 }
    }
  }

}
