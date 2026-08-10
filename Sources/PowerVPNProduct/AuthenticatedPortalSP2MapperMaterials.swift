import Darwin
import PowerVPNCore
import PowerVPNPortal

struct PortalSP2ContextTextMaterial: VendorCharonStartTextMaterial {
  let byteCount: Int
  private let context: AuthenticatedPortalContext

  init(_ context: AuthenticatedPortalContext) throws {
    self.context = context
    byteCount = try context.withVendorGatewayBytes(\.count)
  }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try context.withVendorGatewayBytes(body)
  }
}

struct PortalSP2BorrowedTextMaterial: VendorCharonStartTextMaterial {
  let byteCount: Int
  private let scalar: PortalSP2Scalar

  init(_ scalar: PortalSP2Scalar) throws {
    self.scalar = scalar
    byteCount = try scalar.byteCount
  }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try scalar.withBytes(body)
  }
}

struct PortalSP2SliceTextMaterial: VendorCharonStartTextMaterial {
  let byteCount: Int
  private let scalar: PortalSP2Scalar
  private let range: Range<Int>

  init(_ scalar: PortalSP2Scalar, range: Range<Int>) throws {
    guard range.lowerBound >= 0, range.upperBound <= (try scalar.byteCount) else {
      throw AuthenticatedPortalSnapshotMappingError.materialTooLarge
    }
    self.scalar = scalar
    self.range = range
    byteCount = range.count
  }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try scalar.withBytes { bytes in
      let start = bytes.baseAddress?.advanced(by: range.lowerBound)
      return try body(UnsafeRawBufferPointer(start: start, count: range.count))
    }
  }
}

struct PortalSP2ConstantTextMaterial: VendorCharonStartTextMaterial {
  let bytes: [UInt8]
  var byteCount: Int { bytes.count }

  init(_ bytes: [UInt8]) { self.bytes = bytes }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try bytes.withUnsafeBytes(body)
  }
}

struct PortalSP2ComposedTextMaterial: VendorCharonStartTextMaterial {
  let byteCount: Int
  private let components: [any VendorCharonStartTextMaterial]

  init(_ components: [any VendorCharonStartTextMaterial]) throws {
    var count = 0
    for component in components {
      let (next, overflow) = count.addingReportingOverflow(component.byteCount)
      guard !overflow, next <= VendorCharonStartValidator.maximumTextBytes else {
        throw AuthenticatedPortalSnapshotMappingError.materialTooLarge
      }
      count = next
    }
    self.components = components
    byteCount = count
  }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    guard let storage = malloc(max(byteCount, 1)) else {
      throw AuthenticatedPortalSnapshotMappingError.materialTooLarge
    }
    defer {
      if byteCount > 0 { _ = memset_s(storage, byteCount, 0, byteCount) }
      free(storage)
    }
    var offset = 0
    for component in components {
      try component.withUnsafeUTF8Bytes { bytes in
        if !bytes.isEmpty {
          _ = memcpy(storage.advanced(by: offset), bytes.baseAddress!, bytes.count)
        }
        offset += bytes.count
      }
    }
    return try body(UnsafeRawBufferPointer(start: storage, count: byteCount))
  }
}
