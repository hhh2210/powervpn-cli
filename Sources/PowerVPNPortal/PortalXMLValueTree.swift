import Foundation

enum PortalXMLValueError: Error, Equatable, Sendable {
  case notText
}

struct PortalXMLLimits: Equatable, Sendable {
  static let boundedDefault = PortalXMLLimits(
    maximumInputBytes: 1_048_576,
    maximumDepth: 32,
    maximumNodes: 4_096,
    maximumTextBytes: 1_048_576,
    maximumAttributesPerElement: 64,
    maximumAttributeBytes: 262_144
  )

  let maximumInputBytes: Int
  let maximumDepth: Int
  let maximumNodes: Int
  let maximumTextBytes: Int
  let maximumAttributesPerElement: Int
  let maximumAttributeBytes: Int

  var isValid: Bool {
    maximumInputBytes > 0 && maximumDepth > 0 && maximumNodes > 0
      && maximumTextBytes >= 0 && maximumAttributesPerElement >= 0
      && maximumAttributeBytes >= 0
  }
}

enum PortalXMLStructuralError: Error, Equatable, Sendable, CustomStringConvertible {
  case invalidLimits
  case inputTooLarge
  case forbiddenDeclaration
  case depthLimitExceeded
  case nodeLimitExceeded
  case textLimitExceeded
  case attributeLimitExceeded
  case duplicateRoot
  case trailingContent
  case malformed
  case storageUnavailable

  var description: String {
    switch self {
    case .invalidLimits: "invalid XML parser limits"
    case .inputTooLarge: "XML input exceeded the bounded limit"
    case .forbiddenDeclaration: "XML declarations requiring DTD or entities are forbidden"
    case .depthLimitExceeded: "XML depth exceeded the bounded limit"
    case .nodeLimitExceeded: "XML node count exceeded the bounded limit"
    case .textLimitExceeded: "XML text exceeded the bounded limit"
    case .attributeLimitExceeded: "XML attributes exceeded the bounded limit"
    case .duplicateRoot: "XML contained more than one root"
    case .trailingContent: "XML contained non-structural trailing content"
    case .malformed: "XML was malformed"
    case .storageUnavailable: "secure XML storage unavailable"
    }
  }
}

/// Attribute names are structural metadata. Attribute values stay in owned,
/// explicitly erasable storage and are never exposed as `String`.
struct PortalXMLAttribute: @unchecked Sendable {
  let name: String
  private let value: SecureBytes

  init(name: String, value: SecureBytes) {
    self.name = name
    self.value = value
  }

  var valueByteCount: Int { value.count }

  func withValueBytes<Result>(
    _ operation: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try value.withUnsafeBytes(operation)
  }

  func erase() {
    value.erase()
  }
}

/// Ordered XML infoset content. Adjacent SAX character callbacks are merged,
/// while text/child ordering is preserved. This is structural data only; it
/// does not imply that a LeadSec compatibility profile accepts the document.
enum PortalXMLContent: @unchecked Sendable {
  case text(SecureBytes)
  case element(PortalXMLElement)

  var textByteCount: Int? {
    guard case .text(let bytes) = self else { return nil }
    return bytes.count
  }

  var childElement: PortalXMLElement? {
    guard case .element(let element) = self else { return nil }
    return element
  }

  func withTextBytes<Result>(
    _ operation: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    guard case .text(let bytes) = self else { throw PortalXMLValueError.notText }
    return try bytes.withUnsafeBytes(operation)
  }

  func erase() {
    switch self {
    case .text(let bytes):
      bytes.erase()
    case .element(let element):
      element.erase()
    }
  }
}

/// An immutable structural element. `erase()` clears every scalar and
/// attribute value below this node; `deinit` performs the same cascade.
final class PortalXMLElement: @unchecked Sendable {
  let name: String
  let attributes: [PortalXMLAttribute]
  let contents: [PortalXMLContent]

  init(
    name: String,
    attributes: [PortalXMLAttribute],
    contents: [PortalXMLContent]
  ) {
    self.name = name
    self.attributes = attributes
    self.contents = contents
  }

  func attribute(named name: String) -> PortalXMLAttribute? {
    attributes.first { $0.name == name }
  }

  var childElements: [PortalXMLElement] {
    contents.compactMap(\.childElement)
  }

  func erase() {
    for attribute in attributes { attribute.erase() }
    for content in contents { content.erase() }
  }

  deinit {
    erase()
  }
}

/// Owns a parsed root and provides the checkpoint's explicit erasure boundary.
/// Erasure is idempotent because every underlying `SecureBytes` is idempotent.
final class PortalXMLDocument: @unchecked Sendable {
  let root: PortalXMLElement

  init(root: PortalXMLElement) {
    self.root = root
  }

  func erase() {
    root.erase()
  }

  deinit {
    erase()
  }
}

final class PortalXMLElementBuilder {
  let name: String
  var attributes: [PortalXMLAttribute]
  var contents: [PortalXMLContent] = []
  var textChunks: [SecureBytes] = []

  init(name: String, attributes: [PortalXMLAttribute]) {
    self.name = name
    self.attributes = attributes
  }

  func flushText(
    observer: (@Sendable (UnsafeRawBufferPointer) -> Void)?
  ) throws {
    guard !textChunks.isEmpty else { return }
    let count = textChunks.reduce(0) { $0 + $1.count }
    guard let storage = malloc(max(count, 1)) else {
      throw PortalXMLStructuralError.storageUnavailable
    }
    defer {
      if count > 0 { _ = memset_s(storage, count, 0, count) }
      free(storage)
    }
    var offset = 0
    for chunk in textChunks {
      try chunk.withUnsafeBytes { source in
        if !source.isEmpty {
          _ = memcpy(storage.advanced(by: offset), source.baseAddress!, source.count)
        }
        offset += source.count
      }
    }
    let text = try SecureBytes(
      copying: UnsafeRawBufferPointer(start: storage, count: count),
      eraseObserver: observer
    )
    for chunk in textChunks { chunk.erase() }
    textChunks.removeAll()
    contents.append(.text(text))
  }

  func finish(
    observer: (@Sendable (UnsafeRawBufferPointer) -> Void)?
  ) throws -> PortalXMLElement {
    try flushText(observer: observer)
    let element = PortalXMLElement(name: name, attributes: attributes, contents: contents)
    attributes.removeAll()
    contents.removeAll()
    return element
  }

  func erase() {
    for attribute in attributes { attribute.erase() }
    for content in contents { content.erase() }
    for chunk in textChunks { chunk.erase() }
    attributes.removeAll()
    contents.removeAll()
    textChunks.removeAll()
  }

  deinit { erase() }
}

func securePortalXMLUTF8(
  _ string: String,
  observer: (@Sendable (UnsafeRawBufferPointer) -> Void)?
) throws -> SecureBytes {
  var intermediate = Array(string.utf8)
  defer {
    intermediate.withUnsafeMutableBytes { bytes in
      if !bytes.isEmpty { _ = memset_s(bytes.baseAddress!, bytes.count, 0, bytes.count) }
    }
  }
  return try SecureBytes(copying: intermediate, eraseObserver: observer)
}

extension String {
  var utf16LittleEndian: [UInt8] { utf16.flatMap { [UInt8($0 & 0xff), UInt8($0 >> 8)] } }
  var utf16BigEndian: [UInt8] { utf16.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xff)] } }
  var utf32LittleEndian: [UInt8] {
    unicodeScalars.flatMap { scalar in
      let value = scalar.value
      return [UInt8(value & 0xff), UInt8((value >> 8) & 0xff), UInt8((value >> 16) & 0xff), 0]
    }
  }
  var utf32BigEndian: [UInt8] {
    unicodeScalars.flatMap { scalar in
      let value = scalar.value
      return [0, UInt8((value >> 16) & 0xff), UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
    }
  }
}
