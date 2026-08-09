import Foundation

/// A bounded structural reader, not a LeadSec compatibility validator.
///
/// Parsing consumes and erases `input` on every path. Foundation may retain
/// private parser buffers and delivers attribute/text callbacks as immutable
/// objects that this process cannot promise to zero. We copy callback values
/// immediately into app-owned storage, clear every app-owned intermediate, and
/// expose only `SecureBytes` values in the resulting tree.
struct PortalXMLStructuralParser: Sendable {
  private let limits: PortalXMLLimits
  private let eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)?

  init(
    limits: PortalXMLLimits = .boundedDefault,
    eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)? = nil
  ) throws {
    guard limits.isValid else { throw PortalXMLStructuralError.invalidLimits }
    self.limits = limits
    self.eraseObserver = eraseObserver
  }

  func parse(consuming input: SecureBytes) throws -> PortalXMLDocument {
    defer { input.erase() }
    guard input.count <= limits.maximumInputBytes else {
      throw PortalXMLStructuralError.inputTooLarge
    }
    guard input.count > 0 else { throw PortalXMLStructuralError.malformed }
    guard try !Self.containsForbiddenDeclaration(input) else {
      throw PortalXMLStructuralError.forbiddenDeclaration
    }

    let delegate = StructuralDelegate(limits: limits, eraseObserver: eraseObserver)
    let parser = XMLParser(stream: SecureBodyInputStream(bytes: input))
    parser.delegate = delegate
    parser.shouldProcessNamespaces = false
    parser.shouldReportNamespacePrefixes = false
    parser.shouldResolveExternalEntities = false
    parser.externalEntityResolvingPolicy = .never
    parser.allowedExternalEntityURLs = []

    guard parser.parse(), delegate.failure == nil else {
      delegate.erase()
      throw delegate.failure ?? PortalXMLStructuralError.malformed
    }
    do {
      return try delegate.finish()
    } catch {
      delegate.erase()
      throw error
    }
  }

  private static func containsForbiddenDeclaration(_ input: SecureBytes) throws -> Bool {
    let markers = ["<!--", "-->", "<![CDATA[", "]]>", "<?", "?>", "<!DOCTYPE", "<!ENTITY"]
    let encodings: [[[UInt8]]] = [
      markers.map { Array($0.utf8) },
      markers.map(\.utf16LittleEndian),
      markers.map(\.utf16BigEndian),
      markers.map(\.utf32LittleEndian),
      markers.map(\.utf32BigEndian),
    ]
    return try input.withUnsafeBytes { bytes in
      encodings.contains { containsForbiddenMarkup(in: bytes, markers: $0) }
    }
  }

  private static func containsForbiddenMarkup(
    in bytes: UnsafeRawBufferPointer,
    markers: [[UInt8]]
  ) -> Bool {
    func matches(_ token: [UInt8], at offset: Int) -> Bool {
      offset + token.count <= bytes.count
        && bytes[offset..<(offset + token.count)].elementsEqual(token)
    }
    func end(of token: [UInt8], after offset: Int) -> Int? {
      guard token.count <= bytes.count, offset <= bytes.count - token.count else { return nil }
      return (offset...(bytes.count - token.count)).first { matches(token, at: $0) }
        .map { $0 + token.count }
    }
    var offset = 0
    while offset < bytes.count {
      if matches(markers[0], at: offset) {
        guard let next = end(of: markers[1], after: offset + markers[0].count) else { return false }
        offset = next
        continue
      }
      if matches(markers[2], at: offset) {
        guard let next = end(of: markers[3], after: offset + markers[2].count) else { return false }
        offset = next
        continue
      }
      if matches(markers[4], at: offset) {
        guard let next = end(of: markers[5], after: offset + markers[4].count) else { return false }
        offset = next
        continue
      }
      if matches(markers[6], at: offset) || matches(markers[7], at: offset) { return true }
      offset += 1
    }
    return false
  }
}

private final class StructuralDelegate: NSObject, XMLParserDelegate {
  private let limits: PortalXMLLimits
  private let eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)?
  private var stack: [PortalXMLElementBuilder] = []
  private var root: PortalXMLElement?
  private var rootStarted = false
  private var nodeCount = 0
  private var textByteCount = 0
  private var attributeByteCount = 0
  fileprivate private(set) var failure: PortalXMLStructuralError?

  init(
    limits: PortalXMLLimits,
    eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)?
  ) {
    self.limits = limits
    self.eraseObserver = eraseObserver
  }

  func parser(
    _ parser: XMLParser,
    didStartElement elementName: String,
    namespaceURI: String?,
    qualifiedName qName: String?,
    attributes attributeDict: [String: String]
  ) {
    guard failure == nil else { return }
    guard stack.count < limits.maximumDepth else { return reject(.depthLimitExceeded, parser) }
    guard nodeCount < limits.maximumNodes else { return reject(.nodeLimitExceeded, parser) }
    guard attributeDict.count <= limits.maximumAttributesPerElement else {
      return reject(.attributeLimitExceeded, parser)
    }
    if stack.isEmpty {
      guard !rootStarted else { return reject(.duplicateRoot, parser) }
      rootStarted = true
    } else if !flushTop(parser) {
      return
    }

    do {
      let attributes = try attributeDict.sorted { $0.key < $1.key }.map { name, value in
        let count = value.utf8.count
        guard addAttributeBytes(count) else {
          throw PortalXMLStructuralError.attributeLimitExceeded
        }
        return PortalXMLAttribute(
          name: name,
          value: try securePortalXMLUTF8(value, observer: eraseObserver)
        )
      }
      nodeCount += 1
      stack.append(PortalXMLElementBuilder(name: elementName, attributes: attributes))
    } catch let error as PortalXMLStructuralError {
      reject(error, parser)
    } catch {
      reject(.storageUnavailable, parser)
    }
  }

  func parser(
    _ parser: XMLParser,
    didEndElement elementName: String,
    namespaceURI: String?,
    qualifiedName qName: String?
  ) {
    guard failure == nil, let builder = stack.last, builder.name == elementName else {
      return reject(.malformed, parser)
    }
    do {
      _ = stack.removeLast()
      let element = try builder.finish(observer: eraseObserver)
      if let parent = stack.last {
        parent.contents.append(.element(element))
      } else {
        guard root == nil else { return reject(.duplicateRoot, parser) }
        root = element
      }
    } catch {
      reject(.storageUnavailable, parser)
    }
  }

  func parser(_ parser: XMLParser, foundCharacters string: String) {
    guard failure == nil else { return }
    guard let builder = stack.last else {
      if !string.unicodeScalars.allSatisfy({ [0x09, 0x0A, 0x0D, 0x20].contains($0.value) }) {
        reject(.trailingContent, parser)
      }
      return
    }
    appendText(string.utf8.count, parser: parser) {
      try securePortalXMLUTF8(string, observer: nil)
    } to: {
      builder.textChunks.append($0)
    }
  }

  func parser(_ parser: XMLParser, foundCDATA cdataBlock: Data) {
    guard failure == nil, let builder = stack.last else {
      return reject(.trailingContent, parser)
    }
    appendText(cdataBlock.count, parser: parser) {
      try cdataBlock.withUnsafeBytes { try SecureBytes(copying: $0) }
    } to: {
      builder.textChunks.append($0)
    }
  }

  func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) {
    if failure == nil { failure = .malformed }
  }

  func parser(
    _ parser: XMLParser,
    foundInternalEntityDeclarationWithName name: String,
    value: String?
  ) { reject(.forbiddenDeclaration, parser) }

  func parser(
    _ parser: XMLParser,
    foundExternalEntityDeclarationWithName name: String,
    publicID: String?,
    systemID: String?
  ) { reject(.forbiddenDeclaration, parser) }

  func parser(
    _ parser: XMLParser,
    resolveExternalEntityName name: String,
    systemID: String?
  ) -> Data? {
    reject(.forbiddenDeclaration, parser)
    return nil
  }

  fileprivate func finish() throws -> PortalXMLDocument {
    guard failure == nil, stack.isEmpty, let root else {
      throw failure ?? PortalXMLStructuralError.malformed
    }
    self.root = nil
    return PortalXMLDocument(root: root)
  }

  fileprivate func erase() {
    for builder in stack { builder.erase() }
    stack.removeAll()
    root?.erase()
    root = nil
  }

  private func flushTop(_ parser: XMLParser) -> Bool {
    do {
      try stack.last?.flushText(observer: eraseObserver)
      return true
    } catch {
      reject(.storageUnavailable, parser)
      return false
    }
  }

  private func addAttributeBytes(_ count: Int) -> Bool {
    let (sum, overflow) = attributeByteCount.addingReportingOverflow(count)
    guard !overflow, sum <= limits.maximumAttributeBytes else { return false }
    attributeByteCount = sum
    return true
  }

  private func appendText(
    _ count: Int,
    parser: XMLParser,
    make: () throws -> SecureBytes,
    to append: (SecureBytes) -> Void
  ) {
    guard count > 0 else { return }
    let (sum, overflow) = textByteCount.addingReportingOverflow(count)
    guard !overflow, sum <= limits.maximumTextBytes else {
      return reject(.textLimitExceeded, parser)
    }
    do {
      append(try make())
      textByteCount = sum
    } catch {
      reject(.storageUnavailable, parser)
    }
  }

  private func reject(_ error: PortalXMLStructuralError, _ parser: XMLParser) {
    if failure == nil { failure = error }
    parser.abortParsing()
  }
}
