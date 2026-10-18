import Foundation

package struct PortalLogoutTransportObservation: Codable, Equatable, Sendable {
  package var httpStatus: Int?
  package var failure: String?
  package var curlCode: Int32?
  package var operatingSystemError: Int32?

  init(httpStatus: Int) { self.httpStatus = httpStatus }
  init(error: any Error) {
    if let typed = error as? PortalTransportFailure {
      httpStatus = typed.evidence.httpStatus
      failure = typed.evidence.category.rawValue
      curlCode = typed.evidence.curlCode
      operatingSystemError = typed.evidence.operatingSystemError
    } else {
      failure =
        (error as? PortalTransportError).map { String(describing: $0) }
        ?? (error is CancellationError ? "cancelled" : "unclassified")
    }
  }
}

package struct PortalLogoutSessionObservation: Codable, Equatable, Sendable {
  package enum State: String, Codable, Sendable { case valid, invalid, unknown }
  package let state: State
  package let transport: PortalLogoutTransportObservation
  package var responseCode: UInt64? = nil
  package var responseFormat: String? = nil
  package var confirmsInvalidation: Bool {
    state == .invalid
      && (transport.httpStatus == 401
        || ((200...204).contains(transport.httpStatus ?? 0) && responseCode == 0x8000_0014))
  }
}

package struct PortalLogoutVerificationEvidence: Codable, Equatable, Sendable {
  package let before: PortalLogoutSessionObservation
  package let logout: PortalLogoutTransportObservation
  package let after: PortalLogoutSessionObservation
}

/// Checks the SAME cookie generation before and after logout, while it is still
/// held in sealed, memory-only requests. Only explicit invalid-session evidence
/// proves closure; network/parse failures never count as rejection.
enum PortalLogoutVerification {
  static func run(
    factory: PortalRequestFactory, transport: any PortalTransporting,
    bounder: any PortalLogoutBounding
  ) async -> PortalLeaseLogoutResult {
    let before: PortalHTTPRequest
    let logout: PortalHTTPRequest
    let after: PortalHTTPRequest
    do {
      before = try factory.makeSessionCheckRequest()
      logout = try factory.makeLogoutRequest()
      after = try factory.makeSessionCheckRequest()
    } catch {
      return .init(status: .rejected, failureClass: .requestConstructionFailed)
    }
    defer {
      before.erase()
      logout.erase()
      after.erase()
    }
    let box = PortalLogoutVerificationBox()
    let finished = await bounder.run {
      let prior = await check(before, transport: transport)
      let exchange: PortalLogoutTransportObservation
      do {
        let response = try await transport.perform(logout)
        exchange = .init(httpStatus: response.statusCode)
        response.erase()
      } catch { exchange = .init(error: error) }
      logout.erase()
      let post = await check(after, transport: transport)
      box.set(.init(before: prior, logout: exchange, after: post))
    }
    guard finished, let evidence = box.value else {
      transport.cancel()
      // A timeout must not discard a completed "still valid" observation and
      // turn it into unknown cleanup. Do not promote late invalidation to success.
      return .init(status: .timedOut, verification: box.value)
    }
    return .init(
      status: evidence.after.confirmsInvalidation ? .accepted : .rejected,
      failureClass: evidence.after.confirmsInvalidation
        ? .postLogoutSessionRejected
        : (evidence.logout.failure == nil ? .completedRemoteExchange : .transportFailed),
      verification: evidence)
  }

  private static func check(_ request: PortalHTTPRequest, transport: any PortalTransporting)
    async -> PortalLogoutSessionObservation
  {
    defer { request.erase() }
    do {
      let response = try await transport.perform(request)
      defer { response.erase() }
      let observation = PortalLogoutTransportObservation(httpStatus: response.statusCode)
      guard (200...204).contains(response.statusCode) else {
        return .init(
          state: response.statusCode == 401 ? .invalid : .unknown, transport: observation)
      }
      do {
        let document = try PortalXMLStructuralParser().parse(
          consuming: response.withBodyBytes { try SecureBytes(copying: $0) })
        defer { document.erase() }
        let parsed = sessionCode(document)
        let state: PortalLogoutSessionObservation.State
        switch parsed.code {
        case 0: state = .valid
        case 0x8000_0014: state = .invalid
        default: state = .unknown
        }
        return .init(
          state: state, transport: observation,
          responseCode: parsed.code, responseFormat: parsed.format)
      } catch {
        var malformed = observation
        malformed.failure = "session_response_malformed"
        return .init(state: .unknown, transport: malformed)
      }
    } catch {
      let observation = PortalLogoutTransportObservation(error: error)
      let invalid =
        observation.failure == PortalTransportFailureCategory.httpAuthenticationRejected.rawValue
        && observation.httpStatus == 401
      return .init(state: invalid ? .invalid : .unknown, transport: observation)
    }
  }

  /// The gateway uses RESULT/@code; older fixtures used RESULT/code text.
  /// Require one unambiguous result, and never serialize any other XML value.
  private static func sessionCode(_ document: PortalXMLDocument) -> (code: UInt64?, format: String)
  {
    let roots =
      document.root.name == "RESPONSE"
      ? [document.root]
      : document.root.childElements.filter { $0.name == "RESPONSE" }
    guard roots.count == 1 else { return (nil, "missing_response") }
    let results = roots[0].childElements.filter { $0.name == "RESULT" }
    guard results.count == 1 else { return (nil, "ambiguous_result") }
    let result = results[0]
    let children = result.childElements.filter { $0.name == "code" }
    if let attribute = result.attribute(named: "code") {
      guard children.isEmpty else { return (nil, "ambiguous_code") }
      return ((try? attribute.withValueBytes(parseCode)) ?? nil, "result_attribute")
    }
    guard children.count == 1, children[0].childElements.isEmpty else {
      return (nil, "missing_code")
    }
    let values = children[0].contents.compactMap { part -> SecureBytes? in
      if case .text(let value) = part { return value }
      return nil
    }
    guard values.count == 1 else { return (nil, "ambiguous_code") }
    return ((try? values[0].withUnsafeBytes(parseCode)) ?? nil, "result_element")
  }

  private static func parseCode(_ bytes: UnsafeRawBufferPointer) -> UInt64? {
    guard (1...32).contains(bytes.count) else { return nil }
    let text = String(decoding: bytes, as: UTF8.self).trimmingCharacters(
      in: .whitespacesAndNewlines)
    let digits = text.hasPrefix("0x") || text.hasPrefix("0X") ? String(text.dropFirst(2)) : text
    guard !digits.isEmpty,
      digits.utf8.allSatisfy({
        (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
      })
    else { return nil }
    return UInt64(digits, radix: 16)
  }
}

private final class PortalLogoutVerificationBox: @unchecked Sendable {
  private let lock = NSLock()
  private var evidence: PortalLogoutVerificationEvidence?
  func set(_ value: PortalLogoutVerificationEvidence) { lock.withLock { evidence = value } }
  var value: PortalLogoutVerificationEvidence? { lock.withLock { evidence } }
}
