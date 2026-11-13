import Foundation

public enum NativeFailurePhase: String, Codable, Equatable, Sendable {
  case ike
  case child
}

/// Why a native establishment step failed, classified on positive evidence
/// only. `unclassified` means "no charon line or VICI message proved a cause".
public enum NativeFailureCause: String, Codable, Equatable, Sendable {
  /// charon could not create or see the tunnel's virtual IP on a utun.
  case localVirtualIP = "local_virtual_ip"
  /// The gateway answered with an error notification.
  case gatewayRefused = "gateway_refused"
  /// The gateway did not answer in time.
  case timedOut = "timed_out"
  case unclassified
}

/// Value-free, secret-free description of a failed step. Every text field has
/// passed NativeLogSanitizer and is short, so it can be shown, stored in the
/// session state and written to `recovery inspect --json`.
public struct NativeFailureDetail: Codable, Equatable, Sendable {
  public let phase: NativeFailurePhase
  public let cause: NativeFailureCause
  /// charon's VICI `errmsg`.
  public let charonMessage: String?
  /// The one charon log line that proves `cause`.
  public let evidence: String?
  public let elapsedMilliseconds: Int?
  /// What the helper did about it (`restarted`, `refused:not_idle`, ...).
  public var selfHeal: String?

  public static let textLimit = 160

  public init(
    phase: NativeFailurePhase, cause: NativeFailureCause, charonMessage: String? = nil,
    evidence: String? = nil, elapsedMilliseconds: Int? = nil, selfHeal: String? = nil
  ) {
    self.phase = phase
    self.cause = cause
    self.charonMessage = Self.clean(charonMessage)
    self.evidence = Self.clean(evidence)
    self.elapsedMilliseconds = elapsedMilliseconds.map { max(0, min($0, 3_600_000)) }
    self.selfHeal = Self.clean(selfHeal, limit: 40)
  }

  private static func clean(_ text: String?, limit: Int = textLimit) -> String? {
    guard let text else { return nil }
    let value = NativeLogSanitizer.sanitize(text, limit: limit)
      .trimmingCharacters(in: .whitespaces)
    return value.isEmpty ? nil : value
  }

  public var valid: Bool {
    [charonMessage, evidence].allSatisfy { ($0?.count ?? 0) <= Self.textLimit + 3 }
      && (selfHeal?.count ?? 0) <= 43
  }

  /// One human sentence fragment, for the CLI message.
  public var summary: String {
    var parts: [String] = []
    if let charonMessage { parts.append("charon: \(charonMessage)") }
    if let evidence { parts.append("log: \(evidence)") }
    if let elapsedMilliseconds { parts.append("after \(elapsedMilliseconds) ms") }
    if let selfHeal { parts.append("auto-recovery: \(selfHeal)") }
    return parts.joined(separator: "; ")
  }

  // MARK: token form
  // The proxy child reports failures to its parent as one stderr token. Detail
  // rides in it as `:key=value` fields, percent-encoded so no field can contain
  // `:` or whitespace.

  public var tokenSuffix: String {
    var fields = ["cause=\(cause.rawValue)", "phase=\(phase.rawValue)"]
    if let elapsedMilliseconds { fields.append("ms=\(elapsedMilliseconds)") }
    if let charonMessage { fields.append("msg=\(Self.encode(charonMessage))") }
    if let evidence { fields.append("ev=\(Self.encode(evidence))") }
    if let selfHeal { fields.append("heal=\(Self.encode(selfHeal))") }
    return ":" + fields.joined(separator: ":")
  }

  /// Reads the detail from the proxy child's `tunnel_open_failed:native_...`
  /// token. Only that one whitespace-free token is parsed, never the rest of
  /// the child's stderr; the last such token wins.
  public static func parse(token raw: String) -> NativeFailureDetail? {
    guard
      let token = raw.split(whereSeparator: \.isWhitespace).last(where: {
        $0.hasPrefix("tunnel_open_failed:native_") && $0.contains(":cause=")
      }), let start = token.range(of: ":cause=")
    else { return nil }
    var fields: [String: String] = [:]
    for part in token[token.index(after: start.lowerBound)...].split(separator: ":") {
      guard let equals = part.firstIndex(of: "=") else { continue }
      fields[String(part[..<equals])] = String(part[part.index(after: equals)...])
    }
    guard let cause = fields["cause"].flatMap(NativeFailureCause.init(rawValue:)),
      let phase = fields["phase"].flatMap(NativeFailurePhase.init(rawValue:))
    else { return nil }
    return NativeFailureDetail(
      phase: phase, cause: cause, charonMessage: fields["msg"].flatMap(decode),
      evidence: fields["ev"].flatMap(decode), elapsedMilliseconds: fields["ms"].flatMap(Int.init),
      selfHeal: fields["heal"].flatMap(decode))
  }

  private static let plain = Set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-".utf8)

  static func encode(_ text: String) -> String {
    var result = ""
    for byte in text.utf8 {
      if plain.contains(byte) {
        result.unicodeScalars.append(Unicode.Scalar(byte))
      } else {
        result += String(format: "%%%02X", byte)
      }
    }
    return result
  }

  static func decode(_ text: String) -> String? {
    text.removingPercentEncoding
  }
}

/// Classifies a failed `initiate` from charon's VICI errmsg plus the lines the
/// helper captured from charon's own log. Evidence must be positive: a cause is
/// named only when a specific line or message says so.
public enum NativeFailureClassifier {
  public static func classify(
    phase: NativeFailurePhase, charonMessage: String?, logLines: [String], session: String,
    elapsedMilliseconds: Int?
  ) -> NativeFailureDetail {
    let relevant = logLines.filter { line in
      // Lines tagged with another session's name are not this attempt's.
      guard let tagged = taggedSession(in: line) else { return true }
      return tagged == session
    }
    func detail(_ cause: NativeFailureCause, _ evidence: String?) -> NativeFailureDetail {
      NativeFailureDetail(
        phase: phase, cause: cause, charonMessage: charonMessage,
        evidence: evidence.map(messageText), elapsedMilliseconds: elapsedMilliseconds)
    }
    if let line = relevant.last(where: { $0.contains(" error notify") && notifyName($0) != nil }) {
      return detail(.gatewayRefused, line)
    }
    if phase == .child,
      let line = relevant.last(where: { localMarkers.contains(where: $0.contains) })
    {
      return detail(.localVirtualIP, line)
    }
    if let line = relevant.last(where: { timeoutMarkers.contains(where: $0.contains) }) {
      return detail(.timedOut, line)
    }
    if charonMessage?.contains("not established after") == true {
      return detail(.timedOut, nil)
    }
    return detail(.unclassified, nil)
  }

  static let localMarkers = [
    "scoped Portal VIP preparation failed", "did not appear on",
    "installing virtual IP", "looking up interface for virtual IP",
  ]
  static let timeoutMarkers = ["giving up after", "peer not responding"]

  /// `<powervpn-thu21-abcd1234|3>` -> `powervpn-thu21-abcd1234`
  static func taggedSession(in line: String) -> String? {
    guard let open = line.range(of: "<powervpn-"),
      let bar = line[open.upperBound...].firstIndex(where: { $0 == "|" || $0 == ">" })
    else { return nil }
    return String(line[line.index(after: open.lowerBound)..<bar])
  }

  static func notifyName(_ line: String) -> String? {
    guard
      let range = line.range(of: #"received [A-Z0-9_]+ error notify"#, options: .regularExpression)
    else { return nil }
    return String(line[range])
  }

  /// Drops the helper timestamp, `[charon]`, thread/group prefix and SA tag.
  static func messageText(_ line: String) -> String {
    var text = line
    if let group = text.range(of: #"\d+\[[A-Z]+\] "#, options: .regularExpression) {
      text = String(text[group.upperBound...])
    }
    if text.hasPrefix("<"), let close = text.firstIndex(of: ">") {
      text = String(text[text.index(after: close)...]).trimmingCharacters(in: .whitespaces)
    }
    return text
  }
}
