import Foundation

/// Makes one line of charon, helper or VICI text safe to store and to show.
///
/// The IKE identity of this Mac is the Portal session id (NativeTrialMaterial
/// loads it as `keyid:#<hex>`). charon prints identities with `%Y` at levels 0
/// and 1, and for a printable key id `%Y` prints the raw session id, not the
/// `keyid:` form: `established between 10.0.0.2[<id>]...`, `loaded IKE shared
/// key with id '...' for: '<id>'`, `authentication of '<id>' (myself) ...`.
/// A pattern for "what a session id looks like" is therefore not enough. The
/// sanitizer keeps only what it can name as safe inside the two places charon
/// puts identities, quotes and brackets, and redacts everything else there;
/// opaque runs anywhere else are redacted as well.
///
/// It is a security boundary, applied before a charon line reaches any file,
/// control-socket reply, CLI message or state record, and it fails closed:
/// anything it cannot show safely is replaced, never kept.
public enum NativeLogSanitizer {
  public static let maximumLineLength = 400
  public static let redaction = "<redacted>"

  /// ASCII printable only (control characters and non-ASCII become `?`),
  /// identities, secrets and opaque runs redacted, length capped.
  public static func sanitize(_ text: String, limit: Int = maximumLineLength) -> String {
    var result = ""
    result.reserveCapacity(min(text.utf8.count, limit))
    for scalar in text.unicodeScalars {
      if (0x20...0x7E).contains(scalar.value) {
        result.unicodeScalars.append(scalar)
      } else if scalar == "\t" {
        result.unicodeScalars.append(" ")
      } else {
        result.unicodeScalars.append("?")
      }
    }
    result = redact(result)
    if result.count > limit {
      result = String(result.prefix(limit)) + "..."
    }
    return result
  }

  /// Rules, applied in order:
  ///  1. `keyid:` identities, whatever follows them.
  ///  2. `name=value` / `name: value` pairs whose name denotes a secret.
  ///  3. Quoted text that is not a safe token (`safeQuoted`).
  ///  4. Bracketed text that is not a safe token (`safeBracketed`).
  ///  5. Colon-separated hex (`%#B` dumps), 16+ hex digits, and 24+
  ///     base64-like characters that include a digit (keys, ids, cookies).
  ///
  /// ICU patterns (NSRegularExpression), not Swift Regex: the lookbehind in
  /// the last rule is not available on the oldest supported toolchain.
  static func redact(_ text: String) -> String {
    var value = text
    value = replace(#"(?i)keyid:#?[^\s'"\[\]]*"#, in: value) { _ in "keyid:" + redaction }
    value = replace(
      #"(?i)\b(psk|secret|password|passwd|cookie|token|session[-_ ]?id|sessionid)\s*[=:]\s*\S+"#,
      in: value
    ) { $0[1] + "=" + redaction }
    value = replace(#"'([^']*)'"#, in: value) {
      safeQuoted($0[1]) ? $0[0] : "'" + redaction + "'"
    }
    value = replace(#""([^"]*)""#, in: value) {
      safeQuoted($0[1]) ? $0[0] : "\"" + redaction + "\""
    }
    value = replace(#"\[([^\[\]]*)\]"#, in: value) {
      safeBracketed($0[1]) ? $0[0] : "[" + redaction + "]"
    }
    value = replace(#"(?:[0-9A-Fa-f]{2}:){4,}[0-9A-Fa-f]{2}"#, in: value) { _ in redaction }
    value = replace(#"[0-9A-Fa-f]{16,}"#, in: value) { _ in redaction }
    // Session names (`powervpn-<target>-<8 hex>`) are random, not secret, and
    // are how a failure is matched to its log lines: keep them readable.
    value = replace(#"(?<![A-Za-z0-9+/_\-])(?!powervpn-)[A-Za-z0-9+/_\-]{24,}={0,2}"#, in: value) {
      $0[0].contains(where: \.isNumber) ? redaction : $0[0]
    }
    return value
  }

  /// Names charon quotes that are ours and not secret: session names, the
  /// child name, `%any`, an IPv4 address or subnet, a redaction marker.
  static func safeQuoted(_ text: String) -> Bool {
    matches(#"powervpn-[A-Za-z0-9_\-]{1,119}|selected-resource|%any|<redacted>"#, text)
      || matches(#"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"#, text)
  }

  /// charon brackets a log group (`[IKE]`), an SA unique id or a port (`[3]`,
  /// `[500]`), a payload list (`[ SA V V ]`) and an identity after an address
  /// (`10.0.0.2[<id>]`). Only the first three and an IPv4 or `%any` identity
  /// are kept, plus the helper's own source tags.
  static func safeBracketed(_ text: String) -> Bool {
    matches(#"\d{1,10}|[A-Z]{3}|%any|charon|helper|<redacted>"#, text)
      || matches(#"(?:\d{1,3}\.){3}\d{1,3}"#, text)
      || matches(#" [A-Za-z0-9_ ()\-]* "#, text)
  }

  private static func matches(_ pattern: String, _ text: String) -> Bool {
    guard let expression = try? NSRegularExpression(pattern: "^(?:" + pattern + ")$") else {
      return false
    }
    let range = NSRange(text.startIndex..., in: text)
    return expression.firstMatch(in: text, range: range) != nil
  }

  /// Replaces every match with `transform(groups)`, where `groups[0]` is the
  /// whole match and absent groups are empty. A pattern that fails to compile
  /// redacts the whole text: the sanitizer must not fail open.
  private static func replace(
    _ pattern: String, in text: String, _ transform: ([String]) -> String
  ) -> String {
    guard let expression = try? NSRegularExpression(pattern: pattern) else { return redaction }
    var result = ""
    var cursor = text.startIndex
    for match in expression.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
      guard let whole = Range(match.range, in: text) else { continue }
      let groups = (0..<match.numberOfRanges).map { index in
        Range(match.range(at: index), in: text).map { String(text[$0]) } ?? ""
      }
      result += text[cursor..<whole.lowerBound]
      result += transform(groups)
      cursor = whole.upperBound
    }
    result += text[cursor...]
    return result
  }
}
