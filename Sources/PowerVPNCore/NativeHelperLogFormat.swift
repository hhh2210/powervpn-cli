import Foundation

/// The line format of the helper's rotated log, and the `log-tail` selection
/// over it. Shared so the CLI's evidence lookup is tested against the exact
/// stamp the helper writes.
public enum NativeHelperLogFormat {
  /// `2026-11-13T05:09:41Z [charon] 09[IKE] <powervpn-x|3> ...`, sanitized.
  public static func line(source: String, message: String, at date: Date = Date()) -> String {
    "\(date.formatted(.iso8601)) [\(source)] " + NativeLogSanitizer.sanitize(message)
  }

  /// The newest `count` of `lines` stamped at or after `sinceEpoch` (whole
  /// seconds: stamps have no fraction). A line without a readable stamp is
  /// kept, so an odd line never hides the evidence after it.
  public static func recent(_ lines: [String], sinceEpoch: Double?, count: Int) -> [String] {
    guard let sinceEpoch else { return Array(lines.suffix(count)) }
    let floor = sinceEpoch.rounded(.down)
    let selected = lines.filter { line in
      guard let stamp = line.split(separator: " ", maxSplits: 1).first,
        let date = try? Date(String(stamp), strategy: .iso8601)
      else { return true }
      return date.timeIntervalSince1970 >= floor
    }
    return Array(selected.suffix(count))
  }
}
