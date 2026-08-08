import Foundation

public enum AllowlistedLogReader {
  public static func readLines(
    path: String,
    maximumBytes: UInt64,
    markers: [String],
    maximumLineBytes: Int = 32 * 1_024,
    maximumMatches: Int = 4_096,
    sanitizer: ((String) -> String?)? = nil
  ) -> String {
    guard !markers.isEmpty, maximumBytes > 0,
      let handle = FileHandle(forReadingAtPath: path)
    else { return "" }
    defer { try? handle.close() }

    let end = (try? handle.seekToEnd()) ?? 0
    let start = end > maximumBytes ? end - maximumBytes : 0
    try? handle.seek(toOffset: start)

    var matchedLines: [String] = []
    var line = Data()
    var discardUntilNewline = start > 0

    func collect(_ data: Data) {
      guard matchedLines.count < maximumMatches else { return }
      let text = String(decoding: data, as: UTF8.self)
      let matchedMarkers = markers.filter(text.contains)
      guard !matchedMarkers.isEmpty else { return }

      if let sanitizer {
        guard let sanitized = sanitizer(text), !sanitized.isEmpty else { return }
        matchedLines.append(sanitized)
      } else {
        matchedLines.append(matchedMarkers.joined(separator: " "))
      }
    }

    while true {
      let next: Data?
      do {
        next = try handle.read(upToCount: 16 * 1_024)
      } catch {
        break
      }
      guard let chunk = next, !chunk.isEmpty else { break }
      for byte in chunk {
        if byte == 0x0A {
          if !discardUntilNewline { collect(line) }
          line.removeAll(keepingCapacity: true)
          discardUntilNewline = false
        } else if !discardUntilNewline {
          if line.count < maximumLineBytes {
            line.append(byte)
          } else {
            line.removeAll(keepingCapacity: true)
            discardUntilNewline = true
          }
        }
      }
    }
    if !discardUntilNewline, !line.isEmpty { collect(line) }
    return matchedLines.joined(separator: "\n")
  }
}
