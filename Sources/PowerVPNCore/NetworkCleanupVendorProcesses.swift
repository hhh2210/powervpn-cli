import Foundation

package struct NetworkCleanupVendorProcessSnapshot: Equatable, Sendable {
  package let fingerprint: NetworkCleanupFingerprint
  package let officialGUIProcessCount: Int
  package let charonProcessCount: Int
  package let ipsecProcessCount: Int
  package let shellProcessCount: Int
  let identityTokens: Set<Data>

  package static func unavailable(_ state: NetworkCleanupObservationState) -> Self {
    Self(
      fingerprint: .unavailable(state),
      officialGUIProcessCount: 0,
      charonProcessCount: 0,
      ipsecProcessCount: 0,
      shellProcessCount: 0,
      identityTokens: []
    )
  }

  package var isObserved: Bool {
    fingerprint.isObserved
      && officialGUIProcessCount >= 0 && charonProcessCount >= 0
      && ipsecProcessCount >= 0 && shellProcessCount >= 0
      && officialGUIProcessCount + charonProcessCount
        + ipsecProcessCount + shellProcessCount == fingerprint.itemCount
      && identityTokens.count == fingerprint.itemCount
  }

  package var guiAndUnrelatedHelpersAbsent: Bool {
    officialGUIProcessCount == 0 && ipsecProcessCount == 0 && shellProcessCount == 0
  }

  func isConsistent(with generation: VendorHelperGenerationSnapshot) -> Bool {
    guard isObserved, guiAndUnrelatedHelpersAbsent else { return false }
    if generation.exactInactive { return charonProcessCount == 0 }
    if generation.exactRunning, let activeCount = generation.activeCount {
      return charonProcessCount == activeCount
    }
    return false
  }
}

enum NetworkVendorProcessCanonicalizer {
  private enum ProcessClass: String {
    case officialGUI = "official-gui"
    case charon
    case ipsec
    case shell
  }

  private static let weekdays: Set<Substring> = [
    "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun",
  ]
  private static let months: Set<Substring> = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ]

  static func canonicalize(
    _ data: Data,
    window: NetworkCleanupCaptureWindow
  ) throws -> NetworkCleanupVendorProcessSnapshot {
    var counts: [ProcessClass: Int] = [:]
    var seenPIDs: Set<Int> = []
    var tokens: Set<Data> = []
    for rawLine in try NetworkCleanupText.lines(data) {
      let fields = rawLine.split(whereSeparator: \Character.isWhitespace)
      guard !fields.isEmpty else { continue }
      guard fields.count >= 7, let pid = Int(fields[0]), pid > 0,
        validStartFields(fields[1...5]), seenPIDs.insert(pid).inserted
      else { throw NetworkCleanupCanonicalizationError.invalidShape }
      guard let processClass = classify(String(fields[6])) else { continue }
      let start = fields[1...5].joined(separator: " ")
      let command = fields[6...].joined(separator: " ")
      let record = "\(processClass.rawValue)\t\(pid)\t\(start)\t\(command)"
      guard tokens.insert(window.vendorProcessToken(record)).inserted else {
        throw NetworkCleanupCanonicalizationError.duplicateValue
      }
      counts[processClass, default: 0] += 1
    }
    guard !seenPIDs.isEmpty else {
      throw NetworkCleanupCanonicalizationError.emptyInventory
    }
    let tokenRecords = tokens.sorted(by: Self.lexicographicallyPrecedes).map(Self.hex)
    return NetworkCleanupVendorProcessSnapshot(
      fingerprint: .observed(
        count: tokens.count,
        sha256: NetworkCleanupDigest.sha256(
          domain: "vendor-processes",
          records: tokenRecords
        )
      ),
      officialGUIProcessCount: counts[.officialGUI, default: 0],
      charonProcessCount: counts[.charon, default: 0],
      ipsecProcessCount: counts[.ipsec, default: 0],
      shellProcessCount: counts[.shell, default: 0],
      identityTokens: tokens
    )
  }

  private static func classify(_ executable: String) -> ProcessClass? {
    switch URL(fileURLWithPath: executable).lastPathComponent {
    case "PowerVPN": .officialGUI
    case "com.leadsec.charon-xpc": .charon
    case "com.leadsec.ipsec-xpc": .ipsec
    case "com.leadsec.sh-xpc": .shell
    default: nil
    }
  }

  private static func validStartFields<C: Collection>(_ fields: C) -> Bool
  where C.Element == Substring {
    let values = Array(fields)
    guard values.count == 5, weekdays.contains(values[0]), months.contains(values[1]),
      canonicalDecimal(values[2], range: 1...31),
      canonicalDecimal(values[4], width: 4, range: 1970...9999)
    else { return false }
    let time = values[3].split(separator: ":", omittingEmptySubsequences: false)
    return time.count == 3
      && canonicalDecimal(time[0], width: 2, range: 0...23)
      && canonicalDecimal(time[1], width: 2, range: 0...59)
      && canonicalDecimal(time[2], width: 2, range: 0...59)
  }

  private static func canonicalDecimal(
    _ value: Substring,
    width: Int? = nil,
    range: ClosedRange<Int>
  ) -> Bool {
    guard width.map({ value.count == $0 }) ?? (1...2).contains(value.count),
      value.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
      let integer = Int(value), range.contains(integer)
    else { return false }
    return width != nil || String(integer) == value
  }

  private static func lexicographicallyPrecedes(_ lhs: Data, _ rhs: Data) -> Bool {
    lhs.lexicographicallyPrecedes(rhs)
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }
}
