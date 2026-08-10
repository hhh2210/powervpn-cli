import Darwin
import Foundation
import PowerVPNTLSEvidence

@main
struct PowerVPNTLSEvidenceCommand {
  static func main() async {
    guard CommandLine.arguments.count == 1 else { Darwin.exit(64) }
    let report = await TLSPeerEvidenceRuntime.observeSealedEndpoint()
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    guard let data = try? encoder.encode(report) else { Darwin.exit(70) }
    print(String(decoding: data, as: UTF8.self))
    Darwin.exit(report.status == .observed ? 0 : 2)
  }
}
