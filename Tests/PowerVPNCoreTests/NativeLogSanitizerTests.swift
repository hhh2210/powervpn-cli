import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NativeLogSanitizerTests {
  @Test func redactsPortalSessionIdentityInCharonLines() {
    let hex = "3a7f9c0b12de45a8b6c7d8e9f0a1b2c3"
    let line =
      "09[IKE] IKE_SA powervpn-thu21-5efac0b7[1] established between 10.0.0.2[keyid:#\(hex)]...192.0.2.1[%any]"
    let clean = NativeLogSanitizer.sanitize(line)
    #expect(!clean.contains(hex))
    #expect(clean.contains("10.0.0.2[<redacted>]"))
    #expect(clean.contains("powervpn-thu21-5efac0b7"))  // session names stay matchable
  }

  @Test(arguments: [
    "psk=hunter2hunter2", "Cookie: LEADSEC_SESSION_ABCDEF", "password = abc", "token:abcdef",
    "sessionid=12345",
  ])
  func redactsSecretNamedPairs(text: String) {
    let clean = NativeLogSanitizer.sanitize("got " + text + " end")
    #expect(clean.contains(NativeLogSanitizer.redaction))
    for secret in ["hunter2hunter2", "LEADSEC_SESSION_ABCDEF", "abc", "abcdef", "12345"]
    where text.contains(secret) && secret.count > 3 {
      #expect(!clean.contains(secret))
    }
  }

  @Test func redactsLongOpaqueRunsAndQuotedBlobs() {
    let blob = String(repeating: "Ab3", count: 12)
    #expect(!NativeLogSanitizer.sanitize("value \(blob) x").contains(blob))
    let quoted = "'" + String(repeating: "z ", count: 30) + "'"
    #expect(NativeLogSanitizer.sanitize("id \(quoted)") == "id '<redacted>'")
  }

  /// charon prints a printable key id as the raw session id, not as
  /// `keyid:#hex`, so identities are redacted by position, whatever they hold.
  @Test(arguments: [
    (
      "06[IKE] <powervpn-thu21-5efac0b7|1> IKE_SA powervpn-thu21-5efac0b7[1] established between 192.168.1.5[Q7zK.session-42]...203.0.113.1[203.0.113.1]",
      "06[IKE] <powervpn-thu21-5efac0b7|1> IKE_SA powervpn-thu21-5efac0b7[1] established between 192.168.1.5[<redacted>]...203.0.113.1[203.0.113.1]"
    ),
    (
      "12[CFG] loaded IKE shared key with id 'powervpn-thu21-5efac0b7' for: 'Q7zK.session-42'",
      "12[CFG] loaded IKE shared key with id 'powervpn-thu21-5efac0b7' for: '<redacted>'"
    ),
    (
      "06[IKE] authentication of 'abc' (myself) with pre-shared key",
      "06[IKE] authentication of '<redacted>' (myself) with pre-shared key"
    ),
    (
      "06[IKE] no shared key found for 'abc'[192.168.1.5] - '%any'[203.0.113.1]",
      "06[IKE] no shared key found for '<redacted>'[192.168.1.5] - '%any'[203.0.113.1]"
    ),
    ("key 00:1a:2b:3c:4d:5e:6f", "key <redacted>"),
    ("lookup \"Q7zK\" done", "lookup \"<redacted>\" done"),
  ])
  func redactsIdentitiesWhereverCharonPrintsThem(line: String, expected: String) {
    #expect(NativeLogSanitizer.sanitize(line) == expected)
  }

  @Test(arguments: [
    "09[KNL] <powervpn-thu21-5efac0b7|1> virtual IP 1.1.1.122 did not appear on utun11",
    "09[IKE] <powervpn-thu21-5efac0b7|1> scoped Portal VIP preparation failed",
    "establishing CHILD_SA 'selected-resource' failed",
    "IKE_SA 'powervpn-thu21-5efac0b7' not established after 15000ms",
    "07[IKE] <powervpn-thu21-5efac0b7|1> received NO_PROPOSAL_CHOSEN error notify",
    "05[NET] sending packet: from 192.168.1.5[50020] to 203.0.113.1[500] (180 bytes)",
    "04[ENC] generating QUICK_MODE request 1 [ HASH SA No ID ID ]",
    "2026-11-13T05:09:41Z [helper] route add 11.11.30.21 -> utun11 for powervpn-thu21-5efac0b7",
    "13[KNL] unable to receive from PF_ROUTE event socket",
  ])
  func keepsOrdinaryDiagnosticsReadable(line: String) {
    #expect(NativeLogSanitizer.sanitize(line) == line)
  }

  @Test func sanitizingTwiceChangesNothing() {
    let line = "12[CFG] loaded IKE shared key with id 'powervpn-x' for: 'Q7zK' keyid:#00ff [ab:cd]"
    let once = NativeLogSanitizer.sanitize(line)
    #expect(NativeLogSanitizer.sanitize(once) == once)
    #expect(!once.contains("Q7zK") && !once.contains("00ff") && !once.contains("ab:cd"))
  }

  @Test func replacesControlAndNonASCIIAndCapsLength() {
    #expect(NativeLogSanitizer.sanitize("a\u{1B}[31mb\u{00E9}\n") == "a?[31mb??")
    let long = String(repeating: "a ", count: 400)
    let clean = NativeLogSanitizer.sanitize(long, limit: 50)
    #expect(clean.count == 53 && clean.hasSuffix("..."))
  }
}
