import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NativeFailureAnalysisTests {
  private let session = "powervpn-thu21-5efac0b7"
  private let errmsg = "establishing CHILD_SA 'selected-resource' failed"

  private func line(_ text: String, tag: String? = nil) -> String {
    "2026-11-13T05:10:00Z [charon] 09[IKE] " + (tag.map { "<\($0)|1> " } ?? "") + text
  }

  @Test func localVirtualIPFailureIsNamedFromTheScopedPreparationLine() {
    let detail = NativeFailureClassifier.classify(
      phase: .child, charonMessage: errmsg,
      logLines: [
        "2026-11-13T05:10:00Z [charon] 09[KNL] virtual IP 11.11.30.9 did not appear on utun11",
        line("scoped Portal VIP preparation failed", tag: session),
      ], session: session, elapsedMilliseconds: 1_330)
    #expect(detail.cause == .localVirtualIP)
    #expect(detail.evidence == "scoped Portal VIP preparation failed")
    #expect(detail.charonMessage == errmsg)
    #expect(detail.elapsedMilliseconds == 1_330)
  }

  @Test func kernelLineAloneIsEnoughForLocalCause() {
    let detail = NativeFailureClassifier.classify(
      phase: .child, charonMessage: errmsg,
      logLines: [
        "2026-11-13T05:10:00Z [charon] 09[KNL] virtual IP 11.11.30.9 did not appear on utun11"
      ],
      session: session, elapsedMilliseconds: nil)
    #expect(detail.cause == .localVirtualIP)
  }

  @Test func gatewayNotifyErrorIsGatewayRefusal() {
    let detail = NativeFailureClassifier.classify(
      phase: .child, charonMessage: errmsg,
      logLines: [line("received NO_PROPOSAL_CHOSEN error notify", tag: session)],
      session: session, elapsedMilliseconds: 80)
    #expect(detail.cause == .gatewayRefused)
    #expect(detail.evidence == "received NO_PROPOSAL_CHOSEN error notify")
  }

  @Test func retransmitExhaustionAndVICITimeoutAreTimeouts() {
    #expect(
      NativeFailureClassifier.classify(
        phase: .child, charonMessage: errmsg,
        logLines: [line("giving up after 3 retransmits", tag: session)],
        session: session, elapsedMilliseconds: nil
      ).cause == .timedOut)
    #expect(
      NativeFailureClassifier.classify(
        phase: .ike, charonMessage: "IKE_SA 'x' not established after 15000ms", logLines: [],
        session: session, elapsedMilliseconds: nil
      ).cause == .timedOut)
  }

  @Test func noPositiveEvidenceStaysUnclassified() {
    let detail = NativeFailureClassifier.classify(
      phase: .child, charonMessage: errmsg, logLines: [], session: session,
      elapsedMilliseconds: 1_300)
    #expect(detail.cause == .unclassified)
    #expect(detail.evidence == nil)
    #expect(detail.charonMessage == errmsg)
  }

  @Test func anotherSessionsLinesAreIgnored() {
    let detail = NativeFailureClassifier.classify(
      phase: .child, charonMessage: errmsg,
      logLines: [line("scoped Portal VIP preparation failed", tag: "powervpn-thu52-deadbeef")],
      session: session, elapsedMilliseconds: nil)
    #expect(detail.cause == .unclassified)
  }

  @Test func localMarkersDoNotClassifyIKEPhaseFailures() {
    let detail = NativeFailureClassifier.classify(
      phase: .ike, charonMessage: "establishing IKE_SA 'x' failed",
      logLines: [line("scoped Portal VIP preparation failed", tag: session)],
      session: session, elapsedMilliseconds: nil)
    #expect(detail.cause == .unclassified)
  }

  @Test func detailNeverCarriesSecretsEvenFromHostileText() {
    let hex = "3a7f9c0b12de45a8b6c7d8e9f0a1b2c3"
    let detail = NativeFailureDetail(
      phase: .child, cause: .unclassified,
      charonMessage: "failed for keyid:#\(hex) psk=topsecretvalue",
      evidence: "cookie: abcdefabcdefabcdefabcdefabcdef", selfHeal: "refused:x")
    let text = detail.summary + detail.tokenSuffix
    #expect(!text.contains(hex))
    #expect(!text.contains("topsecretvalue"))
    #expect(!text.contains("abcdefabcdef"))
  }

  @Test func tokenRoundTripsAndHasNoSeparatorsInsideValues() throws {
    let detail = NativeFailureDetail(
      phase: .child, cause: .localVirtualIP, charonMessage: errmsg,
      evidence: "scoped Portal VIP preparation failed", elapsedMilliseconds: 1_330,
      selfHeal: "refused:not_idle")
    let token = "tunnel_open_failed:native_local_vip_failed" + detail.tokenSuffix
    #expect(!token.contains(" "))
    #expect(NativeFailureDetail.parse(token: token) == detail)
    #expect(NativeFailureDetail.parse(token: "tunnel_open_failed:native_child_failed") == nil)
    #expect(NativeFailureDetail.parse(token: "x:cause=bogus:phase=child") == nil)
    // Only the token is read: other stderr text cannot inject fields.
    let noisy = "ssh: msg=evil:cause=gateway_refused:phase=ike\npowervpn proxy: \(token)\n"
    #expect(NativeFailureDetail.parse(token: noisy) == detail)
    #expect(NativeFailureDetail.parse(token: "ssh says :cause=local_virtual_ip:phase=child") == nil)
  }

  /// The self-heal fires only if `log-tail`'s time window returns the line the
  /// helper wrote and the classifier recognises it: test that chain end to end
  /// with the helper's own stamp and charon's `NN[GRP] <name|id>` prefix.
  @Test func helperStampedLinesSurviveTheTailWindowAndClassify() {
    let attemptStart = Date(timeIntervalSince1970: 1_763_010_600.7)
    let stale = NativeHelperLogFormat.line(
      source: "charon", message: "09[IKE] <\(session)|1> scoped Portal VIP preparation failed",
      at: attemptStart.addingTimeInterval(-120))
    let fresh = [
      NativeHelperLogFormat.line(
        source: "charon",
        message: "09[KNL] <\(session)|2> virtual IP 1.1.1.122 did not appear on utun11",
        at: attemptStart.addingTimeInterval(1.2)),
      NativeHelperLogFormat.line(
        source: "charon", message: "09[IKE] <\(session)|2> scoped Portal VIP preparation failed",
        at: attemptStart.addingTimeInterval(1.3)),
    ]
    let tail = NativeHelperLogFormat.recent(
      [stale] + fresh, sinceEpoch: attemptStart.timeIntervalSince1970 - 1, count: 120)
    #expect(tail == fresh)
    let detail = NativeFailureClassifier.classify(
      phase: .child, charonMessage: errmsg, logLines: tail, session: session,
      elapsedMilliseconds: 1_312)
    #expect(detail.cause == .localVirtualIP)
    #expect(detail.evidence == "scoped Portal VIP preparation failed")
  }
}
