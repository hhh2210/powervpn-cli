# GOAL STATUS

## 2026-08-15 — ground-truth catalog shape captured; INTERGRATION_INFO root fix (attempt-1 root cause closed)

**Ground-truth capture provenance.** The real portal catalog XML shape is now
KNOWN, captured value-free from the official client's own session log
(auto-login 2026-08-15 13:52:33, record #3089): the client logs the full
`intergration.xml` verbatim; 2507 bytes extracted, parsed, structure-redacted,
raw XML destroyed. Authoritative structural report:
`~/scratch-data/powervpn-surge-capture-2026-08-14/intergration-structure-report.txt`
(43 elements, every element/attribute with length + format class, values
redacted). Provenance and teardown verification (profile byte-exact revert,
MitMEnabled=0, Replica=0, minted key 401, no background processes, zero raw
leakage — only 4 protocol-enum literal collisions):
`~/scratch-data/powervpn-surge-capture-2026-08-14/evidence-log.md` ("SOLVED
2026-08-15 14:00–14:10" section).

**Root cause of attempt-1 `resource_catalog_rejected`.** In the real reply
the XML root element IS `INTERGRATION_INFO` (report line 4; consistent with
the XMLReader root dictionary carrying `RESPONSE` and `INTERGRATION_INFO` as
sibling top-level keys — resource-list-callback dossier §3, walk at
`0x1000a8c53`+). Our `LeadSecPortalProfile.integrationInfo` only searched
CHILDREN of the root, so the real document classified as
`integration_info_missing` (stage=scope, failureClass=integration_info_missing,
ordinal=nil, fieldPath=nil). Reproduced offline on the ground-truth-shaped
fixture BEFORE the fix; the fixture then mapped completely after the fix —
no other predicate (strictInt32, validText min-1-byte, displayName
fail-closed, duplicate rejection) is tripped by the real shape: every
integer leaf we strict-parse is decimal there, and every empty leaf
(pfs/notice/cmd/ipv6/dnssrv/winssrv/jump-mapid/key_id/SECURED-ROUTES@name)
sits on an optional or unread path.

**Fix (additive, fail-closed preserved).**
`Sources/PowerVPNPortal/LeadSecPortalProfile.swift` `integrationInfo(_:)`:
a root element NAMED `INTERGRATION_INFO` is now accepted as the integration
node — but ONLY with no same-named direct child (review P1 applied): any
direct `INTERGRATION_INFO` child under a root-named document is ambiguous
(XMLReader makes duplicate structural keys arrays at `0x100135459`–
`0x1001354c0`; the official `objectForKey:` path raises on them), so both
one-child and two-child shapes throw `duplicateField` — fail-closed, not
root-wins. Any other root still requires a unique `INTERGRATION_INFO`
child (unchanged). Doc comment cites dossier §3's `0x1000a8c53`+ walk and
the ground-truth report as root-shape proof.

**Ground-truth fixture.**
`Tests/PowerVPNProductTests/AuthenticatedPortalGroundTruthCatalogTests.swift`
— synthetic replica of the structural report (43/43 elements verified by
review; exact lengths/format classes; empties stay empty; structural labels
`nc`/`login21`/`login52` only; documentation-range IPs, synthetic PSK — zero
real captured values). Tests: real shape maps completely (`snapshotComplete`,
displayName `login21`); wrapped-root shape still maps; foreign root without
INTERGRATION_INFO still fails closed (integration_info_missing); near-miss
root name still rejected; root-named + one/two same-named children throw
`duplicateField` at snapshot mint.

**Gates (all offline).** Ground-truth suite 6/6; focused suites
(SP2Mapper+GroundTruth+DryRunRuntime+DryRunCatalogFailure+SnapshotMapper)
46 tests / 5 suites passed; FULL `swift test` exit 0 (37+172+176+273 = 658
swift-testing tests, 0 failures); `swift build --product powervpn --arch
arm64` clean; `xcrun swift-format lint --strict` clean on both changed
files; `git diff --check` clean; `scripts/verify_no_secrets.sh` clean
(2.86 MB scanned, no leaks).

**Review verdict:** GO with one P1 (duplicate-child fail-closed under
root-named documents) — applied and pinned by tests; citation nit
(§3 `0x1000a8c53`+ instead of §2 range) — applied.

**Next:** no live native action yet; attempt-2 dry-run approval pending
(Larry's per-attempt verbatim approval phrase required).

## 2026-08-15 — tunnel parity and charon downstream contract

**Captured ground truth and cardinality.** The catalog root is
`INTERGRATION_INFO`: exactly 1 `NC_RESOURCE` contains 2 sibling `TUNNEL`
elements. Native mapping produces 1 candidate and 1 encoded start envelope
containing both tunnels, matching the official wire shape for this capture.
The earlier multi-NC hypothesis is explicitly refuted for the current ground
truth and deferred until a real multi-NC catalog exists.

**Accepted deltas and integrated review.** A (`01aad98d`) mirrors the daemon's
length guards by allowing empty `vip`/`vipv6`; B (`54830492`) accepts the
official logout HTTP 200–204 status family; C (`cab60035`) maps resource-child
`PRIVATE-IP@addr` into `common.vip` with exact official precedence
`extensionAddr ?? resourceAddr`. A/B/C are GO. D's hidden
`tunnelDisplayNames` alias is NO-GO and fully reverted: it exposed raw,
status-ineligible tunnel names and violated cross-surface truthfulness (two
P1-product findings).

**Frozen charon downstream contract.** The helper drives a custom in-process
libcharon API directly, with no generated config or VICI path.
`common.ike`/`common.esp` pass raw to `proposal_create_from_string`; the PSK
callback copies the raw `strlen` bytes; local identity is `ID_KEY_ID` with
payload `common.sessionid`, preserved from `IKE/CLIENT@id`. The helper contains
no portal-session machinery.

**Exact structural `HASH_V1` ranking.** (1) PSK-byte divergence, stale
authenticated generation, or wrong PSK leaf; (2) wrong IKE-SA/transcript/key
state; (3) block-aligned ciphertext corruption or peer defect; (4) local-ID
content/type mismatch, low for this structural log because that should reach a
semantic HASH mismatch after valid decryption. The stale multi-NC theory is
not a cause for this 1-NC capture and remains deferred.

**Continuity, cardinality, and gates.** Tests pin resource fallback, extension
precedence, missing-extension-addr fallback, ground-truth VIP length 8,
1 candidate/2 tunnels/1 envelope, raw PSK-byte continuity, and
`CLIENT@id` → `common.sessionid` continuity. Final offline gates pass:
668 tests / 107 suites (TLSEvidence 37/9, Product 180/31, Portal 177/30,
Core 274/37), arm64 `powervpn` build, strict lint on all 10 Swift files
changed from origin, diff-check, and no-secrets over approximately 2.88 MB.

**Evidence.**
- `/Users/larry_1/scratch-data/powervpn-suite-parity-2026-08-15/REPORT.md`
- `/Users/larry_1/scratch-data/powervpn-official-reverse-2026-08-11/charon-helper-downstream-dossier.md`
- `/Users/larry_1/scratch-data/powervpn-official-reverse-2026-08-11/charon-helper-downstream-findings.json`
- `/Users/larry_1/scratch-data/powervpn-surge-capture-2026-08-14/intergration-structure-report.txt`
- `/Users/larry_1/scratch-data/powervpn-surge-capture-2026-08-14/evidence-log.md`

**Live boundary.** No live action was taken. Attempt-2 Portal-only dry-run
requires fresh, per-attempt Larry approval.
