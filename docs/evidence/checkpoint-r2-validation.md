# Rescue R2 username/password portal-login gate

Status: **OFFLINE PASS; R2B FAIL / INCOMPLETE — `tls_rejected`; TLS evidence
attempts 1–2 INCONCLUSIVE / FAIL; GOAL ACTIVE.**
The integrated R2 offline-base and raw-header reviews are complete, all direct
findings are applied, and the full offline verifier passes. One authorized,
manifest-bound live window subsequently completed with `checkpointPass=false`.
It did not establish successful TLS, login acceptance or server compatibility.

## Scope

The only server-facing order implemented by this checkpoint is:

```text
POST password login
GET resource catalog
wait 60 seconds
GET session check
POST logout
```

There is no `start_connection`, XPC, VICI, IKE, UDP 500/4500, SA, policy,
route, utun, resource activation, retry, CAPTCHA bypass, or generic insecure
TLS mode. A CAPTCHA/challenge response is a closed `challenge_required`
outcome and stops the transaction.

## Installed configuration evidence

The selected address path was recovered statically from the exact installed
PowerVPN 3.2.1 build 24572: `address_selectedID == 0` selects
`VSGAddressModel ORDER BY pk DESC LIMIT 1`, and the app formats the selected
`address` and decimal `port` as an HTTPS origin. The profile version is the
literal `2.0`.

A bounded read-only confirmation used the exact upstream SQLCipher 3.4.0
CommonCrypto build against a mode-600 encrypted database copy. The vendor's
13-byte database passphrase was derived inside the producer process, delivered
only through a pipe, and zeroed; it did not enter argv, environment, a script,
stdout, stderr, or the repository. The only row query was:

```sql
SELECT quote(address), quote(port), pk
FROM VSGAddressModel
ORDER BY pk DESC
LIMIT 1;
```

No `VSGUsersModel` row was queried. The selected address/port matched the
sealed origin used by the candidate. Runtime discovery accepts no endpoint
argument: it verifies exact app, Info.plist, encrypted-database and preferences
artifacts, validates the selection and language state, then materializes only
that reviewed profile. A changed installation fails closed.

The installed app disables peer and hostname verification. R2 deliberately
does not reproduce that security defect: it requires the exact selected host
and macOS system trust, rejects all redirects before a second request, rejects
task-level authentication challenges, and has no `--insecure` path. This is an
explicit safe product boundary, not evidence that the vendor verified TLS.

## Password and session compatibility profile

Static disassembly of the exact installed binary establishes the default
password POST body:

```text
encode='1'&hardware_hash=<raw-platform-serial>&password=<base64>&terminal_type=mac&type=app&username=<base64>
```

Keys are lexicographically ordered, values are not percent-escaped, username
and password are independently standard-Base64 encoded, and `hardware_hash`
is the unmodified platform serial. The request uses `Content-Type: text/xml`.
R2 does not infer the unobserved `encode=2` version-preflight path.

Login accepts numeric hexadecimal `RESPONSE.RESULT.code == 0`; the known
verification-code challenge fails closed. A `VSG_SESSIONID` comes from the
password response's `Set-Cookie`, not the XML. The fresh isolated jar preserves
the observed vendor spacing and `ORIGINURL` suffix. Foundation still exposes
only a projected Set-Cookie value and cannot establish raw header multiplicity,
so that transport remains fail closed before `session.open`. The reviewed
system-libcurl seam observes bounded raw header fields and accepts only a
factory-proven exact password request with one final `Set-Cookie` field. Its
evidence is synthetic; server tolerance is not used as a substitute for
vendor-exact framing.

Resource acceptance mirrors the vendor's minimal gate: an empty or missing
resource list is allowed, while `0x80000020` and `RESPONSE.ERROR` reject. The
session query is exactly `key=hostid`; only exact `0x80000014` means invalid.
Logout is an empty-body POST with no upload Content-Type or Content-Length.

The installed preferences currently contain `currentLanguageKey=en-US`, but
the vendor compares it against `"en"`, misses, and returns language index zero.
The resulting compatibility cookie is therefore `zh_CN`. R2 preserves this
observed bug instead of normalizing it to the UI language.

## Memory and library boundary

Username, password, platform serial, request bodies, response bodies, parsed
XML scalar values and the session cookie are held in app-owned, explicitly
erasable buffers. The workflow reports erasure only after observing those
owned buffers at zero length and no active tracked request/response.

The URLRequest bridge explicitly constructs one transient Swift `String` from
the Cookie buffer, after which URLSession may create additional Foundation/CF
copies. None of those bridge/framework copies is claimed zeroized. The report
claims only `appOwnedSecureBuffersErasureObserved`; it separately fixes
`swiftAndFoundationBridgeCopiesErasureClaimed=false`. The retained projection
contains no endpoint, serial, cookie, body, resource value or credential
length.

## Offline acceptance and live boundary

The Swift package isolates `PowerVPNPortal`: it may depend only on the
package-local `CPortalCurl` target and cannot import `PowerVPNCore`, XPC, VICI
or helper code. `powervpn login` accepts no option or positional material;
invalid arguments are rejected before runtime construction. The live harness
clears the child environment, leaves stdin at `/dev/null`, supplies prompts
through the controlling TTY, reconstructs stdout through a FIFO and closed
`jq` schema, and retains only mode-600 value-free evidence.

The authorized live harness required all of these before the attempt could
start:

- reviewed candidate manifest SHA-256
  `bde4de003e1c5bd2128f5e4b147f05ae3149f2b639126e783585bfb6a1b6302b`
  and a fresh authorization bound to that exact hash;
- exact manifest-bound network snapshot script;
- PowerVPN GUI, all vendor helpers and native charon absent;
- exact inactive launchd generation;
- explicit non-secret exposed-credential risk acceptance;
- direct controlling TTY;
- before/after network-state equality.

During the window, the CLI was permitted TCP only to the sealed portal origin.
Any UDP descriptor, helper/native-charon process, other remote TCP endpoint,
route/DNS/interface/utun drift, invalid report, or cleanup residue failed the
checkpoint.

One password was pasted into the Codex task text during R2 development. It was
not used by code or tests. The user states that it cannot be rotated and has
explicitly accepted the risk of continuing with the same credential. Chat/task
text remains an invalid runtime source: the value must never be read or copied
from it. The live window required approval bound to the exact manifest and the
non-secret risk-acceptance gate; the user personally re-entered the credential
through the no-echo controlling TTY. The retained schema records
`credentialPath.exposedCredentialRiskAccepted=true` and makes no rotation
claim.

## Authorized live-window result

The retained value-free fixture is
`fixtures/redacted/r2-portal-login-runtime-v1.json`, SHA-256
`78a0815ab247c36e8d30683b7f83a09d34d4da2dbe94e395e6f116c8423ca714`.
It is complete, exact and bound to the archived authorized-manifest bytes at
`fixtures/redacted/r2-portal-login-authorized-manifest-v1.json`, SHA-256
`bde4de003e1c5bd2128f5e4b147f05ae3149f2b639126e783585bfb6a1b6302b`.
The result is `checkpointPass=false`, CLI exit 2 and `status=tls_rejected`.
Only `loginRequested=true`; `loginAccepted=false`, and every resource-list,
session-check and logout request/acceptance field is false.

The exact monitor has `inspectionSucceeded=false` and recorded no portal TCP
descriptor, helper, native charon or UDP descriptor (`portalTCPObserved=false`,
`maximumTCPCount=0`, `maximumUDPCount=0`). Helper launchd stayed inactive with
runs 19→19. Artifact identity and cleanup are exact, no harness kill was sent,
all app-owned secure material was erased, and the fixture contains neither
secrets nor raw portal material.

The strict `networkStable` field is false solely because the raw IPv4 route SHA
changed. Total route count remained 136. Persistent route count 65/hash,
default route, DNS, interfaces, utun, ESP and Surge stayed stable. This bounded
failure is not server/application compatibility evidence and does not authorize
a blind retry.

## Integrated review closure and offline acceptance

Exactly one cumulative R2 integrated review completed. Its five direct findings
were fixed:

1. real process signals now enter bounded task cancellation/cleanup;
2. request cancellation no longer destroys the transport needed for logout;
3. unknown or folded Set-Cookie framing fails closed before network dispatch;
4. the network snapshot dependency is included in manifest identity; and
5. the report limits its erasure claim to observed app-owned secure buffers.

The independent raw-header review returned exactly two direct findings, both
fixed: a factory-only unforgeable operation proof now excludes forged body,
Cookie and User-Agent near misses with zero transport-lane hits; TLS trust
classification is limited to peer/issuer verification while handshake and
cipher failures are `unavailable`. No second raw-header review ran.

The live-authorized manifest archive above binds runtime source aggregate
SHA-256
`83c590c8ebb3c15b8e32d125bfbdef6c4b39aabd94ca9235c35aef140b67eee2`.
The same manifest binds runtime-library SHA-256
`b57c969c986f46c58913c5e5d27bace5131771ff9e343c111e86389d97a12047`
and raw-header-test aggregate SHA-256
`a6d98b928a9c0a63ded37b7b60120e9483fabddf8dea6a895a160276a4acab05`.
The authorized candidate's full offline verifier passed 120 Portal tests in 19
suites and 109 Core tests in 10 suites (229 tests in 29 suites), the arm64
build, strict formatting, the
no-network signal harness, the secret scan and the exact manifest gate. The raw
sub-gates passed 11 direct C parser cases, 5 direct C status cases, 16 Swift
cases in 3 suites and the separate Foundation fail-closed regression.

Post-evidence verifier binding changed the current development manifest to
SHA-256
`8e19d1937d7ab432e9a747725d636e565432159561a0962a6d0ec07afe9fdb1e`.
That manifest was not authorized for the retained live window and is not a
retry authorization.

This proves only the reviewed offline implementation and safety boundary. The
authorized live window used a user-entered TTY credential but retained no
credential or raw portal material. It did not complete TLS, accept login, start
resource/session/logout operations, or invoke helper, XPC, VICI, IKE, UDP,
route, policy, SA or utun actions. Server compatibility remains unproven; R2B
is **FAIL / INCOMPLETE** and the Goal remains active.

The synthetic missing-risk case exits with status 5 before creating live
evidence or changing system state; scratch identity and network/process state
remain unchanged, proving zero residue at that gate.

## Credential-free TLS peer evidence attempt 1

The first credential-free TLS-only window was bound to the byte-exact archived
authorized manifest at
`fixtures/redacted/r2-tls-evidence-authorized-manifest-v1.json`, SHA-256
`e8b622cb4600ae5e603364accd13dffcd45d1a4aa6a48afe69401fee314cd5d4`.
It requested no credential, HTTP operation or application-data send. Its
retained value-free result is
`fixtures/redacted/r2-tls-peer-runtime-v1.json`, SHA-256
`27a0b7a511addff9888041c94c94b1a3ba9f408ff0a15b3941dcb7d4f6e3d61b`;
it records `cliReportExact=true`, and the corresponding standalone live report
has SHA-256
`108b10b5282842b30a29bb4f7a9821520abfaaa12227f629f96992140f91cfe4`.

The live-window artifact is complete, but the checkpoint failed:
`checkpointPass=false`, CLI exit 2 and `status=timed_out`. The CLI reported no
certificate chain (`chainLength=0` and null leaf hashes), so both SSL-host and
basic trust categories are `unavailable`. The exact monitor observed the target
process but could not complete descriptor inspection; it recorded no
sealed-endpoint TCP descriptor and no UDP/helper/native-charon process. The
strict network projection also failed because the transient IPv4 route hash
changed. Launchd remained inactive with runs 19→19, artifact identity and
cleanup were exact, and no harness kill was sent.

This is **INCONCLUSIVE / FAIL**, not evidence that the peer is compatible or
incompatible and not a server/TLS acceptance result. The closed
`nextTrustDisposition=incompatible_or_inconclusive` value is a fail-closed
bucket; the missing peer chain requires the narrower conclusion
`inconclusive`. No credential retry is justified.

The authorization bound to manifest SHA-256
`e8b622cb4600ae5e603364accd13dffcd45d1a4aa6a48afe69401fee314cd5d4`
is consumed and MUST NOT be reused. Before any attempt 2, the timeout and
monitor inspection/process-identity ambiguity must be diagnosed offline, the
corrected source and complete dependencies must be sealed into a new reviewed
manifest, and fresh explicit authorization must bind that exact manifest. Do
not blindly retry, weaken system trust, add an insecure/custom-CA path, send
HTTP/application data or request another credential entry. The Goal remains
active.

## Post-attempt-1 TLS evidence candidate

The attempt-1 timeout was narrowed offline without contacting the portal.
Localhost-only differentials showed that system libcurl and Network.framework
both suppress IP-literal SNI, whether or not the Network.framework server-name
override is present. The override was removed to match the observable libcurl
ClientHello behavior. A second localhost-only differential executed the exact
trust snapshot builder and found no deadlock or multi-second stall. These are
implementation diagnostics only; they do not explain the live timeout or
establish peer compatibility.

The corrected candidate adds a closed v2 `transportProgress` object so a later
timeout distinguishes connection start, preparing, waiting, verify-callback,
failed and ready phases without retaining an error description, endpoint value
or certificate. Its TLS-only observer deadline is 15 seconds and the harness
wait is bounded to 20 seconds. The runner now monitors only the exact
same-PID-exec CLI image with direct-parent, absolute `comm` and exact command
checks. Wrapper visibility no longer satisfies `targetObserved`, pre-exec
`lsof` transitions cannot poison the result, and any post-exec identity or
inspection failure remains fail-closed.

Attempt 2 is additionally bound to the unique byte-exact attempt-1 predecessor:
the archived manifest SHA-256 must be
`e8b622cb4600ae5e603364accd13dffcd45d1a4aa6a48afe69401fee314cd5d4`
and the retained failure fixture SHA-256 must be
`27a0b7a511addff9888041c94c94b1a3ba9f408ff0a15b3941dcb7d4f6e3d61b`.
Missing, altered or extra run evidence, an old experiment selector, or a stale
manifest approval fails before network start. Cold preflight now publishes and
requires `predecessorReady=true` instead of deferring that check until after an
approval.

One post-attempt-1 main-agent narrow review found that missing preflight
predecessor binding and it was fixed. An attempted independent Claude review
did not authenticate (`OAuth session expired`) and is not counted as a passed
review. No review-of-review ran. The resulting candidate manifest is SHA-256
`b63fc19d41a50e99e473156c7c486b44d0d970147da743cf45b25474af00b354`,
with review state
`post_attempt1_narrow_review_completed_findings_applied`.

The complete offline gate passed 14 TLS-evidence tests, 120 Portal tests and
109 Core tests (243 total), arm64 build, strict formatting, shell syntax,
ShellCheck, exact PID/attempt synthetic harnesses, historical failure-fixture
validation, Gitleaks and diff checks. That offline PASS qualified only the
exact reviewed candidate for one separately authorized attempt; it did not
predict or establish the live result recorded below. No credential, HTTP or
application data was part of that window.

## Credential-free TLS peer evidence attempt 2

Attempt 2 was bound to the byte-exact authorized-manifest archive at
`fixtures/redacted/r2-tls-evidence-attempt2-authorized-manifest-v1.json`,
SHA-256
`b63fc19d41a50e99e473156c7c486b44d0d970147da743cf45b25474af00b354`.
The retained value-free result is
`fixtures/redacted/r2-tls-peer-runtime-attempt2-v1.json`, SHA-256
`8766a176e542173bf7b53b79ca005cde0c222a5d2c699871e6aeafd329761219`;
it records `cliReportExact=true`, and the corresponding standalone live report
has SHA-256
`603dce97c50c6c014dc2d83f1be2ded00dee75dfbcfc0ecdb9bd4b4e63ced647`.

The live-window artifact is complete, but the checkpoint failed:
`checkpointPass=false`, CLI exit 2 and `status=timed_out`. Value-free transport
progress proves only that connection start, preparing, waiting and the verify
callback were observed. Neither `ready` nor `failed` was observed. The CLI
reported no certificate chain (`chainLength=0`, empty ordered hashes and null
leaf hashes), so both SSL-host and basic trust categories remain `unavailable`.
These phase markers do not identify a specific blocking line inside the trust
builder and do not establish peer compatibility, incompatibility or TLS/server
acceptance.

The separate value-free live monitor, SHA-256
`0f310886e8bbd99ad28a9ed36de8eec619d9616fbcbc26db8354fb17b6f9b5b0`,
retained exact and stable target identity. Of 62 descriptor inspections, 60
succeeded and 2 failed, making its aggregate `inspectionSucceeded=false`. It
observed no sealed-endpoint TCP descriptor and no UDP/helper/native-charon
process. Because the positive TCP condition was not met, the closed result
correctly retains `monitorExact=false` and `monitor=null`; process identity and
successful samples are diagnostic evidence, not acceptance evidence. The
strict network projection also failed on a transient IPv4 route-hash change.
Launchd remained inactive at runs 19→19, artifact identity and cleanup were
exact, and no harness kill was sent.

Attempt 2 is therefore **INCONCLUSIVE / FAIL**. It requested no credential,
HTTP operation or application-data send and retained no raw certificate,
certificate identity or secret. The closed
`nextTrustDisposition=incompatible_or_inconclusive` bucket is narrowed here to
`inconclusive` because no peer chain or trust result exists. It does not
reclassify R2B or attempt 1.

The authorization bound to manifest SHA-256
`b63fc19d41a50e99e473156c7c486b44d0d970147da743cf45b25474af00b354`
is consumed and MUST NOT be reused. Do not blindly start attempt 3, retry the
password login, weaken system trust, add an insecure/custom-CA path, send HTTP
or application data, or request another credential entry. Any later live
attempt requires a new evidence-bounded offline diagnosis, a newly sealed and
reviewed exact manifest, and fresh explicit authorization. The Goal remains
active.

## Post-attempt-2 narrow hardening candidate

The retained attempt-2 failure was diagnosed offline and was not replayed.
Localhost-only Network.framework tests now prove that automatic IP-literal TLS
and an explicit IP-literal server-name setter both emit no SNI extension; each
enters the verify callback once, calls `completion(false)` once, never becomes
ready and sends no application data. The connection lifecycle is now
linearizable and sticky: cancellation before or during construction cannot
start a connection, duplicate start cannot re-arm it, cancellation is
idempotent and late callbacks cannot mutate terminal evidence.

The harness now uses one absolute monotonic deadline across its gate, child,
validator, monitor, snapshot and cleanup phases. Synthetic blocked-gate and
blocked-validator cases terminate with closed deadline evidence and zero owned
process/FIFO residue. The process monitor validates PID, PPID, executable and
exact command before counting an inspection; its single `lsof -i` classifier
has positive localhost TCP, zero-socket, wrong-endpoint and inspection-error
coverage. A successful live checkpoint would additionally require exactly one
sealed-endpoint TCP descriptor and zero UDP descriptors.

Trust classification no longer lets accepted Basic trust rewrite a failed SSL
hostname evaluation. Swift and shell both require integral observed chain
lengths in 1...16 and the same closed progress/category invariants. Post-run
`manifestExact` is recomputed from the current candidate bytes and authorized
SHA instead of being hard-coded. Source, full TLS test tree, all transitive
runtime/test scripts, network-snapshot inputs, verifier inputs and the exact
test-only `/usr/bin/openssl` executable are now sealed; symlinks, FIFOs and
other special descendants fail closed.

The complete offline verifier passed 18 TLS-evidence, 120 Portal and 109 Core
tests (247 total), the localhost differential, arm64 product build, strict
formatting, ShellCheck, historical fixtures, manifest-mutation tests, Gitleaks
and diff checks. The current exact candidate manifest SHA-256 is
`d46773c3f2e5a1f3aaebc2409da3ff807e02ef102c75cf9ea5158481c35713c2`;
its review state remains `post_attempt1_narrow_review_pending`, so cold
preflight is deliberately not live-authorized. No new TLS live window, portal
login, credential request, HTTP request or application-data send occurred.
Attempt 3 requires a completed independent review, a newly sealed exact
manifest if any byte changes, and fresh explicit authorization. The Goal
remains active.

## Attempt-3 review-only candidate

The new candidate is an offline diagnostic delta over the exact retained
attempt-2 failure. It does not reuse either consumed authorization and it has
not opened a new live window. The predecessor gate requires exactly the two
historical run directories, each with the exact five mode-600 evidence files.
Their closed aggregates are
`aef7d3b7734b132f6b5d1bb3fc498d7609d3424c0808a5a029af0e4076d687c9`
and
`21eb127eae03c6c49a56538e285cab0215e00d7122a1c8c0d8184d646bbdcce2`.
It also binds the attempt-2 authorized manifest
`b63fc19d41a50e99e473156c7c486b44d0d970147da743cf45b25474af00b354`
and retained result
`8766a176e542173bf7b53b79ca005cde0c222a5d2c699871e6aeafd329761219`.
Any missing, altered or extra predecessor artifact fails before network start.
A future exact approval would be consumed atomically in a manifest-named
directory before the runner creates a live run; this code path has not run.

The v3 observer copies 1...16 peer certificates directly from
`sec_protocol_metadata_access_peer_certificate_chain`, caps each copied DER at
65,536 bytes, and invokes the verify completion with `false` exactly once per
callback. SSL-host and Basic-X509 trust objects are newly constructed and kept
alive until two `SecTrustEvaluateAsyncWithError` results complete or the single
five-second evaluation deadline expires. Evaluation is outside the handshake
callback, on a dedicated serial queue, with certificate fetching and revocation
network access disabled. Security.framework exposes no cancellation API for an
already-running async evaluation; cancellation/deadline releases app-owned
state, suppresses publication and ignores late callbacks rather than claiming
the system operation was killed.

The retained CLI schema contains only ordered certificate/SPKI SHA-256 values,
closed trust categories and phase booleans. It contains no certificate bytes,
subject, issuer, SAN, serial, endpoint/error description, credential, HTTP,
application data or helper result. An observed report no longer depends on a
later `.failed` state callback. The root result independently records
`executionSafetyPass`, `transportEvidenceComplete`, `trustEvidenceComplete`,
`compatibilityOutcome`, `trustDisposition`, `monitorQuality`,
`environmentStable` and `checkpointPass`; these dimensions cannot prove one
another.

The follow-up delta analysis of `c86aa105…e2f48` required stronger closure than
the earlier two P1 fixes alone. Transport and evidence progress now come from
one lock-protected combined snapshot; active-callback fields are written
transactionally; late rejection-only completion remains a documented exception;
and Swift construction/encode/decode plus shell closed-schema validation agree.
Trust reservation commit is the logical start linearization point. The shell
runner stops, PID-acknowledges, waits for and rechecks the deadline guard before
computing dimensions once and atomically publishing the final result. Its exact
manifest SHA-256 is
`22b73d9f6b1f583335f2b0f24f2331b904c8b6bb0f2cb29ef8c99ebb43d54f9d`, with review
state `post_attempt2_narrow_review_pending`. The full offline verifier and
deterministic review-bundle synthetic gate pass: 37 TLS-evidence, 120 Portal
and 109 Core tests (266 total), arm64 product build, strict formatting,
ShellCheck, Gitleaks, historical/lineage/manifest negatives and byte-identical
ZIP construction. The final ZIP itself is exported only from the clean commit.
Until an independent delta reviewer returns on those exact bytes and a new exact
authorization is given, attempt 3, portal login, R3 and UI work are **HARD
NO-GO**.
