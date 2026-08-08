# PowerVPN native goal status

Authoritative contract: [`GOAL.md`](../../GOAL.md)

Repository: `/Users/larry_1/Opensource/powervpn-cli`

## 2026-08-08 — Checkpoint 0

State: PASS

Verified: Repository boundary, vendor immutability, rollback boundary, and
exclusion of gateway/server-admin/vendor-update/watchdog/GUI-restart routes.

Evidence: `GOAL.md` sections 3, 5, and 6; native replacement plan; repository
history and working-tree audit; commit `0ee4cb3`.

Changed files: Strategy documents and the read-only lab framing.

Tests/commands: Repository inventory, `git status`, helper/app inventory.

Safety/cleanup: No vendor binary or installed app changed.

Remaining: Execute protocol checkpoints.

Next command: Read-only vendor oracle validation.

Approval required: no.

## 2026-08-08 — Checkpoint 1

State: PASS

Verified: Vendor strongSwan base 5.8.0; helper architectures and hashes;
critical `leadsecbridge`; custom kernel-ipsec; private IKEv1 ADDRULE/DELRULE
markers; B+C classification; PowerVPN `utun9` versus Surge `utun8` correction.

Evidence: [`../evidence/vendor-inventory.json`](../evidence/vendor-inventory.json),
[`../protocol-ike.md`](../protocol-ike.md), and the allowlisted oracle parser
tests in commit `7cba7a2`.

Changed files: Oracle models/parsers, inventory command, protocol documents,
and incident correction.

Tests/commands: `swift run powervpn oracle inventory --json`; vendor oracle
unit tests.

Safety/cleanup: Only static binaries and allowlisted log markers were read;
raw log and symbol lines were not committed.

Remaining: Preserve build evidence and close the TunnelSpec gate.

Next command: Validate the 6.0.7 artifact manifest.

Approval required: no.

## 2026-08-08 — Checkpoint 2

State: PASS for build baseline

Verified: Official strongSwan 6.0.7 commit; scratch-only arm64 `charon`,
`swanctl`, VICI, PF_KEY, PF_ROUTE, and kernel-libipsec artifacts; `make`, scratch
install, `make check`, and unprivileged plugin-load smoke.

Evidence: [`../strongswan-6.0.7-arm64.md`](../strongswan-6.0.7-arm64.md) and
the scratch build/prefix named in `GOAL.md`.

Changed files: 6.0.7 build evidence, artifact manifest, and scratch-enforcing
build wrapper; source/build trees remain outside Git.

Tests/commands: `make check -j8`, `file` on selected artifacts, random-port
unprivileged load smoke.

Safety/cleanup: No system-prefix install, root launch, SA, route, utun, or VPN
configuration.

Remaining: Only the separately approved privileged backend checkpoint. The
reproducible build wrapper and artifact manifest are now complete; build PASS
must still not be read as runtime PASS.

Next command: Begin offline Checkpoint 4 evidence work.

Approval required: no.

## 2026-08-08 15:19 +08:00 — Checkpoint 3

State: PASS

Verified: Streaming log allowlist; static-capability semantics; historical log
truth correction; closed TunnelSpec; strict placeholder-only redacted gate;
synthetic fixture; commit-safe oracle inventory.

Evidence: [`../evidence/checkpoint-3-validation.md`](../evidence/checkpoint-3-validation.md),
[`../../fixtures/redacted/tunnel-spec.example.json`](../../fixtures/redacted/tunnel-spec.example.json),
and [`../evidence/vendor-inventory.json`](../evidence/vendor-inventory.json).

Changed files: `Sources/PowerVPNCore`, `Sources/PowerVPNCLI`, tests, fixture,
evidence, README, capture policy, and protocol/strategy documents.

Tests/commands: `swift test` (20 PASS), `swift build --arch arm64`, live
read-only oracle inventory, fixture forward validation, `jq empty`,
`git diff --check`, and Gitleaks 8.30.1 directory scan.

Safety/cleanup: No raw secret/capture entered Git; no root or live network
mutation; Gitleaks reported no leaks.

Remaining: Checkpoint 4 must recover the body field boundaries before any
network or strongSwan runtime work.

Next command: Establish the offline expandrule evidence table and synthetic
golden-byte contract.

Approval required: no.

## 2026-08-08 16:26 +08:00 — Checkpoint 4A

State: PASS

Verified: Offline expandrule wire syntax; five explicit direction/type/body
forms; dialect0/dialect1 and IPv4/IPv6 context; asymmetric client envelope and
server short body; lossless structural parser; separate canonical/local safety
profile; deterministic encoder; owned decode buffers; non-sensitive errors;
seven synthetic byte vectors and nine logical contexts.

Evidence: [`../evidence/expandrule-wire-contract.md`](../evidence/expandrule-wire-contract.md),
[`../evidence/checkpoint-4a-validation.md`](../evidence/checkpoint-4a-validation.md),
[`../../fixtures/redacted/expandrule-synthetic-v1.json`](../../fixtures/redacted/expandrule-synthetic-v1.json),
and the replayable strongSwan patch under `patches/strongswan-6.0.7/`.

Canonical commit: this checkpoint commit in the lab repository; upstream-side
implementation commit `1fda864cca91da0aa9a87dd96e1823c3962dbd09` based directly
on official 6.0.7 commit `5973ff8e41deef4e015e1138a2de688acedf6f75`.

Changed files: IKEv1-only codec/model/profile source, IKEv1-only libcharon test
wiring, 28 codec cases, V2 Goal contract, wire evidence, synthetic fixture,
checkpoint verifier, protocol status, validation evidence, and one patch file.

Tests/commands: `scripts/verify_checkpoint.sh 4a` exit 0; targeted codec suite
PASS; full strongSwan `make check` PASS; patched libcharon arm64; 20 Swift tests
PASS; Swift arm64 build PASS; exact JSON-to-C fixture/context gate PASS;
`git apply --check` against clean 6.0.7 PASS; Gitleaks and diff checks PASS.

Review lane and result: Guarded. Exactly one integrated review and one
independent targeted review ran. All direct findings were fixed before final
acceptance; no third review ran.

Safety/cleanup: Offline only. No vendor modification, live VPN, root process,
UDP binding, SA, route, policy, utun, Surge mutation, credential, raw capture,
or secret file. Upstream implementation worktree is clean.

Remaining: CP5 must correlate control-plane/XPC observations while keeping
wire fields opaque; CP4B may promote a field name only with two independent
evidence classes. Payload/task/VICI integration remains deferred to CP6.

Next command: establish the CP5 redacted field/type/order correlation table
without recording values.

Approval required: no.

## 2026-08-08 17:18 +08:00 — Checkpoint 5

State: PASS

Verified: Closed value-free correlation schema and CLI validator; ordered
control/XPC event and field model; independent auth/control/resource/helper
state domains; static portal request and response-parser order; `cs -> nc ->
ipsec` object lineage; charon/ipsec helper consumer types and order; confirmed
GUI `kDeleteActionKey` versus helper `tunnel-name` toggle mismatch; hash-locked
x86_64 LLDB observer; legal runtime session-check request/HTTP 200 correlation;
live GUI resource-toggle producer metadata; first session-timeout boundary;
resource restoration and Surge coexistence checks.

Evidence: [`../evidence/checkpoint-5-static-correlation.md`](../evidence/checkpoint-5-static-correlation.md),
[`../../fixtures/redacted/protocol-correlation-value-free-v1.json`](../../fixtures/redacted/protocol-correlation-value-free-v1.json),
[`../../fixtures/redacted/protocol-correlation-runtime-metadata-v1.json`](../../fixtures/redacted/protocol-correlation-runtime-metadata-v1.json),
and the correlation tests in `PowerVPNCoreTests`.

Canonical commit: this checkpoint commit.

Changed files: value-free Core model/decoder/validator, shared closed-JSON
shape helper, thin `oracle correlate` CLI route, tests, synthetic fixture, and
the control-plane/XPC evidence documents. The temporary debugger observer
remains outside Git in mode-700 scratch.

Tests/commands: `scripts/verify_checkpoint.sh 5` exit 0; 41 Swift tests PASS;
arm64 Swift build PASS; changed-file Swift format lint PASS; both fixture CLI
validations PASS; Gitleaks and cumulative diff checks PASS. The scratch observer
has eight sanitizer/dedup/family tests; runtime output is mode 600 under a
mode-700 root and passes the same closed validator.

Review lane and result: Guarded. Exactly one integrated checkpoint review ran.
Its direct findings—operation field profiles, helper-family discrimination,
identity-safe paths/fields, confidence consistency, cumulative staged/commit
verification, and README live-boundary wording—were fixed. Final acceptance
passed; no second review ran.

Safety/cleanup: No installed app/helper/signature, log body, Keychain, packet,
credential value, session value, or raw XPC description was changed or read.
One explicitly approved resource off/on cycle was restored; both fresh SSH
banner probes succeeded, the PowerVPN resource routes returned, Surge retained
the default route, and LLDB detached cleanly while the legal session remained
running.

Remaining: CP4B must compare this evidence with the opaque expandrule fields.
WebSocket behavior, live `start_connection` ordering, and exact
portal-field-to-PSK/resource mapping remain explicitly unknown and cannot be
guessed into CP4B names.

Next command: run the CP4B semantic-promotion gate and leave every wire field
opaque unless two independent evidence classes agree.

Approval required: no. The live observation and approved resource cycle are
complete; no further network action is part of CP5.

## 2026-08-08 18:25 +08:00 — Checkpoint 4B

State: PASS with zero semantic promotions

Verified: Eight candidate wire slots were evaluated under the
two-independent-direct-mapping-class rule. A hash-locked static chain maps the
XPC consumer into the vendor expandrule writer, but it remains one
`vendor_static_disassembly` evidence class. CP5 runtime and differential
observations did not cross `start_connection` or a plaintext serializer slot,
so they do not qualify as a second direct mapping class.

Evidence: [`../evidence/checkpoint-4b-semantic-promotion.md`](../evidence/checkpoint-4b-semantic-promotion.md)
and [`../../fixtures/redacted/semantic-promotion-gate-v1.json`](../../fixtures/redacted/semantic-promotion-gate-v1.json).

Changed files: Machine-readable promotion gate, evidence matrix, independent
CP4B verifier, IKE status, Goal checkpoint state, and this progress record. No
Swift, codec, upstream patch, or synthetic wire-vector file changed.

Tests/commands: `scripts/verify_checkpoint.sh 4b` exit 0; targeted expandrule
encode/decode/profile suite PASS; the seven JSON vectors remain byte-identical
to the compiled C fixture and CP4A commit; 41 Swift tests PASS; arm64 Swift
build PASS; Gitleaks and cumulative diff checks PASS.

Review lane and result: Exactly one integrated checkpoint review ran. Its two
P1 findings were fixed by pinning the complete candidate decision tuples,
linking candidates and promotions bidirectionally, and scoping each direct
evidence edge to an exact wire slot and candidate semantic. Final acceptance
passed; no additional independent review ran.

Safety/cleanup: Offline only. No installed app/helper, live VPN process,
session, route, SA, utun, packet, credential, Keychain, raw capture, or raw log
was read or changed. The CP4A upstream worktree remains clean at its canonical
commit.

Remaining: CP6 must integrate the neutral codec into the minimum
payload/message/task skeleton and a credential-reference-safe VICI dry run. It
must not reinterpret opaque fields during integration.

Next command: implement the CP6 replayable patch skeleton and synthetic VICI
dry run without creating an SA, route, policy, or utun.

Approval required: no.
