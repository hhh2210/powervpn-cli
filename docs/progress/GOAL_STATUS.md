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

## 2026-08-08 19:26 +08:00 — Checkpoint 6

State: PASS (offline compatibility-port checkpoint). The post-fix
implementation matches the vendor static Quick Mode phase/HASH(3) contract and
an independent synthetic reference. Live vendor differential behavior and
server acceptance remain unproven. The separate daemon VICI smoke remains
BLOCKED but is outside deterministic dry-run acceptance.

Verified vendor static evidence: `_get_hash_phase2` at `0x10014fa70` has no
custom branch; Quick Mode `_build_i` state 0 builds standard SA/NONCE/TS and
state 1 appends ADDRULE. The `[HASH ADDRULE]` message therefore uses standard
`HASH(3) = PRF(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)` and excludes ADDRULE bytes.

Verified implementation evidence: private payload factory/raw-header wrapper,
explicit neutral form/dialect task, exact state-0/state-1 placement, standard
HASH(3), stock ordered VICI `load-conn` bytes, credential-reference-safe dry
run, duplicate-key rejection, and no-IKEv1 link isolation. The independent
synthetic reference calculates the expected PRF and proves ADDRULE-byte
exclusion with mutation counterchecks.

Protocol fidelity hard rules:

1. MUST NOT add/remove/reorder/normalize/reinterpret/symmetrize observed wire.
2. Every outbound byte MUST have evidence.
3. Unknown values MUST remain opaque.
4. Parse MUST NOT imply accept or emit.
5. The private predicate MUST be complete; outside it, upstream is unchanged.
6. Same-implementation round trips prove self-consistency only.
7. Observed vendor behavior outranks standards cleanup.
8. Wire-neutral safety is allowed; wire-visible improvement/generalization is
   forbidden.
9. Owned XPC/control/internal architecture may be refactored.
10. Intentional divergence MUST be outside the compatibility profile,
    independently feature-gated, and default off.

Evidence: [`../evidence/checkpoint-6-validation.md`](../evidence/checkpoint-6-validation.md),
[`../../patches/strongswan-6.0.7/series.json`](../../patches/strongswan-6.0.7/series.json),
[`../../fixtures/redacted/leadsec-qm-hash3-static-vector-v1.json`](../../fixtures/redacted/leadsec-qm-hash3-static-vector-v1.json),
[`../../fixtures/redacted/vici-load-conn-dry-run-v1.json`](../../fixtures/redacted/vici-load-conn-dry-run-v1.json),
and [`../../fixtures/redacted/vici-daemon-smoke-summary-v1.json`](../../fixtures/redacted/vici-daemon-smoke-summary-v1.json).

Canonical lab commit: this checkpoint commit. Upstream CP6 commit
`67c9810900e2d8486cb3b11495a8362433494ca0`, 0002 patch SHA-256
`6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213`, on CP4A
commit `1fda864cca91da0aa9a87dd96e1823c3962dbd09`.

Changed files: Pure Swift ordered VICI model/codec and TunnelSpec builder,
closed JSON duplicate-key scanner, CLI dry-run route, tests, official Python
oracle fixture verifier, redacted fixtures, two-patch strongSwan series,
LeadSec HASH(3) static/reference fixture, checkpoint verifier, evidence,
protocol status, README, Goal state, and this progress record.

Tests/commands: `scripts/verify_checkpoint.sh 6` exit 0; targeted expandrule
39/39; full libcharon 5/5; full patched strongSwan checks; arm64 `libcharon`;
independent no-IKEv1 PASS; `keymat_v1.c` and `task_manager_v1.c` zero-diff from
CP4A; patch replay tree equality; independent HASH(3) synthetic reference;
14 targeted Swift tests; 55 full Swift tests; arm64 Swift build; official 6.0.7
Python VICI oracle exact 324/335-byte equality; strict Swift format; Gitleaks
and cumulative diff checks.

Review lane and result: Exactly one integrated checkpoint review found two P2
issues: duplicate JSON keys survived Foundation canonicalization, and the
no-IKEv1 build retained an unlinked expandrule factory reference. Both were
fixed and tested. The one permitted independent narrow review found one P2:
reversed `[NONCE, ADDRULE]` order could evade the direct keymat private-payload
presence flag in the pre-static-evidence candidate. The vendor-faithful post-fix
implementation supersedes that keymat branch and leaves `keymat_v1.c`
unchanged. No additional or third review ran.

Safety/cleanup: Offline implementation and dry run performed no socket,
credential-secret, SA, route, policy, utun, or vendor mutation. One isolated
non-root daemon attempt used random ports and fake kernel but timed out on its
first VICI `version` request; it sent no `load-conn` and left no process, UDP
descriptor, PID, UNIX socket, or new utun. Whole-route-table equality was not
claimed because unrelated dynamic routes changed during the window.

Remaining: `current_checkpoint` advances to CP7 live-backend approval prep.
Diagnose the VICI `version` timeout as a bounded unprivileged control-path issue
and write the live launch/stop/rollback artifacts. Live differential and server
acceptance, backend SA/policy installation, Surge coexistence, and server interop
remain unproven.

Next command: diagnose the scratch VICI `version` response timeout and write the
Live Approval Gate artifacts without loading credentials or mutating network
state.

Approval required: no for the bounded diagnosis; explicit approval remains
required before any Checkpoint 7 live-backend action.

## 2026-08-08 — Checkpoint 7A

State: PASS (local runtime only). Workflow state: WAITING FOR APPROVAL at Live
Approval Gate 1.

Verified: The locked arm64 CP6 `charon` now has a real VICI control path. The
old timeout was causally isolated to four workers being occupied by four
long-running CRITICAL jobs. Changing only `threads=4` to `threads=5` changed
both official-Python and Swift clients from response-header timeout to the same
valid `version` response on the same daemon/socket window. Both clients then
completed the credential-free RFC-5737 load/list/unload lifecycle and restored
the daemon baseline.

Evidence: [`../evidence/vici-runtime-diagnosis.md`](../evidence/vici-runtime-diagnosis.md),
[`../evidence/live-test-plan.md`](../evidence/live-test-plan.md),
[`../evidence/rollback.md`](../evidence/rollback.md), and
[`../../fixtures/redacted/vici-runtime-cp7a-summary-v1.json`](../../fixtures/redacted/vici-runtime-cp7a-summary-v1.json).
This is L5 local-runtime evidence, not privileged-backend or server evidence.

Canonical commit: this checkpoint commit. Locked strongSwan runtime commit
`67c9810900e2d8486cb3b11495a8362433494ca0`; arm64 runtime binary SHA-256
`a2f6813d3c21ed8f907072754051d40afb2630ffc7101dd40576fa0c81fdfc2a`.

Changed files: framed Unix-domain VICI transport/session/runtime probe, thin CLI
commands, official 6.0.7 Python runtime oracle, pinned scratch-piddir build,
generation-owned launch/stop/snapshot/assert scripts, tests, value-free fixture,
and evidence/rollback documentation. CP6 strongSwan source and patch anchors are
unchanged.

Tests/commands: `scripts/verify_checkpoint.sh 7a` exit 0; candidate run had 25
targeted VICI tests and 74 full Swift tests PASS, arm64 build PASS, shell
negative tests PASS, strict Swift format PASS, Gitleaks PASS, and diff check
PASS. Post-review affected validation added a sixth session test, reran the
lifecycle negative suite, brought the targeted VICI total to 26/26, and passed
a bounded unprivileged `start -> version -> stop` cleanup smoke.

Review lane and result: Exactly one integrated review ran. It found three
direct issues: streamed terminal `success=no` was ignored, failed-start cleanup
did not explicitly wait/reap, and missing state could mask a fixed socket or
generation-directory residue. All were fixed with fail-closed tests. No second
or unrelated history review ran.

Safety/cleanup: All accepted runs were unprivileged, fake-kernel, credential-free,
serverless, and on ephemeral ports. No SA, policy, route, utun, production IKE
port, PowerVPN process, or Surge configuration was changed. Final teardown has
no state, PID file, fixed socket, generation directory, or native process.

Remaining: A privileged macOS backend, SA/policy installation, server
interoperability, credential handoff, IKE/CHILD SA, ADDRULE acceptance, resource
route/data path, and recovery all remain unproven. None is implied by CP7A.

Next command at this historical gate: request CP7B preflight authorization.
The later CP7B material finding supersedes the random-high-port proposal; see
the following entry.

Approval required at this historical gate: yes. Preflight implementation was
subsequently authorized, but privileged launch still requires separate approval.

## 2026-08-09 — Checkpoint 7B preflight

State: **WAITING FOR APPROVAL.** The cumulative preflight is PASS; root/live
execution has not run and requires a second explicit approval.

Evidence level: L1/L3/L4 source, build, review, and dry-preflight evidence only.
No privileged backend constructor has run, so L5 is not proven.

Verified: `socket-default` is excluded because its macOS PF_KEY NAT-T path writes
global `net.inet.ipsec.esp_port` without teardown restore. The candidate uses
`socket-dynamic` with a zero-UDP/no-send contract. A dedicated arm64 closure is
protected by a root-owned parent and fully revalidated before `exec`/`dlopen`.
The launcher writes a handshake, commits atomic `starting` state, then releases
the gate and `execv()`s `charon` with the same PID. The 300-second guard begins
before the first privileged snapshot. UDP inspection, loaded-plugin equality,
PowerVPN/Surge process identity, and retained manifest/source/config bindings
all fail closed.

Evidence: [`../evidence/checkpoint-7b-preflight.md`](../evidence/checkpoint-7b-preflight.md),
[`../evidence/live-test-plan.md`](../evidence/live-test-plan.md),
[`../evidence/rollback.md`](../evidence/rollback.md), and the finalized value-free
approval manifest. Manifest SHA-256 is
`c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`.

Canonical commit: this cumulative CP7B preflight checkpoint commit.

StrongSwan commit/patch SHA-256: locked CP6 parent
`67c9810900e2d8486cb3b11495a8362433494ca0`; CP7B build-only commit
`a81298234753f314dbf2c4f2867a9a144006bd8c`; patch 0003 SHA-256
`3c7615e5bf2ec284f04177e903b88fb3b452f1ce9d1f39968fd89c40ea6771c4`.
It changes macOS RFC 3542 compile declarations only, not IKE/expandrule/wire
behavior.

Changed files: dedicated build/patch manifest, sealed closure and copied
`libcrypto`, manifest-bound runner/authorizer/root worker, same-PID gated
launcher, state/attempt/snapshot/emergency-stop/assert helpers, official-Python
value-free VICI inventory, negative tests, and evidence/gate/rollback docs.

Tests/commands: `scripts/verify_checkpoint.sh 7b-preflight` PASS; dedicated build
and arm64/scratch-piddir checks PASS; exact patch replay PASS; same-PID and
spawn-before-state TERM injection PASS; scratch replacement of charon, plugin,
and libcrypto is rejected; CP7A lifecycle regression, ShellCheck, AppleScript
compile, Gitleaks, and cumulative diff checks PASS. Manifest-bound run/stop dry
runs exit before `osascript`.

Review result: exactly one integrated preflight review initially returned NO-GO
with two P1 findings (user-replaceable root execution closure and spawn/state
gap) plus five P2 findings (deadline coverage, no-send observation, exact plugin
set, process identity, and retained evidence binding). All direct findings were
fixed and their scoped validations pass. No second independent review ran; no
live/post-run evidence review has occurred.

Safety/cleanup: No root authorization completed, daemon started, PF_KEY/PF_ROUTE
constructor ran, UDP socket opened, server traffic occurred, credential was read,
or SA/SPD/route/utun/PowerVPN/Surge state changed. Final dry validation exposed a
generic shell `mode` collision that reached an AppleScript authorization wait;
it was terminated before approval with no root entry or residue. The wrappers
now use readonly `operation_mode`, and both dry runs exit before authorization.

Last good state: finalized UID-502 closure and manifest hash above; runtime top
level contains only the reviewed closure, with no state, PID, VICI socket,
ledger, generation, bootstrap, native charon, or gated-launcher process.

First bad event: static inspection found the unavoidable `socket-default`
global-ESP-port write. The first implementation review then found the two P1
ownership/lifecycle gaps; no unsafe live backend attempt was made.

Remaining: obtain the separate manifest-bound live authorization, run one
serverless PF_KEY/PF_ROUTE window, assert cleanup, then perform the single scoped
post-run evidence review. Server, credential, IKE, resource, and recovery work
remain separately gated and unproven.

Next command after explicit approval:
`scripts/run_cp7b_backend.sh --execute-reviewed --manifest-sha256 c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`.

Approval required: **yes**, separately, before any CP7B root/live execution.
