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
subsequently authorized; the later manifest-bound root window is recorded in
the following entry.

## 2026-08-09 — Checkpoint 7B first root window and route-gate remediation

State: **WAITING FOR FRESH MANIFEST-BOUND APPROVAL.** The offline CP7B preflight
remains PASS. The first root window is `INCONCLUSIVE_PREFLIGHT_FAILURE`, not a
backend failure or backend PASS.

Evidence level: L1/L3/L4 source, build, review, and offline-preflight evidence
remain PASS. A privileged root worker ran only through its preflight snapshots;
it did not launch `charon` or the gated launcher. VICI, PF_KEY/PF_ROUTE backend
constructors, and L5 are unproven.

Historical authorization: the user explicitly authorized one root window bound
to manifest
`c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`.
Immediate commit/source/closure/arm64/piddir/dry-run checks passed and the native
macOS authorization dialog completed. The two root preflight snapshots were not
stable, so the worker failed closed before daemon launch. The old authorization
is consumed; neither an automatic retry nor unused attempt allowance transfers
to changed bytes.

Current approval manifest SHA-256:
`7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`.
Fresh approval must bind that exact hash and command.

Verified design: `socket-default` remains excluded because its macOS PF_KEY
NAT-T path writes global `net.inet.ipsec.esp_port` without teardown restore. The
candidate uses `socket-dynamic` with a zero-UDP/no-send contract, a root-owned
sealed closure, and same-PID gated launcher. The route snapshot now separates a
strict structural parser from the CP7B persistent profile. Canonical rows contain
only `family/destination/gateway/flags/netif`; the profile excludes rows with a
nonempty `Expire` value or uppercase `W` (`RTF_WASCLONED`) while retaining
`D`/`C`/`c`. Parse, project, sort, count, hash, command execution, and
default-route parsing fail closed independently. A structurally valid table with
zero persistent rows fails at the profile/fingerprint gate.

Failure-result/lifecycle remediation: daemon-before failures retain a bounded,
value-free result tied to manifest, source, and config. The 300-second prompt
deadline terminates and reaps its child guard promptly instead of waiting for
the full sleep. Legacy full-table route count/hash is diagnostic only;
persistent IPv4/IPv6 projections are the hard route gate.

Evidence: [`../evidence/checkpoint-7b-preflight.md`](../evidence/checkpoint-7b-preflight.md),
[`../evidence/live-test-plan.md`](../evidence/live-test-plan.md),
[`../evidence/rollback.md`](../evidence/rollback.md), the historical manifest,
and the current value-free approval manifest.

Canonical commit: this cumulative CP7B first-window remediation checkpoint
commit.

StrongSwan commit/patch SHA-256: locked CP6 parent
`67c9810900e2d8486cb3b11495a8362433494ca0`; CP7B build-only commit
`a81298234753f314dbf2c4f2867a9a144006bd8c`; patch 0003 SHA-256
`3c7615e5bf2ec284f04177e903b88fb3b452f1ce9d1f39968fd89c40ea6771c4`.
The StrongSwan source/closure remains unchanged by the route-gate remediation.

Changed scope: route parsing/fingerprinting and checked snapshot plumbing;
preflight stability/profile gates; bounded early-failure result; prompt
deadline-child cleanup; route/live-evidence negative tests; manifest hash chain;
and CP7B evidence, live-plan, rollback, README, Goal, and status documentation.

Tests/commands: the historical and remediated
`scripts/verify_checkpoint.sh 7b-preflight` runs are PASS. The remediated
candidate adds targeted route-stage/default-route/profile, first-live
classification, early-result, and deadline-child tests. Closure, arm64 scratch
runtime, AppleScript compile, ShellCheck, Gitleaks, and cumulative diff gates
also pass without a second root, Surge, or server action.

Review result: exactly one integrated preflight review initially returned NO-GO
with two P1 ownership/lifecycle findings and five P2 direct findings; those were
fixed before the historical manifest was sealed. After the inconclusive root
window, exactly one additional narrow review covered only route layout,
parser/profile separation, canonicalization, stage/default-route failure
propagation, deadline cleanup, and the first review's direct boundary. It found
two P1 fail-open paths and one P2 parser/profile conflation; the current
remediation addresses those findings. No third review and no unrelated
repository-history review ran.

Safety/cleanup: no `charon`, gated launcher, VICI response, PF_KEY/PF_ROUTE
constructor, UDP descriptor, server traffic, credential read, SA/SPD install,
route install, utun, or PowerVPN/Surge mutation was observed. The reviewed stop
returned `alreadyStopped=true`. Current direct inspection found no native
process, state, PID, VICI socket, ledger, emergency-stop copy, bootstrap, or
generation residue. The runtime parent is UID 502, mode 700, and its top level
contains exactly the reviewed `closure`.

Cleanup limitation: the outer `after` snapshot was post-hoc at 496 seconds,
outside the 300-second window. Only the legacy full IPv4 route count/hash
changed; IPv6, default route, interfaces/utun, DNS, ESP-port hash,
PowerVPN/Surge identities, and read-only Surge environment hash matched.
SAD/SPD were unavailable to the unprivileged outer snapshot. Process and owned
filesystem cleanup is proven, but the post-hoc comparison is not bounded
kernel-teardown proof. An accidentally malformed zsh-sourced diagnostic was
discarded; only the corrected `/bin/sh` snapshot is referenced.

Last good state: current clean UID-502 runtime baseline above, with no active
CP7B process or generation-owned residue.

First bad event: the root worker rejected unstable preflight snapshots. Three
value-free one-second samples then showed that complete-table churn came from
nonempty `Expire` and `RTF_WASCLONED` rows while the new persistent projection
was stable.

Remaining: obtain fresh manifest-bound approval before one new serverless
PF_KEY/PF_ROUTE window. Server, credential, IKE, resource, and recovery work
remain separately gated and unproven.

Next command only after fresh explicit approval:
`scripts/run_cp7b_backend.sh --execute-reviewed --manifest-sha256 7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`.

Approval required: **yes, fresh and manifest-bound**. The historical
authorization cannot be retried or inherited.

## 2026-08-09 — Checkpoint 7B privileged backend live acceptance

State: **PASS (serverless L5 backend only).** This is not IKE or server-protocol
PASS.

Evidence level: L5 privileged local runtime. The explicitly authorized command
was bound to manifest
`7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`
and StrongSwan source `a81298234753f314dbf2c4f2867a9a144006bd8c`.
Manifest attempt 1 completed in 21 seconds with backend `pfkey-pfroute`, socket
provider `socket-dynamic`, `failureCategory=none`, and `success=true`.

Verified: PF_KEY/PF_ROUTE reached ready; the official 6.0.7 VICI client
completed `version`, read-only `stats`, and empty connection/SA/policy listing
checks under the reviewed runner contract. Native UDP descriptor count stayed
zero. No server endpoint, packet, credential read, `load-*`, `initiate`, or
install operation occurred. Global SAD/SPD, ESP port, persistent IPv4/IPv6
route projections, default route, DNS, interface/utun inventory, PowerVPN, and
Surge remained stable.

Safety/cleanup: `scripts/assert_cp7b_teardown.sh` PASS. No native process, VICI
socket, PID, config/log, state, bootstrap, emergency-stop copy, attempt ledger,
or generation directory remains. Runtime ownership is UID 502:GID 20, mode
700, and its top level contains exactly the reviewed `closure`.

Review result: the existing integrated preflight review and the one permitted
post-first-window narrow review are the complete CP7B review history. No third
review and no unrelated repository-history review ran.

Not proven: IKEv1 Main Mode, Quick Mode/ADDRULE, server acceptance, credential
handoff, SA/policy/route installation, resource data path, and recovery.

Evidence: [`../evidence/checkpoint-7b-preflight.md`](../evidence/checkpoint-7b-preflight.md),
[`../evidence/live-test-plan.md`](../evidence/live-test-plan.md),
[`../evidence/rollback.md`](../evidence/rollback.md), and the retained
manifest-bound value-free result.

Canonical implementation/evidence base: `d1173bb6579a5d2b35fb0b9242282367e39b4bfe`;
this cumulative PASS record belongs to the canonical CP7B acceptance commit.

Remaining: CP8A secure runtime material handoff, with **NO SERVER TRAFFIC**.
Real material requires an exact user-authorized secure provider/path; secret
values must never enter argv, environment, files, fixtures, or logs.

Next command: begin CP8A provider-boundary implementation and synthetic failure/
zeroization tests without reading real runtime material or contacting a server.

Approval required: **yes before any real runtime-material read**; the completed
CP7B authorization does not transfer to CP8A material access or CP8B traffic.

## 2026-08-09 — Rescue R0 preserve and switch

State: **PASS. Native V3 is paused and Rescue is the only active execution
contract.**

Verified: the complete noncanonical CP8A candidate is preserved on
`native-v3-cp8a-wip` at
`75dee758ce0be6dbfa15ea0a2a0211123102ed79`; `main` remains the clean CP7B
fallback at `8d2e026c1f5db15f5b1e1e0ca81c72d2ae5f2073`; and
`rescue-state-machine` was created directly from that same clean baseline.
The user-provided compact Rescue contract replaced the repository-root
`GOAL.md`, which now advances only to R1.

User input required: none.

Derived automatically: branch identities and the active checkpoint only. No
gateway, identity, credential, session, route, resource or protocol material
was requested or derived.

Evidence: exact Git refs for all three branches; a byte-for-byte comparison of
the installed Rescue Goal before its checkpoint-state transition; and a clean,
recoverable CP8A WIP commit.

Tests/commands: `git diff --cached --check`; exact branch/ref assertions; Rescue
Goal `cmp`; R0 integrated review; clean-worktree assertion after the R0 commit.

Safety/cleanup: no GUI/helper action, login, credential read, server packet,
XPC request, SA, policy, route, utun, vendor modification, signing change or
Surge action occurred.

Remaining: R1 read-only direct XPC `get_version`, including interruption,
invalidation, timeout and helper-generation evidence.

Next command: implement and verify the arm64 read-only charon helper probe; do
not authenticate or send `start_connection`.

Approval required: no additional approval for the user-requested read-only R1
probe while the GUI is already absent. Stopping an active GUI/tunnel would
require a separate explicit approval.

## 2026-08-09 — Rescue R1 direct vendor XPC acceptance

State: **PASS.** Rescue may advance only to the R2 username/password portal
login approval gate; R2 has not started.

Verified: the arm64 CLI sent only the locked two-field `get_version` request and
received the genuine installed helper business event for build `24572` with
`get_version=true`. The reply was synchronously bound to the exact cold-start
helper generation; launchd runs increased by exactly one. The helper was
observed with zero TCP/UDP descriptors and became absent within the deadline
without a harness kill.

User input required: none. Username and password were not read in R1.

Derived automatically: installed app/helper/LaunchDaemon identities, the
reviewed source/runner/library/arm64 CLI manifest binding, and the single live
helper generation. No gateway, identity, PSK, session, VIP, route, resource, or
protocol material was requested from the user.

Evidence: reviewed-candidate manifest SHA-256
`472526cb210aff500e8b744b85d82364f0192498a3e1beb2e55ef6400e5fd044`;
byte-exact canonical result
`fixtures/redacted/r1-xpc-runtime-v1.json`; and three retained value-free runs.
Attempt 1 proved the genuine reply but lacked lifetime binding, attempt 2
exposed late-event/classifier defects, and the explicitly predecessor-gated
attempt 3 is the accepted result.

Tests/commands: 33 focused VendorXPC/helper-generation tests; full Swift tests;
arm64 build; strict Swift formatting; shell syntax and ShellCheck; active-monitor,
closed-schema, predecessor-tamper, and CLI-negative harness tests; secret scan;
and one final `scripts/verify_checkpoint.sh r1` acceptance run.

Review result: the only integrated R1 review initially returned BLOCKED with
seven direct findings. All were fixed in the cumulative candidate. No second
R1 review and no unrelated-history review ran.

Safety/cleanup: no login, server request, `start_connection`, credential read,
SA, policy, route, or utun action occurred. Persistent route projections,
default route, DNS, interfaces/utun, Surge, PowerVPN, and ESP-port metadata were
stable. Vendor-log contents were not read. Direct global SAD/SPD comparison was
unavailable to the unprivileged harness and is not claimed. Cancel request and
cleanup evidence remain distinct: external bounded observation proves natural
helper absence and no harness kill.

Remaining: R2 legal portal authentication using only username and password from
secure TTY. Every gateway/session/PSK/resource value remains the client's
derivation responsibility.

Next command: none until a fresh explicit R2 live-login authorization is
received. Do not authenticate in the current checkpoint.

Approval required: **yes** before sending the real username/password login
request. R1's read-only authorization does not transfer to R2.

Canonical commit: this cumulative Rescue R1 implementation and evidence commit.

## 2026-08-09 — Rescue R2 review closure and raw-header-framing blocker

State: **HARD NO-GO — RAW SET-COOKIE FRAMING UNPROVEN.** R2 is not PASS and
the active Goal remains open. A synthetic production-path test rejected locally
before `session.open`; no real credential, portal request or network connection
was used.

Verified: the new dependency-free `PowerVPNPortal` target implements the exact
default password body, sealed installed origin, system-trust-only TLS,
pre-follow redirect rejection, bounded structural XML, a separate strict
LeadSec profile, fresh isolated Cookie handling, resource fetch, exact
60-second first session delay, literal `key=hostid` check and one bounded
logout. `powervpn login` rejects every option/extra argument before constructing
the runtime and emits only a closed value-free JSON report.

User input required: none. The next raw-header-framing subcheckpoint is
value-free and requires no password rotation or credential input. The exposed
password remains forbidden; rotation is deferred until a future real-login
gate is otherwise ready.

Derived automatically: current origin/version/address-selection/language state,
raw platform serial, Cookie/session state, operation timing and logout. The
endpoint was confirmed by a narrow latest-address query on a mode-600 encrypted
database copy using the exact SQLCipher 3.4.0 profile. No user-table row was
queried and no database passphrase was retained.

Evidence: `docs/evidence/checkpoint-r2-validation.md`; the corrected CP5
password-field fixture; and reviewed-candidate manifest
`676e8062b3b29c83dc56e738c475452f029bc3e77f74261eea15878a618774eb`.
The live value-free fixture does not exist because dispatch stopped before
`session.open`.

Tests/commands: after the five direct review findings were fixed, the complete
offline verifier passed with 108 Portal tests in 17 suites and 109 Core tests in
10 suites (217 total), the corrected CP5 password-profile test, arm64 build,
strict Swift formatting, shell syntax and ShellCheck, closed-schema bounded
signal-cleanup harness tests, secret scan, exact manifest and diff check.
This does not claim an R2 live/server acceptance run.

Safety/cleanup: the synthetic production path failed closed before
`session.open`; no real credential, portal connection, PowerVPN GUI, helper,
XPC, VICI, native charon, IKE/UDP, SA, policy, route or utun action occurred.
One password pasted into Codex task text is compromised, was not used, and is
forbidden from every future live run.

Review result: complete. Exactly one integrated R2 review inspected the frozen
cumulative checkpoint and returned five direct findings. All five were fixed:
signal-to-task cancellation, cancellation-safe logout transport, fail-closed
Set-Cookie framing, manifest binding for the network snapshot dependency, and
truthful secure-buffer erasure claims. No second or unrelated-history review
ran.

Remaining: complete an independent, value-free R2 raw-header-framing
subcheckpoint. Foundation's projected Set-Cookie value is not raw multiplicity
evidence, so no password login may run yet. Password rotation and a fresh macOS
confirmation are deferred until this blocker is independently closed and a
future live gate is otherwise ready.

Next command: execute only the independent R2 raw-header-framing subcheckpoint
without username/password. Do not run `powervpn login`.

Approval required: no credential/live-login approval now. Any future real
password request still requires fresh approval and prior rotation; the old
password and all chat/task text are invalid credential sources.

Canonical commit: pending successful live evidence and final checkpoint
validation.
