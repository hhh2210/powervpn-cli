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

## 2026-08-10 — Rescue R2 authorized live failure and TLS evidence gate

State: **OFFLINE PASS; R2B FAIL / INCOMPLETE — `tls_rejected`; GOAL ACTIVE.**
The reviewed system-libcurl seam and cumulative candidate pass offline
validation. One authorized, exact-manifest-bound live window then completed
with `checkpointPass=false`, CLI exit 2 and no successful TLS or login
acceptance.

Verified: the `PowerVPNPortal` target implements the exact
default password body, sealed installed origin, system-trust-only TLS,
pre-follow redirect rejection, bounded structural XML, a separate strict
LeadSec profile, fresh isolated Cookie handling, resource fetch, exact
60-second first session delay, literal `key=hostid` check and one bounded
logout. `powervpn login` rejects every option/extra argument before constructing
the runtime and emits only a closed value-free JSON report.

User input required next: none. The next gate is credential-free and bounded to
TLS trust evidence. The completed live window used personal no-echo TTY entry
with `exposedCredentialRiskAccepted=true`; chat/task text was not a credential
source, and no rotation is claimed.

Derived automatically: current origin/version/address-selection/language state,
raw platform serial, Cookie/session state, operation timing and logout. The
endpoint was confirmed by a narrow latest-address query on a mode-600 encrypted
database copy using the exact SQLCipher 3.4.0 profile. No user-table row was
queried and no database passphrase was retained.

Evidence: `docs/evidence/checkpoint-r2-validation.md`; the corrected CP5
password-field fixture; the exact live-authorized manifest archive
`fixtures/redacted/r2-portal-login-authorized-manifest-v1.json`, SHA-256
`bde4de003e1c5bd2128f5e4b147f05ae3149f2b639126e783585bfb6a1b6302b`;
and runtime source aggregate SHA-256
`83c590c8ebb3c15b8e32d125bfbdef6c4b39aabd94ca9235c35aef140b67eee2`.
The manifest also binds runtime-library SHA-256
`b57c969c986f46c58913c5e5d27bace5131771ff9e343c111e86389d97a12047`
and raw-header-test aggregate SHA-256
`a6d98b928a9c0a63ded37b7b60120e9483fabddf8dea6a895a160276a4acab05`.
The completed value-free live fixture is
`fixtures/redacted/r2-portal-login-runtime-v1.json`, SHA-256
`78a0815ab247c36e8d30683b7f83a09d34d4da2dbe94e395e6f116c8423ca714`.
It is exact, complete and bound to the archived authorized manifest, and it
contains no secret or raw portal material. Post-evidence verifier binding
changed the current development manifest to SHA-256
`8e19d1937d7ab432e9a747725d636e565432159561a0962a6d0ec07afe9fdb1e`;
those bytes were not live-authorized and do not authorize a retry.

Tests/commands: the full offline verifier passed with 120 Portal tests in 19
suites and 109 Core tests in 10 suites (229 tests in 29 suites), the corrected
CP5 password-profile test, arm64 build, strict Swift formatting, shell syntax
and ShellCheck, closed-schema bounded signal-cleanup harness tests, secret scan,
exact manifest and diff checks. Raw sub-gates passed 11 C parser cases, 5 C
status cases, 16 Swift cases in 3 suites and the separate Foundation fail-closed
regression. The synthetic missing-risk case exits 5 before live evidence or
system change and leaves scratch/network/process state unchanged with zero
residue. The authorized live result is `checkpointPass=false`, CLI exit 2 and
`tls_rejected`; this does not claim an R2 server/TLS acceptance run.

Safety/cleanup: the user personally entered the credential through the no-echo
controlling TTY; argv, environment, stdin, files and chat/task text were not
credential sources. App-owned material was erased and no secret/raw portal
material was retained. Only login was requested; resource list, session check
and logout were not. No helper, native charon or UDP descriptor appeared,
launchd stayed inactive at 19→19, and artifact identity/cleanup were exact.

R2 offline-base review result: complete. Exactly one integrated review
inspected the frozen cumulative base and returned five direct findings. All
five were fixed:
signal-to-task cancellation, cancellation-safe logout transport, fail-closed
Set-Cookie framing, manifest binding for the network snapshot dependency, and
truthful secure-buffer erasure claims. No second offline-base review or
unrelated-history review ran.

Offline implementation remaining: none. R2B remains failed/incomplete because
TLS was rejected before login acceptance. Strict `networkStable=false` came
only from a changed raw IPv4 route SHA: total route count stayed 136, while
persistent route count 65/hash, default route, DNS, interfaces, utun, ESP and
Surge stayed stable. This does not override the strict gate or establish server
compatibility.

Raw-header subcheckpoint status: **OFFLINE PASS — INTEGRATED REVIEW COMPLETE;
FINDINGS APPLIED.** Its synthetic-only acceptance matrix and architecture
boundary are frozen in
`docs/evidence/checkpoint-r2-raw-header-framing.md`. The independent verifier
passed 11 C parser cases, 5 C status/finalization cases, 16 Swift
raw/composite/factory cases, the Foundation local fail-closed regression,
strict compile/format checks, arm64 system-libcurl linkage, secret scan and
diff checks.

Raw-header review result: exactly one integrated review returned two direct
findings, both fixed. First, the compatibility predicate now requires a
factory-only unforgeable operation proof; directly forged body, Cookie and
User-Agent near misses produce zero raw-driver or Foundation-lane hits. Second,
TLS trust classification is restricted to peer/issuer verification, while
handshake and cipher failures are `unavailable`. No second review ran. Within
that synthetic subcheckpoint, no successful TLS transfer, portal/server
interaction, credential read or server-compatibility claim occurred.

Next action: run only a credential-free, bounded TLS trust evidence gate. Do
not blindly retry `powervpn login`, weaken system trust, add an insecure/custom
CA path or request another credential entry.

Approval required: no new credential/live approval for the credential-free
evidence gate. Any later live retry remains separately gated and is not
authorized by the failed R2B window.

Canonical commit: pending the TLS evidence gate and any later successful R2B
and final checkpoint validation.

## 2026-08-10 — Rescue R2 credential-free TLS evidence attempt 1

State: **INCONCLUSIVE / FAIL — `timed_out`; GOAL ACTIVE.** The TLS-only
live-window artifact completed, but the checkpoint did not pass and no peer
certificate or trust disposition was obtained.

Verified: the exact authorized-manifest archive is
`fixtures/redacted/r2-tls-evidence-authorized-manifest-v1.json`, SHA-256
`e8b622cb4600ae5e603364accd13dffcd45d1a4aa6a48afe69401fee314cd5d4`.
The exact retained value-free result is
`fixtures/redacted/r2-tls-peer-runtime-v1.json`, SHA-256
`27a0b7a511addff9888041c94c94b1a3ba9f408ff0a15b3941dcb7d4f6e3d61b`;
it records `cliReportExact=true`, and the corresponding standalone live report
has SHA-256
`108b10b5282842b30a29bb4f7a9821520abfaaa12227f629f96992140f91cfe4`.

Result: `checkpointPass=false`, CLI exit 2, `status=timed_out`, zero
certificate-chain entries, null leaf hashes and both trust categories
`unavailable`. The process monitor did not complete descriptor inspection and
recorded no sealed-endpoint TCP descriptor. The strict network projection
failed on transient IPv4 route-hash drift. These observations do not prove
peer incompatibility, server acceptance or TLS acceptance.

Safety/cleanup: no credential, HTTP request or application data was requested.
No raw certificate or certificate identity was retained. The monitor recorded
no helper, native charon or UDP descriptor. Launchd remained inactive at runs
19→19; artifact identity and cleanup were exact; no harness kill was sent.

Remaining: diagnose the timeout and monitor inspection/process-identity
ambiguity offline. Attempt 1's manifest-bound authorization is consumed and
cannot be reused. Do not blindly retry the TLS window or the password login,
and do not weaken system trust or introduce an insecure/custom-CA path.

Next action: after the offline diagnosis and fix, seal all corrected inputs in
a new reviewed manifest. Any attempt 2 requires fresh explicit authorization
bound to that exact new manifest; it remains credential-free and must not send
HTTP or application data.

Canonical commit: pending corrected TLS evidence and later R2 completion.

## 2026-08-10 — Rescue R2 TLS evidence attempt-2 offline candidate

State at candidate seal: **OFFLINE PASS; REVIEW FINDING APPLIED; ATTEMPT 2 NOT
YET AUTHORIZED; GOAL ACTIVE.** The attempt-1 result remains `INCONCLUSIVE /
FAIL` and is not reclassified. The later attempt-2 result is recorded in the
next status entry and does not retroactively turn this offline PASS into live
acceptance.

Verified: localhost-only SNI and exact trust-builder differentials ruled out
the two initial implementation hypotheses without contacting the portal. The
new report schema is v2 and retains only value-free transport progress. The
process monitor now requires the exact exec image and records separate identity,
attempt, success and failure evidence. The predecessor gate accepts only the
unique archived attempt-1 manifest `e8b622cb…5d4` and exact result
`27a0b7a5…61b`; all missing, altered, additional or stale-selector variants
fail closed.

Review: one post-attempt-1 main-agent narrow review found one P2: cold preflight
did not bind the predecessor even though live execution did. Preflight now
requires and emits `predecessorReady=true`. An independent Claude invocation
failed authentication before review and is not counted as PASS. No second
completed narrow review or review-of-review ran.

Evidence: current reviewed candidate manifest SHA-256
`b63fc19d41a50e99e473156c7c486b44d0d970147da743cf45b25474af00b354`;
review state `post_attempt1_narrow_review_completed_findings_applied`. The
offline verifier passes 14 TLS-evidence + 120 Portal + 109 Core tests (243
total), arm64 build, strict format, ShellCheck, exact monitor and predecessor
synthetic tests, historical failure fixture validation, Gitleaks and diff
checks. TLS observation is bounded to 15 seconds; harness wait is bounded to
20 seconds. No portal, credential, HTTP, application data, helper or live TLS
action occurred in this offline correction.

Remaining at this pre-live snapshot: attempt 2 had not run and the reviewed
manifest had not been live authorized. Its later exact authorization and
inconclusive result are recorded below. Attempt 1's authorization remained
consumed and could not be reused. R3-R7 remained pending.

Canonical commit: pending the final offline verifier and checkpoint-local
squash; R2 remains incomplete until a later accepted TLS/login path.

## 2026-08-10 — Rescue R2 credential-free TLS evidence attempt 2

State: **INCONCLUSIVE / FAIL — `timed_out`; GOAL ACTIVE.** The exact TLS-only
live window completed, but `checkpointPass=false` and no peer certificate or
trust disposition was obtained. R2B remains failed/incomplete; R3–R7 remain
pending.

Evidence: the byte-exact authorized manifest archive is
`fixtures/redacted/r2-tls-evidence-attempt2-authorized-manifest-v1.json`,
SHA-256
`b63fc19d41a50e99e473156c7c486b44d0d970147da743cf45b25474af00b354`.
The byte-exact retained result is
`fixtures/redacted/r2-tls-peer-runtime-attempt2-v1.json`, SHA-256
`8766a176e542173bf7b53b79ca005cde0c222a5d2c699871e6aeafd329761219`;
it records `cliReportExact=true`, and the corresponding standalone live report
has SHA-256
`603dce97c50c6c014dc2d83f1be2ded00dee75dfbcfc0ecdb9bd4b4e63ced647`.

Result: CLI exit 2 and `status=timed_out`. The value-free progress record has
`connectionStarted`, `preparingObserved`, `waitingObserved` and
`verifyCallbackObserved` true; `readyObserved` and `failedObserved` are false.
The report contains no certificate-chain entry or leaf hash, and both trust
categories are `unavailable`. This does not locate a particular blocking line
inside the trust builder and does not prove peer compatibility,
incompatibility, TLS acceptance or server acceptance.

Monitor: the separate value-free live monitor has SHA-256
`0f310886e8bbd99ad28a9ed36de8eec619d9616fbcbc26db8354fb17b6f9b5b0`
and retained exact and stable target identity. Sixty of 62 descriptor
inspections succeeded and two failed; aggregate `inspectionSucceeded=false`.
No sealed-endpoint TCP descriptor was observed, so the closed checkpoint result
correctly has `monitorExact=false` and `monitor=null`. No UDP descriptor, vendor
helper or native charon was observed. The strict network projection failed on
transient IPv4 route-hash drift. Launchd remained inactive at runs 19→19.

Safety/cleanup: no credential, HTTP request or application data was requested.
No raw certificate, certificate identity or secret was retained. Artifact
identity and cleanup were exact, the predecessor was validated and no harness
kill was sent.

Remaining: attempt 2's manifest-bound authorization is consumed and cannot be
reused. Do not blindly run attempt 3 or retry the password login; do not weaken
system trust or introduce an insecure/custom-CA path. Any later live attempt
requires a newly bounded offline diagnosis, a new reviewed exact manifest and
fresh explicit authorization.

Canonical commit: pending this attempt-2 failure evidence and later R2
completion; the Goal is not complete.

## 2026-08-10 — Rescue R2 post-attempt-2 narrow hardening

State: **OFFLINE VERIFIER PASS; EXTERNAL REVIEW PENDING; LIVE HARD NO-GO;
GOAL ACTIVE.** No new TLS live window or portal login ran in this hardening
step, and the consumed attempt-2 authorization was not reused.

Verified: localhost-only IP-literal ClientHello tests show automatic and
explicit server-name modes both omit SNI, reach one rejecting verify callback,
never become ready and send no application data. Connection start/cancel is
now a sticky linearizable state machine. One absolute monotonic deadline covers
all harness phases, and blocked FIFO/validator tests prove bounded cleanup with
zero owned residue. Exact PID/PPID/image/command monitoring plus a positive
localhost `lsof -i` fixture closes the earlier false inspection failure; live
acceptance would require exactly one sealed TCP descriptor and zero UDP.

Classification and evidence closure: Basic trust no longer coerces an SSL
failure into hostname mismatch. Swift and shell share the same v2 report
invariants and integral 1...16 observed-chain bound. Runtime source, full test
trees, all transitive shell/runtime/snapshot/verifier inputs and test-only
OpenSSL identity are hash-bound; symlink/FIFO/special descendants fail closed.
The live-result `manifestExact` field is recomputed post-run instead of being a
constant.

Evidence: 18 TLS-evidence + 120 Portal + 109 Core tests pass (247 total), along
with arm64 build, strict format, ShellCheck, localhost-only runtime/deadline
tests, historical fixture gates, manifest mutation negatives, Gitleaks and
diff checks. Exact candidate manifest SHA-256:
`d46773c3f2e5a1f3aaebc2409da3ff807e02ef102c75cf9ea5158481c35713c2`.
Its fixed review state is `post_attempt1_narrow_review_pending`, therefore
`R2TLS_REVIEW_COMPLETE=false` and cold preflight cannot authorize live use.

Remaining: obtain the independent review over these exact bytes. Any finding
must be fixed offline and causes a new manifest SHA. Any later attempt 3 still
requires a separately reviewed manifest and fresh exact user authorization;
do not retry TLS/login or request credentials under the current manifest.

Canonical commit: this checkpoint-local amend records only the offline
hardening candidate; R2 and the project Goal remain active.

## 2026-08-10 — Rescue R2 attempt-3 review-only candidate

State: **OFFLINE IMPLEMENTATION COMPLETE; FINAL SEAL/EXTERNAL REVIEW PENDING;
LIVE HARD NO-GO; GOAL ACTIVE.** No attempt-3 socket, portal login, credential,
HTTP request, application-data send, helper action or UI work ran.

The diagnostic delta now captures the peer chain from TLS metadata inside the
verify callback, invokes `completion(false)` exactly once, then evaluates new
SSL-host and Basic-X509 trust objects on a dedicated bounded asynchronous lane
with all network fetching disabled. The v3 value-free report separates chain
copy, verify invocation/return, both trust evaluations, deadline and duplicate
callback phases. It no longer waits for `.failed` before publishing complete
evidence.

Attempt-3 lineage requires exact attempt1/attempt2 five-file run aggregates
`aef7d3b7734b132f6b5d1bb3fc498d7609d3424c0808a5a029af0e4076d687c9`
and
`21eb127eae03c6c49a56538e285cab0215e00d7122a1c8c0d8184d646bbdcce2`,
plus the byte-exact attempt-2 manifest/result. The selector is fixed to
`attempt3-after-inconclusive-v2`; a future exact authorization is consumed by
an atomic manifest-named marker before any network activity. The current
scratch contains no such marker.

Evidence so far: 37 TLS-evidence tests pass, including metadata order/bounds,
single-lock combined progress snapshots, encode/decode cross-object rejection,
inline and asynchronous trust callbacks, atomic per-policy start reservations,
a shared absolute deadline, late and duplicate callbacks, retained trust
lifetime and localhost-only IP-literal TLS.
Attempt lineage/dimension, historical fixture, manifest DAG and deterministic
ZIP synthetic tests also pass. PID-bound guard acknowledgement, one-shot final
dimension computation and same-filesystem atomic result publication close the
remaining finalization boundary identified in the follow-up analysis.
The replacement pending-review candidate manifest SHA-256 is
`22b73d9f6b1f583335f2b0f24f2331b904c8b6bb0f2cb29ef8c99ebb43d54f9d`.
The complete offline verifier passes 37 TLS-evidence + 120 Portal + 109 Core
tests (266 total), arm64 build, strict format, ShellCheck, Gitleaks, diff check,
historical/lineage/manifest negatives and deterministic bundle construction.

Remaining: perform one independent delta review on the exact replacement
manifest, then require a fresh manifest-bound user authorization. Attempt 3,
login and R3 remain unauthorized.

## 2026-08-10 — Rescue product reset and M1 vertical slice

User-visible capability: `powervpn doctor --json`,
`powervpn helper status --json`, `powervpn resources --json`, and
`powervpn snapshot --dry-run --json` now provide strict product-facing
readiness output. The current machine reports PowerVPN 3.2.1/24572, the
installed x86_64 helper, launchd inactive at run 19, a sealed installed portal
profile, zero selectable production resources, and `common.sessionid` as the
first missing required vendor-snapshot field.

Production code changed: active development moved to `rescue-mvp`; the frozen
evidence branch remains `rescue-state-machine@b1908f2`. Portal now exposes a
generation-bound, memory-only authenticated lease and a scoped resource-tree
borrow. The XMLReader fidelity boundary now admits helper leaves and GUI
display fields only as exact attributes: each resource display name is the
first `TUNNEL@tunnel-name`, and `VERSION@major` is borrowed as
generation-bound Portal metadata. Product binds that display name to a
snapshot-stable opaque handle; helper/session, route and PSK values are never
serialized into Product JSON. Core owns the nested typed charon start contract,
ordered value-free field reports, an opaque non-Codable snapshot proof and a
package-only lineage token. Every value in a complete candidate must share that
same resource lineage. This replaces the former `Set(allCases)` readiness
model: every tunnel and every materialized route must be complete within one
candidate. Product maps candidates independently from single `NC_RESOURCE`
nodes and never unions sibling resources.

The same-resource SP2 mapper now promotes the proven session ID, VIP, IKE port,
major version, IKE/ESP proposals, PSK and lifetimes; tunnel status/name and
direct-or-vendor-default authority/family; route flag/name, map ID and negotiate
mode; direct IPv4/CIDR routes; and the exact empty-route shape. Ascending IPv4
ranges are converted to an ordered minimal CIDR cover. Malformed and reversed
ranges make the whole tunnel routes field missing; rejecting reversed endpoints
is an intentional safe divergence from the vendor loop rather than a claim of
byte-for-byte behavior.

Gateway provenance is now statically closed for the sealed current-machine
profile: the selected `VSGAddressModel` address flows through `VSGService` and
its `vpnAddress`, numeric-IPv4 `getaddrinfo` preserves that address identity,
and the SP2 builder consumes it as `common.gateway`. Runtime admits only the
sealed literal IPv4. A hostname, IPv6 address or different IPv4 literal fails
closed instead of being treated as an equivalent gateway.

Product's package-scoped `withValidatedStartSnapshot` constructs and consumes
the Core snapshot inside the same context/resource borrow. A complete synthetic
candidate can call the exact in-memory encoder inside that body; retaining the
snapshot past the body leaves its borrowed material unavailable and encoding
fails. The encoder permits the proven empty `tunnels[].name` and itself creates
no connection or send.

Core also contains a bounded control seam: synchronous `beginStart` submits
while the borrow is valid, returns a single-consumption pending result, and an
acknowledged start retains that same connection behind a lease for exact
`stop_connection`. Timeout, cancellation, peer-generation mismatch and
unexpected payloads fail closed. An exact empty acknowledgement establishes
only `transportAcknowledged`; `helperSuccessEstablished` is always false and no
connected/tunnel state is inferred. CLI parsing continues to accept only the
four exact M1 argument sequences, and `doctor=ready` still additionally requires
GUI absence, observable helper generation, safe preflight and current
direct-XPC reachability.

Live result: all four M1 observation commands ran locally. No live action,
network request, TTY input, direct XPC probe, helper launch, login, SSH probe,
`start_connection`, route, DNS, interface, utun, or SA mutation ran. `doctor`
and `helper status` returned completed degraded state; `resources` and
`snapshot --dry-run` returned the expected unavailable-provider result.

This third offline slice itself used only synthetic documents and drivers. It
did not rerun a portal request, open a real XPC connection, contact the helper,
read a TTY credential or perform any live/network action.

Current blocker: the default commands have no authenticated snapshot provider,
so their first missing field remains `common.sessionid` and production still
has no selectable resource snapshot. In the offline authenticated synthetic
path, Product derives that field only from `NC_RESOURCE.TUNNEL.IKE.CLIENT.id`
in the same resource generation; the Portal `VSG_SESSIONID` cookie is neither
exposed nor used as helper material. With the sealed gateway provenance above,
that synthetic M1 path now produces a materially complete snapshot and encodes
it only inside the active borrow. This is offline implementation completeness,
not a login, helper acceptance, tunnel connection or production readiness
claim. The Goal remains ACTIVE.

Cleanup status: no helper process was started, launchd remained inactive, and
the commands wrote no runtime artifact or secret-bearing file.

Deferred debt: remaining R2 TLS evidence findings are frozen in
`docs/debt/R2_TLS_EVIDENCE_BACKLOG.md`; they are not M1 product gates.

Next end-to-end action: implement the Product M2 coordinator and CLI around the
scoped snapshot plus bounded start/lease/stop contracts. Keep synthetic drivers
as the default verification lane. Do not send a portal request, create a real
XPC connection or start a helper until a fresh explicit approval is bound to
that first live action.

Approval required: yes, immediately before any official-GUI onboarding,
portal request, direct XPC probe, `start_connection`, SSH proof, or network
mutation. No approval is needed for further offline implementation and tests.

## 2026-08-11 — M2 production composition and approval-gated connect-once CLI

User-visible capability: the arm64 CLI now exposes exactly one M2 transaction:
`powervpn m2 connect-once --resource-display-name <exact> --ssh-target
<thu21|thu52> --json`. It deliberately returns only after Portal acquisition,
start, fresh SSH proof, stop/logout and cleanup verification have all reached a
terminal result. It is not an M3 background connection or a pair of
cross-process connect/disconnect commands.

Production code changed: Core now provides a no-reconnect XPC-session boundary,
bounded async helper-generation validation, bounded fixed-command process and
network observation, value-free cleanup assessment and a selected-route matcher
that proves the locked SSH target is covered without retaining raw routes.
Product composes the current-machine Portal lease, scoped snapshot, synchronous
start submission, retained same-session stop, authenticated emergency-stop
fallback, fresh strict SSH challenge proof and the same capture window across
the A/B/after network snapshots. CLI parsing is an exact seven-token grammar.
A random eight-hex confirmation code is exchanged only through `/dev/tty`
before the production runtime is constructed; `SIGINT` and `SIGTERM` only
cancel the task and the command waits for the cleanup report before exiting.

Live result: no M2 live transaction ran. Offline full `swift test`, arm64
`powervpn` build, strict formatting of changed files, diff checks and the secret
scan pass. The real binary was exercised only for `help` (`0`), rejection of a
`--yes` bypass (`64`) and a no-controlling-TTY attempt (`77`) whose sorted JSON
states `runtimeInvoked=false`. No credential was read and no Portal, SSH,
helper/XPC or network action was started.

Current blocker: there is no remaining demonstrated offline architecture
blocker for the bounded M2 attempt. Product usability is still unproven because
the first authorized resource has not been started, no fresh SSH proof has been
observed through it, and cleanup has not been measured against the real machine.
The Goal remains **ACTIVE**.

Cleanup status: the offline slice started no installed helper or GUI, opened no
real XPC session or SSH connection, changed no route/DNS/interface/utun state,
and wrote no credential or runtime evidence artifact. HEAD and
`origin/rescue-mvp` were equal at `daebe856366ab134458f7e4934dc9af7889420cf`
before this documentation update.

Deferred debt: M3 long-lived `connect/status/disconnect` remains intentionally
out of scope. Existing fail-closed diagnostic compression and the frozen R2 TLS
evidence backlog do not authorize or substitute for the M2 live result.

Next end-to-end action: after a fresh explicit authorization, run one exact M2
command for the user-selected resource and one locked SSH target. The user
enters the Portal credential and the random approval code through the
controlling TTY; the command performs zero retry and must return a cleanup
report even after cancellation or failure.

Approval required: yes. The authorization must name the exact resource display
name and `thu21` or `thu52`, and must be given immediately before that single
Portal/start/SSH/stop/cleanup transaction. This entry does not authorize it.

## 2026-08-11 — M2 provider truth and active-path hard gate

User-visible capability: the exact M2 CLI grammar remains present, but its
default production composition now exits locally with
`authorized_resource_provider_unavailable` before generating an approval code,
opening `/dev/tty`, installing signal handlers, sampling the machine or
constructing any live runtime. It no longer silently falls back to the native
username/password Portal lane whose last authorized result was `tls_rejected`.

Production code changed: Product now has a source-neutral, closed authorization
model. The default source is `vendor_once`; the native Portal adapter requires
explicit injection, and exact acquisition failures such as `tls_rejected` are
preserved in the value-free report. Core cleanup snapshots now fail closed on
PowerVPN GUI, charon, ipsec and shell-helper residue. A retained charon session
must observe a bounded connected status, and stop submission atomically records
the latest status from that same non-reconnecting session. The active network
gate uses one capture window and the selected resource's locked route matcher:
the effective route for the fixed numeric SSH target must uniquely resolve
against the same route-table snapshot to a selected binding introduced after
the cold baseline. A route-table delta alone cannot authorize SSH.

Live result: no M2 live transaction ran. No official-GUI onboarding, Portal or
server request, TTY credential read, helper launch, real XPC session, SSH
connection or network mutation was attempted. One read-only local
`/sbin/route -n get 127.0.0.1` invocation inspected the installed BSD host-route
output shape; it sent no packet and changed no state. All other status, route,
provider and cleanup verification used synthetic drivers and fixtures. The
built CLI's default-provider gate was executed once and returned exit `69` with
`outcome=provider_unavailable`, `runtimeInvoked=false` and
`containsSecrets=false`; it exited before any live dependency. An independent
integrated review found two P1 product gaps—stale connected status across SSH
and route-table membership without effective-target routing—and both now have
deterministic negative tests and fail-closed production gates.

Current blocker: **live NO-GO**. The exact blocker is
`authorized_resource_provider_unavailable`: there is no implemented,
legally sourced production provider that turns the allowed official
`vendor_once` onboarding result into a generation-bound, scoped authorized
resource lease. The earlier statement that no demonstrated offline blocker
remained, and its instruction to proceed directly to an M2 live attempt, are
superseded by this entry. The Goal remains **ACTIVE**.

Cleanup status: this slice created no installed helper or GUI process, opened
no real XPC or SSH connection, changed no route, DNS, interface or utun state,
and wrote no credential or secret-bearing runtime artifact. Synthetic cleanup
can claim success only when default route, DNS, interface/utun inventory,
persistent routes, Surge, helper generation and all tracked vendor processes
return to the baseline and selected-route residue is zero.

Deferred debt: the internal authorization lease still uses Portal-shaped
borrowed material until a real `vendor_once` provider contract is implemented.
Inactive XPC-session exceptional-path diagnostics and the frozen R2 TLS
evidence backlog remain fail-closed debt; none authorizes M2 live use.

Next end-to-end action: implement and offline-verify the legally sourced
`vendor_once` authorized-resource provider. Only after it supplies one scoped,
erasable, generation-bound resource may the team prepare the single bounded M2
transaction and bind a fresh approval to its exact resource display name and
SSH target.

Approval required: no approval is needed for further offline provider code,
synthetic tests or review. Fresh explicit approval is required immediately
before any official-GUI onboarding, Portal/server contact, credential entry,
helper/XPC start, SSH proof or network mutation. No earlier approval transfers.

## 2026-08-11 — Source-neutral authorization lease and installed-artifact audit

User-visible capability: the M2 command remains locally blocked by the exact
`authorized_resource_provider_unavailable` gate. The default path still exits
before approval-code generation, `/dev/tty`, signal installation, machine
observation or runtime construction. This slice does not add a fallback or make
the command live-ready.

Production code changed: Product no longer models M2 authorization as a Portal
snapshot. A source-neutral actor owns one authorization generation, caches one
validated value-free catalog, issues at most one exact display-name selection
and one start, revokes the start capability before asynchronous close, and
erases app-owned material before the first close suspension. Acquisition and
close receipts separately preserve source, server-contact truth, source-close
outcome and owned-material erasure. M2 report schema v5 exposes the erasure
result without serializing a handle, route, snapshot or secret. The native
Portal implementation is now only an explicit adapter.

The selected-route matcher and the actual start snapshot are bound by the same
opaque Core lineage and the same locked numeric SSH target. Duplicate catalog
handles, mismatched prepared summaries or targets, and a matcher from resource
A paired with a start snapshot from resource B all fail before control
submission. Once synchronous `beginStart` has submitted, that pending receipt
is the irreversible linearization point: a source wrapper's second callback or
post-callback error cannot make Product misreport the mutation as unsent, and
the coordinator retains the receipt and runs same-lease cleanup.

Installed-artifact result: **NO-GO for a real `vendor_once` provider**. The
installed app's signed `Contents/Resources/resource.xml` is 10,217 bytes with
SHA-256
`e08bf5fbad1eadd4ecf1c03d16a89d10850019a5d1e35aed1dcf9bd87f6a60d5`.
It contains resource-shaped attributes, but it is sealed build-time template
material dated with the 2024-08-20 app build, not a current-user authenticated
generation. Static inspection found the official GUI's authorized resources
only in process-global arrays after login; logout clears them and no persistence
or export API was found. Preferences contain UI/auth policy, while the user
SQLite model is credential history and was not opened or treated as a resource
source. Helpers expose no resource-export command. No raw attribute, database
row, credential, log or Keychain material was read or recorded.

Verification: targeted lineage, target, cross-resource, duplicate-catalog and
post-submission wrapper tests pass. Full `swift test` passes 539 tests: 37 TLS,
108 Product, 146 Portal and 248 Core. The arm64 `powervpn` product build passes.
No Portal request, TTY read, helper launch, real XPC session, SSH connection or
network mutation ran.

Current blocker: the architecture can now accept a lawful source-neutral
provider, but no installed artifact satisfies authorization generation,
freshness, scoped borrow and erase provenance. The bundle template and
credential database must not be adapted into one. The Goal remains **ACTIVE**.

Next end-to-end action: obtain or implement an official onboarding handoff that
returns one generation-bound, scoped and erasable authorized-resource lease.
Only after that offline contract exists may a fresh approval be bound to one
resource display name and one SSH target for the bounded M2 live transaction.

Approval required: no approval is needed for continued offline provider
contract work, synthetic tests or review. Fresh explicit approval remains
mandatory immediately before official-GUI onboarding, Portal/server contact,
credential input, helper/XPC start, SSH proof or any network mutation.

## 2026-08-11 — Explicit helper reachability and submitted-start cleanup authority

User-visible capability: `powervpn helper status --probe --json` is now the one
explicit Product M1 reachability action. The passive helper status command
still performs no probe. The explicit form is fixed to the installed charon
service and exact `get_version` request, has no caller-controlled payload, and
reports only value-free final generation and reachability state. The new
`scripts/build_and_run.sh` wrapper builds the arm64 product before executing the
exact CLI arguments supplied by the user; with no arguments it only prints
usage.

Installed result: one authorized, credential-free Product probe ran. Before it,
the official GUI and vendor-helper process counts were zero and launchd showed
charon exactly inactive at run 19. The command returned exit 0 in 1.70 seconds
with `current_reachable`; the helper returned to exact inactive at run 20 with
zero vendor-helper processes. Default-route, DNS and interface aggregates
matched the pre-state. No retry, Portal request, credential read,
`start_connection`, SSH connection or network mutation ran.

Production code changed: Core now preserves a cleanup-only capability at the
successful start-submission linearization point when the start later ends in
cancel, timeout, generation mismatch or another non-acknowledged result. The
capability owns only the original non-reconnecting XPC session and can send
only fixed `stop_connection`; it cannot expose status or encode arbitrary
requests. Product consumes it from a non-cancelled cleanup task before falling
back to the existing authenticated emergency classifier. Active starts still
use the normal retained lease. Report schema 6 distinguishes
`same_session_provisional_stop` from `same_lease_stop`, and terminal sessions
truthfully produce an unsent stop receipt rather than a false cleanup claim.

Verification: the provisional-stop Core/Product suites cover cancel, timeout,
generation mismatch, terminal session, rejected submission, duplicate stop and
active-lease separation. The full package test run, strict Swift formatting,
arm64 `powervpn` build, shell wrapper tests, diff check and secret scan pass.

Current blockers: the default M2 runtime remains locally blocked by
`authorized_resource_provider_unavailable`; no installed artifact has become a
lawful current-generation `vendor_once` handoff. In addition, the current CLI
120-second timer is only a cooperative cancellation trigger. There is not yet
one monotonic absolute budget spanning acquisition, mutation, same-session or
emergency stop, authorization close, after-state capture and report. Therefore
no M2 live connection attempt is eligible and the Goal remains **ACTIVE**.

Next end-to-end action: implement `ProductM2AbsoluteBudget` with a 65-second
mutation cutoff and 55-second cleanup reserve, thread absolute remaining time
through every Product/Core stage, and require a cancellable bounded provider
attempt contract. A lawful authorized-resource provider is still required
before the first connection-changing experiment.

Approval required: no approval is needed for that offline budget/provider
contract work or synthetic verification. Fresh explicit approval remains
mandatory immediately before any future Portal/server contact, credential
entry, `start_connection`, SSH proof or network mutation.

## 2026-08-11 — Monotonic M2 supervisor budget and cancellation closure

Status: the offline supervisor-budget blocker is closed. One TTY-approved
monotonic T0 now governs the 65-second mutation cutoff and the 73/94/118/120
second control, authorization, verification and report cutoffs. Report schema
v7 exposes `deadline_exceeded`; cleanup-unproven remains the higher-priority
terminal truth.

Production changes: Core dynamically bounds generation, preflight and network
snapshot commands from one remaining deadline. Product makes authorization a
one-shot cancellable attempt, gates the explicit Portal child across task
creation/installation, rechecks the absolute work deadline inside the scoped
snapshot borrow immediately before start submission, and rechecks every
cleanup cutoff after its await. Cancellation-shielded fallback observation can
still select the authenticated emergency stop after an unsent provisional
stop. Late stop/logout/network evidence remains visible but cannot be promoted
to verified cleanup.

Review and verification: an initial independent review found cancel-before-
result provider execution, a stale relative timeout at the mutation point and
late cleanup evidence being accepted. All three were reproduced and fixed; a
second integration pass also closed the Portal create/install gap, inherited-
cancellation cleanup observation and false time charging for absent stages.
Final independent verdict is `NO_FINDINGS`. Product M2 passes 86 tests in 17
suites; focused budget/CLI tests pass 27 cases; Core budget tests pass 20 cases;
the full package test run, arm64 build, strict formatting, diff checks, build/run
wrapper tests and secret scan pass.

Live status: **NO-GO**. No connection-changing live action was attempted. The
only remaining first-order blocker is
`authorized_resource_provider_unavailable`: the installed product exposes no
lawful, current-generation, scoped and erasable `vendor_once` resource handoff.
The budget guarantee is conditional on future production dependencies honoring
their bounded/cancellable contract; the product deliberately does not use a
hard process kill that could abandon cleanup.

Next product action: obtain an official authorized-resource handoff or a
separately reviewed native onboarding path, implement it behind the existing
source-neutral provider contract, and repeat all offline gates. Only then may a
fresh approval name one exact resource and SSH target for the first bounded M2
transaction.

## 2026-08-11 — First vendor-once M2 live attempt: clean start/session failure

M1 result: the narrow official-app onboarding path is now real. Before opening
the GUI, `powervpn vendor-once begin --json` recorded a value-free cursor for
the installed source. The official app then performed one normal login and its
normal automatic resource start; normal Cmd-Q closed the GUI/helper path. The
adapter accepted only the complete generation after that cursor and projected
exactly one selectable resource, `login21`, with
`onboardingMode=vendor_once`. `resources --json` returned that one resource and
`snapshot --dry-run --json` returned a complete in-memory snapshot with no
missing field, `containsSecrets=false` and `snapshotSerialized=false`.

First live M2 result: one TTY-approved `login21`/`thu21` transaction submitted
exactly one `start_connection`. The start timed out, so no connected status,
active-network proof or fresh SSH proof was attempted or claimed. The retained
same-session cleanup capability then submitted exactly one provisional
`stop_connection`. The command performed no retry, consumed the one-shot
onboarding cursor and finished truthfully in `disconnected`, not connected.

Cleanup result: **PASS**. Cleanup verification was complete across default
route, DNS, interface inventory, utun inventory, persistent routes, zero
selected-route residue, Surge state, vendor processes and helper generation.
No credential, cookie, PSK, route value, complete dictionary or raw log line was
written into the report or this document.

Live diagnosis: one allowlisted `invalid HASH_V1` marker occurred after the M2
start. Its raw line and values are intentionally not retained here. A subsequent
fixed `get_version` reachability request succeeded. Therefore the blocker is
not generic helper/XPC reachability; the complete dry-run also rules out a
missing required snapshot field. The exact current blocker is the vendor
start/session-reuse boundary after normal official-app Cmd-Q. The marker is
corroborating timing evidence, not a claim that its cryptographic cause is fully
isolated.

Production correction found on this path: the default-route canonicalizer now
accepts the valid gatewayless point-to-point shape while continuing to require
destination, interface and flags. This prevents a utun-style default route from
being mislabeled as an unavailable cleanup observation; it does not relax any
resource, session or helper-start gate.

Product status: **M1 PASS, M2 NOT PASS, Goal ACTIVE**. The authorization source
and complete `login21` snapshot now exist, and failure cleanup is proven on the
real machine. A usable connection is still absent because the vendor helper did
not accept/reach connected state with the just-onboarded material after GUI
exit. No automatic relogin or second connection attempt was made.

## 2026-08-11 — Non-logout vendor-once handoff implemented offline

Root-cause refinement: static inspection of the official app's normal
termination path proved that Cmd-Q calls the vendor logout stack and initiates
`/vpn/user/logout`. The first M2 attempt therefore tested material after a
normal vendor logout, not a session-preserving handoff. Value-free timing also
showed the M2 helper had already emitted its allowlisted failure marker 150 ms
after start, while nine observed successful vendor starts reached connected
status within 182–371 ms. Extending the two-second start timer was not selected
as the next experiment.

Production change: `powervpn vendor-once handoff --json` replaces the dead
`vendor-once begin` flow. A foreground Product coordinator keeps one network
capture window, one pre-login cursor and the exact `NSRunningApplication`
receiver returned by its own normal LaunchServices start. It requires a first
TTY code before any coordinator construction or app launch and a second fresh
code after the user confirms `login21` is connected in the official app. The
only permitted termination mutation is `forceTerminate()` on that retained
receiver; PID signalling, Cmd-Q, normal termination and fallback rediscovery
are absent. A synthetic current-machine probe confirmed that this API delivered
SIGTERM without entering AppKit's graceful termination callbacks on macOS build
`26A5406e`; the production gate also pins PowerVPN 3.2.1 build 24572 and its
installed signature identity.

Proof publication is fail closed. A callback that launched an app but could not
seal the exact receiver is reported as `launchedButUnusable` and retains only a
read-only running observation. Cancellation is rechecked immediately before
force. After an accepted force, cleanup continues outside inherited task
cancellation and polls network restoration and final source stability within
one 60-second absolute deadline. The CLI converts SIGHUP, SIGINT and SIGTERM to
Task cancellation and continues awaiting that shielded cleanup instead of
allowing the process to abandon it. Only a terminated exact receiver, absent
GUI and vendor helpers, restored pre-login network state, a complete no-logout
source generation and the final inactive helper generation can atomically
upgrade the armed cursor to a current-machine proof. Legacy proof-less cursors
are rejected, and M2 still consumes a successful proof exactly once.

Verification: the handoff coordinator, exact-receiver bridge, proof/provider
gate and two-approval CLI suites are synthetic and do not construct the default
launcher in tests. They cover identity drift, already-launched-but-unusable
truth, cancellation immediately before and during force, incomplete cleanup,
later-restored network and later-stable source observations. No official app,
helper, XPC session, network request or SSH connection ran during this
implementation.

Current status: **M1 PASS, M2 NOT PASS, Goal ACTIVE**. The next live action is
one explicitly approved `vendor-once handoff`, followed by `resources`,
`snapshot --dry-run`, and exactly one bounded `login21`/`thu21` M2 transaction.
There will be no retry or second login. Success still requires connected status,
selected-route evidence, fresh SSH proof, stop and complete cleanup; otherwise
the result remains the exact value-free blocker from that one experiment.

## 2026-08-11 — First non-logout handoff stopped before force

Live result: both fresh TTY approvals were accepted. The coordinator proved a
stable cold A/B baseline, captured the pre-login cursor and normally launched
the exact installed PowerVPN App. The user completed the official login and
confirmed `login21` connected in the App window. The handoff then returned
`source_not_ready` before the irreversible operation:
`forceTerminationAccepted=false`, `exactReceiverTerminated=false`,
`proofPersisted=false`, `sourceSnapshotComplete=false` and
`officialAppStillRunning=true`. No `forceTerminate`, M2 start, status wait, SSH,
stop or retry occurred.

Value-free diagnosis: the cursor generation contained exactly one fresh fixed
`get_version` request and one fresh `start_connection`; no `stop_connection` or
logout marker followed it, and the appended bytes remained below the 64 KiB
cap. The root-owned log nevertheless continued growing after the second
approval. Schema 1 collapsed the exact internal rejection to
`source_not_ready`, so the strongest supported classification is a pre-force
source-stability failure while the vendor helper was still writing, not a
missing resource field or over-cap append.

Failure cleanup: because force was never accepted, the program intentionally
left the official App under user control and cleared the unproven cursor. The
user then performed normal Cmd-Q. Passive post-state showed the App stopped,
charon exact inactive at runs 10, no vendor process, no DNS recovery file and
no cursor. The passive bounded preflight was safe. Normal quit may contact the
vendor logout endpoint, so this generation is intentionally unusable and no
M2 attempt followed.

Offline correction: handoff report schema 2 adds a closed, value-free
`sourceObservation` (`changed_during_read`, `append_too_large`, malformed,
incomplete, stale logout and related categories). The pre-force gate now polls
the same cursor-bound source for at most five monotonic seconds. Each sample is
a bounded-prefix observation: it accepts only same-inode, security-preserving,
monotonic growth within the cursor's 64 KiB window, and rejects rotation,
shrink, unsafe metadata, an over-cap append, malformed input or a captured
logout. This prefix API returns only completeness, so its observational seal
cannot reach proof/provider. The separate post-force load still requires an
exact current seal before proof publication. Cancellation is rechecked
immediately before force and there is still no login or force retry. Post-force
cleanup retains its separate 60-second absolute deadline. The second TTY gate
now uses nonblocking 50 ms cancellation polling with a ten-minute human-input
window. One-shot proof consumption has moved from acquisition to the validated
start-submission boundary, so a wrong resource name, wrong target, stale source,
deadline or pre-start cancellation does not consume it. M2 cleanup now also
requires structural route-table equality. Synthetic tests cover
append-during-read metadata, rotation/shrink/security rejection, final sealed
polling, TTY cancellation, deferred proof consumption and expiration with the
last source category preserved. Full `swift test`, arm64 product build, strict
Swift formatting, diff validation and secret scan passed. No second live
handoff is authorized by this result.

Current status: **M1 PASS, M2 NOT PASS, Goal ACTIVE**. The next live action, if
separately approved, is one fresh handoff using schema 2. Only `outcome=ready`
and `sourceObservation=ready` may proceed to resources, dry-run and the sole
bounded M2 transaction.

## 2026-08-11 — Vendor-log authorization path retired

The official-app/log handoff is permanently superseded and removed from the
active product surface. Earlier entries remain historical evidence only and do
not authorize another handoff or retry. The current-machine default is now an
inert `native_portal/provider_unavailable` gate; readiness may inspect only the
sealed installed profile and publishes no resource until native Portal trust
and authorization are explicitly implemented.

## 2026-08-12 — Official XMLReader password-response compatibility

Installed PowerVPN 3.2.1 XMLReader projection requires a direct `RESPONSE` root,
one exact direct `RESULT` child, and its exact `code` attribute. The native
password callback now matches that shape while retaining strict hexadecimal
parsing and fail-closed rejection of case-folded or namespace-local-name
collisions and child/attribute shadows. Request bytes, bootstrap/cookie
lifecycle, credentials, and account state remain lower-ranked and unproven.

Offline gates passed: `LeadSecPortalProfileTests` 12/12,
`PortalLoginWorkflowTests` 9/9, the full Swift suite 632 tests across 105 suites,
the arm64 build, strict format lint for the scoped files, `git diff --check`, and
the approximately 2.81 MB no-secrets scan with 0 leaks. The sole integrated
review P1 identified collision/shadow ambiguity; the implementation was made
fail-closed and the affected gates were rerun successfully.

This correction ran no live request, consumed no live authorization, launched
no app, read no credential, and invoked no helper, SSH, or M2 action. The prior
one-attempt authorization remains consumed. The next decision is whether to
separately approve exactly one fresh Portal-only discriminator using the same
command, resource `login21`, and target `thu21`; helper, SSH, M2, and retry
remain prohibited.

## 2026-08-12 — XMLReader-corrected Portal discriminator attempt 1

State: **GOAL ACTIVE; VPN/M2 NO-GO.** The single approved Portal-only attempt is
consumed. No retry is authorized.

Canonical value-free evidence directory:
`/Users/larry_1/scratch-data/powervpn-portal-xmlreader-2026-08-12.aHyIBv/`.
The approved command's product binary
`.build/out/Products/Debug/powervpn` has SHA-256
`0189fbb9dd15c57954fba3b12c513a99d98b6f50a1ee07387945e826b6b7d839`
and size 7,568,384 bytes; its observed modification time
`2026-08-12T05:20:09Z` predates the run.

Exact result: attempt 1 exited `69`; `portalAcquisitionStatus=accepted`;
`loginAccepted=true`, `resourceListRequested=true`, and
`resourceListAccepted=true`; `outcome=resource_catalog_rejected`; candidate,
matching-candidate, and selected-candidate counts are all `0`; snapshot
construction/completeness and target-route coverage are false; logout was
attempted and rejected; `ownedMaterialErased=true`. The report also records
`containsSecrets=false`, `helperMutationRequested=false`, `sshRequested=false`,
and `m2CoordinatorRequested=false`.

The three zero counts are **not evidence of an empty catalog**.
`ProductPortalDryRunRuntime.inspect` catches an error from
`AuthenticatedPortalSnapshotMapper.map` and returns before assigning
`candidateCount`; a genuinely empty mapped resource list would instead reach
`resource_not_found`. The XMLReader correction therefore unlocked password
login and resource-catalog transport/profile acceptance. The current product
blocker is value-free mapper-stage classification and compatibility: the
catch-all cannot distinguish context/list/version shape failures from a
per-`NC_RESOURCE` field failure.

Logout rejection is separate and did not cause catalog mapping to fail.
`AuthenticatedPortalLease.logoutAndErase` erased the local snapshot before the
logout request and subsequently erased the locally owned session material, but
the report cannot prove remote invalidation. Its `rejected` class conflates
request construction, transport failure, and every HTTP status other than
exactly 200. Existing official static evidence supports 200 through 204 as the
shared accepted HTTP family, so logout compatibility warrants an independent
offline investigation; the unseen response must not be inferred.

This is a concrete current diagnosis/safety blocker, not a demonstrated
architectural impossibility under `GOAL.md`. No legacy behavior has been shown
irreproducible, but wrong-resource and ambiguity safety prohibit M2 while the
mapper failure remains unclassified.

Ranked offline work:

1. Add value-free mapper-stage and typed failure diagnostics, with focused
   offline fixtures distinguishing empty catalog, context/list/version failure,
   and per-resource display/integer failure.
2. Do not skip invalid siblings. Only after the classifier proves a safe
   wrong-resource/ambiguity contract may per-resource handling be considered.
3. Independently investigate and later implement logout 200...204 compatibility
   from existing static evidence, with no live retry.

Next end-to-end action: implement and review the value-free mapper/logout
classifier offline. No Portal, helper, SSH, or M2 action is authorized.