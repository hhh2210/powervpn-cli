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
