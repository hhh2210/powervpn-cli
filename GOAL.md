---
title: PowerVPN Rescue CLI — Headless login and recovery
goal_version: rescue-1-compact
status: active-codex-goal
updated: 2026-08-10
repository: /Users/larry_1/Opensource/powervpn-cli
strategy: arm64 control plane over installed vendor helpers
supersedes_for_active_execution: Native Goal V3
native_v3_role: frozen fallback
native_fallback_baseline_commit: 8d2e026c1f5db15f5b1e1e0ca81c72d2ae5f2073
current_checkpoint: R2-username-password-portal-login
immediate_next: attempt3-independent-delta-review
user_input_contract: username-and-password-only
review_policy: one integrated review per checkpoint
---

# PowerVPN Rescue CLI Goal

## Start

Place this file at repository root as `GOAL.md` and run:

```text
/goal Implement GOAL.md checkpoint by checkpoint. Freeze Native V3 as a
fallback and do not execute both architectures in parallel.

The only live user-provided inputs are username and password through secure
TTY. Never ask the user for gateway, port, identity, PSK, session, VIP, route,
map ID, resource dialect/family, opaque bytes, proposal, ADDRULE body, or
Keychain reference. Discover non-secret installation configuration and derive
all runtime material from the legal portal response. If a required value cannot
be derived, stop with an exact blocker instead of prompting for protocol data.

Execute only the current checkpoint. Use targeted tests while implementing,
one integrated checkpoint review, and one final acceptance run. Pause at every
live approval gate.
```

## 1. Objective

Build an arm64 Swift CLI that runs without the PowerVPN GUI and uses the
installed x86_64 vendor helpers as an unmodified tunnel core.

The user experience must remain equivalent to the old client:

```text
Username: ...
Password: ...   # no echo
```

The CLI must then automatically:

1. discover the configured gateway and non-secret client defaults;
2. perform password login, session check, resource listing and logout;
3. derive session, PSK, identities, VIP, routes and resource metadata from the
   authenticated portal response;
4. map that response to the exact vendor XPC snapshot;
5. start/stop one authorized resource without running the GUI;
6. maintain truthful auth/helper/tunnel/resource/path/probe state;
7. recover after path changes or helper crashes with bounded retries;
8. preserve Surge default route/DNS and clean up completely.

This Goal does not remove Rosetta. Native strongSwan V3 remains the fallback if
vendor helper control is impossible or too unstable.

## 2. Hard input contract

Allowed live input:

- username;
- password from `readpassphrase()` or equivalent secure TTY.

Forbidden live input:

- gateway or IKE port;
- local/remote identity;
- PSK, session, cookie or token;
- VIP, selector, route, prefix or map ID;
- resource family/dialect;
- opaque record or resource-envelope bytes;
- proposal strings;
- credential locator or Keychain persistent reference.

All forbidden inputs must be derived from installed non-secret configuration or
the legal portal response. If the server unexpectedly requires CAPTCHA/MFA or
another challenge, record its schema and pause for Goal revision. Do not guess
or bypass it.

The current CP8A manual-material prompt is therefore not a valid product path.
Its secure-memory primitives may be preserved on a WIP/native fallback branch,
but CP8A is not PASS and must not continue as the active Goal.

## 3. Runtime boundary

```text
arm64 powervpn CLI / foreground watch
├── InstalledConfigDiscovery
├── PortalClient
├── memory-only AuthenticatedPortalSnapshot
├── LeadSecConfigMapper
├── VendorXPCClient
├── RecoveryCoordinator actor
└── TruthEvaluator
             │ raw XPC
             ▼
installed vendor charon-xpc/ipsec-xpc/sh-xpc
             │
             ▼
existing IKEv1/ADDRULE/ESP/utun implementation
```

Do not modify, re-sign, inject or replace vendor components. GUI automation is
not a control interface. The GUI may only be used in a separately approved,
value-free research observation.

## 4. Success and blocked outcomes

### Success A

All must hold:

- PowerVPN GUI is not running;
- arm64 CLI communicates directly with vendor helper;
- user supplies only username/password;
- login, session check and resource catalog work;
- all tunnel material is automatically derived;
- one authorized resource starts and a fresh SSH connection receives a banner;
- status reports separate Auth, Control, Helper, Tunnel, Path, Resource and
  Probe state;
- route, helper PID, GUI state, TCP connect or historical log alone never imply
  health;
- one controlled path change or helper restart recovers to new-SSH capability,
  or clearly enters `needs_authentication`/`blocked`;
- session expiry stops tunnel restart and requests authentication;
- manual disconnect cancels recovery;
- Surge remains functional;
- logout/disconnect leaves no incorrect route, runaway task or secret file;
- password, PSK, session, cookie and raw XPC dictionaries never enter argv,
  environment, ordinary files, Git or CLI output.

“Long-lived” means automatically restoring the ability to open a new SSH
connection. It does not mean preserving the same TCP connection through sleep
or interface changes.

### Blocked B

Stop with evidence if any of these is proven:

- helper requires vendor caller identity/signing;
- direct XPC cannot be reproduced without modifying vendor code;
- configured portal endpoint cannot be legally discovered;
- username/password is insufficient for the deployed authentication flow;
- portal response cannot legally produce the helper material;
- mapping requires replayable secret extraction from vendor logs/process memory;
- Rosetta helper remains too unstable after bounded full-snapshot recovery;
- the discovered portal endpoint is incompatible with macOS system trust and
  no legally derived system-trusted hostname exists; Rescue MUST NOT reproduce
  the vendor client's disabled peer or hostname verification without an
  explicit security-policy revision of this Goal;
- Surge coexistence or cleanup cannot be made safe.

A blocker report must contain last-good-state, first-bad-event, cleanup status,
and whether Native V3 should resume.

## 5. Preserved baseline

Preserve:

- CP0–CP6 protocol/oracle evidence and strongSwan patch;
- CP7A real VICI request/response;
- CP7B serverless PF_KEY/PF_ROUTE smoke and teardown;
- Native V3 documents.

Use clean fallback baseline:

```text
8d2e026c1f5db15f5b1e1e0ca81c72d2ae5f2073
```

Preserve current CP8A candidate as an explicitly noncanonical
`native-v3-cp8a-wip` branch/commit. Create `rescue-state-machine` from the clean
fallback baseline. Do not lose work and do not merge the CP8A candidate into the
Rescue branch.

## 6. Truth and recovery rules

Track at least:

```text
AuthState       signed_out/authenticating/valid/expired/needs_user_action/failed
ControlState    idle/discovering/logging_in/ready/checking/backoff/failed
HelperState     unavailable/launching/responsive/unresponsive/crashed + generation
TunnelState     disconnected/starting/established/degraded/restarting/blocked
PathState       unsatisfied/stabilizing/satisfied + generation
ResourceState   desired + observed per resource
ProbeState      unknown/probing/healthy/unhealthy/timeout
UserIntent      connect/disconnect
```

Rules:

- session expiry, helper failure, path failure and probe failure are distinct;
- helper generation change resets observed tunnel/resource state to unknown;
- old callbacks cannot overwrite a newer generation;
- path change is debounced before diagnosis;
- recovery is single-flight, at most 3 quick attempts, then cooldown;
- session invalid stops tunnel/helper restart;
- helper restart replays a complete snapshot, not an incremental toggle;
- manual disconnect cancels pending recovery.

## 7. Checkpoints

### R0 — Preserve and switch

- audit worktrees;
- preserve CP8A on `native-v3-cp8a-wip`;
- create clean `rescue-state-machine` branch;
- install this file as the only active `GOAL.md`;
- record Native V3 paused / Rescue active;
- perform no live action.

PASS when no work is lost and both branches are clean/recoverable.

### R1 — Read-only direct XPC gate

With the GUI stopped, implement only a read-only vendor-helper probe:

```text
charon get_version
XPC interruption/invalidation/timeout classification
helper generation observation
```

Do not log in, contact the VPN server, send `start_connection`, or create
SA/route/utun.

PASS: a genuine helper reply is received and cleanup is clean.

NO-GO: caller identity/signing rejection is proven. Do not bypass it; resume
Native V3.

For service/framing/readiness ambiguity, perform at most three minimal,
information-gaining experiments.

### R2 — Username/password-only portal login

#### R2A offline

- discover gateway/base URL/version/trust assets from installed non-secret
  configuration;
- lock the password-login request schema;
- determine `type`, `mac`, `verifycode` generation from evidence;
- implement TLS trust narrowly; no generic `--insecure`;
- add synthetic request/response/session/resource tests.

Acceptance path must not require `--gateway`.

The server-facing implementation is a compatibility port, not a redesigned
portal protocol. Preserve the observed field order, lack of percent escaping,
Base64 mode, Cookie spacing, operation order and 60-second first session-check
delay. Keep bounded structural XML parsing separate from the strict LeadSec
acceptance profile. Unknown header folding, challenge shape or response
semantics fail closed; a generate/parse round trip is not server-compatibility
evidence.

#### R2A.1 — independent raw-header-framing gate

The one permitted integrated R2 offline-base review is complete and its five
direct findings have been fixed. That review established the strict Cookie
boundary: Foundation's projected `Set-Cookie` value does not independently
prove the raw response-header multiplicity or framing required by the
compatibility profile and therefore remains fail closed. This independent,
value-free subcheckpoint now supplies a bounded raw-header observation seam for
offline progression; it does not establish server compatibility or authorize a
live request.

This subcheckpoint uses no username or password and does not authorize password
authentication. R2B remains blocked even though the direct findings from both
the offline-base and raw-header reviews are fixed; review closure is not
server-compatibility evidence.

The synthetic offline verifier passes and the raw-header gate's one integrated
review is complete. It returned exactly two direct findings, both applied:

1. entry to the raw password lane now requires a factory-only unforgeable
   operation proof; directly forged body, Cookie and User-Agent near misses
   produce zero raw-driver or Foundation-lane hits;
2. TLS trust classification now contains only peer/issuer verification;
   handshake and cipher failures are classified as `unavailable`.

No second raw-header review ran. Within that synthetic subcheckpoint, no live
request, successful TLS transfer, server interaction or credential use
occurred. The reviewed result is implementation evidence only.

Its acceptance surface is frozen in
`docs/evidence/checkpoint-r2-raw-header-framing.md`: an in-process arm64
macOS-14 system-libcurl seam, exact raw single-field preservation, and bounded
synthetic rejection cases. Subprocess curl, proxy/insecure/custom-CA inputs,
credentials, portal traffic, and any weakening of the existing Foundation
fail-closed path are outside the subcheckpoint.

The exact live-authorized manifest bytes are archived at
`fixtures/redacted/r2-portal-login-authorized-manifest-v1.json`, SHA-256
`bde4de003e1c5bd2128f5e4b147f05ae3149f2b639126e783585bfb6a1b6302b`.
The archived manifest binds runtime source aggregate SHA-256
`83c590c8ebb3c15b8e32d125bfbdef6c4b39aabd94ca9235c35aef140b67eee2`.
It also binds runtime-library SHA-256
`b57c969c986f46c58913c5e5d27bace5131771ff9e343c111e86389d97a12047`
and raw-header-test aggregate SHA-256
`a6d98b928a9c0a63ded37b7b60120e9483fabddf8dea6a895a160276a4acab05`.
The full offline R2 verifier passes. This closes the offline implementation
gate only. The later manifest-bound R2B window reached the login request but
failed with `tls_rejected` before login acceptance; it proves neither successful
TLS nor server compatibility.

After retaining that result, verifier evidence binding changed. The current
post-evidence development manifest is SHA-256
`8e19d1937d7ab432e9a747725d636e565432159561a0962a6d0ec07afe9fdb1e`.
It was not the live-authorized byte sequence and does not authorize a retry.

#### R2B live gate

The authorized window permitted only:

```text
powervpn login
Username: ...
Password: ...
```

A passing window would then perform session check, fetch the resource catalog
and logout. It would not start a helper tunnel.

PASS only if the user enters no other material and no secret is persisted or
printed.

One password was exposed in the Codex task text during R2 implementation. The
user stated that it cannot be rotated and explicitly accepted the risk of
continuing with the same credential. Chat/task text remained an invalid
credential source: the implementation did not read or copy the exposed value.
The authorized R2B window was bound to manifest SHA-256
`bde4de003e1c5bd2128f5e4b147f05ae3149f2b639126e783585bfb6a1b6302b`
and the non-secret exposed-credential risk-acceptance gate. The user personally
re-entered the credential through the no-echo controlling TTY. The evidence
records `exposedCredentialRiskAccepted=true`; it does not claim that the
credential was rotated. No credential appears in chat-derived runtime input,
argv, environment, files, fixtures, logs or retained evidence.

#### Authorized R2B window result

The manifest-bound window completed with `checkpointPass=false`, CLI exit 2
and status `tls_rejected`. Only `loginRequested=true`; login acceptance and all
resource-list, session-check and logout request/acceptance fields are false.
The complete value-free fixture SHA-256 is
`78a0815ab247c36e8d30683b7f83a09d34d4da2dbe94e395e6f116c8423ca714`.
The monitor observed no helper, native charon, portal TCP descriptor or UDP
descriptor; helper launchd stayed inactive at run count 19. Artifact identity
and cleanup are exact. The strict `networkStable` gate is false only because
the raw IPv4 route SHA changed: total route count stayed 136, while persistent
route count 65/hash, default route, DNS, interfaces, utun, ESP and Surge stayed
stable.

R2B is failed and incomplete; the Goal remains active. Next is a bounded,
credential-free TLS trust evidence gate. Do not blindly retry login, weaken
system trust, add an insecure path or re-enter a credential in that gate.

#### Post-attempt-2 TLS evidence candidate

Attempt 1 and attempt 2 were both inconclusive and their exact authorizations
are consumed. Attempt 3 is the final credential-free TLS evidence attempt
permitted by this Goal, and it is not authorized. Its offline candidate MUST
bind the two retained run directories byte-for-byte, accept only the exact
`attempt3-after-inconclusive-v2` selector, and atomically consume any future
manifest-specific authorization before opening a socket. No attempt 4 may be
implemented, authorized or run without an explicit revision of this Goal.

The diagnostic delta is deliberately narrow. Inside the TLS verify callback it
copies the peer-presented certificate chain directly from
`sec_protocol_metadata`, rejects the handshake exactly once with
`completion(false)`, and performs no trust evaluation there. It then constructs
independent SSL-host and Basic-X509 `SecTrust` objects and evaluates them with
network fetching disabled on one bounded asynchronous lane. The result retains
only hashes, closed trust categories and value-free phase booleans. It MUST NOT
retain certificate bytes, identity fields, endpoint/error descriptions,
credentials, HTTP data, application data or helper evidence.

The live-result contract separates `executionSafetyPass`,
`transportEvidenceComplete`, `trustEvidenceComplete`, `compatibilityOutcome`,
`monitorQuality`, `environmentStable` and `checkpointPass`. A complete trust
diagnosis may be `blocked_by_system_trust` without being relabelled compatible.
Before any possible attempt 3, these bytes require an independent review and a
new exact user authorization. R3 and all UI work remain blocked.

An attempt-3 outcome of `compatible_under_system_trust` may support only a
separately reviewed, newly manifest-bound R2B login window. It does not complete
R2B, authorize that login by itself, or unblock R3.

#### Attempt-3 terminal decision

- `compatible_under_system_trust` is necessary but not sufficient for R3. It
  permits preparation of one separately reviewed R2B password-login window;
  only an accepted login and authenticated portal response can complete R2.
- `blocked_by_system_trust` closes Rescue R2 under the current security
  boundary. Do not add an insecure, custom-CA or vendor-equivalent trust bypass;
  resume only after an explicit Goal/security-policy revision or record
  Blocked B.
- If peer-chain capture succeeds but trust evidence remains incomplete or
  times out, stop this Network.framework evidence lane. Attempt 4 remains
  prohibited without an explicit Goal revision and a genuinely
  information-gaining design.
- An execution, monitor or environment failure permits only an offline fix tied
  to a specific diagnostic defect; it never authorizes a blind retry.

### R3 — Portal response to vendor XPC snapshot

- create a memory-only authenticated snapshot;
- derive common/tunnel dictionaries from portal response;
- preserve exact field names, Foundation/XPC types and nesting;
- verify with synthetic fixtures and value-free differential evidence;
- do not send the snapshot yet;
- do not read replayable material from vendor logs/helper memory.

PASS only when one real username/password login yields a complete snapshot
without user-supplied protocol fields.

### R4 — GUI-free one-resource connection

After explicit live approval:

1. GUI absent;
2. CLI username/password login;
3. send full `start_connection` snapshot for one authorized resource;
4. verify helper/route attribution and a fresh SSH banner;
5. stop, logout and verify cleanup/Surge.

R4 PASS is Rescue technical GO.

### R5 — Foreground watch

Implement only after R4:

```bash
powervpn connect <resource> --watch
powervpn status --json
powervpn diagnose --json
powervpn disconnect
powervpn logout
```

Add actor-owned state, generation fencing, bounded retry and manual-disconnect
suppression.

### R6 — Recovery qualification

With separate approval, test once each:

- 30–120 second network outage;
- path/Wi-Fi change;
- controlled helper termination;
- deterministic session expiry.

Require truthful state, fresh SSH recovery, Surge coexistence and full cleanup.

### R7 — Optional daily-use hardening

Only after R6:

- saved username;
- opt-in Keychain password;
- user LaunchAgent;
- concise notifications.

No SwiftUI, installer, notarization or Native V3 work in this Goal.

## 8. Approval and secret rules

Require separate approval before:

- stopping an active GUI/tunnel;
- sending real username/password to portal;
- `start_connection`/`stop_connection`;
- route/utun/resource changes;
- helper termination;
- network/sleep fault injection.

Password uses secure TTY and zeroizable owned memory. Session/cookie/PSK and
complete snapshots remain memory-only. Do not read credentials from vendor
logs or make vendor-memory extraction a runtime dependency. Keychain is R7
opt-in, not an R2 prerequisite.

## 9. Review cadence

Per checkpoint:

```text
implement continuously
→ targeted tests
→ checkpoint candidate
→ one integrated review
→ fix blockers
→ one full acceptance run
→ one canonical commit
```

No per-commit double review, review-of-review, repeated repo-wide audit, or UI/
LaunchAgent work before its checkpoint.

## 10. Progress record

For every checkpoint, update `docs/progress/GOAL_STATUS.md` with:

```markdown
State:
Verified:
User input required:
Derived automatically:
Evidence:
Tests/commands:
Safety/cleanup:
Remaining:
Next command:
Approval required:
```

`User input required` may only be `none` or `username + password via secure
TTY`. Any other live protocol input fails the checkpoint.

## 11. Immediate steering message

```text
Freeze Native CP8A/CP8B. Preserve the current CP8A work as a noncanonical
native-v3-cp8a-wip branch/commit and retain the clean CP7B fallback baseline.
Adopt this Rescue GOAL.md as the only active execution contract.

The user can provide only username and password via secure TTY. Never ask for
gateway, identities, PSK, session, VIP, routes, map IDs, resource dialect/
family, opaque records, ADDRULE bytes, proposals or Keychain references. Those
must be discovered from installed non-secret configuration or derived from the
legal portal response. If they cannot be derived, stop with an exact blocker.

Execute R0, then only R1. With the GUI stopped, send a read-only get_version
request from the arm64 CLI to the installed helper. Do not log in, contact the
VPN server, send start_connection, create SA/route/utun, modify/re-sign/inject
vendor components, or continue Native V3 in parallel.

If R1 receives a genuine reply, stop and report Rescue GO for R2. If R1 proves
caller-identity/signing rejection, clean up and recommend resuming Native V3.
```
