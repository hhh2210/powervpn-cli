# PowerVPN Native Rescue

An unofficial, arm64-native macOS client under development for ordinary
GUI-free use of the installed LeadSec PowerVPN tunnel helpers. Authentication
is never bypassed, and the current product still requires the official PowerVPN
installation.

## Current product status — 2026-08-11

The active branch is `rescue-mvp`. M1 exposes four passive, value-free
product-readiness commands:

```sh
powervpn doctor --json
powervpn helper status --json
powervpn resources --json
powervpn snapshot --dry-run --json
```

One separate explicit command performs the bounded local helper probe:

```sh
powervpn helper status --probe --json
```

One narrow onboarding command records a value-free boundary immediately before
the official app is used:

```sh
powervpn vendor-once begin --json
```

On this Mac they currently establish:

- PowerVPN 3.2.1 build 24572 is installed as x86_64;
- the root-owned x86_64 charon helper is installed, launchd-observed and
  inactive at the latest value-free post-run observation;
- the sealed installed portal profile is available;
- the four passive commands do not launch the helper and therefore report
  `directXPCStatus=not_probed`. One explicit arm64 product probe issued only the
  fixed `get_version` request and returned `current_reachable`. A second fixed
  reachability request after the first real M2 attempt also succeeded;
- `onboardingMode=vendor_once` now uses a pre-GUI cursor and only the official
  app's subsequent normal-login generation. The official app auto-started its
  resources; normal Cmd-Q then closed the GUI/helper path without an explicit
  Portal logout;
- the passive resource catalog exposed exactly one selectable resource,
  `login21`. `snapshot --dry-run` constructed its complete snapshot in memory,
  reported no missing field and serialized none of the snapshot material;
- the Portal target now has a generation-bound, memory-only authenticated lease
  with a scoped resource-tree borrow, and Core has a nested typed charon
  `start_connection` contract instead of a forgeable field-name set;
- Product accepts statically proven XMLReader helper leaves only as element
  attributes. Each resource display name is the first `TUNNEL@tunnel-name`,
  while `VERSION@major` is generation-bound Portal metadata;
- the same-resource SP2 mapper now covers session ID (only `CLIENT@id`, never
  the Portal cookie), VIP, IKE port/version, IKE/ESP proposals, PSK/lifetimes,
  tunnel direct/default fields, map ID, negotiate mode, direct IPv4/CIDR routes
  and the exact empty-route shape. Ascending IPv4 ranges become a minimal CIDR
  cover; malformed or reversed ranges fail closed, with reversed-range rejection
  an intentional safety divergence from the vendor loop;
- sealed gateway provenance is now closed from the selected `VSGAddressModel`
  row through `VSGService.vpnAddress`, numeric-IPv4 `getaddrinfo` identity and
  the builder's `common.gateway`. Hostnames, IPv6 and any different literal
  still fail closed;
- Product's `withValidatedStartSnapshot` keeps gateway, resource leaves and the
  Core snapshot inside one borrow. A complete synthetic snapshot encodes inside
  that callback, while an escaped snapshot can no longer borrow its material;
- Core also has a bounded begin/pending control primitive. A start transport
  acknowledgement retains the same connection for lease-bound stop, but an
  exact empty acknowledgement proves transport only and
  `helperSuccessEstablished` remains false. If a submitted start instead ends
  in cancellation, timeout or generation mismatch, Core now transfers an
  opaque cleanup-only capability over that same non-reconnecting XPC session.
  Product attempts its fixed `stop_connection` exactly once before considering
  authenticated emergency cleanup; report schema 7 distinguishes this as
  `same_session_provisional_stop` rather than claiming an active lease.

The four passive M1 commands contact no server, read no TTY credential and send
no XPC. The explicit helper probe also contacts no server and cannot encode
`start_connection`; it performs one bounded local XPC `get_version`
transaction. The bounded M2 transaction is exposed behind one strict,
single-process command:

```sh
powervpn m2 connect-once \
  --resource-display-name "<exact>" \
  --ssh-target <thu21|thu52> \
  --json
```

The default runtime currently stops with
`authorized_resource_provider_unavailable` before generating an approval code,
opening `/dev/tty`, installing signal handlers or running any observer. It does
not silently fall back to the native username/password Portal lane whose last
authorized result was `tls_rejected`. M2 authorization is now source-neutral:
one actor-owned authorization generation provides a value-free validated
catalog, one exact resource selection, one target-bound selected-route matcher
and one start capability. Core lineage binds the matcher to the snapshot that
is reborrowed for start; a submitted start remains an irreversible receipt even
if a source wrapper subsequently invokes its callback again or throws. Close
revokes the capability and erases app-owned material before its first await.
The native Portal path exists only as an explicitly injected adapter.

M2 now derives every stage from one monotonic budget created only after the
TTY approval succeeds. New helper mutation is cut off at 65 seconds; control
cleanup, authorization close, after-state verification and the final report
have absolute cutoffs at 73, 94, 118 and 120 seconds. Each Core observation
shrinks its command timeout from the same remaining stage budget. Cancellation
before authorization result cannot start the provider, and the final
`start_connection` gate is checked again inside the scoped snapshot borrow at
the irreversible submission point. Cleanup is cancellation-shielded, retains
the same-session provisional stop authority, and preserves late receipts while
refusing to call them verified. A deadline report maps to exit `124`, while
unproven cleanup retains the higher-priority exit `74`.

The development `vendor_once` adapter is deliberately narrow. It does not
reimplement Portal login or copy the vendor's TLS behavior. `vendor-once begin`
persists only the pre-GUI source cursor; after normal official-app login and
Cmd-Q, Product accepts only the new complete generation after that cursor,
filters it to exactly one `login21` candidate, owns the material only in memory
and consumes the cursor when the mutating acquisition is claimed. The signed
bundle template, preferences and credential-history database remain rejected
as authorization sources.

The first real M2 transaction has now run, but it did **not** connect. It
submitted exactly one `start_connection`; that request timed out before any
connected status, active-path proof or fresh SSH proof. Cleanup then submitted
exactly one same-session provisional `stop_connection`, verified every cleanup
dimension and finished in `disconnected` with zero retry. The one-shot cursor
was consumed. A gatewayless point-to-point default-route shape encountered in
this path is now canonicalized without weakening the required destination,
interface or flags checks.

One allowlisted `invalid HASH_V1` marker was observed after the M2 start. A
subsequent fixed `get_version` request succeeded, so the current blocker is not
generic XPC reachability and the complete dry-run excludes a missing snapshot
field. The exact live blocker is the vendor start/session-reuse boundary after
normal official-app Cmd-Q. The marker narrows that boundary but is not claimed
as a fully isolated cryptographic root cause. The product is therefore still
not a usable VPN and the Goal remains **ACTIVE**.

## Development

```sh
swift build --product powervpn --arch arm64
swift test --filter 'ProductReadinessRuntimeTests|ProductCommandTests'
```

For a one-command arm64 build followed by an exact CLI invocation:

```sh
scripts/build_and_run.sh doctor --json
```

With no arguments the wrapper builds the product and prints CLI usage; it does
not choose or run a live operation by default.

Product JSON commands use exit `0` when ready, `2` for a completed degraded
observation, `64` for invalid product-command grammar, and `69` when a required
local provider is unavailable. The M2 command additionally uses `74` when
cleanup is unproven and `124` when its absolute report deadline is exceeded
without a higher-priority cleanup failure.

## Archived evidence history

The following sections preserve the protocol lab and Rescue R1/R2 lineage. They
are useful implementation inputs, but they are no longer the active product
critical path.

- Active execution has switched to the Rescue CLI on
  `rescue-state-machine`; Native V3 remains frozen at the clean CP7B fallback,
  and its noncanonical CP8A work is preserved on `native-v3-cp8a-wip`.
- Rescue R1 is **PASS**. The arm64 CLI directly received the installed charon
  helper's exact `version="24572"`, `get_version=true` business event and bound
  it synchronously to the single cold-start launchd generation. The helper had
  zero TCP/UDP descriptors and exited naturally within the deadline; network,
  Surge, route, DNS, interface, and utun evidence stayed stable. The probe did
  not log in, contact a server, send `start_connection`, or create an SA,
  route, or utun. Direct SAD/SPD comparison remained unavailable to the
  unprivileged harness and is not claimed.
- Rescue R2 is a **hard NO-GO, not PASS**. The `PowerVPNPortal` target
  implements the evidence-locked password POST,
  resource GET, 60-second session check and logout with a no-echo controlling
  TTY, system TLS trust, a closed XML profile, bounded response storage and
  app-owned buffer erasure. The current endpoint was confirmed by a narrow
  latest-address query against a mode-600 encrypted database copy; no user row
  was queried. The one permitted integrated review completed with five direct
  findings, and all five were fixed. Foundation's projected `Set-Cookie` value
  remains locally fail closed because it cannot prove raw header
  multiplicity/framing. The independent, value-free raw-header subcheckpoint
  now passes its synthetic offline verifier and its one integrated review is
  complete. That review returned exactly two direct findings, both applied: a
  factory-only unforgeable operation proof now keeps forged body, Cookie and
  User-Agent near misses out of both transport lanes, and TLS trust
  classification is limited to peer/issuer verification while handshake and
  cipher failures are `unavailable`. No second raw-header review ran. That
  synthetic evidence remains implementation evidence, not server compatibility.
  The exact live-authorized manifest is archived at
  `fixtures/redacted/r2-portal-login-authorized-manifest-v1.json`, SHA-256
  `bde4de003e1c5bd2128f5e4b147f05ae3149f2b639126e783585bfb6a1b6302b`
  and runtime source aggregate SHA-256
  `83c590c8ebb3c15b8e32d125bfbdef6c4b39aabd94ca9235c35aef140b67eee2`.
  The manifest separately binds runtime-library SHA-256
  `b57c969c986f46c58913c5e5d27bace5131771ff9e343c111e86389d97a12047`
  and raw-header-test aggregate SHA-256
  `a6d98b928a9c0a63ded37b7b60120e9483fabddf8dea6a895a160276a4acab05`.
  Its full offline verifier passes with 120 Portal tests in 19 suites and 109
  Core tests in 10 suites (229 tests in 29 suites), plus the direct raw C
  parser/status gates. One authorized, exact-manifest-bound R2B window then ran
  with TTY-only credential re-entry and
  `exposedCredentialRiskAccepted=true`. It completed with
  `checkpointPass=false`, CLI exit 2 and `tls_rejected`; only the login request
  was attempted. Resource listing, session check and logout were not requested.
  The complete value-free runtime fixture is
  `fixtures/redacted/r2-portal-login-runtime-v1.json`, SHA-256
  `78a0815ab247c36e8d30683b7f83a09d34d4da2dbe94e395e6f116c8423ca714`.
  No helper, native charon or UDP descriptor appeared, launchd stayed 19→19,
  and artifact identity/cleanup were exact. The strict network gate failed only
  because the raw IPv4 route SHA changed; route count 136, persistent route
  count 65/hash, default route, DNS, interfaces, utun, ESP and Surge remained
  stable. R2B is **FAIL / INCOMPLETE** and the Goal remains active. Next is a
  credential-free bounded TLS trust evidence gate, not a blind login retry.
  Post-evidence verifier binding produced development manifest SHA-256
  `8e19d1937d7ab432e9a747725d636e565432159561a0962a6d0ec07afe9fdb1e`;
  those changed bytes were not live-authorized and cannot authorize a retry.
  Two later credential-free TLS evidence windows were both inconclusive and
  their authorizations are consumed. The post-attempt-2 offline candidate now
  copies the peer chain directly from Network.framework metadata, calls the
  rejecting verify completion exactly once, and evaluates new SSL/basic trust
  objects only on a bounded asynchronous, no-network-fetch lane. Its v3 report
  separates execution safety, transport evidence, trust evidence,
  compatibility, monitor quality and environment stability. The candidate is
  review-only. Follow-up delta analysis required a single-lock combined
  transport/evidence snapshot, pre-serialization report validation, an exact
  trust-reservation linearization point, and a one-way finalization barrier
  with PID-bound guard acknowledgement and atomic result publication. The new
  pending-review manifest SHA-256 is
  `22b73d9f6b1f583335f2b0f24f2331b904c8b6bb0f2cb29ef8c99ebb43d54f9d`;
  the full offline verifier passes 37 TLS-evidence, 120 Portal and 109 Core
  tests (266 total). Attempt 3, portal login, R3 and UI work remain a hard
  NO-GO pending an independent delta review.
  The frozen raw-header contract is documented in
  `docs/evidence/checkpoint-r2-raw-header-framing.md`.

- The vendor helper is based on strongSwan 5.8.0. This is proven by unstripped
  Mach-O symbol paths, not inferred from release dates.
- `leadsecbridge` is both a custom strongSwan kernel plugin and part of a
  private IKEv1 resource-rule extension. Successful sessions send encrypted
  QUICK_MODE messages containing `ADDRULE`; the binary also contains the
  matching `DELRULE` and `expandrule` payload/task code.
- The standard base is still recognizable: IKEv1 Main Mode, PSK, a conventional
  IKE proposal, a conventional ESP proposal, and a base CHILD_SA.
- Upstream strongSwan 6.0.7 builds successfully as arm64 on this Mac with VICI,
  PF_ROUTE, PF_KEY, kernel-libipsec, IKEv1, and XAuth support. PF_KEY and
  kernel-libipsec reach their expected root capability gate in an unprivileged
  startup smoke test.
- CP4A now has a strict offline 6.0.7 codec for the five observed expandrule
  wire forms. Seven synthetic byte vectors cover nine logical contexts; the
  payload's opaque fields deliberately remain unnamed until CP5/CP4B evidence.
- CP5 correlates the recovered portal/helper schemas with one authorized legal
  session. The value-free runtime fixture confirms session-check request/status
  metadata and the GUI resource-toggle producer shape; WebSocket behavior and
  the exact portal-field-to-PSK/resource mapping remain explicitly unknown.
- CP4B made zero business-semantic wire promotions: the complete static writer
  chain remains one evidence class, so opaque resource fields stay opaque.
- CP6 is **PASS (offline compatibility-port checkpoint)**. Upstream commit
  `67c9810900e2d8486cb3b11495a8362433494ca0` and replayable 0002 patch SHA-256
  `6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213`
  implement the payload/factory/task surface while leaving `keymat_v1.c` and
  `task_manager_v1.c` unchanged from CP4A.
- New static evidence fixes the private Quick Mode contract: vendor
  `_get_hash_phase2` at `0x10014fa70` has no custom branch; `_build_i` state 0
  builds standard SA/NONCE/TS and state 1 appends ADDRULE. The resulting
  `[HASH ADDRULE]` uses standard
  `HASH(3)=PRF(SKEYID_a,0|M-ID|Ni_b|Nr_b)` and excludes ADDRULE bytes.
- `fixtures/redacted/leadsec-qm-hash3-static-vector-v1.json` records the
  value-free static contract, and an independent synthetic HASH(3) reference
  matches the implementation. Targeted expandrule tests pass 39/39, full
  libcharon suites pass 5/5, the no-IKEv1 build passes, and patch replay equals
  the implementation tree.
- The strict Swift VICI dry run remains accepted: its 335-byte stock
  `load-conn` request matches the official Python VICI encoder. This does not
  prove live vendor differential behavior or server acceptance, both of which
  remain unproven.
- CP7A is **PASS (local runtime, no backend/server)**. The old VICI
  timeout was caused by a four-worker pool fully occupied by long-running
  CRITICAL jobs. With five workers, the official 6.0.7 Python client and the
  Swift client receive byte-identical `version` responses from the same daemon,
  then both complete a credential-free synthetic load/list/unload lifecycle.
  The accepted run used ephemeral ports and a fake kernel, created no route or
  utun, preserved Surge/default-route/DNS, and left no generation-owned residue.
  Its one integrated review was closed by rejecting streamed command failures,
  preserving ownership state on unexpected cleanup residue, and detecting
  orphan fixed sockets and generation directories.
- CP7B is **PASS (serverless L5 backend only)**. The authorized window bound to
  manifest
  `7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`
  ran source `a81298234753f314dbf2c4f2867a9a144006bd8c` for 21 seconds as attempt 1.
  `pfkey-pfroute` and `socket-dynamic` reached ready; the official VICI client
  completed `version` and read-only status/list probes, with empty
  connection/SA/policy inventories under the runner contract. Native UDP
  descriptors stayed at zero, with no endpoint, server packet, credential
  read, `initiate`, or install operation.
- The same CP7B result proves SAD, SPD, global ESP port, persistent IPv4/IPv6
  route projections, default route, DNS, utun inventory, PowerVPN, and Surge
  remained stable. Cleanup assertion passed; the runtime returned to
  UID 502:GID 20, mode 700, with only the reviewed `closure` at top level. The
  earlier manifest's preflight-only inconclusive result remains historical and
  does not weaken this later PASS.
- CP7B does **not** prove IKE or server compatibility: no connection was loaded,
  no credential was handed off, and no SA/policy/route was installed. Main
  Mode, Quick Mode, ADDRULE, resource data path, and server acceptance remain
  untested. CP8A secure runtime-material handoff remains the next Native V3
  fallback step, but it is paused rather than active. Rescue R1 first tests
  whether the installed helper can be controlled read-only without the GUI.
  CP7B's one integrated review and one additional narrow review are complete;
  no third or unrelated-history review is planned.

The frozen Native V3 target remains:

```text
upstream strongSwan 6.0.7
    + minimal, maintained ADDRULE/DELRULE payload + IKEv1 task extension
    + a verified macOS kernel/userland IPsec backend
    + an independent HTTPS/WebSocket control plane
    + an event-driven recovery coordinator
```

The vendor 5.8.0 code is a behavioral reference only. Its x86_64 plugin is not
reused, and strongSwan 6.0.3+ rejects plugins built for a different version in
any case.

## Protocol fidelity invariant

This repository is a compatibility port, not a protocol-design project:

1. It MUST NOT add, remove, reorder, normalize, reinterpret, or symmetrize any
   observed payload, field, byte order, HASH coverage, or directional asymmetry.
2. Every outbound byte MUST trace to vendor evidence, a protected reference
   vector, or an explicitly approved server-acceptance result.
3. Unknown length-delimited values MUST remain opaque and neutral.
4. Structural parseability MUST NOT imply profile acceptance or permission to
   emit; parse, accept, and emit are separate decisions.
5. The private-context predicate MUST be complete; outside it, payload order,
   HASH behavior, message rules, and results remain identical to upstream.
6. A same-implementation generate/verify round trip proves self-consistency
   only and MUST NOT be reported as compatibility evidence.
7. Observed vendor behavior outranks standards-driven cleanup or upstream
   intuition inside the compatibility profile.
8. Wire-neutral bounds, memory safety, secret hygiene, and fail-closed checks are
   allowed; wire-visible improvements or generalizations are forbidden.
9. Owned GUI, XPC/control schema, helper names, classes, and state machines may
   be refactored; only server-observable bytes, timing, and effects must match.
10. Intentional divergence MUST live outside the compatibility profile behind
    an independent feature gate that is default off.

## Commands

```bash
swift run powervpn status
swift run powervpn probe --timeout 5
swift run powervpn diagnose --json
swift run powervpn oracle inventory --json
swift run powervpn oracle correlate fixtures/redacted/protocol-correlation-value-free-v1.json --json
swift run powervpn oracle correlate fixtures/redacted/protocol-correlation-runtime-metadata-v1.json --json
swift run powervpn spec validate-redacted fixtures/redacted/tunnel-spec.example.json
swift run powervpn spec vici-dry-run fixtures/redacted/tunnel-spec.vici-dry-run.json --json
swift run powervpn vici version --socket <scratch-charon.vici> --timeout-ms 2000 --json
swift run powervpn vici cp7a-smoke --socket <scratch-charon.vici> --timeout-ms 2000 --json
swift run powervpn xpc get-version --timeout-ms 2000 --json
scripts/run_r2_portal_login.sh --preflight-only
```

The VICI runtime commands connect only to an explicitly supplied local socket;
`cp7a-smoke` loads and removes one RFC-5737 synthetic config with
`start_action=none`, no credential, and no initiation. Other CLI commands are
read-only. The old `reconnect` command was removed because terminating and
relaunching the vendor GUI automates a workaround; it does not advance the
native replacement.

The XPC command has no configurable service or payload. It is the Rescue R1
read-only gate and fails closed unless the GUI and helper are absent and the
legacy DNS/log cold-start hazards are safe. Run the reviewed live harness, not
the raw command, for checkpoint evidence.

`powervpn login` accepts no options or positional material and emits only a
closed value-free JSON report. Do not run it directly for checkpoint evidence.
The completed R2B window was bound to manifest SHA-256
`bde4de003e1c5bd2128f5e4b147f05ae3149f2b639126e783585bfb6a1b6302b`,
explicit non-secret exposed-credential risk acceptance and a direct no-echo
controlling TTY. The credential was personally re-entered through the TTY and
was never read or copied from chat. The result is a TLS rejection, not login or
server-compatibility evidence. Do not rerun the raw command or repeat the live
window; the next gate is credential-free TLS trust evidence collection.

## Repository map

- `Sources/PowerVPNCore`: reusable oracle inspection, redaction, TunnelSpec,
  and end-to-end probe logic.
- `Sources/PowerVPNPortal`: isolated installed-config, secure TTY, HTTPS,
  structural XML, LeadSec profile and portal-login workflow logic; it has no
  dependency on `PowerVPNCore`.
- `Sources/PowerVPNCLI`: thin command routing and rendering.
- `docs/protocol-*.md`: verified protocol facts, unknowns, and next experiments.
- `docs/evidence/checkpoint-7b-preflight.md`: reviewed scope and safety contract
  for the separately approved privileged PF_KEY/PF_ROUTE backend window.
- `fixtures/redacted`: synthetic structures and derived value-free runtime
  metadata only; no captured values or replayable payloads.
- `patches/strongswan-6.0.7`: minimal patches replayable on the official tag.
- `captures`: policy and manifests only; raw packet captures never enter Git.

Start with [the native replacement plan](docs/2026-08-08-native-replacement-plan.md)
and [the 6.0.7 build evidence](docs/strongswan-6.0.7-arm64.md).

## Build and test

```bash
swift build --arch arm64
swift test
BIN="$(swift build --show-bin-path)/powervpn"
file "$BIN"
scripts/verify_checkpoint.sh 4a
scripts/verify_checkpoint.sh 5
scripts/verify_checkpoint.sh 6
scripts/verify_checkpoint.sh 7a
scripts/verify_checkpoint.sh 7b-preflight
scripts/verify_checkpoint.sh r1
scripts/verify_checkpoint.sh r2
```

The Swift package has one executable product, `powervpn`, and two independent
library targets, `PowerVPNCore` and `PowerVPNPortal`.

## Safety and scope

- No credential, session ID, PSK, cookie, raw log, or raw packet capture may be
  committed or printed by the CLI.
- A credential pasted into chat or task text is exposed and is never an
  approved runtime source. If rotation is impossible, live reuse requires
  explicit manifest-bound risk acceptance and personal re-entry through the
  no-echo controlling TTY; evidence must not claim it was rotated.
- Raw evidence belongs under a mode-700 directory in `~/scratch-data`, not in
  this repository.
- `/Applications/PowerVPN.app`, its helpers, and code signature are never
  modified. Live network state changes only inside an explicit approval window
  and must be immediately restored and verified.
- A live backend test requiring root or a VPN configuration change is a
  separately approved isolation-window experiment because it may interact with
  Surge.
- CP7B's completed manifest-bound serverless window does not authorize a replay,
  CP8/CP9 server traffic, or access to real runtime material. CP8A may test only
  synthetic/reference-based provider paths until the user authorizes the exact
  secure handoff path; secrets remain forbidden in argv, environment, files,
  fixtures, and logs.
- No SwiftUI, LaunchDaemon, or recovery service is built until protocol gates
  pass.

This is an independent, unofficial project. It is not affiliated with LeadSec
or Tsinghua University. The lab code is MIT-licensed; strongSwan and any future
patch set retain their own upstream licensing and must be distributed
separately and correctly.
