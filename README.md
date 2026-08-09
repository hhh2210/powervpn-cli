# PowerVPN Protocol Lab

An unofficial, Apple Silicon-native protocol feasibility lab for replacing the
LeadSec PowerVPN macOS client without changing the server or bypassing
authentication.

This repository is **not a working VPN replacement yet**. Its current job is to
turn the installed x86_64 client into a read-only protocol oracle, preserve
redacted evidence, and measure the exact delta between LeadSec's fork and
upstream strongSwan 6.0.7.

## Current verdict

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
  cipher failures are `unavailable`. No second raw-header review ran. No live
  request, successful TLS transfer, server interaction or credential use
  occurred, so this is implementation evidence, not server compatibility or
  authorization to contact the portal. The reviewed R2 candidate is now
  resealed by manifest SHA-256
  `00411979105d9023916af3eef5bda0f3886231a5ad74714c0e47d5197bf9e084`
  and runtime source aggregate SHA-256
  `83c590c8ebb3c15b8e32d125bfbdef6c4b39aabd94ca9235c35aef140b67eee2`.
  The manifest separately binds runtime-library SHA-256
  `d6c3f1696e18beac31ffd425e177febce5ec523a0f6a05c2f8bf6c9e8cf56152`
  and raw-header-test aggregate SHA-256
  `a6d98b928a9c0a63ded37b7b60120e9483fabddf8dea6a895a160276a4acab05`.
  Its full offline verifier passes with 120 Portal tests in 19 suites and 109
  Core tests in 10 suites (229 tests in 29 suites), plus the direct raw C
  parser/status gates. R2 live login remains **HARD NO-GO / NOT TESTED**. The
  next action is external rotation of the password exposed in task text,
  followed by fresh approval bound to the exact manifest. New credentials may
  be entered only through the no-echo controlling TTY, never chat. The frozen
  raw-header contract is documented in
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
The R2 harness requires exact manifest SHA-256
`00411979105d9023916af3eef5bda0f3886231a5ad74714c0e47d5197bf9e084`,
a separate external password-rotation confirmation, fresh manifest-bound
approval and a direct no-echo controlling TTY. Only the TTY may receive the new
credentials; they must never be sent through chat. The authorized harness then
permits TCP only to the sealed portal while rejecting all helper, native-charon
and UDP activity.

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
- A credential pasted into chat or task text is considered compromised. It is
  never an approved runtime source and must be rotated before live use.
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
