# PowerVPN Protocol Lab

An unofficial, Apple Silicon-native protocol feasibility lab for replacing the
LeadSec PowerVPN macOS client without changing the server or bypassing
authentication.

This repository is **not a working VPN replacement yet**. Its current job is to
turn the installed x86_64 client into a read-only protocol oracle, preserve
redacted evidence, and measure the exact delta between LeadSec's fork and
upstream strongSwan 6.0.7.

## Current verdict

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
- CP7B preflight is **PASS; root/live execution is waiting for a second explicit
  approval** bound to manifest SHA-256
  `c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`.
  Source inspection found
  that macOS PF_KEY plus `socket-default` writes the global
  `net.inet.ipsec.esp_port` when opening its NAT-T socket and has no teardown
  restore path. The candidate therefore uses an independent scratch CP7B build
  with `socket-dynamic`; its root-executed closure is hash-pinned and sealed
  before launch, and its same-PID gated launcher closes the spawn/state gap.
  The `0/0` port config must produce exactly zero UDP descriptors in this
  no-send smoke. No privileged backend, IKE SA, server
  traffic, credential handoff, or resource data path has passed.

The target is therefore:

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
```

The VICI runtime commands connect only to an explicitly supplied local socket;
`cp7a-smoke` loads and removes one RFC-5737 synthetic config with
`start_action=none`, no credential, and no initiation. Other CLI commands are
read-only. The old `reconnect` command was removed because terminating and
relaunching the vendor GUI automates a workaround; it does not advance the
native replacement.

## Repository map

- `Sources/PowerVPNCore`: reusable oracle inspection, redaction, TunnelSpec,
  and end-to-end probe logic.
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
```

The Swift package has one executable product, `powervpn`, and one reusable
library target, `PowerVPNCore`.

## Safety and scope

- No credential, session ID, PSK, cookie, raw log, or raw packet capture may be
  committed or printed by the CLI.
- Raw evidence belongs under a mode-700 directory in `~/scratch-data`, not in
  this repository.
- `/Applications/PowerVPN.app`, its helpers, and code signature are never
  modified. Live network state changes only inside an explicit approval window
  and must be immediately restored and verified.
- A live backend test requiring root or a VPN configuration change is a
  separately approved isolation-window experiment because it may interact with
  Surge.
- CP7B's implementation/build/dry-review authorization is not root execution
  authorization. Its integrated preflight review and manifest are finalized,
  but the privileged command still requires a second explicit user approval.
  PowerVPN and Surge remain running; `socket-default` is excluded and
  any native UDP descriptor or global ESP-port change fails closed.
- No SwiftUI, LaunchDaemon, or recovery service is built until protocol gates
  pass.

This is an independent, unofficial project. It is not affiliated with LeadSec
or Tsinghua University. The lab code is MIT-licensed; strongSwan and any future
patch set retain their own upstream licensing and must be distributed
separately and correctly.
