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

## Commands

```bash
swift run powervpn status
swift run powervpn probe --timeout 5
swift run powervpn diagnose --json
swift run powervpn oracle inventory --json
swift run powervpn spec validate-redacted fixtures/redacted/tunnel-spec.example.json
```

All current commands are read-only. The old `reconnect` command was removed
because terminating and relaunching the vendor GUI automates a workaround; it
does not advance the native replacement.

## Repository map

- `Sources/PowerVPNCore`: reusable oracle inspection, redaction, TunnelSpec,
  and end-to-end probe logic.
- `Sources/PowerVPNCLI`: thin command routing and rendering.
- `docs/protocol-*.md`: verified protocol facts, unknowns, and next experiments.
- `fixtures/redacted`: synthetic, commit-safe structures only.
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
```

The Swift package has one executable product, `powervpn`, and one reusable
library target, `PowerVPNCore`.

## Safety and scope

- No credential, session ID, PSK, cookie, raw log, or raw packet capture may be
  committed or printed by the CLI.
- Raw evidence belongs under a mode-700 directory in `~/scratch-data`, not in
  this repository.
- `/Applications/PowerVPN.app`, its helpers, code signature, and live network
  state are never modified by the lab.
- A live backend test requiring root or a VPN configuration change is a
  separately approved isolation-window experiment because it may interact with
  Surge.
- No SwiftUI, LaunchDaemon, or recovery service is built until protocol gates
  pass.

This is an independent, unofficial project. It is not affiliated with LeadSec
or Tsinghua University. The lab code is MIT-licensed; strongSwan and any future
patch set retain their own upstream licensing and must be distributed
separately and correctly.
