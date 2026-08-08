# powervpn-cli

An unofficial, Apple Silicon-native control and diagnostic CLI for the LeadSec
PowerVPN macOS client.

This project does **not** replace the proprietary VPN tunnel yet. It replaces
the fragile GUI control loop with explicit, inspectable commands while reusing
the installed vendor helper and its authenticated session.

The full interaction timeline, local evidence, corrected misdiagnoses, and
remediation analysis are recorded in
[the 2026-08-08 incident postmortem](docs/2026-08-08-power-vpn-incident-postmortem.md).

## Why this exists

PowerVPN 3.2.1 build 24572 on Apple Silicon can display `login21` and `login52`
as enabled while both SSH endpoints stop producing an SSH banner. Local
evidence shows two independent recovery defects:

- IKEv1 can enter a stale-authentication loop with `invalid HASH_V1`, long
  retransmission backoff, and no session refresh.
- the GUI WebSocket failure and close callbacks only log the error; they do not
  reconnect or reauthenticate.

The x86_64 `com.leadsec.charon-xpc` helper has also crashed under Rosetta with
`SIGILL` in its XPC dictionary conversion path. A full native tunnel requires
replacing the vendor's strongSwan-derived helper and private `leadsecbridge`
plugin; recompiling the GUI alone cannot accomplish that.

## Commands

```bash
swift run powervpn status
swift run powervpn probe --timeout 5
swift run powervpn diagnose --json
swift run powervpn reconnect --yes
```

`reconnect` is never automatic. It terminates and relaunches the existing
PowerVPN app, which remains responsible for authentication.

## Build and test

```bash
swift build --arch arm64
swift test
BIN="$(swift build --show-bin-path)/powervpn"
file "$BIN"
```

## Scope and safety

- No credentials, session IDs, or raw VPN logs are printed.
- No LaunchAgent is installed.
- `/Applications/PowerVPN.app` and its code signature are not modified.
- This is an independent, unofficial project and is not affiliated with
  LeadSec or Tsinghua University.
