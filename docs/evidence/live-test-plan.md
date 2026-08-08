# Live test plan

This plan separates the completed unprivileged CP7A control-path test from the
next privileged backend window. It is not blanket authorization for server
traffic, credentials, route changes, or recovery testing.

## CP7A — completed without approval

The verifier runs one bounded fake-kernel daemon with five workers, ephemeral
UDP ports, no credential, and no initiation:

```bash
scripts/verify_checkpoint.sh 7a
```

The verifier performs two stable preflight snapshots, official-Python and
Swift VICI `version` plus synthetic load/list/unload, a during snapshot,
identity-checked stop, and clean-teardown comparison. It never contacts a VPN
server or uses root.

## Live Approval Gate 1 — CP7B split authorization

Objective: prove one real macOS backend can initialize and stop without a
server connection, while Surge remains active.

The user has authorized the preflight implementation only: dedicated scratch
build, runner/rollback implementation, dry validation, and one integrated
preflight review. This authorization does not permit AppleScript elevation,
Touch ID, a root daemon, PF_KEY/PF_ROUTE runtime access, or any network change.

### Material finding and revised provider

The original `socket-default` proposal is retired for CP7B. On macOS its NAT-T
startup path calls PF_KEY `enable_udp_decap()`, which writes the selected port
to the global `net.inet.ipsec.esp_port` sysctl. `port_nat_t = 0` still allocates
a port before that write, and upstream destroy paths do not restore the prior
value. A transient write is unsafe while PowerVPN remains active.

The preflight candidate therefore uses a separate CP7B build with
`socket-dynamic`. Its no-send constructor creates no UDP socket. The config
still sets `port = 0` and `port_nat_t = 0`, but the live gate expects exactly
zero UDP descriptors throughout the serverless smoke. See
[the CP7B preflight evidence](checkpoint-7b-preflight.md).

Proposed live window after a second explicit approval:

- backend: PF_KEY + PF_ROUTE only;
- socket provider: `socket-dynamic`, with `socket-default` excluded from the
  loaded plugin set;
- daemon: dedicated arm64 CP7B build whose parent is the locked CP6 commit,
  with separate scratch source/build/prefix/PID directories;
- ports: config values `0/0`, but no socket is created without a send; required
  observed native UDP descriptor count is zero;
- server configuration: none;
- credentials: none;
- attempts: at most two PF_KEY launches;
- duration: at most five minutes including cleanup;
- PowerVPN: keep running unless a separately documented conflict requires a
  second approval;
- Surge: keep running; no reload, switch, profile edit, or VPN-manager action;
- privilege: one macOS native authorization dialog through AppleScript/Touch
  ID after the second approval; no password is requested, read, or typed by
  Codex.

All script and binary hashes in
`fixtures/redacted/cp7b-approval-manifest-v1.json` are finalized and the single
integrated preflight review is closed. The exact execution form awaiting the
second approval is:

```bash
scripts/run_cp7b_backend.sh \
  --execute-reviewed \
  --manifest-sha256 c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877
```

The finalized hash is an integrity boundary, not authorization by itself.

The approved window will execute this order:

```text
1. verify the reviewed manifest, binary/script hashes, source commit, arm64
   artifacts, scratch piddir and exact config bytes; take and revalidate the
   complete root execution closure before any `exec`/`dlopen`
2. capture two stable process/interface/route/default-route/DNS/Surge/PowerVPN,
   SAD, SPD and `net.inet.ipsec.esp_port` pre-state snapshots
3. commit a same-PID gated-launch state, then launch one temporary root charon
   with exactly PF_KEY/PF_ROUTE and `socket-dynamic`
4. require zero UDP descriptors and no packet-send event
5. use the root-owned copy of the official Python VICI client for `version`,
   read-only `stats`, and empty connection/SA/policy listings; never execute
   root `swanctl`, load a credential/config, or initiate
6. capture state both before and after the VICI probes, including a second
   zero-UDP/no-send check and exact backend readiness/error boundary
7. stop only the generation-owned process with bounded INT/TERM/KILL
8. assert no process/socket/PID/config/log/state/attempt-ledger/bootstrap/
   SA/SPD/route/utun/sysctl residue
9. compare read-only Surge environment/DNS and publish only value-free evidence
```

The separately invocable stop form is:

```bash
scripts/stop_cp7b_backend.sh \
  --execute-reviewed \
  --manifest-sha256 c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877
```

Zero residue is then checked with:

```bash
scripts/assert_cp7b_teardown.sh --result <scratch-result-json>
```

These commands remain unauthorized until the second approval. CP7A's
`run_native_charon.sh` continues to reject root and is not reused as the CP7B
privilege boundary.

If PF_KEY fails with an evidence-complete errno/plugin boundary, this window
stops. A kernel-libipsec/utun experiment requires a new reviewed manifest and a
separate approval; the two providers are never loaded together.

Approval for CP7B does not authorize CP8/CP9 server traffic.
