# Live test plan

This plan separates the completed unprivileged CP7A control-path test, the
inconclusive first CP7B root preflight, and the next privileged backend window.
It is not blanket authorization for server traffic, credentials, route changes,
or recovery testing.

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

The user first authorized dedicated scratch build, runner/rollback
implementation, dry validation, and one integrated preflight review. The user
later authorized one root window bound to historical manifest
`c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`.
That root worker rejected unstable preflight snapshots before daemon launch.
The old authorization is consumed: it neither permits an automatic retry nor
transfers to a changed manifest.

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

Proposed live window after fresh explicit approval of the current manifest:

- backend: PF_KEY + PF_ROUTE only;
- socket provider: `socket-dynamic`, with `socket-default` excluded from the
  loaded plugin set;
- daemon: dedicated arm64 CP7B build whose parent is the locked CP6 commit,
  with separate scratch source/build/prefix/PID directories;
- ports: config values `0/0`, but no socket is created without a send; required
  observed native UDP descriptor count is zero;
- server configuration: none;
- credentials: none;
- attempts: bounded by the newly approved manifest, with no automatic second
  launch; the historical manifest's unused allowance is not inherited;
- duration: at most five minutes including cleanup;
- PowerVPN: keep running unless a separately documented conflict requires a
  second approval;
- Surge: keep running; no reload, switch, profile edit, or VPN-manager action;
- privilege: one macOS native authorization dialog through AppleScript/Touch
  ID after the second approval; no password is requested, read, or typed by
  Codex.

All script and binary hashes in
`fixtures/redacted/cp7b-approval-manifest-v1.json` are integrity inputs. The
historical manifest bound only the completed first window. After the route-gate
remediation and one additional narrow review, the exact execution form awaiting
fresh approval is:

```bash
scripts/run_cp7b_backend.sh \
  --execute-reviewed \
  --manifest-sha256 7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187
```

The finalized hash is an integrity boundary, not authorization by itself.

The approved window will execute this order:

```text
1. verify the reviewed manifest, binary/script hashes, source commit, arm64
   artifacts, scratch piddir and exact config bytes; take and revalidate the
   complete root execution closure before any `exec`/`dlopen`
2. capture two stable process/interface/persistent-route/default-route/DNS/
   Surge/PowerVPN, SAD, SPD and `net.inet.ipsec.esp_port` pre-state snapshots;
   legacy complete-route hashes remain diagnostic only
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
   SA/SPD/persistent-route/utun/sysctl residue
9. compare read-only Surge environment/DNS and publish only value-free evidence
```

The separately invocable stop form is:

```bash
scripts/stop_cp7b_backend.sh \
  --execute-reviewed \
  --manifest-sha256 7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187
```

Zero residue is then checked with:

```bash
scripts/assert_cp7b_teardown.sh --result <scratch-result-json>
```

These commands remain unauthorized until fresh manifest-bound approval.
CP7A's
`run_native_charon.sh` continues to reject root and is not reused as the CP7B
privilege boundary.

If PF_KEY fails with an evidence-complete errno/plugin boundary, this window
stops. A kernel-libipsec/utun experiment requires a new reviewed manifest and a
separate approval; the two providers are never loaded together.

Approval for CP7B does not authorize CP8/CP9 server traffic.

### First root-window result and current gate

The historical root invocation is `INCONCLUSIVE_PREFLIGHT_FAILURE`, not a
backend result. The root worker launched, but `charon`, the gated launcher,
VICI, PF_KEY/PF_ROUTE constructors, and L5 did not. A separately reviewed stop
found the runtime clean and returned `alreadyStopped=true`.

The outer `after` snapshot was post-hoc at 496 seconds, so it cannot prove
bounded kernel teardown. Its only mismatch was the legacy full IPv4 route-table
count/hash. Process and owned filesystem residue are clean; SAD/SPD were not
available to the unprivileged outer snapshot.

The full-table mismatch was traced to transient rows with nonempty `Expire` or
uppercase `W` (`RTF_WASCLONED`). The current route gate uses a strict structural
parser plus a persistent projection over
`family/destination/gateway/flags/netif`, excluding those transient rows while
retaining `D`/`C`/`c`. Parse, project, sort, count, hash, command execution, and
default-route parsing fail closed independently. Structurally valid input with
zero persistent rows is rejected by the profile, not by the parser. Early root
preflight failure now returns bounded manifest/source/config evidence, and the
prompt deadline guard terminates and reaps its child.

Exactly one additional narrow review covered route layout,
direction/profile-independent structural parsing, canonicalization, failure
propagation, deadline cleanup, and the first review's direct findings. It did
not re-review unrelated repository history, and no third review is permitted.

The next root window requires fresh explicit approval bound to current manifest
SHA-256
`7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`
and the exact command above. Neither
the historical authorization nor any unused retry allowance is reusable.
