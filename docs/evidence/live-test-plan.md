# Live test plan

This plan records the completed unprivileged CP7A control-path test, the
inconclusive first CP7B root preflight, and the accepted second CP7B privileged
backend window. It is not authorization for server traffic, credentials, route
changes, or recovery testing.

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

## Live Approval Gate 1 — CP7B completed

Objective: prove one real macOS backend can initialize and stop without a
server connection, while Surge remains active.

The user first authorized dedicated scratch build, runner/rollback
implementation, dry validation, and one integrated preflight review. The user
later authorized one root window bound to historical manifest
`c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`.
That root worker rejected unstable preflight snapshots before daemon launch.
The user then separately authorized manifest
`7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`;
its attempt 1 passed the serverless backend window and cleanup. Both
authorizations are consumed and cannot be replayed.

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

Accepted live-window profile:

- backend: PF_KEY + PF_ROUTE only;
- socket provider: `socket-dynamic`, with `socket-default` excluded from the
  loaded plugin set;
- daemon: dedicated arm64 CP7B build whose parent is the locked CP6 commit,
  with separate scratch source/build/prefix/PID directories;
- ports: config values `0/0`, but no socket is created without a send; required
  observed native UDP descriptor count is zero;
- server configuration: none;
- credentials: none;
- attempts: attempt 1 only, with no automatic second launch;
- duration: 21 seconds including bounded runtime work;
- PowerVPN: keep running unless a separately documented conflict requires a
  second approval;
- Surge: keep running; no reload, switch, profile edit, or VPN-manager action;
- privilege: one macOS native authorization dialog through AppleScript/Touch
  ID after the second approval; no password is requested, read, or typed by
  Codex.

All script and binary hashes in
`fixtures/redacted/cp7b-approval-manifest-v1.json` are integrity inputs. The
historical manifest bound only the completed first window. After the route-gate
remediation and one additional narrow review, the user authorized this exact
execution form:

```bash
scripts/run_cp7b_backend.sh \
  --execute-reviewed \
  --manifest-sha256 7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187
```

The finalized hash was both the integrity boundary and the object named by the
user's explicit authorization.

The accepted window executed this order:

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

The launch authorization is consumed; the command must not be replayed. The
stop form remains documentation of the completed rollback contract, not a new
authorization.
CP7A's
`run_native_charon.sh` continues to reject root and is not reused as the CP7B
privilege boundary.

If PF_KEY fails with an evidence-complete errno/plugin boundary, this window
stops. A kernel-libipsec/utun experiment requires a new reviewed manifest and a
separate approval; the two providers are never loaded together.

Approval for CP7B does not authorize CP8/CP9 server traffic.

### Root-window results and current gate

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

The separately authorized second window bound to manifest
`7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`
completed attempt 1 in 21 seconds with source
`a81298234753f314dbf2c4f2867a9a144006bd8c`. PF_KEY/PF_ROUTE and
`socket-dynamic` reached ready; official VICI read-only probes succeeded and
connection/SA/policy inventories were empty under the runner contract. Native
UDP count stayed zero, with no endpoint, server traffic, credential read,
`initiate`, or install. SAD/SPD/ESP port, persistent routes, default route,
DNS, utun, PowerVPN, and Surge stayed stable; teardown assertion passed and the
runtime returned to UID 502:GID 20, mode 700, closure-only.

CP7B is therefore **PASS at serverless L5 backend**, not IKE or server-protocol
PASS. The next checkpoint is CP8A secure runtime-material handoff with **NO
SERVER TRAFFIC**. Real material requires a user-authorized secure provider/path,
and secrets may not enter argv, environment, files, fixtures, or logs.
