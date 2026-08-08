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

## Live Approval Gate 1 — CP7B, not yet authorized

Objective: prove one real macOS backend can initialize and stop without a
server connection, while Surge remains active.

Proposed first window:

- backend: PF_KEY + PF_ROUTE only;
- daemon: locked arm64 CP6 build, scratch prefix and scratch PID directory;
- ports: OS-assigned high UDP ports, never 500/4500;
- server configuration: none;
- credentials: none;
- attempts: at most two PF_KEY launches;
- duration: at most five minutes including cleanup;
- PowerVPN: keep running unless a separately documented conflict requires a
  second approval;
- Surge: keep running; no reload, switch, profile edit, or VPN-manager action;
- privilege: one macOS native authorization dialog through AppleScript/Touch
  ID; no password is requested, read, or typed by Codex.

The approved window will execute this order:

```text
1. verify locked binary/source/piddir and reviewed CP7B config
2. capture process/interface/route/default-route/DNS/Surge/SA-policy pre-state
3. launch one temporary root charon with exactly one kernel provider
4. require VICI version/read-only status; never load credential or initiate
5. capture during state and exact backend readiness/error boundary
6. stop the generation-owned process
7. assert no process/socket/PID/config/log/SA/policy/route/utun residue
8. compare Surge/default-route/DNS and publish only value-free evidence
```

The exact privileged AppleScript command will be emitted in the approval
request after the CP7B config has received its one preflight review. CP7A's
current `run_native_charon.sh` deliberately rejects root, so this document
cannot accidentally cross the gate.

If PF_KEY fails with an evidence-complete errno/plugin boundary, a separate
reviewed window may use kernel-libipsec. The two providers are never loaded
together. A kernel-libipsec window may create a utun and therefore requires its
own explicit impact statement.

Approval for CP7B does not authorize CP8/CP9 server traffic.
