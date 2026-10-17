---
name: powervpn
description: Run commands on Larry's THU servers (thu21 login node, thu52) that are reachable only through PowerVPN. Use whenever a task needs to execute anything on thu21/thu52, copy files to or from them, or hits a failing `ssh thu21`. One command does it all — `powervpn run <target> -- '<cmd>'` — and a quarantined session is cleared with `powervpn recovery clear --json` without asking Larry. For Slurm jobs, environments or models on thu21, use it together with thu21-gpu-workflow.
---

`powervpn run thu21 -- '<cmd>'` is the command for normal work. For a stuck session, the only other commands are `powervpn recovery inspect --json`, `powervpn recovery clear --json` and, when `next:` names it, `powervpn repair vendor-log --json` (see Recovery). Do not read the powervpn source, README, `--help`, or `debug` output, and do not call `up`, `down`, `status` or `doctor` yourself: `run` already does what they would diagnose, every failure ends with a `next:` line saying what to do, and `down` would cut the session that concurrent `run` calls share.

## What it does

- Reuses the live thu21 session, or starts one and keeps it for later calls (first call ~5 s, later ~0.2 s).
- Clears a leftover cleanup quarantine itself, through the same measured safety gate a human would use.
- Retries one transient start failure.
- Passes stdin, stdout, stderr, and the remote exit code straight through; parallel calls are fine.

The same works for `thu52` (only one target can be connected at a time).

## Exit codes

| Code | Meaning | Do |
|---|---|---|
| remote command's own code | the command ran on the server | handle it as that command's result |
| 75 | retryable (busy, start failed twice, session dropped mid-command) | wait ~10 s, rerun the same command; after 3 tries treat as 77 |
| 77 | blocked | read the `next:` line; if it is a `powervpn recovery …` step, run Recovery yourself; otherwise see "When to involve Larry" |
| 64 | your command line is malformed | fix it: `run <target> -- <command>` |

A PowerVPN-side failure always ends stderr with `powervpn run: <token>` then `next: <action>`. If those lines are absent, a 75 or 77 came from the remote command itself.

## Recovery (no human approval needed)

Larry authorized agents to clear PowerVPN quarantines on their own: this is an intranet VPN to his own servers, and `clear` only succeeds after its own measured network-baseline gate passes, so it cannot leave the Mac in a worse state.

Trigger: `powervpn run` ends with a token such as `recovery_rejected` or `cleanup_unproven`, or with `next: powervpn recovery …`.

1. `powervpn recovery inspect --json`: read-only. Note `originalFailure` and `measurement.failure`.
2. `powervpn recovery clear --json`. Success is `"quarantineCleared": true` with `"outcome": "recovered"`.
3. Rerun the original `powervpn run …` command.

If `clear` does not recover, the JSON's `captureAssessment` names the unstable item (for example `vendorProcessesAbsent`, `surgeStable`, `utunStable`, `defaultRouteStable`). Wait ~30 s for the network to settle and run `clear` again, up to 3 attempts. A first `run` attempt can fail the gate while `clear` passes moments later; that is normal, so do not stop after one rejection.

If the `next:` line is `powervpn repair vendor-log --json`, run it yourself: the local preflight found the vendor log missing or no longer root-only, and repair restores it through one macOS administrator dialog that Larry approves (you never see a password). On `"outcome": "repaired"`, continue with `powervpn recovery clear --json`. `run` already retries the intermittent Portal catalog failure (`selection_rejected`) up to 3 times; the recovery JSON names it in `measurement.selectionFailure`, and a failed local check in `measurement.preflightFindings`.

## When to involve Larry

Only when the next step needs his physical presence or a secret: a password, 2FA/SMS code, portal sign-in, Touch ID, or a macOS approval dialog. The same applies when `clear` still fails after 3 attempts. Then send him the `powervpn run:` / `next:` lines and the failing `captureAssessment` fields verbatim, and ask only for that one action. Never request, read, or type a password yourself.

## Patterns

```bash
powervpn run thu21 -- hostname
powervpn run thu21 -- 'cd ~/WORK/haozy/proj && git log -1 --oneline'
# Slurm, uv, conda are only on PATH in a login shell:
powervpn run thu21 -- 'bash -lic "squeue -u \$USER"'
# stdin is forwarded:
git archive HEAD | powervpn run thu21 -- 'mkdir -p ~/WORK/haozy/rel && tar -xf - -C ~/WORK/haozy/rel'
# rsync/scp/plain ssh reuse the session once it is up:
powervpn run thu21 -- true && rsync -a ./out/ thu21:WORK/haozy/out/
```

Leave the session running when you finish; other agents may be using it. Run `powervpn down` only when the user asks to disconnect.
