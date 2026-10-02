---
name: powervpn
description: Run commands on Larry's THU servers (thu21 login node, thu52) that are reachable only through PowerVPN. Use whenever a task needs to execute anything on thu21/thu52, copy files to or from them, or hits a failing `ssh thu21`. One command does it all — `powervpn run <target> -- '<cmd>'` — so never read PowerVPN source, README, or help output.
---

`powervpn run thu21 -- '<cmd>'` — this is the only PowerVPN command you need. Do not read the powervpn source, README, `--help`, or `debug` output, and do not call `up`, `down`, `status`, `doctor`, or `recovery` yourself.

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
| 77 | needs a human | stop; report the `powervpn run: <token>` and `next: <action>` lines to the user verbatim |
| 64 | your command line is malformed | fix it: `run <target> -- <command>` |

A PowerVPN-side failure always ends stderr with `powervpn run: <token>` then `next: <action>`. If those lines are absent, a 75 or 77 came from the remote command itself.

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
