# CP7A VICI runtime diagnosis

State: **PASS, local runtime only (L5)**. This document does not prove
a privileged backend, an IKE exchange, or server interoperability.

## Locked runtime

The accepted runtime was rebuilt from the locked CP6 strongSwan commit
`67c9810900e2d8486cb3b11495a8362433494ca0`, with a scratch-only compiled PID
directory. The arm64 `charon` binary SHA-256 is
`a2f6813d3c21ed8f907072754051d40afb2630ffc7101dd40576fa0c81fdfc2a`.
The earlier CP6 smoke binary was stock 6.0.7 and is not promoted as the CP7A
runtime.

The CP7A daemon used:

- a fake kernel provider and `initiators = 0`;
- ephemeral UDP ports, never 500 or 4500;
- no credential, endpoint, `initiate`, `install`, SA, policy, route, or utun;
- a mode-700 scratch root and generation-owned mode-600 state/config/log/socket;
- the same daemon PID and VICI socket inode for the official/Swift comparison.

## Last good state and first bad event

The old smoke reached a listening Unix socket and completed client-side
`connect()`. Its first protocol operation, `version`, then received no response
header before timeout. `load-conn` was never sent.

The cause is worker-pool exhaustion, not VICI framing:

1. The old config set `charon.threads = 4`.
2. strongSwan has four long-running CRITICAL jobs in this configuration:
   scheduler, watcher, IKE receiver, and IKE sender.
3. accepting a VICI connection queues another CRITICAL job; processing a
   complete request queues a MEDIUM job.
4. The kernel can complete Unix `connect()` into the listen backlog while no
   worker remains to accept or dispatch it.

Relevant upstream locations are
`scheduler.c:310-334`, `watcher.c:553-563`, `receiver.c:738-740`,
`sender.c:217-219`, `stream_service.c:199-225`, and
`vici_socket.c:552-568` in the locked 6.0.7 source tree.

## One-variable causal result

The locked CP6 binary reproduced the failure with four workers: both the
official 6.0.7 Python client and the Swift client timed out before the first
four-byte response header. The same binary with five workers returned a valid
response to both clients. Each four-worker and five-worker run used one daemon
window and ended with clean teardown.

The `version` exchange agreed exactly:

| Property | Official Python | Swift |
|---|---:|---:|
| Request payload | 9 bytes | 9 bytes |
| Request wire frame | 13 bytes | 13 bytes |
| Request payload SHA-256 | `6f16c46a…4e58bf` | same |
| Response operation | `CMD_RESPONSE` (`1`) | same |
| Response payload | 83 bytes | 83 bytes |
| Response wire frame | 87 bytes | 87 bytes |
| Response payload SHA-256 | `17c18068…bc7ec9` | same |
| Ordered keys | `daemon, version, sysname, release, machine` | same |

The official oracle is the locked source module `vici/protocol.py`, SHA-256
`f86247d58ce36a84a651bc7fcce9b5acd789b185c056e8fc6dc7015bfc07d3a5`.

## Synthetic lifecycle

Both clients then independently completed a bounded lifecycle on the same
five-worker daemon:

```text
version
list-conns baseline
load-conn (RFC 5737 data, start_action=none, no credential)
list-conns (exactly one new synthetic match)
unload-conn
list-conns (synthetic match removed, baseline restored)
```

The fake-kernel load-tester contributes one baseline connection event. The
probe therefore compares the before/after delta instead of assuming an empty
daemon. It does not assign business meaning to that baseline event.

## Safety findings during implementation

- A first runner draft exceeded macOS `sockaddr_un.sun_path`; strongSwan
  truncated the path. Readiness failed closed. The runner now uses a fixed short
  scratch socket and rejects paths over 103 bytes before launch.
- The Codex PTY host terminates detached descendants when an execution cell
  ends even with `nohup`. The acceptance verifier keeps launch, both clients,
  stop, and cleanup in one bounded parent shell. This is host lifecycle, not a
  daemon readiness signal.
- One discarded window observed default-route/DNS drift while no native
  residue remained. It was not promoted. Surge's system extension stayed
  running and `utun8` returned without project mutation. The accepted window
  required two stable preflight snapshots and stable default route, DNS, Surge
  process, and utun set through teardown.
- Global route-table hashes may change because of unrelated cloned/cache
  routes. They are informational; generation-owned routes, synthetic routes,
  default route, DNS, and new utun interfaces are hard gates.

Machine-verifiable, value-free evidence is in
[`vici-runtime-cp7a-summary-v1.json`](../../fixtures/redacted/vici-runtime-cp7a-summary-v1.json).
Raw temporary runtime files remain outside Git and contain no credentials.

## Integrated review closure

Exactly one cumulative review covered the VICI transport, daemon lifecycle,
script safety, secret boundary, and cleanup. No second review ran. Its three
direct findings are closed:

- ordinary and streamed commands both reject a top-level `success=no` without
  retaining or rendering daemon `errmsg` content; streamed commands unregister
  their event before returning the redacted failure;
- failed launches use bounded `INT -> TERM -> KILL`, wait/reap the spawned child,
  and preserve a mode-600 ownership record instead of deleting evidence if the
  child still cannot be stopped;
- stop keeps `current.state` until the generation directory is removed, while
  snapshots and the teardown assertion independently reject an orphan fixed
  VICI socket or any `generation-*` directory.

Targeted negative tests cover daemon rejection, unexpected directory contents,
an orphan Unix socket, an orphan generation directory, and a child that ignores
`INT` and `TERM`. A final bounded unprivileged `start -> version -> stop` smoke
left no state, PID file, socket, or generation directory.

## Reproduction

```bash
scripts/build_strongswan.sh --verify-cp7a-runtime
swift test --filter 'PowerVPNCoreTests.VICI'
scripts/verify/native_charon_runtime_tests.sh
scripts/verify_checkpoint.sh 7a
```

CP7A does not authorize CP7B. The next action is the separate Live Approval
Gate for a serverless privileged backend smoke.
