# Checkpoint 7B privileged-backend preflight

Checkpoint 7B is a serverless macOS backend experiment. It is not an IKE or
server-interoperability test. The user has authorized implementation, scratch
build, dry validation, and integrated preflight review only. Starting a root
daemon still requires a second explicit approval tied to the finalized
manifest hash and exact command.

## Material finding: `socket-default` is unsafe for this window

The initial plan paired PF_KEY/PF_ROUTE with `socket-default` and configured
`charon.port = 0` and `charon.port_nat_t = 0`. Source inspection disproved the
assumption that this was a wire-neutral pair of ephemeral sockets on macOS:

1. `socket-default` binds the normal and NAT-T sockets during construction;
2. a zero port asks the kernel to allocate a port and then stores the result;
3. opening the NAT-T socket calls the selected kernel provider's
   `enable_udp_decap()` callback;
4. the macOS PF_KEY callback writes the process's NAT-T port to the global
   `net.inet.ipsec.esp_port` sysctl;
5. neither `socket-default` nor `kernel-pfkey` restores the previous value on
   destroy.

The relevant upstream 6.0.7 paths are:

```text
src/libcharon/plugins/socket_default/socket_default_socket.c
  open_socket()              bind port 0 and recover the allocated port
  open_socketpair()          create normal and NAT-T sockets immediately
  socket_default_socket_create()
                              initialize both socket families

src/libcharon/plugins/kernel_pfkey/kernel_pfkey_ipsec.c
  enable_udp_decap()         sysctlbyname("net.inet.ipsec.esp_port", ...)
```

Changing `port_nat_t` to another high value would still write the global
sysctl. Because PowerVPN is intentionally kept running, snapshot-and-restore is
not an acceptable first-window mitigation: the transient value could affect the
vendor tunnel before rollback. The CP7B compatibility build therefore MUST NOT
load `socket-default`.

## Revised serverless socket boundary

The preflight candidate uses `socket-dynamic`. Its constructor creates only a
notification pipe, lock, and empty socket table. Its receiver blocks on the
notification pipe. The only path that creates a UDP socket is the packet-send
path:

```text
sender -> find_socket -> open_socket -> bind/bypass_socket/enable_udp_decap
```

CP7B loads no connection or credential and never calls `initiate`, so that path
must remain unreachable. The config retains `port = 0` and `port_nat_t = 0` as
defensive neutral values, but with `socket-dynamic` they do not create startup
sockets. The required runtime observation is exactly zero UDP descriptors. Any
UDP descriptor, `sending packet:` log event, or change to
`net.inet.ipsec.esp_port` fails the window.

This is bounded to the serverless backend smoke. It does not establish that
`socket-dynamic` is the final socket provider for live PowerVPN interop.

## Pinned candidate build

The candidate is isolated from CP7A and from system prefixes:

```text
source      ~/scratch-data/powervpn-strongswan/strongswan-6.0.7-cp7b
build       ~/scratch-data/powervpn-strongswan/build-6.0.7-cp7b-arm64
prefix      ~/scratch-data/powervpn-strongswan/runtime-6.0.7-cp7b/closure
piddir      ~/scratch-data/powervpn-strongswan/runtime-6.0.7-cp7b
```

The source parent remains the locked CP6 commit
`67c9810900e2d8486cb3b11495a8362433494ca0`. A build-only follow-up commit
`a81298234753f314dbf2c4f2867a9a144006bd8c` defines
`__APPLE_USE_RFC_3542` so `socket-dynamic` uses the current macOS RFC 3542
packet-info declarations. Patch 0003 has SHA-256
`3c7615e5bf2ec284f04177e903b88fb3b452f1ce9d1f39968fd89c40ea6771c4`.
It changes no IKE, expandrule, serializer, HASH, task, or server-visible path.

The scratch build has arm64 `charon`, `swanctl`, `kernel-pfkey`,
`kernel-pfroute`, `socket-dynamic`, and VICI artifacts. Their hashes are pinned
in `fixtures/redacted/cp7b-approval-manifest-v1.json`. The root-executed
dependency chain is pinned separately: `libcharon`, `libstrongswan`, the
OpenSSL and nonce plugins, a copied `libcrypto`, and the gated launcher. The
OpenSSL plugin resolves that copied library inside the closure rather than a
user-replaceable Homebrew symlink. Manifest SHA-256
`c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`
binds the finalized bytes.

The AppleScript boundary copies the hash-bound root entry to a mode-700,
root-owned bootstrap directory after transferring the dedicated runtime parent
to root. The entry first copies and verifies the closure helper, then recursively
takes ownership of every closure directory, regular file, and four reviewed
relative dylib aliases. It revalidates the complete tree before any executable
or plugin can be opened. It then copies the worker, remaining shell libraries,
official Python VICI package, and read-only probe into the same bundle, verifies
the copied bytes, and only then executes the worker. The bundle is removed by
an exact-file allowlist after the window. Python bytecode writes are disabled,
so an unreviewed `__pycache__` cannot survive cleanup.

## Exact runtime profile

The candidate renders this minimal profile:

```text
charon {
    load_modular = no
    load = openssl! nonce! kernel-pfkey! kernel-pfroute! socket-dynamic! vici!
    threads = 5
    port = 0
    port_nat_t = 0
    install_routes = no
    install_virtual_ip = no
    interfaces_use = lo0
    initiator_only = yes
    plugins {
        vici {
            socket = unix://<scratch-cp7b-piddir>/charon.vici
        }
    }
}
```

The `!` suffixes make each plugin critical. A failed PF_KEY socket/register,
PF_ROUTE constructor, socket provider, or VICI constructor must abort daemon
initialization instead of leaving a VICI-ready process with an unproven
backend. `initiator_only` rejects inbound initiation but is not treated as a
local-initiation guard; the root worker separately allowlists only read-only
VICI operations.

`kernel-pfkey` still opens two raw PF_KEY sockets and performs ephemeral
`SADB_REGISTER` operations for ESP and AH. `kernel-pfroute` opens a routing
socket and registers a watcher. Their constructors do not add or flush SAs,
policies, routes, or virtual IPs. Global SAD/SPD hashes nevertheless remain
hard before/during/after gates because constructor success alone does not prove
absence of a side effect on this macOS build.

## Integrated preflight result

Exactly one integrated review first returned NO-GO with two P1 and five P2
findings. The cumulative candidate closes them as follows:

- a root-owned parent and fully revalidated execution closure eliminate the
  hash-check-to-`exec`/`dlopen` replacement window;
- a gated launcher writes its PID handshake, commits an atomic `starting`
  state, then releases one byte and `execv()`s `charon` with the same PID;
- emergency stop recognizes only the exact launcher/target argv and stable
  process identity in each phase; an injected-TERM scratch test leaves no
  process, gate, handshake, state, or generation residue;
- the 300-second guard starts before the first privileged snapshot;
- `--debug-net 2`, successful full `lsof` capture, and one exact six-plugin log
  line make the no-send checks fail closed;
- PowerVPN and each Surge process group are compared by count plus a value-free
  digest of PID, start time, and canonical command;
- retained evidence binds the approval manifest, source commit, and config
  hash.

Final dry validation also caught a POSIX-shell namespace collision: a sourced
helper overwrote the wrapper's generic `mode` variable, so a nominal dry run
reached an AppleScript authorization wait. The waiting process was terminated
before approval; no root entry, daemon, state, PID, socket, ledger, or ownership
change occurred. The wrappers now use a readonly `operation_mode`, and both
manifest-bound dry runs exit before `osascript`.

No second independent review ran. The finalized offline verifier and negative
tests are the direct-finding validation, not evidence that a privileged backend
has initialized.

## Preflight and live boundaries

Authorized now:

- create and edit the bounded runner, stop, snapshot, assertion, and test
  artifacts;
- build and verify the dedicated scratch prefix;
- run unprivileged shell negative tests and dry runs;
- perform one integrated preflight review;
- finalize a value-free approval manifest.

Not authorized now:

- AppleScript privilege elevation or Touch ID prompt;
- root `charon` or raw PF_KEY/PF_ROUTE runtime access;
- UDP socket creation or server traffic;
- VICI `load-*`, `initiate`, terminate, install, or credential operations;
- SA, SPD, route, address, utun, DNS, default-route, PowerVPN, or Surge changes.

The preflight is now PASS. The second approval request must name the exact
command and finalized manifest SHA-256. The manifest authorizes at most two launches
and 300 seconds total, with no automatic second launch. It does not authorize a
kernel-libipsec fallback or any CP8/CP9 server traffic.

## Required live observations

If the second approval is granted, one generation may PASS only when all of the
following are true:

- two stable preflight snapshots agree on SAD, SPD, global ESP port, default
  route, DNS, utun inventory, PowerVPN, and Surge;
- the loaded plugin set is exactly `openssl nonce kernel-pfkey kernel-pfroute
  socket-dynamic vici`;
- the official VICI client receives `version` and read-only `stats` succeeds;
- `list-conns`, `list-sas`, and `list-policies` are empty;
- the native process owns the recorded PID file and VICI socket;
- its UDP descriptor count is zero;
- SAD, SPD, `net.inet.ipsec.esp_port`, complete IPv4/IPv6 route hashes,
  default route, DNS, utun inventory, PowerVPN, and Surge remain unchanged
  before the VICI probes, after all five probes, and after teardown;
- bounded stop removes the process, socket, PID, config, log, emergency-stop
  copy, state, and generation directory;
- only value-free result JSON survives outside the root runtime directory.

The five VICI operations run through the reviewed official 6.0.7 Python
client inside the root-owned bundle. The root path does not execute `swanctl`;
the retained inventory contains only zero/nonzero counts and wire hashes, not
connection, SA, policy, address, or identity values.

The runtime root remains root-owned while a launch attempt or protected retry
ledger exists. It is returned to the desktop user only after the top level is
exactly the reviewed `closure` baseline; the closure is recursively returned to
UID 502 before the parent. Incomplete cleanup retains root ownership and fails
closed.

An existing PowerVPN rekey or unrelated system churn may make a global hash
unstable. That is a fail-closed inconclusive window, not proof that the native
daemon caused the change and not permission to weaken the gate.

## Current evidence level

This document records a PASS for L1/L3/L4 source, build, review, and
dry-preflight evidence. No privileged backend constructor has run, so CP7B has
not reached L5 and is **WAITING FOR LIVE APPROVAL**. Server acceptance remains
entirely untested.
