# Checkpoint 7B privileged-backend preflight

Checkpoint 7B is a serverless macOS backend experiment, not an IKE or
server-interoperability test. It is now **PASS at L5 for the local privileged
backend**. The offline implementation, scratch build, dry validation, and
integrated preflight review passed. The user first authorized a root window
bound to historical manifest
`c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`;
that window ended before daemon launch as `INCONCLUSIVE_PREFLIGHT_FAILURE`.
After route-gate remediation, the user separately authorized the exact window
bound to manifest
`7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`
and its exact command. Attempt 1 reached PF_KEY/PF_ROUTE ready, completed the
bounded read-only VICI probes in 21 seconds, and cleaned up with zero residue.
Both authorizations are consumed and cannot authorize a replay.

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
user-replaceable Homebrew symlink. Historical manifest SHA-256
`c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`
bound the bytes used by the first root window. The remediated candidate became
the accepted CP7B build under manifest SHA-256
`7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`.

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

The finalized offline verifier and negative tests closed this integrated
preflight review. They are not evidence that a privileged backend initialized.

## First manifest-bound root window

The user explicitly authorized the exact root window bound to historical
manifest
`c5464052f21af585a348a3fced8d1b5cf4fa336f8128fd9e64acc10465add877`.
The reviewed runner passed its immediate unprivileged checks and the native
macOS authorization dialog completed. The root worker then attempted its two
preflight snapshots. They did not satisfy the stability gate, so the worker
failed closed before daemon launch.

This result is classified as `INCONCLUSIVE_PREFLIGHT_FAILURE`, not backend
failure or backend PASS. No `charon` process, gated launcher, VICI socket or
response, PF_KEY/PF_ROUTE constructor, UDP descriptor, SA, SPD, route install,
utun, credential, or server packet was observed. Consequently the invocation
does not prove L5.

The retained outer `before` snapshot was taken at window start. The corrected
unprivileged `after` snapshot was necessarily post-hoc, 496 seconds later and
outside the 300-second experiment bound. It differed only in the legacy full
IPv4 route-table count/hash; IPv6, default route, interface and utun inventory,
DNS, global ESP-port hash, PowerVPN/Surge identities, and read-only Surge
environment hash matched. SAD/SPD were unavailable to the unprivileged outer
snapshot. Thus current cleanup is proven for process and owned filesystem
residue, but the post-hoc comparison is not a bounded kernel-teardown proof.
An accidentally malformed zsh-sourced diagnostic snapshot was discarded; it
is not experiment evidence.

The separately reviewed stop command returned `alreadyStopped=true`. Direct
inspection found no native `charon` or gated-launcher process and no state, PID,
VICI socket, attempt ledger, emergency-stop copy, bootstrap bundle, or
generation directory. The runtime parent was UID 502, mode 700, and its top
level contained exactly the reviewed `closure` baseline. This is the current
clean state, subject to the post-hoc kernel-state limitation above.

## Route-gate remediation

Three value-free one-second route samples isolated the instability to transient
macOS routing rows. Nonempty `Expire` values churn, and uppercase `W` denotes
`RTF_WASCLONED`; hashing the complete rendered table therefore made unrelated
cache activity a hard gate. The old full-table count/hash remains diagnostic
only.

The remediated route snapshot has two explicit layers:

1. a strict structural parser accepts well-formed route rows and extracts only
   `family`, `destination`, `gateway`, `flags`, and `netif`;
2. the CP7B persistent compatibility profile rejects an empty persistent set
   and excludes every row with a nonempty `Expire` field or uppercase `W` flag,
   while retaining dynamic/cloning flags `D`, `C`, and `c` when they are not
   transient by those two observed criteria.

Parse, project, sort, count, and hash are separate checked stages backed by
protected temporary files. A command error or malformed/duplicate/missing
default-route interface fails closed instead of being masked by a downstream
pipeline stage. Structural parseability is not acceptance: a structurally valid
table with zero persistent rows is rejected by the CP7B profile/fingerprint
gate.

Daemon-before failures now emit a bounded, value-free result tied to manifest,
source, and config instead of leaving an empty result file. The 300-second
deadline guard terminates and reaps its child sleep when the foreground root
worker returns, avoiding the observed prompt-cleanup delay.

Exactly one additional narrow review followed the first root window. Its scope
was limited to route layout, parser/profile separation, canonicalization,
failure propagation/default-route handling, deadline cleanup, and the first
review's directly affected boundary. It found two P1 fail-open command/stage
paths and one P2 parser/profile conflation; the remediation above closes those
direct findings. No third review or unrelated repository-history review ran.

## Accepted manifest-bound root window

The user explicitly authorized the exact command bound to manifest
`7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`.
One authorization prompt was canceled before the root entry ran; it is an
operational non-attempt and produced no runtime result. Re-running the same
already-authorized command then completed manifest attempt 1 with these
value-free facts:

```text
source commit          a81298234753f314dbf2c4f2867a9a144006bd8c
attempt                 1
duration                21 seconds
backend                 pfkey-pfroute
socket provider         socket-dynamic
failure category        none
result                   success
```

The exact six-plugin profile loaded and the PF_KEY/PF_ROUTE constructors
reached ready. The root-owned official strongSwan 6.0.7 VICI client completed
`version`, read-only `stats`, `list-conns`, `list-sas`, and `list-policies`.
Under the reviewed runner contract, the last three inventories were empty; the
retained result deliberately stores only the version request/response hashes
and overall value-free success/safety fields, not inventory values.

The run had no endpoint or server configuration. Native UDP descriptor count
remained exactly zero; there was no packet send, server traffic, credential
read, `load-*`, `initiate`, terminate, or install operation. Global SAD and SPD,
`net.inet.ipsec.esp_port`, persistent IPv4/IPv6 route projections, default
route, DNS, interface/utun inventory, PowerVPN identity, Surge process identity,
and read-only Surge environment/DNS evidence remained stable across the bounded
window and final comparison. Churn in the legacy complete IPv4 route-table
hash remained diagnostic and did not affect the persistent compatibility gate.

The generation-owned stop removed `charon`, VICI socket, PID, config, protected
log, state, bootstrap, emergency stop, attempt ledger, and generation
directory. `scripts/assert_cp7b_teardown.sh` passed against the retained result.
The runtime parent ended as UID 502:GID 20, mode 700, with exactly the reviewed
`closure` at top level.

This is a **serverless L5 backend PASS**. It proves privileged PF_KEY/PF_ROUTE
initialization, VICI control, no-send behavior, state preservation, and clean
teardown. It is not IKE/server protocol evidence: Main Mode, Quick Mode,
ADDRULE, server acceptance, SA/policy installation, resource routes, and data
path remain untested.

## Preflight and live boundaries

Completed across the two manifest-bound authorization windows:

- create and edit the bounded runner, stop, snapshot, assertion, and test
  artifacts;
- build and verify the dedicated scratch prefix;
- run unprivileged shell negative tests and dry runs;
- perform one integrated preflight review;
- finalize both value-free approval manifests;
- execute one root preflight window under the historical manifest; it failed
  closed before daemon launch;
- remediate only the observed route/deadline boundary and complete the one
  permitted additional narrow review;
- execute manifest
  `7e7f6b8525f39e67ef4e45ad348a216b7eba2bb8638bd8f981dc3294238c8187`
  attempt 1 through serverless backend ready, VICI probes, bounded stop, and
  zero-residue assertion.

Neither consumed CP7B authorization permits any of the following:

- replaying the CP7B root command or reusing its attempt allowance;
- server traffic or an endpoint-bearing configuration;
- VICI `load-*`, `initiate`, terminate, install, or credential operations;
- SA, SPD, route, address, utun, DNS, default-route, PowerVPN, or Surge changes.

CP7B is complete. The next checkpoint, CP8A, is still serverless: it may build
and test a secure in-memory material-provider boundary, but real material may
be read only through an exact path/provider explicitly authorized by the user.
No secret may enter argv, environment, files, fixtures, or logs. CP8B/CP9
server traffic remains a later, separate approval gate.

## Accepted live observations

The accepted attempt satisfied all of the following:

- two stable preflight snapshots agree on SAD, SPD, global ESP port, default
  route, persistent IPv4/IPv6 route projection, DNS, utun inventory, PowerVPN,
  and Surge;
- the loaded plugin set is exactly `openssl nonce kernel-pfkey kernel-pfroute
  socket-dynamic vici`;
- the official VICI client receives `version` and read-only `stats` succeeds;
- `list-conns`, `list-sas`, and `list-policies` are empty;
- the native process owns the recorded PID file and VICI socket;
- its UDP descriptor count is zero;
- SAD, SPD, `net.inet.ipsec.esp_port`, persistent IPv4/IPv6 route projections,
  default route, DNS, utun inventory, PowerVPN, and Surge remain unchanged
  before the VICI probes, after all five probes, and after teardown; legacy
  complete-table hashes are diagnostic only;
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

The earlier preflight-only window remains a useful record that unrelated system
churn can make a protected snapshot unstable. It did not authorize weakening
the persistent profile; the remediated attempt passed the strict gate.

## Current evidence level

This document records L1/L3/L4 source, build, review, and offline-preflight PASS
plus L5 privileged local-runtime PASS for PF_KEY/PF_ROUTE + `socket-dynamic`.
It proves no server-facing protocol behavior. Server acceptance, IKEv1 Main
Mode, Quick Mode/ADDRULE, SA/policy installation, routes, and resource data
path remain entirely untested and must not be inferred from CP7B.
