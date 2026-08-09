# Rescue R1 read-only direct XPC gate

Status: **PASS**. The cumulative candidate completed its one integrated review,
closed every direct finding, and passed the bounded live acceptance gate.

## Scope

R1 asks exactly one question: can the arm64 CLI exchange the vendor's read-only
`get_version` message directly with the installed x86_64 charon helper while
the GUI and all tunnel state are absent?

R1 does not authenticate, discover a gateway, contact the portal or VPN server,
send a tunnel snapshot, initialize strongSwan, create an SA, change a route, or
create an utun. Username and password are not inputs to this checkpoint.

## Locked vendor contract

Static analysis of the installed PowerVPN 3.2.1 build 24572 producer and the
byte-identical installed/bundled charon helper establishes:

- privileged Mach service `com.leadsec.charon-xpc`;
- an exact two-string request, inserted as `type=rpc` then
  `rpc=get_version`;
- a full business event containing exactly `version:string` and
  `get_version:boolean`;
- locked success bytes equal to ASCII build `24572` and boolean `true`.

The framing is nonstandard. The GUI calls
`xpc_connection_send_message_with_reply`, but the helper ordinary-sends the
full business dictionary to the connection event handler. The outer dispatcher
then ordinary-sends an empty dictionary, while the GUI's nominal reply callback
does no business parsing. An empty dictionary therefore cannot prove success.

Evidence locations:

- GUI `-[VSGXPCConnection getCharonProcessVersion:]` at
  `0x1001cf050..0x1001cf26e`;
- helper `_get_version` at `0x1001abc40..0x1001abcff`;
- helper `_handle` at `0x1001ac1d0..0x1001ac3d9`;
- helper command table at `0x1003721b0`.

The helper's accept/dispatch path imports no audit-token, code-signing,
`SecTask`, `SecRequirement`, or `csops` checks. That makes the experiment
eligible; it does not prove that launchd or the OS will accept the caller.

## Implementation boundary

`RawVendorXPCTransport` owns the classic C XPC boundary and a one-shot terminal
gate. It accepts business data only from the connection event handler, validates
the closed shape and raw version bytes, and synchronously passes the peer PID to
a generation validator while that helper is still alive. Only the resulting
boolean is retained; the PID is neither serialized nor written to evidence.
Once a business event is classified, it is terminal. A 200 ms observation hold
may record the empty dispatcher tail and process descriptors, but a late helper
exit, interruption, invalidation, error, or timeout cannot overwrite the
business result. The transport cancels exactly once and never converts or
serializes the raw dictionary or version string.

`VendorXPCProbe` requires a cold preflight, observes the helper generation
before and after the transaction, and emits a value-free report. The thin CLI
surface is closed to:

```text
powervpn xpc get-version [--timeout-ms N] [--json]
```

There is no service, RPC, payload, retry, start, stop, gateway, credential, or
resource argument.

## Cold-start and cleanup gates

Static analysis also found two local startup hazards. The live harness must
abort unless `lstat(/tmp/vpntmp.log)` returns `ENOENT`, because its presence can
activate legacy DNS recovery, and unless `/var/log/vsgvpn.log` is absent or a
regular file no larger than `0x1e00000`, because a larger log can be deleted on
startup. Log contents are never read.

The GUI, charon helper, ipsec helper, and shell helper processes must all be
absent before the call. Installed app, helper, bundled helper, signature,
architecture, LaunchDaemon schema, and hashes are pinned. Value-free
before/after snapshots cover persistent routes, default route, DNS,
interfaces/utun, Surge, PowerVPN, and ESP-port metadata. A bounded
poller records only whether the helper was seen and its maximum TCP/UDP
descriptor count. The harness never kills the helper; R1 requires bounded
natural exit and unchanged local state.

Unprivileged macOS does not expose the global SAD/SPD through `setkey`. The live
artifact must state this as unavailable and must not claim direct SAD/SPD
equality. The independent static call-graph boundary—`get_version` does not
enter `_start_connection` or strongSwan initialization—remains a separate
evidence class.

## Offline verification

The cumulative candidate passes:

- 33 focused tests across request/reply shape, both XPC error channels,
  timeout/late-event fencing, terminal business-event arbitration,
  cancel-once, reply-time generation binding, and cold preflight;
- arm64 Swift build;
- strict Swift formatting;
- manifest-bound harness tests, active-monitor signal cleanup, and closed CLI
  rejection before transport construction;
- secret/raw-XPC/static-mutation scans and `git diff --check`.

No offline test launches the vendor helper. The checkpoint verifier binds the
launchd run counter before and after its tests so an accidental live XPC call
fails the gate.

## Acceptance boundary

R1 became PASS only after the final reviewed candidate received the exact
business event, bound it to the launched helper generation, observed zero
helper TCP/UDP descriptors, saw the helper exit naturally, preserved the
network/process/artifact baseline, and retained only value-free evidence.

`connection_invalid`, `connection_interrupted`, or timeout alone does not prove
a caller-signing restriction. Only the explicit peer-code-signing error or
independent OS evidence can establish the Rescue NO-GO condition.

## Integrated review and live evidence

Exactly one integrated R1 review ran. It initially returned BLOCKED with seven
direct findings: fail-open launchd parsing, an unbound exited generation,
overstated cancel cleanup, missing reviewed-candidate binding, an untested
active-monitor signal path, non-closed lstat/log/result evidence, and missing
dynamic CLI rejection tests. The cumulative candidate fixes all seven. No
second R1 review or unrelated-history review ran.

Three minimal, information-gaining experiments were retained:

1. Attempt 1 received the genuine exact business event, but the helper exited
   before after-the-fact PID and descriptor instrumentation could bind it. It
   did not pass. Its missing-result harness bug was subsequently fixed.
2. Attempt 2 proved a single launchd run and stable local state, but exposed an
   implementation error: a late `connection_interrupted` during the observation
   hold overwrote the already delivered business decision. It also exposed two
   evidence-classification bugs (`null` optional length and zero-match `lsof`).
   It did not pass and was not retried automatically.
3. Attempt 3 was enabled only by exact value-free predecessor gates for attempts
   1 and 2. It received `version="24572"`, `get_version=true`, validated the
   peer against the live single launchd generation, observed zero TCP/UDP
   descriptors, and saw the helper disappear naturally without a harness kill.
   Persistent routes, default route, DNS, interfaces/utun, Surge, PowerVPN, and
   ESP-port metadata stayed stable.

The accepted result is byte-for-byte preserved as
`fixtures/redacted/r1-xpc-runtime-v1.json` and is bound to reviewed-candidate
manifest SHA-256
`472526cb210aff500e8b744b85d82364f0192498a3e1beb2e55ef6400e5fd044`.
`connectionCancelRequested=true` proves only that cancellation was requested;
cleanup is independently evidenced by bounded natural process absence and the
stable final snapshots. Vendor-log contents were never read. Global SAD/SPD
remained `unavailable_unprivileged`, so the artifact explicitly sets
`claimedStable=false`.
