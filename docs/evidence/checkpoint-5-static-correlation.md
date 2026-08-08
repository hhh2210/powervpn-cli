# Checkpoint 5 static correlation evidence

Date: 2026-08-08

State: static and legal runtime evidence complete; checkpoint review pending.

This report contains field names, static types, ordering, and code locations
only. No log body, credential, session value, PSK, cookie, identity, endpoint
address, Keychain item, packet, or runtime XPC object was read. Static code can
establish producer/consumer contracts, but it cannot establish a successful
legal login, HTTP status, live field length, or WebSocket message sequence.

## Control-plane request producers

All rows below are confirmed from the PowerVPN 3.2.1 build 24572 x86_64 Mach-O
at `/Applications/PowerVPN.app/Contents/MacOS/PowerVPN`. `unknown` means the
dynamic Objective-C class or value length cannot be established from the
producer alone.

| Operation | Method/path | Ordered request fields | Field type status | Evidence |
| --- | --- | --- | --- | --- |
| Password auth | `POST /vpn/user/auth/password` | `type`, `mac`, `verifycode`, `username`, `password` | objects; string-like is inferred, exact classes unknown | `-[VSGPassWorldAuth startPwdAuthAction:]`, `0x1000326c0..0x100033250` |
| Token auth | `POST /vpn/user/auth/token` | `token` | unknown | `-[VSGTockenAuth startAuthWithResourceType:params:]`, `0x1000156b0..0x1000158a0` |
| Anonymous auth | `POST /vpn/user/auth/anonymity` | none proven | unknown | `0x100038e70..0x100038fa0` |
| Resource catalog | `GET /vpn/user/portal/intergration.xml` | `version` | string | `-[VSGAuthManager requestReaource:]`, `0x1000a7e80..0x1000a8040` |
| Session check | `GET /vpn/user/check/session` | `key` | string | `-[VSGAuthManager checkSessionAction]`, `0x1000ae4d0..0x1000ae650` |
| Logout | `POST /vpn/user/logout` | none proven | unknown | `0x1000a6810..0x1000a6a80` |

Static code does not prove response status. The legal runtime observation below
confirmed HTTP 200 for session check; other response statuses remain unknown.

## Response and resource parser order

Session-check traversal is confirmed as:

```text
RESPONSE -> RESULT -> code -> hostid -> kCheckSessionNotice
```

`code` receives `intValue`; its raw XML class is therefore only known to be
number/string-convertible. Evidence: the session reply block at
`0x1000ae650..0x1000aeba0`.

Resource-response traversal is confirmed as:

```text
RESPONSE -> RESULT -> code -> TCPUDP_RESOURCE -> INTERGRATION_INFO
-> RESOURCE_LIST -> REMOTE_RESOURCE -> NC_RESOURCE -> WEB_RESOURCE
-> WEBVPN_RESOURCE -> IPSEC_RESOURCE -> VERSION -> SESSION -> USER
-> DNS_INFO -> PRIVATE-IP -> HOST_LIST/HOST_ITEM
```

Nested names observed by the parser, in parser order, are:

| Parent | Ordered field names | Type confidence |
| --- | --- | --- |
| `VERSION` | `major`, `minor` | unknown without a live XML specimen |
| `SESSION` | `collect_machineinfo`, `login-addr`, `login-time`, `sid_name` | unknown |
| `USER` | `client_jump_pskey`, `jump-mapid`, `modify_flag` | unknown |
| `DNS_INFO` | `DOMAIN_HOST`, `dnssrv`, `dns`, `dnssrv_v6`, `dnsv6` | unknown |
| `PRIVATE-IP` | `addr`, `vip` | unknown |
| `HOST_LIST/HOST_ITEM` | converted to `hostItem` | exact source collection class unknown |

Evidence: the resource reply block at `0x1000a8040..0x1000ab1e0`. Existence and
read order are confirmed; scalar/array runtime classes and lengths are not.

## Portal object to helper ordering

The same auth-result parameter object is stored by
`-[VSGMainWIndowController setParams:]` and passed to
`-[VSGResourceManager parseSorce:]` (`0x10008ec10..0x10008ec80`). The success
block then sets the connection object's online flag and calls
`startAllXPCCPnnections:` with that captured object (`0x100113310..0x1001133b0`).

One second later, `startCharonAction:delay:` consumes top-level arrays in this
confirmed order:

```text
cs -> nc -> ipsec
```

It sends `nc.lastObject` to helper type 0, then each `ipsec` element to helper
type 1 (`0x1001cb510..0x1001cba30`). This proves object lineage and dispatch
order. It does not yet prove which raw portal response field produced every
helper field, or that a particular runtime session successfully traversed the
path.

## Charon helper consumer schema

Binary:
`/Library/PrivilegedHelperTools/com.leadsec.charon-xpc`, `_start_connection`
at `0x1001aa580..0x1001ab260`.

```text
root
  1 type: string
  2 rpc: string
  3 common: dictionary
  4 tunnels: array<dictionary>

common
  1 sessionid: string
  2 vip: optional string
  3 vipv6: optional string
  4 gateway: string
  5 ike_port: number -> int
  6 majorVersion: number -> int
  7 ike: string
  8 esp: string
  9 psk: string
 10 ike_life_time: number -> int
 11 ipsec_life_time: number -> int

tunnels[]
  1 authority: number -> int
  2 status: number -> int
  3 tunnel-name: string
  4 family: number -> int
  5 rflag: number -> int
  6 name: string
  7 routes: array<dictionary>
      1 net: string
      2 prfix: number or string-format-compatible
  8 mapid: string
  9 negotiate-mode: optional number -> int
```

A later status path also reads `common.hostItem`; its exact class remains
unknown.

## IPsec helper consumer schema

Binary:
`/Library/PrivilegedHelperTools/com.leadsec.ipsec-xpc`, `_start_connection`
at `0x10019d650..0x10019dde0`.

```text
root
  1 type: string
  2 rpc: string
  3 common: array<dictionary>

common.lastObject
  1 sessionid: string
  2 vip: string
  3 vipv6: string
  4 gateway: string
  5 ike_port: number -> int
  6 natt_port: number -> int

common[] records
  1 tunnel-name: string
  2 route_addr: string
  3 ike: string
  4 esp: string
  5 psk: string
```

The `psk` rows above describe a field name and static consumer type only. No
credential value was read or retained.

## XPC envelope, command order, and replies

Both helper dispatchers require `type:string`, then `rpc:string`, create an
empty reply dictionary, scan a fixed four-entry table, invoke one handler, and
reply.

| Helper | Fixed command-table order |
| --- | --- |
| charon | `start_connection`, `updown_nc`, `stop_connection`, `get_version` |
| ipsec | `start_connection`, `updown_ipsec`, `get_tun_name`, `stop_connection` |

Additional confirmed shapes:

| Operation | Request fields in order | Reply fields in order |
| --- | --- | --- |
| stop | `type:string`, `rpc:string`, optional `tunnel-name:string` | ipsec: `stop_connection_success:boolean`; charon: empty |
| NC toggle, GUI producer | `type:string`, `rpc:string`, `updown:boolean`, `kDeleteActionKey:string` | `updown_nc_success:boolean` |
| IPsec toggle, GUI producer | `type:string`, `rpc:string`, `updown:boolean`, `kDeleteActionKey:string` | empty |
| get tunnel name | `type:string`, `rpc:string`, `get:string`, optional `tunnel-name:string` | `name:string`, `get_tun_name_success:boolean` |
| get version | `type:string`, `rpc:string` | `version:string`, `get_version:boolean` |

The helper consumers for both toggle commands read `tunnel-name:string`, while
the GUI producer sends `kDeleteActionKey:string`. This is a confirmed static
producer/consumer key mismatch. It is not proof of a successful or failed live
toggle. The `name` reply is a compile-time constant and must not be treated as
runtime interface ownership evidence.

## WebSocket boundary

The app contains `webSocketDidOpen`, `didReceiveMessage`, `didFailWithError`,
and `didClose...` callbacks at `0x1001cf380..0x1001cf5b0`. They log and return;
they do not transition session state, restart a helper, or parse a message.

The following remain unknown:

- endpoint and subprotocol;
- runtime message type and order;
- keepalive behavior;
- resume behavior;
- whether the observed callbacks belong to the portal control channel or a
  local component.

A bare `keepalive` string in bundled generic VPN/crypto code is not evidence of
a portal heartbeat.

## Safe runtime gate

The value-free schema contract is
[`../../fixtures/redacted/protocol-correlation-value-free-v1.json`](../../fixtures/redacted/protocol-correlation-value-free-v1.json).
It is synthetic and carries `confidence: unknown`; it is not runtime evidence.
The validator rejects unknown value-bearing slots and never echoes rejected
content.

The runtime microscope is kept outside Git under a mode-700 scratch directory.
An initial Frida 17 observer passed an arm64 self-process load test but failed
the x86_64/Rosetta boundary in two independent controller architectures; it was
retired before attaching to PowerVPN. The replacement x86_64 LLDB observer was
tested only against a generated, ad-hoc-signed scratch process with
`get-task-allow`:

- the debugger installed two resolved value-free breakpoints;
- three identical callbacks reduced to one bounded metadata event;
- synthetic source strings and data bytes did not appear in the output;
- the parent directory was mode 700 and output was mode 600;
- `powervpn oracle correlate ... --json` returned `valid: true`;
- output contained only ordered field name/type/length metadata and the two
  non-secret flags remained false.

PowerVPN itself has `get-task-allow` and can be attached by x86_64 LLDB without
patching or re-signing the installed app. That fact proves the observation
mechanism, not a legal login or protocol event.

## Legal runtime observation

The user manually authenticated in PowerVPN; Codex never received or entered a
credential. An x86_64 LLDB observer was attached without modifying or
re-signing the installed app. Its offset-based HTTP completion hook was locked
to PowerVPN 3.2.1 build 24572 by the exact executable SHA-256 and refused a
different binary in a negative smoke test.

The mode-600 scratch output recorded only value-free metadata. Repeated pairs
confirmed:

```text
GET /vpn/user/check/session
  request: key:string (length/unit metadata only)
  response: HTTP 200
```

A user-approved Computer Use resource cycle confirmed entry into the exact
GUI-side `resource_toggle_nc` method and observed the final string argument's
type/length metadata. Static disassembly at that same method supplies the full
inferred producer order:

```text
type:string -> rpc:string -> updown:boolean -> kDeleteActionKey:string
```

Accordingly, the runtime fixture marks the event and final argument confirmed,
while the first three field entries remain inferred. It does not claim a
runtime-inspected dictionary that never existed at the breakpoint.

The resource-toggle method breakpoint hit twice for the off/on cycle. The first
scratch capture implementation deduplicated adjacent metadata-identical events,
so the derived Git fixture intentionally carries one representative event and
does not invent an `updown` value. The scratch observer was fixed to deduplicate
only callbacks within 100 ms and its seven sanitizer/dedup tests pass. The live
network action was not repeated just to improve fixture aesthetics.

Four WebSocket breakpoints, `setParams:`, and `startNCXPCConnection:xpcType:`
had zero hits in the bounded window. This is recorded as `not observed`; it does
not override the static schema or prove that these paths are absent.

The first observation window reached a visible session-timeout error before the
resource action. Dismissing it stopped both the GUI and helper. A fresh manual
login then produced successful session checks and the approved resource cycle.
This is evidence that control-session state, displayed resource state, and
helper/tunnel state are independent axes.

After the cycle, both resource switches were visibly on, both fresh SSH banner
probes succeeded, the PowerVPN-associated interface again carried two resource
routes, and Surge remained running and retained the default route. The LLDB
observer was detached cleanly while the second legal session remained running.

Commit-safe evidence:

- [`../../fixtures/redacted/protocol-correlation-runtime-metadata-v1.json`](../../fixtures/redacted/protocol-correlation-runtime-metadata-v1.json)
- `scripts/verify_checkpoint.sh 5`

No header, cookie, raw body, endpoint, identity, audit token, session value,
PSK, password, resource value, packet, TLS key, or raw XPC description was read
or retained. The full scratch metadata document remains under the mode-700
capture root and is not tracked by Git.

## Integrated review closure

The single checkpoint review initially returned NOT PASS despite the first
verifier run succeeding. All direct findings were fixed before acceptance:

- known HTTP requests and XPC calls/replies now use closed name/type/order
  profiles;
- shared start/stop operations require a `charon` or `ipsec` helper family;
- known paths are exact allowlist entries, while unknown paths/fields accept
  placeholders only;
- synthetic evidence cannot claim confirmed confidence, and runtime inferred
  versus confirmed facts match the documents;
- the checkpoint verifier is pinned to the CP4A base and covers cumulative
  staged, unstaged, and post-commit changes;
- README safety wording now reflects the approved and verified off/on window.

Negative tests cover missing, extra, wrong-name, wrong-type, wrong-order,
wrong-family, literal-identity, source mismatch, confidence mismatch, and
oversized-file cases without echoing rejected input. Final
`scripts/verify_checkpoint.sh 5` completed with 41 tests and no leak or diff
finding. No second review ran.
