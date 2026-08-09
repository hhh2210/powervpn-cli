# GUI to helper XPC evidence

Status: producer and helper-consumer schemas are statically recovered; one
legal value-free GUI resource-toggle trace is captured.

Detailed evidence and code locations are in
[`evidence/checkpoint-5-static-correlation.md`](evidence/checkpoint-5-static-correlation.md).

## Confirmed command surfaces

| Helper | Fixed dispatcher order |
| --- | --- |
| charon | `start_connection`, `updown_nc`, `stop_connection`, `get_version` |
| ipsec | `start_connection`, `updown_ipsec`, `get_tun_name`, `stop_connection` |

Every request starts with ordered `type:string`, `rpc:string`. Both dispatchers
allocate an outbound dictionary, scan their fixed four-entry command table,
invoke one handler, and send that dictionary. A handler may separately send its
business result first, as the exact `get_version` path below demonstrates.

## R1 exact charon `get_version` framing

The Rescue R1 static pass resolves the previously value-free `get_version`
envelope. The installed GUI inserts exactly:

```text
type:string = "rpc"
rpc:string  = "get_version"
```

It creates the privileged Mach connection to
`com.leadsec.charon-xpc`. The handler ordinary-sends the full business
dictionary through the connection:

```text
version:string = installed build bytes
get_version:boolean = true
```

For the pinned installed helper, the expected version is build 24572. The
outer dispatcher then ordinary-sends an empty dictionary. Although the GUI
uses `xpc_connection_send_message_with_reply`, its reply callback performs no
business decoding; the full result is consumed by its connection event
handler. A compatible probe must therefore accept only the exact full event
from that handler and must never promote the empty dispatcher tail or an empty
reply acknowledgement to success.

This is a read-only helper-control contract, not the owned product XPC design.
It carries no session, PSK, endpoint, route, resource, or tunnel action.

## Confirmed start schemas

Charon consumes `common:dictionary`, then `tunnels:array<dictionary>`. Its
ordered common fields are:

```text
sessionid, vip?, vipv6?, gateway, ike_port, majorVersion, ike, esp, psk,
ike_life_time, ipsec_life_time
```

Each tunnel is consumed in this order:

```text
authority, status, tunnel-name, family, rflag, name, routes[], mapid,
negotiate-mode?
```

Each route reads `net` then `prfix`.

The ipsec helper consumes `common:array<dictionary>`. Shared fields are read
from `common.lastObject` in this order:

```text
sessionid, vip, vipv6, gateway, ike_port, natt_port
```

Each record then supplies:

```text
tunnel-name, route_addr, ike, esp, psk
```

These are field names and static consumer types only. No value was read.

## Confirmed producer/consumer mismatch

For resource toggles the GUI produces:

```text
type:string, rpc:string, updown:boolean, kDeleteActionKey:string
```

Both helper handlers consume `tunnel-name:string` instead of
`kDeleteActionKey`. The legal runtime trace confirmed entry into the exact
`resource_toggle_nc` producer method and observed the
`kDeleteActionKey:string` argument metadata. The preceding
`type:string`, `rpc:string`, `updown:boolean` order remains inferred from the
static producer at that same method; it was not independently introspected as a
materialized runtime dictionary. Helper consumption is also a static binary
fact. Together these support the producer/consumer mismatch while preserving
the evidence-class boundary.

## Ordered metadata fixture shape

JSON object key order is not wire evidence. Requests, fields, and transitions
therefore use arrays with explicit ordinals:

```json
{
  "sequence": 1,
  "boundary": "xpc",
  "direction": "gui_to_helper",
  "operation": "start_connection",
  "fields": [
    {
      "order": 1,
      "name": "sessionid",
      "type": "string",
      "length": 24,
      "lengthUnit": "bytes",
      "evidenceClass": "synthetic",
      "confidence": "unknown"
    }
  ]
}
```

Shared `start_connection` and `stop_connection` events also carry a closed
`helperFamily` discriminator (`charon` or `ipsec`) so the validator can apply
the correct `common` and reply profiles instead of merging two incompatible
dictionary contracts.

The example length is synthetic, not observed. A commit-safe runtime row may
contain only name, type, length/unit, order, evidence class, and confidence.
Values, raw `xpc_object_t` descriptions, audit tokens, credentials, session
material, PSKs, and stable identifiers are forbidden.

## Legal runtime observation

One user-approved resource cycle was triggered with Computer Use. The switch
was visibly off and then restored on; the GUI method breakpoint hit twice.
Because the first scratch observer collapsed adjacent metadata-identical calls,
the commit-safe runtime fixture retains one representative toggle event. The
scratch deduplicator was then narrowed to suppress only callbacks within 100 ms
and has a regression test; the network action was not repeated merely to refill
the fixture.

After restoration, both fresh SSH banner probes succeeded, a distinct
PowerVPN-associated interface generation again had two resource routes, and
Surge still owned the default route. These checks establish cleanup/restoration
for this observation; they do not turn the legacy CLI's historical log hint
into current tunnel truth.

No live `start_connection`, helper reply, or WebSocket callback was captured in
this bounded window. Their static schemas remain `confirmed static`, while
runtime ordering stays `unknown`.

## Decision rule

This boundary is useful for understanding the oracle, but it is not the target
product API. The target remains a narrow owned app-to-daemon protocol followed
by VICI plus the resource extension. If an arm64 observer is rejected by the
vendor signing requirement, record the rejection and move on; do not implement
a signature bypass or reproduce the vendor XPC surface in the final daemon.
