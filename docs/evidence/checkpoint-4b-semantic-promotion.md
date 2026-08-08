# CP4B semantic-promotion gate

Status: PASS with zero promotions
Evidence date: 2026-08-08
Scope: offline, value-free correlation only

## Decision

The gate was applied to every CP4A field whose business meaning remained
unknown. No field has two independent evidence classes that directly map the
same control/XPC concept to the same wire slot. Consequently the promotion set
is empty and the CP4A codec, patch, synthetic bytes, and neutral field names are
unchanged.

This is a successful negative result, not a blocked checkpoint. It prevents a
strong static candidate from becoming a permanent protocol claim before an
independent runtime or differential observation confirms the same slot.

The machine-readable decision is
[`../../fixtures/redacted/semantic-promotion-gate-v1.json`](../../fixtures/redacted/semantic-promotion-gate-v1.json).

## Evidence-class rule

A rename requires at least two evidence classes that each establish a direct
mapping to the same wire slot. The following do not qualify by themselves:

- similar names, lengths, values, or address-like shapes;
- multiple disassemblies from the same vendor implementation family;
- a synthetic codec vector;
- a runtime action that did not observe the corresponding serializer slot;
- absence of a breakpoint hit.

Static evidence from the PowerVPN GUI and `charon-xpc` is kept in one
`vendor_static_disassembly` class. The CP5 live resource cycle contributes
`runtime_metadata` and `differential_observation`, but neither observation
crossed the `start_connection` or plaintext expandrule serialization boundary.
Their mere existence cannot be combined with static evidence as if they mapped
a wire field.

## Hash-locked static chain

The static data flow was checked against:

- PowerVPN SHA-256
  `069dee7b624ff2d8a3714bfed06aa6444ad45406d102b5933b987b88a39c7a46`,
  UUID `51779BEB-78C6-33C1-8EB0-237E7CD2067D`;
- installed `charon-xpc` SHA-256
  `ce25374f028216374d386c91a7ee8fea8146b4bfd80f5fde6a59954700555404`,
  UUID `D6973685-6A34-30CD-A8A9-94A342B1CA47`.

PowerVPN's `startCharonAction` path takes `nc.lastObject` and sends the same
dictionary through `startNCXPCConnection`. In `charon-xpc`, `_start_connection`
parses the common and tunnel dictionaries, `_tunnel_start_all` feeds
`_add_nc_expandrule`, and Quick Mode `_build_i` calls `_add_expandrule` before
creating private payload type 18. Informational add/delete follows
`_queue_expandrule_notify_by_name/mapid` to `_expandrule_notify_create` and its
builder.

This is a complete static writer chain inside the vendor implementation, so it
is stronger than name similarity. It is still one evidence class.

## Candidate matrix

| CP4A wire slot | Strong static candidate | Direct evidence classes | Missing independent join | Decision |
|---|---|---:|---|---|
| `leadingAddress[V]` | XPC `common.vip` / `common.vipv6` | 1 | no live start/serializer field observation | retain `leadingAddress` |
| `primaryCount` | enabled category-1 `expandrule_info` count | 0 for `routeCount` | count is not `routes.count`; category meaning unknown | reject `routeCount`; retain neutral name |
| `secondaryCount` | enabled category-2 `expandrule_info` count | 0 for `resourceCount` | category meaning unknown | retain neutral name |
| dialect-0 primary record | converted XPC route address/prefix | 1 | no independent slot correlation | retain syntax-only address/mask/prefix names |
| dialect-0 secondary opaque | XPC tunnel `name` bytes | 1 | `name`, resource name, and resource ID are not proven equivalent | retain opaque |
| dialect-1 primary opaque | XPC tunnel `mapid` bytes | 1 | no independent slot correlation | retain opaque |
| dialect-1 secondary opaque | XPC tunnel `mapid` bytes | 1 | no independent slot correlation | retain opaque |
| short server revoke value | unknown match value | 0 | no portal/XPC producer and no live server revoke | retain opaque |

The dialect-0 address and prefix shape remains a confirmed wire-syntax fact.
Calling it a route business object would be a semantic promotion and is not
allowed by the current evidence. Likewise, `tunnel-name` selects records in an
Informational path but is not itself shown entering the recovered body.

## CP5 boundary used by this gate

The legal live CP5 window confirmed a session-check request and a GUI-side
`resource_toggle_nc` producer, then restored the resource and verified the
application probes and Surge default route. It did not hit live
`start_connection`, a helper reply, WebSocket callbacks, or a plaintext
ADDRULE/DELRULE serialization boundary. The runtime fixture therefore supports
action and recovery facts only; it contains no value that could be correlated
to the wire body.

## Reproducible acceptance

Run:

```bash
scripts/verify_checkpoint.sh 4b
```

The verifier pins the CP4A/CP5 commits and the canonical upstream codec commit,
checks that the CP4A patch and seven synthetic byte vectors are byte-identical,
validates the evidence-class decision table, rejects semantic identifiers in
the codec source surface, runs the targeted encode/decode/profile tests, then
runs Swift, arm64, secret, and diff gates.

No installed binary, VPN process, session, route, SA, utun, packet, credential,
or raw log is read or changed by this acceptance command.

## Integrated review closure

Exactly one integrated checkpoint review ran after the cumulative candidate
first passed acceptance. It found two P1 verifier-model gaps:

1. the verifier locked only the slot list, so a candidate could say `promote`
   while the top-level promotion list stayed empty;
2. one broad direct-evidence ID could be reused by a candidate for a different
   slot or semantic.

The final gate now pins the complete eight-candidate tuple, derives and compares
the promoted candidate IDs, and requires every direct-evidence edge to carry
the same `wireSlot` and `candidateSemantic` as its candidate. The static writer
chain is split into five candidate-scoped edges, all in the same evidence class.
Final acceptance passed after these fixes. No additional independent review was
run.

## Next evidence capable of changing the result

A future rename requires both:

1. the existing static XPC-consumer-to-writer data flow for that exact slot;
2. an independent, value-free runtime or differential observation at the
   plaintext serialization boundary that confirms the same position, length,
   count, or category without retaining the value.

Until then CP6 must integrate the neutral CP4A model without reinterpretation.
