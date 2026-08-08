# IKE and data-plane evidence

Status: base protocol and private resource extension identified; the CP4A
wire-syntax codec and CP4B semantic gate are complete. No business-semantic
field promotion passed the two-evidence-class gate. Task integration and
backend equivalence remain unverified.

## Vendor baseline

- strongSwan base: 5.8.0, proven by Mach-O OSO/SO source and archive paths.
- IKE: IKEv1 Main Mode with PSK evidence.
- Negotiated IKE proposal:
  `AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024`.
- Negotiated ESP proposal:
  `AES_CBC_128/HMAC_SHA1_96/NO_EXT_SEQ`.
- A conventional base IKE_SA and CHILD_SA are established before resource
  activation.

These algorithms describe compatibility, not a security recommendation. The
server is unchanged, so the first interop test must reproduce the observed
proposal exactly and may not silently strengthen it.

## `leadsecbridge` classification

Classification is B + C, confirmed:

- B: `leadsecbridge` is a critical strongSwan plugin providing a custom
  `CUSTOM:kernel-ipsec` feature. Static symbols cover custom utun/network and
  resource policy handling.
- C: successful sessions generate encrypted IKEv1 QUICK_MODE requests with a
  `HASH ADDRULE` payload. The binary contains ADDRULE/DELRULE names, an
  `expandrule` payload codec, verification/encoding code, and Quick Mode task
  integration.

It is therefore incorrect to model `login21`/`login52` as ordinary VICI child
configs alone. Upstream strongSwan can own the standard IKE/ESP machinery, but
resource activation needs a maintained payload/task extension.

## CP4A wire-syntax result

Static serializer/parser evidence is sufficient to implement the private body
without guessing from encrypted packets. The strict contract and seven
synthetic vectors are recorded in
[`evidence/expandrule-wire-contract.md`](evidence/expandrule-wire-contract.md)
and `fixtures/redacted/expandrule-synthetic-v1.json`.

The codec uses five explicit contexts: Quick Mode ADD snapshot, Informational
ADD delta, Informational DELETE delta, server type-19 short revoke, and a
receive-only type-17 compatibility revoke. Type 19 is direction-dependent and
the current type is carried by the predecessor's `Next Payload`, so type,
direction, exchange, body shape, dialect, and family may not be inferred from
the custom payload bytes alone.

CP4A intentionally calls the two encodings dialect 0/1 and keeps their
length-delimited fields opaque. Names such as map ID, resource ID, or resource
name require CP5 correlation and the CP4B two-evidence promotion gate.

## CP4B semantic-promotion result

The hash-locked vendor writer chain strongly correlates `leadingAddress` with
the XPC VIP fields, dialect-0 records with converted route/name inputs, and
dialect-1 opaque records with the XPC map-ID input. That complete chain is
still one `vendor_static_disassembly` evidence class. CP5 did not observe live
`start_connection` or a plaintext serialization slot, so its runtime resource
toggle and recovery observations do not directly map any body field.

The promotion set is therefore empty. Counts retain positional category names;
dialect-0 address/mask/prefix names remain syntax-only; every length-delimited
identity value and the short server revoke value remain opaque. The exact
matrix and machine gate are recorded in
[`evidence/checkpoint-4b-semantic-promotion.md`](evidence/checkpoint-4b-semantic-promotion.md)
and `fixtures/redacted/semantic-promotion-gate-v1.json`. CP6 must integrate
this neutral model and may not introduce semantic aliases as a shortcut.

## macOS backend evidence

The vendor helper contains custom kernel-ipsec, PF_ROUTE, utun, and
kernel-libipsec-related code. Its exact active ESP processing path is not yet
fully attributed.

The upstream 6.0.7 arm64 build produced all three candidate plugins:

- `kernel-pfkey`;
- `kernel-pfroute`;
- `kernel-libipsec`.

In an unprivileged, random-port startup smoke test, PF_ROUTE and VICI loaded.
PF_KEY and kernel-libipsec each stopped at the expected `CAP_NET_ADMIN` gate.
This proves build/ABI viability but not SA installation or server interop.

## Remaining checkpoint sequence

1. CP5 correlated the legal value-free control/XPC observations; no raw value
   entered Git.
2. CP4B applied the two-independent-class gate and made zero promotions.
3. At CP6, add the minimal payload/message/task/VICI skeleton and keep it dry;
   CP4A itself does not touch message factories or IKE tasks.
4. In an approved CP7/CP8 window, use 6.0.7 to establish the standard base SA
   with PF_KEY; repeat with kernel-libipsec only if needed.
5. Add the minimum resource extension and prove exactly one desired `/32` route
   plus an SSH banner.
6. Prove teardown removes the rule, route, SA, and owned utun state without
   disturbing Surge.

No step may use production writes beyond the authenticated VPN actions the user
would normally perform, and no capture may enter Git.
