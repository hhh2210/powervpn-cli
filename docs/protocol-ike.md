# IKE and data-plane evidence

Status: base protocol and private resource extension identified; the CP4A
wire-syntax codec is implemented as an offline checkpoint candidate. Opaque
field semantics, task integration, and backend equivalence remain unverified.

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

1. At CP5, correlate control-plane/XPC differential observations with the
   still-opaque wire fields; retain any raw evidence only in protected scratch.
2. At CP4B, promote a field name only when two independent evidence classes
   agree.
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
