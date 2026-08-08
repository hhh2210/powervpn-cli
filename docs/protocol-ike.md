# IKE and data-plane evidence

Status: base protocol and private resource extension identified; payload body
schema and backend equivalence remain unverified.

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

## Required experiments

1. Capture one successful vendor session on UDP 500/4500 with packet bodies
   retained only in protected scratch.
2. Derive the standard Main Mode/Quick Mode sequence and the private
   ADDRULE/DELRULE ordering.
3. Recover an offline `expandrule` body schema and build parser/encoder round
   trips from redacted synthetic fixtures.
4. In an approved isolation window, use 6.0.7 to establish the standard base SA
   with PF_KEY; repeat with kernel-libipsec only if needed.
5. Add the minimum resource extension and prove exactly one desired `/32` route
   plus an SSH banner.
6. Prove teardown removes the rule, route, SA, and owned utun state without
   disturbing Surge.

No step may use production writes beyond the authenticated VPN actions the user
would normally perform, and no capture may enter Git.
