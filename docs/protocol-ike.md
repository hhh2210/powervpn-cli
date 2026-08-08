# IKE and data-plane evidence

Status: base protocol and private resource extension identified; the CP4A
wire-syntax codec and CP4B semantic gate are complete. CP6 is PASS as an offline
compatibility-port checkpoint: vendor static state-0/state-1 and HASH(3)
contracts are implemented and matched by an independent synthetic reference.
No business-semantic field promotion passed the two-evidence-class gate. Live
vendor differential behavior, server acceptance, a responsive daemon VICI path,
and backend equivalence remain unverified.

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

## Protocol fidelity invariant

This work is a compatibility port from observed LeadSec 5.8.0 behavior to
upstream 6.0.7, governed by ten hard rules:

1. MUST NOT add/remove/reorder/normalize/reinterpret/symmetrize observed wire
   fields, payloads, HASH coverage, or directional asymmetry.
2. Every outbound byte MUST trace to vendor evidence, a protected reference
   vector, or explicitly approved server acceptance.
3. Unknown length-delimited values MUST remain opaque and neutral.
4. Structural parseability MUST NOT imply profile acceptance or permission to
   emit; parse, accept, and emit remain distinct.
5. The private predicate MUST be complete; outside it, payload order, HASH,
   message rules, and results remain identical to unmodified upstream.
6. Same-implementation generate/verify proves self-consistency only, never
   vendor compatibility.
7. Observed vendor behavior outranks standards cleanup or upstream intuition
   inside the compatibility profile.
8. Wire-neutral safety checks are allowed; wire-visible improvements and
   generalizations are forbidden.
9. Owned GUI, XPC/control schema, helper names, classes, and state machines may
   be refactored; only server-observable wire, timing, and effects must match.
10. Intentional divergence MUST remain outside the compatibility profile behind
    an independent feature gate that is default off.

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

## CP6 integration result — PASS (offline compatibility-port checkpoint)

Static vendor evidence now fixes the Quick Mode placement and HASH contract:

- vendor `_get_hash_phase2` at `0x10014fa70` contains no expandrule/custom
  branch;
- vendor Quick Mode `_build_i` state 0 builds the standard SA/NONCE/TS request;
- `_build_i` state 1 appends ADDRULE to the later initiator message;
- that message uses standard
  `HASH(3) = PRF(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`;
- ADDRULE bytes are excluded from the HASH input.

The corrected port preserves the normal state-0 exchange, adds ADDRULE at the
exact state-1 phase, and reuses upstream HASH(3) without a custom keymat branch.
The private predicate covers only that scheduling context; every path outside
it remains identical to upstream.

The accepted reference test independently calculates HASH(3) from fixed
SKEYID_a/M-ID/Ni/Nr values, asserts standard SA/NONCE/TS at state 0 and
`[HASH ADDRULE]` at state 1, proves that changing only ADDRULE leaves HASH
unchanged, proves that changing Ni or Nr changes HASH, and retains unchanged
upstream results outside the complete private predicate.

The value-free contract and reference are recorded in
`fixtures/redacted/leadsec-qm-hash3-static-vector-v1.json`. Upstream commit
`67c9810900e2d8486cb3b11495a8362433494ca0`, 0002 patch SHA-256
`6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213`,
targeted 39/39, full libcharon 5/5, no-IKEv1 PASS, patch replay equality, and
zero diffs for both `keymat_v1.c` and `task_manager_v1.c` from CP4A establish
the offline compatibility-port checkpoint.

The Swift dry run builds an ordered stock VICI `load-conn` request whose 335
bytes match the official 6.0.7 Python implementation. Credential references
are placeholder-validated but never resolved or serialized, and CP4B-unresolved
resource-rule metadata remains outside the VICI tree. Closed TunnelSpec JSON
rejects duplicate object keys, including escaped-key aliases, before
Foundation canonicalization. This independent oracle covers stock VICI framing
only; it does not oracle the private IKEv1 ADDRULE body or HASH input.

The one bounded daemon smoke remains **BLOCKED**: the first `version` request
timed out and `load-conn` was never sent. Cleanup left
no process, UDP descriptor, PID, UNIX socket, or new utun. See
[`evidence/checkpoint-6-validation.md`](evidence/checkpoint-6-validation.md).
This blocker is separate from and does not invalidate deterministic VICI
dry-run acceptance.

## Remaining checkpoint sequence

1. CP5 correlated the legal value-free control/XPC observations; no raw value
   entered Git.
2. CP4B applied the two-independent-class gate and made zero promotions.
3. CP6 passed the offline compatibility-port checkpoint with the minimal
   payload/message/task skeleton, exact vendor state-0/state-1 scheduling,
   independent synthetic HASH(3) reference, and deterministic VICI dry run.
   This is not live/server compatibility evidence.
4. Diagnose the daemon VICI `version` timeout as a separate control-path
   blocker; neither blocker may be used as evidence for the other.
5. Before any privileged action, write the Live Approval Gate
   launch/stop/rollback artifacts.
6. In an approved CP7/CP8 window, use 6.0.7 to establish the standard base SA
   with PF_KEY; repeat with kernel-libipsec only if needed.
7. Add the minimum resource extension and prove exactly one desired `/32` route
   plus an SSH banner.
8. Prove teardown removes the rule, route, SA, and owned utun state without
   disturbing Surge.

No step may use production writes beyond the authenticated VPN actions the user
would normally perform, and no capture may enter Git.
