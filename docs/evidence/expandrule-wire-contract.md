# Expandrule wire-syntax contract (CP4A)

Status: checkpoint candidate, offline only
Target: official strongSwan 6.0.7 at
`5973ff8e41deef4e015e1138a2de688acedf6f75`
Vendor behavior oracle: PowerVPN strongSwan 5.8.0 fork
Evidence date: 2026-08-08

## Scope and evidence boundary

This document records only syntax that is sufficient to implement a strict,
offline codec. It does not assign portal/resource semantics to opaque fields.
Those names may only be promoted at CP4B after CP5 correlation provides two
independent evidence classes.

No packet capture, endpoint, credential, session value, PSK, real resource
identifier, or vendor binary is stored in Git. The implementation evidence is:

- `CP4A-STATIC-01` (confirmed): vendor enum-name table and call-site xrefs map
  current payload type 18 to ADDRULE and type 19 to DELRULE;
- `CP4A-STATIC-02` (confirmed): the receive path accepts type 19 plus a legacy
  type-17 alias for the short server form;
- `CP4A-STATIC-03` (confirmed): `expandrule_payload_create`, its encoding-rule
  table, the client serializer, and the server parser establish the generic
  header, field widths, byte order, counts, and asymmetric body shapes;
- `CP4A-STATIC-04` (confirmed): Quick Mode creates `[HASH ADDRULE]`; the current
  custom type is therefore carried by the predecessor payload's `Next Payload`
  field and is not present in the custom payload bytes themselves;
- `CP4A-INFER-01` (inferred profile only): vendor allocation sizes imply
  dialect-0 opaque values of at most 64 bytes and dialect-1 opaque values of at
  most 16 bytes for canonical client output. These are not wire limits;
- `CP4A-UNKNOWN-01`: the business meaning of `leadingAddress`, primary/secondary
  categories, dialect selection, and opaque values is deliberately unknown.

The 5.8.0 encoding-rule enum used numeric value 18 for `CHUNK_DATA`. In 6.0.7
that enum value changed. Future payload integration must use the symbolic
`CHUNK_DATA` constant, never copy numeric 18. CP4A does not register a payload
factory or message rule.

## Generic payload frame

All byte order below is network order.

```text
0               1               2               3
+---------------+---------------+-------------------------------+
| next payload  | raw flags     | total length (u16, incl. hdr) |
+---------------+---------------+-------------------------------+
| body ...                                                      |
+---------------------------------------------------------------+
```

- `next payload`: structurally preserved. The observed canonical profile
  requires zero because expandrule is last in the known message form.
- `raw flags`: client envelopes use exactly `0x00` (IPv4) or `0x06` (IPv6).
  The short server form preserves the byte without assigning family semantics.
- `total length`: exactly the input length and at least four bytes.
- The current private payload type (17/18/19) comes from the previous payload's
  `Next Payload`; a raw custom-payload byte string is ambiguous without context.

## Five explicit wire forms

| Form | Exchange | Direction | Current type | Body | Canonical cardinality |
|---|---|---|---:|---|---|
| `QM_ADD_SNAPSHOT` | Quick Mode | client to server | 18 | full envelope | 0..N records |
| `INFO_ADD_DELTA` | Informational | client to server | 18 | full envelope | exactly 1 record |
| `INFO_DELETE_DELTA` | Informational | client to server | 19 | full envelope | exactly 1 record |
| `INFO_REVOKE_V1` | Informational | server to client | 19 | short opaque form | one value |
| `INFO_REVOKE_LEGACY` | Informational | server to client | 17 | short opaque form | one value, decode only |

The form enum is the context source of truth. Illegal combinations are not
representable by passing independent direction/type/body flags. In particular:

- type 19 has two direction-dependent body shapes;
- type 17 is receive-only;
- Quick Mode type 19 is unsupported;
- server-to-client type 18 is unsupported;
- dialect is caller/session context and is never autodetected from bytes.

## Client full envelope

For address width `V` (`4` for IPv4, `16` for IPv6):

```text
leadingAddress[V]
primaryCount:u32
primaryRecord[primaryCount]
secondaryCount:u32
secondaryRecord[secondaryCount]
```

Dialect 0:

```text
primary IPv4: address[4]  + contiguousNetmask[4]
primary IPv6: address[16] + prefixLength:u32 (0..128)
secondary:    opaqueLength:u8 + opaqueBytes[length]
```

Dialect 1:

```text
primary:   opaqueLength:u8 + opaqueBytes[length]
secondary: opaqueLength:u8 + opaqueBytes[length]
```

The primary/secondary labels are positional syntax only. Opaque values are
length-delimited bytes, not C strings: structural decode and the client
canonical profile preserve embedded NUL and do no UTF-8 validation, case fold,
Unicode normalization, sorting, or semantic deduplication.

IPv4 masks must have one contiguous high-order run of ones. `/0`, `/1`, `/24`,
and `/32` are valid; `ff00ff00`, `7fffffff`, and `ffffff01` are invalid. The
address bytes are preserved as received; host bits are not canonicalized.
IPv6 prefix is a u32 and must be 0 through 128.

## Short server form

```text
opaqueLength:u8 + opaqueBytes[length]
```

Structural decoding accepts the full u8 range and preserves `raw flags`. The
canonical vendor-safety profile requires 1..63 bytes, exact body consumption,
and no embedded NUL before the value can enter the vendor-compatible matching
path. The profile does not infer an IP family from server flags.

## Structural parser versus canonical profile

Structural decode rejects only unsafe or unambiguous syntax failures:

- truncated header/body, inconsistent total length, or trailing bytes;
- client flags other than `0x00` or `0x06`;
- invalid direction/form/dialect context;
- count above the local 4096-record DoS cap or impossible for remaining bytes;
- len8 truncation, non-contiguous IPv4 mask, or IPv6 prefix above 128;
- payload length above 65535.

Structural decode deliberately preserves:

- nonzero `next payload`;
- zero-length and embedded-NUL opaque values;
- duplicate values and original record order;
- raw server flags;
- the full len8 range through 255.

Canonical profile validation then requires:

- `next payload == 0` for every observed flow;
- exactly one total record for Informational add/delete deltas;
- no exact duplicate within the same category;
- nonempty dialect-0/1 opaque client values within inferred 64/16 limits;
- short server value length 1..63 with no embedded NUL;
- exact family/address widths and valid prefix ranges.

Cross-category equal opaque bytes are not duplicates. Two address records in
the same subnet are not duplicates if their raw address bytes differ. Encoding
always validates the canonical profile first, writes `next payload = 0`, is
deterministic, and rejects the legacy type-17 transmit path.

Errors contain only a stable error code and byte offset. They never retain or
format input bytes, opaque values, addresses, or hex.

## Synthetic golden corpus

The canonical machine-readable corpus is
`fixtures/redacted/expandrule-synthetic-v1.json`. It contains seven unique
synthetic byte strings. The single-delta bytes are exercised under both type 18
and type 19 contexts; the short bytes are exercised under both type 19 and
legacy type 17. Therefore logical cases outnumber unique byte strings.

All addresses use TEST-NET or RFC 3849 ranges and all opaque bytes are invented.
The test suite covers byte-for-byte encoding, decoding, round-trip ownership,
strict prefixes, invalid lengths/flags/context, count preflight, mask/prefix
boundaries, opaque len8/NUL behavior, duplicates, cardinality, profile limits,
oversize output, raw server flags, and deterministic encoding.

## CP4A integration boundary

The codec is compiled only when `USE_IKEV1` is enabled. CP4A intentionally does
not modify `payload.h`, `payload.c`, `message.c`, Quick Mode, Informational,
task manager, payload factory, HASH/order rules, VICI, SA, route, utun, or any
network path. Those changes begin no earlier than CP6 after the CP4B semantic
promotion gate.
