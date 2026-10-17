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


## 2026-10-17 NC semantic follow-up (static evidence)

The syntax-only limits above describe the original CP4A checkpoint. The following
findings add semantics for the installed macOS helper's dialect-0 NC path, based
on `com.leadsec.charon-xpc` and `charon.dis` in the existing helper-RE directory.
They do not by themselves establish native data-plane interoperability; that was
established later the same day once the `NEW CLIENT` vendor ID was added (see
`native-strongswan-backend.md`).

- `_add_nc_expandrule` (`0x100125ff0`): `rflag == 0` inserts category 1 using
  the tunnel's parsed address/prefix; nonzero rflag inserts category 2 using the
  resource name. The "not immediately start up" message precedes insertion;
  it does not establish a required follow-up Informational packet.
- `_add_expandrule` (`0x100166bf0`): dialect-0 IPv4 primary records are exactly
  four network-address octets and four mask octets. Counts and masks are big
  endian. Category 2 carries one byte of name length followed by that many
  bytes. A category-1 resource does not also emit its name. `mapid` is used by
  dialect 1, not this dialect-0 serialization path.
- QM3 contains type-18 ADDRULE after HASH. The snapshot enumerates enabled
  manager records matching gateway/address family. A coexistence trial must
  keep the declared resource scope to its selected resource; a complete vendor
  snapshot is not a safe reason to claim the other live resource.
- `_vpn_nc_create` (`0x100127960`) takes the new-connection path when no service
  exists. The Informational delta path (`0x100127e45`) is reached only when an
  existing service/address family is already active. Thus a fresh standalone
  native NC connection does not need an unconditional INFO_ADD_DELTA.
- The CIDR assigned in `_start_connection` is intermediate resource state.
  `_set_adapter_name`, NC connection type 2, appends `0.0.0.0/0` at
  `0x100122d69..0x100122d7b`. `_set_virtip` adds local VIP/32 at
  `0x100122afd..0x100122b12`. `_create_child_cfg` consumes those lists as local
  and remote TS. This invalidates the prior inference that the vendor NC CHILD
  necessarily negotiates the selected resource /32 as its remote TS.

The installed experimental `kernel-libipsec` called its automatic route installer
unconditionally; the generic `charon.install_routes` value alone did not stop it.
The scoped follow-up adds a guard in that existing plugin and sets the experimental
configuration to `install_routes = no`. The existing runner remains responsible
for the selected target's /32 OS route. Broad remote TS must not be tested with the
old plugin, including when its configuration merely says `install_routes = no`.

Live run `addrule-r2-all` tested a two-rule snapshot with /32 remote TS. It sent
three encrypted SYN packets and received zero ESP packets before the runner
aborted on vendor-helper exit. The crash report shows received CHILD deletion ->
child_updown -> NotifyNCResourceStatus -> xpc_connection_send_message (SIGILL).
This is a censored negative trial, not proof that all-rule ADDRULE works, nor proof
that the crash was independent of the concurrent native trial. The vendor owner
subsequently rebuilt its connection; an SSH command over the new thu21
ControlMaster returned exit 0. No all-rule retry is planned.


Follow-up run `addrule-r3-ncts` used selected-resource ADDRULE, remote TS
`0.0.0.0/0`, and the guarded native route installer. It still produced out=3,
in=0 after the TCP probe; SSH exited 255 after 5096 ms with a TCP connect timeout.
Runner cleanup reported restored52=1, utun_baseline=1, route21_same=1,
vendor_alive=1, thu21_master=1. Default and IKE-gateway routes matched before/after.
The TS mismatch was real, but correcting it alone did not restore forwarding.

A further static difference was found in vendor `isakmp_vendor.c` `_build`
(`0x100160293..0x100160431`): an NC connection name ending in `4` causes an
additional type-13 Vendor ID containing exactly nine bytes `31 32 33 34 49 50
56 34 00` (`1234IPV4` including NUL). `_build_i` emits it on its first invocation,
so it is in the initial Main Mode request. Upstream/native lacked this extension.
The experimental patch adds it only for initiator connections with an explicitly
configured dialect-0 IPv4 ADDRULE. This is a hypothesis about gateway NC setup,
not yet a demonstrated cause of the no-ESP-reply symptom.


Run `addrule-r4-ncvid` stopped before IKE due to the known transient Portal
`integration_info_missing`. Its bounded retry `addrule-r4b-ncvid` logged the
nine-byte NC IPv4 Vendor ID in the initial IKE request, established the CHILD,
and still had out=3/in=0 after nc; SSH exited 255 after 5092 ms. Cleanup again
reported all five checks true. Final read-only SSH checks returned exit 0 for
thu21 through its existing ControlMaster and for thu52 through vendor directly.
No native daemon remains. Native SSH is NOT working; these protocol-parity
corrections are not a successful repair claim.

Additional static comparison found the standard protocol|SPI|Ni|Nr CHILD seed,
PRF expansion without an appended counter, standard SPI/sequence/IV/ICV ESP
layout, and send_no_marker for encrypted ESP. No additional vendor-specific
seed/header was identified in these inspected paths. This is not a runtime
key-equivalence proof. The next discriminating evidence must explain gateway
acceptance of QM3/ADDRULE or the handling of the first native ESP packet; the
current local trace cannot identify the precise remote drop stage.


## 2026-10-17 successful Quick Mode differential

The later exclusive capture supersedes the earlier unresolved data-plane status.
An isolated vendor helper copy connected only thu52 and completed SSH in 699 ms
with exit 0. Its host DNS/gateway integrations were disabled and its VIP interface
used /32; its negotiation/crypto code was unchanged. The original helper was not
modified. Three Quick Mode plaintext payload chains were captured before encryption
and after decryption in this copy, excluding Main Mode identities and key material.

Vendor QM1/QM2 used proposal number 0 plus SA_LIFE_TYPE=seconds and
SA_LIFE_DURATION=3600. Native used number 1 and omitted the two lifetime attributes.
QM3 ADDRULE was already byte-identical after normalizing session VIP/HASH.

| Native case | Stable payload difference from vendor | Outcome |
| --- | --- | --- |
| Initial | Missing lifetime attributes; proposal 1 | ESP in=0, SSH timeout |
| Portal lifetime mapped | Only byte 40 in QM1/QM2: proposal 1 | ESP in=0, SSH timeout |
| Lifetime mapped, scoped proposal 0 | None after HASH/nonce/SPI/VIP normalization | ESP in=4/out=4, SSH exit 0 in 718 ms |

The protocol fix maps Portal ipsecLifetime to child life_time and sets the
proposal number to zero only for initiator connections with the explicit private
ADDRULE extension and no IPComp. The successful trace has identical normalized
QM1/QM2/QM3 bytes. This identifies proposal numbering as the decisive compatibility
change in the controlled sequence; the gateway's internal lookup implementation
has not been observed.

The native success window restored the target route, utun set, default route, and
DNS to baseline. Twelve confirmed orphan capture processes from earlier admin
scripts were stopped in one final root batch. The existing expiring runner now
waits after TERM, uses KILL if needed, and reaps its capture children. The default
mode is exclusive; no vendor/thu21/ControlMaster prerequisite remains. Future root
updates must be batched; any repeated vendor capture must first be installed as a
fixed runner mode, not executed via arbitrary root scripts/binaries.

The formal installed CLI was not replaced. Long-duration rekey/reconnect behavior
is outside this short-window interoperability acceptance.
