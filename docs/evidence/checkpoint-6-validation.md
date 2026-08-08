# Checkpoint 6 validation: payload/task skeleton and VICI dry run

Date: 2026-08-08

## Verdict

**PASS (offline compatibility-port checkpoint).** The post-fix implementation
matches the value-free vendor static Quick Mode phase/HASH(3) contract and an
independent synthetic reference. This is not a live differential or server
compatibility PASS; both remain unproven.

The separate unprivileged daemon/VICI socket smoke remains **BLOCKED and is not
counted as daemon passing evidence**: its first `version` request timed out
before any `load-conn` request was sent. This distinct control-path blocker is
outside deterministic VICI dry-run acceptance.

This checkpoint proves the offline compatibility-port contract, replayable
source delta, strict codec/task behavior, and deterministic VICI bytes. It does
not prove a real VICI daemon load, live vendor differential behavior, server
acceptance, SA/CHILD creation, a kernel backend, routing, or a utun data path.

## Protocol fidelity boundary

PowerVPN native is a compatibility port, not a protocol-design exercise. Its
evidence verdict follows ten hard rules:

1. MUST NOT add/remove/reorder/normalize/reinterpret/symmetrize observed wire.
2. Every outbound byte MUST have vendor/reference/server-acceptance evidence.
3. Unknown length-delimited values MUST remain opaque and neutral.
4. Parseability MUST NOT imply profile acceptance or permission to emit.
5. The private predicate MUST be complete; outside it, upstream behavior is
   unchanged.
6. Same-implementation round trips prove self-consistency only.
7. Observed vendor behavior outranks standards cleanup.
8. Wire-neutral safety is allowed; wire-visible improvements/generalizations
   are forbidden.
9. Owned XPC/control/internal architecture may be refactored because it is not
   the compatibility surface.
10. Intentional divergence MUST be outside the compatibility profile,
    independently feature-gated, and default off.

## Replayable strongSwan patch-series status

The series is rooted at official strongSwan 6.0.7 commit
`5973ff8e41deef4e015e1138a2de688acedf6f75`:

1. `0001-Add-strict-IKEv1-expandrule-wire-codec.patch`
   - upstream implementation commit
     `1fda864cca91da0aa9a87dd96e1823c3962dbd09`;
   - SHA-256
     `b46031db4589865deef87433fe62ef2437ae0a55fe2f3fe42fa171c240d1aa6e`.
2. `0002-Integrate-IKEv1-expandrule-payload-task-and-HASH.patch`
   - upstream implementation commit
     `67c9810900e2d8486cb3b11495a8362433494ca0`;
   - SHA-256
     `6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213`.

`patches/strongswan-6.0.7/series.json` pins the new order, commits, hashes,
integration boundary, and safety classification. Replaying both patches from
the official base produces the exact implementation tree.

## Payload, message, HASH, and task boundary

The CP6 patch adds the minimum integration surface required to exercise the
CP4A codec without inventing business semantics:

- IKEv1 private payload types are fixed at receive-only legacy revoke `17`,
  ADDRULE `18`, and DELRULE/revoke `19`.
- The generic private frame preserves the complete second header octet as a
  raw byte and uses the symbolic `CHUNK_DATA` encoding rule. This avoids the
  incompatible numeric encoding-rule shift between the vendor 5.8.0 base and
  upstream 6.0.7.
- Vendor Quick Mode `_build_i` state 0 builds the standard SA/NONCE/TS request;
  it is not replaced by a custom-only exchange.
- `_build_i` state 1 appends ADDRULE to the later initiator message.
- Vendor `_get_hash_phase2` at `0x10014fa70` has no custom branch. The state-1
  message uses standard
  `HASH(3) = PRF(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`, excluding ADDRULE bytes.
- Informational accepts one custom request payload from the `17/18/19` family;
  it may not be mixed with a second custom or standard payload. Response rules
  do not register a private type.
- The neutral task requires an explicit CP4A wire form and dialect. It owns no
  IKE SA, sender, VICI, policy, route, or interface state.
- Exact state-0/state-1 task scheduling reuses upstream HASH(3); the complete
  private predicate leaves all other upstream paths unchanged.

The targeted arm64 suite passes 39/39 tests, including:

- all seven CP4A synthetic byte vectors and their structural/profile cases;
- raw header flag byte `0xa5` generation and parsing;
- factory isolation to IKEv1;
- all five explicit form/dialect task decode paths;
- wrong form, dialect, profile, cardinality, actor direction, and message
  context rejection;
- rejection of Informational standard/custom mixing, dual custom payloads, and
  Quick Mode DELRULE;
- the value-free vendor static contract fixture
  `fixtures/redacted/leadsec-qm-hash3-static-vector-v1.json`;
- standard state-0 SA/NONCE/TS and state-1 `[HASH ADDRULE]` placement;
- independent HASH(3) calculation from fixed synthetic SKEYID_a/M-ID/Ni/Nr;
- ADDRULE-only mutation leaving HASH unchanged and Ni/Nr mutation changing it;
- unchanged upstream behavior outside the complete private predicate.

The complete libcharon run passes 5/5 suites. The independent no-IKEv1 build
passes. Both `src/libcharon/sa/ikev1/keymat_v1.c` and
`src/libcharon/sa/ikev1/task_manager_v1.c` are zero-diff from CP4A, proving the
port adds neither a custom keymat HASH branch nor task-manager wiring. Patch
replay equals the post-fix implementation tree.

## Deterministic VICI dry run

The Swift core now encodes a strict ordered VICI AST instead of rendering a
human-readable `swanctl.conf`. `powervpn spec vici-dry-run` performs no socket
connection and emits only a metadata report and payload digest.

The accepted IKEv1 Main Mode PSK tree contains only stock `load-conn` fields:

- connection: `version`, `aggressive`, `remote_addrs`, and `proposals`;
- local and remote authentication: `auth=psk` and redacted `id`;
- one child per redacted resource name with `local_ts=dynamic`, one exact
  redacted `remote_ts`, `esp_proposals`, and `start_action=none`.

The credential reference is required and placeholder-validated, but its
identifier is never dereferenced, resolved, or serialized. No secret is read.
`mapID`, resource operations, and rule identifiers remain local metadata with
`wireBinding=unresolved_cp4b`; they are not inserted into stock VICI or mapped
to an opaque CP4A field.

The official strongSwan 6.0.7 Python `vici.protocol` implementation is the
independent byte oracle:

- inner `Message.serialize`: 324 bytes, SHA-256
  `994e8884c42618b643595a46e2a9744428df3ce06be7df52151f01e8f884eb3a`;
- named `Packet.request("load-conn", ...)` payload, excluding the four-byte
  transport length: 335 bytes, SHA-256
  `07e9e6de79024f6c2d879e410942e7a402ce2f2c99d6b2fc8064ddea9819fa15`.

The Swift encoder produces the same 335 bytes and digest. Both the VICI
payload and TunnelSpec file readers are bounded, and the JSON inputs use
closed schemas. TunnelSpec decoding rejects exact, escaped-alias, and nested
duplicate object keys before Foundation parsers can canonicalize them.
This oracle covers stock VICI encoding only; it provides no independent check
of private ADDRULE serialization or the Quick Mode HASH input.

## Bounded daemon smoke blocker

One unprivileged, isolated attempt was made using stock 6.0.7, random high UDP
ports, a scratch PID/VICI socket, fake kernel, `initiators=0`, and a fail-closed
load-tester control socket. It loaded no user, project, or VICI credential;
the stock in-process public load-tester credential set was the only credential
provider.

The first allowed VICI operation, `version`, received no response within five
seconds. Consequently:

- `load-conn` was not sent;
- daemon-side SA and policy counts were not observed;
- this smoke cannot support a zero-side-effect or successful VICI-daemon claim.

The daemon was stopped immediately. The utun set was unchanged, no synthetic
documentation-prefix route appeared, and no process, UDP descriptor, PID file,
or UNIX socket remained. The global route snapshot changed because existing
utun/AWDL cache and cloned routes changed during the observation window, so a
strict whole-table equality claim is intentionally not made. The redacted
aggregate result is in
`fixtures/redacted/vici-daemon-smoke-summary-v1.json`; raw scratch evidence is
not part of Git.

## Acceptance commands

The cumulative entrypoint is:

```bash
scripts/verify_checkpoint.sh 6
```

The entrypoint pins upstream commit
`67c9810900e2d8486cb3b11495a8362433494ca0` and 0002 SHA-256
`6e4c609240ae2a1996a3a547cede72ac1be7121922aa6f576687632609f34213`.
It verifies 39/39 targeted tests, full libcharon 5/5, no-IKEv1 PASS,
keymat/task-manager zero diffs, patch replay equality, arm64 and Swift/VICI
gates, formatting, secret scan, and cumulative diff hygiene.

## Review closure

Exactly one integrated checkpoint review ran after the initial offline
implementation gate passed. It
found two P2 issues: duplicate TunnelSpec JSON keys could survive Foundation
canonicalization, and a `--disable-ikev1` build retained a factory reference
whose implementation was conditional. Both were fixed with targeted tests and
the offline cumulative gate returned to PASS. This did not promote the CP6
compatibility verdict at that stage.

The one permitted independent narrow review then found one P2 in the
pre-static-evidence keymat helper: a standard payload before ADDRULE could stop
the private-payload scan early. That candidate was subsequently superseded by
the vendor-faithful HASH(3) implementation, which leaves `keymat_v1.c`
unchanged. No additional review ran.

## Remaining boundary

CP6 is closed only as an offline compatibility-port checkpoint and must not be
treated as a working VPN client or live/server compatibility proof. The next
bounded task is diagnosing the VICI `version` timeout and writing the Live
Approval Gate launch/stop/rollback artifacts. Live differential and server
acceptance remain unproven. Root charon, UDP 500/4500, SA, policy, route, utun,
PowerVPN interruption, and Surge-impacting tests remain unapproved.
