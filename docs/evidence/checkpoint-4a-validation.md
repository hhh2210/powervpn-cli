# Checkpoint 4A validation

Date: 2026-08-08 16:26 +08:00
State: PASS
Lane: guarded
Network/root impact: none

## Candidate identity

- Upstream: strongSwan 6.0.7,
  `5973ff8e41deef4e015e1138a2de688acedf6f75`.
- Isolated source worktree:
  `/Users/larry_1/scratch-data/powervpn-strongswan/strongswan-6.0.7-expandrule`.
- Isolated arm64 build:
  `/Users/larry_1/scratch-data/powervpn-strongswan/build-6.0.7-expandrule-arm64`.
- Canonical upstream-side implementation commit:
  `1fda864cca91da0aa9a87dd96e1823c3962dbd09`.
- Commit tree: `28cf7e5852bcde0a5dc6b4888896b657e6e41f44`.
- Replayable patch:
  `patches/strongswan-6.0.7/0001-Add-strict-IKEv1-expandrule-wire-codec.patch`.
- Patch SHA-256:
  `b46031db4589865deef87433fe62ef2437ae0a55fe2f3fe42fa171c240d1aa6e`.
- Patch size: 78,115 bytes.

The patch applies cleanly with `git apply --check` to the clean official 6.0.7
source tree.

## Accepted contract

- Five explicit forms bind exchange, direction, current payload type, and body
  shape; type 19 is not treated as a direction-free operation.
- Client dialect and family are explicit context. Dialect is never guessed from
  bytes and remains named `dialect0`/`dialect1`.
- The generic header and full/short bodies follow
  [`expandrule-wire-contract.md`](expandrule-wire-contract.md).
- Structural decode is lossless for nonzero next-payload, duplicate records,
  zero-length/embedded-NUL opaque bytes, raw server flags, and len8 up to 255.
- Canonical/local validation separately enforces known flow placement,
  Informational cardinality, exact duplicates, inferred 64/16 client limits,
  and the 1..63 non-NUL short-server safety profile.
- Error output contains only code and offset. Decode clones all borrowed input;
  encode transfers an allocated output chunk to the caller.
- Seven unique synthetic byte strings cover nine logical contexts. No value is
  copied from a real session or resource.
- CP4A adds no payload factory, message rule, Quick Mode task, VICI path, SA,
  policy, route, utun, network request, or credential handling.

## Final acceptance command

```bash
cd /Users/larry_1/Opensource/powervpn-cli
scripts/verify_checkpoint.sh 4a
```

Final result: exit 0.

The fixed entrypoint verified:

- changed-component arm64 build for `libcharon`;
- 28 expandrule positive/negative cases inside `libcharon_tests`;
- full strongSwan `make check` including 48 libstrongswan suites, libipsec,
  VICI, libcharon, and exchange suites;
- arm64 architecture of the patched `libcharon.0.dylib`;
- source-diff allowlist and `git diff --check`;
- per-changed-file Gitleaks scans in the upstream worktree;
- exact JSON `(id, hex, byteLength)` tuples against the compiled C fixture
  manifest, followed by C `hex/length` against byte-array tests;
- the exact nine-context/five-form direction/type/dialect/family matrix;
- 20 Swift tests and `swift build --arch arm64`;
- main repository Gitleaks and `git diff --check`.

The repeated warning that the scratch prefix has no `strongswan.conf` is the
known test-harness initialization message; all named test suites still ran and
reported PASS.

## Bounded reviews

Exactly one integrated implementation review ran after first acceptance. It
reported no P0/P1 and found two direct gaps: fixture JSON was not tied to the C
arrays, and fixture dialect numbers could be confused with C enum ordinals.
Both were fixed with symbolic dialects plus a compiled manifest bridge.

One independent targeted review then checked only wire layout,
direction/dialect/family, parser/profile separation, canonicalization, and the
first review fixes. It found:

- tuple association was not yet exact;
- the context gate did not require every form or Informational family/dialect;
- one API comment blurred inferred limits with confirmed syntax.

The final candidate binds each JSON `(id, hex, byteLength)` to one C manifest
record, enforces the exact form multiset and client context fields, and labels
the limits as canonical/local inference. Final acceptance passed after these
fixes. No third review was run.

## Safety and cleanup

- Vendor app/helper files were not modified or executed for this checkpoint.
- No live VPN, UDP 500/4500, root daemon, SA, route, policy, utun, Surge setting,
  credential, or network path changed.
- Build outputs remain under the scratch root and outside Git.
- Gitleaks found no secret in changed source or the repository candidate.
- The upstream implementation worktree is clean at its canonical commit.

Next command: begin CP5 control-plane/XPC semantic correlation under its
redaction constraints; no live backend approval is required until CP7.
