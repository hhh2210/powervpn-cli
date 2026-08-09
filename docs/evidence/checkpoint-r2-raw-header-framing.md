# Rescue R2 raw-header-framing gate

Status: **OFFLINE PASS — INTEGRATED REVIEW COMPLETE; FINDINGS APPLIED; LIVE
HARD NO-GO.** This independent subcheckpoint is synthetic-only. It uses no
username, password, session value, installed portal endpoint, or VPN server
traffic. Its offline verifier passes and its one integrated review is complete,
and the reviewed R2 manifest has been resealed. The full offline R2 verifier
passes, but this does not authorize a password POST; all R2B live prerequisites
must still be satisfied.

## Question being closed

Foundation exposes a projected `Set-Cookie` value but does not prove how many
raw response-header fields produced that value. The LeadSec compatibility
profile requires exactly one raw `Set-Cookie` field on the final password
response. This gate adds a bounded raw-header observation seam; it does not
relax the Cookie grammar or use server tolerance as evidence.

## Frozen architecture contract

- `PowerVPNPortal` may depend only on the C target `CPortalCurl`; the C target
  has no package dependencies.
- The package deployment floor remains macOS 14. The acceptance build is
  arm64 and the resulting executable must link the macOS system
  `/usr/lib/libcurl.4.dylib`.
- The implementation is in-process. `Process`, `/usr/bin/curl`, shell
  execution, and credential material in argv or environment are forbidden.
- There is no caller-controlled proxy, insecure-TLS switch, CA file/path,
  client certificate, authentication credential, redirect policy, or portal
  endpoint override.
- Redirect following and automatic HTTP authentication are disabled. macOS
  system trust remains the production trust source.
- Raw header parsing is bounded and rejects ambiguous framing. C and Swift
  implementation/test files added by this subcheckpoint stay below 300 lines.
- Entry to the raw password lane requires a factory-only unforgeable operation
  proof. Matching body, Cookie or User-Agent bytes constructed outside the
  factory cannot mint that proof and cannot reach either transport lane.
- The existing Foundation transport remains fail closed for the password path:
  its `.foundationFoldedValue` projection is never promoted to
  `.provenSingleWireHeader`.
- TLS trust classification is restricted to peer/issuer verification.
  Handshake, cipher and local setup failures are closed as `unavailable`, not
  presented as trust evidence.

The C shim owns libcurl callback mechanics and returns only a bounded transport
result plus raw-header framing status. Swift owns the existing origin, request,
response, secure-buffer, cancellation, and LeadSec compatibility boundaries.
Neither layer interprets an unknown Cookie field or invents a default.

## Synthetic acceptance matrix

All cases run against in-memory bytes or injected adapters. The test inputs use
only synthetic values; no installed endpoint or credential may be read. A
successful loopback TLS transfer is deliberately excluded: accepting a local
self-signed peer would require a test-only CA or insecure path that the
production API is forbidden to expose.

| Case | Required result |
|---|---|
| One raw final `Set-Cookie: VSG_SESSIONID=...` field | accepted and projected as exactly one proven wire header |
| Two raw `Set-Cookie` fields | rejected as ambiguous, even if values match |
| Missing `Set-Cookie` | rejected |
| Interim response/header block | rejected; it cannot supply or multiply the final field |
| Obsolete folded continuation (`obs-fold`) | rejected |
| Redirect response or changed final URL | rejected without following |
| HTTP origin/server authentication challenge | rejected without negotiation or retry |
| Direct body, Cookie or User-Agent near miss without factory proof | rejected with zero raw-driver and Foundation-lane hits |
| Peer/issuer verification failure | normalized as a value-free TLS trust failure |
| TLS handshake or cipher failure | normalized as `unavailable`, not a trust failure |
| Header/body/count limit crossing | cancelled and rejected at the first excess unit |
| Caller task cancellation | libcurl operation cancelled and normalized without leaking a retained response |
| Deadline expiration | libcurl operation cancelled and normalized as timeout |

The positive case proves only that the new implementation preserves one
synthetic raw field boundary. The negative cases prove parser, closed-status,
finalization, adapter-mapping, and cancellation behavior. No successful
libcurl TLS transfer or redirect/authentication exchange is executed, so the
tests do not prove those wire paths end to end. Together they are implementation
evidence, not vendor differential evidence, real-server acceptance, or proof
of the later portal workflow.

## Offline verifier contract

The independent entry point is:

```text
scripts/verify_checkpoint.sh r2-raw-headers
```

It must:

1. bind the checkpoint-local file allowlist to the reviewed R2 closure base;
2. inspect SwiftPM target dependencies and the macOS 14 deployment floor;
3. compile and execute the C raw-header tests directly with `xcrun clang`
   under a temporary directory;
4. run only the named synthetic raw/composite/factory Swift tests plus the
   existing Foundation fail-closed regression;
5. build arm64 and verify system-libcurl linkage;
6. reject subprocess curl, proxy/insecure/custom-CA input surfaces;
7. enforce the per-file line limit, strict formatting, secret scan, and
   whitespace checks.

The verifier must not load the R2 live manifest, prompt for a credential, run
`powervpn login`, contact the installed portal, start the GUI/helper/native
charon, or modify SA, policy, route, DNS, interface, or utun state.

## Current evidence and decision

The independent offline verifier passed on the cumulative reviewed candidate
after both direct review findings were applied:

- 11 direct C raw-header parser cases passed, including exact-one,
  duplicate/missing/interim/obs-fold and three independent size caps;
- 5 direct C status/finalization cases passed, covering 3xx, 401/407, timeout,
  cancellation, callback-failure precedence, changed effective URL, URL
  userinfo rejection, exact request-header order and network-free pre-cancel;
- 16 Swift raw/composite/factory cases passed, including the factory-only
  operation proof and zero-hit body/Cookie/User-Agent near misses;
- the existing Foundation password request still rejected before its network
  seam;
- strict C warning compilation, strict Swift formatting, arm64 build, exact
  `/usr/lib/libcurl.4.dylib` linkage, secret scan and diff checks passed;
- every checkpoint C/Swift file remained below 300 lines.

The one integrated raw-header review returned exactly two direct findings:

1. the compatibility predicate could be reached by a directly forged request;
   the applied fix requires a factory-only unforgeable operation proof and the
   regression cases prove body, Cookie and User-Agent near misses produce zero
   lane/driver hits;
2. TLS error mapping overclassified handshake/cipher failures as trust errors;
   the applied fix reserves trust classification for peer/issuer verification
   and maps handshake/cipher failures to `unavailable`.

No second review ran. No successful TLS transfer, live request, portal/server
interaction or credential read occurred. Therefore:

- R2 raw-header framing: **OFFLINE PASS; INTEGRATED REVIEW COMPLETE; FINDINGS
  APPLIED**;
- R2 password login: **HARD NO-GO**;
- live/server compatibility: **NOT TESTED**;
- successful libcurl TLS and redirect/auth wire integration: **NOT TESTED**;
- credential use in the offline evidence: **none**.

The raw-header implementation is incorporated into reviewed manifest SHA-256
`00411979105d9023916af3eef5bda0f3886231a5ad74714c0e47d5197bf9e084`,
which binds runtime source aggregate SHA-256
`83c590c8ebb3c15b8e32d125bfbdef6c4b39aabd94ca9235c35aef140b67eee2`.
The manifest independently binds the raw-header test-source aggregate as
SHA-256
`a6d98b928a9c0a63ded37b7b60120e9483fabddf8dea6a895a160276a4acab05`
and the runtime library as SHA-256
`d6c3f1696e18beac31ffd425e177febce5ec523a0f6a05c2f8bf6c9e8cf56152`.
The full offline R2 verifier passes with 120 Portal tests in 19 suites and 109
Core tests in 10 suites (229 tests in 29 suites), including 16 raw Swift cases
across 3 suites and the separate Foundation fail-closed regression; the direct
C gates pass 11 parser and 5 status cases.

Next: the user rotates the exposed password outside PowerVPN, then provides
fresh approval bound to the exact manifest before any R2B window. New
credentials may be entered only through the no-echo controlling TTY, never
chat. Do not interpret the raw-header or full offline PASS as live/server/TLS
compatibility evidence.
