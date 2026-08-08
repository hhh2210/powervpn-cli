# Checkpoint 3 validation evidence

Date: 2026-08-08 15:19 +08:00

Host: Apple Silicon (`arm64`), macOS 27.0 build 26A5388g

Swift: Apple Swift 6.4, target `arm64-apple-macosx27.0.0`

## Required commands

| Command | Result | Evidence |
| --- | --- | --- |
| `swift test` | PASS | 20 Swift Testing tests passed; no failures. |
| `swift build --arch arm64` | PASS | Debug executable and library built successfully. |
| `swift run powervpn oracle inventory --json` | PASS | Returned schema v1, vendor 3.2.1 build 24572, strongSwan 5.8.0 debug-path evidence, and B+C classification. |
| `swift run powervpn spec validate-redacted fixtures/redacted/tunnel-spec.example.json --json` | PASS | Returned `valid: true` with an empty issue list. |

The committed inventory is
[`vendor-inventory.json`](vendor-inventory.json). It contains only helper paths,
architectures, SHA-256 hashes, versions, allowlisted marker names, and
classification states. It contains no raw symbol line, vendor log line, packet
body, endpoint, resource, identity, session, or credential value.

The committed TunnelSpec fixture is synthetic. Its proposal names reproduce
the observed algorithm family, while all environment-specific identifiers,
addresses, routes, and resources are placeholders.

## Safety checks

- `jq empty` accepted both committed JSON artifacts.
- `git diff --check` returned success.
- Gitleaks 8.30.1 scanned the current directory with full redaction enabled and
  reported `no leaks found` after scanning approximately 75.4 MB.
- The oracle retained its FileHandle streaming allowlist boundary. Stored
  results contain canonical marker text only; plugin lines retain only known
  plugin tokens. Mixed marker/secret lines, unmatched lines, and partial leading
  tail lines are covered by tests.
- Source search and the CLI surface contain no `reconnect`, terminate, or
  relaunch operation.

No root process was started. No VPN was connected or disconnected, and no SA,
route, policy, utun, DNS, NetworkExtension, or Surge state was changed.

## Scope of this PASS

This proves Checkpoint 3 only: read-only oracle safety, a closed TunnelSpec
schema, a commit-safe inventory, and a forward-validated redacted fixture. It
does not prove an ADDRULE body codec, privileged backend behavior, server
interoperability, or a native tunnel.
