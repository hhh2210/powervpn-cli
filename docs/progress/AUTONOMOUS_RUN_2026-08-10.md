# Autonomous PowerVPN product sprint

## 2026-08-11 05:14 +0800 — resumed unattended window

- Start commit: `ca44f6f44485de1832111dc6828e2ab286e976f5`
- Branch: `rescue-mvp` (clean, equal to `origin/rescue-mvp` at resume)
- Active milestone: M1 truthfulness completion, then the smallest M2-enabling
  product work that does not require credentials or ambiguous resource data.
- User-visible capability: arm64 `powervpn` provides `doctor`, `helper status`,
  `resources`, `snapshot --dry-run`, and a fail-closed `m2 connect-once` path.
  The default provider exits locally with
  `authorized_resource_provider_unavailable` before runtime invocation.
- Current hypothesis: M1 still lacks an explicit bounded direct-XPC reachability
  probe even though the transport exists. Adding a deliberate probe surface can
  close that truthful product gap without inventing resource material.
- Exact next action: inspect the existing Core XPC/version transport and Product
  readiness injection seams; implement and synthetically verify an explicit
  `helper status --probe --json` route if it can remain bounded, value-free, and
  incapable of `start_connection`.
- Live boundary: the attached standing authorization is active until
  2026-08-11 12:00 +0800, but no connection-changing action is eligible unless
  one exact authenticated resource and an agent-independent cleanup path are
  both proven. No credential, GUI, Keychain, TCC, interactive sudo, fixture, or
  placeholder value may be used.

## 2026-08-11 05:31 +0800 — explicit helper probe implemented offline

- Product capability: `powervpn helper status --probe --json` now routes to one
  explicit, fixed-service, exact `get_version` transaction. The passive
  `helper status --json` path remains observation-only and does not construct a
  probe.
- Safety contract: Core performs bounded launchd-generation observation and
  cold preflight before XPC, validates the reply against the launched helper
  generation, supports task cancellation, and returns a value-free final
  generation receipt. No caller can choose the service or request payload.
- Verification: the integrated helper/Product/CLI targeted set passed 44 tests;
  the full package test run passed; `swift build --arch arm64 --product
  powervpn` passed; strict formatting and diff checks passed. No real helper,
  XPC, network, Portal, SSH, or credential path has been invoked yet.
- Supervisor review: adding `SIGHUP` handling and a 120-second cancellation
  trigger improves cooperative teardown, but does not by itself prove the
  unattended contract. A P0 remains where a submitted start can lose its
  normal lease and, under an unclassified generation, send zero stop requests.
- Exact next action: preserve a same-session cleanup-only capability at the
  start submission linearization point, test every submitted failure path for
  an exact-one stop attempt, then reassess whether the read-only helper probe is
  eligible to run on the installed machine.
