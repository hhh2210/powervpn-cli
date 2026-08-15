# Autonomous PowerVPN handoff

Operating window:
2026-08-11 05:14–06:49 +0800, unattended local product work under the attached
authorization. One read-only installed helper probe was used; no M2 connection
attempt was eligible.

Final commit / branch:
Product commit `01c954334e0a8af136c9f3b37034078652b9f80a` on `rescue-mvp`.
The branch is local-only and was not pushed.

User-visible capability:
The arm64 CLI has truthful passive M1 status, one explicit bounded helper
reachability probe, a deterministic build/run wrapper, and a strict M2
connect-once surface. M2 now owns a staged monotonic supervisor budget and
submitted-start cleanup authority, but the default provider gate deliberately
prevents any connection-changing execution.

Commands that now work:

- `powervpn doctor --json`
- `powervpn helper status --json`
- `powervpn helper status --probe --json`
- `powervpn resources --json`
- `powervpn snapshot --dry-run --json`
- `scripts/build_and_run.sh <exact powervpn arguments>`; no arguments prints
  usage after an arm64 build.
- `powervpn m2 connect-once --resource-display-name <exact> --ssh-target
  <thu21|thu52> --json` parses and supervises the exact transaction contract,
  but the installed default returns exit 69 before approval or side effects
  because no authorized provider exists.

Live end-to-end result:
M1 helper reachability passed once: fixed `get_version`, exit 0,
`current_reachable`, launchd returned from inactive run 19 to inactive run 20,
and no Portal/start/SSH/network action occurred. M2 was not run live and the
project is not yet a usable VPN.

Current exact blocker:
`authorized_resource_provider_unavailable`. The installed PowerVPN app exposes
no lawful current-user, current-generation, scoped and erasable `vendor_once`
resource handoff. Its signed `resource.xml` is build-time template material,
not an authorization artifact, and is intentionally rejected.

Cleanup result:
The one helper probe ended with no GUI/vendor/other-VPN process and charon
exactly inactive. Default-route, DNS and interface aggregates matched the
pre-state; later canonical structural and persistent route projections were
stable. The final offline budget slice launched no real helper/XPC, Portal,
SSH or network mutation and left no cleanup work running.

Production code changed:

- Explicit fixed-wire helper reachability with cancellation and final
  generation truth.
- Opaque same-session provisional stop authority for every submitted start
  that fails before yielding an active lease.
- One monotonic M2 T0 with mutation/control/authorization/verification/report
  cutoffs at 65/73/94/118/120 seconds and schema v7 deadline reporting.
- Dynamic Core command timeouts under one capture deadline; zero, overflow,
  clock regression and expiry fail closed.
- One-shot cancellable authorization attempts, a Portal create/install gate,
  an in-borrow final mutation check, cancellation-shielded cleanup observation,
  and post-await cutoff validation that preserves late receipts without
  claiming cleanup success.
- Deterministic arm64 `scripts/build_and_run.sh` wrapper.

Focused tests/builds:

- Final root focused budget/CLI run: 27/27 passed.
- Product M2: 86/86 across 17 suites passed.
- Core budget/observer set: 20/20 passed.
- Full `swift test`: passed.
- `swift build --arch arm64 --product powervpn`: passed; output is Mach-O arm64.
- Strict formatting of every changed Swift file, ShellCheck, wrapper tests,
  `git diff --check`, independent P0/P1 review and the 2.64 MB secret scan:
  passed. Final independent verdict: `NO_FINDINGS`.

Deferred evidence debt:

- No lawful production `vendor_once` provider and therefore no authorized M2
  resource, active-path proof or live cleanup measurement.
- The 120-second guarantee requires a future provider to honor the
  bounded/cancellable contract. `SIGKILL`, an uninterruptible kernel wait or a
  dependency that violates that contract cannot be made cleanup-safe by a hard
  process kill.
- Native username/password Portal onboarding remains explicitly injected only;
  its earlier `tls_rejected` evidence was not retried or bypassed.
- M3 long-lived connect/status/disconnect remains out of scope.

Uncommitted files:
None after this handoff's docs-only local commit.

Superseded product-direction note (2026-08-12): the recommendation below is
historical; the official client is discontinued and frozen, there is no
current-generation official handoff route, and active work uses it only as a
read-only static protocol oracle while native compatibility remains open.

Next single product action:
Obtain an official authorized-resource handoff, or make and separately review
the product-security decision for a native onboarding path; then implement one
source-neutral provider behind the existing bounded lease contract and rerun
all offline gates.

Human action required, if unavoidable:
Vendor/administrator support or an explicit product-security decision is
required to supply a lawful authorization source. After that code is offline
green, Larry must give a fresh approval naming one exact resource display name
and one SSH target immediately before the first M2 live transaction. No action
is required now.
