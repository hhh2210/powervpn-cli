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

## 2026-08-11 05:34 +0800 — one installed helper reachability probe passed

- Pre-state: official GUI and vendor-helper process counts were zero; the
  product reported `launchdObserved=true`, `inactiveConfirmed=true`,
  `activeCount=0`, `runs=19`, `probeAvailable=true`, and
  `preflightSafe=true`. Aggregate checks found no other VPN process.
- Action: ran exactly one arm64 product command,
  `powervpn helper status --probe --json`. It issued only the fixed read-only
  `get_version` request; it did not invoke Portal, SSH, or `start_connection`.
- Result: exit 0 in 1.70 seconds; `directXPCStatus=current_reachable`,
  `productState=ready`, `liveProbePerformed=true`, and
  `helperMutationRequested=false`.
- Post-state: launchd was again exactly inactive with `activeCount=0` and
  `runs=20`; vendor-helper and other-VPN process counts were zero. Default-route,
  DNS, and interface aggregate hashes matched the pre-state. The raw full route
  table hash changed once (an informational projection containing expiring
  entries); two subsequent canonical structural and persistent IPv4/IPv6
  projections were byte-stable one second apart. No retry was performed.
- Product conclusion: M1 now has a truthful current-helper reachability result,
  while the overall doctor remains blocked by
  `authorized_resource_provider_unavailable`. This probe does not make M2
  connection-changing execution eligible.

## 2026-08-11 05:54 +0800 — submitted-start cleanup P0 closed offline

- Core now transfers an opaque cleanup-only capability for the exact original
  XPC session when a submitted start ends in cancellation, timeout, generation
  mismatch or another non-acknowledged result. The capability can only submit
  fixed `stop_connection`, is exact-once, and cancels its session when
  abandoned.
- Product attempts that capability from cancellation-shielded cleanup before
  considering authenticated emergency cleanup. Reports distinguish
  `same_session_provisional_stop` from `same_lease_stop`; schema is now 6.
- Terminal/invalid sessions are sealed first. Their provisional attempt is
  truthfully unsent and the existing generation classifier decides whether one
  authenticated emergency stop is still safe; changed or unavailable state
  remains `cleanup_unproven` rather than targeting an uncertain helper.
- Independent review found no remaining P0/P1-product in this slice. Integrated
  targeted tests, the full package test run, strict Swift formatting, arm64
  product build, diff check and secret scan passed.
- Product operability: `scripts/build_and_run.sh` now provides one deterministic
  arm64 build-and-exec entry, defaulting to usage rather than a live command.
- Remaining supervisor blocker: the CLI's 120-second timer is a cooperative
  cancellation request, not an absolute end-to-end budget. A concrete next
  contract is locked: monotonic T0 after approval, mutation cutoff at 65s,
  control cleanup by 73s, authorization close by 94s, after-state by 118s and
  report by 120s. It must be threaded through every stage and through a future
  cancellable provider attempt; no partial scaffolding was added.
- Exact next action: implement that coherent absolute-budget/provider-attempt
  contract. The independent installed-state blocker remains the absence of a
  lawful current-generation `vendor_once` resource provider.

## 2026-08-11 06:48 +0800 — absolute supervisor budget closed offline

- Product now creates one monotonic budget only after the fresh TTY approval.
  It stops new mutation at 65 seconds, completes control cleanup by 73 seconds,
  authorization close by 94 seconds, after-state verification by 118 seconds
  and final report classification by 120 seconds. M2 report schema is now 7;
  `deadline_exceeded` maps to exit 124, while `cleanup_unproven` retains exit 74.
- Core consumes the remaining budget rather than restarting fixed timeouts.
  Generation/preflight observation accepts a shrinking timeout, and one
  network capture owns a monotonic deadline across every fixed command. Zero,
  overflow, clock regression and deadline exhaustion start no later command
  and return value-free unavailable evidence.
- Authorization acquisition is a cancellable one-shot attempt. A cancel that
  wins before result permanently removes the provider operation; the explicit
  Portal adapter also gates its child task across create/install so cancellation
  cannot enter the provider through that gap. Native Portal remains injected
  only and is not the default production provider.
- The final `start_connection` check now occurs inside the snapshot borrow,
  immediately before synchronous submission. A stale relative timeout cannot
  cross the 65-second boundary. After submission, cancellation/deadline always
  enters cleanup with active-lease or provisional same-session authority.
- Cleanup generation observation is detached from inherited cancellation. Each
  stop, authorization-close and verification await is checked again against
  its absolute cutoff; late receipts are retained but cannot make cleanup
  verified. Stages that were genuinely not required are not falsely charged.
- Independent review first found two P0 races and one P1 cutoff-truth issue;
  deterministic counterexamples were added and the final re-review returned
  `NO_FINDINGS`. Root verification passed the full package test run, 27 focused
  budget/CLI tests, Product M2 86/86, Core budget 20/20, the arm64 product build,
  strict changed-file formatting, wrapper tests, diff checks and a 2.64 MB
  secret scan.
- No additional live helper probe, Portal request, credential read, TTY
  exchange, `start_connection`, SSH connection or network mutation ran.
- Remaining exact blocker: `authorized_resource_provider_unavailable`. No
  installed artifact is a lawful current-generation `vendor_once` handoff, so
  the production command still exits locally before approval and side effects.
