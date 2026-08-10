---
title: PowerVPN Native Rescue MVP
goal_version: rescue-2-product-reset
status: active
updated: 2026-08-10
repository: /Users/larry_1/Opensource/powervpn-cli
strategy: product-first vertical slice over installed vendor helpers
current_milestone: M1-helper-control-vertical-slice
immediate_next: produce-one-usable-connect-disconnect-path
assurance_mode: development
review_budget: one review pass per milestone
evidence_branch: rescue-state-machine
product_branch: rescue-mvp
---

# PowerVPN Native Rescue MVP

## 1. Product objective

Build a native arm64 macOS client that replaces the official PowerVPN GUI for
normal daily use while continuing to use the installed vendor tunnel helpers
as the tunnel core.

The first usable product is not required to replace every vendor component.
It must let the user, with the official GUI closed:

```text
open the native client
select one known resource
connect
see truthful status
disconnect
```

A fresh SSH connection through the selected resource is the primary end-to-end
proof. Full native portal onboarding, recovery automation, packaging and a
polished menu-bar UI are later milestones.

## 2. MVP definition

MVP PASS requires all of the following:

- an arm64 `powervpn` executable runs on macOS;
- PowerVPN GUI is not running while the connection is in use;
- the client can discover or load one authorized resource without asking the
  user for gateway, PSK, VIP, route, map ID or opaque protocol material;
- the client can issue one bounded `start_connection`;
- a new SSH connection receives a banner through the VPN;
- `powervpn status` distinguishes at least:
  `signed_out`, `ready`, `connecting`, `connected`, `disconnecting`,
  `disconnected`, `blocked`, and `failed`;
- `powervpn disconnect` tears down the resource;
- default route, DNS, Surge state and unrelated interfaces are not left in a
  changed state after disconnect;
- no credential, cookie, PSK or complete XPC snapshot is printed, committed,
  placed in argv/environment, or written to an ordinary file.

The MVP may still require the official PowerVPN installation, Rosetta and
vendor helpers.

### One-time onboarding allowance

For the fastest Rescue MVP, one-time authentication through the official
client is allowed during development if, and only if:

- the official GUI is not required during ordinary connect/disconnect use;
- no credential or replayable secret is scraped from process memory or logs;
- the native client consumes only a legally available installed profile,
  helper state, or an authenticated response produced by its own code;
- this limitation is shown truthfully as `onboardingMode=vendor_once`.

The final product target remains native username/password login, but onboarding
must not block proving the helper-control vertical slice.

## 3. What is frozen

The existing R2 TLS evidence work is preserved on `rescue-state-machine`.
It is a research and hardening asset, not the active product-development
critical path.

Do not delete it. Do not continue fixing its manifest, deterministic ZIP,
closed evidence schema, review lineage, PID-monitor or terminal-artifact edge
cases unless one of those defects directly prevents interpreting the final
bounded TLS experiment.

Record all remaining evidence-only findings in:

```text
docs/debt/R2_TLS_EVIDENCE_BACKLOG.md
```

They do not block the Rescue MVP.

## 4. Non-goals before the first usable connection

The following are explicitly deferred:

- proof-grade, byte-exact live manifests for every local development run;
- repeated independent review of each evidence harness revision;
- deterministic review ZIPs;
- complete formal closure of diagnostic JSON schemas;
- exact historical-attempt lineage for ordinary development runs;
- full sleep/Wi-Fi/helper-crash recovery;
- LaunchAgent, installer, notarization and distribution;
- polished SwiftUI;
- replacement of vendor helpers or removal of Rosetta;
- native strongSwan/IKEv1 reimplementation.

A generic `--insecure` TLS mode remains forbidden. If strict system trust is
incompatible with the deployed portal, stop and make an explicit product
security decision: retain the vendor-onboarding limitation, or design a
separately reviewed certificate/SPKI pinning policy with out-of-band
verification. Do not silently disable peer or hostname verification.

## 5. Development safety boundary

A development live run requires:

- an explicit user confirmation immediately before a server request,
  `start_connection`, `stop_connection`, route/utun change, or helper fault;
- a bounded timeout;
- a before/after snapshot of default route, DNS, interfaces, utun and relevant
  helper processes;
- a guaranteed disconnect/cleanup path;
- no secrets in logs or retained fixtures.

A byte-exact manifest is not required for each local development run.
Release-grade evidence and reproducibility return after the vertical slice
works.

Only these issues block the active milestone:

1. credential or session leakage;
2. uncontrolled or unbounded helper/network mutation;
3. inability to disconnect or restore network state;
4. code that can start the wrong resource;
5. a defect that prevents the end-to-end connection from being diagnosed.

Instrumentation consistency, report cosmetic correctness, deterministic hash
ordering and review-bundle publication are backlog items unless they trigger
one of the five blockers above.

## 6. Milestones

### M0 — Preserve and branch

- leave `rescue-state-machine` and its current review bundle intact;
- create `rescue-mvp` from the best reusable production-code commit;
- copy remaining R2 review findings into the evidence backlog;
- install this file as the active `GOAL.md`;
- do not alter historical fixtures.

PASS when both branches are clean and recoverable.

### M1 — Helper-control vertical slice

Implement or expose:

```text
powervpn doctor --json
powervpn helper status --json
powervpn resources --json
powervpn snapshot --dry-run --json
```

The commands must identify:

- installed PowerVPN version and helper availability;
- direct XPC reachability and helper generation;
- the source of resource/profile data;
- whether enough material exists to construct one complete vendor snapshot;
- the exact first missing field if it does not.

Do not build another generic evidence harness. Use ordinary structured
development logs with secret redaction.

PASS when the code can construct a complete in-memory snapshot for one
authorized resource, or returns one concrete product blocker.

### M2 — One-resource live connection

After explicit approval:

1. ensure the official GUI is closed;
2. select one authorized resource;
3. send one complete `start_connection` snapshot;
4. wait under a bounded timeout;
5. prove a fresh SSH banner;
6. report status;
7. send `stop_connection`;
8. verify route/DNS/interface/utun/helper cleanup.

No automatic retry. No recovery actor. No menu-bar UI.

PASS is the first usable Rescue product.

If this fails, produce only:

```text
last good state
first bad event
helper reply or timeout class
network state delta
cleanup result
next single experiment
```

Do not start a review loop.

### M3 — CLI MVP

Implement:

```text
powervpn connect <resource>
powervpn status --json
powervpn diagnose --json
powervpn disconnect
powervpn logout
```

Add clear terminal output and stable exit codes. The default path must not
require protocol material from the user.

PASS when the user can perform an ordinary work session without the official
GUI.

### M4 — Native portal completion

Return to native username/password onboarding.

Run at most one final credential-free TLS diagnostic from the frozen R2 lane.
Then make a terminal decision:

- system trust compatible: complete one native login/resource-list flow;
- system trust incompatible: keep vendor-onboarding MVP or approve a separate
  pinning design;
- still inconclusive: stop the diagnostic lane and use a different transport
  or instrumentation design.

Do not create attempt 4 merely by adding more booleans, hashes or shell gates.

### M5 — Reliability

Add:

- actor-owned connection state;
- generation fencing;
- bounded reconnect;
- path-change handling;
- helper-crash handling;
- session-expiry behavior;
- manual-disconnect suppression.

PASS after one controlled test of each fault class and successful cleanup.

### M6 — Menu-bar daily driver

Create a small native menu-bar app over the proven CLI/core:

- resource picker;
- Connect/Disconnect;
- concise status;
- authentication prompt;
- notifications;
- optional Keychain storage;
- launch-at-login only after reliability is proven.

The UI must call the same tested core rather than duplicate protocol logic.

### M7 — Release hardening

Only now restore:

- deterministic evidence bundles;
- release manifests;
- full secret scanning;
- signing/entitlements review;
- packaging and notarization;
- broad regression and recovery matrices.

## 7. Review policy

Each milestone receives at most one integrated review.

A finding blocks only when it is:

- P0: secret exposure, destructive state change, privilege/signing violation,
  or cleanup failure;
- P1-product: prevents the milestone's end-to-end behavior or makes its state
  materially untruthful.

Everything else is recorded and deferred.

Do not perform review-of-review, byte-level resealing cycles, or repeated
repo-wide audit before the milestone produces a user-visible behavior.

Time-box diagnosis:

- 90 minutes without new end-to-end information: change the experiment;
- two failed experiments with the same observable outcome: stop that lane;
- no milestone may spend more implementation time on its harness than on the
  production path it is supposed to exercise.

## 8. Progress report

At the end of each work session, report only:

```markdown
User-visible capability:
Production code changed:
Live result:
Current blocker:
Cleanup status:
Deferred debt:
Next end-to-end action:
Approval required:
```

Test counts and manifest hashes are secondary. They must not be presented as
product progress unless they unlock a new user-visible capability.

## 9. Immediate steering message

```text
Stop the R2 evidence review/fix loop. Preserve it unchanged on
rescue-state-machine and move all remaining evidence-only findings to
docs/debt/R2_TLS_EVIDENCE_BACKLOG.md.

Create or switch to rescue-mvp and adopt this GOAL.md. The active objective is
one GUI-free, one-resource connect/status/disconnect vertical slice using the
installed vendor helpers. Do not work on deterministic review bundles,
manifest lineage, evidence-schema edge cases, repeated independent reviews,
recovery, LaunchAgent, notarization or polished UI.

First implement M1: doctor/helper status/resources/snapshot --dry-run. Reuse
existing production modules. Report the exact missing field if a complete
snapshot cannot yet be built.

Then, after explicit user approval, execute one bounded M2 live connection:
start one authorized resource, verify a fresh SSH banner, stop it, and prove
cleanup. A product-safety defect may block. Evidence-harness correctness that
does not affect the live operation or its interpretation must be logged as debt
and must not restart the review loop.

Stop only after either:
A. the first usable connect/disconnect path works; or
B. one concrete architectural blocker is demonstrated.
```
