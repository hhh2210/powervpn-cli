# R2 TLS evidence backlog

Status: deferred by `rescue-2-product-reset`; not an M1/M2 product gate.

The frozen evidence branch remains `rescue-state-machine` at
`b1908f2a08fa3c170dd4c6fac1fb76783bf0e470`. Its deterministic review bundle
and pending-review manifest remain historical inputs, not product approval.

Post-review fixes were preserved without moving the frozen branch:

```text
branch: rescue-r2-evidence-post-review-wip
commit: b14a4dc88e8fbfb291e7bd68d540fc8e2c2a042e
```

## Deferred findings

- Accept the legitimate value-free state where peer DER and verify rejection
  completed but the trust-evaluation deadline won before SSL reservation.
- Make result publication and signal/deadline handling leave exactly one
  terminal artifact; reject and clean `mv -n` destination collisions.
- Canonically sort shell-test manifest inputs and propagate `sort` failure even
  when it emitted partial output.
- Keep Swift and shell producer invariants aligned:
  duplicate verify implies metadata access attempted, Basic start implies SSL
  start, and an observed report cannot use an unavailable trust category.
- Publish completed trust evidence only with the winning captured event so
  cancel/timeout cannot observe a complete trust snapshot without its result.
- Serialize duplicate/ready invalid events and captured trust completion on the
  source queue. The archived production fix restores that ordering, but its
  final FIFO regression test still uses a fake source rather than driving
  `NetworkTLSTrustSource`; bind a future test to the production dispatcher.
- Reseal/re-review only if one of these issues prevents interpreting the single
  final M4 TLS experiment. Do not restart a review-bundle loop for M1/M2.

## Product impact

None of the items above prevents read-only product discovery, construction of
an in-memory helper snapshot, or a separately approved bounded
connect/disconnect experiment. A defect becomes active only if it causes one
of the five product blockers in the current `GOAL.md`.
