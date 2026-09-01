# Secure N16 Route-B live-capacity design audit

**Date:** 2026-09-01  
**Scope:** trusted physical-memory origin, dynamic peak fields, generation
freshness, state publication and side-effect ordering for Route-B  
**Verdict:** **PASS DESIGN — 0 Critical / 0 Major / 0 Minor**

## Frozen review inputs

| Artifact | SHA-256 |
|---|---|
| `secure_n16_route_b_auth_wire.md` | `BD7332CF726DF541C0E2252D712CB8549EF085C21768692515E0E7577B0B1C4E` |
| `secure_n16_route_b_two_stage_construction.md` | `1644707333DB195557878D1CCA8570C37F2355007E62CEBF7B0439F02847A898` |

This audit evaluates the design only. The current `route_b_auth_wire.go` still
contains fixture-frozen peak semantics and is therefore an implementation
target, not evidence that live Authority exists.

## Disposition of the first audit findings

| First-audit finding | Repair | Result |
|---|---|---|
| Snapshot-derived remaining margin and duplicate excess were frozen as builder invariants, rejecting a different honest admitted snapshot. | Four builder sizes remain static. `RemainingBelowLimitBytes` and `DuplicateDefaultExcessBytes=max(2,641,362,944-remaining,0)` are derived per sample. Zero excess is valid. No later gate compares dynamic values with a fixture or prior gate. | Closed |
| Caller-provided snapshot IDs and totals could fabricate host availability. | Every live entry obtains total/available physical bytes through an Authority-owned Windows/Linux OS adapter. Public live methods accept no capacity inputs. Authority adds a secret owner, one-shot generation and authenticated snapshot ID inside a private critical section. | Closed |

## Fresh audit checks

### Arithmetic and wire compatibility

- Static values remain `2,968,063,744`, `7,129,861,888`,
  `7,842,848,076`, and `2,641,362,944` bytes.
- Checked integer reconstruction of the canonical fixture gives
  `used=16,465,830,871`, `limit=26,894,226,214`,
  `projected=24,308,678,947`, `remaining=2,585,547,267`, and
  `duplicate excess=55,815,677`.
- The distinct admitted pair gives `used=16,426,213,376`,
  `limit=26,894,601,420`, `projected=24,269,061,452`,
  `remaining=2,625,539,968`, and `duplicate excess=15,822,976`.
- The existing audit fixture remains the byte golden; field order, widths,
  `RBAUTH-v1` record sizes and domain tag are unchanged. Only the sixth peak
  field's semantic name and validation become saturating and sample-derived.

### Trust, freshness and concurrency

- The OS adapter returns raw totals only. It cannot choose owner, generation,
  snapshot ID, report or permit.
- Authority reserves and validates each generation in one private sampling
  critical section and destroys the capability before return. The capability
  never enters a record or callback.
- Generations are globally unique, while a lineage requires only a strictly
  newer generation. Interleaved lineages therefore do not falsely require
  adjacent global generations.
- `AuthorizeBuild`, `BeginBuild`, `AuthorizeReady`, install and first-operation
  preflight each require a new sample. Only inert evidence survives a gate.
- Windows `GlobalMemoryStatusEx` and Linux `MemTotal`/`MemAvailable` semantics
  are exact; unsupported platforms and malformed/overflowing samples fail
  closed.

### Publication and side effects

- `BeginBuild`, Ready, install and preflight admit capacity and repeat any
  required pure preparation before their consuming CAS.
- Ready uses `private-uninstalled -> readying -> ready`; only the `readying`
  winner reads resident matrices or writes Ready anchors. This removes both
  loser-anchor pollution and state-before-anchor publication.
- Install's first artifact-state action is `ready -> installing`; preflight's
  resident read follows `installed-unverified -> preflighting`.
- A capacity-blocked attempt performs no preparation or side effect. An
  admitted CAS loser may already have sampled and run pure preparation, but it
  performs no encoder/DFT allocation, resident read, key generation, install or
  HE. The design and counter expectations now state this distinction exactly.

### Implementation reachability

- `secureprofile.GaoN16PackingL11CapacityPlan.Evaluate` already computes a
  report from an explicit value and can remain the OS-independent arithmetic
  core when called only with Authority-produced snapshots.
- The accepted RBAUTH byte grammar can be preserved while replacing
  `defaultRBAUTHPeakContract` equality with static-bound plus dynamic-formula
  validation.
- Legacy `GaoN16RouteBConstruction*` objects remain non-authoritative until
  migrated; no adapter can turn them into a live permit.
- The private test sampler supplies scripted raw totals only, allowing exact
  alternate-snapshot, threshold, error and interleaving tests without exposing
  a production injection seam.

## Residual implementation gates

The design PASS authorizes implementation of the sampler, dynamic RBAUTH
validation, `Authority`, live BuildSpec/Permit and state transitions. It does
not establish a live capability, artifact, key set, L11 allocation, measured
RSS, MR0, ciphertext correctness, performance or application security.
