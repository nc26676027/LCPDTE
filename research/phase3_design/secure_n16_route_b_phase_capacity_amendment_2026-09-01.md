# Secure N16 Route-B phase-capacity amendment

**Date:** 2026-09-01  
**Stage:** ARS Stage 2 engineering gate  
**Status:** registered after a blocked installed-preflight run and before any
successful canonical L11 MR0 result  
**Scope:** live-memory admission only; the physical-memory 80% boundary,
minimum guard, cryptographic parameters and HE circuit remain unchanged

## Triggering observation

The second canonical one-process L11 attempt completed the unique artifact
build, resident Ready validation, evaluation-key generation and prebuilt
evaluator installation. Its fresh preflight sample was
`total=33,618,251,776`, `available=13,602,926,592` and
`current-used=20,015,325,184` bytes. The gate then added the original
from-zero combined requirement of `7,842,848,076` bytes and blocked at a
projected `27,858,173,260` bytes versus the strict floored 80% limit of
`26,894,601,420` bytes. No MR0 HE dispatch occurred and no result row was
published.

That calculation counted the already resident artifact, 41 evaluation keys
and evaluator buffers a second time. The original combined plan remains the
correct `AuthorizeBuild` whole-lifecycle admission contract and the accepted
RBAUTH type-01/type-02 byte grammar remains frozen. It is not the incremental
allocation contract for later gates whose baseline already contains earlier
phases.

## Registered repair

Every consuming gate still obtains a fresh Authority-owned physical-memory
sample before preparation, resident access, key generation or HE. Each gate
now admits only the canonical incremental envelope that can be added after its
current lineage state. Every envelope is derived from the already sealed L11
capacity components; no measured favorable RSS value is substituted.

| Gate | Incremental components | Pre-guard bytes | Guard | Guarded bytes |
|---|---|---:|---:|---:|
| `AuthorizeBuild` | complete artifact + keys + evaluator + operation scratch | 7,129,861,888 | 712,986,188 | 7,842,848,076 |
| `BeginBuild` | full artifact-construction peak | 2,968,063,744 | 536,870,912 | 3,504,934,656 |
| `AuthorizeReady` | one maximum encoded-factor validation envelope + `N`-coefficient scratch | 872,939,520 | 536,870,912 | 1,409,810,432 |
| `Install` | Ready validation envelope + 38 DFT/Trace/conjugation keys + 3 fixed keys + evaluator buffers + four pre-rotated ciphertexts + scratch | 5,034,213,376 | 536,870,912 | 5,571,084,288 |
| first-operation preflight/MR0 | installed-resident validation envelope + four pre-rotated ciphertexts + scratch | 981,991,424 | 536,870,912 | 1,518,862,336 |

The validation envelope deliberately charges the full largest encoded factor
(`872,415,232` bytes), although the implementation rehashes it through a
bounded streaming writer and does not clone it. This preserves a conservative
allowance for preparation, allocator retention and resident scanning. The
guard remains `max(512 MiB, floor(incremental/10))`; admission remains strict:
`current-used + incremental + guard < floor(4*total/5)`.

At the blocked preflight snapshot, the amended canonical preflight projection
is `21,534,187,520` bytes, leaving `5,360,413,900` bytes below the same strict
limit. This arithmetic is a preregistered expectation, not a successful-run
claim.

## Evidence and failure rules

1. A distinct digest-sealed phase plan must bind the phase, base combined-plan
   digest, exact named components, policy and incremental requirement.
2. Runtime evidence must reconstruct the phase plan, report and permit from
   its snapshot; changing the operation, component set, requirement, guard or
   capacity binding must fail validation.
3. The original combined-plan digest and accepted RBAUTH type-01/type-02
   golden bytes must remain unchanged.
4. Capacity blocking must still precede preparation and every resident/key/HE
   side effect. Post-CAS failures remain terminal and clear private donors.
5. The canonical L11 experiment may be attempted again only after exact
   arithmetic, tamper, empirical-snapshot, gate-order, package, vet and
   existing golden tests pass.
6. If measured process peak reaches the strict 80% limit, phase arithmetic
   disagrees with its sealed components, or the repaired preflight dispatches
   an unobserved HE path, Route B remains blocked.

