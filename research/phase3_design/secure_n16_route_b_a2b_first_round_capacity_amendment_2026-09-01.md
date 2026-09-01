# Secure N16 Route-B first-A2B-round capacity amendment

**Date:** 2026-09-01  
**Stage:** ARS Stage 2 engineering gate  
**Status:** registered before the first canonical Route-B A2B-round run  
**Scope:** the first low-nibble A2B round only; the accepted bare-MR0
preflight phase, its digest, and its canonical evidence remain unchanged

## Trigger

The accepted Route-B MR0 run covered installed-resident validation and the
`ScaleDown -> observed ModUp/Trace -> C2S` prefix.  Composing the actual Gao
A2B round adds live construction of the 512-word special-b0 pair, its mask,
and the degree-46/shared-LUT operands before executing that prefix and kernel.
Those allocations are absent from the existing bare-MR0 preflight envelope.
Running the composition under that envelope would therefore be an
under-accounted live dispatch.

The special-b0 key plan was derived without encoding or HE execution.  Its
exact rotations are `[1, 2, 3, 2044]`; including the real-projection
conjugation, its Galois elements are `[5, 25, 125, 89745, 131071]`.  Every
element is already contained in the frozen 38-key Route-B inventory, so this
amendment changes no cryptographic parameter or evaluation-key set.

## Registered phase

A distinct `a2b-first-round` capacity phase is added.  It reuses only named,
digest-sealed estimates from the accepted combined L11 plan and deliberately
uses the plan-wide bounds for all fourteen compiled transform polynomials,
both masks, all transform specifications, and all three polynomial operands,
although the first round constructs a strict subset.

| Incremental component | Bytes |
|---|---:|
| resident validation: maximum encoded-factor envelope | 872,415,232 |
| all transform specifications | 18,874,368 |
| fourteen compiled transform polynomials | 205,520,896 |
| two Q-only masks | 20,971,520 |
| three polynomial operands | 69,376 |
| four maximum-factor baby-step pre-rotated ciphertexts | 109,051,904 |
| one `N`-coefficient scratch buffer | 524,288 |
| **pre-guard incremental peak** | **1,227,427,584** |
| minimum guard | 536,870,912 |
| **guarded requirement** | **1,764,298,496** |

Admission remains strict:

`current system use + 1,764,298,496 < floor(4 * total physical memory / 5)`.

The original `preflight` phase remains exactly
`981,991,424 + 536,870,912 = 1,518,862,336` bytes and continues to validate
the already published bare-MR0 evidence.  The new phase has its own sealed
plan digest and runtime operation label.

## Dispatch and failure rules

1. `RunFirstSparseMR0` must continue to select the original `preflight`
   phase; the composed first A2B round must select `a2b-first-round`.
2. The phase sample, canonical plan reconstruction, and admission decision
   precede resident validation, transform compilation, mask encoding, and HE.
3. A capacity block performs none of those operations and leaves the
   installed-unverified lineage available.
4. After the exclusive lineage transition, any resident, compilation, key,
   state, scale, kernel, or report failure is terminal and clears the private
   installed evaluator.
5. The composed report must bind the new capacity-plan digest, the exact
   special-b0 rotation/key plan, all thirteen ciphertext boundaries, and the
   Gao operation ledger.
6. This phase authorizes one A2B round, not the second nibble round, a complete
   8-bit A2B conversion, comparator/tree correctness, security, or performance.

