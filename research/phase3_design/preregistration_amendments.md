# Pre-Benchmark Amendments

All amendments below were made on 2026-08-29 in response to Devil's Advocate Checkpoint 2, before any comparative latency/memory benchmark or secure Pareto result existed. They cannot be justified by a favorable measured outcome.

## A1 — supported word widths

Remove width 4 from the registered encrypted-operator grid. Gao--Zheng's committed root/vector families and the local machine-word API begin at width 8. Width 8 already permits exhaustive unary and all-pairs binary tests. Registered widths are now 8, 16, 32 and 64. Width 128 is exploratory only and cannot enter the preregistered Pareto decision.

## A2 — decoding metric

Replace the ambiguous “error below half of the unique-decoding radius” rule with one normalized rule. Let `d_min` be codeword spacing in the relevant normalized representation, `R=d_min/2` the unique-decoding radius, `E` the measured representation error, and `rho=E/R`. Correctness requires `rho<1` and exact oracle agreement. Report `1-rho` as the remaining normalized margin. The theorem-specific noise inequalities remain separate gates.

## A3 — SIMD saturation point

Add `q=16,384` for `N=2^16,w=4`, because one full B-A2B group contains `n/w` arithmetic ciphertexts and therefore `N/w` word evaluations. Freeze physical-ciphertext formulas and two occupancy dimensions rather than interpreting “per ciphertext” as “per query.”

## A4 — comparator variants

Replace the single `RangeSafe` label with separately costed same-width borrow, widened unsigned, signed-no-overflow and signed-corrected variants. Any logical-to-physical width change is an experimental factor that changes packing and conversion cost.

## A5 — communication accounting

Replace aggregate “ciphertext/key bytes” with actual-marshalling fields for online request/response and setup public/evaluation/bootstrap keys. Output ciphertexts are serialized at their real output levels.

## A6 — R0 execution schedules

This amendment supersedes the original three-label R0 schedule. For every group
beginning at binary depth `d`, freeze `h=min(g,D-d)`, `S=2^d`, and
`K=2^h-1`. Structural radix grouping alone is not an HE optimization. Register
four schedules separately:

1. `R0-Sequential`: `h` dependent blind selections and `h` CT--CT comparisons.
2. `R0-Eager-Active-CTCT`: `K` width-`S` attribute selections, `K` width-`S`
   threshold selections, and `K` CT--CT comparisons.
3. `R0-Eager-All-CTPT`: all `S*K` CT--server-plaintext comparisons followed by
   the complete encrypted active-supernode/result selector.
4. `R0-FusedLUT`: at `d=0`, one same-feature finite-domain LUT after an
   equivalence proof; at `d>0`, either all `S` supernode-specific LUTs plus
   selection or one proved global state-aware LUT with its full domain,
   packing, transform, rotation, refresh and selector costs.

Every result row reports `(d,h,S,K)`, comparison operand provenance, physical
comparator streams, refresh/bootstrap, packing, and selector cost. The older
combined `eager-candidate` label is ineligible for benchmark evidence.
