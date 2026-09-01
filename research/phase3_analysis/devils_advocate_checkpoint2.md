# Devil's Advocate Checkpoint 2

Date: 2026-08-29  
Scope: Stage 1 RQ, method, search/bibliography, paper-to-code maps, synthesis, design and benchmark manifests  
Independent verdict: `REVISE`  
Finding count: 0 Critical, 7 Major, 6 Minor

## Decision

The 15-source corpus supports a conditional, non-exhaustive technical synthesis, but Stage 1 is not ready for `PASS`. The defects are repairable by closing provenance and search records and by freezing experimental denominators. Sage's absence is a downstream security-estimation blocker, not a Stage 1 blocker.

## Major findings

1. **Search reproducibility and counterexample coverage.** `search_strategy.md` does not list the seven title/abstract exclusions individually and lacks combination/counterexample searches for multiway/radix HE trees, encrypted-index selection, overflow-correct CKKS integer comparison, and A2B PDTE. Remedy: record exact queries, dates, result-count availability, candidates and inclusion/exclusion reasons; retain a non-exhaustive scope unless evidence supports more.
2. **Official LCPDTE source provenance.** The paper names `thrudgelmir/LCPDTE`, whereas the local origin is `nc26676027/LCPDTE`. The pinned local commit appears author-produced and the official HEAD appears one README-only commit ahead, but this relationship is missing from the evidence record. The `Theta(p*2^D)` raw-operation result is a source audit, not a paper-page claim. Remedy: archive URLs, commits, ancestry/diff, and function-level code anchors alongside paper anchors.
3. **Integer correctness gate mismatch.** The RQ's `R/2` language conflicts with the manifest's unique-rounding conditions; width 4 appears only in one frozen grid; width 128 is not marked post-registration exploratory; canonical unsigned and two's-complement intervals are missing. Remedy: define codeword spacing, unique-decoding radius, normalized error and optional engineering margin once; reconcile widths and intervals.
4. **SIMD denominator conflict.** Integer input ciphertext reduction is query-dependent; Boolean full uses two half ciphertexts for the same `N/n` words, not 1,024 complete words per ciphertext; B-A2B's `N/w=16,384` saturation point is absent. Remedy: freeze physical-CT formulas and add the saturation workload and occupancy fields.
5. **R0 has no executable HE schedule.** Structural grouping alone does not reduce encrypted depth. Sequential active-path keeps `g` dependent comparisons; eager evaluation pays `2^g-1` predicates; fused LUT requires stated same-feature/domain preconditions and proof. Remedy: enumerate and charge these schedules; prohibit calling structural compilation an optimization.
6. **`RangeSafe` is not one physical operator.** `n+1` widening is unavailable directly for the root families and may map logical 32 bits to physical 64 bits, changing capacity and conversion rounds. Signed correction also adds sign extraction. Remedy: separate unsigned-widened, signed-no-overflow and signed-corrected variants and freeze logical-to-physical width mapping/cost.
7. **Communication objective lacks a result schema.** Request/response and setup keys are not separated or measured at actual levels. Remedy: require marshalled `online_request_bytes`, `online_response_bytes`, `setup_public_key_bytes`, `setup_eval_key_bytes`, and `setup_bootstrap_key_bytes`.

## Minor findings

1. Update the stale upstream build/run status in `source_verification.md` to the documented dependency/environment blocker.
2. Recount or soften evidence-count wording in the synthesis.
3. Remove categorical-digit R1 from current scope or mark it as a separate future scope.
4. Rename ambiguous “public threshold” API text to `ServerPlaintextThreshold`.
5. Freeze the exact forest sizes or mark `model-derived` as exploratory.
6. State whether quantum estimates are reporting-only or a hard gate, and freeze the parameter-to-estimator conversion script before results.

## Independent judgments

- OBO ciphertext--ciphertext correction: `PASS`.
- Higher radix: partial; no automatic speed claim, but R0 scheduling needs operationalization.
- SIMD amortization: partial; main batching condition is correct, Boolean denominator and saturation point need repair.
- Security estimation: honest `pending-estimator`; remains a downstream hard gate.
- Corpus adequacy: sufficient for design hypotheses/gaps, insufficient for exhaustive novelty.

## Strongest counter-argument

The apparent composition benefit may disappear when one operator graph charges encrypted-threshold selection, range-correct ciphertext--ciphertext comparison, physical packing, B-A2B occupancy and radix selection together. It is credible that every matched workload favors the bit-sliced baseline. Stage 1 establishes an experiment-worthy hypothesis, not the existence of an improvement point.

## Required disposition

Repair every Major item, record the disposition, and rerun Checkpoint 2 independently. Do not advance on the original `REVISE` verdict.
