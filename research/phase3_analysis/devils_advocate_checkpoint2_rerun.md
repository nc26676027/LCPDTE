# Devil's Advocate Checkpoint 2 — Independent Rerun

Date: 2026-08-29  
Review mode: read-only independent rerun after the first DA2 revision  
Verdict: **REVISE**  
Counts: **0 Critical, 3 Major, 4 Minor**

Stage 1 was not released at this checkpoint. The findings below are preserved
as the pre-revision audit record; their dispositions belong in a separate file
so the original verdict is not rewritten after the fact.

## Prior-major closure check

| Prior item | Result | Independent finding |
|---|---|---|
| M1 counterexample-search reproducibility | Open | The 70-query supplement is rerunnable and honestly bounded, but omitted the generic PFE/private-program/oblivious-processor family and therefore missed HEGIDE. |
| M2 LCPDTE provenance/citation boundary | Artifact closed; guardrail reopened | The prose and provenance ledger separate paper claims from checkout counts, but `claim_intent_manifest.yaml` recombined them. |
| M3 integer-correctness gate | Closed | Widths, residue domains, decoding radius, boundary tests and exploratory-128 labeling are explicit. |
| M4 SIMD denominator and OBO operand type | Closed | Physical ciphertext counts, word/group occupancy and CT--CT OBO are frozen. |
| M5 executable R0 schedule | Open | `R0-Eager` simultaneously assumed a secret active supernode and CT--plaintext comparisons. |
| M6 range-safe comparator variants | Closed | Borrow, widening and sign-corrected/no-overflow routes are distinct contracts and costs. |
| M7 communication boundary | Closed | Online request/response and setup/evaluation/bootstrap keys are separate serialized-byte fields. |

## Major 1 — missing generic private-program counterexample family

The supplement concentrated on decision trees, encrypted indexes, comparators
and A2B. It did not query generic private function evaluation, private program
execution or oblivious processors. That omission missed Dumezy et al.,
*HEGIDE: A MIMD Oblivious Processor for Private Function Evaluation over
CKKS*, ePrint 2026/1187 and ACM CCS 2026. Its official record states private
program and private data, discrete CKKS, an oblivious MIMD processor, arbitrary
word sizes/instructions and an OpenFHE proof of concept. Its full paper also
contains an end-to-end private depth-4 binary decision-tree benchmark.

Required closure:

1. add a dated generic PFE/private-program/oblivious-processor query family;
2. inspect HEGIDE's full threat model, integer representation, control-flow
   treatment, bootstrap/cost boundary, decision-tree benchmark and code status;
3. record whether it is a baseline, surrounding prior art or excluded;
4. disposition ePrint 2026/1631, 2026/732 and 2026/1026;
5. replace every broad `innovation gap`, `closest`, `first` or absence statement
   with a frozen-corpus candidate-composition statement.

## Major 2 — inconsistent R0-Eager operand model

Below the root, the active supernode is encrypted state. Evaluating only its
`2^g-1` predicates requires encrypted feature/threshold selection and CT--CT
comparison. Keeping CT--server-plaintext comparisons instead requires
evaluating every possible supernode at that grouped depth and then selecting
under encryption. `R0-FusedLUT` has the same encrypted function-identity
problem.

Required closure: split the two eager schedules, state per-group candidate and
selector widths, physical ciphertexts, refresh/bootstrap counts and dependency
depth, and make fused LUTs below the root ineligible unless all functions are
evaluated or a global state-aware LUT is proved and fully charged.

## Major 3 — claim-intent evidence laundering

The main manifest combined the paper's key-switch/relinearization bound with a
checkout-derived tensor/addition count while listing only the paper reference.
It also labeled engineering adaptations and implementation hypotheses as
ordinary theoretical claims.

Required closure: split paper and pinned-source claims; include commit,
file/function and derivation for source counts; retain explicit
`engineering inference`, `adaptation claim` and `implementation hypothesis`
labels; add a prohibition against using a paper citation alone for a checkout
operation count; and add a HEGIDE novelty gate.

## Minor findings

1. Kim's row still said preprint despite the official TCHES 2025 status, and
   the 15-source historical synthesis was mixed with the 22-source updated
   preprint count.
2. The methods blueprint called the focal works preprints/conference artifacts
   even though their official records identify CCS 2026 and CRYPTO 2026.
3. `reproducible search` was too strong without result snapshots, ranks and a
   query-to-candidate map; `rerunnable bounded search` is the supportable term.
4. The preregistration files remained untracked and therefore had to be frozen
   by content hash and commit before any comparative benchmark.

## Strongest counterargument

The project may remain a careful composition study rather than an algorithmic
advance. HEGIDE already carries encrypted programs and data through a discrete-
CKKS processor and directly evaluates a private decision tree. LCPDTE's OBO
reduces selected expensive operations but retains node-proportional raw
selection work, while Gao's B-A2B advantage depends on high utilization. Secret
supernode selection, wider radix selectors, bootstraps and packing holes may
consume the apparent logical-depth saving. Only a range-correct implementation,
complete HE schedule, matched secure parameters and a measured Pareto gain can
support a stronger contribution claim.

## Primary records used by the rerun

- <https://eprint.iacr.org/2026/1187>
- <https://eprint.iacr.org/2026/1631>
- <https://eprint.iacr.org/2026/732>
- <https://eprint.iacr.org/2026/1026>
- <https://eprint.iacr.org/2026/1263>
- <https://eprint.iacr.org/2026/233>
- <https://eprint.iacr.org/2025/066>
