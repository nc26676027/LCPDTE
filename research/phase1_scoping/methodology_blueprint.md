# Methodology Blueprint

## Research Paradigm

**Selected:** Pragmatist with a positivist measurement core.

**Justification:** Primary RQ asks for the Pareto-efficient implementable designs inside a preregistered design space, not an unbounded global optimum. Answering it requires formal algorithm/complexity analysis, source-faithful reproduction, empirical cryptographic systems measurement, and engineering design iteration. Claims about correctness and performance are treated as observable and falsifiable; design choices remain conditioned on available Lattigo/OpenFHE interfaces and host constraints.

## Method

**Type:** Mixed technical method.

**Specific method:** Primary-source document/code analysis + replication study + controlled comparative benchmarking + design-science implementation.

**Justification:**

- Document/code analysis recovers the exact algorithms, security assumptions and cost models.
- Replication tests whether reported behaviors can be obtained from pinned upstream artifacts.
- Controlled benchmarking answers comparative cost questions.
- Design science is required because the Lattigo integer layer and radix-aware tree evaluator do not yet exist.

## Data Strategy

**Data type:** Secondary source material plus primary experimental measurements.

**Sources:**

- Primary papers: CCS 2026 private decision-tree paper and ePrint 2026/233.
- Authoritative code: paper-linked `thrudgelmir/LCPDTE`, its verified ancestry/README-only difference from the local `nc26676027/LCPDTE` audit pin, official Lattigo v6.1.1 plus local patch diff, and pinned `fhe-simd-alu` commit/submodules.
- Local workloads: deterministic synthetic trees; committed depth-8/10/12 XGBoost models, inputs and prediction oracles; exhaustive small `Z_{2^n}` domains; seeded randomized integer vectors.
- Measurements: wall-clock, peak resident memory, operation counters, levels/scales, rotations, ciphertext/key sizes, bootstrap count, failure rate and prediction match rate.

**Sampling:**

- Exhaustive enumeration where bit width and slot count make it tractable.
- Fixed seeded randomized tests for larger widths and batched slots.
- Secure tree depths are frozen as `{2,4,6,8,10}` with `12` as a stretch point; R0 radix values are `{2,4,8,16}`. Any extra point is labeled exploratory and excluded from the preregistered Pareto decision.
- Run one untimed warm-up followed by seven timed repetitions. Execute one benchmark process at a time with fixed `GOMAXPROCS`/OpenMP settings and no concurrent build. If `IQR/median > 10%`, expand to 15 repetitions rather than selecting favorable runs.
- Per-run timeout is two hours for Core/Extended secure configurations and eight hours for Stretch. A preflight estimate above 80% of physical RAM is marked resource-infeasible and not launched; timeout/OOM/skipped cases remain in the raw result table.

**Time frame:** Software/repository states are pinned at experiment time. New upstream changes are excluded unless deliberately introduced as a separately versioned comparison.

## Analytical Framework

### A. Source-faithfulness matrix

For every claimed primitive/protocol step, record:

1. paper section/algorithm/equation;
2. authoritative source file/function;
3. local Lattigo function or explicit missing implementation;
4. semantic invariants;
5. theoretical cost;
6. measured cost and validation evidence.

### B. Representation and correctness analysis

- Define integer domain, canonical residue interval, signedness, scale, rounding map and admissible approximation error.
- Prove or test closure and wraparound for each operator.
- Distinguish deterministic approximation bounds from probabilistic bootstrap failure.
- Verify encrypted outputs against independent plaintext modular arithmetic.

### C. Controlled implementation sequence

1. Pin sources and preserve the four existing Lattigo patches.
2. Reproduce upstream smoke tests/behavior vectors.
3. Implement a public `Z2NValue`/`IntegerEvaluator` seam one primitive at a time.
4. Replace only the binary comparator while retaining existing packing/traversal.
5. Add integer packing and fused selection variants.
6. Implement `RadixTree`/`RadixTreeState` separately from the binary baseline.
7. Run matched end-to-end and ablation experiments.

### D. Cost model

For each design, derive and measure:

- multiplicative depth and consumed modulus levels;
- ciphertext-ciphertext/plaintext multiplications;
- relinearizations, rescales, rotations and conjugations;
- bootstraps and multi-output LUT evaluations;
- live ciphertext/path-state cardinality;
- actual marshalled `online_request_bytes`, `online_response_bytes`, `setup_public_key_bytes`, `setup_eval_key_bytes`, and `setup_bootstrap_key_bytes` at their real serialization levels;
- latency and peak memory.

The model will explicitly separate comparison, active-node selection, path-state update, leaf selection and refresh costs. This prevents a square-root state bound from being reported as a square-root total runtime bound without support.

### E. Tree-equivalence framework

- Binary comparator substitution must preserve every node decision.
- R0 radix compilation combines at most `{1,2,3,4}` consecutive binary levels into radix `{2,4,8,16}` while preserving all original predicates and leaf mapping. For a group beginning at depth `d`, freeze `h=min(g,D-d)`, `S=2^d`, and `K=2^h-1`; the final partial group is costed at its actual `h`, without uncharged padding. Establish equivalence symbolically or exhaustively over the declared quantized domain, then verify the full committed input set as regression evidence.
- R0 execution is registered separately as (a) `R0-Sequential`: `h` dependent blind selections and CT--CT comparisons, (b) `R0-Eager-Active-CTCT`: `K` width-`S` attribute and threshold selections followed by `K` CT--CT comparisons, (c) `R0-Eager-All-CTPT`: all `S*K` CT--server-plaintext comparisons followed by encrypted result selection, and (d) `R0-FusedLUT`: a root same-feature finite-domain LUT or, below the root, all `S` LUTs plus selection or a proved and fully charged global state-aware LUT. Every schedule reports physical comparator streams, operand provenance, refresh/bootstrap, packing and selector cost; structural grouping alone is not an HE speedup.
- R1 covers every accuracy-changing retraining, threshold change, quantization or pruning and is never pooled with R0.
- Structural savings are decomposed from HE-operator savings through ablations.

### F. Statistical summary

- Functional correctness: exact pass/fail counts, maximum residue/rounding error and confidence interval for observed failure probability where applicable.
- Runtime/memory: median, minimum/maximum and IQR across repeated runs; host and process isolation documented.
- Scaling: empirical curves against derived operation formulas; no extrapolated point labeled as measured.

### G. Security and protocol comparability

- Freeze the two-party semi-honest roles, public metadata, output leakage, and offline/online boundary defined in the Research Question Brief.
- For every secure-performance point, archive the complete parameter tuple and run one pinned security-estimator procedure over the total modulus chain. No unverified parameter point enters the secure Pareto frontier.
- Report setup/evaluation-key traffic separately from online encrypted input/output traffic.
- Treat OpenFHE as a semantic/vector oracle. Its WSL latency is not compared with native-Windows Lattigo latency unless both are rebuilt and run under a matched OS, compiler, thread policy and hardware allocation.

### H. Integer acceptance protocol

- Widths: `{8,16,32,64}`; width 128 is exploratory only. Interpretations: unsigned raw interval `[0,2^n-1]` and two's-complement interval `[-2^(n-1),2^(n-1)-1]` over the same raw residues; overflow is modulo `2^n`.
- For each mode define codeword spacing `d_min`, unique-decoding radius `R=d_min/2`, measured error `E`, normalized error `rho=E/R`, and remaining margin `1-rho`. Require `rho<1` and exact decoded residue/Boolean agreement; theorem-specific inequalities are separate gates.
- Exhaust tractable domains/pairs for `n<=8`; for larger widths, test three fixed seeds and at least `2^15` boundary-heavy vectors per operator/width.
- Define a bootstrap failure as any oracle mismatch. Require zero observed mismatches for acceptance and publish the one-sided 95% binomial upper bound; do not infer a cryptographic failure bound from empirical zero failures.

## Tools

- Go 1.23.11 and vendored/patched Lattigo v6.1.1 for the target implementation.
- Ubuntu WSL2 GCC/G++/CMake environment for the OpenFHE reference build.
- Git hashes, submodule hashes and file hashes for provenance.
- Go tests/benchmarks and deterministic CLI experiment wrappers.
- Primary PDF extraction plus rendered-page inspection for equations, algorithms, tables and footnotes.
- OS/process tools for time and peak-memory measurement.

## Validity Criteria

| Criterion | Strategy |
|---|---|
| Construct validity | Operational definitions for reproduction, exact-modular correctness, security target and matched semantics; no reliance on README labels alone. |
| Internal validity | One-variable ablations, fixed parameters/workloads, independent oracles, warm-up and repeated runs. |
| External validity | Multiple bit widths, tree depths, batch sizes, radix values, synthetic and committed XGBoost workloads. |
| Implementation validity | Red-green vertical slices at the three public seams; upstream conformance vectors; error propagation and invariant checks. |
| Reproducibility | Pinned commits/submodules, patch manifest, environment snapshot, stable commands, raw machine-readable results and hashes. |
| Security validity | Performance/security claims restricted to explicitly justified 128-bit parameter sets; demo parameters labeled non-secure. |
| Claim validity | Every algorithm/performance assertion linked to paper, code, test or raw result; inference and hypothesis labeled separately. |

## Limitations by Design

- The current host has 31.3 GiB RAM; configurations reported by the README at about 34 GiB or above will not be launched without a safe feasibility check. Missing exact high-memory runs remain explicit gaps.
- Windows and WSL2 timings are not directly comparable with the paper's Linux/Ryzen 7900X/128-GiB environment. Cross-paper conclusions emphasize matched local comparisons and operation counts.
- The local repository has no enforced client/server boundary, so transport and setup-key communication require separate modeling or a later protocol harness.
- Numerical binary splits are the supported baseline; missing-value and categorical split semantics require separate implementation before general XGBoost coverage can be claimed.
- The two focal records are recent 2026 publications (LCPDTE: ACM CCS 2026; Gao--Zheng: CRYPTO 2026 major revision). Forward-citation coverage is immature, so any contribution statement remains corpus-bounded and is refreshed before submission.

## Ethical Considerations

- No human subjects, interviews, interventions or identifiable raw records are used.
- Public source licenses and attribution must be preserved; code is independently reimplemented when APIs are incompatible.
- Security and failure-probability limits will be reported plainly so benchmark configurations are not mistaken for deployable security.
- The work concerns privacy-enhancing computation. Dual-use risk is low and does not require operational harm-enabling detail beyond standard cryptographic implementation.

## IRB Plan

- IRB level: Not applicable; no human-subject interaction or identifiable personal-data analysis.
- Informed consent: Not applicable.
- Data de-identification: Use only committed derived arrays/models and synthetic data; do not reacquire raw credit-card records for this objective.
- Timeline: No IRB dependency.

## Reporting Standard

- No EQUATOR guideline directly governs cryptographic systems replication.
- Use an ACM-style reproducibility/artifact structure: environment, provenance, algorithms, commands, raw results, limitations and claim-evidence matrix. Exact current ACM policy wording will be verified from the official source before finalization.

## Preregistration

- Recommended: Internal protocol freeze, yes; public clinical/social-science preregistration, not required.
- Platform: Version-controlled experiment specification in this repository; OSF optional if the work becomes a formal empirical paper.
- Status: RQ, decision rule, threat model, R0/R1 split, widths, radix/depth grid, repetition/dispersion rule and completion gates frozen at Checkpoint 1. Exact source-derived parameter tuples and representation-specific decoding radii will be appended after paper extraction but before any comparative performance run.

## Completion Tiers

- **Core completion:** pinned-source analysis; reference smoke vectors; Lattigo `Z2N` representation and minimal compare/select/refresh operators; matched binary-tree evaluation; deterministic correctness suite; all locally feasible secure benchmarks.
- **Extended completion:** fused integer packing plus R0 semantics-preserving radix evaluator and ablations.
- **Stretch completion:** full D=12 and upstream-scale runs. A documented 80%-RAM preflight failure remains an explicit gap rather than silently substituting demo parameters.

## Design-Freeze Checkpoint Audit

- Primary decision: `sound after revision` — the method now answers a bounded Pareto RQ and freezes matched semantics, security comparability, correctness thresholds, timing rules and completion tiers before performance observation.
- Cross-model decision: unavailable — cross-model mode is disabled.
- Outcome: initial Devil's Advocate Checkpoint 1 returned `REVISE`; after incorporating all five Major findings, the independent re-check returned `PASS` with one non-blocking preregistration completion item to resolve before comparative timing.
