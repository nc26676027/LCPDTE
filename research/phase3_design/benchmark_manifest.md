# Pre-Registered Benchmark Manifest

This file closes the remaining methodology-design items before comparative timing. Values marked `pending-estimator` are not eligible for a secure-performance claim. The Lattigo Gao-compatible tuple now has an exact unlimited-sample sensitivity transcript, but remains ineligible while its application-security decision is `INCONCLUSIVE`.

## Workload Grid

| Axis | Core | Extended | Stretch |
|---|---|---|---|
| word width | 8, 16, 32 | 64 | 128 exploratory only; excluded from Pareto decision |
| logical queries | 1, 32, 512, 2048, 8192 | 16384, 32768 | largest memory-safe full batch (exploratory) |
| tree depth | 2, 4, 6, 8 | 10 | 12 |
| forest size | 1, 2, 4, 8 | 16 | exploratory only; exact fixture/tree count named in each row |
| R0 radix grouping | 1, 2 | 3, 4 | none |
| R1 radix | 4 | 8 | 16 |

All methods evaluate the same selected queries and public feature order. R0 methods use the identical padded binary model and leaf outputs.

## Eligible Operator Variants

1. `LCPDTE-bit-GEQ`: current adjacent-bit complex packing and `CmpGeBits`.
2. `Gao-A2B`: triangle subtraction, full Algorithm-1 A2B, sign extraction.
3. `Gao-BA2B`: full Algorithm-2 batches of exactly `n/4`; utilization reported.
4. `A2Sign`: exploratory sign-only output with all necessary `LUT_ID` peeling.
5. `UnsignedBorrow`: same-width A2B/Boolean borrow construction.
6. `UnsignedWidened`: logical-to-physical mapping `8->16`, `16->32`, `32->64`; logical 64 requires exploratory physical 128.
7. `SignedNoOverflow`: same-width sign of subtraction with a machine-checked range precondition.
8. `SignedCorrected`: same-width sign-overflow correction, charging every required sign extraction.

No decrypt/re-encrypt shortcut, plaintext branch decision, or debug bootstrap is benchmark eligible.

Paper-level sensitivity baselines are `HEGIDE` (general all-path/all-instruction
private-tree execution), `CharacterBlock-Lattigo` (single-level LUT and prefix-
scan radix comparison), and `Sparse-THI` (functional-bootstrap cleaning). They
do not enter the local timed Pareto table until authoritative code is available
or an independently specified reimplementation passes conformance tests. Their
packing, conversion, security and batch denominators remain mandatory in the
qualitative baseline table.

## Frozen Packing Denominators

For logical query count `q`, bit width `p`, ring degree `N`, and integer width `n`:

- `C_bit=(p/2)*ceil(q/(N/2))` for LCPDTE adjacent-bit complex packing;
- `C_triangle=ceil(q/(N/n))` for arithmetic triangle words;
- `C_boolean=2*ceil(q/(N/n))` for full Boolean words.

A Boolean physical ciphertext contains `N/n` half-word records; two halves cover the same `N/n` complete words. For `w=4`, one full B-A2B group has `n/w` arithmetic input ciphertexts and `N/w` word evaluations (`16,384` when `N=2^16`). Every result records `word_slot_occupancy` and `ba2b_group_occupancy` separately, including forest/node streams used to fill a group.

## Frozen R0 Schedules

For a group beginning at binary depth `d`, let `h=min(g,D-d)`, let
`S=2^d` be the number of possible group-root supernodes, and let
`K=2^h-1` be the number of internal predicates in one depth-`h`
supernode. Let `C_cmp(q,n)` denote the number of physical ciphertext
streams required by one comparator over the registered logical batch, and
let `B_cmp(n)` denote the measured bootstrap/refresh count per physical
comparator stream. These symbols must be replaced by measured operator
counters in every result row; they are not assigned a favorable constant in
the cost model.

1. `R0-Sequential`: perform `h` dependent blind selections and `h` CT--CT
   comparisons in the group. At relative depth `j`, the selector spans
   `2^(d+j)` possible nodes. The complete tree therefore retains exactly `D`
   comparisons and `D*C_cmp(q,n)*B_cmp(n)` comparator refreshes; grouping only
   changes the planning boundary.
2. `R0-Eager-Active-CTCT`: select all `K` encrypted attributes and selected
   thresholds belonging to the secret active supernode from its `S`
   possibilities, perform `K` CT--CT comparisons in parallel, then construct
   the `h`-bit child digit obliviously. Per group the minimum logical charges
   are `K` width-`S` attribute selections, `K` width-`S` threshold selections,
   `K*C_cmp(q,n)` physical comparator streams, and
   `K*C_cmp(q,n)*B_cmp(n)` comparator refreshes, plus every path-state and
   digit-selector multiplication/addition. A selected threshold is a
   ciphertext even though the server's original threshold table is plaintext.
3. `R0-Eager-All-CTPT`: avoid encrypted active-supernode selection by
   evaluating all `S*K` predicates in the grouped global depth range against
   their server-plaintext thresholds, then obliviously select the active
   supernode and child digit. Per group it charges `S*K*C_cmp(q,n)` physical
   comparator streams and `S*K*C_cmp(q,n)*B_cmp(n)` comparator refreshes, plus
   the complete width-`S` result selector. This is the only eager schedule in
   which all comparisons remain CT--plaintext.
4. `R0-FusedLUT`: at `d=0`, one same-feature finite-domain LUT is eligible only
   after exhaustive or symbolic equivalence proof. At `d>0`, the encrypted
   supernode/function identity must be handled explicitly: either evaluate all
   `S` supernode LUTs and select the result (charging `S` LUT evaluations and a
   width-`S` selector), or prove one global LUT over both group-start state and
   feature domain and charge its full domain, transforms, outputs and
   bootstraps. A secret active supernode may not choose a plaintext LUT for
   free. Until one of those constructions is instantiated, fused rows below
   the root are ineligible for comparative benchmarks.

No R0 row is labeled optimized solely because its structural depth is `ceil(D/g)`.
Every row additionally reports the per-group tuple
`(d,h,S,K,C_cmp,attribute_selector_width,threshold_selector_width,comparison_operand_type,physical_comparator_streams,selector_terms,dependency_depth,refreshes,bootstraps)`.

Historical note: the pre-Stage-2 planner exposed the combined
`R0EagerCandidate`, simplified `R0FusedLUT`, and
`R0SequentialActivePath` placeholders. They are now rejected. The current
typed identifiers are `R0SequentialSourceFaithfulOBO`,
`R0SequentialActiveCTCT` (explicit conservative uniform oracle),
`R0EagerActiveCTCT`, `R0EagerAllCTPT`, and `R0StateAwareFusedLUT`. Fused plans
remain benchmark-ineligible while proof artifacts are only
`external_unverified`; all physical tuple fields remain typed `not_measured`
until a backend attaches observations through the validated constructor.

## Frozen Parameter Families

### LCPDTE paper tuple

`logN=16`, `logQP=1328--1508`, `H/h=(192,32)`, base scale 45, StC `39x3`, circuit `45x(8+logD)`, LUT `45x(K+1)`, EvalExp `45x8`, CtS `42x3`, P `46x5`. This is a paper record, not the effective checkout tuple.

### LCPDTE effective checkout tuples

- single-tree: `logN=16`, main `H=32768`, ephemeral `h=32`, `Logbase=1`, Hermite order 1, depth-dependent `logQP=1328--1508`;
- batch-eight: `logN=16`, main `H=32768`, ephemeral `h=32`, `Logbase=4`, real/imag packing, effective depth-12 `logQP approximately 1643`.

Both are `pending-estimator`. Exact `Q/P` prime lists and evaluation-key decomposition are emitted by the benchmark binary.

### Gao paper tuple

`N=2^16`, `logDelta=43`, multiplicative depth 20, `logQP=1254`, `H/h=(192,32)`, Gaussian sigma 3.2, seven 50-bit P primes, hybrid `dnum=3`, `w=4`, A2B cutoff -16. The OpenFHE paper/check-out version mismatch is recorded separately.

### Lattigo Gao-compatible tuple

New independent literal, not a renamed LCPDTE preset. The accepted parameter manifest fixes `LogN=16`, `LogQ=[43x21]`, `LogP=[50x7]`, scale 43, `H/h=(192,32)`, Gaussian sigma 3.2, and exact Q/P/QP product bit lengths 904/351/1254. Its exact Q/QP unlimited-sample sensitivity transcript is complete. Status: `parameter-candidate-unverified`, `application-security-inconclusive`; the complete evaluation-key/sample inventory and accepted secure circuit profile remain required.

### Functional-test tuple

Small ring/short chain permitted only for deterministic unit/integration tests. Every output is labeled `FUNCTIONAL-NOT-SECURE` and excluded from performance/security tables.

## Decoding and Correctness Gates

- Canonical raw residues are `[0,2^n-1]`; unsigned uses that interval and two's-complement interprets it as `[-2^(n-1),2^(n-1)-1]`.
- For each mode define normalized codeword spacing `d_min`, unique-decoding radius `R=d_min/2`, measured error `E`, normalized error `rho=E/R`, and remaining margin `1-rho`. Acceptance requires `rho<1` and exact oracle agreement; there is no second undocumented `R/2` gate.
- Arithmetic triangle: `E=||t e||_infinity`, `R=Delta/2`, so `rho=2||t e||_infinity/Delta`.
- Boolean full after scale normalization: `d_min=1`, `R=1/2`, and `E` is distance to the intended bit.
- D-CKKS chunk LUT: all 16 residues for `p=16` must produce exact `LUT_ID` and `LUT_MSB` after rounding; tests also evaluate inputs immediately inside/outside the accepted noise radius.
- A2B/B2B acceptance additionally checks the paper Theorem-5/6 inequalities using measured input noise where the implementation exposes it; otherwise the result is labeled empirical correctness only.
- Integer test protocol: zero mismatches, plus a one-sided 95% binomial upper bound for unobserved failure in non-exhaustive suites.

## Measurement Protocol

- One warmup plus seven timed repetitions; increase to 15 when `IQR/median > 10%`.
- One process, fixed thread count, fixed seeds, no concurrent benchmark jobs.
- Report median, IQR, min/max, peak RSS, rotations, tensor multiplications, relinearizations, rescale levels, and bootstraps.
- Measure actual marshalled bytes into separate fields: `online_request_bytes`, `online_response_bytes`, `setup_public_key_bytes`, `setup_eval_key_bytes`, and `setup_bootstrap_key_bytes`. Serialize outputs at their actual result level; never substitute a max-level size proxy.
- Report total and amortized time per logical query/word; include physical ciphertext count and batch utilization.
- Core/extended jobs have a two-hour cap; stretch jobs have an eight-hour cap.
- Preflight skips any case predicted or observed to exceed 80% of physical RAM. A skip is an auditable result, not a zero or timeout.

## Security Estimator Pin

Tool: `malb/lattice-estimator`, commit `53da5982597709ba0fdf94ea37a84d822310fd84` (2026-08-19), vendored read-only at `research/upstream/lattice-estimator`. The pin, execution boundary, and transcript contract are recorded in `security_estimator_pin.md`.

Execution status: `ESTIMATOR-SENSITIVITY-COMPLETE / APPLICATION-SECURITY-INCONCLUSIVE` for the exact Lattigo Gao-compatible candidate. An isolated WSL Sage 10.9 environment, SHA-pinned micromamba binary, exact 389-package explicit lock, authenticated converter, and two byte-identical real transcripts are reproducible. Exact-QP minima are 150.672 classical and 136.740 quantum bits; all rows use `m=+Infinity`. The functional `LogN=5` negative control returns 11.680/10.600 bits and `FAIL`. The LCPDTE paper/checkout tuples remain `pending-estimator`, and no candidate row may be labeled `128-bit secure` until finite sample/key exposures and the accepted secure circuit profile pass the frozen gate.

Required settings: classical and quantum Core-SVP estimates; actual ring dimension, full QP modulus, ternary/sparse secret distribution and weight, Gaussian error, number of samples/evaluation keys, and sparse-secret encapsulation assumptions. Classical `>=128` bits is the hard ranking gate; quantum cost is mandatory reporting/advisory with no threshold selected after results. The committed converter and transcript authenticate the current unlimited-sample sensitivity only. Finite exposures must be attached and re-estimated before any row is labeled `128-bit`; an estimator result alone does not discharge Gao--Zheng's application-aware correctness/noise obligations.
