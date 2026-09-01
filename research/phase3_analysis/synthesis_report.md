# Synthesis Report

Status: ARS Stage 1 / Phase 3 analysis artifact. The matrix preserves the verified 15-source historical core; the DA2 extension adds ten included sources for a 25-source corpus and is integrated below with its separate ledger. This report does not certify the future Lattigo implementation or its performance.

## Literature Matrix

| Source | PDTE comparison/traversal | Discrete CKKS / conversion | SIMD / packing | Security / correctness | Method and evidence fitness |
|---|---|---|---|---|---|
| Park et al. (2026) <!--ref:park2026lcpdte--><!--anchor:page:5-10--> | OBO, GenOH, BSGS, level-major bootstrap | batched bit bootstrap | 32,768 row slots; complex bit pairs | semi-honest; incomplete numerical failure account | formal system + code/benchmarks; Level III, B |
| Gao and Zheng (2026) <!--ref:gao2026alu--><!--anchor:page:15-28--> | comparison via arithmetic-to-Boolean sign | triangle arithmetic, A2A/A2B/B-A2B/B2B/B2A | `N/n` words; batching precondition | decode/noise theorems + application-aware claim | formal system + code/benchmarks; Level III, A-/B+ |
| Azogagh et al. (2022) <!--ref:azogagh2022probonite--><!--anchor:page:1-9--> | one-branch TFHE, `d` comparisons | functional bootstrap path step | limited SIMD relevance | protocol security in its own scheme | protocol + implementation; Level III, B |
| Cong et al. (2022) <!--ref:cong2022sortinghat--><!--anchor:page:1-24--> | plaintext-threshold compare, traversal | no triangle ALU | batching and optional transciphering | protocol analysis | protocol + implementation; Level III, A-/B+ |
| Akhavan Mahdavi et al. (2023) <!--ref:mahdavi2023levelup--><!--anchor:page:2-12--> | XXCMP/RCC and two PDTEs | no discrete bootstrap | SIMD accelerates batch/single inference | leveled-HE parameterized correctness | protocol + SEAL benchmarks; Level III, A-/B+ |
| Cong et al. (2024) <!--ref:cong2024faster--><!--anchor:page:1-17--> | batched RCC/CW + adapted SumPath | no discrete bootstrap | batch 16,384 focus | leveled-FV protocol | controlled system benchmark; Level III, A-/B+ |
| Liang et al. (2024) <!--ref:liang2024bpdte--><!--anchor:page:1-2--> | three comparisons, six batch PDTEs | no triangle ALU | amortized comparison | preprint proofs | preprint system study; Level III, C+ |
| Bae et al. (2024a) <!--ref:bae2024bits--><!--anchor:page:1-3--> | Boolean gates usable in traversal | bit-specific CKKS bootstrap | throughput grows with many packed gates | numerical bootstrap analysis | peer-reviewed system; Level III, A |
| Bae et al. (2024b) <!--ref:bae2024small--><!--anchor:page:1-7--> | small-domain LUT can form branch digits | root-of-unity SI-BTS/BB-BTS | high batch-fill requirement | precision/parameter analysis | peer-reviewed system; Level III, A |
| Drucker et al. (2024) <!--ref:drucker2024bleach--><!--anchor:page:1-3--> | supports Boolean/integer path circuits | error cleaning | favors wide parallel circuits | correctable-error condition | journal system study; Level III, A-/B+ |
| Alexandru et al. (2025) <!--ref:alexandru2025functional--><!--anchor:page:6-25--> | arbitrary/multi-value LUT option | trigonometric-Hermite functional bootstrap | amortized across RLWE coefficients/slots | explicit noise cleaning/scale tradeoff | peer-reviewed formal system; Level III, A |
| Kim (2025) <!--ref:kim2025integer--><!--anchor:page:3-5--> | comparison and shifts through radix decomposition | unsigned CKKS integer computer | high throughput; width-linear bootstrap count | modular-reduction contract | peer-reviewed TCHES system study; Level III, B+ |
| Boneh and Kim (2025) <!--ref:boneh2025nested--><!--anchor:page:23-27--> | comparison is not its strength | nested slot-wise RNS | trades slots for modulus size | modular arithmetic analysis | peer-reviewed formal system; Level III, A |
| Bossuat et al. (2022) <!--ref:bossuat2022sparse--><!--anchor:page:1-4--> | indirect dependency | CKKS bootstrap substrate | full-slot bootstrap | dense/sparse key separation and failure model | peer-reviewed security/system study; Level III, A |
| Alexandru et al. (2026) <!--ref:alexandru2026application--><!--anchor:page:1-8--> | application specification includes circuit/traversal | approximate/discrete correctness framing | batching belongs in application spec | application-aware correctness/security | field-standard definitions work, A |

## Source Effect Inventory and Consistency Check

The following inventory freezes how repeatedly cited sources are used across themes. The same source is not allowed to change effect direction between sections.

| Citation key | Effect inventory used in this synthesis | Cross-section check |
|---|---|---|
| `park2026lcpdte` | reduces comparisons and key switches through OBO/BSGS; does not establish sub-exponential total ring work | consistent: every section distinguishes key-switch savings from total work |
| `gao2026alu` | supplies triangle arithmetic/conversions and batch amortization; does not supply overflow-safe general comparison or automatic PDTE speedup | consistent: benefits are conditional on packing/range/batch fill |
| `cong2024faster` | reduces batched comparator cost and response size; does not prove constant total server work | consistent |
| `bae2024bits`, `bae2024small`, `alexandru2025functional` | show CKKS functional/discrete bootstrap throughput under filled SIMD batches | consistent: no isolated-word constant-cost claim |
| `kim2025integer`, `boneh2025nested` | expose radix-versus-CRT tradeoffs | consistent: neither is presented as universally superior |
| `bossuat2022sparse`, `alexandru2026application` | require complete parameter/application context for security/correctness | consistent |
| `dumezy2026hegide` | establishes private-program/private-data discrete-CKKS execution and a direct all-node private-tree benchmark; its headline throughput requires full MIMD occupancy | consistent: never used as one-query latency or as Gao/LCPDTE equivalence |
| `dumezy2026characterblock`, `alexandru2026sparsehermite` | supply a Lattigo representation/comparator alternative and a newer cleaning alternative | consistent: both are preprint baselines, not proof of a local gain |

## Key Themes

### Theme 1 — PDTE cost is a vector, not a single asymptotic

**Evidence strength:** Strong for cost decomposition. Six PDTE sources, predominantly peer-reviewed Level III system studies; the exact Go operation count is a pinned-source audit result.

The literature converges on reducing one of four different bottlenecks: number of comparisons, comparison circuit cost, oblivious traversal/leaf selection, or communication. PROBONITE and LCPDTE reduce a depth-`D` evaluation to `D` branch comparisons, but do so in different schemes and with different path-state mechanisms (Azogagh et al., 2022) <!--ref:azogagh2022probonite--><!--anchor:page:1-9--> (Park et al., 2026) <!--ref:park2026lcpdte--><!--anchor:page:7-9-->. SortingHat and Level Up focus on high-precision ciphertext--plaintext comparison and leveled traversal (Cong et al., 2022) <!--ref:cong2022sortinghat--><!--anchor:page:1-2--> (Akhavan Mahdavi et al., 2023) <!--ref:mahdavi2023levelup--><!--anchor:page:2-12-->. FASTER adds batched comparators and adapted SumPath, making the response compact without making every server operation constant (Cong et al., 2024) <!--ref:cong2024faster--><!--anchor:page:1-17-->.

The LCPDTE paper derives its `O(p·2^{D/2})` mechanism around key switching/relinearization (Park et al., 2026) <!--ref:park2026lcpdte--><!--anchor:page:9-15-->. Separately, the frozen author-derived checkout audit counts `Theta(p·2^D)` raw tensor products/additions in the factored inner products (`f5ff611`, `tree/main_tree.go:84-210`; provenance and derivation in `lcpdte_paper_code_map.md` §8). The resulting research object is therefore a cost vector

`(comparisons, ct-ct multiplications, relinearizations, rotations, bootstraps, live states, online bytes)`,

not one scalar “server complexity.” Any new integer evaluator must improve a measured dominant component without silently worsening another.

### Theme 2 — Exact discrete computation over CKKS is an encoding-and-cleaning contract

**Evidence strength:** Strong. Five mutually reinforcing sources.

BLEACH establishes the broad principle: discrete CKKS circuits remain reliable only while approximation error stays inside a correctable region and is periodically cleaned (Drucker et al., 2024) <!--ref:drucker2024bleach--><!--anchor:page:1-3-->. Bit-specific and small-integer bootstraps then specialize the encoded domain to bits or roots of unity (Bae et al., 2024a) <!--ref:bae2024bits--><!--anchor:page:1-3--> (Bae et al., 2024b) <!--ref:bae2024small--><!--anchor:page:1-7-->. General functional bootstrapping adds multi-value LUTs and zero-derivative Hermite cleaning for arbitrary small domains (Alexandru et al., 2025) <!--ref:alexandru2025functional--><!--anchor:page:6-25-->.

Gao--Zheng contribute a different representation layer: a word is a polynomial residue in `R[X]/(X^n-X+2)`, decoded by multiplying by `X-2`, rounding every coefficient, and only then evaluating at `X=2` (Gao & Zheng, 2026) <!--ref:gao2026alu--><!--anchor:page:15-17-->. This ordering converts an approximate CKKS state into an exact residue only under the theorem's rounding margin. Consequently, “using CKKS for integers” is not equivalent to placing an integer in an ordinary complex slot. Correctness tests must measure coefficient-rounding margin, representation mode, overflow budget and bootstrap failure, not just the final approximate numeric error.

### Theme 3 — SIMD amortization is conditional on occupancy and physical ciphertext accounting

**Evidence strength:** Strong. Four discrete-CKKS sources plus the focal PDTE packing.

Across bit, small-integer and general functional bootstrapping, the reported throughput advantage emerges when hundreds or thousands of equal-domain operations fill the available RLWE/SIMD capacity (Bae et al., 2024a) <!--ref:bae2024bits--><!--anchor:page:1-3--> (Bae et al., 2024b) <!--ref:bae2024small--><!--anchor:page:1-4--> (Alexandru et al., 2025) <!--ref:alexandru2025functional--><!--anchor:page:6-10-->. Gao's B-A2B has the same condition: its width-proportional iterations amortize across the `n/w` input ciphertexts only when that batch exists (Gao & Zheng, 2026) <!--ref:gao2026alu--><!--anchor:page:21-23-->.

This resolves the apparent packing paradox. At `N=2^16` and 32-bit words, a Gao arithmetic ciphertext carries 2,048 logical words, so 32,768 queries require 16 arithmetic ciphertexts per feature. LCPDTE's adjacent-bit layout also uses 16 physical ciphertexts per feature for the same 32,768 queries (Park et al., 2026) <!--ref:park2026lcpdte--><!--anchor:page:7-15--> (Gao & Zheng, 2026) <!--ref:gao2026alu--><!--anchor:page:14-16-->. The general ledger is `C_bit=(p/2)ceil(q/(N/2))`, `C_triangle=ceil(q/(N/n))`, and `C_boolean=2ceil(q/(N/n))`. A Boolean ciphertext holds `N/n` half-word records; two halves form the same `N/n` complete words. Triangle encoding therefore changes the operator graph, not necessarily the matched input-ciphertext count.

For `w=4`, one fully occupied B-A2B group spans `n/w` arithmetic ciphertexts and `N/w=16,384` word evaluations. Query-slot occupancy and cross-ciphertext group occupancy are different denominators; forest/node work used to fill a group must be reported separately. The benchmark unit is both physical ciphertexts and logical queries, and per-ciphertext latency alone cannot establish a PDTE gain.

### Theme 4 — Radix/multiway trees trade depth, representation capacity, comparisons and selector width

**Evidence strength:** Moderate. The representation tradeoff is well supported; the specific PDTE combination is untested.

Kim's radix/decomposition integer computer makes comparison and shifts tractable but refresh work grows with word width for a fixed digit size (Kim, 2025) <!--ref:kim2025integer--><!--anchor:page:3-5-->. Nested RNS moves in the opposite direction: it scales large-modulus multiplication and arbitrary modular reduction, while explicitly conceding weaker support for comparison, shifting and arbitrary functions (Boneh & Kim, 2025) <!--ref:boneh2025nested--><!--anchor:page:23-24-->. Small-integer functional bootstrapping suggests a third option: classify a small encrypted digit with a LUT when the domain and batch are full (Bae et al., 2024b) <!--ref:bae2024small--><!--anchor:page:1-7-->.

The DA2 extension adds a fourth option. Character Block Encodings spends several CKKS slots per finite-alphabet value so a unary LUT is an affine plaintext map and radix equality/comparison has depth `3+ceil(log2 d)` in its finite-state prefix scan; its prototype is already evaluated in Lattigo (Dumezy & Suvanto, 2026) <!--ref:dumezy2026characterblock--><!--anchor:page:3-6,19-29-->. Conversion from a standard discrete-CKKS scalar into the block remains nonlinear and packing capacity falls with block size. It is therefore a mandatory matched representation/comparator baseline, not a free replacement.

The engineering inference is conditional. A complete radix-`r` interval tree with `L` leaves performs `(r-1)·log_r(L)` active-path threshold tests and must obliviously select among `r` encrypted children. An encrypted child digit cannot select a Galois rotation index. Thus a lower logical depth does not imply lower latency; the candidate wins only if threshold LUT fusion or grouped bootstrap scheduling saves more than the wider one-hot selector costs.

R0 therefore needs an executable schedule, not just a grouped tree. For a group beginning at depth `d`, let `h=min(g,D-d)`, `S=2^d`, and `K=2^h-1`. Sequential active-path evaluation performs `h` dependent CT--CT comparisons. Active eager evaluation must first select `K` encrypted attribute/threshold pairs from `S` possible supernodes and then pay `K` CT--CT comparisons. An all-supernode eager alternative keeps CT--plaintext operands only by evaluating `S*K` predicates and selecting the result under encryption. A fused LUT below the root must either evaluate all `S` functions or prove and charge one global state-aware LUT; a secret function identity cannot select a plaintext LUT for free. R1 retraining may reduce model depth, but it changes predictions and belongs to a separate accuracy/leakage frontier.

### Theme 5 — Security and correctness attach to the declared application and full parameter chain

**Evidence strength:** Strong. Two dedicated sources plus both focal papers.

Sparse-secret encapsulation allows a dense main key to determine homomorphic capacity while a low-modulus sparse key keeps bootstrapping efficient; its negligible-failure examples depend on the exact key-switch modulus, secret weights and noise model (Bossuat et al., 2022) <!--ref:bossuat2022sparse--><!--anchor:page:1-4-->. Application-aware HE then makes the circuit, input set, bootstrap placement and error estimator part of the correctness/security statement (Alexandru et al., 2026) <!--ref:alexandru2026application--><!--anchor:page:1-8-->.

This evidence rules out parameter-by-label reasoning. Matching `N=2^16` or citing a paper's “128-bit” sentence is insufficient. Each secure local point needs the total Q/P chain, error distribution, dense and encapsulated secret distributions, decomposition parameters, application bounds, decoding radius, estimator tool/commit and failure interpretation. This study uses classical modeled cost `>=128` bits as the hard gate and reports quantum estimates as sensitivity information. Demo parameters can establish functionality but never enter the secure Pareto frontier.

### Theme 6 — Private-program CKKS already reaches decision trees, with a different cost frontier

**Evidence strength:** Moderate. One peer-reviewed direct system and surrounding PFE/tree work; source release is pending.

HEGIDE encrypts instructions and addresses, flattens branches, evaluates every ISA operation, and uses Kim-style radix digits inside an OpenFHE MIMD processor. Its formal leakage includes padded cycle count, memory size, word size and ISA (Dumezy et al., 2026) <!--ref:dumezy2026hegide--><!--anchor:page:9,16-20-->. Section 6.3 directly evaluates a private depth-4 binary tree by processing all 15 internal nodes. The paper reports about 28,400 s for one fully occupied `2^16`-slot batch and about 433 ms amortized per program, while one program's latency is almost eight hours (Dumezy et al., 2026) <!--ref:dumezy2026hegide--><!--anchor:page:23-24-->.

HEGIDE eliminates any broad priority claim for discrete-CKKS private programs or private CKKS trees. It does not implement Gao triangle/A2B or LCPDTE OBO/BSGS, so the useful experiment is narrower: compare a specialized model-private evaluator with a general all-path/all-instruction processor using both one-query latency and occupied-batch throughput, matched leakage and security. The paper states that HEGIDE source release is planned, so current quantitative use remains a paper baseline rather than a local reproduction.

## Contradictions and Resolutions

| Claim A | Claim B | Resolution |
|---|---|---|
| LCPDTE describes traversal/server work with a square-root exponential term (Park et al., 2026) <!--ref:park2026lcpdte--><!--anchor:page:3-10--> | Appendix B.2 states per-level exponential additions (Park et al., 2026) <!--ref:park2026lcpdte--><!--anchor:page:14-15-->; the frozen `f5ff611` audit independently counts the tensor products in `tree/main_tree.go:84-210` | Resolved by cost dimension: square-root applies to key switches/relinearizations, not all ring operations. |
| Gao reports amortized `O(1)` bootstrapping per input ciphertext (Gao & Zheng, 2026) <!--ref:gao2026alu--><!--anchor:page:22-28--> | A2B has `n/w` sequential digit-extraction rounds (Gao & Zheng, 2026) <!--ref:gao2026alu--><!--anchor:page:21-23--> | Resolved by denominator: batch A2B processes `n/w` ciphertexts together; a partial or isolated word retains width-proportional work. |
| Multiway depth is `log_r L` | An interval node needs `r-1` thresholds and an oblivious `r`-way selector | Resolved analytically: depth alone is not the cost; compare `(r-1)log_r L` plus selector/refresh costs. |
| Nested RNS gives superior large-integer arithmetic (Boneh & Kim, 2025) <!--ref:boneh2025nested--><!--anchor:page:23-27--> | Radix methods better support comparison/shifts/functions (Kim, 2025) <!--ref:kim2025integer--><!--anchor:page:2-5--> | Conditional difference, not contradiction: modulus size/multiplication and branch-oriented operations optimize different workloads. |
| Thresholds are server plaintexts in PDTE | OBO claims one selected comparison per depth | Resolved at the protocol seam: encrypted path weights turn the selected threshold into a ciphertext. Only an all-node strategy retains plaintext-threshold comparisons, at exponentially more comparisons. |

### Cross-Paper Tension Inventory

```yaml
cross_paper_tensions:
  - pair_id: CP-001
    paper_a: park2026lcpdte
    paper_b: cong2024faster
    candidate_basis: shared RQ subtopic
    overlap_topic: batched PDTE complexity
    a_finding: LCPDTE reduces comparison rounds and key switches through OBO/BSGS.
    a_evidence_pointer: PDF pp. 7-10 and Appendix B.2 pp. 14-15
    b_finding: FASTER reduces batched comparator time and response complexity with adapted SumPath.
    b_evidence_pointer: PDF p. 1 and conclusion p. 17
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: Synthesis Report > Key Themes > Theme 1
    scholar_confirmation: pending
  - pair_id: CP-002
    paper_a: park2026lcpdte
    paper_b: gao2026alu
    candidate_basis: scholar flag
    overlap_topic: matched 32-bit SIMD input packing and comparison substrate
    a_finding: Adjacent-bit packing serves 32768 queries with 16 ciphertexts per feature.
    a_evidence_pointer: PDF p. 7 and Appendix C p. 15
    b_finding: Triangle arithmetic packs N/n words, or 2048 32-bit words at N=2^16.
    b_evidence_pointer: PDF pp. 14-16
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: Synthesis Report > Key Themes > Theme 3
    scholar_confirmation: pending
  - pair_id: CP-003
    paper_a: gao2026alu
    paper_b: kim2025integer
    candidate_basis: shared construct/outcome/measure
    overlap_topic: machine-word comparison and bootstrapping scaling
    a_finding: Batched A2B amortizes width-proportional digit extraction across n/w ciphertexts.
    a_evidence_pointer: Gao--Zheng PDF pp. 21-23 and 28
    b_finding: Radix modular reduction supports comparison and shifts but its refresh count scales linearly with word width for fixed digit width.
    b_evidence_pointer: Kim PDF pp. 3-5 and 19
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: Synthesis Report > Key Themes > Themes 3-4
    scholar_confirmation: pending
  - pair_id: CP-004
    paper_a: kim2025integer
    paper_b: boneh2025nested
    candidate_basis: opposite finding direction
    overlap_topic: best representation for encrypted integers
    a_finding: Radix decomposition targets comparison, shifts and machine-word functions.
    a_evidence_pointer: Kim PDF pp. 2-5
    b_finding: Nested RNS targets very large-modulus multiplication and explicitly trades away efficient comparison/function evaluation.
    b_evidence_pointer: Boneh--Kim PDF pp. 23-27
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: Synthesis Report > Key Themes > Theme 4
    scholar_confirmation: pending
  - pair_id: CP-005
    paper_a: alexandru2025functional
    paper_b: gao2026alu
    candidate_basis: shared construct/outcome/measure
    overlap_topic: CKKS LUT/conversion for sign and integer logic
    a_finding: General multi-value Hermite LUTs evaluate arbitrary small-domain functions with cleaning.
    a_evidence_pointer: Alexandru--Kim--Polyakov PDF pp. 20-25
    b_finding: A2B performs structured chunk peeling and Boolean reconstruction for triangle words.
    b_evidence_pointer: Gao--Zheng PDF pp. 21-23 and Algorithms 1-2 pp. 47-48
    pair_assessment: no_material_conflict
    resolution_status: not_applicable
    scholar_confirmation: pending
  - pair_id: CP-006
    paper_a: bossuat2022sparse
    paper_b: alexandru2026application
    candidate_basis: shared construct/outcome/measure
    overlap_topic: meaning of secure/correct CKKS bootstrapping parameters
    a_finding: Failure and security depend on dense/sparse key encapsulation and the complete bootstrap parameter set.
    a_evidence_pointer: Bossuat et al. PDF pp. 1-4 and 11-20
    b_finding: Correctness/security must be tied to an explicit application specification and error estimator.
    b_evidence_pointer: Alexandru et al. PDF pp. 1-8
    pair_assessment: no_material_conflict
    resolution_status: not_applicable
    scholar_confirmation: pending
```

**Coverage note:** the historical-core inventory covers 15 papers and 6 candidate pairs selected by shared RQ subtopic, construct, opposite direction, scholar flag or cross-cluster relevance. The DA2 tension inventory extends the bounded corpus to 25 sources in `da2_major1_counterexample_synthesis.md`. Both scans are scoped advisories rather than complete pairwise contradiction detection. Cross-neighborhood pairs may be missing, bibliographic coupling is only an inclusion signal, and every resolution remains `scholar_confirmation: pending`.

## Knowledge Gaps

1. **Methodological — no Lattigo triangle-word replication:** no included source demonstrates Gao's high-precision block transforms, conversions and failure margins in Lattigo v6.1.1. This project must establish cross-library conformance rather than assume OpenFHE behavior transfers.
2. **Empirical — no matched PDTE composition:** no paper measures LCPDTE's OBO/BSGS traversal over Gao-style triangle/A2B operators under the same security, batch and model semantics.
3. **Theoretical/engineering — sign-only A2B:** PDT needs one branch bit, yet published A2B reconstructs the full Boolean word. Whether low-chunk identity peeling can be retained while discarding low output halves to save rotations/memory remains unproved and unmeasured.
4. **Protocol — model-private OBO comparator:** selected thresholds become encrypted. Same-width unsigned borrow, widened unsigned, signed-no-overflow and signed-corrected ciphertext--ciphertext comparison are different physical designs; none is supplied as an overflow-safe PDTE comparator by the literal composition.
5. **Representation — secure/full-scale repeated block transforms:** the Gao construction requires `N/n` independent word blocks. The local functional slice now demonstrates high-precision Lattigo block-diagonal U/V transforms with no four-word cross-block contamination; production-parameter precision, cost and bootstrap composition remain unmeasured.
6. **Tree structure — R0/R1 radix evidence:** no source establishes that grouping binary levels or retraining multiway trees lowers total HE cost after selector width, batch fill and prediction differences are charged.
7. **Security — estimator-complete local parameters:** neither focal paper supplies a directly reusable Lattigo parameter literal plus reproducible estimator transcript for the patched local bootstrap path.

## Evidence Convergence Map

```text
Strong:   [==========] Cost-vector view of PDTE             (6 PDTE sources)
Strong:   [==========] Discrete CKKS needs cleaning/contracts (5 sources)
Strong:   [========= ] SIMD gain requires batch occupancy    (5 sources)
Strong:   [========= ] Security is parameter/application bound (4 sources)
Moderate: [======    ] Radix/CRT workload tradeoff            (3 sources)
Gap:      [          ] Matched Lattigo ALU × OBO implementation (0 prior sources)
```

## Theoretical Integration

The evidence supports a two-axis design framework.

First, represent every evaluator with the decomposed cost

`C = C_compare + C_active_select + C_path_update + C_leaf_select + C_refresh + C_online_io`,

then measure each component in ring operations, bootstraps, levels, bytes, latency and peak memory. This reconciles the different “low complexity” claims across PDTE papers without declaring them mutually inconsistent.

Second, separate semantic class from HE mechanism:

- **Reference:** original binary model and bit-sliced CKKS baseline.
- **R0:** same predicates/leaves, possibly a triangle comparator or grouped radix scheduling; prediction equality is mandatory.
- **R1:** retrained/pruned/multiway model; prediction/accuracy/leakage changes are explicit outcomes.

The comparator dimension is split into same-width borrow, explicitly widened unsigned, bounded signed subtraction and sign-overflow-corrected variants; logical and physical word widths cannot share one cost point. Integer correctness uses `rho=E/R<1`, where `R` is half the normalized codeword spacing, plus exact oracle agreement. The communication component is also explicit: actual marshalled online request/response bytes are distinct from setup public, evaluation and bootstrap keys.

The combined innovation target is consequently not “replace binary by integer.” It is to find a Pareto point where one frozen comparator, filled B-A2B scheduling, fused sign extraction, or a proved R0 schedule reduces a dominant measured component while preserving R0 semantics—or to report that no such point exists on the tested host/parameters.

## Post-implementation evidence update (2026-09-01)

The Lattigo Route-B vertical slice now executes a complete two-round signed-byte A2B, a public root, all-node depth-two batching, and a 512-query selected-child depth-two circuit. The application profile binds the exact key and sample inventory to the pinned estimator and returns an assumption-explicit `CONDITIONAL-PASS`; it is not an unconditional protocol-security proof.

The first exact same-feature radix experiment isolates a useful but narrow algebraic optimization. Three monotone branch bits select four leaves through a telescoping CT–PT terminal, removing three CT–CT path products, three relinearizations, three path rescales, two complements and one path addition relative to an equivalent binary depth-two terminal. A 16-pair alternating-order confirmation passes its registered timing-direction rule, but the arm-median change is only 3.94% for the complete circuit and 1.25% for lifecycle, below the 10% candidate-promotion threshold; paired deltas are also smaller than their IQRs. The supplied D8/D10/D12 models contain no complete same-feature height-two subtree. The result therefore promotes the operation-graph insight, not radix as the main systems optimization.

This negative result sharpens the innovation map. The common A2B/broadcast/alignment prefix dominates the measured circuit, so the next credible gains must amortize or remove conversion work across nodes, trees or queries. The highest-value open candidates are a verified A2Sign/full-A2B ablation, exact filled-batch B-A2B scheduling, cross-query common-prefix conversion, and a private-model overflow-safe comparator. Multiway training remains an R1 model-design question whose accuracy, leakage and HE cost must be charged together.

## Synthesis Limitations

- The review is focused and rerunnable but not an exhaustive systematic review. Search-result ranks/pages were not archived for every query, and forward-citation coverage for 2026 publications is immature.
- The historical 15-source core contains one preprint-only work (`liang2024bpdte`). The full 25-source corpus contains four official-record preprints; the other three are identified in the supplemental ledger and carry less weight for performance claims.
- Cross-paper timings are not pooled because workload, hardware, compiler, scheme and security parameters differ.
- The current synthesis identifies only a candidate exact-composition gap inside the dated 96-query corpus. It does not establish priority, closest work, absence, novelty or performance; those remain contingent on refreshed search, the Lattigo implementation, secure parameter audit and matched experiments.
- Cross-paper tension detection used a recall-limited candidate-edge heuristic, not all possible pairs in the 25-source corpus.
