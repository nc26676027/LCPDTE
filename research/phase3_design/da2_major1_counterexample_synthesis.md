# DA2 Major 1 Counterexample Synthesis and Bounded Novelty

Status: focused primary-source synthesis from the 96-query supplement executed on 2026-08-29. This is not a systematic review, an absence proof, a closest-work ranking, or a performance result. The associated pre-commitment is `da2_major1_claim_intent_manifest.yaml`; the exact search and screening record is `../phase2_investigation/da2_major1_query_ledger.md`.

## Evidence Map

### Multiway CKKS trees already exist

HEaaN-ID3 handles nominal and ordinal categorical variables, creates one child per category, and conducts encrypted training and inference with CKKS SIMD (Lee et al., 2025) <!--ref:lee2025heaanid3--><!--anchor:section:1-->. Its own scalability analysis observes that a maximum category count `n_max` yields up to `n_max` children per internal node and exponentially growing node/slot demand with depth (Lee et al., 2025) <!--ref:lee2025heaanid3--><!--anchor:section:8.4-->.

Anchor justification: the publisher Introduction supplies the multiway/categorical mechanism; Section 8.4 supplies the fanout and slot-growth boundary.

This is a direct counterexample to “the first multiway FHE decision tree” or “the first multiway CKKS tree.” It does not implement Gao--Zheng triangle words, A2B, or the LCPDTE OBO/BSGS operator graph. The defensible question is therefore whether the exact triangle/radix composition improves a matched model-private evaluator, not whether multiway CKKS trees exist.

### Mixed CKKS and Boolean/LUT private-tree evaluation already exists

PEGASUS switches between packed CKKS and FHEW ciphertexts, evaluates non-polynomial functions as FHEW LUTs, and applies the bridge to a single-round private decision tree using edge comparisons, path sums, and leaf LUTs (Lu et al., 2021) <!--ref:lu2021pegasus--><!--anchor:section:Application-II-->.

Anchor justification: the IACR manuscript's “Application II: Private Decision Tree Evaluation” is the direct application section, while the official record identifies the IEEE S&P 2021 publication.

PEGASUS is not an A2B conversion internal to discrete CKKS: it is a CKKS--FHEW scheme-switching design. That distinction preserves an exact-composition hypothesis but defeats broad claims such as “the first CKKS arithmetic/Boolean mixed PDTE.” Shin et al. independently provide CKKS training/inference with encrypted models and inputs and addition-only path evaluation at constant multiplicative depth (Shin et al., 2024) <!--ref:shin2024hbdt--><!--anchor:section:Abstract-->, so CKKS private decision-tree evaluation is itself established prior art.

Anchor justification: the HBDT official abstract explicitly states encrypted model/input inference and the addition-only path mechanism.

### Encrypted-query selection and tree-to-LUT evaluation already exist

The CKKS tree-LUT construction evaluates batched encrypted queries against encrypted or plaintext LUTs. Its official abstract gives `O(log n)` comparisons and `O(n)` multiplications for encrypted tables, and `O(log n)` comparisons plus `O(sqrt(n))` ciphertext multiplications and `O(n)` scalar multiplications for plaintext tables (Cheon et al., 2025) <!--ref:cheon2025treelut--><!--anchor:section:Abstract-->.

Anchor justification: these complexity statements and the CKKS proof of concept appear in the official IACR abstract and journal-linked record.

Petrean and Potolea compile a decision tree into a `2^M`-entry encrypted LUT and use an encrypted binary-decomposed feature vector as the index for vertical-packed MK-TFHE lookup (Petrean & Potolea, 2024) <!--ref:petrean2024mkrf--><!--anchor:section:4.3.1-->. Their encrypted-model setting is tree-specific but trades traversal for exponential table storage (Petrean & Potolea, 2024) <!--ref:petrean2024mkrf--><!--anchor:section:4.1.3-->.

Anchor justification: Section 4.3.1 defines encrypted-index selection; Section 4.1.3 defines the `2^M` decision LUT.

Independent Vector Evaluation is a newer CKKS alternative for a plaintext server table: it builds a linearly independent vector from powers of one encrypted scalar index and applies a precomputed DCT change of basis, reducing the authors' vector-generation accounting from `O(p log p)` to `O(p)` (Cheon et al., 2026) <!--ref:cheon2026embedding--><!--anchor:section:Abstract-->.

Anchor justification: the author-posted arXiv abstract states the encrypted-index model, IVE construction, complexity change, and plaintext embedding-table boundary. This source is preprint-only.

These results preclude a first-encrypted-index or first-oblivious-selection claim. They also impose three matched baselines: CKKS tree-LUT for encrypted/plaintext table selection, IVE for plaintext-table encrypted indices, and Petrean--Potolea for encrypted-model whole-tree LUT evaluation.

### Range-aware CKKS comparison already has carry-based antecedents

Kim defines unsigned radix comparison as `Carry(ct-ct')+1`. The correctness proof uses the explicit range `-t < z_i < t`: carry is zero on `[0,t)` and minus one on `(-t,0)` (Kim, 2025) <!--ref:kim2025integer--><!--anchor:page:11-13-->.

Anchor justification: PDF pp. 11--13 contain the comparison definition, theorem, and range argument; the official ePrint record identifies TCHES 2025 publication.

Cha et al. reduce radix digit-carry bootstraps to `O(log k)` with a two-step construction and use restored unique radix representations to enable comparison (Cha et al., 2026) <!--ref:cha2026radix--><!--anchor:section:Abstract-->.

Anchor justification: the official ePrint abstract states the carry complexity, three-to-six-bootstrap 32--2048-bit restoration result, and comparison support; the record identifies a EUROCRYPT 2026 major revision.

By contrast, the audited Gao public comparator computes modular subtraction followed by Boolean sign extraction. The paper only sketches subtraction plus sign extraction and supplies no general overflow-correction theorem (Gao & Zheng, 2026) <!--ref:gao2026alu--><!--anchor:page:41-->. The exact source pointer is `research/upstream/fhe-simd-alu/src/pke/lib/scheme/ckksrns/z-user-advanced.cpp:142`, recorded in `../phase2_investigation/gao_paper_code_map.md` Section 5.3.

Anchor justification: Gao--Zheng p. 41 supports the intended composition; the pinned source line supports the literal implementation. Neither supports an unqualified same-width signed or unsigned comparator.

The innovation cannot be “CKKS integer comparison.” A candidate contribution is a triangle-specific comparison API with one frozen physical design: same-width Boolean borrow, explicit widening with charged packing loss, signed-no-overflow under a proven input range, or sign-overflow correction. Metadata alone cannot repair modular wraparound.

### Discrete-CKKS private-program execution already includes a private tree

HEGIDE compiles a private program into encrypted opcodes and operand addresses,
then runs a public fixed Read--Execute--Write processor circuit on private data.
Its semi-honest definition hides program and data while leaking the padded cycle
count `T`, memory size `M`, word size `W`, and ISA (Dumezy et al., 2026)
<!--ref:dumezy2026hegide--><!--anchor:page:9-->. The ALU uses Kim-style radix
digits, evaluates every supported instruction, and selects the encrypted opcode's
result; the compiler flattens branches into arithmetic selection (Dumezy et al.,
2026) <!--ref:dumezy2026hegide--><!--anchor:page:16-20-->.

Most importantly for this project, §6.3 directly benchmarks a private depth-4
binary decision tree. All `2^D-1=15` internal nodes are evaluated; the program
uses 60 HEGIDE cycles. At `N=2^16`, the paper reports about 28,400 s for the
whole occupied batch and about 433 ms amortized per program, while noting that a
single program waits almost eight hours (Dumezy et al., 2026)
<!--ref:dumezy2026hegide--><!--anchor:page:23-24-->.

Anchor justification: pp. 9, 16--20 and 23--24 respectively define leakage,
encrypted instruction/control flow, and the private-tree experiment. The paper's
footnote says a public source release is planned subject to approval; no
authoritative HEGIDE repository was located on the search date.

HEGIDE defeats any priority claim over discrete-CKKS private programs, encrypted
instruction streams, or private CKKS decision-tree execution. It remains a
different baseline from the proposed specialization: all-path/all-instruction
Kim-radix execution in OpenFHE rather than LCPDTE OBO/BSGS with Gao triangle
words in Lattigo. Both one-program latency and occupied-batch throughput are
therefore required comparison axes.

### New representation and bootstrap baselines constrain the operator claim

Character Block Encodings represents one finite-alphabet value across a basis of
CKKS slots. Unary LUTs become affine plaintext maps at one level, selected group
laws become one multiplication, and a finite-state prefix scan evaluates radix
equality/comparison in depth `3+ceil(log2 d)` (Dumezy & Suvanto, 2026)
<!--ref:dumezy2026characterblock--><!--anchor:page:3-6,23-29-->. Its experiments
are already in Lattigo, and conversion from ordinary discrete CKKS into a block
still needs nonlinear evaluation/functional bootstrapping
<!--ref:dumezy2026characterblock--><!--anchor:page:19-20-->.

Sparse-THI separately changes the functional-bootstrap cleaning frontier through
arbitrary-order sparse trigonometric Hermite interpolation and an explicit noise-
capacity metric (Alexandru et al., 2026)
<!--ref:alexandru2026sparsehermite--><!--anchor:page:3-4,25-28-->. It is a
bootstrap/noise sensitivity baseline, not a tree or triangle construction.

Anchor justification: the Character Block sections ground representation,
comparison depth, Lattigo cost and conversion; Sparse-THI §§1.1 and 6 ground the
cleaning/implementation claim. Both official records are preprints, and both
papers defer public code release.

The planned system cannot claim the first discrete-CKKS LUT, radix comparison,
or Lattigo integer representation. Character Blocks must be compared against
triangle/A2B for word packing, conversion, levels, rotations, refreshes and
decision-tree integration; Sparse-THI must be tested where cleaning margin, not
only LUT latency, is the bottleneck.

## Claim Boundary

| Claim | Status after counterexample search | Required wording or action |
|---|---|---|
| First multiway/radix FHE decision tree | contradicted | Do not claim; HEaaN-ID3 is a direct multiway CKKS antecedent. |
| First CKKS private decision-tree evaluation | contradicted | Do not claim; PEGASUS, HBDT and HEaaN-ID3 cover distinct CKKS tree routes. |
| First CKKS arithmetic/Boolean mixed PDTE | contradicted in broad form | PEGASUS is the hybrid antecedent; restrict any claim to Gao-style triangle/discrete-CKKS A2B without scheme switching. |
| First encrypted-index FHE tree selection | contradicted | Compare against CKKS tree-LUT and tree-specific MK-TFHE LUT evaluation; include IVE when table privacy matches. |
| First exact, integer, LUT, or radix CKKS comparator | contradicted | Kim, Cha and Character Blocks supply carry/prefix-scan routes. A triangle-specific safe contract may still be an engineering contribution. |
| First discrete-CKKS private program or private tree | contradicted | HEGIDE encrypts programs and data and directly benchmarks a private binary decision tree. |
| Candidate Gao--Zheng triangle/A2B plus LCPDTE OBO/BSGS composition | not observed within the dated 96-query corpus | Treat only as a corpus-bounded candidate composition; rerun forward/citation search before submission and never convert the current observation into priority, closest-work, or absence language. |
| Lattigo realization of the exact composition | implementation hypothesis | Establish with reproducible code, conformance tests, parameters, estimator transcript, and end-to-end operator graph. |
| Radix grouping improves total cost | unproved empirical hypothesis | Charge comparisons, threshold selection, selector width, refresh, physical ciphertexts, occupancy, online bytes, latency and prediction semantics. |

## Radix Design Consequence

Grouping `g` binary levels into a radix-`2^g` supernode changes the structural depth but does not by itself reduce homomorphic work. HEaaN-ID3 shows that higher fanout can rapidly consume nodes and slots (Lee et al., 2025) <!--ref:lee2025heaanid3--><!--anchor:section:8.4-->. CKKS tree-LUT shows that logarithmic comparison depth can coexist with linear table work (Cheon et al., 2025) <!--ref:cheon2025treelut--><!--anchor:section:Abstract-->, while whole-tree LUT compilation exposes `2^M` model growth (Petrean & Potolea, 2024) <!--ref:petrean2024mkrf--><!--anchor:section:4.1.3-->.

Anchor justification: the three records separately ground fanout/slot growth, selector complexity, and exponential whole-tree table size.

R0 is eligible as an optimization only under one of four costed schedules. For
a group starting at depth `d`, use `h=min(g,D-d)`, `S=2^d` possible supernodes
and `K=2^h-1` predicates per supernode:

1. Sequential active-path evaluation performs `h` dependent blind selections
   and CT--CT comparisons, preserving the original comparison/refresh depth.
2. Active eager evaluation first selects `K` encrypted attributes/thresholds
   from `S` secret supernodes, then pays `K` CT--CT comparisons and the digit
   selector.
3. All-supernode eager evaluation preserves CT--plaintext comparisons only by
   paying `S*K` comparisons and a width-`S` encrypted result selector.
4. A fused LUT below the root must evaluate all `S` functions and select, or
   prove one global state-aware LUT and charge its entire domain. Same-feature
   equivalence inside an implicitly chosen secret supernode is insufficient.

R1 retraining is a different model. It belongs on an accuracy/leakage/cost frontier and cannot be labeled semantically equivalent without matched predictions.

## Required Baselines and Falsification Tests

| Proposed component | Required prior-art baseline | Falsification condition |
|---|---|---|
| Triangle range-safe comparator | Kim radix carry; Cha lightweight carry; Character Block prefix scan; Boolean borrow/widening variants | No gain after physical width, block/word packing, conversions, bootstraps, levels and failure margin are charged. |
| Encrypted branch/node selection | CKKS tree-LUT; Petrean--Potolea encrypted tree LUT; IVE when table plaintext | Claimed selector advantage disappears under matched table privacy, fanout, batch and error. |
| Mixed arithmetic/Boolean tree path | PEGASUS hybrid PDTE; HBDT CKKS path evaluation; HEGIDE general private processor | Composition has higher latency/bytes or weaker model privacy at matched semantics/security and occupied-batch denominator. |
| Multiway/radix tree | HEaaN-ID3 and the unchanged binary R0 baseline | Logical depth falls but total predicate, selector, refresh, memory or accuracy cost does not. |
| Functional bootstrap/cleaning | AKP, BKSS and Sparse-THI | Claimed exactness or latency gain disappears when the same input-noise threshold, output margin, levels and security tuple are required. |

## Cross-Paper Tension Inventory

```yaml
cross_paper_tensions:
  - pair_id: CP-DA2-001
    paper_a: lee2025heaanid3
    paper_b: park2026lcpdte
    candidate_basis: shared RQ subtopic
    overlap_topic: encrypted decision-tree structure and SIMD evaluation
    a_finding: HEaaN-ID3 supports categorical multiway nodes and pays fanout-driven node and slot growth.
    a_evidence_pointer: publisher Sections 1 and 8.4
    b_finding: LCPDTE targets a fixed binary tree with OBO comparison and BSGS branch selection.
    b_evidence_pointer: local primary PDF pp. 5-10
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: DA2 Synthesis > Multiway CKKS trees already exist
    scholar_confirmation: pending
  - pair_id: CP-DA2-002
    paper_a: lu2021pegasus
    paper_b: gao2026alu
    candidate_basis: shared construct/outcome/measure
    overlap_topic: arithmetic and Boolean or LUT composition for private decision trees
    a_finding: PEGASUS switches CKKS to FHEW for LUTs and applies the bridge to private decision trees.
    a_evidence_pointer: IACR paper Application II
    b_finding: Gao--Zheng converts triangle arithmetic words to a Boolean CKKS representation without FHEW scheme switching.
    b_evidence_pointer: local primary PDF pp. 21-23 and Algorithms 1-2
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: DA2 Synthesis > Mixed CKKS and Boolean/LUT private-tree evaluation already exists
    scholar_confirmation: pending
  - pair_id: CP-DA2-003
    paper_a: cheon2025treelut
    paper_b: cheon2026embedding
    candidate_basis: shared construct/outcome/measure
    overlap_topic: selecting a server-side record from an encrypted CKKS query
    a_finding: Tree-LUT supports encrypted and plaintext LUTs with tree-structured comparisons and multiplications.
    a_evidence_pointer: IACR official abstract
    b_finding: IVE selects from a plaintext embedding table using powers and a DCT change of basis.
    b_evidence_pointer: arXiv v3 official abstract
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: DA2 Synthesis > Encrypted-query selection and tree-to-LUT evaluation already exist
    scholar_confirmation: pending
  - pair_id: CP-DA2-004
    paper_a: kim2025integer
    paper_b: gao2026alu
    candidate_basis: opposite finding direction
    overlap_topic: correctness of encrypted machine-word comparison under modular arithmetic
    a_finding: Kim proves unsigned comparison through radix carry under an explicit difference range.
    a_evidence_pointer: local PDF pp. 11-13
    b_finding: Gao's public implementation takes the sign of a same-width modular subtraction without a general overflow correction.
    b_evidence_pointer: Gao paper p. 41 and pinned source z-user-advanced.cpp:142
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: DA2 Synthesis > Range-aware CKKS comparison already has carry-based antecedents
    scholar_confirmation: pending
  - pair_id: CP-DA2-005
    paper_a: dumezy2026hegide
    paper_b: park2026lcpdte
    candidate_basis: shared RQ subtopic and direct application
    overlap_topic: non-interactive model-private CKKS decision-tree execution
    a_finding: HEGIDE hides encrypted instructions and data in a fixed processor, evaluates all tree nodes, and amortizes a depth-4 tree over 2^16 MIMD slots.
    a_evidence_pointer: local HEGIDE PDF pp. 9, 16-24
    b_finding: LCPDTE specializes binary-tree traversal with OBO/BSGS and a different bitwise CKKS comparator/packing layout.
    b_evidence_pointer: local LCPDTE PDF pp. 5-10
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: DA2 Synthesis > Discrete-CKKS private-program execution already includes a private tree
    scholar_confirmation: pending
  - pair_id: CP-DA2-006
    paper_a: dumezy2026characterblock
    paper_b: gao2026alu
    candidate_basis: opposite representation and shared outcome
    overlap_topic: exact CKKS machine-word LUT, comparison and arithmetic
    a_finding: Character blocks trade slots for affine LUTs and leveled finite-state radix comparison in Lattigo.
    a_evidence_pointer: local Character Block PDF pp. 3-6, 19-29
    b_finding: Gao triangle words pack N/n words and use functional-bootstrap A2B for Boolean comparison logic.
    b_evidence_pointer: local Gao--Zheng PDF pp. 14-23, 41, 47-48
    pair_assessment: conditional_difference
    resolution_status: resolved_in_synthesis
    resolution_pointer: DA2 Synthesis > New representation and bootstrap baselines constrain the operator claim
    scholar_confirmation: pending
```

Coverage note: 25 sources are in the updated corpus; six DA2 candidate pairs were assessed using shared RQ, direct application, construct, or opposite-direction signals. This is a scoped advisory scan, not complete pairwise contradiction detection. Cross-neighborhood pairs may be absent, bibliographic coupling was never used to exclude a pair, and every resolution remains `scholar_confirmation: pending`.

## Bounded Novelty Statement

Within the dated 96-query primary-source corpus, no inspected work implements Gao--Zheng triangle encoding and arithmetic-to-Boolean conversion inside LCPDTE's OBO/BSGS evaluator. The same corpus contains direct antecedents for every surrounding category: multiway CKKS trees, CKKS/FHEW hybrid private-tree evaluation, encrypted-query CKKS LUTs, tree-specific encrypted-index lookup, discrete-CKKS private-program/private-tree execution, radix/discrete-CKKS comparison, single-level block-encoded LUTs in Lattigo, and stronger functional-bootstrap cleaning. This is a corpus-bounded candidate-composition observation, not a first, closest, unique, or absence claim.

The bounded contribution target is therefore the exact composition and its evidence: a Lattigo implementation, a proved and exhaustively tested comparison contract, a packing-accurate selector, and a matched end-to-end Pareto improvement against specialized PDTE, HEGIDE, radix/carry, Character Block and bootstrap alternatives. If those measurements do not improve on the required baselines, the valid result is a negative integration study.

## Synthesis Limitations

- Raw search totals were unavailable from the interface; the ledger preserves this instead of manufacturing counts.
- The original seven title/abstract exclusions lack row-level identities and cannot be retrospectively recovered.
- Seven first-round supplemental sources remain official-web-only. Five DA2-rerun papers were acquired and hashed; three enter the 25-source corpus and two remain context-only.
- The search is current to 2026-08-29; forward citations for 2026 publications remain immature.
- Cross-paper timings were not pooled because the schemes, security targets, table privacy, packing, hardware and workload differ.
