# Lattigo `Z_{2^n}` and Private-Tree Integration Design

Status: design freeze candidate. Paper facts are separated from local engineering choices; no performance claim in this document is a result.

## 1. Objective and Non-Goals

The implementation will reproduce the Gao--Zheng triangle representation and the operator subset needed to evaluate LCPDTE-compatible private decision trees, then evaluate two explicitly different research branches:

- **R0, semantics preserving:** replace the input/comparison/operator layer while preserving every binary split and leaf prediction of the original tree.
- **R1, model changing:** retrain or compile a radix/integer tree and report accuracy/model size separately. R1 can never be used as evidence for an R0 speedup.

The first implementation will not claim support for arbitrary 128/256-bit ALUs, malicious security, categorical/missing splits, or data-dependent ciphertext rotations. These features are outside the decision-tree minimum and require separate designs.

## 2. Representation and Types

The existing `he.CT` remains the bit-sliced LCPDTE baseline. A separate package owns exact-modular metadata:

```go
type Mode uint8 // Arithmetic, BooleanFull, DCKKS
type Signedness uint8 // Unsigned, TwosComplement

type Bounds struct {
    Min, Max *big.Int
    Proven   bool
}

type Parameters struct {
    WordBits   int
    ChunkBits  int
    WordSlots  int
    WordCount  int
    Scale      rlwe.Scale
    A2BCutoff  int
}

type Value struct {
    Cts        []*rlwe.Ciphertext
    Mode       Mode
    Parameters Parameters
    Signedness Signedness
    Bounds     Bounds
}
```

`Value` validation rejects mismatched word width, mode, number of ciphertext halves, physical slots, scale/level incompatibility, and an operation whose documented range precondition is absent.

## 3. Layering

### 3.1 Plain mathematical oracle — `integer/z2n`

- polynomial arithmetic in `R[X]/(X^n-X+2)`;
- binary polynomial `[m]_t` and arithmetic triangle `t^{-1}[m]_t`;
- exact wraparound oracle for `Z_{2^n}`;
- 128-bit fixed-point roots copied from the authoritative implementation;
- `tau` and the closed-form inverse;
- decode in the required order: multiply by `t`, coefficient-wise round, then evaluate at `X=2` modulo `2^n`.

This layer has no secret keys and is the independent oracle for encrypted tests.

### 3.2 Homomorphic embedding — `integer/homchain`

- block packing of `N/n` arithmetic words per CKKS ciphertext;
- Lattigo `lintrans` transformations for `U_{tau,0/1}` and `V_{tau,0/1}`;
- normal, special-`b0`, fused-`t`, and fused-`t^{-1}` matrices;
- transformations use `*bignum.Complex`, not `complex128`;
- two half transforms share rotations through `EvaluateManyNew`;
- all additional Galois elements are enumerated before evaluator construction.

Lattigo terminology is the reverse of the paper at the CKKS ring/slot boundary: paper R-To-C corresponds to Lattigo `CoeffsToSlots`; paper C-To-R corresponds to Lattigo `SlotsToCoeffs`.

### 3.3 Integer evaluator — `integer/evaluator`

Dependency order:

1. arithmetic encode/decode;
2. Add/Sub and plaintext variants;
3. `MultShort` and Full Mult;
4. D-CKKS multi-output LUT;
5. B2B;
6. A2B Algorithm 1;
7. B-A2B Algorithm 2;
8. B2A;
9. range-safe Compare and Select;
10. A2A-I/A2A-e only when a measured circuit needs them.

The local patched `DiBootstrapMany` will be factored behind a reusable D-CKKS LUT interface. The port must not equate Lattigo `ScaleDown` with Gao's `RLWE.Truncate` until a differential invariant test verifies message/overflow removal, bottom scale, and ModUp behavior.

## 4. Exact Operator Contracts

### Arithmetic

- `Add/Sub`: operands have equal word width and packing; result is modulo `2^n`.
- `MultFull`: both operands are arithmetic triangle values; slotwise product is multiplied by the encoded `t`; consumes two CKKS levels in the paper construction.
- `MultShort`: the second operand is the short/binary representation; consumes one level.
- decode succeeds only when coefficient rounding is unique. The paper sufficient condition is `||t e||_infinity < Delta/2`; tests record the observed minimum coefficient-rounding margin.

### Conversion

- A2B uses `p=2^w`, initially `w=4`; `LUT_ID(0)=0`, `LUT_ID(x)=x-p` for nonzero residues, and the paper's negative-fractional `LUT_MSB` convention.
- B-A2B accepts exactly `n/w` arithmetic ciphertexts for a full batch. Padding is recorded as wasted capacity and cannot support an amortized-constant claim.
- Boolean full mode uses two ciphertexts per logical batch, one per half-word.

### Compare

The public API never exposes an unqualified `LessThan`:

```text
CompareUnsignedBorrow     // same-width Boolean borrow circuit; engineering adaptation
CompareUnsignedWidened    // zero-extend into the next supported physical word width
CompareSignedNoOverflow   // requires a proven subtraction range
CompareSignedCorrected    // sign(x), sign(y), sign(x-y) overflow correction
CompareServerPlaintextThreshold // CT--server-plaintext variant; not client-public
```

These are distinct benchmark variants, not one `RangeSafe` wrapper:

- same-width unsigned borrow keeps physical width `n` and charges the A2B/Boolean borrow circuit;
- widened unsigned maps logical `8->16`, `16->32`, and `32->64`; logical 64 requires exploratory physical 128 support. Packing, A2B rounds and communication use the physical width;
- signed-no-overflow keeps width `n` but is eligible only when declared operand bounds prove subtraction stays in `[-2^(n-1),2^(n-1)-1]`;
- signed-corrected keeps width `n` and charges extraction/use of `sign(x)`, `sign(y)`, and `sign(x-y)` unless a sign is already an explicitly accounted cached value.

For the LCPDTE server-private model, thresholds begin as server plaintexts, but the comparison contract depends on traversal:

- a **full-level** strategy compares each encrypted feature with each node's server-plaintext threshold and therefore retains ciphertext--plaintext subtraction, at the cost of `2^D-1` comparisons for a complete depth-`D` tree;
- the paper's **OBO** strategy first selects the active feature and threshold with encrypted path weights. The selected threshold is consequently a ciphertext, so the one comparison per level is ciphertext--ciphertext and needs a range-safe signed/unsigned contract.

No benchmark may combine OBO's `D` comparison count with the full-level strategy's plaintext-threshold cost. Server-plaintext-threshold subtraction remains a useful branch primitive and R1 interval-tree building block, but it is not by itself a faithful implementation of model-private OBO. “Server plaintext” describes the HE operand type; it does not mean the threshold is disclosed to the client.

### Select

Gao--Zheng does not define a general MUX. The local engineering operator is

```text
Select(b, left, right) = left + B2A(b) *short (right-left).
```

Its provenance is always labeled as an engineering adaptation.

## 5. Decision-Tree Seams

```go
type BranchEvaluator interface {
    GreaterEqualServerPlaintextThreshold(feature *z2n.Value, threshold uint64) (*z2n.Value, error)
    GreaterEqualEncrypted(feature, selectedThreshold *z2n.Value) (*z2n.Value, error)
}

type TreeEvaluator interface {
    Evaluate(batch []*z2n.Value, model *tree.Model) (*z2n.Value, Metrics, error)
}
```

R0 is implemented in vertical slices:

1. fixed feature/server-plaintext-threshold branch;
2. one depth-2 tree;
3. binary tree with the existing OBO/parity selector;
4. level-major forest scheduling;
5. matched query-block scheduling for B-A2B.

The baseline tree remains unchanged. A narrow branch interface permits the bit-sliced GEQ and triangle comparator to run on identical plaintext models and predictions.

## 6. Packing and Throughput Accounting

At `N=2^16`:

Let `q` be logical queries, `p` the bit width, and `N/2` the CKKS complex-slot count. The frozen input formulas are

`C_bit=(p/2)*ceil(q/(N/2))`, `C_triangle=ceil(q/(N/n))`, and `C_boolean=2*ceil(q/(N/n))`.

| Representation | Records in one physical ciphertext | Ciphertexts per feature for 32,768 queries |
|---|---:|---:|
| LCPDTE adjacent-bit complex packing | 32,768 queries for one adjacent-bit pair | 16 bit-pair ciphertexts |
| Gao arithmetic triangle | `N/n=2,048` complete words | 16 arithmetic ciphertexts |
| Gao Boolean full | 2,048 half-word records; two ciphertexts form the same 2,048 complete words | 32 physical ciphertexts |

Thus triangle encoding does not reduce input ciphertext count for the paper's 32-bit/32,768-query workload; it changes the operator structure. Every latency, communication, and bootstrap table reports both per physical ciphertext and per matched logical query.

For `w=4`, a fully occupied B-A2B group contains `n/w` arithmetic ciphertexts and `N/w=16,384` word evaluations. Results record both word-slot occupancy within each ciphertext and group occupancy across the `n/w` ciphertext streams; forest/node batching cannot be folded silently into query batching.

## 7. Radix/Integer Tree Candidates

Prior-art gate: `da2_major1_counterexample_synthesis.md` records an existing multiway CKKS tree (HEaaN-ID3), hybrid CKKS/FHEW private-tree evaluation (PEGASUS), CKKS tree-LUT selection, encrypted-model tree-to-LUT evaluation, radix carry comparators, HEGIDE's discrete-CKKS private-program/private-tree execution, and Character Block Encodings' Lattigo single-level LUT/low-depth comparator. R0 and R1 are therefore engineering hypotheses, not first-multiway, first-private-program/tree, first-Lattigo-integer or first-discrete-CKKS-LUT claims. Selector results are compared against the privacy-matched tree-LUT/IVE/MK-TFHE class; operator results also compare Gao triangle/A2B against radix/carry and character-block packing, conversion, level, refresh and error costs.

### R0 radix grouping

Group `g in {1,2,3,4}` consecutive binary levels into radix `r=2^g` supernodes while retaining the same predicates and leaf map. Four schedules are eligible and separately costed:

1. `R0-Sequential`: select and compare the active predicate `h=min(g,D-d)` times in sequence for a group beginning at depth `d`. It preserves OBO but does not reduce comparison/refresh depth.
2. `R0-Eager-Active-CTCT`: for a group beginning at depth `d`, set
   `h=min(g,D-d)`, `S=2^d`, and `K=2^h-1`. Blindly select the `K` attributes and
   thresholds of the secret active supernode from `S` possible supernodes,
   perform `K` CT--CT comparisons, and form the child digit. Each group charges
   `K` width-`S` attribute selections, `K` width-`S` threshold selections, all
   `K` comparator streams/refreshes and the complete digit-selector graph.
   Server ownership of the plaintext model does not make the selected
   threshold a plaintext operand.
3. `R0-Eager-All-CTPT`: evaluate every predicate in every possible supernode
   for the grouped range, namely `S*K` CT--server-plaintext comparisons, then
   select the active supernode and digit under encryption. It preserves the
   plaintext-threshold operand type only by paying `S*K` comparisons and a
   width-`S` result selector.
4. `R0-FusedLUT`: a root group may use one finite-domain LUT only when all
   grouped predicates use the same feature and equivalence is proved over the
   declared domain. Below the root, either evaluate all `S` supernode-specific
   LUTs and obliviously select, or construct and prove one global LUT whose
   encrypted input includes the group-start state. LUT construction, complete
   domain, transforms, bootstrap outputs, physical ciphertext streams and
   result selection are charged. A fused schedule with an implicit secret
   function identity is ineligible.

For every schedule, `C_cmp(q,n)` physical ciphertext streams per logical
comparison and the measured per-stream refresh/bootstrap count are multiplied
by the exact logical comparison count above. The benchmark artifact records
the group tuple `(d,h,S,K)`, selector widths, operand type, physical stream
count, dependency depth and every refresh/bootstrap; `ceil(D/g)` alone is not
an HE latency model.

The compiled tree structure is a correctness oracle and planning artifact. It is not called an optimization until a concrete schedule improves a measured cost vector.

### R1 retrained radix tree

Train/evaluate `r in {4,8,16}` ordered interval nodes. Report predictive accuracy, leaf count, depth, and leakage separately. Arbitrary categorical/missing-value nodes remain outside the current scope. R1 cannot be compared as a drop-in evaluator until prediction equivalence is explicitly measured.

For ordinary thresholds, `(r-1)log_r L` comparisons are not automatically better than binary. An encrypted digit also cannot directly address a ciphertext array; leaf retrieval still needs a one-hot, MUX network, polynomial, or LUT.

## 8. TDD and Acceptance

### Plain oracle

- `n=8`: all 256 encodings and all 65,536 operand pairs for Add/Mult/compare;
- `n=16,32,64`: fixed edge cases plus deterministic boundary-heavy random vectors;
- root residual, conjugate pairing, and `tau^{-1}tau` error;
- multiple-word isolation.

Canonical raw residues are `[0,2^n-1]`; two's-complement interpretation is `[-2^(n-1),2^(n-1)-1]`. For every mode, tests record `rho=E/R`, where `R` is half the normalized codeword spacing, and require `rho<1` plus exact oracle agreement. Width 128 is exploratory and excluded from the registered Pareto decision.

### Encrypted operators

- first fail on the independent oracle, then implement;
- exact zero mismatches for `n<=8` exhaustive suites;
- for larger widths, three fixed seeds and at least `2^15` boundary-heavy cases per operator/width;
- record coefficient rounding margin, levels, scale, rotations, relinearizations, bootstraps, actual marshalled online request/response bytes, setup key bytes, peak RSS, and wall time;
- a security-level benchmark is separate from a small-parameter functional test.

### Tree

- compare every encrypted output with a plaintext traversal oracle;
- R0 requires bit-for-bit identical predictions;
- R1 reports model/prediction difference and accuracy before performance;
- missing/NaN/signed-zero behavior is rejected or explicitly normalized, never silently inherited.

## 9. Principal Risks

| Risk | Detection / response |
|---|---|
| 128-bit root constants lose precision during port | Preserve integer/sign/scale form; residual and inverse tests at >=128-bit precision. |
| ScaleDown is not Gao Truncate | Differential invariant test; mark A2A blocked if it fails. |
| Comparison wraps | Bounds-aware API plus exhaustive overflow tests. |
| Amortized B-A2B batch is underfilled | Report utilization and padding; no O(1) label for partial batches. |
| Matched throughput erases per-ciphertext gain | Always normalize by logical words/queries and physical ciphertext blocks. |
| BSGS paper model hides tensor work | Instrument tensor multiplications and additions separately from relinearizations. |
| Radix tree changes semantics | Separate R0/R1 artifacts and metrics. |
| Known prior art makes the novelty wording overbroad | Apply the prohibited/candidate claim table in `da2_major1_counterexample_synthesis.md`; retain only exact-composition claims supported by code, proof, and matched measurements. |
| Character blocks or HEGIDE dominate the proposed composition on the relevant frontier | Include them as mandatory paper baselines; reproduce locally when authoritative code is released, and until then report the source-code gap rather than substituting incomparable paper timings. |
| Host OOM | Preflight gate at 80% physical RAM and retain skip artifact. |
