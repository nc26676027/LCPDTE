# Model-private oblivious tree evaluator seam

`treeeval` consumes a complete `treeplan.BinaryTree` and opaque feature values.
It exposes only public constants, addition, subtraction, multiplication, and
greater-than-or-equal comparison to a backend. `ValueKind` makes public versus
opaque provenance part of the interface and of every operation count.

The caller supplies `opaqueOne`, an encryption/opaque representation of scalar
one. A real backend obtains it from the query ciphertext domain; the evaluator
cannot decrypt it to verify the scalar. Its provenance is checked fail-closed.
Threshold and leaf scalar types are generic. `PublicScalar` preserves either a
finite real value or the exact low-bit pattern, width, and signedness of an
integer. Values such as `uint64(2^63+1)` never pass through `float64`.

Every evaluation call also requires a `ComparisonPolicy`. Real policies name
real ordering explicitly. Integer policies declare:

- bit width and unsigned versus two's-complement signed interpretation;
- inclusive ranges for the encrypted feature (left operand) and threshold
  (right operand);
- the physical comparator family (`UnsignedBorrow`, `UnsignedWidened`,
  `SignedNoOverflow`, or `SignedCorrected`);
- the matching overflow-correctness contract.

`SignedNoOverflow` is accepted only when the declared endpoint ranges prove
that every possible subtraction remains in the signed interval. The plain
backend checks actual operands against both ranges. A ciphertext backend cannot
inspect encrypted features, so its adapter must enforce the same contract at
encoding/protocol boundaries and instantiate the named comparator. Policy/type
or width mismatches fail closed before evaluation.

## Model-private OBO

At binary depth `d`, the evaluator holds `2^d` opaque one-hot path weights. It:

1. multiplies each weight by that node's opaque feature value and sums;
2. multiplies each weight by that node's server-public threshold and sums;
3. calls `CompareGE` once on the two selected opaque values under the explicit
   policy;
4. computes `right_i = weight_i * branch` and
   `left_i = weight_i - right_i` for every path state;
5. selects public leaves with the final opaque weights.

The crucial boundary is step 2: a plaintext server threshold selected by an
encrypted path weight becomes ciphertext/opaque. OBO therefore uses a CT-CT
comparator, not a CT-public comparator. Supplying opaque one at the root keeps
this statement true for every depth.

For `L=2^D` leaves, this implementation issues exactly:

- `2L-1` server-public constant constructions (`L-1` thresholds and `L`
  leaves);
- `D` CT-CT comparisons;
- `2(L-1)` CT-CT multiplications;
- `2L-1` CT-public multiplications;
- `3L-3-2D` additions;
- `L-1` subtractions.

Counting each backend method once gives `10L-8-D` total calls. Comparison
provenance fields are classifications of the `D` comparison calls and are not
double-counted by `TotalBackendCalls`.

These are full arithmetic calls, not a paper-specific key-switch-only model.

## Full-level public-threshold baseline

`EvaluateFullLevel` evaluates every node predicate with its threshold still
public, then updates all path weights obliviously. It therefore uses
`2^D-1` CT-public comparisons, `L-1` CT-CT path multiplications, and `L`
CT-public leaf multiplications. It also constructs the same `2L-1` public
constants, for `7L-5` total backend calls. This avoids encrypted-threshold OBO
but gives up the one-comparison-per-depth property.

Both strategies stream one level at a time. `PeakLivePathStates` counts opaque
one-hot path entries; `PeakLiveComparisonStates` distinguishes OBO's single
branch bit from a full level's predicate batch. Concrete Lattigo implementations
must report ciphertext packing, rotations, relinearizations, rescaling, and
bootstrap costs in addition to `OperationCounts`.
