# Independent Mathematical and Code Audit

Date: 2026-08-29  
Scope: `integer/z2n`, `integer/evaluator`, `integer/homchain`, `integer/treeplan`, `integer/treecompile`, and `integer/treeeval`  
Initial verdict: `REVISE`  
Initial finding count: 0 Critical, 4 Major, 3 Minor

Final independent rerun verdict: `PASS`  
Final unresolved finding count: 0 Critical, 0 Major, 2 Minor

This report preserves the read-only audit that followed the first green
integer/tree test suite. A green test suite was not treated as evidence that
the public contracts were complete.

## Major findings

### M1 — Triangle canonicalization boundary differed from the reference

The local `CanonicalizeArithmetic` originally computed `x-ceil(x)`. The pinned
Gao--Zheng source subtracts `epsilon=2^(-n-1)` before applying `ceil`, which is
equivalent to `x-ceil(x-epsilon)` and maps coefficients to
`(-1+epsilon,epsilon]`. The two maps usually decode to the same residue, but
their coefficients and available noise margin differ by almost one close to
the positive epsilon boundary.

Disposition: **fixed**. The implementation now follows the pinned reference
operation order. Coefficient-level tests cover values below, at, and above the
epsilon boundary for n=8/16/32/64; ten repeated runs pass. The complete ring
suite and encrypted evaluator regression also pass after the change.

### M2 — Generic tree values erased exact machine-word semantics

The first generic backend represented constants as `float64` and called a
policy-free comparison operation. Values above `2^53`, negative two's-complement
inputs, logical width, signedness, and the overflow/range contract could not be
preserved. This API could validate the committed float fixtures but could not
honestly claim generic Gao `Z_(2^64)` tree support.

Disposition: **fixed**. `treeplan.PublicScalar` preserves exact signed/unsigned
machine-word values and floating-point bit patterns, while an explicit
`ComparisonPolicy` carries width, signedness, and the admissible comparison
range. Regression tests cover values above `2^53`, negative two's-complement
inputs, and identical bits interpreted under distinct signedness policies.

### M3 — Transform provenance could diverge after construction

`TransformSpec` retained an internal matrix but also exposed mutable diagonal
state that `Compile` trusted. A caller could mutate the public diagonals so the
compiled transform no longer matched the matrix from which the specification
was supposedly derived.

Disposition: **fixed**. Transform state is private; all accessors return values
or deep copies. `Compile`, `Parameters`, and Galois-key enumeration derive from
one trusted full-slot representation. Mutation tests demonstrate that changing
returned copies cannot alter the matrix, compiled plaintexts, fused transforms,
or Galois elements. Ten repeated package runs and `go vet` pass.

### M4 — R0 equivalence was a forgeable label

The first radix plan exposed mutable JSON fields and structural validation only;
`Semantics()` returned `R0Equivalent` without proving that the plan came from a
specific binary source tree. An arbitrary structurally valid plan could
therefore self-label as semantics-preserving.

Disposition: **fixed**. The R0 certificate binds the plan to a canonical binary
encoding of the source tree and is checked through `VerifyAgainst(source)`.
The digest is independent of JSON tags and custom marshalers, encodes ordered
structure and raw numeric bits (including `+0` versus `-0`), and rejects
mutated or wrong-source plans. Structural grouping remains an engineering plan,
not an HE performance claim.

## Minor findings

1. Public `homchain.Parameters()` described compact repeated-block dimensions
   that the Lattigo encoder could not consume, while `Compile` silently used a
   flattened full-slot specification. **Fixed:** the public method now returns
   `(ckkslintrans.Parameters, error)` for the same full-slot representation as
   `Compile`, with consistency tests.
2. `treecompile.Forest` did not reject a negative `NumOutputGroup` in one edge
   path. **Fixed:** negative values are rejected while the documented zero/one
   compatibility case remains accepted.
3. A one-threshold multiway node could admit NaN because no ordering comparison
   was executed. **Fixed:** binary and multiway thresholds, leaves, complete
   feature vectors, and forest margin accumulation now reject every non-finite
   value or overflow.

Two new non-blocking findings remain from the independent `z2n`/`homchain`
rerun:

1. `TransformSpec.GaloisElements` can turn an invalid-parameter/full-slot
   construction error into an empty element set because its public signature
   has no error return. The benchmark-eligible API must either surface this
   error or validate construction before enumeration.
2. The precision contract records significand bits, but `Ring.validate` does
   not separately prove the precision of every supplied polynomial. Extremely
   large or mixed-precision caller coefficients can therefore erase the
   epsilon shift through floating-point significance loss. Stage 2 must either
   enforce a coefficient/precision bound or document and test the admissible
   constructor domain.

## Confirmed properties

The audit independently confirmed the following properties and raised no
finding against them:

- coefficient-first arithmetic decoding and `uint64` wrap semantics at n=64;
- the U/V transform algebra, full-slot boundary rotations, and block isolation;
- faithful model-private OBO's ciphertext--ciphertext comparison requirement;
- exact comparison counts for OBO and full-level control schedules.

## Independent reverification

The tree rerun reported `PASS` with 0 Critical, 0 Major, and 0 Minor findings.
It independently checked the canonical digest against JSON/custom-marshaler
bypass, exact `PublicScalar` semantics, full-input finite-value validation,
forest overflow handling, and public-constant/backend-call accounting. Ten
repeated package runs, `go vet`, and `gofmt -d` all passed.

The separate `z2n`/`homchain` rerun reported `PASS` with 0 Critical, 0 Major,
and the two Minor contract findings recorded above. Those findings are carried
into the Stage-2 design gate and do not certify performance, secure parameters,
or a complete Gao conversion/bootstrap stack.

Historical state at this audit snapshot: `treeplan.MetricsForSchedule` still
used `R0SequentialActivePath`, combined `R0EagerCandidate`, and simplified
`R0FusedLUT` placeholders. Stage 2 has since replaced them with a distinct
source-faithful OBO control, an explicit conservative uniform CT--CT control,
and the typed eager-active, eager-all, and state-aware fused schedules. Current
rows bind `(d,h,S,K)`, provenance-separated comparator charges, selectors,
structured external proof artifacts, and typed physical observations to a
schedule certificate; the historical placeholders remain rejected.

The functional audit gate is therefore closed as `PASS`: every initial Major
and Minor finding is fixed, and there is no unresolved Critical or Major
finding. Performance, security, and novelty claims remain outside this audit
and require their own matched benchmark, estimator, and final review gates.
