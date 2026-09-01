# Stage-2 Lattigo Port Contract

Status: active engineering contract; quantitative claims remain unverified.

## 1. Scope and evidence classes

This contract governs the Lattigo implementation of Gao--Zheng `Z_{2^n}`
operators and their use in the LCPDTE evaluator. Every result belongs to one of
four disjoint classes:

1. `upstream-faithful`: same mathematical operator, packing, range contract,
   and raw state as the pinned OpenFHE implementation;
2. `lattigo-adaptation`: semantically equivalent output with a separately
   documented Lattigo normalization or schedule;
3. `tree-optimization-r0`: exactly preserves the compiled binary model and
   prediction function;
4. `tree-optimization-r1`: changes quantization, topology, arity, training, or
   prediction semantics and is evaluated as a new model.

Decoded agreement alone cannot promote an operator to `upstream-faithful`.
Raw level, scale, representation, packing, error, and operation-trace gates
must also pass.

Pinned Gao source commit:
`08f1eb87434e7be072cba889270a8400bbffc08e`.

## 2. Typed ciphertext metadata

Every public integer ciphertext carries or is accompanied by immutable
metadata containing:

- word width `n` and modulus `2^n`;
- arithmetic, Boolean-low/high, coefficient, or root-slot representation;
- signedness and the proved input interval used by comparison;
- word count, `LogSlots`, and full/sparse packing mode;
- ciphertext level and exact Lattigo scale at each public boundary;
- operator provenance and whether the result is faithful, adapted, or
  exploratory;
- logical counters and measured physical counters as separate records;
- a precision/error diagnostic with a declared acceptance threshold.

An unknown or unmeasured physical quantity is represented as such. It is not
encoded as zero.

## 3. A2A-I high-refresh contract

### 3.1 Source call graph

The production path is:

```text
Z2C(normal V)
  -> C2R / SlotsToCoeffs with fused RLWE.Truncate
  -> ModRaise plus partial-sum/Trace
  -> R2C / CoeffsToSlots with upstream 1/N normalization
  -> C2Z(normal U)
```

The upstream standalone `EvalTruncate` is not the production implementation.
The Lattigo path is initially classified as `lattigo-adaptation` until the
raw-state differential gates in section 3.4 pass.

### 3.2 First vertical slice

The first slice is full packed, `n=8`, dense/full-slot, and uses `gap=1`. The
test plaintext is a valid arithmetic representative `f + I`, where `f`
encodes a known residue and `I` has at least one nonzero integral coefficient.
The integral component is invisible under the triangle residue decode but is
observable by coefficient inspection and must be removed by A2A-I. The exact
coefficient target is `CanonicalizeArithmetic(ArithmeticEncode(m))`; a raw
arithmetic encoding is a valid residue representative but is not necessarily
already in Gao's canonical coefficient interval.

The public operation is non-mutating. It returns a new ciphertext and an audit
record containing input/output level, input/output scale, `ScaleDown`
`errScale`, DFT depths, and the exact transform/rotation-key profile.

### 3.3 Lattigo transform normalization

Use dedicated raw DFT matrices, not the bootstrapping evaluator's initialized
S2C/C2S matrices:

- `HomomorphicDecode` / SlotsToCoeffs: two transform levels;
- `HomomorphicEncode` / CoeffsToSlots: three transform levels;
- split real/imaginary format suitable for the existing two Z2C coefficient
  halves;
- matrix literal `Scaling = 1`;
- full packing only for the first slice.

Use all-one Lattigo level vectors (`[1,1]` and `[1,1,1]`). In the vendored
implementation, non-unit entries expose a discrepancy between
`MatrixLiteral.Depth(true)` and the number of rescale operations actually
performed by `EvaluateSequential`; runtime output-level assertions are
authoritative for this port.

Lattigo homomorphic encoding already contributes `1/(2*slots)` in the selected
split format, and `bootstrapping.ModUp` performs normalized Trace. The first
slice must not add a separate partial sum or another `1/N` factor.

### 3.4 Truncate/ScaleDown promotion gate

`bootstrapping.Evaluator.ScaleDown` is not named or documented as Gao
`RLWE.Truncate` unless all of the following are demonstrated:

- `LogMessageRatio = 0` (`MessageRatio = 1`);
- the input scale has the Gao `Delta` meaning at the C2R boundary;
- the same `Q_l -> q0` chain is used;
- a centered-message bound justifies any early limb-dropping `Resize`;
- the returned `errScale` is recorded and within a predeclared tolerance;
- output raw scale is `q0`, not merely a decode-equivalent ratio;
- Lattigo `ModUp`'s conditional scaling-to-Mod1 branch is absent or is
  separately corrected and proved; a unit coefficient multiplier with a
  changed scale tag is not raw-state equivalence;
- the fused-C2R versus standalone-ScaleDown rounding difference is bounded by
  independent vectors;
- the post-ModUp Trace/normalization matches full-packing and later sparse
  packing cases separately.

Before this gate passes, the API and reports call the step `guarded
ScaleDown/ModUp adaptation`.

### 3.5 Acceptance tests

One test must jointly assert:

1. exact `Z_{2^8}` residue preservation for every populated word;
2. removal or bounded canonicalization of the nonzero integral overflow;
3. no cross-word contamination;
4. input ciphertext byte/state immutability;
5. expected post-ModUp transform level and output scale;
6. finite, exposed, bounded `errScale`;
7. exact presence of all Z2C, DFT, Trace, inverse-DFT, C2Z and conjugation keys.

A simple Z2C/C2Z or DFT round trip is a diagnostic only and does not satisfy
this acceptance test.

## 4. Remaining Gao operator contracts

Implementation order:

```text
P0 typed metadata and parameter profiles
P1 exact triangle algebra and roots
P2 normal Z2C/C2Z and raw C2R/R2C
P3 special-b0, fused-t, and fused-t^-1 transforms
P4 guarded Truncate/ModRaise/Trace adaptation
P5a A2A-I
P5b standalone B2A
P6a sine kernel, A2A-e, full A2A
P6b D-CKKS exponential and shared-power two-LUT kernel
P7 A2B
P8 exact-batch B-A2B
P9 normal-C2Z plus MultShort Boolean multiplier
P10 OpenFHE intermediate differential vectors
```

### A2A-e and full A2A

A2A-e clones its input because Lattigo ScaleDown mutates its argument and the
algorithm subtracts the refreshed error from the original. The full operator
always runs A2A-I before A2A-e. Reversing the order is rejected.

A2B does **not** call A2A-e. The two operators share only the
`C2R -> fused truncate -> ModRaise/partial-sum -> R2C` bootstrap skeleton.
A2A-e enters through the fused-`t` Z2R path, evaluates the degree-32 sine and
three double-angle steps, exits through fused-`t^-1` C2Z, and subtracts the
refreshed error. A2B instead starts from the special-b0 Z2C path, masks code
blocks, then invokes the Boolean LT/two-LUT path. These special transform
families are mutually typed and cannot be substituted for one another.

### A2B

- `w` divides `n`; the initial port uses `w=4`;
- the code-domain `LUT_ID` and `LUT_MSB` use Gao's fractional/centered
  representatives, not conventional unsigned lookup tables;
- propagation cutoff `-16` and the pinned full-benchmark variant `-24` are
  distinct named configurations;
- full arithmetic packing produces two Boolean ciphertext halves;
- a sign-only specialization is exploratory and cannot be labeled faithful
  A2B until proved independently.

### B-A2B

The direct full-packed API accepts exactly `d=n/w` inputs and requires even
`d` for the pinned grouping. It returns
`[A.low,A.high,B.low,B.high,...]`. Partial-batch padding belongs only to an
outer dispatcher and is charged explicitly.

### B2A

Standalone B2A uses the fused `t^-1` C2Z transform. Boolean data used as a
multiplier uses normal C2Z followed by `MultShort`. The two paths have distinct
types so that `t^-1` cannot be silently applied twice.

## 5. Range-safe comparison

The pinned `EvalLessThan` computes modular subtraction and extracts the sign;
it is incorrect for unrestricted signed inputs when subtraction overflows and
is not an unsigned comparator.

Every comparison API therefore declares:

- CT--plaintext or CT--CT provenance;
- signed or unsigned interpretation;
- the closed input intervals for both operands;
- whether subtraction is proved not to overflow;
- the output representation (Boolean bit, triangle bit, or selector digit).

The faithful signed fast path is accepted only when interval arithmetic proves
`x-y` lies in the signed `n`-bit domain. General comparison must use widening,
borrow, or sign-overflow correction and is a separate measured variant.

Independent boundary tests include equality, minimum/maximum values, opposite
signs, and the counterexample `int8(127) - int8(-1)`.

## 6. Private-tree integration

The encrypted backend exposes four explicit primitives rather than hiding
work inside scalar multiplication:

- `CompareGEPublic`;
- `CompareGEOpaque`;
- `SelectMany` plus a lazy dot-product finalizer;
- `RefreshMany`.

Each call emits physical counts for ciphertext multiplications, rotations,
relinearizations, rescales, key switches, transforms, bootstraps, live
ciphertexts, bytes, and wall time. Logical algorithm counts remain separate.

The source-faithful OBO schedule has one CT--plaintext root comparison and
`D-1` CT--CT comparisons. The existing uniform `D` CT--CT oracle may remain as
a conservative variant but cannot share the source-faithful label.

The float compiler gets a separate ordered-uint32 view. It must define NaN,
infinity, and signed-zero behavior and prove equivalence to the supported
float32 comparison domain. Leaves remain real-valued margins; branch bits are
bridged explicitly into leaf selection/accumulation rather than retagged as
integer leaves.

## 7. R0 and R1 isolation

R0 accepts only a verified source binary tree and a plan whose digest passes
`VerifyAgainst`. Grouping, scheduling, packing, and fused evaluation may
change; predictions and the compiled model may not.

The source-faithful OBO reproduction control is reported separately from four
R0 scheduling alternatives. The conservative uniform CT--CT control and the
three eager/fused alternatives are:

1. sequential active CT--CT;
2. eager active-supernode CT--CT;
3. eager all-supernode CT--plaintext;
4. state-aware fused LUT with an explicit finite-domain equivalence proof.

R1 has a different input and result type. Quantization, retraining, pruning,
threshold merging, and genuinely multiway/integer nodes are R1. R1 results are
matched for task accuracy and leakage, not described as a reproduction of the
binary model.

## 8. Parameter and experiment profiles

`FUNCTIONAL-NOT-SECURE` profiles may reduce `LogN` and workload size but must
retain the operator's level/scale topology. Their results support wiring and
correctness only.

Secure-performance profiles archive the complete Q/P chain, ring degree,
dense and sparse secret distributions, error distribution, evaluation-key
decomposition, packing, failure/correctness bound, and estimator transcript.
The current local dense-secret `H=32768` parameter is not Gao's or LCPDTE's
reported `H=192`; it is a separate baseline until a matched profile passes the
security and correctness gates.

Matched PDTE throughput is per query at equal prediction semantics and includes
all ciphertext blocks. Gao full arithmetic packing carries `N/n` words, not
LCPDTE's `N/2` independent CKKS query slots, so per-ciphertext timings are never
used as the sole comparison.

## 9. Non-goals for the first slice

- no claim of 128-bit security from functional parameters;
- no full A2B or decision-tree latency claim before P4/P7 pass;
- no replacement of the frozen original `tree/` baseline;
- no data-dependent ciphertext rotation indexed by an encrypted child id;
- no multiway superiority claim from depth alone;
- no use of symbolic planner counts as measured HE operations;
- no private GitHub mutation or final push before all pipeline gates pass.

## 10. Active risks and stop conditions

| Risk | Required response |
|---|---|
| ScaleDown early `Resize` violates the centered-message bound | Stop the faithful port label; implement an explicit Gao-style adapter or tighten the admitted input domain. |
| Raw DFT normalization differs despite decoded agreement | Preserve as a Lattigo adaptation and derive/measure the missing factor before continuing. |
| ModUp retags q0 scale toward the Mod1 scaling factor | Stop the faithful label; guard the branch or implement and test a raw basis-extension adapter. |
| Required Trace/DFT keys cannot coexist with the bootstrapping keyset | Add a documented merged keyset and charge its size; do not omit rotations. |
| Functional profile lacks enough levels for the exact chain | Expand only the functional Q-chain while retaining the same topology and keep the non-secure label. |
| Float ordering cannot preserve signed zero/NaN semantics | Restrict and validate the supported domain or classify the compiler as R1. |
| R0 fused LUT lacks a finite-domain equivalence proof | Reject the schedule instead of assigning it zero comparator cost. |

## 11. Stage-2 exit gate

Stage 2 can reach its FULL checkpoint only when:

- the public metadata and parameter profiles are frozen;
- the A2A-I raw-state slice has a reproducible red/green trace or an explicit
  technical blocker with a falsifiable next test;
- every remaining Gao operator has a dependency, oracle, level/scale, packing,
  and range contract;
- the four R0 schedules and R1 separation are represented by types;
- benchmark workloads, security inputs, and unsupported claims are frozen;
- full Go tests, static checks, formatting, and an independent design/code
  audit pass.
