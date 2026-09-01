# Secure N16 Route-B transport-parameter contract

**Date:** 2026-08-31  
**Status:** design repair v2; independent re-review pending  
**Scope:** `LogN=16`, `LogSlots=11`, 512-word R1 sparse-packing adaptation

## Decision

Route B freezes one project-owned raw `bootstrapping.Parameters` value. The
value exists to prepare and assemble the Lattigo transport stages used around
the Gao integer kernel:

```text
special-b0 / pre-raise work
-> STC (SlotsToCoeffs)
-> ScaleDown at MessageRatio=1
-> sparse ModUp and observed Trace
-> CTS (CoeffsToSlots)
-> Gao A2B degree-46 exponential and two explicit squares
-> shared ID/MSB LUT and remaining integer pipeline
```

The raw value is not a stock Lattigo modular-reduction circuit. Its small
`SinContinuous` literal is a transport-normalization compatibility literal.
`PrepareParameters` really materializes its degree-3 polynomial, the prebuilt
assembler really installs a `Mod1Evaluator`, and ScaleDown/ModUp really consume
the derived MessageRatio and ScalingFactor fields. The private capability
boundary makes the polynomial and `Mod1Evaluator` unreachable for execution.
The Route-B A2B path instead executes Gao's pinned degree-46 exponential, two
explicit squares and the shared ID/MSB LUT.

Gao's pinned degree-32 Chebyshev polynomial and three explicit double-angle
rounds belong to the separately typed A2A-e path. A2B never dispatches that
kernel, and A2A-e never substitutes the A2B degree-46/R2 kernel.

This distinction is normative. Matching the raw/prepared digest does not show
that either Gao kernel ran, and running Lattigo's generated degree-3
polynomial cannot satisfy an A2B or A2A-e kernel gate.

## Evidence class

This contract freezes an R1 Lattigo adaptation, not a source-faithful Gao
parameter set:

- the exact CKKS Q/P chain, default scale and secret distributions are the
  accepted `lattigo-gao-compatible-n16-v1` candidate;
- the L11 transforms and 512-word layout are a separately labelled capacity
  adaptation;
- the upstream Gao A2B kernel remains the pinned degree-46 exponential plus
  two squares and shared ID/MSB LUT;
- the upstream Gao A2A-e kernel remains K=16, degree 32 and three
  double-angle rounds with the pinned coefficients;
- application security still requires the complete key/sample exposure and
  accepted circuit profile.

The constructor, preparation and digest gates therefore establish project
configuration identity only. They establish neither MR0 correctness nor a
security or performance result.

## Canonical raw value

The production constructor creates a fresh value internally. It accepts no
caller-selected raw parameters and does not call
`bootstrapping.NewParametersFromLiteral`.

### CKKS parameter sets

Both fields are the exact independent value returned by
`securityparams.GaoCompatibleN16Parameters()`:

```text
ResidualParameters      = GaoCompatibleN16Parameters()
BootstrappingParameters = GaoCompatibleN16Parameters()

LogN=16
RingType=Standard
Q=[the frozen 21-prime Gao-compatible chain]
P=[the frozen 7-prime Gao-compatible chain]
LogDefaultScale=43
Xs=balanced sparse ternary H=192
Xe=discrete Gaussian sigma=3.2, bound=19.2
```

Using the same value in both fields is an explicit R1 adaptation decision. It
keeps the accepted single-chain Q20/P6 profile and avoids introducing an
unreviewed stock-generated bootstrap chain. It is not attributed to Gao's
OpenFHE implementation.

### Raw STC and CTS literals

The two scaling values are present, exact binary rationals created without a
`float64` conversion:

```text
precision=256
rounding=ToNearestEven
accuracy=Exact
signbit=false

STC Scaling = +1
CTS Scaling = +2^-4 = +1/16
```

The literals are:

| Field | STC / `SlotsToCoeffsParameters` | CTS / `CoeffsToSlotsParameters` |
|---|---:|---:|
| `Type` | `HomomorphicDecode` = 1 | `HomomorphicEncode` = 0 |
| `LogSlots` | 11 | 11 |
| `LevelQ` | 18 | 20 |
| `LevelP` | 6 | 6 |
| `Levels` | `[1,1]` | `[1,1,1]` |
| `Format` | `SplitRealAndImag` = 1 | `SplitRealAndImag` = 1 |
| `BitReversed` | false | false |
| `LogBSGSRatio` | 0 | 0 |
| `Scaling` | present exact `+1` | present exact `+1/16` |

`RepackImagAsReal` has value 2 and is not admitted.

### Transport-normalization compatibility literal

The raw value freezes this complete literal:

```text
LevelQ          = 17
LogScale        = 43
Mod1Type        = SinContinuous
Scaling         = 0              # raw identity; derived meaning is one
LogMessageRatio = 0              # MessageRatio = 1
K               = 1
Mod1Degree      = 3
DoubleAngle     = 0
Mod1InvDegree   = 0
```

These fields have a narrow but real runtime role:

- `LogMessageRatio=0` fixes the MR0 ScaleDown target to `q0`;
- `LogScale=43` fixes the ModUp requested scale and the S2C initialization
  factor;
- `K=1` prevents a second `/16`, because the CTS raw scaling already embeds
  Gao's basis change;
- the remaining literal fields produce a small deterministic polynomial and
  derived object that are physically installed by evaluator assembly but are
  ineligible for dispatch.

`LevelQ=17`, `SinContinuous`, degree 3 and zero double angle do not describe
either Gao kernel. They must never appear in a result as a reproduced kernel
degree, start level or depth. Calling the installed `Mod1Evaluator` is a hard
capability violation.

### Remaining fields

```text
CircuitOrder          = bootstrapping.DecodeThenModUp = 1
EphemeralSecretWeight = 32
IterationsParameters  = nil
```

`DecodeThenModUp` preserves the useful preparation check
`BootstrappingMaxLevel(20) - CTSDepth(3) = Mod1LevelQ(17)`.
`ModUpThenEncode` fails its second relation because
`17 - Mod1Depth(2) = 15 != STCLevelQ(18)`. `Custom` would unnecessarily skip
these checks and is not admitted. `CircuitOrder` affects preparation
validation and identity; it does not change the stock `Bootstrap` method's
hard-coded execution order. `nil` excludes META-BTS. The ephemeral weight
fixes the required dense-to-sparse and sparse-to-dense key boundary.

## Preparation and canonical identity

Capacity admission precedes the only call to
`bootstrapping.PrepareParameters`. Preparation must observe DFT construction
delta `[0,0,0,0]`, leave the caller value unchanged and detach all mutable
levels, scaling and iteration state.

The following identities are frozen by tests before live Authority exists:

1. exact CKKS parameter binary digest;
2. canonical raw `Parameters.MarshalBinary` digest as a diagnostic identity;
3. the authoritative `PreparedParameters.Digest`, which also binds exact
   scaling metadata, `CircuitOrder`, iterations and the derived polynomial;
4. all eight `RBAUTH-v1` raw/effective STC/CTS literal/scaling identities;
5. the derived compatibility-literal fields and resident degree-3 polynomial
   fingerprint;
6. the zero DFT-construction counter delta.

The JSON/raw digest alone is not authority because it does not by itself make
the nullable `big.Float` precision/mode/accuracy distinction. The prepared
digest and eight RBAUTH fragments close that boundary.

Every constructor call returns detached slices and `big.Float` values. A
mutation of one returned value cannot change any later constructor output.

## Runtime capability boundary

The general `*bootstrapping.Evaluator` created by the prebuilt assembler is
owned only by an unexported `integer/secureeval` wrapper. The wrapper never
returns that pointer, its `Mod1Evaluator`, DFT matrices, parameters or keys.

Only the following vendor operations may support the Route-B transport:

```text
ScaleDown
an independently accepted observed ModUp/Trace seam
CoeffsToSlots / the installed C2S matrix
SlotsToCoeffs / the installed S2C matrix
the lower-level evaluator operations explicitly required by special-b0
```

The current stock `ModUp` is not yet admitted: it calls `Trace` internally and
does not report the Galois elements it actually dispatches. Before encrypted
Route-B execution, a vendor-owned observed seam must bind the real successful
or failed Trace prefix to the ciphertext operation. Recomputing the expected
list from parameters is not execution evidence.

The public wrapper exposes a complete typed Route-B operation, not these raw
stages. It performs the owner-bound install and resident-payload preflight
before the first permitted operation.

The following stock calls are forbidden on the installed evaluator:

```text
Bootstrap
BootstrapMany
Evaluate
EvaluateConjugateInvariant
EvalMod
EvalModAndScale
EvalSinAndScale
EvalCosAndScale
any direct Mod1Evaluator method
ShallowCopy
stock NewEvaluator and every stock matrix-generating constructor
NewParametersFromLiteral
```

They dispatch the generated Lattigo Mod1 polynomial or a stock circuit and
therefore violate this contract even if their ciphertext output appears
numerically plausible. The private package is statically audited for these
selectors, and the encrypted vertical gate records the custom-kernel trace
before accepting a result. `Depth`, `OutputLevel` and `MinimumInputLevel` are
also ineligible as evidence for the custom route's real depth or execution
trace.

## Required tests

### Constructor and preparation

- reproduce the existing exact parameter, base-profile and L11-shape goldens;
- assert every raw field above, including true non-nil scalings and their
  precision, mode, accuracy, sign and hexadecimal mantissa/exponent form;
- assert same-value residual/bootstrap fields and different detached raw
  scaling/level storage across constructor calls;
- prepare twice and freeze identical raw, prepared and eight RBAUTH identities;
- assert raw input immutability and DFT counter delta `[0,0,0,0]`;
- independently recompute the effective DFT scaling formula;
- fingerprint the resident derived polynomial while labelling it
  non-executable compatibility state;
- reject or change the authoritative identity for each Mod1 field,
  CircuitOrder, iterations, residual/bootstrap parameter and raw-scaling
  nil/value/precision/mode/accuracy mutation;
- prove `DecodeThenModUp` passes, `ModUpThenEncode` fails at `15 != 18`, and
  `Custom` is rejected by project identity even though it can prepare;
- test `CircuitOrder` explicitly because Lattigo `Parameters.Equal` omits it;
- prove nil iterations are canonical and every non-nil value, including an
  empty or all-zero structure, is rejected;
- prove the same-chain configuration needs no N1/N2 ring-switch keys while
  dense-to-sparse and sparse-to-dense keys remain mandatory;
- validate the exact `qDiff` correction. A rounded ModUp scalar of one does
  not make the scale-metadata multiplication by approximately `1/qDiff` a
  no-op.

### Capability and negative execution

- prove the private installed type exposes no vendor evaluator or Mod1
  evaluator accessor;
- statically reject every forbidden stock selector in production
  `integer/secureeval` Route-B sources;
- use path spies to prove the accepted MR0 invokes STC, ScaleDown, the
  observed sparse ModUp/Trace seam, CTS and the typed A2B degree-46/R2 kernel
  in the frozen order;
- prove no stock EvalMod or bootstrap path is invoked;
- prove the resident degree-3 polynomial has zero dispatches;
- distinguish the A2B degree-46/R2 trace, A2A-e degree-32/R3 trace and
  resident degree-3 compatibility polynomial, and reject both cross-wirings;
- fail closed on any raw/prepared/receipt/resident-payload identity drift
  before key generation, installation or HE according to its gate position.

## Stop conditions

- A caller-provided valid `bootstrapping.Parameters` value can mint lineage.
- Preparation occurs before current L11 capacity admission in the live path.
- `BootstrappingParameters` is generated from stock defaults or differs from
  the frozen same-chain adaptation.
- Either raw DFT scaling is nil, rounded through `float64`, or loses its exact
  256-bit metadata identity.
- `CircuitOrder` is inferred through `Parameters.Equal`, or `Custom` is
  admitted merely because preparation accepts it.
- The degree-3 transport polynomial is evaluated or reported as Gao's kernel.
- A2B dispatches the A2A-e degree-32/R3 kernel, or A2A-e dispatches the A2B
  degree-46/R2 kernel.
- Expected Trace elements are reported without observing the real
  automorphism-dispatch prefix.
- Any forbidden stock evaluator method is reachable through the project
  wrapper.
- A successful MR0 receipt lacks the pinned typed A2B-kernel trace.
- The R1 L11 result is labelled full-packed, source-faithful or sufficient for
  application security.

## Source anchors

- `integer/securityparams/gao_compatible.go`
- `integer/secureprofile/gao_n16_packing_l11.go`
- `research/phase3_design/a2b_lattigo_port_contract.md`
- `research/phase3_design/gao_sine_kernel_contract.md`
- `research/phase3_design/secure_n16_port_seam.md`
- `research/phase3_design/secure_n16_route_b_two_stage_construction.md`
- `research/phase3_design/secure_n16_route_b_auth_wire.md`
- `vendor/github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping/prepared_parameters.go`
- `vendor/github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping/evaluator.go`
- `vendor/github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1/mod1_parameters.go`
