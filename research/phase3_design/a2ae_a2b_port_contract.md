# Gao--Zheng A2A-e and A2B Lattigo Port Contract

Status: source-mapped Stage-2 contract; implementation pending.

Pinned upstream commit:
`08f1eb87434e7be072cba889270a8400bbffc08e`.

Evidence labels:

- `S1-code`: direct pinned-source evidence;
- `S1-paper`: local ePrint 2026/233 evidence;
- `S2`: paper/source agreement;
- `I`: falsifiable Lattigo port requirement.

## 1. Dependency correction

The production A2A-e entry is `FHEZImpl::EvalArithToArithNoise`
(`z-fhe.cpp:330-381`). A2B does not call this function. The two paths share
only the bootstrap backbone

```text
C2R -> fused Truncate -> ModRaise/PartialSum -> R2C.
```

A2A-e uses fused-`t` Z2R, the sine/double-angle circuit, fused-`t^-1`
C2Z, and final subtraction. A2B begins with special-b0 Z2C, applies chunk
masks, and invokes the Boolean LT/two-LUT path. Reusing the A2A-e wrapper for
A2B is not source-faithful. `[S1-code]`

## 2. A2A-e production graph

```text
EvalArithToArithNoise(ct)                         z-fhe.cpp:330-381
|
+- EvalZ2R(ct, Z2C_SPECIAL_A2AE)                 :336
|  +- special V0,V1 = V * diag(t)                precompute.cpp:197-211
|  +- Z2C linear transforms, conjugate/add, rescale
|  +- full-pack half recombination
|  `- C2R: SlotsToCoeffs + fused Truncate, landing at q0
|
+- EvalModRaisePartialSum                        :342
|  +- dense(h=192) -> sparse(h=32) switch
|  +- clone q0 tower into the full Q basis
|  +- sparse -> dense switch
|  `- rotate/add PartialSum (empty at full-pack gap=1)
|
+- EvalR2C(..., SCALE_NK_PRE)                    :351
|  `- CoeffsToSlots with embedded 1/(N*K), K=16
|
+- EvalChebyshevSeriesPS(degree-32 coefficients) :359-360
|  `- Gao fixed 128-bit sine polynomial
|
+- ApplyDoubleAngleIterations(R=3)               :362-366
|  `- three square/rescale/affine recurrences
|
+- EvalC2Z(..., C2Z_SPECIAL_A2AE)                :376
|  `- special U0,U1 = diag(t^-1) * U
|
`- EvalSubWithAdjust(original, recovered_error)  :381
```

Constants `K=16` and `R=3` are in `z-fhe.h:303-308`; the degree-32
coefficients and recurrence constants are in
`z-fhe-constants.h:234-314`. The source comments assign about 37 bits of sine
precision and depth `6+3`. `[S1-code, S2]`

## 3. State and key ledger

| Stage | Operator | Level budget | Scale/modulus contract | Keys |
|---|---|---:|---|---|
| fused-`t` Z2C | CT--PT LT, rotation, conjugation, rescale | 1 | `V*diag(t)`; neither normal V nor special-b0 | rotations, conjugation |
| C2R + Truncate | SlotsToCoeffs, CT--PT LT, rescale | 2 | final transform scale `(q0*q1)/Delta`, then q0-scale output | DFT rotations; sparse trace rotations |
| ModRaise | tower copy and two distribution switches | 0 multiplication levels | preserve q0 scale while restoring full Q basis | dense/sparse switching keys |
| PartialSum | rotate/add | 0 | no-op for full-pack gap=1 | gap-dependent rotations |
| R2C | CoeffsToSlots | 3 | matrix embeds `1/(N*16)` | DFT rotations and required conjugation/monomial keys |
| sine | degree-32 CT--CT polynomial | 6 | exact Gao 128-bit coefficients | relinearization |
| double angle | three square/rescale/affine rounds | 3 | exact Gao recurrence constants | relinearization |
| fused-`t^-1` C2Z | CT--PT LT | 1 | `diag(t^-1)*U` | Z-transform rotations |
| subtraction | level/scale adjustment and subtraction | 0 | align original and recovered error | none new |

Two depth values must be recorded separately:

```text
logical end-to-end A2A-e budget = 1 + 2 + 3 + 6 + 3 + 1 = 16;
post-ModRaise physical depth    = 3 + 6 + 3 + 1         = 13.
```

The pre-raise three levels land at q0. ModRaise returns to the full Q basis;
therefore Table 4's logical `L-16` budget does not imply a returned Lattigo
ciphertext whose physical level field is 16. Except for the q0 contract after
fused Truncate, source scale metadata is stage/modulus dependent and must be
traced exactly rather than replaced by a final decoded-value assertion.

## 4. Neighboring operator boundaries

### A2A-I

`EvalArithToArithHigh` (`z-fhe.cpp:299-318`) uses normal Z2R,
`SCALE_N_PRE` R2C, and normal C2Z. It has no sine or final subtraction and a
seven-level logical budget. Full A2A has the fixed order

```text
A2A-I -> A2A-e
```

at `z-fhe.cpp:384-388`; reversing it exposes A2A-e transforms to the large
integral component and is rejected. `[S1-code, S1-paper]`

### A2B

Sparse/full/direct-batched paths are at `z-fhe.cpp:391-813`; shared Boolean
transforms and two-LUT are at `:816-955`. The path is

```text
special-b0 Z2C
-> chunk mask and ModReduce
-> C2R / fused truncate / ModRaise / PartialSum / R2C
-> exponential two-LUT
-> residual update and rotation.
```

Special-b0 replaces only the first V0 row with `2*V0[1]`
(`z-fhe-precompute.cpp:191-195`). It is independent of `V*diag(t)`.

### B2A

`EvalBooleanToArith` (`z-fhe.cpp:1028-1036`) calls only special-A2AE C2Z,
using `diag(t^-1)*U`, then retags OpenFHE metadata. It has no C2R, ModRaise,
sine, or subtraction. The local standalone B2A slice is correctly classified
as a Lattigo adaptation until raw upstream state vectors exist.

## 5. Functional Lattigo A2A-e slice

The first non-secure wiring profile is preregistered as:

```text
n              = 8
ring           = Standard
LogN           = 5                     # 16 complex slots, four words
LogQ           = [35 x 17]             # 17 primes, 16 consumable levels
LogP           = [60]
DefaultScale   = 2^35
C2R levels     = [1,1]
R2C levels     = [1,1,1]
K              = 16
double angles  = 3
message ratio  = 1
packing        = full
```

It uses the existing `VFusedTPair()` and `UFusedTInvPair()`, raw DFT
matrices, the exact Gao degree-32 coefficients, three explicit double-angle
rounds, and the current guarded dense/no-switch ScaleDown/ModUp adapter. It is
`functional_not_secure` and `lattigo_adaptation`. Without the h=192 to h=32
encapsulated ModRaise path, it cannot be source-faithful.

The uniform Q35/P60 chain is a measured composition requirement, not a claim
about Gao's secure benchmark parameters. The accepted sine power chain requires
S35 at every multiplication. A previous provisional `[50,35 x 16],P50` chain
would make the post-CTS value enter the sine kernel near S50 and has no
zero-level, exact-scale path back to S35. The A2A-e-specific CTS therefore owns
both the semantic `1/16` normalization and a factor-scale schedule that lands
at the exact default scale. Its fused-`t^-1` U matrix similarly owns the scale
needed to rescale the recovered error to exact S35 at level 3; neither output
may be repaired with `SetScale`, metadata retagging, or an unbudgeted rescale.

The paper/source performance profile is separately frozen as `N=2^16`,
`n=8`, 8192 words, 32768 complex slots, `L=20`, 21 Q primes, approximately
43-bit Delta, seven 50-bit P primes, decomposition number three, sigma 3.2,
main secret h=192, sparse secret h=32, and C2R/R2C budgets 2/3.

## 6. Differential acceptance gates

Positive gates:

1. For n=8 basis vectors and all 256 words, verify
   `VFusedT=V*diag(t)` and `UFusedTInv=diag(t^-1)*U`.
2. On explicit `[m]_t/t + I + e`, prove the fused Z2R/refresh path recovers
   the error representative, fused C2Z maps it back to `e`, and subtraction
   preserves `m` while improving the declared noise diagnostic.
3. Trace pre-raise budget three, q0 ScaleDown output, scale-preserving
   ModRaise, post-raise physical depth 13, and logical budget 16.
4. Compare the exact fixed sine plus three recurrences with a high-precision
   scalar oracle over `[-16,16]`, including integer and noise boundaries.
5. Use a path spy proving A2B invokes special-b0 and two-LUT but not the A2A-e
   sine, fused-`t` Z2R, or final subtraction.
6. Retain exhaustive standalone B2A Boolean-half/raw-coefficient conformance.

Source-distinguishing negative gates:

- normal V/U or special-b0 V cannot replace the fused A2A-e pair;
- returning recovered `e` instead of `input-e` must fail the message oracle;
- a second ScaleDown after fused Truncate must fail state/numeric gates;
- A2B with fused-`t` V or A2A-e sine must fail its n=8 oracle;
- B2A with normal U must fail nontrivial raw-coefficient vectors;
- `A2A-e -> A2A-I` is assessed by precision/noise degradation on large-I
  inputs, not by assuming that every vector must decode incorrectly.

Gao fused Truncate and Lattigo ScaleDown remain different contracts. Promotion
requires seeded cross-library vectors for centered decoded coefficients, q0
landing, raw scale, and post-ModRaise value/scale.

## 7. Paper--code discrepancies

1. Paper A2A-e is named `EvalArithToArithNoise` in code.
2. A high-level paper description says special-b0 Z2R; detailed algorithm and
   code perform special-b0 Z2C, mask, then C2R.
3. Standalone `EvalTruncate` exists but is marked unused; live Truncate is
   fused into C2R.
4. An `EvalTruncate` comment says q0/2 while code metadata is q0.
5. `simple-ckks-bootstrapping.cpp:168-174` labels an A2Ae example but calls
   the High operator; `benchmark-full.cpp:204-231` calls the Noise operator.
6. The paper states OpenFHE 1.4.2 while pinned `CMakeLists.txt:28-31` declares
   1.4.0.
7. Paper/noise-test cutoff is `-16`; full benchmark uses `-24`.
8. Table 6 has no independent A2A-e time; only a full-A2A minus A2A-I
   inference is possible.
9. Lattigo v6.1.1 `mod1.SinContinuous` rejects nonzero double-angle settings
   and regenerates coefficients; it cannot stand in for Gao's fixed sine+3DA.

## 8. Implementation order

```text
fused matrix oracles
-> fused-Truncate/ScaleDown differential
-> functional dense ModRaise backbone
-> K=16 raw R2C normalization
-> exact degree-32 sine and three double angles
-> A2A-e with dual depth ledger
-> A2A-I then A2A-e
-> shared bootstrap backbone abstraction
-> special-b0/two-LUT A2B without calling A2A-e
-> exact-batch B-A2B
-> sparse-encapsulated ModRaise promotion work.
```

No A2A-e reproduction claim is made before the sine and Truncate differential
gates pass. No Gao key-path fidelity claim is made before the h=192/h=32
switching path is implemented and measured.
