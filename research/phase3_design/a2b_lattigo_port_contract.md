# Gao A2B Lattigo Port Contract

Status: Stage-2 source map and independently accepted fixed-slice contract.
The encrypted `n=8,w=4,d=2` serial graph passed its stable repair audit at
0C/0M/0m; no secure-performance, source-secure, normalized-input-certified, or
general-width claim is made.

Pinned upstream commit: `08f1eb87434e7be072cba889270a8400bbffc08e`.

## 1. Fixed first slice

The first encrypted slice is regular full-packed A2B with:

```text
n=8, w=4, d=ceil(n/w)=2
standard CKKS ring, LogN=5, 16 slots
four Z2^8 words/ciphertext
output=[low4 LSB-first, high4 LSB-first]
fidelity=functional Lattigo adaptation
maturity=functional_not_secure
```

This slice is intentionally not B-A2B, A2A-e, B2A, or a generic dispatcher.

## 2. Exact upstream graph

Primary code anchor: `research/upstream/fhe-simd-alu/src/pke/lib/scheme/ckksrns/z-fhe.cpp:485-579`.

The source path is:

1. `EvalZ2C(ct, Z2C_SPECIAL_B0)` produces `core0/core1`.
2. For each of the two four-bit chunks, select its half, multiply by the
   chunk mask, and modulus-reduce.
3. Run one D-CKKS Boolean refresh and the shared-power two-LUT kernel to
   obtain both `ID` and `MSB`.
4. Propagate scaled `ID` to future chunks, including the cross-half rotation
   correction, and subtract it from the residual core.
5. Subtract the current `ID`, accumulate MSB within its half, and finally
   return `[MSB0,MSB1]`.

For `n=8,w=4`, this specializes to:

```text
iter 0: low half -> ID0, MSB0
        raw future distance=-4; cross-half correction +4
        effective residual rotation=0
        subtract ID0/16 from high core; subtract ID0 from low core
iter 1: high half -> ID1, MSB1; no future propagation
return [MSB0, MSB1]
```

Consequently the residual-peeling rotation-key set is empty in this one
special case. That fact must not be generalized to larger `n`.

## 3. special-b0 and packing

Source anchors:

- `z-fhe.cpp:97`: special-b0 replaces only V0; V1 remains normal.
- `z-fhe-precompute.cpp:191`: `V0SpecialB0[0][i] = 2*V0SpecialB0[1][i]`.
- local exact matrix/spec: `integer/homchain/matrix.go:137` and
  `integer/homchain/spec.go:108`.

If `a=ArithmeticEncode(m).Coefficients()`, one word's two four-slot blocks are:

```text
low  = [2*a1, a1, a2, a3]
high = [a4,   a5, a6, a7]
```

The existing full-slot block-diagonal transform must preserve word boundaries.
At `n=8,w=4`, each source chunk mask numerically covers its complete half.
Omitting the multiply/rescale is therefore a separately labeled Lattigo
schedule optimization, not a source-operation reproduction.

Normal V, fused-t V, normal U, and fused-t-inverse U are not acceptable
substitutes for the special-b0 ingress.

## 4. Boolean refresh backbone

Source anchor: `z-fhe.cpp:816-844`. Regular A2B refreshes each selected half
with the sparse helper:

```text
C2R
-> EvalModRaisePartialSum
-> R2C(SCALE_NK_PRE)
```

It must not call the two-ciphertext full helper at `z-fhe.cpp:846-866`.

The guarded full-packed Lattigo adaptation is:

```text
SlotsToCoeffs:
  HomomorphicDecode, SplitRealAndImag, Levels=[1,1], Scaling=1
ScaleDown(copy) -> level 0
ModUp -> MaxLevel
Trace/partial-sum -> identity at full packing
CoeffsToSlots:
  HomomorphicEncode, SplitRealAndImag, Levels=[1,1,1], Scaling=1/16
```

The inverse scaling `1/16` represents upstream `1/(N*K)` with `K=16`;
Lattigo's split-real HomomorphicEncode also supplies its built-in
`1/(2*slots)=1/N` factor (`vendor/.../ckks/dft/dft.go:749`). The current
A2A-I `RawFullSlotDFT`, whose two literal scalings are fixed to one, cannot be
reused as an authoritative A2B configuration.

Only a parameterized refresh backbone may be shared with A2A-e. Its R2C
scaling, transform family, operator certificate, and digest remain distinct.

## 5. Exponential and shared-power two-LUT

Source anchors: `z-fhe.cpp:868` and `z-fhe-precompute.cpp:239`.

```text
guarded refresh + CTS /16 output y = (I + m/16)/16 in [-1,1]
-> degree-46 P(y) approximating exp(i*8*pi*y)
-> square/rescale
-> square/rescale
-> exp(i*32*pi*y) = exp(i*2*pi*(I+m/16)) = exp(i*2*pi*m/16)
-> one shared power basis
-> degree-15/order-1 ID LUT
-> degree-15/order-1 MSB LUT
-> add conjugate to both outputs
```

CTS Scaling=`1/16` is the change of basis; the kernel must not divide again.
The integral lift `I` is generally nondeterministic under the guarded Lattigo
ScaleDown/ModUp adaptation, but the two squarings remove it periodically. The
composition witness therefore checks `16*y-m/16` against the nearest integer
and evaluates several admissible integer lifts. A deterministic `y=m/16`
assertion is false. Conversely, a standalone zero-lift test that feeds code
`m` as `m/16` instead of `m/256` makes the squared exponential approximately
one for all 16 codes and must fail both LUT oracles.

The fixed exponential is budgeted as six polynomial levels plus two square
levels. ID and MSB must share the power basis/BSGS decomposition, using
`EvaluateMultiPoly` or an explicit power basis with two
`EvaluateFromPowerBasis` calls. Two unrelated generic `Evaluate` calls do not
reproduce the source graph or its cost.

The separate 47-term complex Chebyshev table is frozen as
`research/phase3_design/a2b_exp16_degree46.tsv`. Each real/imaginary signed
numerator has denominator `2^128`; the LF-canonical SHA-256 is:

```text
a960edc18c4c7dee294d0f452eb3ef377c1d2094dadc0a046f49a68902e36e4d
```

`research/scripts/extract_a2b_exp46.ps1` requires exactly one named vector and
exactly 47 matching `BigComplex(BigFixedPoint(...))` entries in the pinned
header before emitting the table. The upstream header SHA-256 is
`9c8f020e4d46daa01d3f554082270232aa3de1f92612e66d61340ae46d062b6b`;
the extractor SHA-256 is
`e6b6161ecaa23a6a9e16a48820fe8a4153ba4276c240790225d0902003b6c704`.
OpenFHE's PS evaluator divides the free Chebyshev term by two. A Lattigo import
therefore divides only coefficient zero by two once. In composition it
evaluates the table directly on the CTS output `y=(I+m/16)/16`; no additional
scale bridge is applied. Its base target is `exp(i*8*pi*y)`; the two source
squares produce `exp(i*32*pi*y)=exp(i*2*pi*(I+m/16))`. The isolated exp46
oracle's generic notation `x=u/16` remains valid only when its `u` denotes the
entire pre-normalization value `I+m/16`, not the four-bit code itself.

For `p=16`:

```text
ID(0)=0
ID(x)=(x-16)/16, x in {1,...,15}

MSB(x)=1, x in {1,...,8}
MSB(x)=0, x in {0,9,...,15}
```

Gao's MSB is therefore not the conventional `x>=8` bit. The order-1 Hermite
coefficients are produced upstream through a double-complex DFT, a `2^-32`
threshold, and 128-bit fixed-point conversion. The converted coefficient
artifacts and their digests must be frozen; runtime approximation generation
cannot carry a source-faithful label.

The exact `p=16`, order-1 artifacts are now frozen in
`research/phase3_design/a2b_lut_p16_order1.tsv`. Each row is
`name, degree, signed-real-numerator, signed-imaginary-numerator`, with the two
numerators divided by `2^128`. Its canonical SHA-256 is:

```text
f3aa5c55fa47acd6c5a0f96d362d442948c6b2999d3bd4a6061870d3d21564e3
```

`research/scripts/dump_a2b_lut_coefficients.cpp` is a dependency-free replay
of the pinned upstream operation order. It reproduces `M_PI`, the nested
`std::complex<double>` DFT, the inclusive `2^-32` truncation test, the `c0/2`
step, and `BigFixedPoint::fromDouble(..., 128)`. On the recorded environment
(`g++ 11.4.0`, glibc 2.35, x86-64 WSL2), `-O0` and `-O2` emit identical bytes.
The reconstructed `2*Re(poly(exp(2*pi*i*x/16)))` grid errors are at most
`6.6613381477509392e-16` for MSB and `3.9378222904673521e-16` for ID.

The provenance hashes are:

| Input/artifact | SHA-256 |
|---|---|
| upstream `hermite.cpp` | `6fd6657103cdaec38a5ffcb313a4f1d013d59e58b45fa7d988258524650b5e16` |
| upstream `bigfixedpoint.h` | `232b348a13a45cf679fc2678a7775c68d44203dfc55f3eee028aeccb6228df4f` |
| upstream `z-fhe-precompute.cpp` | `067ae4dafbbada2d1953e6f1e465b87af8071efaa2154cb0e48a251f7733295` |
| local replay generator | `b97fae59bd5b41bb557d356b34e12a03290dac328f7ca6592adddc9b8a305ec1` |
| canonical coefficient table | `f3aa5c55fa47acd6c5a0f96d362d442948c6b2999d3bd4a6061870d3d21564e3` |

The encrypted port must parse the frozen table and independently recheck all
16 ID/MSB points. It must not silently regenerate coefficients with Go's
complex arithmetic or a different libm.

## 6. Logical and physical ledgers

The paper gives the A2B allowance `L-18` (`eprint-2026-0233...txt:1293`):

| Source component | Logical levels |
|---|---:|
| C2R | 2 |
| R2C | 3 |
| exponential | 6 |
| two squares | 2 |
| degree-15/order-1 shared LUT | 5 |
| special-b0/mask | separately charged |

A first functional Lattigo trace should start at `MaxLevel=20` and measure,
not assume, this provisional ledger:

| Stage | Provisional level | Scale contract |
|---|---:|---|
| input | 20 | exact default Delta |
| special-b0 Z2C | 19 | Delta |
| mask/rescale | 18 | Delta |
| STC `[1,1]` | 16 | Delta |
| guarded ScaleDown | 0 | exact recorded Delta0 |
| ModUp | 20 | unchanged Delta0 |
| CTS `[1,1,1]` | 17 | must match the sealed kernel ingress scale |
| exp degree 46 | 11 | target Delta |
| two squares | 9 | target Delta |
| Lattigo shared multi-polynomial LUT | 5 | exact default Delta target |
| add conjugate | 5 | exact default Delta |
| source `ID/16` update | 4 | exact default Delta |

Vendored Lattigo's generic degree-15 evaluator advertises four levels while
the upstream PS schedule charges five. A four-level physical result is a
`lattigo_optimized_adaptation`; reproducing the upstream cost requires its
fixed five-level PS schedule. Every actual level and exact scale remains a
runtime assertion until the ciphertext trace is green.

The first stopped refresh trace used `LogMessageRatio=0`. It was green as a
bounded normalization diagnostic but not composable: special/mask/STC carried
approximately S35, while ScaleDown set the raw scale near q0 and CTS returned
`L17/S50`; the isolated kernel correctly rejected that state. The local
zero-extra-level repair compiles special-b0 with matrix scale `q_20`, uses
`LogMessageRatio=15`, and folds Lattigo's bootstrap-constructor initialization
factors into separate execution DFT literals. The raw paper literals remain
STC Scaling=`1` and CTS Scaling=`1/16`; the execution literals apply STC
`2^15` and CTS `qDiv/(K*QDiff)`. Five direct all-256 refresh-to-kernel runs now
reach exact `L17/S35` without retagging or another rescale, with lattice
distance below `8.6e-8` and ID/MSB error below `1.31e-6`. Independent audit
accepted this bounded first-refresh seam at 0C/0M/0m. No full-A2B claim may
cross the still-unaccepted serial second-refresh boundary.

Packing is `S=N/2` CKKS slots, four slots/word, `N/8` words/ciphertext. Each
regular `n=8` A2B invocation performs two Boolean refreshes and returns two
full-slot ciphertexts.

The ledger above describes the first refresh. The two refreshes are serial,
not parallel: after the first LUT, source `EvalSubWithAdjustInPlace` lowers
`core1` to the scaled `ID0/16` level before the second mask. Consequently a
Lattigo full composition cannot reuse a SlotsToCoeffs matrix whose `LevelQ`
is fixed to the first refresh's level 16. It must construct a second matrix at
the measured post-update/post-mask level. The isolated encrypted kernel now
fixes ID/MSB at level 5 and exact default S35 through the shared polynomial
evaluator's documented target-scale correction; the source `ID/16`
multiplication/rescale remains exact S35 at level 4;
after aligning the untouched high core and applying the second mask, the
second SlotsToCoeffs ingress is therefore level 3. The first real A5 serial
trace now confirms `L3 -> STC L1 -> ScaleDown L0 -> ModUp L20 -> CTS L17 ->
kernel L5`, all at exact S35 and without an extra bridge. This is an
author-side functional milestone; exhaustive output, self-removal, sealed
profile/key checks, and independent audit remain required. Two independent
high-level refreshes are still only a backbone test and are not a complete
A2B reproduction.

For signed comparison, a separately accepted rank-one egress consumes only
the high Boolean half at L5/S35. It maps column 3 of each four-slot word
through the first column of fused `U0*t^-1`, uses BSGS `N1=2`, rotations
`[1,2]`, and returns arithmetic `b7` at L4/S35 after one rescale. Its profile
digest is `68b3bcc5...74a4ae`, and all-256, block-isolation, semantic-B2A,
real-kernel, key, graph, and provenance gates passed an independent 0C/0M/0m
audit. This is not yet a complete comparator: subtraction range/no-overflow,
the public `1-b7` orientation, and the same-input encrypted-isolation timing
baseline remain separate acceptance gates.

## 7. Propagation cutoff

- paper/default: cutoff `-16` (`z-fhe.h:136`);
- full benchmark: cutoff `-24` (`benchmark-full.cpp:103`).

The exact break condition is `rotationIndex <= cutoff`. At `n=8,w=4`, the
only raw distance is `-4`; both variants propagate it and have identical
ciphertexts, levels, and residual rotation keys. Their profile digests must
still differ.

The distinguishing test must use `n=32,w=4`:

```text
cutoff -16 propagates chunk distances {1,2,3}
cutoff -24 propagates chunk distances {1,2,3,4,5}
```

This test must also distinguish `<` from the source's inclusive `<=` cutoff.

## 8. Plaintext and ciphertext oracles

The exact local plaintext oracle is `integer/z2n/boolean_oracle.go`, with
exhaustive `p=16` tests in `boolean_oracle_test.go`.

For bits `b0..b7`, chunk `q`, slot `r`:

```text
u(q,r) = sum[j=0..r] b[4*q+r-j] * 2^(3-j)
code   = (16-u) mod 16
ID     = 0 if code=0, otherwise (code-16)/16 = -u/16
MSB    = b[4*q+r]
```

For `m=0xA5`:

```text
iter0 u=[8,4,10,5], ID=[-1/2,-1/4,-5/8,-5/16], MSB=[1,0,1,0]
independently re-encoded high-prefix oracle:
  u=[0,8,4,10], ID=[0,-1/2,-1/4,-5/8], MSB=[0,1,0,1]
source-scheduled serial residual after elementwise ID0/16 propagation:
  rawHigh=[-5/32,-37/64,-37/128,-165/256]
  ID0/16=[-1/32,-1/64,-5/128,-5/256]
  highUpdated=ID1=[-1/8,-9/16,-1/4,-5/8]
final low=[1,0,1,0], high=[0,1,0,1]
```

The two ID rows are deliberately different. At pinned upstream
`z-fhe.cpp:543-545`, ID0 is scaled by `2^-4`; lines 546--555 change the raw
cross-half distance `-4` to effective rotation zero by adding `n/2`; line 558
then subtracts the scaled ID elementwise from the high core. No slot broadcast
or residual rotation is executed for `n=8,w=4`. The independently re-encoded
high-prefix ID remains a useful Boolean semantic oracle, but it is not the
physical second-iteration residual and must not be used as that intermediate
ciphertext's expected value. Across all 256 words and four high slots, these
two residual models differ in 544 of 1,024 cases even though both yield all
1,024 final MSB bits correctly. The exhaustive gate must therefore compute
`rawHigh-ID0/16` from independent plaintext source oracles; deriving the
expected residual or ID1 from decrypted `HighUpdated` is self-referential.

Encrypted gates must inspect:

1. special-b0 raw coefficient blocks;
2. masked prefix residues;
3. exact level/scale at STC, ScaleDown, ModUp, and CTS;
4. the normalized `y=(I+m/16)/16` state, integer-lattice residual, and
   exponential accuracy/invariance against high-precision
   `exp(i*2*pi*(I+m/16))` semantics;
5. ID/MSB on all 16 code points;
6. the `ID0/16` elementwise high-core update against the source-scheduled
   residual oracle, with the independently re-encoded prefix retained as a
   source-distinguishing negative;
7. all 256 final low/high bit outputs in LSB order; and
8. input and saved-core immutability.

## 9. Key/profile contract

The minimal functional key union is:

- relinearization key;
- special-b0 V0/V1 compiled-transform Galois keys;
- STC and CTS `MatrixLiteral.GaloisElements(params)`;
- conjugation key;
- residual rotations (empty only for `n=8,w=4`);
- Trace rotations (empty only at full packing).

Normal/fused U and C2Z keys are absent. A source-secure profile separately
requires dense-to-sparse and sparse-to-dense switching keys for `h=192` and
`h-tilde=32`; the first functional slice is dense/no-switch and cannot inherit
that security claim.

Provisional functional parameters:

```text
Standard, LogN=5
LogQ=[50,35x20], LogP=[50], LogDefaultScale=35
n=8,w=4,d=2,full packing
STC=[1,1],Scaling=1
CTS=[1,1,1],Scaling=1/16
K=16, cutoff=-16 or -24
exp degree46 + two squares
ID/MSB degree15, Hermite order1, explicit BSGS
dense/no-switch guarded refresh
```

The immutable profile/digest binds parameters, exact scales, cutoff,
coefficient artifacts, BSGS, DFT literals, key union, transform family, and
packing.

## 10. Source-distinguishing negatives and blockers

Required negatives include normal/fused-t V, conventional sign bit, `ID=x/16`,
standalone code input `m/16` instead of zero-lift `m/256`, an extra `/16`, one missing square,
cosine/sine/EvalMod substitutions, independent LUT power
bases, omitted cross-half correction, low/high swap, MSB-first order, cutoff
`<`, sparse/partial input, and every missing key before mutation.

Current blockers to an upstream-faithful or secure label are:

- no pinned OpenFHE intermediate ciphertext/level/scale trace;
- no numeric differential proof for Lattigo ScaleDown/ModUp and upstream
  `q0/SCALE_NK_PRE` normalization;
- no sparse-secret switching implementation/evidence;
- frozen exp46 and Hermite LUT profiles have not yet been composed into and
  validated on the encrypted shared-power A2B graph;
- generic Lattigo LUT depth differs from the upstream PS ledger;
- the 21-Q-prime functional profile has not yet executed;
- `n=8` cannot distinguish cutoff variants; and
- no centered-noise bound, failure margin, or security estimate.

Until these close, the strongest admissible label is
`functional Lattigo adaptation`.
