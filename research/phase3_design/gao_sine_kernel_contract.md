# Gao A2A-e Exact Sine Kernel Contract

Status: implemented as an isolated `FUNCTIONAL-NOT-SECURE` Lattigo adaptation.
The second operational-dispatch audit repair is implemented and locally
verified; the independent re-audit accepted it at 0 Critical / 0 Major /
0 Minor. This is not an A2A-e reproduction claim.

Pinned Gao source commit:
`08f1eb87434e7be072cba889270a8400bbffc08e`.

## 1. Exact scalar semantics

The preceding R2C transform embeds `1/K`, with `K=16`. The kernel input is

```text
x = u/16 in [-1,1], where u is in [-16,16].
```

The header phrase “in [-16,16]” names the pre-normalized variable `u`; the
degree-32 Chebyshev polynomial itself is evaluated on `x in [-1,1]`.

The base target is

```text
g0(x) = (2*pi)^(-1/8) * cos(2*pi*(16*x - 1/4)/8).
```

The 33 source constants are ascending Chebyshev `T_i` coefficients. OpenFHE's
evaluation convention divides `c0` by two, so the mathematical polynomial is

```text
p0(x) = c0/2 + sum_{i=1}^{32} c_i*T_i(x).
```

Lattigo directly adds `Coeffs[0]`; a manual import must therefore divide only
the first source coefficient by two exactly once.

Three fixed double-angle rounds follow:

```text
p_(j+1) = 2*p_j^2 + r_j,  j=0,1,2
r0 = -(2*pi)^(-1/4)
r1 = -(2*pi)^(-1/2)
r2 = -(2*pi)^(-1)
```

In the ideal zero-approximation-error case,

```text
p3(x) = sin(32*pi*x)/(2*pi) = sin(2*pi*u)/(2*pi).
```

The exact recurrence numerators over denominator `2^128` are:

```text
-214928732683141070416123562033692253131
-135753023439836232162591007175785461952
-54157620742477409023451113735280473968
```

## 2. Pinned degree-32 coefficients

Each signed numerator below has denominator `2^128`; every imaginary part is
zero. The order is Chebyshev degree zero through 32.

```text
 0  +83554883558593341156762503528993204567
 1  -16306012819143647948975713401021095753
 2  +96601747242705937627150555596486294472
 3  -10189598517276305072350718402058306820
 4  +121060633236220369893857061438096148094
 5  +5140496634290316194783058668439513777
 6  +100495409965487171893958806222693651962
 7  +24229330335422135436851604093583455254
 8  -35210198440953349910397135793057630914
 9  +15311886605351491773147017323171236363
10  -145473136138920781961207264747490262523
11  -30741833736894896715423726116380449398
12  +125097585517474914520603377430295523953
13  +16782068243828144697612532317579843330
14  -49463398143066233903337385547582654922
15  -5140624783945922523649698647368979137
16  +12233809707070413755946479415658393860
17  +1056120164830265392342384475687453176
18  -2131685501108436666954167368614470691
19  -158603673235989998134290690894975991
20  +279469820658646095142599816571795196
21  +18344804074901673392718736965820196
22  -28771401482185452351376264247803869
23  -1693714708314538678609151232741534
24  +2397854839256579916125159675533236
25  +128149684565346523194831948305107
26  -165542301805254342444294230167176
27  -8109019875829502650635810444033
28  +9640100595106718768996691169391
29  +436164392778452373087215310130
30  -480554329501726644416052973191
31  -20180875894855208537597014500
32  +21539486933367133352719181825
```

The implementation constructs every value from signed `big.Int` and an exact
power-of-two denominator at least 256-bit precision. It never converts the
constants through `float64`.

## 3. Source path and operation order

`z-fhe.cpp:330-381` calls the kernel after `SCALE_NK_PRE` R2C. The fixed
polynomial call is at `:359-360`; the three rounds are at `:321-327,362-366`.
Each round is

```text
MulRelin -> ModReduce/Rescale -> double -> add r_j.
```

The source CT--CT multiplication automatically relinearizes but does not
automatically rescale (`z-leveledshe.cpp:135-144,317-335`). A Lattigo source-
ordered implementation uses `MulRelinNew`, `Rescale`, `Add(y,y)`, then
`Add(r_j)`. Lattigo `mod1.Evaluator` uses a different affine/rescale order and
is not the reproduction path.

## 4. Required Lattigo construction

Do not use `mod1.SinContinuous`: vendored v6.1.1 forces its double-angle count
to zero and regenerates a different `sin(2*pi*x)` approximation. Use:

```text
bignum.NewPolynomial(bignum.Chebyshev, exactCoefficients, [-1,1])
ckks/polynomial.NewEvaluator
PolynomialEvaluator.Evaluate
three explicit MulRelin/Rescale/affine rounds.
```

Both parity classes remain enabled because the phase-shifted base function is
neither even nor odd. The kernel operates analytically on complex CKKS slots;
it must not project them to their real parts.

For a nonuniform Q chain, derive the polynomial target scale backward from the
desired final scale. If the polynomial result is at level `Lp`, the three
rounds consume `q_Lp`, `q_(Lp-1)`, and `q_(Lp-2)`. Starting with final scale
`S`, apply `S <- sqrt(S*q_i)` in reverse consumption order. The evaluator must
reach this scale naturally; changing only the output scale tag is rejected.

The fixed functional profile is:

```text
LogN=5 (functional-not-secure)
LogQ=[35 x 10], LogP=[60], LogDefaultScale=35
```

This choice is required by the actual Chebyshev power-basis scale recurrence,
not merely by final-output retagging. Each doubling of the polynomial degree
approximately follows `s_(2k)=2*s_k-q` in log2 scale. The rejected Q60/S55
profile therefore collapses along `T2...T32` as
`55 -> 50 -> 40 -> 20 -> -20 -> -100`; Q60/S35 collapses still earlier.
Matching Q35/S35 keeps every generated power near 35 scale bits. P60 supports
relinearization/key switching but does not participate in this Q-rescale
recurrence.

The first operational-encoder audit found that the original implementation
validated an external `>=256`-bit encoder but left the polynomial evaluator on
the caller evaluator's default 53-bit encoder. The first repair shallow-copied
the caller evaluator and bound a shallow copy of the validated encoder. A
second independent audit then found that encoder binding alone was
insufficient: Lattigo's scalar `Add` and single-polynomial `MulThenAdd`
branches quantize through `Parameters.EncodingPrecision()` (53 here) and do
not call the evaluator's bound encoder. Both audit rounds were Major findings;
the second invalidated the first repair's claim about the live coefficient
path while leaving its private evaluator isolation mechanism useful.

The second repair changes the actual operand graph. The degree-32 polynomial
is supplied as one `ckkspolynomial.PolynomialVector` whose non-nil mapping
covers slots `0..15` exactly once. Lattigo consequently obtains every
coefficient through `GetVectorCoefficient` and dispatches vector `Add` /
`MulThenAdd`, which encode with `eval.Encoder.Encode`. Each of the three exact
dyadic recurrence constants is likewise expanded to an independent
16-element `[]*big.Float`, so every recurrence `Add` takes the vector branch.
The private evaluator remains bound to the validated 256-bit encoder; the
caller evaluator and encoder remain unchanged. Evaluation re-derives a trace
from the concrete polynomial mapping and recurrence operand lengths, fails
closed on drift, and records that trace with the actual operational precision
in result provenance.

A transparent-ciphertext dispatch sentinel uses the first exact recurrence
dyadic at scale `2^200`. On the same evaluator, both scalar `Add` and scalar
`MulThenAdd` lose `2.66736330e-17`, while their 16-slot vector counterparts
round-trip exactly at the 256-bit test precision. This test distinguishes the
vendored scalar and vector sources; it does not infer dispatch merely from a
precision accessor.

## 5. Dual depth ledger

Gao/OpenFHE reports degree 32 at six levels plus three double-angle levels:

```text
source kernel depth = 6 + 3 = 9.
```

Vendored Lattigo contains a power-of-two boundary discrepancy. Its simulation
helper reports `PolynomialDepth(32)=5`, but the public evaluator documents
`ceil(log2(deg+1))`, and the real degree-32 Chebyshev ciphertext trace consumes
six levels because the Paterson--Stockmeyer path performs its final rescale.
Three repeated encrypted runs observed level `8 -> 2`. The preregistered
five-level prediction is therefore falsified:

```text
vendored simulation prediction = 5 + 3 = 8 (falsified)
Lattigo ciphertext kernel depth = 6 + 3 = 9.
```

The isolated functional profile uses ten Q primes, starts the kernel at level
9, and records `[9,3,2,1,0]`. No `DropLevel` or scale retag is used. With a
full A2A-e ModRaise output level 16, the corrected physical ledger is

```text
R2C: 16 -> 13; kernel: 13 -> 4; C2Z: 4 -> 3.
```

This now matches Gao's 6+3 logical depth, although matching depth alone does
not prove an identical multiplication/rescale schedule. Every result records
the source ledger, the real ciphertext ledger, and the falsified vendored
simulation prediction separately.

The stable isolated measurements are:

```text
208 scalar probes:
  max base-polynomial error       6.69528901e-12
  max fixed-kernel analytic error 7.70672009e-11
second-repair encrypted five-run max error 1.533e-8 ... 1.068e-7
second-repair encrypted precision          23.16 ... 25.96 bits
exact metadata scale-delta        about 125.42 bits
second-repair targeted count=5     PASS
```

These are tiny functional-profile correctness measurements, not secure
precision or performance claims.

## 6. Independent plaintext oracle

At 256--512-bit precision:

1. construct exact dyadic coefficients from the pinned integers;
2. evaluate `c0/2 + sum c_i*T_i(x)` by an independent Clenshaw or explicit
   Chebyshev recurrence;
3. execute the three exact fixed recurrences;
4. separately compute `sin(32*pi*x)/(2*pi)`;
5. report base-polynomial approximation error, final fixed-kernel
   approximation error, and ciphertext-to-fixed-oracle error separately.

The scalar grid covers `[-1,1]`, the 33 Chebyshev nodes, roots approached by
`u=k+-2^-j`, extrema at `u=k+1/4,k+3/4`, endpoints, and `u=+-15.75`. A
conservative initial scalar gate is final maximum error below `2^-30`; the
actual measured maximum is archived rather than replacing this preregistration.

## 7. Ciphertext acceptance and negative gates

The first 16-slot ciphertext includes

```text
u = [0, +-0.125, +-0.25, +-0.75, +-7.75, +-15.75, 15.5, -15.5, 16, -16]
x = u/16.
```

It asserts input immutability, result-copy isolation, degree one output, exact
nine-level decrease, auditable per-stage scale, actual operational encoder
precision of at least 256 bits without mutating the caller evaluator, and a
preregistered functional precision threshold against the fixed scalar oracle.

At `u=0.25` (`x=1/64`), source-distinguishing diagnostic outputs are:

| Variant | Approximate output |
|---|---:|
| correct fixed kernel | `+0.159154943076` |
| conventional `sin(2*pi*x)/(2*pi)` | `+0.015599912391` |
| only two double-angle rounds | `+0.398942280392` |
| forgot `/16`, evaluates at `u=0.25` | approximately zero |

Additional negative probes:

- at `u=0.75`, correct is negative while conventional sine is positive;
- at `u=15.75`, an unnormalized Chebyshev evaluation diverges;
- at `u=0`, omitting the one required `c0/2` conversion yields roughly 4.88
  after three rounds;
- treating the coefficients as monomial-basis values fails the grid.

Formal expected values come from the high-precision oracle, not these
double-precision diagnostics.

## 8. Promotion blockers

- R2C must certify that the kernel input is exactly the `u/16` domain.
- Seeded OpenFHE intermediate values are absent for polynomial input, each
  double-angle state, raw scale, and levels.
- Vendored `PolynomialDepth(32)=5` disagrees with the public evaluator and
  ciphertext trace, which consume six levels. The fixed slice records this
  discrepancy; exact source scheduling still needs operation-level traces.
- Full A2A-e still depends on the fused-Truncate/ModRaise differential and the
  h=192/h=32 switching path.
- The n=8/LogN=5 profile is functional-not-secure.
- Windows CGO is disabled on this host, so the Go race gate is unavailable;
  ordinary repeated tests, vet, formatting, and the repository suite pass.
- An isolated kernel pass does not verify both R2C branches, fused C2Z, or
  final `original-error` subtraction.

Primary artifact hashes:

```text
z-fhe-constants.h  9C8F020E4D46DAA01D3F554082270232AA3DE1F92612E66D61340AE46D062B6B
z-fhe.cpp           7CE844CE40829AB39B1F93EC376770020739D5DCE9CE89574A05BDD9F61AF6D5
cheby.py            3318800EFD09ABD9768CCDB5B0C2B06188A34C29C862E7A5929D8EB3616A5B4E
```
