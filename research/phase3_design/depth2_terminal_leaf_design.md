# Depth-2 child decoding and terminal-leaf selection design

Date: 2026-08-30
Stage: ARS Stage 2
Status: implementation-ready design; the accepted child comparator is a hard
dependency

## Decision and source of truth

The depth-2 source-faithful tree returns an encrypted ordinary CKKS real leaf.
The child comparison therefore gets a child-specific periodic decoder, and a
terminal module consumes that decoder output together with the authenticated
root selector.

There is no constructor or binder that accepts a leaf slice. The four leaves
are derived once from the exact tree owned by the accepted prefix:

```go
tree := child.prefix.Profile().Tree()
// Require depth=2, len(tree.Leaves)=4 and a valid frozen R0 schedule.
l00, l01, l10, l11 := tree.Leaves[0], tree.Leaves[1], tree.Leaves[2], tree.Leaves[3]
```

`TreeDigest`, `ScheduleDigest`, the four IEEE-754 bit patterns and every
derived leaf operand enter the terminal profile digest. Changing a leaf means
constructing a new prefix, child comparator, decoder and terminal module. A
free leaf list, a post-construction leaf setter, or a caller-supplied
certificate is forbidden.

The tree order is the `treeplan.BinaryTree` MSB-first order. Branch `0` means
LT and branch `1` means GE, so equality goes right. Correctness tests use
`BinaryTree.Route`/`Evaluate` as their oracle; they must not use the HE mux
formula as the oracle.

## External seams

The modules expose small interfaces and keep the execution graph, cached
plaintexts and provenance derivation private:

```go
func NewSigned8Depth2ChildSelectorDecodeCircuit(
    child *Signed8Depth2ChildComparatorCircuit,
) (*Signed8Depth2ChildSelectorDecodeCircuit, error)

func (c *Signed8Depth2ChildSelectorDecodeCircuit) BindChildResult(
    childInput Signed8Depth2ChildComparatorInput,
    childResult Signed8Depth2ChildComparatorResult,
) (Signed8Depth2ChildSelectorDecodeInput, error)

func (c *Signed8Depth2ChildSelectorDecodeCircuit) BindEvaluator(
    source *bootstrapping.Evaluator,
) (*Signed8Depth2ChildSelectorDecodeEvaluator, error)

func NewSigned8Depth2TerminalLeafCircuit(
    child *Signed8Depth2ChildComparatorCircuit,
) (*Signed8Depth2TerminalLeafCircuit, error)

func (c *Signed8Depth2TerminalLeafCircuit) BindChildResult(
    childInput Signed8Depth2ChildComparatorInput,
    childResult Signed8Depth2ChildComparatorResult,
) (Signed8Depth2TerminalLeafInput, error)

func (c *Signed8Depth2TerminalLeafCircuit) BindEvaluator(
    source *bootstrapping.Evaluator,
) (*Signed8Depth2TerminalLeafEvaluator, error)
```

The terminal constructor internally constructs and owns the child decoder.
Its `BindChildResult` calls the owned decoder's binder and also takes an owned
copy of `childInput.operands.conditionedSelector`. The caller never supplies
`b0`, `b1`, leaves, deltas, plaintext caches or a magnitude certificate.

The terminal evaluator runs the decoder and mux as one closed operation:

```go
EvaluateNew(input Signed8Depth2TerminalLeafInput) (
    Signed8Depth2TerminalLeafResult,
    Signed8Depth2TerminalLeafTrace,
    error,
)
```

The standalone decoder evaluator remains available for its focused acceptance
tests. The combined terminal evaluator does not admit a caller-created decoded
result.

## Child-result admission and mode binding

Both binders take the pair `(childInput, childResult)`. Before copying any
ciphertext they perform all of the following checks:

1. `child.validateInput(childInput)` and
   `child.validateResult(childResult)` both succeed.
2. `childResult.InputBindingDigest() == childInput.BindingDigest()` and
   `childResult.OperandsProvenanceDigest() ==
   childInput.OperandsProvenanceDigest()`.
3. The child profile, prefix profile, parameter, protocol-range, tree,
   schedule and operand-source digests all match the exact owned child and
   prefix profiles.
4. The result's current branch payload digest matches its sealed output digest;
   the input's current feature, threshold and conditioned-selector payloads
   match the complete operands provenance.
5. The root operand mode is derived only by comparing
   `childInput.operands.producerProfileDigest` with the exact public and opaque
   producer profile digests owned by `child.prefix.selector.producer`. The
   only admitted values are `Signed8PublicThresholdCTPT` and
   `Signed8OpaqueThresholdCTCT`.
6. The derived mode, producer digest, child-input binding and operands
   provenance are copied into the decoder/terminal input digest. A public
   input paired with opaque provenance, or the reverse, fails admission.

The child branch is copied only from `childResult.branch`. The root branch
`b0` is copied only from the same admitted
`childInput.operands.conditionedSelector`; it is never accepted as a raw
ciphertext or recovered from another prefix token. Thus an input/result
cross-pair, even one with identical public metadata, cannot supply a branch.

The child decoder must not construct or retag a `Signed8ComparatorResult`, and
must not call `SelectorReraiseDecodeCircuit.BindComparatorResult`. Either act
would launder a child producer through the root producer seam. The decoder may
orchestrate the accepted selector evaluator's package-private mathematical
helpers after its own child-specific admission has succeeded:

```text
evaluateNormalV -> evaluateSlotsToCoeffs -> guarded ScaleDown -> dense ModUp
-> evaluateCoeffsToSlots -> evaluatePeriodicBoolean
```

Its schemas are distinct:

```text
signed8-depth2-child-selector-decode-profile-v1
signed8-depth2-child-selector-decode-input-v1
signed8-depth2-child-selector-decode-result-v1
signed8-depth2-child-selector-decode-trace-v1
signed8-depth2-terminal-leaf-profile-v1
signed8-depth2-terminal-leaf-input-v1
signed8-depth2-terminal-leaf-result-v1
signed8-depth2-terminal-leaf-trace-v1
```

## Base-selector graph seal

The child decoder derives its numerical graph from the exact
`child.prefix.selector`, but replaces the root producer admission/result
schemas with the child-specific schemas above. At evaluator bind time it may
call the base selector's `BindEvaluator(source)` to construct the already
audited helper graph. It never calls that evaluator's public `EvaluateNew`.

The wrapper seals all helper objects it will dereference: base selector
circuit/evaluator, bootstrap source, main CKKS evaluator, DFT evaluator,
linear-transform evaluator, periodic kernel source/CKKS/polynomial evaluator,
256-bit encoder, key set, relinearization key, the seven Galois keys, DFT
literals, compiled linear transforms, polynomial operands, affine plaintexts
and their immutable payload copies. It records the corresponding vendor
`RuntimeIdentitySnapshot` values for CKKS, RLWE buffers/evaluator, DFT,
linear-transform, polynomial and encoder objects.

Every `EvaluateNew` performs the wrapper graph comparison, vendor snapshot
comparison, exact key inventory/identity check, immutable-cache digest check,
`baseEvaluator.preflight()` and child-specific input validation before the
first HE operation. A self-consistent foreign base evaluator is rejected. The
same comparisons run after execution to prove that normal scratch use did not
replace graph topology or caches. No reflection over private layouts and no
`unsafe` seal is allowed.

## Exact child-decoder contract

Let `S` be `params.DefaultScale()` and

```text
T = S^2/q11
R = T^2/q10 = S^4/(q11^2*q10).
```

The admitted child arithmetic branch is `L4/S`, degree 1, four repeated
four-slot words. The decoder records these 19 ordered degree-1 states:

| # | Stage/lane | Level | Scale |
|---:|---|---:|---|
| 0 | child arithmetic selector / whole | 4 | `S` |
| 1 | normal-V raw / low | 4 | `S*q4` |
| 2 | normal-V raw / high | 4 | `S*q4` |
| 3 | normal-V rescaled / low | 3 | `S` |
| 4 | normal-V rescaled / high | 3 | `S` |
| 5 | STC factor 0 / whole | 2 | `S` |
| 6 | STC factor 1 / whole | 1 | `S` |
| 7 | guarded ScaleDown / whole | 0 | `S` |
| 8 | dense no-switch ModUp / whole | 20 | `S` |
| 9 | CTS factor 0 / whole | 19 | `S` |
| 10 | CTS factor 1 / whole | 18 | `S` |
| 11 | CTS factor 2 / whole | 17 | `S` |
| 12 | shared CTS split / low | 17 | `S` |
| 13 | shared CTS split / high | 17 | `S` |
| 14 | accepted exp46 / low | 11 | `S` |
| 15 | periodic square 0 / low | 10 | `T` |
| 16 | periodic root of unity / low | 9 | `R` |
| 17 | affine raw / low | 9 | `R*q9` |
| 18 | periodic Boolean scalar / whole | 8 | `R` |

The exact operation ledger is inherited mathematically, not by copying root
producer provenance:

```text
linear transformations                 7
diagonal plaintext products            35
non-conjugation rotations              19
conjugations                            3
key switches                            22
ciphertext additions/subtractions      34
scalar multiplications by +/-i          2
explicit rescales                      10
ScaleDown                               1
ModUp                                   1
exp46 polynomial evaluations            1
ciphertext-ciphertext products          2
relinearizations                        2
ciphertext-plaintext products           1
plaintext-vector additions              1
ID/MSB LUT evaluations                  0
logical peak live ciphertexts           8
```

The exact key union is Galois elements
`[5,17,25,33,41,49,63]` plus relinearization. The child-specific profile
binds that union and the exact key identities.

The decoder byte schema renames the former root-facing `OnlineInput` and
`OnlineOutput` as internal boundaries:

| Decoder field | Bytes | Classification |
|---|---:|---|
| child arithmetic input, L4 | 2,942 | internal |
| normal-V low, L3 | 2,414 | retained local evidence |
| normal-V high, L3 | 2,414 | retained local evidence |
| slots-to-coefficients, L1 | 1,358 | retained local evidence |
| raised coefficients, L20 | 11,390 | retained local evidence |
| coefficients-to-slots low, L17 | 9,806 | retained local evidence |
| coefficients-to-slots high, L17 | 9,806 | retained local evidence |
| exponential base, L11 | 6,638 | retained local evidence |
| periodic root, L9 | 5,582 | retained local evidence |
| decoded child selector, L8 | 5,054 | internal |

The retained subtotal is 49,408 bytes and the decoder module total is 57,404
bytes. None is online communication in the composed tree.

## Four-leaf mux

Let `b0` be the authenticated root branch and `b1` the decoded selected-child
branch, with `0=LT` and `1=GE`. Define from the frozen tree:

```text
dL = l01 - l00
dR = l11 - l10
dX = l10 - l00
cross = dR - dL = l11 - l10 - l01 + l00

A = l00 + b1*dL
D = dX + b1*cross
y = A + b0*D
```

For Boolean branches this is exactly

```text
(1-b0)(1-b1)l00 + (1-b0)b1l01
+ b0(1-b1)l10 + b0b1l11.
```

The form uses one CT--CT interaction and two CT--PT products. It is
source-equivalent to the CCS depth-2 final selection and is a Lattigo
constant-delta adaptation.

## Exact terminal schedule

Let

```text
B = q8*S/R.
```

For the current manifest, `S=34359738368`, `q7=34359736513`,
`q8=34359736193`, `R≈34359734909.000515` and
`B≈34359739651.99961`. The profile stores exact `ExactScaleSnapshot` values;
these decimals are audit aids, not reconstruction inputs.

Inputs:

```text
b1 : L8/R       owned child periodic-decoder output
b0 : L7/q7      owned conditioned selector from the same prefix operands
```

Cached repeated-real plaintext vectors:

```text
PT(dL)  : L8/B
PT(cross): L8/B
PT(l00) : L7/S
PT(dX)  : L7/S
```

Execution:

```text
rawA = b1 * PT(dL)        L8/(q8*S)
a    = Rescale(rawA)      L7/S
A    = a + PT(l00)        L7/S

rawD = b1 * PT(cross)     L8/(q8*S)
d    = Rescale(rawD)      L7/S
D    = d + PT(dX)         L7/S

rawY = MulRelin(b0,D)     L7/(q7*S)
z    = Rescale(rawY)      L6/S
A6   = DropLevel(A,1)     L6/S
y    = A6 + z             L6/S
```

`Lx/(...)` denotes level and exact scale, not division of the plaintext
message. There is no `SetScale`, metadata retag, bootstrap, rotation or
operand-dependent branch. The wrapper ledger is exactly:

```text
CT--PT multiplications       2
CT--CT multiplications       1
relinearizations             1
rescales                     3
plaintext-vector additions   2
ciphertext additions         1
level drops                  1
rotations                    0
```

All four cached plaintexts are constructed and all fixed operations execute
when any leaf delta is zero. Equal-leaf relationships cannot change timing,
counts, states or byte accounting. The terminal adds no Galois element; its
relinearization key is already present in the decoder union.

## Typed leaf-magnitude certificate

The current parameters are fixed at `LogN=5`, 16 slots,
`LogQ=[50,35x20]`, `LogP=[50]` and `LogDefaultScale=35`. Version 1 uses a
conservative finite-real policy that leaves at least 15 magnitude-free bits at
the default scale and at least 192 bits of ideal centered-message headroom at
every cached/plain/ciphertext state:

```go
const (
    signed8Depth2LeafCertificatePrecision       = uint(256)
    signed8Depth2LeafMaxAbs                      = 1 << 16
    signed8Depth2IntermediateMaxAbs              = 1 << 20
    signed8Depth2SelectorAbsErrorNumerator       = 1
    signed8Depth2SelectorAbsErrorDenominator     = 1 << 8  // eps = 2^-8
    signed8Depth2ArithmeticSlackNumerator        = 1
    signed8Depth2ArithmeticSlackDenominator      = 1 << 12 // eta = 2^-12
    signed8Depth2MinimumIdealCenteredHeadroomBits = 192
    signed8Depth2CacheRoundingPolicy = "big-float-256-nearest-even-rat-v1"
    signed8Depth2IdealHeadroomPolicy = "exact-rational-cross-multiply-v1"
)

type Signed8Depth2ExactRationalSnapshot struct {
    numerator, denominator string // canonical reduced big.Rat integers
}

type Signed8Depth2LeafMagnitudeLedger struct {
    leaves                         [4]Signed8Depth2ExactRationalSnapshot
    absLeafMax, absDL, absDR, absDX Signed8Depth2ExactRationalSnapshot
    absCross                        Signed8Depth2ExactRationalSnapshot
    boundRawA, boundA               Signed8Depth2ExactRationalSnapshot
    boundRawD, boundD               Signed8Depth2ExactRationalSnapshot
    boundRawY, boundZ               Signed8Depth2ExactRationalSnapshot
    boundA6, boundY                 Signed8Depth2ExactRationalSnapshot
    cacheErrorL00, cacheErrorDL      Signed8Depth2ExactRationalSnapshot
    cacheErrorDX, cacheErrorCross    Signed8Depth2ExactRationalSnapshot
    cacheErrorTolerance              Signed8Depth2ExactRationalSnapshot
}

type Signed8Depth2LeafHeadroomState struct {
    name  string
    level int
    scale ExactScaleSnapshot
    bound Signed8Depth2ExactRationalSnapshot
    floorIdealCenteredHeadroomBits uint
}

type Signed8Depth2LeafMagnitudeCertificate struct {
    schema, parameterDigest, treeDigest, scheduleDigest string
    cacheRoundingPolicy, idealHeadroomPolicy string
    leafBits [4]uint64
    ledger Signed8Depth2LeafMagnitudeLedger
    states []Signed8Depth2LeafHeadroomState
    selectorAbsError, rootSelectorMagnitudeBound Signed8Depth2ExactRationalSnapshot
    childSelectorMagnitudeBound, arithmeticSlack Signed8Depth2ExactRationalSnapshot
    outputTolerance Signed8Depth2ExactRationalSnapshot
    digest string
}
```

All fields are private; accessors return values or detached copies. The circuit
derives the certificate from its frozen tree and re-derives it during
validation. `float64` leaves are first checked with `math.IsNaN`/`math.IsInf`,
then captured by their exact `math.Float64bits` representation and converted
to exact reduced rationals with `new(big.Rat).SetFloat64`. Deltas, semantic
bounds and tolerance are computed as `big.Rat` values; this remains exact even
when two finite leaves have widely separated exponents. Only cached CKKS
operands are rounded by the reproducible construction

```go
rounded := new(big.Float).
    SetPrec(signed8Depth2LeafCertificatePrecision).
    SetMode(big.ToNearestEven).
    SetRat(exact)
actualCacheRat, accuracy := rounded.Rat(nil)
// Require accuracy == big.Exact; err = abs(exact-actualCacheRat).
```

The certificate stores the exact absolute error for every cache source. Its
rounding precision, mode and algorithm-version string enter the certificate
digest. The actual encoded payloads and digests, rather than an assumed
decimal value, are sealed. Decimal parsing is forbidden.

Admission requires:

```text
max_i |li| <= 2^16
dL = l01-l00
dR = l11-l10
dX = l10-l00
cross = dR-dL
```

Let `eps=2^-8`, the next power-of-two envelope above the accepted decoder's
`2e-3` Boolean error gate. For the known plaintext branch bit, the
root-conditioned and child-decoded selectors must each independently pass
`cmplx.Abs(decoded-complex(expectedBit,0)) <= eps` in decryptor-backed
encrypted acceptance tests. The existing per-coordinate `2e-3` decoder gate
implies complex-modulus error below `sqrt(2)*2e-3 < 2^-8`; the conditioned
root selector must pass the same complex-modulus gate separately at its actual
`L7/q7` boundary after its extra Mul/Rescale. This is empirical functional
evidence, not an online certificate available to the evaluator. Conservative
semantic bounds are exact rationals:

```text
beta0 = 1+eps  // only after the separate conditioned-root b0 gate passes
beta1 = 1+eps  // only after the separate decoded-child b1 gate passes

boundRawA = beta1*|dL|
boundA    = |l00| + boundRawA
boundRawD = beta1*|cross|
boundD    = |dX| + boundRawD
boundRawY = beta0*boundD
boundZ    = boundRawY
boundA6   = boundA
boundY    = boundA + boundZ
```

Every derived value must be finite and every conservative bound must be at
most `2^20`. Thus `LogDefaultScale=35` leaves at least
`35-20=15` bits after the admitted magnitude exponent.

For a universal leaf cap `L`, the model-independent consequences are:

```text
|dL|, |dR|, |dX| <= 2L
|cross|            <= 4L
boundRawA          <= 2*beta1*L
boundA             <= (1+2*beta1)*L
boundRawD          <= 4*beta1*L
boundD             <= (2+4*beta1)*L
boundRawY          <= beta0*(2+4*beta1)*L
boundY             <= ((1+2*beta1)+beta0*(2+4*beta1))*L.
```

At the admitted edge `L=2^16`, `eps=2^-8` and
`beta0=beta1=257/256`, the exact worst-case ledger is:

```text
|dL|, |dR|, |dX| <= 131,072
|cross|            <= 262,144
boundRawA          <= 131,584
boundA             <= 197,120
boundRawD          <= 263,168
boundD             <= 394,240
boundRawY=boundZ   <= 395,780
boundA6            <= 197,120
boundY             <= 592,900 < 2^20
```

For each cached or runtime state, let `M` be its conservative message bound,
`Delta` its exact scale, `Q_L=product(q0,...,qL)`, and `E=16` the full-slot
canonical-embedding infinity-norm guard. The ideal centered-message admission
test is the conservative inequality

```text
2 * E * Delta * M * 2^192 < Q_L.
```

For an actual model, `M` includes the outward 256-bit cache-rounding envelope
recorded in the certificate. The integer bounds in the universal table below
are safe ceilings for the edge configurations; construction still recomputes
the inequality from the model's actual rounded cache sources.

`Delta` is reconstructed from its `ExactScaleSnapshot` and converted to the
exact rational represented by the stored `big.Float` with `Rat(nil)`. The
inequality and largest admitted headroom exponent are evaluated by exact
`big.Rat`/`big.Int` cross multiplication; logarithms and floating comparisons
are forbidden. A zero bound has infinite ideal headroom. The algorithm version
`exact-rational-cross-multiply-v1` enters the certificate digest. The
certificate records the floored ideal centered-message headroom for all states
and rejects if any is below 192 bits:

```text
b1 L8/R, b0 L7/q7,
PT(dL) L8/B, PT(cross) L8/B, PT(l00) L7/S, PT(dX) L7/S,
rawA L8/(q8*S), a L7/S, A L7/S,
rawD L8/(q8*S), d L7/S, D L7/S,
rawY L7/(q7*S), z L6/S, A6 L6/S, y L6/S.
```

For the current parameter manifest,

```text
Q6 = 1852673279733349604425988749527669925098673361164237887459994568921216392365569
Q7 = 63657365736313435306989752043273091829224862215455300731577160216544013897137375613320897
floor((Q6-1)/(2*S)) = 26959944512540090427879313203850614446836310688584313720057173761906
floor((Q7-1)/(2*S)) = 926336589855977731451126631047708969406446881700762616406095333754550867846954
```

The two budgets are approximately `2^224` and `2^259`, respectively.

`q8` cancels from the ideal `L8/(q8*S)` raw-product budget and `q7`
cancels from the ideal `L7/(q7*S)` rawY budget. With the universal bounds
above, the frozen floored ideal-headroom ledger is:

| States | Ideal centered-message limit before `E` guard |
|---|---:|
| `b1` at `L8/R` | `Q8/(2R)` |
| `b0` at `L7/q7` | `Q7/(2q7)=Q6/2` |
| `PT(dL)`, `PT(cross)` at `L8/B` | `Q8/(2B)=Q7*R/(2S) ≈ 3.183e88` |
| `rawA`, `rawD` at `L8/(q8*S)` | `Q7/(2S)` |
| `a,A,d,D,PT(l00),PT(dX)` at `L7/S` | `Q7/(2S)` |
| `rawY` at `L7/(q7*S)` | `Q6/(2S)` |
| `z,A6,y` at `L6/S` | `Q6/(2S)` |

Applying `E=16` and the actual message bounds gives:

| State | Bound | Floored bits |
|---|---:|---:|
| `b1` | `beta1=257/256` | 289 |
| `b0` | `beta0=257/256` | 254 |
| `PT(dL)` | 131,072 | 272 |
| `PT(cross)` | 262,144 | 271 |
| `PT(l00)` | 65,536 | 238 |
| `PT(dX)` | 131,072 | 237 |
| `rawA`, `a` | 131,584 | 237 |
| `A` | 197,120 | 237 |
| `rawD`, `d` | 263,168 | 236 |
| `D` | 394,240 | 236 |
| `rawY`, `z` | 395,780 | 201 |
| `A6` | 197,120 | 202 |
| `y` | 592,900 | 200 |

The minimum is 200 bits, leaving eight bits above the admitted 192-bit guard.

After encoding, each cached plaintext's level, dimensions, exact scale,
payload digest and immutable copy are sealed. The certificate and actual cache
digests enter the terminal profile digest. This arithmetic headroom
calculation does not certify ciphertext noise or decryption correctness. The
current runtime has no analytic noise-certificate interface; Lattigo precision
statistics require a decryptor and therefore remain test-only evidence. The
factor `E=16` is an ideal embedding-amplitude guard, not a noise bound. The
module and certificate retain the `functional_not_secure` label.

The host-side certificate guarantees finite admitted leaves, exact rational
delta/bound arithmetic, a recorded 256-bit cache-rounding envelope, the ideal
message inequalities, and immutable parameter/tree/cache provenance. It does
not guarantee the empirical selector-error assumption or decryptor-free
ciphertext correctness.

The numerical acceptance tolerance is model-specific and deterministic. Let
`eta=2^-12`, a three-bit empirical test slack inside the 15-bit
magnitude-free budget. It is an acceptance policy, not a proved CKKS error
bound:

```text
tol = eps*(|dL| + |dX| + 2*|cross|)
    + eps^2*|cross|
    + eta*(1 + |l00| + |dL| + |dR| + |dX| + |cross|)
    + cacheTol

cacheTol = err(l00)
         + beta1*err(dL)
         + beta0*err(dX)
         + beta0*beta1*err(cross).
```

`tol` is computed exactly as a rational and stored in the certificate; its
floating test projection is rounded upward. It is used for both
`abs(real(got)-tree.Evaluate(features)) <= tol` and
`abs(imag(got)) <= tol`. Tests also report the observed maximum error; they do
not widen `tol` at runtime. At the universal leaf edge the exact tolerance
upper bound before the nonnegative, model-specific 256-bit cache-rounding term
is `3252.000244140625`. `err(v)` is the exact rational distance between `v`
and the actual 256-bit `big.Float` cache source converted back to a rational;
it is stored in the ledger. This is a decryptor-backed functional acceptance
threshold, not a production proof of CKKS noise.

## Terminal states, bytes and communication

The terminal trace records these 12 distinct degree-1 ciphertext boundaries,
each marshaled once:

| # | Stage | Level/scale | Bytes | Classification |
|---:|---|---|---:|---|
| 0 | decoded `b1` | `L8/R` | 5,054 | internal input |
| 1 | root `b0` | `L7/q7` | 4,526 | internal input |
| 2 | `rawA` | `L8/(q8*S)` | 5,054 | retained local |
| 3 | `a` | `L7/S` | 4,526 | retained local |
| 4 | `A` | `L7/S` | 4,526 | retained local |
| 5 | `rawD` | `L8/(q8*S)` | 5,054 | retained local |
| 6 | `d` | `L7/S` | 4,526 | retained local |
| 7 | `D` | `L7/S` | 4,526 | retained local |
| 8 | `rawY` | `L7/(q7*S)` | 4,526 | retained local |
| 9 | `z` | `L6/S` | 3,998 | retained local |
| 10 | `A6` | `L6/S` | 3,998 | retained local |
| 11 | `y` | `L6/S` | 3,998 | online output if transported |

The terminal internal-input subtotal is 9,580 bytes, retained-local subtotal
is 40,734 bytes, online-output size is 3,998 bytes, and terminal module total
is 54,312 bytes.

For the composed decoder+terminal trace, `b1` is the same actual ciphertext at
the decoder output and terminal input. Deduplicating that one boundary gives:

```text
decoder module total                         57,404
terminal module total                        54,312
deduplicate shared b1 boundary               -5,054
unique composed measured bytes              106,662
unique internal/retained local bytes        102,664
online client-to-server bytes                     0
online server-to-client final L6 leaf bytes   3,998
```

The decoder input/output, root selector and every retained checkpoint are
server-local evidence, not communication. Upstream encrypted feature uploads
belong to the prefix/end-to-end protocol ledger and are not recounted here.
The 3,998 output bytes count as communication only when the benchmark actually
serializes/transports the final result.

## Result, trace and failure contracts

The decoder result seals its child-specific profile, child input/result
provenance, operands provenance, derived operand mode, periodic path, output
payload and result digest. The terminal result additionally seals the exact
tree/schedule, magnitude certificate, four cache payloads, terminal input,
decoder result/trace digests and final output payload. Accessors return copied
ciphertexts, copied state slices and value-only certificates.

The terminal trace contains the nested child-decoder trace, wrapper counts,
the 12 states, serialized-byte ledger, runtime key inventory, relin match,
profile/result digests, wall time and retained ciphertext copies. Nested bytes
remain separately typed so communication cannot be inferred by summing every
serialized checkpoint.

All pre-operation admission, graph, cache and key validation completes before
nested decoder or mux work begins. On such a failure the result is the exact
zero value; operation counts, states, serialized bytes and nested-work evidence
are empty/zero. An
optional failure-stage tag and the returned error are the only permitted
diagnostics. Post-operation invariant failure also returns no usable result.

## Acceptance matrix

### Positive decoder gates

1. Public and opaque root-producer modes both bind without retagging.
2. All 16 four-word Boolean patterns, including all-zero, all-one and mixed
   SIMD patterns, pass `L4/S -> 19 states -> L8/R`.
3. The exact operation, state, byte, key, graph and logical-peak ledgers match
   the profile; input/caches remain byte-identical and accessors return copies.
4. The decoded real and imaginary errors are each at most `2e-3`; explicitly
   assert the resulting complex modulus is below `eps=2^-8`.

### Positive terminal gates

1. One SIMD batch realizes paths `00,01,10,11` in words 0--3 and returns
   `l00,l01,l10,l11` from `tree.Evaluate`.
2. Run both public and opaque root modes; make root and child equality cases
   route right.
3. Cover the current fixture leaves `[-1.25,2.5,-3.75,5]`, negative and
   fractional leaves, cancellation-heavy deltas, all-equal/zero-delta leaves,
   and admitted bound-edge leaves `+/-2^16`.
4. The magnitude certificate, headroom inequalities and fixed tolerance pass;
   all 12 terminal states, fixed counts and exact 54,312-byte ledger match.
5. Zero deltas still execute two CT--PT products, one CT--CT product and the
   complete fixed schedule.
6. Decrypt and check both the actual conditioned `b0` at `L7/q7` and decoded
   `b1` at `L8/R` against their known bits with complex-modulus error at most
   `eps`; do not infer the `b0` gate from the pre-conditioner selector test.

### Negative pre-operation gates

Each case below must return a zero result with zero operations, states, bytes
and nested decoder work:

1. nil/zero circuit, `childInput`, `childResult`, source or evaluator; foreign
   but self-consistent graph;
2. child input/result cross-pairing, including equal-metadata ciphertexts;
3. tree, range, schedule, prefix, child profile, source-kind, derived mode,
   payload or provenance drift;
4. replacement/mutation of the admitted input's owned root `b0`, child
   arithmetic branch or a same-state replacement of either input ciphertext;
5. NaN, infinity, `|leaf|>2^16`, derived bound `>2^20`, insufficient precision
   or any ideal-headroom state below 192 bits;
6. replacement/mutation of `PT(dL)`, `PT(cross)`, `PT(l00)`, `PT(dX)`, their
   immutable seals, leaf/certificate digests, base DFT/linear/polynomial
   objects or evaluator runtime snapshots;
7. missing, replaced, foreign or structurally changed relinearization key and
   each of Galois elements `[5,17,25,33,41,49,63]`.

### Post-operation result, trace and copy gates

Decoded `b1` and terminal `y` do not exist at the closed terminal admission
seam, so their mutation cannot be classified as a pre-operation/zero-work
failure. Test them only after the producing operation:

1. Mutating an accessor copy of the standalone decoder's `b1`, the terminal
   result `y`, a retained state or a nested trace state leaves the sealed
   result/trace byte-identical and valid.
2. Package-internal tests that replace or mutate the sealed decoder-result
   `b1`, terminal-result `y`, a same-level/scale ciphertext payload or any
   corresponding payload/provenance digest make `validateResult` or trace
   validation reject it before any downstream admission.
3. A post-execution graph, cache, input-immutability, output-state or
   result/trace invariant failure returns no usable result and cannot be
   admitted downstream. Its diagnostic trace may record physical nested work
   already performed; it must never claim zero operations, states or bytes.

No production fault-injection seam is added. Same-package unit tests mutate
private detached fixtures; external integration tests exercise accessor-copy
isolation. The zero-result/zero-work requirement remains exclusive to the
pre-operation list above.

Constructor/profile immutability, result/trace copy semantics, encrypted
integration, focused `-count=5`, full `integer/homchain`, `go vet`, formatting,
hash freeze and an independent 0C/0M/0m review are required before depth-2
closure.

## New-file ownership

Only add:

```text
integer/homchain/signed8_depth2_child_selector_decode.go
integer/homchain/signed8_depth2_child_selector_decode_test.go
integer/homchain/signed8_depth2_child_selector_decode_integration_test.go
integer/homchain/signed8_depth2_terminal_leaf.go
integer/homchain/signed8_depth2_terminal_leaf_test.go
integer/homchain/signed8_depth2_terminal_leaf_integration_test.go
```

Do not modify the accepted root selector, scalar conditioner, source prefix,
ingress, A2B, sign, root comparator/tree or child comparator. A later generic
arithmetic-root decoder refactor would reopen selector profile v5 and require
its full independent audit.

## Claim labels

- Branch predicate, MSB-first leaf order, OBO child selection and encrypted
  terminal output: source-faithful/R0-equivalent.
- Constant-delta mux, fused child conditioning, typed provenance, magnitude
  certificate and four-word Lattigo layout: Lattigo adaptation.
- Radix change, heterogeneous per-word models, complex-packed mux or reduced
  secure packing: R1; these do not belong in the matched binary baseline.
