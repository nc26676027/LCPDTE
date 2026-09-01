# Signed 8-bit no-overflow comparator contract

Status: Stage-2 implementation contract. The direct rank-one sign fusion and
fixed serial A2B profile named below are independently accepted within their
functional scopes. This document does not claim secure parameters, a complete
CCS reproduction, or a speedup.

## 1. Predicate and proof obligation

For two's-complement signed operands with declared inclusive ranges

```text
X=[x_min,x_max], T=[t_min,t_max]
d_min=x_min-t_max, d_max=x_max-t_min
```

construction admits the comparator only when every endpoint is in
`[-128,127]` and `[d_min,d_max]` is also contained in `[-128,127]`. Endpoints
and differences are computed with `big.Int`; machine overflow is not an
admissible proof path. Under this contract, `d=x-t` has its mathematical
two's-complement sign, A2B high-half column 3 is `b7=[d<0]`, and the CCS branch
predicate is

```text
right = [x >= t] = 1 - b7.
```

Equality therefore returns one. The range certificate binds the four source
endpoints, derived difference endpoints, width 8, signedness, `ge` predicate,
child convention `0=lt,1=ge`, and proof status
`internally_derived_endpoint_interval`. Binding an encrypted value to the
declared range is a trusted encoder/protocol admission assumption, not a
cryptographic range proof.

## 2. Fail-closed API seam

The implementation lives in `integer/homchain/signed_comparator.go` and uses
opaque handles. A raw high-half ciphertext plus caller-selected role/order is
not a public input.

```go
func NewSigned8NoOverflowRange(xMin, xMax, tMin, tMax int64) (Signed8NoOverflowRange, error)

func NewSigned8ComparatorCircuit(
    params ckks.Parameters,
    refreshEncoder *ckks.Encoder,
    integerEncoder *ckks.Encoder,
    ranges Signed8NoOverflowRange,
) (*Signed8ComparatorCircuit, error)

func (c *Signed8ComparatorCircuit) BindEvaluator(
    source *bootstrapping.Evaluator,
) (*Signed8ComparatorEvaluator, error)

func (c *Signed8ComparatorCircuit) BindFeature(
    ciphertext *rlwe.Ciphertext,
    declaredSource ckks.Parameters,
) (Signed8FeatureInput, error)

func (c *Signed8ComparatorCircuit) BindOpaqueThreshold(
    ciphertext *rlwe.Ciphertext,
    declaredSource ckks.Parameters,
) (Signed8OpaqueThresholdInput, error)

func (e *Signed8ComparatorEvaluator) CompareGEPublicNew(
    feature Signed8FeatureInput,
    thresholds [4]int64,
) (Signed8ComparatorResult, Signed8ComparatorTrace, error)

func (e *Signed8ComparatorEvaluator) CompareGEOpaqueNew(
    feature Signed8FeatureInput,
    threshold Signed8OpaqueThresholdInput,
) (Signed8ComparatorResult, Signed8ComparatorTrace, error)
```

Feature and opaque-threshold inputs must be canonical Gao arithmetic root-slot
values with two's-complement width 8, four words/16 slots, full-dense packing,
degree one, NTT form, exact L20/S35, canonical parameters, and range/provenance
digests matching the sealed circuit. The public-threshold path validates all
four constants and encodes their residues at L20/S35 with the same 192-bit
refresh/input encoder used by the accepted arithmetic feature source, then
performs one CT--PT subtraction. The opaque path requires matching ciphertext
states and performs one CT--CT subtraction. The separate 256-bit kernel/sign
encoder is used for the L4 arithmetic-word-one complement plaintext. Both
precision roles and operand modes remain distinct in profiles and measurements;
swapping them is a negative test.

The binders hash and compare the complete marshaled `declaredSource`, run the
strict ciphertext-state gate (including LogN), own a `CopyNew` of the admitted
ciphertext, and bind its serialized payload digest into the opaque handle.
Evaluation recomputes that digest before the first homomorphic operation, so
post-bind caller mutation and handle-payload tampering fail closed.  This is a
trusted encoder/protocol declaration, not a cryptographic proof that an
arbitrary raw `rlwe.Ciphertext` was originally generated under the declared Q
chain or key: the raw object does not carry such a verifiable identity.  A
different-LogN or reordered-Q value whose source parameters are honestly
declared is rejected; a malicious false declaration remains outside this
functional admission contract.

## 3. Physical composition

The accepted full-A2B candidate follows this exact S35 trace:

```text
difference/input                    L20
special-b0 low/high                 L19/L19
iteration-0 mask                    L18
iteration-0 STC                     L16
iteration-0 ScaleDown/ModUp/CTS     L0 -> L20 -> L17
iteration-0 ID/MSB                  L5/L5
ID0/16                              L4
high aligned/updated                L4/L4
low aligned/self-removed            L5/L5
iteration-1 mask                    L3
independent iteration-1 STC         L1
iteration-1 ScaleDown/ModUp/CTS     L0 -> L20 -> L17
iteration-1 ID/MSB                  L5/L5
ID1 aligned/high self-removed       L4/L4
```

Only `HighMSB()` enters sign fusion:

```text
[b4,b5,b6,b7]                 L5 / 0x1p+35
rank-one transform            L5 / 0x1.fffffe904p+69
arithmetic b7                 L4 / 0x1p+35
```

The complement must use a 256-bit plaintext encoding of four copies of
`z2n.ArithmeticRootSlots(1)` at L4/S35. Scalar CKKS `1` is not the Gao
arithmetic-root-slot word one. Negating the sign ciphertext and adding this
plaintext returns a degree-one, full-packed L4/S35 branch with no rescale or
evaluation key.

## 4. Profile, graph, and key binding

The comparator profile schema is `signed8-ge-comparator-profile-v1` and binds:

- canonical parameter digest;
- accepted serial-A2B profile and key-profile digests;
- sign source/compiled/profile digests;
- range-evidence digest;
- arithmetic-one plaintext payload digest;
- CT--PT or CT--CT mode and branch orientation;
- all exact states, packing dimensions, nested ledgers, fidelity, and maturity.

Accepted sign pins are:

```text
parameter 085e0a9b826d469ac5514d3db988672f41ab0a4f1bb2fe82705842226a8eacc2
source    c5bda437c079d1b60671cf2909460a3f2a0f29d0bef81bacb4fa8d2dd147849f
compiled  da9827044a8ee1f07769b47fff01213e23f6ea5e7d644f6dd03fd133d8031b0b
profile   68b3bcc5edd24e7e2aeefbf184534b750a3d94506cbf10afb1839ebed474a4ae
```

Accepted fixed serial-A2B pins are:

```text
profile              d9c156fb3347daa8a10976b04c69a118f4b07cd34b4b6f4d92b1d71c133dfc90
second raw STC       b40ce04fb171af270ea77e0142bd7d695c58e670e733e5e09eab97a4cd2a854e
second execution STC 6381e519b59a10832ad615399b29b416941c8c7185bff9a7802dc06418395ae0
second-STC profile   b4d1cb37cf6cb73f9f3411266a04d3b9686064d56492f0cda01a691f6245b882
```

A2B and sign fusion bind one exact `MemEvaluationKeySet`. Evaluation rechecks
the keyset, relinearization key, every Galois-key pointer, evaluator graph, and
child profiles before the first operation. Missing, swapped, same-element
replacement, foreign-secret, or graph mutations fail with zero trace states.
Sign elements `[5,25]` must be a subset of the sealed A2B union; no residual
rotation is admitted for fixed `n=8,w=4`.

## 5. Operation accounting

Keep nested ledgers instead of fabricating a partial flattened total:

```text
wrapper: 1 CT-PT or CT-CT subtraction; 1 negation; 1 CT-PT vector addition
serial A2B: 1 special-b0; 2 mask/rescales; 2 refreshes; 2 kernels;
            1 ID-scale/rescale; 3 alignment drops; 3 subtractions;
            0 residual rotations; 2 shared CTS uses
two kernels: 2 exp polynomial evaluations; 4 complex squares;
             2 shared multi-polynomial evaluations/bases;
             4 conjugations; 4 real recoveries
sign fusion: 1 LT; 2 rotations/key switches; 4 CT-PT diagonal products;
             3 additions; 1 rescale
```

Peak live ciphertexts, serialized bytes, wall time, internal refresh-transform
counts, and cached setup encodings are measured fields.  The 256-bit
arithmetic-one operand is encoded exactly once in the constructor and checked
later against a frozen copy and payload digest without re-encoding.  Successful
wall time starts at the public evaluator entry, so it includes handle
validation and, for CT--PT mode, per-evaluation threshold encoding.

## 6. Mandatory tests

Range gates admit `X=[-128,127],T=[0,0]` and `X=T=[-8,7]`; they reject the full
Cartesian box, positive/negative overflow witnesses, reversed/out-of-domain
endpoints, wrong width/signedness/comparator/overflow contract, and foreign
range digests.

Ciphertext gates cover:

- all 256 signed features against public threshold zero;
- every pair in `[-8,7]^2` through both CT--PT and CT--CT paths;
- equalities at `-128,0,127` and differences `-128,-1,0,1,127`;
- distinct four-lane inputs, block isolation, independent host and `Z2^8`
  oracles, exact trace/digests, defensive copies, and input immutability;
- nil/wrong level, exact scale metadata, modular scale, precision/mode, degree,
  NTT, dimensions, packing, encoder precision, parameters, Q ordering, half
  role/order, child profile, keys, evaluator, and graph.

Every negative must fail before recording an operation or mutating an input.
Focused tests run five times, followed by full package/repository tests, vet,
formatting, and an independent read-only audit.

## 7. Tree integration boundary

The branch orientation matches `treeeval.Backend.CompareGE`, but the current
backend lacks a refresh primitive. Comparator output is L4/S35 and the next
full A2B ingress is L20/S35. A multi-depth implementation therefore needs an
explicit counted extension:

```go
type RefreshingBackend[V any] interface {
    Backend[V]
    RefreshMany(values []V, target StateProfile) ([]V, error)
}
```

Selected features/thresholds must be restored to L20/S35 before CT--CT
comparison, and branch/path states must be refreshed under an explicit level
schedule. The source-faithful CCS schedule distinguishes a direct root
comparison from below-root selected CT--CT comparisons; the generic OBO
control deliberately makes even the root threshold opaque. Leaf selection
also needs an explicit arithmetic-root-selector to real-output bridge or a
compatible encoded-leaf construction.

Finally, signed `n=8` is R0 only for a source model already defined over int8.
The repository's exact float32 view is ordered unsigned 32-bit. Applying this
profile to that model is quantized/model-changing R1; an exact R0 replacement
requires a width-32 unsigned borrow/widened comparator or retains the original
bit comparator.
