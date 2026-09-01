# Gao-backed private decision-tree integration contract

Status: Stage-2 design and falsification record. The fixed signed-int8
comparator, bounded T0 root wrapper, and periodic selector reraiser are
independently accepted as functional-not-secure slices. No multi-depth
encrypted tree, level-elastic A2B family, performance result, secure circuit,
application-security result, or novelty claim is accepted by this document.

## 1. Semantic tiers

The implementation and experiments keep three tiers separate:

1. **T0 int8 root tree:** one signed-int8 split and public integer or real
   leaves. This is an encrypted correctness seam requiring no inter-level
   selector refresh. It is R0 only for a source tree actually defined over
   signed int8.
2. **T1 private-model int8 binary tree:** the source-faithful CCS schedule uses
   a direct root CT--PT comparison and below-root CT--CT comparisons after
   oblivious feature/threshold selection. Applying it to the repository's
   float32 XGBoost model requires declared quantization/retraining and is R1.
3. **T2 exact float32 CCS reproduction:** retain the original bit comparator,
   or implement ordered-uint32 conversion plus a proved 32-bit unsigned
   comparator. Signed-int8 results never substitute for this R0 baseline.

For every tier, branch `0` is left (`x<t`) and branch `1` is right (`x>=t`).

## 2. Typed representations

The new backend must distinguish at least:

```text
arithmetic_word      Gao tau^-1 root slots, signed width 8
arithmetic_selector  Gao tau^-1 root slots, exact range {0,1}
scalar_selector      ordinary CKKS slots, each four-slot word block repeated
real_output          ordinary CKKS slots
public_constant      server-known scalar or encoded word
```

Every ciphertext value binds parameters, level, exact scale, degree, NTT,
dimensions, packing, range/proof, producer profile, keyset, and fidelity.
Generic multiplication is not allowed to erase the representation tag.

In particular, slotwise multiplication of two arithmetic-root values produces
a `tau^-2` product. Gao arithmetic multiplication needs a `tau` correction.
Tree selection must either charge that correction or multiply the arithmetic
feature by an ordinary scalar selector repeated over the block.

## 3. T0 one-level gate

The one-level evaluator consumes four encrypted features at L20/S35 and four
server-public or encrypted thresholds under one accepted no-overflow range
certificate. It calls the accepted comparator and receives an arithmetic-root
GE selector at L4/S35.

For integer leaves, define `E(a)=roots(tau^-1[a]_tau)` and
`delta=(right-left) mod 256`.  T0 packs the left leaf as `E(left)` but packs the
public corrected delta as `roots([delta]_tau)=tau*E(delta)`.  It evaluates

```text
leaf = E(left) + E(selector) * roots([delta]_tau).
```

The corrected-delta plaintext is encoded at L4 with exact scale `Q[4]`.
Ciphertext--plaintext multiplication followed by one physical rescale produces
an arithmetic word at L3/S35; an `E(left)` plaintext at L3/S35 completes the
selection.  The wrapper therefore charges one CT--PT multiplication, one
rescale, and one CT--PT vector addition, with no rotations, relinearization, or
new keys.  Encoding `E(delta)` instead is a forbidden negative control because
it leaves a `tau^-2` representation.

This equation fixes the source-scheduled arithmetic representative.  When the
leaf difference wraps modulo 256, its root slots can differ from a freshly
canonicalized `E(selected)` by an integral lift even though both decode to the
same `Z/256Z` residue.  Encrypted correctness therefore compares slots against
an independent high-precision replay of the source formula and separately
checks the decoded residue.  A non-wrap case must agree with the canonical
encoding, while at least one wrap case must distinguish the two representatives;
canonical re-encoding is not the positive root-slot oracle for all leaves.

For real leaves, T0 should instead use the scalar selector bridge in Section 4
and evaluate

```text
leaf = left + scalar_selector * (right-left).
```

The test set exhausts the admitted `(x,t)` box, equality, four-block isolation,
both threshold modes, both child orientations, distinct leaves, and input
immutability. It reports comparator, bridge, and leaf-selection costs
separately.

## 4. Accepted periodic selector reraiser

`SelectorReraiseDecodeCircuit` converts the accepted comparator's arithmetic-
root GE bit into an ordinary scalar bit repeated across each four-slot word.
It admits only the authenticated four-word/16-slot, degree-one, NTT comparator
result at L4 and exact S35 with the internally bound range `{0,1}`. Public and
opaque comparator modes retain distinct producer provenance.

The production state sequence is:

```text
arithmetic selector                         L4
normal V low/high raw -> rescaled           L4 -> L3
two-factor SlotsToCoeffs                    L2 -> L1
guarded ScaleDown -> dense/no-switch ModUp  L0 -> L20
three-factor CoeffsToSlots, low/high split  L19 -> L18 -> L17 -> L17/L17
accepted exp46                              L17 -> L11
two ciphertext squares                      L11 -> L10 -> L9
slotwise affine product/rescale/add         L9 -> L8
ordinary repeated scalar selector           L8, exact profile-bound scale
```

This is a 19-state ordered ledger. The nonlinear suffix consumes the shared
CTS low half, the accepted packed-vector degree-46 exponential, two
ciphertext--ciphertext square/relinearize/rescale steps, and one slotwise
ciphertext--plaintext affine map. It does not evaluate the ID/MSB LUTs and does
not execute a normal-U or fused-D/U transform.

Let `a_j` be a low-half coefficient of `tau^-1` at root-slot position `j`.
After the exponential and two squares, periodicity removes the integral lift
and produces

```text
z_j = exp(2*pi*i*(I + b*a_j)) = exp(2*pi*i*b*a_j),  b in {0,1}.
```

The frozen 256-bit affine constants are
`m_j=1/(exp(2*pi*i*a_j)-1)` and `c_j=-m_j`. Therefore
`m_j*z_j+c_j` is exactly zero for `b=0` and one for `b=1` in the plaintext
oracle. The all-16 nonuniform-lift oracle passes at the `2^-200` gate, and real
encrypted public/opaque tests recover all four repeated Boolean blocks.

The runtime-derived operation ledger fixes 7 linear transformations, 35
diagonal plaintext products, 19 non-conjugation rotations, 3 conjugations, 22
key switches, 34 ciphertext additions/subtractions, 2 scalar `+/-i`
multiplications, 10 explicit rescales, one ScaleDown, one ModUp, one
exponential evaluation, 2 ciphertext products and relinearizations, one
ciphertext--plaintext product, and one plaintext-vector addition. Logical peak
live ciphertexts is eight. The exact key inventory is
`[5,17,25,33,41,49,63]` plus relinearization.

The v4 profile separately seals online serialization boundaries and retained
local evidence. For the frozen functional profile, the marshalled input is
2,942 bytes and the output is 5,054 bytes, giving an online boundary total of
7,996 bytes. Eight retained diagnostic ciphertexts total 49,408 bytes; this is
local evidence storage, not communication. The successful path remeasures all
ten real ciphertext objects before return and rejects ledger tampering or
retained-pointer aliasing and double counting.

The circuit and evaluator seal the complete source/compiled transform graph,
raw/execution DFT payloads, periodic operands, affine plaintexts, evaluator
components, keyset object, exact Galois inventory, and each cached Galois-key
identity. The 27-case zero-operation matrix rejects nil boundaries, input and
profile mutations, graph/cache/key substitutions, and same-map deletion,
replacement, or insertion before the first HE operation. Every rejection
returns no ciphertext, a zero trace, and unchanged input and evaluator state.

The scalar-leaf bridge multiplies the accepted L8 selector by a public leaf
delta, performs one physical rescale to L7, and adds the public left leaf. Its
four-block test selects the intended left/right value without mutating the
selector. The periodic circuit passed independent review with 0 Critical,
0 Major, and 0 Minor findings. Its fidelity remains
`functional_not_secure`; it establishes neither multi-depth composition nor a
performance improvement.

### Falsified linear control

The earlier no-Mod1 `D o U` proposal remains a negative design record. A real
encrypted smoke showed that fused `D o U` and normal-U-then-D agree within
approximately `1e-9`, yet both retain the unknown integral term from
`(I+a)/16` and fail to decode Boolean selectors. The L16 output, profile,
savings estimate, and downstream schedule are withdrawn. The deterministic
linear algebra constructor is test-only and absent from the production graph.

The new path never calls legacy `he.MultiBootstrapCT`, whose dependency graph
contains decrypt-round-reencrypt and error-oblivious global state. The accepted
A2A-I circuit also remains parameter- and ingress-level-incompatible.

## 5. Depth-2 selection and fixed L6 A2B gate

The accepted periodic selector leaves L8 with exact scale

```text
R = S^4/(q_11^2*q_10),  S=2^35,
```

not exact S35. The fixed functional chain gives
`R approximately 34359734909.0005`. Selection first conditions this ciphertext
without `SetScale`. Encode a full-slot plaintext one at L8 with exact scale
`A=q_8*q_7/R`, multiply, and rescale by `q_8`. The resulting Boolean scalar is
exactly L7/q7.

For the two candidate nodes at depth one, use the source-scheduled delta form:

```text
DeltaF = F_right - F_left                         L20/S35
b' * DeltaF, relinearize, rescale by q_7          L6/S35
F_selected = align(F_left,L6) + product           L6/S35

DeltaT = E(T_right) - E(T_left)                   plaintext L7/S35
b' * DeltaT, rescale by q_7                       L6/S35
T_selected = E(T_left) + product                  ciphertext L6/S35
```

`E(T_right)-E(T_left)` is the exact root-slot source formula.
`E((T_right-T_left) mod 256)` may differ by an integral lift and is a mandatory
negative/differential control. The physical prefix charges two CT--PT
products, one CT--CT product, one relinearization, three rescales, one feature
subtraction, two result additions, and explicit feature-level alignment. It
uses no rotations. The logical source schedule remains a width-two one-hot
selection; the delta form is accepted only after a ciphertext differential
against the two-term source formula.

The next Boolean conversion is a fixed sibling named
`A2BFullIngress6Circuit`, not an arbitrary dynamic-level API:

```text
input difference                     L6/S35
special-b0                           L5/S35
mask                                 L4/S35
first STC factors [1,1]              L3 -> L2/S35
guarded ScaleDown                    L0/S35
ModUp/shared CTS/kernel              L20 -> L17 -> L5/S35
ID0/16 and serial second refresh     accepted serial suffix
final low/high                       L5/S35
```

L6 is the minimum ingress compatible with the accepted suffix: special-b0 must
leave the untouched high core at L5 so that the low-half `ID0/16` update can
align at L4. L5, L7, wrong-scale, and foreign-profile inputs fail closed. The
fixed circuit recompiles and seals special-b0, the mask, and first STC for the
exact Q prefix, then runs an all-256 semantic differential against the accepted
L20 circuit.

A bare `DropLevel` or ScaleDown/ModUp pair is not a semantic reraiser for the
selected arithmetic words: it lacks the special-b0/STC/CTS periodic path that
removes the coefficient lift. The L6 comparator and the selector that consumes
its result therefore use sibling producer profiles and audit anchors. They do
not forge the accepted L20 comparator or selector-v4 identities.

## 6. Source-faithful private-model schedule

At depth zero, compare the original encrypted feature with the root public
threshold (CT--PT). After each comparison:

1. reraise/decode the arithmetic branch into a high-level scalar selector;
2. condition its exact scale for the measured selection level;
3. add it to the appropriate even/odd branch-product set;
4. construct scalar one-hot path weights with the existing parity-balanced
   algebra, but through the typed fail-closed evaluator;
5. multiply each candidate arithmetic feature and encoded threshold by its
   scalar path weight and sum;
6. subtract selected CT--CT operands;
7. invoke only the sealed A2B profile registered for that measured ingress;
8. repeat until the leaf level;
9. select ordinary real leaves using scalar one-hot weights.

This matches the distinction in `tree/main_tree.go`: the root is direct, while
below-root model hiding makes both selected operands ciphertexts. The generic
`treeeval.EvaluateOBO` remains a conservative control because it intentionally
turns the root threshold opaque as well.

Every branch reraiser, CT--CT product/rescale, CT--PT product, rotation,
relinearization, A2B refresh, kernel, live ciphertext, serialized byte, and
wall-clock interval is counted. Setup encodings and evaluation-key bytes are
reported separately. No refresh is hidden inside `Mul`, `CompareGE`, or a
metadata conversion.

## 7. Acceptance gates

T1 is accepted only after:

- depth-1, depth-2, and bounded random complete-tree ciphertext results match
  an independent plaintext oracle for every packed word;
- root CT--PT and below-root CT--CT provenance cannot be swapped;
- exact state/profile/key/range certificates survive defensive-copy and
  mutation tests;
- scalar weights remain in `[0,1]`, sum to one within the registered error
  threshold, and inactive paths remain zero;
- real leaf output matches the source tree under the declared int8/R1 model;
- operation ledgers are runtime-derived and matched to source schedule;
- targeted count-five, full repository, vet, formatting, and independent
  Standards+Spec audit pass.

Only after these gates may R0 grouping or R1 multiway designs replace the
binary schedule in matched experiments.
