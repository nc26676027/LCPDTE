# Fixed-L6 Depth-2 Child Comparator Design

Status: implementation design; no accepted circuit, security, or speed claim.

## 1. Accepted input boundary

The only admissible input is `Signed8Depth2Operands` minted by the depth-2 source prefix. Its feature and threshold ciphertexts are exact full-packed degree-one NTT values at `L6/S35`. The child circuit must own the prefix circuit and call its package-private full operand validator before any homomorphic operation. Calling `A2BFullIngress6Circuit.BindInput` on an arbitrary raw `L6/S35` ciphertext is not sufficient provenance for a decision-tree comparison.

The child profile binds two distinct range facts:

- the prefix's signed no-overflow certificate for the selected feature and threshold; and
- the ingress circuit's complete `Z_256` residue-domain certificate for the arithmetic-to-Boolean conversion.

These digests are not interchangeable. The first proves the signed predicate under the declared protocol range; the second states the conversion domain.

## 2. Arithmetic and Boolean path

For each packed word, let the root selector choose the exact logical child operands `x1` and `t1`. The prefix already implements threshold selection with `E(t_R)-E(t_L)`, so the child must not apply another modular threshold correction.

The fixed path is:

```text
x1, t1             L6/S35 arithmetic root slots
d = x1 - t1        L6/S35, one CT--CT subtraction
A2B ingress input  owned typed copy of d
A2B high half      L5/S35, LSB-first Boolean high half
b7                  L4/S35 arithmetic root slots, direct sign fusion
-b7                 L4/S35
ge = 1 - b7         L4/S35, branch convention 0=LT and 1=GE
```

The signed result is correct when the sealed interval satisfies

```text
d_min = x_min - t_max >= -128
d_max = x_max - t_min <= 127.
```

Within this interval, the most-significant bit of the `Z_256` two's-complement residue is one exactly for a negative mathematical difference. Equality has residue zero and therefore returns `ge=1`.

The CKKS ciphertext approximates the selected integral root vector. This is a functional numerical condition tested against the independent integer oracle; it is not a cryptographic proof that an arbitrary caller supplied an in-range integer. The trusted protocol admission label remains explicit.

The existing `SignFusionCircuit.BindBooleanHalf` checks the exact L5 state,
half role, and bit order, but it does not authenticate an ingress producer.
The child evaluator must therefore consume `A2BFullIngress6Evaluator`'s high
half immediately inside the same closed call, after validating the typed
depth-2 operands and both nested circuit graphs. It must not expose the
intermediate `A2BFullResult` and later re-admit a raw same-state ciphertext.
The child result seal is the first external boundary that binds the ingress-6
trace, sign-fusion trace, input provenance, and final branch payload together.

## 3. Producer and result provenance

The child comparator is a new producer. It must not construct a legacy `Signed8ComparatorResult` carrying the accepted L20 comparator digest.

Its profile and result provenance bind:

- depth-2 prefix profile, tree, schedule, range, operand-provenance, and parameter digests;
- fixed ingress-6 profile, admission, full-ring range, suffix, kernel, key, transform, and mask digests;
- direct-sign profile/source/compiled digests;
- the cached arithmetic-root one payload;
- exact ordered state, operation, key, and serialized-byte ledgers; and
- the final branch ciphertext payload, sealed when evaluation succeeds.

The output is a distinct `Signed8Depth2ChildComparatorResult`. Accessors return copies. A package-private validator recomputes the payload and result provenance before any downstream admission.

## 4. Runtime accounting

The wrapper ledger contains exactly:

- one ciphertext--ciphertext subtraction;
- one fixed ingress-6 A2B invocation;
- one direct sign-fusion invocation;
- one negation; and
- one ciphertext--plaintext vector addition.

Nested ingress, Gao-kernel, refresh, and sign counts remain in their own ledgers and are referenced, not copied into a fabricated flat total. Required Galois elements are the exact union of ingress-6 and sign-fusion elements. The ingress set is `[5,17,25,33,41,49,63]`; sign fusion requires `[5,25]`, so it is a strict subset and does not enlarge the union. Relinearization is required by ingress-6 and not by sign fusion.

Because `A2BFullResult` and `SignFusionResult` predate this producer boundary,
neither type is sufficient as a downstream provenance token. They remain
strictly internal values; the child evaluator validates their runtime states
and nested traces before minting its own sealed result.

Every byte entry is measured by `MarshalBinary` on the actual runtime ciphertext. Input/output communication boundaries are separated from retained local evidence.

## 5. Fail-close gate

The evaluator completes all operand, circuit-graph, cached-plaintext, nested-profile, required-key-inventory, key-identity, and pointer-identity checks before subtraction. Every admission or preflight negative case returns a zero result and zero runtime states, operations, and bytes, while preserving the prefix operands and all cached objects. A typed failure stage and authenticated profile metadata may remain in the failure trace; they are not evidence that an HE operation ran.

The mutation matrix includes nil seams; prefix payload/provenance/tree/schedule/range drift; same-state ciphertext replacement; ingress graph/profile/mask/STC/CTS drift; sign graph drift; arithmetic-one drift; relinearization deletion/replacement; Galois deletion/replacement; and same-element foreign-key pointers. The child validates its exact required-key cache and identities; unrelated valid keys already present in the shared `MemEvaluationKeySet` are not an error.

## 6. Terminal leaves versus recursive selection

An accepted child branch is an arithmetic-root representation at `L4/S35`, not an ordinary repeated scalar.

For signed-int8 terminal leaves, a separate integer-leaf variant may use the existing tau-corrected rule: encode the left leaf arithmetically, encode the leaf difference with the Boolean map, multiply by the arithmetic-root branch, rescale, and add the left leaf. That variant changes the supported leaf domain and must be reported as R1.

The source depth-2 tree stores general `float64` leaves. Replacing them with int8 root-slot leaves changes the model. Source-faithful evaluation therefore requires a sibling periodic decoder that authenticates the new child producer, converts its `L4` branch to an ordinary repeated scalar, and then evaluates the four-leaf multilinear selection. The accepted selector-v4 binder cannot admit the child result because it is sealed to the legacy L20 comparator profiles. Reusing those digests would forge provenance.

The sibling selector may reuse the accepted periodic mathematics and transformation infrastructure, but its profile must distinguish:

- the legacy comparator circuit used as immutable transform/key infrastructure; and
- the fixed-L6 child comparator that produced the admitted branch.

It must preflight both graphs and mint a new selector profile/result provenance. A second complete implementation of the periodic mathematics is unnecessary.

## 7. TDD and acceptance gates

1. Exhaustively verify the signed host predicate for every int8 pair whose difference is representable, including equality and both endpoints.
2. Run encrypted selected-child cases covering root-left/root-right, negative/zero/positive child differences, every packed word, and both root comparator modes.
3. Compare the child branch with an independently evaluated legacy L20 comparator on the same logical selected values; compare ingress high halves with the already accepted L20 serial-A2B differential.
4. Run the full public-evaluator zero-operation mutation matrix and immutable-input/cache assertions.
5. Freeze ordered states, exact scales, operations, key identities, real-runtime byte constants, profile/result/file hashes, and repeat the encrypted gate five times.
6. Obtain an independent read-only audit before composing the sibling selector or claiming depth-2 closure.

## 8. Source anchors

- Prefix typed operands and validator: `integer/homchain/signed8_depth2_source_prefix.go`, `Signed8Depth2Operands` and `validateOperands`.
- Fixed L6 conversion: `integer/homchain/a2b_full_ingress6.go`, `BindInput` and `EvaluateNew`.
- Direct sign extraction: `integer/homchain/sign_fusion.go`, `BindBooleanHalf` and `EvaluateNew`.
- Predicate construction and branch convention: `integer/homchain/signed_comparator.go`, `compareNew`.
- Legacy selector producer binding: `integer/homchain/selector_reraise_decode.go`, `BindComparatorResult` and `validateInput`.
- Tau-corrected integer-leaf control: `integer/homchain/signed8_root_tree.go`, `signed8RootTreeSelectSlots`.
- Complete-tree leaf order: `integer/treeplan/binary.go`, `BinaryTree.Route`.
