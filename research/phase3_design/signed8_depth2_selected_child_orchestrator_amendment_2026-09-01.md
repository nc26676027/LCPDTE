# Signed-int8 depth-2 selected-child orchestration amendment

Date: 2026-09-01  
Stage: ARS Stage 2 preregistration amendment  
Status: implementation contract; no acceptance or performance claim

## Question closed by this amendment

The accepted C47--C52 modules establish the root comparator, root selector
reraising, source-faithful depth-one operand selection, fixed-L6 child
comparison, child selector decoding and terminal real-leaf mux separately.
Their integration tests still assemble those modules by hand. This amendment
registers one production seam that owns the complete depth-2 selected-child
protocol and makes omission, reordering or cross-tree substitution fail
closed.

This seam is the R1 signed-int8 analogue of the original LCPDTE OBO schedule.
It is not the Route-B C73 all-node batch and does not upgrade the small
functional profile to a security or performance result.

## Frozen semantic graph

For a complete `treeplan.BinaryTree[int8,float64]` of depth two, with branch
zero defined as `<` and branch one as `>=`, the only admitted public-root
execution is:

```text
feature[tree.split[0].feature]
  -> root CompareGEPublic(tree.split[0].threshold)       CT--PT
  -> root periodic selector reraiser                     L4 -> L8
  -> exact selector conditioner                          L8 -> L7
  -> select feature of split 1 or 2                     CT--CT
  -> select encoded threshold of split 1 or 2           CT--PT -> CT
  -> selected feature - selected threshold              CT--CT
  -> fixed-ingress-L6 complete A2B + sign fusion
  -> child-specific periodic selector decoder
  -> four-leaf real CKKS mux
```

The root threshold is derived from the owned tree and repeated across all four
words. Below the root, the selected threshold is a ciphertext even though the
two candidate thresholds are server-known constants. This preserves the
source distinction in `EvalXGBForestHEProdParityParallel`: direct root
comparison followed by encrypted selected-child comparison. The module never
evaluates both child predicates and never accepts a caller-supplied root
threshold, candidate threshold, selector, child result or leaf vector.

## External API

The circuit constructor takes the already authenticated comparator and source
tree, then internally constructs and owns the selector, prefix, child and
terminal circuits:

```go
NewSigned8Depth2SelectedChildCircuit(
    comparator *Signed8ComparatorCircuit,
    tree treeplan.BinaryTree[int8, float64],
) (*Signed8Depth2SelectedChildCircuit, error)
```

`BindFeatures` accepts a feature-indexed slice of existing
`Signed8FeatureInput` tokens. `BindCiphertexts` is a convenience admission
path that first invokes the owned comparator's `BindFeature` for the three
node-referenced features. Both methods copy only the root, left-child and
right-child feature tokens selected by the exact tree and bind their feature
identifiers, payload digests and provenance to a new orchestration input.
Repeated feature identifiers are allowed and retain the source-tree mapping.
Missing identifiers, foreign comparator handles and payload mutations fail
before online evaluation.

`BindEvaluator` binds all nested evaluators to the same bootstrap source and
exact `MemEvaluationKeySet`. The online method has no protocol options:

```go
EvaluatePublicNew(input Signed8Depth2SelectedChildInput) (
    Signed8Depth2SelectedChildResult,
    Signed8Depth2SelectedChildTrace,
    error,
)
```

An opaque-root overload is deliberately excluded from this first seam. The
source-faithful LCPDTE root operand is CT--PT. The already accepted opaque
component tests remain negative/differential evidence, not the default tree
protocol.

## Authentication and evidence

The profile binds the parameter/range/tree/schedule digests, the three node
feature identifiers, the exact public-root threshold-plaintext payload, all
five nested profile digests, the public-root operand mode and the
`functional_not_secure` fidelity label.

Before the first HE operation the evaluator validates the complete input and
all nested circuit/evaluator/key identities. During execution every stage
crosses only the existing typed binder:

```text
comparator result -> selector input
selector result   -> conditioner input
prefix operands   -> child input
child result      -> terminal input
```

The outer result owns only the authenticated terminal result plus the complete
input/profile/linkage digests. The outer trace retains the five nested traces,
stage wall times and a linkage record containing the exact payload/provenance
digests at every typed boundary. Its digest does not replace nested
validation: acceptance revalidates the input, nested runtime evidence,
terminal result/trace and every cross-stage equality.

Serialized-size reporting remains typed. The outer trace reports each
module's existing ledger and may expose a clearly labelled
`module-reported-sum`; that sum is neither communication nor a unique-live-byte
measure because nested modules retain overlapping boundary evidence.

## Pre-implementation tests

The first RED tests must establish:

1. constructor-derived feature mapping and public-root threshold identity;
2. rejection of missing/foreign/mutated feature handles before HE dispatch;
3. a four-word encrypted execution covering all four root/child paths and
   equality-goes-right semantics against `BinaryTree.Evaluate`;
4. exact root CT--PT and child CT--CT operand-mode provenance;
5. input immutability and defensive output copies;
6. rejection of self-consistently resealed linkage, result or nested-trace
   mutations;
7. one complete runtime/key/operation/byte/time ledger whose component
   profiles match the accepted C47--C52 modules.

Only after these gates pass may this seam support the claim that the existing
functional profile executes one complete source-faithful depth-2 selected-child
tree. Security, matched performance, exact float32 parity, arbitrary depth and
radix improvement remain separate gates.
