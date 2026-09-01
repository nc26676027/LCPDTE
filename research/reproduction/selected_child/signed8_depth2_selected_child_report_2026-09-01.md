# Signed-int8 depth-2 selected-child reproduction report

Date: 2026-09-01  
Evidence ID: C74  
Status: author-side `functional_not_secure` acceptance; independent audit and
secure-profile port remain open

## Result

The repository now exposes one closed Lattigo orchestration seam for the
complete depth-2 source-faithful schedule:

```text
root feature --CT/PT compare--> b0
  --periodic reraising--> scalar b0
  --select child feature and public-model threshold--> two ciphertext operands
  --CT/CT compare--> b1
  --child-specific periodic decoding--> scalar b1
  --four-leaf real mux--> encrypted prediction
```

The implementation is `Signed8Depth2SelectedChildCircuit`. Its constructor
derives the root threshold, both child thresholds, three feature identifiers
and four real leaves from one immutable `treeplan.BinaryTree[int8,float64]`.
Its online API accepts only an authenticated feature vector. There is no
caller seam for a threshold, selector, child result or leaf vector.

This closes the manual C52 composition gap. It does not change the fidelity
label of the underlying small functional parameter set and does not establish
a secure or faster private-tree implementation.

## Source-schedule correspondence

The original LCPDTE production path performs a direct root comparison, then
uses the encrypted path state to select one feature and one threshold before
the next comparison. C74 preserves that distinction:

| Boundary | Operand form | Measured wrapper evidence |
|---|---|---|
| root split | encrypted feature minus encoded public threshold | one CT--PT subtraction; zero CT--CT subtractions |
| child selection | encrypted scalar selects one of two encrypted features and one of two encoded public thresholds | one feature CT--CT product and one threshold CT--PT product, both physically rescaled |
| child split | selected encrypted feature minus selected encrypted threshold | one CT--CT subtraction and one fixed-L6 complete A2B invocation |
| terminal | decoded `b0,b1` select one of four public real leaves | one CT--CT product, two CT--PT products, three rescales |

The profile digest is
`25141ea2f596c5b51fe22342a98c48733d0fccb321436eefbae1bd248ac751c7`.
The frozen public-root mode is `ct_pt_public_threshold`; the child operand kind
is recorded as `selected-feature-minus-selected-threshold-ct-ct`.

## Authentication closure

Every stage crosses an existing typed binder:

1. comparator result to root-selector input;
2. root-selector result to conditioner input;
3. prefix operands to child-comparator input;
4. child result to terminal input.

The outer trace binds the three source feature payload/provenance digests and
all eight intermediate payload/provenance boundaries. Validation replays the
nested comparator and selector runtime validators, the prefix operand seal,
the child trace digest and the complete terminal input/result/trace tuple.
Self-consistently resealing an altered root linkage or root operation count is
rejected.

The frozen linkage, result, trace and record digests are:

| Record | SHA-256 identity |
|---|---|
| linkage | `70e9657e86346eed2c28c4dbddbc8d1cf92ddb5880439dbb4aac570f842f3836` |
| result provenance | `f727af0ae92ca0de3777f5babffaa2d715c0e762a9038a0b38377aad96bca10a` |
| trace | `866d8c849ddcc99417da0e99583503c226e849fdaa828011e786a0e4b414285c` |
| output payload | `ead81a39fcea71c4dba9a1c18769b23465a81eae064975c143d5bb94c7c29ffa` |
| canonical record | `575f1d2167f16ed5a2b599e5b6a29e71213627e8da59f3f5b64b27e23bf33850` |

## Correctness experiment

The canonical tree is:

```text
root:  x0 >= 0
left:  x1 >= -4
right: x2 >= 3
leaves: [-1.25, 2.5, -3.75, 5.0]
```

Four SIMD words use node-feature triples
`(-1,-5,0)`, `(-1,-4,0)`, `(1,0,2)`, `(1,0,3)`. They route to paths
`00,01,10,11` and therefore cover all four leaves. The second and fourth words
are exact equality controls at the two child thresholds and both route right.

The 16 decoded output slots have zero mismatches at the preregistered
`1e-3` acceptance tolerance. Maximum real and imaginary absolute errors are
`7.007895456823121e-6` and `4.618971947066847e-6`. The independently derived
terminal magnitude certificate permits `0.0689849853515625`; the tighter
experiment gate, rather than the certificate bound, decides this run.

The canonical JSON is
[signed8_depth2_selected_child_2026-09-01.json](signed8_depth2_selected_child_2026-09-01.json):

- size: `9,047 B`;
- file SHA-256:
  `4dc5d51f0cc8034d8a57ee5b64bee1cfe7041eabeb78aca4ea14adcfde012b97`;
- schema: `lcpdte-signed8-depth2-selected-child-result-v1`;
- required Galois elements: `[5,17,25,33,41,49,63]`, plus one
  relinearization key;
- mismatch count: `0`.

## Wall-time ledger

This is one Windows/amd64, Go 1.23.11 functional run. It is not a benchmark
distribution.

| Interval | Time |
|---|---:|
| setup: circuit/key/evaluator construction and input encryption | `43.0253747 s` |
| root comparator | `0.6378065 s` |
| root selector reraiser | `1.0860051 s` |
| source prefix | `2.7317030 s` |
| child comparator | `2.9417132 s` |
| terminal child decoder plus leaf mux | `35.5178313 s` |
| sum of five online module calls | `42.9150591 s` |
| complete authenticated online wrapper | `70.4440529 s` |
| post-online independent trace verification and decoding | `46.0498067 s` |
| measured lifecycle | `159.5192343 s` |

The identity
`43.0253747 + 70.4440529 + 46.0498067 = 159.5192343 s` is checked during
offline replay. The difference between the five stage-call sum and the online
wrapper time is validation, typed-boundary copying/digesting and final trace
assembly inside `EvaluatePublicNew`; it is not omitted compute.

## Serialized-size ledger

The outer report preserves each module's established meaning. The
`296,178-B` module-reported sum includes overlapping retained boundaries and
is neither communication nor unique live memory.

| Module ledger | Reported bytes |
|---|---:|
| root comparator boundary ledger | `37,972` |
| root selector online plus retained evidence | `57,404` |
| source-prefix external/internal/output/retained ledger | `69,850` |
| child-comparator online plus retained ledger | `24,290` |
| terminal decoder-plus-mux unique composed ledger | `106,662` |
| module-reported sum | `296,178` |

The terminal-local subset is `54,312 B`; it is already included once in the
`106,662-B` terminal composed ledger and is not added again.

## Verification performed

The implementation followed a RED--GREEN sequence. The first focused test
failed because `NewSigned8Depth2SelectedChildCircuit` and its fidelity type did
not exist. After implementation:

- profile/feature-admission test passed in `34.176 s` on the final compile;
- the complete four-path encrypted test passed in `187.970 s` test-process
  wall, with a `72.727 s` wrapper wall in that development run;
- the independent CLI lifecycle above passed its internal `Validate()` gate;
- the exact `9,047-B` artifact passed 20 hash-locked offline replays in
  `0.390 s`;
- `go vet ./integer/homchain ./cmd/signed8-depth2-selected-child` passed.

## Interpretation and next gate

C74 proves that the existing Gao-backed functional components can execute one
complete signed-int8 depth-2 selected-child tree through a single typed API.
It also exposes the structural cost that C73 avoids: selected-child traversal
must materialize a high-level scalar selector between comparisons. In this
small profile, the child decoder and terminal account for most of the measured
stage time.

C73 and C74 are not performance-comparable. C73 uses the N16/L11 secure
Route-B candidate, 170-query all-node packing and one shared complete A2B;
C74 uses N32 functional parameters, four words and two periodic selector
decoders. Their timings answer different questions.

The next secure selected-child gate must port the periodic selector reraiser
and the post-selection fixed-ingress comparator to the Route-B parameter
identity, then compare it against C73 under the same machine, security
estimate, query count, tree, setup policy and repeated-run protocol. Until
that gate passes, no selected-child speedup, private-model security, arbitrary
depth, exact float32 parity or radix-tree improvement is claimed.
