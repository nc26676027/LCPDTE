# Route-B signed-int8 depth-2 node-batch reproduction report

Date: 2026-09-01  
Status: accepted functional reproduction artifact

## Outcome

The Lattigo N16/L11 Route-B implementation now evaluates all three internal
nodes of a public depth-2 signed-int8 tree with one complete SIMD A2B call.
The canonical run packed 170 queries as adjacent `(root,left,right)` words,
used the remaining two words as authenticated padding, selected one of four
public real leaves, and checked all 2,048 decrypted slots. All 680 active
slots matched the independent tree oracle and all 1,368 inactive slots
remained zero within the registered tolerance.

```text
510 encrypted node words + 2 padding words
  -> subtract three role-specific public thresholds
  -> one complete SIMD 8-bit A2B over all 512 words
  -> broadcast b7 within every four-slot word
  -> ge(root), ge(left), ge(right)
  -> role masks and +4/+8 child alignment
  -> p01, p10, p11
  -> l00 + p01*dL + (p10+p11)*dX + p11*dR
```

The frozen model uses thresholds `[0,0,0]` and leaves
`[-3.25,-0.75,2.5,5.125]`. Equality takes branch one. Each node carries a
trusted certificate for `x in [-128,127]`, fixed threshold zero and
`x-t in [-128,127]`.

## What changed from the root-only slice

The root-only C72 circuit spends one A2B call on 512 independent queries. C73
instead assigns three adjacent words to the three internal nodes of each
query, so 170 complete depth-2 queries share the same A2B call. Public masks
retain the root, left-child and right-child words; rotations by `+4` and `+8`
move the two child selectors into the root word. Three ciphertext products
then form the path basis:

```text
p01 = (1-b0) * bL
p10 = b0 * (1-bR)
p11 = b0 * bR
```

This schedule avoids a selector refresh between tree levels. It evaluates
both children before selecting the active path, trading SIMD query capacity
for node parallelism.

## Canonical evidence

Artifact:
`research/reproduction/route_b/route_b_signed8_depth2_node_batch_2026-09-01.json`

| Field | Measured value |
|---|---:|
| JSON bytes | 281,296 |
| JSON SHA-256 | `8b99e96e439e13703b0eadc26c27b86ad17f9e5c562401e0c6f05d84a6dd85d8` |
| Queries | 170 |
| Input words / padding words | 512 / 2 |
| Output slots | 2,048 |
| Active / inactive slots | 680 / 1,368 |
| Path counts | `[44,42,42,42]` |
| Eight branch-triple counts | `[22,22,21,21,21,21,21,21]` |
| Active / inactive mismatches | 0 / 0 |
| Maximum active absolute error | `4.0057496697443185e-7` |
| Maximum inactive absolute value | `9.3551663520329e-10` |
| Maximum imaginary magnitude | `1.0905832896081732e-9` |
| Build wall time | 5.7770101 s |
| Complete A2B wall time | 26.8006752 s |
| Depth-2 circuit wall time | 28.8937126 s |
| Whole lifecycle wall time | 58.7611216 s |
| Build peak RSS | 3,273,629,696 B |
| Post-install peak RSS | 6,569,250,816 B |
| Post-depth-2 peak RSS | 13,206,462,464 B |
| Construction-counter delta | `[0,0,0,3]` |

The measured depth-2 wrapper outside A2B took 2.0930374 s in this run. This is
a descriptive subtraction from one sample, not an isolated benchmark.

Identity anchors:

| Item | SHA-256 |
|---|---|
| Depth-2 report | `54fb7d525d0ddca6a2ccbcc9579a286b6152ec6699b47085d3577678d0fddb1a` |
| Nested complete A2B | `bc066aacca6054c745fb2eabaafab007229925250fef16efc13c4a0d5d68e5f6` |
| Supplemental L3-to-L1 STC | `bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a` |
| Depth-2 capacity plan | `888b4650d8148ec438e4da82ef95598c984cc29651c1b6d47846f977cf2a6298` |
| Input pattern | `6036bfdd76c0e486a45ad8dc08527421da3d5233e2fe1d02d9e97c515e39c7c2` |
| Canonical parameter payload | `c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816` |

The JSON and replay gate also bind the threshold, global-one, root-one, three
role masks, three leaf deltas, base leaf, input ciphertext and output
ciphertext payloads.

## Exact level and scale schedule

Every recorded ciphertext is degree one, batched, NTT-form and uses L11
dimensions.

| Stage group | Levels | Exact scales |
|---|---|---|
| Input; threshold difference | `20,20` | `S,S` |
| Complete-A2B high Boolean half | `5` | `S` |
| Sign broadcast raw; repeated sign; `ge` | `4,3,3` | `S*q4,S,S` |
| Root mask raw; root aligned | `3,2` | `S*q3,S` |
| Left mask raw; left masked/aligned | `3,2,2` | `S*q3,S,S` |
| Right mask raw; right masked/aligned | `3,2,2` | `S*q3,S,S` |
| `1-b0`; `1-bR` | `2,2` | `S,S` |
| `p01`, `p10`, `p11` raw | `2,2,2` | `S^2` |
| `p01`, `p10`, `p11`, `p10+p11` | `1,1,1,1` | `P=S^2/q2` |
| Three leaf terms raw | `1,1,1` | `q1*S` |
| Three leaf terms; final output | `0,0,0,0` | `S,S,S,S` |

The frozen exact hexadecimal anchors are:

- `S = 0x1p+43`;
- `S*q4 = 0x1.00001340002p+86`;
- `S*q3 = 0x1.ffffe300004p+85`;
- `P = 0x1.00000b000059000273000fd1005f9b02p+43`;
- leaf plaintext operand scale
  `0x1.ffffd480016c7ffa900008p+42`;
- raw leaf-product scale `0x1.ffffea80004p+85`.

The implementation performs physical rescaling at every registered boundary.
It does not increase a ciphertext level or retag ciphertext scale metadata.

## Operation ledger

The wrapper records the following work around the separately authenticated
complete A2B circuit:

| Operation | Count |
|---|---:|
| Public-threshold subtraction | 1 |
| Complete A2B invocation | 1 |
| Broadcast linear transform | 1 |
| Broadcast diagonal plaintext products | 4 |
| Broadcast ciphertext additions | 3 |
| Broadcast rotations / key switches | 2 / 2 |
| Broadcast rescale | 1 |
| `ge` negation / plaintext addition | 1 / 1 |
| Role-mask plaintext products / rescales | 3 / 3 |
| Alignment rotations / key switches | 2 / 2 |
| Path-complement negations / plaintext additions | 2 / 2 |
| Path ciphertext products / relinearizations / rescales | 3 / 3 / 3 |
| Path ciphertext additions | 1 |
| Leaf plaintext products / rescales | 3 / 3 |
| Leaf ciphertext additions | 2 |
| Base-leaf plaintext additions | 1 |
| Conservative peak live wrapper ciphertexts | 16 |

The four wrapper rotations are `[1,2,4,8]`, with Galois elements
`[5,25,625,128481]`. They are already present in the frozen 38-key Route-B
inventory.

## Capacity evidence

The `signed8-depth2-node-batch` gate uses the complete-A2B envelope plus a
136,314,880-byte wrapper allowance.

| Field | Bytes |
|---|---:|
| Total physical memory | 33,618,251,776 |
| Available memory at admission | 13,071,425,536 |
| Pre-guard incremental requirement | 2,517,438,208 |
| Guarded requirement | 3,054,309,120 |
| Remaining below the strict 80% limit | 3,293,466,060 |

## Negative controls and corrections

Three fail-closed events improved the accepted contract:

1. A pure artifact test showed that encoding sparse role masks at scale one
   rounded away inverse-FFT coefficients and produced identical serialized
   masks. Before any depth-2 HE run, the schedule was amended to encode masks
   at scale `q3`, rescale them to L2/S43 and move the path/leaf schedule to
   the exact L0 endpoint.
2. The first encrypted run completed the circuit but rejected report
   publication because the reconstructed state ledger did not equal the
   observed ledger.
3. A diagnostic replay isolated the only discrepancy: the broadcast raw
   scale had been reconstructed with `q5`, while the frozen transform is
   encoded at `q4`. The evidence reconstruction was corrected to `S*q4`.
   The third run then passed all 30 state records and every decoded-slot gate.

No failed run wrote the canonical result path. Unit tests now reject malformed
models, overflow-admitting certificates, wrong alignment topology, foreign
plaintext identities, changed state or operation ledgers, and self-consistent
mutations of nested A2B evidence.

The hash-locked replay passed 20 consecutive executions in 33.904 s. Complete
`secureeval`, `secureprofile` and command-package tests passed in
35.245/2.049/2.398 s respectively, followed by clean `go vet` results for all
three targets.

## Performance interpretation

This result establishes one-A2B all-node batching for 170 depth-2 queries.
The root-only C72 run evaluated 512 independent roots in 27.6964074 s; C73
evaluated 170 full depth-2 queries in 28.8937126 s. These are different
workloads and single observations. They do not define a speedup ratio.

A matched comparison requires at least:

- repeated isolated runs with the same query count and process conditions;
- a source-faithful selected-child depth-2 implementation with two serial
  comparison rounds or an authenticated refresh boundary;
- separate reporting of latency, queries per second, evaluated internal
  nodes per second and memory;
- the original BFV/BGV evaluator under its own packing and model semantics.

## Implication for integer and radix trees

C73 demonstrates a concrete design axis: SIMD words may encode nodes as well
as queries. For a complete binary tree of decision depth `d`, naive all-node
packing spends `2^d-1` words per query, so the 512-word Route-B layout admits
only `floor(512/(2^d-1))` queries. That exponential capacity loss makes
all-node batching a bounded-depth technique rather than a general traversal
solution.

The integer ALU creates a second research path. An `r`-bit digit or bounded
integer predicate can select among multiple children in one node, reducing
decision depth when the model is quantized or retrained for multiway splits.
The next radix experiment must implement digit extraction or equality,
construct a multiway selector, measure its extra Boolean products and leaf
mux cost, and compare total work at matched model quality. A higher arity is
useful only when the depth reduction outweighs selector and packing cost.

## Frozen implementation snapshot

| File | SHA-256 |
|---|---|
| `integer/secureeval/route_b_signed8_depth2_node_batch.go` | `5db4a1aac469015b8199ff64f81d629259c0c5c958fa825f627799124560e63e` |
| `integer/secureeval/route_b_signed8_depth2_node_batch_model.go` | `12000d0ff553417718eee47a1b1ed96b870d994141f728224f4e0508e268aec1` |
| `integer/secureeval/route_b_signed8_depth2_node_batch_test.go` | `57203929dc1d89acc138e19bbc0059c5ad7ebca883c3d185c671fc9cded5412f` |
| `integer/secureeval/route_b_signed8_depth2_node_batch_experiment.go` | `5af98967e402255b81d321a3db75e9371f8697bf815a2266591180b2ec83e811` |
| `cmd/route-b-signed8-depth2-node-batch/main.go` | `f0341fe90c725829fe66ac5552e644556c9606d4bde77324e448db5acf4074aa` |
| `cmd/route-b-signed8-depth2-node-batch/main_test.go` | `902ef32ecd5e3fc2135666b285dc9e8fa0addad4ae307675a8b1410987b203c9` |
| Registered amendment | `5f30ad645cd595e2a9d1df3c49e94c8d46b60dc677194119d5b0c662ce6f5688` |

## Reproduction commands

```powershell
go run ./cmd/route-b-signed8-depth2-node-batch `
  -out research/reproduction/route_b/route_b_signed8_depth2_node_batch_2026-09-01.json

go test ./cmd/route-b-signed8-depth2-node-batch `
  -run TestAcceptedRouteBSigned8Depth2NodeBatchArtifactReplaysEverySlot -count=20

go test ./integer/secureeval ./integer/secureprofile -count=1
go vet ./integer/secureeval ./integer/secureprofile `
  ./cmd/route-b-signed8-depth2-node-batch
```

## Evidence boundary and next gate

The artifact proves the declared R1 public-model signed-int8 depth-2 function
for one canonical batch. The implementation evaluates every child rather than
the source schedule's selected child. Thresholds and leaves are public, range
certificates are trusted admission metadata, and the model is quantized rather
than ordered-float32 equivalent. Security estimation, client/server isolation,
model privacy, repeated performance, full-depth evaluation, matched CCS
comparison and radix-tree improvement remain separate acceptance gates.

The next secure vertical slice is either a selected-child comparison ingress
with an authenticated refresh boundary or a preregistered multiway integer
node. Both must retain the C73 exact-level discipline and use matched benchmark
manifests before supporting a performance claim.
