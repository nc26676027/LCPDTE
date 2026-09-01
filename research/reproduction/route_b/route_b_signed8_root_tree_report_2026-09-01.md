# Route-B signed-int8 root-tree reproduction report

Date: 2026-09-01  
Status: accepted functional reproduction artifact; cryptographic security and
end-to-end speedup remain unverified.

## Outcome

The Lattigo N16/L11 Route-B implementation now evaluates a complete SIMD
signed-int8 root decision node and selects public real leaves. The canonical
experiment packed two copies of every signed-int8 value into 512 four-slot
words, evaluated threshold zero, and checked all 2,048 output slots against an
independent plaintext tree oracle. Every slot matched.

```text
encrypted ArithmeticRootSlots(x)
  -> x - ArithmeticRootSlots(t)
  -> complete two-round 8-bit A2B
  -> high Boolean half [b4,b5,b6,b7]
  -> direct column-3 broadcast [b7,b7,b7,b7]
  -> ge = 1 - b7
  -> left + ge * (right-left)
```

The model was `t=0`, `left=-2.25`, and `right=3.5`. The registered range
certificate was `x in [-128,127]`, `t in [0,0]`, and therefore
`x-t in [-128,127]`. Equality selected the right leaf.

## Relation to LCPDTE

This slice preserves the LCPDTE root schedule: the client feature is
encrypted, while the root threshold is server-public and enters through one
ciphertext-plaintext subtraction. One comparison serves all packed queries.
The new comparison represents each feature as one Gao `Z_(2^8)` arithmetic
word rather than eight independent bit planes.

The repository's source models use float32 thresholds. Signed-int8 evaluation
therefore defines an R1 quantized or retrained model arm, not an R0 replacement
for exact ordered-float32 LCPDTE. Below-root private threshold selection and
multi-depth path-state orchestration remain separate tasks.

## Direct selector bridge

Complete Route-B A2B returns the ordinary Boolean high half at L5/default
scale. A four-diagonal block transform copies its fourth column to all four
positions in each word. The transform is encoded at Q4/P6, uses rotations
`[1,2]` and Galois elements `[5,25]`, and returns L4 before one rescale to
L3/default scale.

This bridge directly produces the repeated scalar selector needed by real
leaf selection. It removes the older functional S35 route through Gao
arithmetic-root sign fusion followed by periodic selector reraising. The
measured root-tree result establishes correctness of this local replacement;
its end-to-end performance effect requires a matched baseline.

Frozen broadcast evidence:

| Item | Value |
|---|---|
| Source digest | `078fa95a6f35955ff4a8f8bbe9a10ba065e0f07ed318eb04185d09631b1bd5a2` |
| Compiled digest | `f5ce60cc821470595ee12a6c99155bcbed29c698da29b030638f973a452e0063` |
| Encoded bytes | 25,166,272 |
| Rotations | `[1,2]` |
| Galois elements | `[5,25]` |

Both keys already belong to the frozen 38-key Route-B union; the tree wrapper
adds no evaluation key.

## Canonical evidence

Artifact:
`research/reproduction/route_b/route_b_signed8_root_tree_2026-09-01.json`

| Field | Measured value |
|---|---:|
| JSON bytes | 267,104 |
| JSON SHA-256 | `2410dc161bf37f404fcf88a1b0cfd8973f136833d6dfe902d098757b5c5fb67c` |
| Input words / distinct values | 512 / 256 |
| Checked output slots | 2,048 |
| Left / right words | 256 / 256 |
| Mismatched slots | 0 |
| Maximum absolute leaf error | `4.1590670063484936e-7` |
| Maximum imaginary magnitude | `6.313179629879332e-10` |
| Build wall time | 5.5014542 s |
| Complete A2B wall time | 25.8248727 s |
| Root-tree circuit wall time | 27.6964074 s |
| Whole lifecycle wall time | 56.8712487 s |
| Build peak RSS | 3,273,736,192 B |
| Post-install peak RSS | 6,568,878,080 B |
| Post-tree peak RSS | 13,130,219,520 B |
| Construction-counter delta | `[0,0,0,3]` |

Identity anchors:

| Item | SHA-256 |
|---|---|
| Root-tree report | `fa0c3563714d95077833e1b085e55a679e02a220305ace9588d916754d323feb` |
| Nested complete A2B | `d26dd046f85c507055ffadffa1a03c596ab4155df34e950f3f200ac5c36fd2f9` |
| Supplemental L3-to-L1 STC | `bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a` |
| Root-tree capacity plan | `61e5f8bce34231dbdd33621ec247939a27b5bad806530cf79163e5d22a9c19f9` |
| Input pattern | `2db53e1464ae019964bdf79f18177058f0a48b2a9226aae0f4373dacd5e765f3` |
| Canonical parameter payload | `c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816` |

The threshold, scalar-one, leaf-delta, and left-leaf plaintext payload digests
are also bound in the JSON and replay test.

## Exact state ledger

| Stage | Level | Exact scale |
|---|---:|---|
| Encrypted feature | 20 | `0x1p+43` |
| Feature minus public threshold | 20 | `0x1p+43` |
| Complete-A2B high Boolean half | 5 | `0x1p+43` |
| Sign broadcast before rescale | 4 | `0x1.00001340002p+86` |
| Repeated sign | 3 | `0x1p+43` |
| Repeated GE selector | 3 | `0x1p+43` |
| Leaf-delta product before rescale | 3 | `0x1.ffffe300004p+85` |
| Selected real leaf | 2 | `0x1p+43` |

Every state is degree one, batched, NTT-form, and has L11 dimensions.

## Operation ledger

The wrapper adds the following work around the separately reported complete
A2B circuit:

| Operation | Count |
|---|---:|
| Public-threshold CT-PT subtraction | 1 |
| Complete A2B invocation | 1 |
| Broadcast linear transform | 1 |
| Broadcast diagonal plaintext products | 4 |
| Broadcast ciphertext additions | 3 |
| Broadcast rotations / key switches | 2 / 2 |
| Broadcast rescale | 1 |
| Ciphertext negation | 1 |
| Selector plaintext addition | 1 |
| Leaf CT-PT product | 1 |
| Leaf rescale | 1 |
| Leaf plaintext addition | 1 |
| Additional relinearizations | 0 |

The nested complete A2B circuit reports one special-b0 transform, two masks,
two refreshes, two Gao kernels, one ID-scale product, three level alignments,
three subtractions, zero residual rotations, and two shared-CTS uses.

## Capacity evidence

The independent `signed8-root-tree` runtime gate sampled:

| Field | Bytes |
|---|---:|
| Total physical memory | 33,618,251,776 |
| Available memory at admission | 13,304,766,464 |
| Pre-guard incremental requirement | 2,451,902,208 |
| Guarded requirement | 2,988,773,120 |
| Remaining below the strict 80% limit | 3,592,342,988 |

The 70,778,880-byte increment over complete A2B accounts for the public
threshold, high-precision threshold slots, broadcast source and encoded
diagonals, selector/leaf plaintexts, and five wrapper ciphertexts.

## Fail-closed evidence

Development exposed two distinct negative controls:

1. Treating the bootstrapping key wrapper as a raw
   `*rlwe.MemEvaluationKeySet` was rejected before the first HE operation. The
   accepted preflight now checks the installed `rlwe.EvaluationKeySet`
   interface after the canonical installed-evaluator validator has sealed its
   embedded memory key set and 38-key inventory.
2. The initial state contract placed the returned high Boolean half at L4.
   Runtime evidence showed that the complete A2B API returns it at L5 and that
   the Q4 transform produces L4. The preregistered ledger was corrected before
   accepting an artifact; no metadata retag or scale override was used.

Unit tests reject overflow-admitting ranges, thresholds not fixed by the range
certificate, non-finite or oversized leaves, wrong broadcast topology, and
self-consistent mutations of model, state, operation, transform, or nested A2B
evidence.

## Frozen implementation snapshot

| File | SHA-256 |
|---|---|
| `integer/secureeval/route_b_signed8_root_tree.go` | `164596a521c12da7f809b8d7a1b7d79f0fbb83ddebbf1750651e2955f3f1875e` |
| `integer/secureeval/route_b_signed8_root_tree_model.go` | `1fc12f3cbec31414218c32135d07bbbd9946c3851c44d5eb0068c107295ea8b6` |
| `integer/secureeval/route_b_signed8_root_tree_test.go` | `a6f5f36b035316ff01346e8e5772d92d1270fa977bae9f80955f83dfc898256a` |
| `integer/secureeval/route_b_signed8_root_tree_experiment.go` | `f7ad5bf71207ed4e18926e7921f43f8258bcb9552002334101a9e111d67032cd` |
| `cmd/route-b-signed8-root-tree/main.go` | `a488284c811254ddc745333db441123d10f97ee2de0090ba8a4a3d34fad59031` |
| `cmd/route-b-signed8-root-tree/main_test.go` | `a4c8084ede86202d1f3d39f173a663025b03d4a2d0f7e3f5bd39a8f39f271360` |
| Registered amendment | `afce58e4d7b54f2018cb69a0c2ba0773a95c0185e0055f1f7b6bf66efa0fc197` |

## Reproduction commands

```powershell
go run ./cmd/route-b-signed8-root-tree `
  -out research/reproduction/route_b/route_b_signed8_root_tree_2026-09-01.json

go test ./cmd/route-b-signed8-root-tree `
  -run TestAcceptedRouteBSigned8RootTreeArtifactReplaysEverySlot -count=20

go test ./integer/secureeval ./integer/secureprofile -count=1
go vet ./integer/secureeval ./integer/secureprofile ./cmd/route-b-signed8-root-tree
```

## Evidence boundary and next slice

This artifact proves a functional public-threshold root node with public real
leaves under one canonical Route-B parameter chain. It does not establish a
security level, client/server isolation, encrypted range enforcement, private
below-root thresholds, complete LCPDTE traversal, model-quality parity with
float32 XGBoost, or a speedup.

The next vertical slice must convert the repeated root selector into a
source-faithful depth-two selection: choose one of two encrypted features and
thresholds, perform the below-root CT-CT comparison with a registered ingress
profile, and select four real leaves. That experiment will determine whether
the direct scalar bridge can replace the older periodic reraiser throughout a
multi-depth schedule.
