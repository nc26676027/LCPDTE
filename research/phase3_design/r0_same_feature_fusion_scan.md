# R0 Same-Feature Fusion Scan

Status: Stage-2 workload evidence; necessary-condition scan, not an HE speed claim.

## Method

The repository models `xgb_model_d8.json`, `xgb_model_d10.json`, and
`xgb_model_d12.json` were scanned in their raw sparse XGBoost form. The
reproducible command is:

```powershell
& research/scripts/scan_same_feature_fusion.ps1 -ModelDirectory xgbdata
```

The script validates the parallel tree arrays and child bounds before counting:

- internal-to-internal parent/child edges;
- edges whose endpoints split on the same feature;
- maximal connected same-feature components;
- the longest same-feature run on any path; and
- roots of complete uniform same-feature subtrees of heights 2, 3, and 4.

A same-feature edge is only a necessary opportunity marker. Exact R0 fusion
still requires a finite-domain certificate covering threshold ordering,
equality convention, every induced interval, and the identical downstream
source state. A complete uniform height-2 root is the stricter structure in
which a root and both of its internal children use one feature; it can induce
an ordinary four-way interval partition only after the same semantic proof.

## Frozen result

| Raw model | SHA-256 | Trees | Internal nodes | Internal edges | Same-feature edges | Fraction | Multi-node components | Longest path run | Full uniform height 2/3/4 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| D=8 | `a2109512f7acafef4a3f8e96fb476a7aa76e4acdb25df44cc61afb57322132f7` | 8 | 353 | 345 | 5 | 1.45% | 5 | 2 | 0 / 0 / 0 |
| D=10 | `ea1e7914620d32f684c4e2f27fdad4f604c3ee93c73fd84cdc52e305916f24f6` | 8 | 461 | 453 | 13 | 2.87% | 13 | 2 | 0 / 0 / 0 |
| D=12 | `78917ad344b005f0005bd7d39ec1fdd10d6965bfe4935d226f63f0962ef27641` | 8 | 547 | 539 | 26 | 4.82% | 26 | 2 | 0 / 0 / 0 |

Every multi-node component contains exactly two internal nodes. The script
also emits the tree/node identifiers, side, feature, and both thresholds for
all 44 candidate edges so a later proof compiler can address them without an
unverifiable aggregate.

## Consequence for the innovation plan

These three supplied workloads falsify the premise that complete local
same-feature binary subtrees are common: none contains even one complete
height-2 block, and same-feature internal edges account for only 1.45--4.82%
of internal edges. R0 same-feature fusion therefore remains a bounded sparse
special case rather than the main expected speedup on the supplied models.

The primary integer/multiway investigation should instead test R1 models and
operator-level amortization: shared A2B conversion, exact batched B-A2B,
unary-to-digit conversion, and fewer dependent refresh rounds. Those R1 arms
must remain model-changing and must be compared on a matched accuracy/cost
frontier. The raw scan does not establish that any such arm is faster.
