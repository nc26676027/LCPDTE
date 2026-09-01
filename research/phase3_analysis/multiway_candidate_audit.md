# Integer/radix decision-tree candidate audit

Status: Stage-2 design audit, 2026-08-30.  This document records structural
evidence, exact cost corrections, implementation gates, and falsification
criteria.  It makes no latency, security, or novelty claim.

## Decision

Only two candidates remain eligible for implementation:

1. **A — R0 exact common-prefix forest DAG.**  Share an OBO predicate producer
   across trees only when the complete cumulative predicate map and every HE
   producer/provenance field are identical.  This is source-semantics
   preserving for the supplied ordered-float32 forest, but must first use the
   ordered-float32/T2 comparison backend.  A signed-int8 realization is R0 only
   for a model natively defined over signed int8.
2. **C — conditional R1 oblivious radix-4 shared-A2B interval operator.**  The
   only admissible path fuses three public-threshold nibble summaries into the
   two existing Gao LUT rounds, combines them at L5, and emits one L4 unary
   bundle.  It is eligible only for a level-wise oblivious radix-4 model (or a
   publicly known active node) and only if the whole bundle enters one real
   scalar-lane reraiser.

All other higher-radix constructions below are controls or stopped ideas.

## Corrected comparison and refresh denominators

For `L=2^D` leaves, a uniform active-route radix-`r` interval tree evaluates

```text
C_r(L) = (r-1) log_r(L).
```

Because `(r-1)/ln(r)` increases for `r>1`, radix two minimizes independent
threshold predicates.  Radix four evaluates `3D/2` predicates, not `D/2`.

The earlier exploratory `12D versus 16D` comparison is withdrawn.  It compared
radix-4 B-A2B against binary serial A2B and was not matched.  For `n=8,w=4`,
Gao Algorithm 2 accepts exactly two arithmetic streams and still performs two
LUT rounds:

| evaluator | binary | radix-4 | matched ratio |
|---|---:|---:|---:|
| B-A2B refresh rounds, 8 trees | `8D` | `12D` | 1.5 |
| B-A2B kernel rounds, 8 trees | `8D` | `12D` | 1.5 |
| serial-A2B refresh rounds, 8 trees | `16D` | `24D` | 1.5 |
| serial-A2B kernel rounds, 8 trees | `16D` | `24D` | 1.5 |

These are algorithm-round counts, not observations from an encrypted B-A2B
implementation.  Every experiment must additionally report group occupancy,
word-slot occupancy, padding, combination rotations, and physical ciphertext
streams.

## Candidate matrix

| construction | semantics | physical result | disposition |
|---|---|---|---|
| exact common-prefix forest DAG | R0 | can remove pre-bootstrap per-tree comparator/selection/path producers; legacy bootstrap remains once per depth | candidate A |
| same-feature local interval/LUT | R0 after a finite-domain proof | only 1.45--4.82% same-feature internal edges; no complete height-2 block | sparse special case |
| mixed-feature binary-to-k-ary rewrite | not generally R0 | cannot preserve the active predicate and usually increases comparisons | reject |
| three independent signed-difference A2B calls | R1 | 1.5x binary refresh/kernel work | rejecting control |
| three differences through B-A2B | R1 | still 1.5x the matched B-A2B binary baseline | rejecting control |
| materialized-bit Boolean prefix compares | R1 | exact, but L5 to L2 and incompatible with current B2A/selector ingress | reject / C stop gate |
| fused nibble-LUT shared-A2B plus unary bundle | R1 | conditionally reaches L4 with two refreshes/two kernels per four records | candidate C |
| encrypted digit `b0+b1+b2` alone | R1 | two additions do not remove three predicates; no data-dependent rotation | not a separate candidate |

## A: exact common-prefix forest DAG

### Source evidence and physical denominator

The pinned implementation in `tree/main_tree.go` evaluates `CmpGeBits`
separately for every tree.  Only after those comparisons does
`MultiBootstrap_FeatureTree` pack up to eight branch ciphertexts: trees 0--3
in real lanes with weights `1,2,4,8`, and trees 4--7 in imaginary lanes with
the same weights.  Therefore exact prefix sharing can remove pre-bootstrap
physical comparator streams; it does **not** reduce the legacy one-bootstrap-
per-depth schedule.

For the eight supplied trees, the number of exact cumulative-prefix classes at
each depth is:

| model | `G_d` by depth | `sum G_d` | separate-tree streams | removed streams |
|---|---|---:|---:|---:|
| D8 | `[1,2,2,3,8,8,8,8]` | 40 | 64 | 24 |
| D10 | `[1,2,2,3,7,8,8,8,8,8]` | 55 | 80 | 25 |
| D12 | `[1,2,2,3,8,8,8,8,8,8,8,8]` | 72 | 96 | 24 |

The non-singleton memberships found by the read-only scan are:

- depth 0: `{0,1,2,3,4,5,6,7}`;
- depths 1 and 2: `{0}` and `{1,2,3,4,5,6,7}`;
- depth 3: `{0}`, `{1,3,5,7}`, and `{2,4,6}`;
- D10 depth 4 additionally contains `{4,6}`; the later classes are singletons.

Source and oracle digests:

| artifact | SHA-256 |
|---|---|
| `xgbdata/xgb_model_d8.json` | `a2109512f7acafef4a3f8e96fb476a7aa76e4acdb25df44cc61afb57322132f7` |
| `xgbdata/xgb_model_d10.json` | `ea1e7914620d32f684c4e2f27fdad4f604c3ee93c73fd84cdc52e305916f24f6` |
| `xgbdata/xgb_model_d12.json` | `78917ad344b005f0005bd7d39ec1fdd10d6965bfe4935d226f63f0962ef27641` |
| `xgbdata/x_test.bin` | `0908110a9ca20f52eef98eaa35e88a7b78b80bd493156910c9d58bab939d6abd` |
| `xgbdata/pred_d8.bin` | `c2d901d6fff1f5022b0df8531f7d46093cb993be75ee92c4ba31ad267fed01e2` |
| `xgbdata/pred_d10.bin` | `075af3a60b61c5cd6d14e6c7f1f11a3d185bc5def265953fba71fc781455b4df` |
| `xgbdata/pred_d12.bin` | `b67c4b6497420e5913853dbc0f2e177acfbec5d8b0cf2e67d8db8071f08a9da0` |

The class-token hashes observed during discovery are not accepted as sharing
proofs.  A class certificate must additionally bind the source and compile
digests, ordered-float32 convention and missing/default policy, parent class,
every path-position leaf marker/feature/exact threshold bits, feature and
threshold producer handles/order/packing, prior path-state provenance, root
CT--PT versus later CT--CT mode, range, exact level/scale/dimensions,
parameter/key/profile digests, class members, bootstrap lane, and immutable
fan-out relation.

The class packer orders classes by minimum tree id.  For `G<=4`, class `c` uses
real weight `2^c`; otherwise the first `ceil(G/2)` classes use real weights and
the rest use imaginary weights.  A shared ciphertext is copied before fan-out;
aliasing it into the legacy mutating packer is forbidden.

If class membership is observable to a client or runtime observer, A leaks
cross-tree prefix equivalence.  A structure-hiding experiment must pad back to
eight lanes; if that removes the physical saving, A fails under that leakage
contract.

### A acceptance gate

- exact route, leaf, and margin equality against raw ordered-float32 traversal
  and all frozen `pred_d*.bin` files;
- physical comparator streams equal `sum G_d`, while bootstrap calls remain
  exactly `D`;
- no alias mutation, hidden copy, profile substitution, or digest-only proof;
- matched parameters, packing, key material, leakage, query set, and forest;
- median end-to-end improvement at least 10%, 95% bootstrap interval excluding
  zero, and neither peak RSS nor communication worsening by more than 5%.

## Same-feature R0 negative evidence

The reproducible command is:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File research/scripts/scan_same_feature_fusion.ps1 -ModelDirectory xgbdata
```

| model | same-feature / internal-to-internal edges | fraction | max run | complete h2/h3/h4 blocks |
|---|---:|---:|---:|---:|
| D8 | 5 / 345 | 1.45% | 2 | 0 / 0 / 0 |
| D10 | 13 / 453 | 2.87% | 2 | 0 / 0 / 0 |
| D12 | 26 / 539 | 4.82% | 2 | 0 / 0 / 0 |

This evidence concerns local same-feature fusion.  It is separate from A's
cross-tree exact-prefix equivalence.

## C: conditional fused shared-A2B radix-4 interval operator

### Rejected materialized-bit path

For signed order let `y=x xor 0x80` and `c=t xor 0x80`.  A public-constant bit
comparison can use

```text
g_i = y_i (1-c_i)
e_i = 1-y_i-c_i+2 c_i y_i
G'  = G + E g
E'  = E e
GE  = G + E.
```

In the current two-half layout, one threshold costs ten CT--CT products, eight
rotations, and multiplicative depth three.  Three thresholds cost 30 products
and 24 rotations and leave L5 input at L2.  Current B2A requires both word
halves at L5, and the comparator-selector bridge requires an arithmetic-root
selector at L4.  This path therefore fails closed and is a control, not C.

### Only eligible L4 path

Each four-slot word continues to represent one query/tree node; the threshold
axis is not substituted for the word axis.  For public ranks `j=0,1,2`, compile
degree-at-most-15 truth tables into the two existing four-bit Gao LUT rounds:

```text
L_j = [lowNibble(x) >= lowNibble(c_j)]
G_j = [signedFlippedHighNibble(x) > signedFlippedHighNibble(c_j)]
E_j = [signedFlippedHighNibble(x) = signedFlippedHighNibble(c_j)]
B_j = G_j + E_j L_j.
```

The two kernels add three low and six high auxiliary outputs.  Those outputs,
coefficient work, live ciphertexts, and memory are charged; kernel cost is not
assumed constant.  Three parallel `E_j*L_j` multiply/relinearize/rescale
operations take L5 to L4.  The monotone bits form a sparse unary bundle with

```text
u0=1-B0, u1=B0-B1, u2=B1-B2, u3=B2.
```

Moving `u0..u3` to local slots 0..3 costs three rotations and six additions or
subtractions, with no further CT product.  The target for each four-record
physical stream is therefore two Gao refreshes, two kernels, nine auxiliary
LUT outputs, three CT--CT multiply/relinearize/rescales, three rotations, and
one scalar-lane bundle reraiser.

C stops immediately if thresholds below the root require encrypted active-node
selection, if any threshold gets its own refresh, if the materialized L5-to-L2
path is used, if more than one bundle reraiser is needed, or if the exact
`kernel L5 -> unary L4` state cannot be maintained.  Thus C requires a newly
trained level-wise oblivious radix-4 model and is model-changing R1.

### C acceptance gate

- exhaustive `x in [-128,127]` for every trained threshold triple;
- every 16-point nibble LUT, monotonicity `B0>=B1>=B2`, one-hot unary sum, and
  branch index match independent plaintext oracles;
- matched controls: oblivious binary int8 with the same fused public-threshold
  operator, three independent radix-4 signed comparators, radix-4 difference
  B-A2B, and the stopped materialized-bit path;
- exact state `kernel L5 -> combine/unary L4 -> one bundle reraiser`, with only
  two refresh and two kernel rounds per radix level;
- model-quality tolerances frozen before training/evaluation; suggested upper
  losses are AUROC 0.005 and AUPRC 0.01;
- median end-to-end improvement at least 10% with 95% interval excluding zero
  and peak RSS no greater than 1.10x the matched binary arm.

The result of A/C testing is a regime map.  Neither candidate supports a
general claim that integer or radix trees dominate binary trees.
