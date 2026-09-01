# Decision-tree planning contract

`treeplan` separates model semantics from any Lattigo ciphertext layout. An HE
backend can consume the exported arenas and metrics without importing the
current monolithic tree evaluator.

## Branch and leaf convention

- A binary split takes branch `0` when `x[feature] < threshold`; equality takes
  branch `1`.
- A depth-`D` full binary tree stores `2^D-1` breadth-first splits and `2^D`
  leaves. The root-to-leaf branch string is the MSB-first leaf index.
- `CompileR0` groups `g in {1,2,3,4}` consecutive levels. A supernode contains
  the original local binary subtree, so its digit is the same `g`-bit path. No
  split or leaf is merged, fitted, or reordered.
- Numeric thresholds and scalar floating-point leaves must be finite. NaN and
  infinities are rejected before routing because they do not define the stated
  total branch convention.
- Thresholds, leaves, and direct plaintext feature inputs use the `Ordered`
  numeric contract. Arbitrary struct/object leaves are intentionally excluded:
  model payloads that need richer labels must keep a separate numeric leaf ID
  table outside the certified routing plan. Every direct route rejects NaN or
  infinity in the complete supplied feature vector, including unused entries.

## R0 versus R1

`CompileR0` issues a package-private certificate binding a canonical binary
digest of the source tree to one of the compiled public arena. The digest writes
structural fields in a fixed order and numeric values by reflection kind, bit
width, exact integer value, or raw IEEE-754 bits. It never invokes JSON tags,
`MarshalJSON`, or other user-defined serialization. `Validate` detects a
mutated arena, and `VerifyAgainst(source)` checks both the source binding and a
fresh compiler reconstruction. A hand-built or JSON-round-tripped arena is
structurally inspectable but reports `unverified`, not R0 equivalence.
`Certificate()` exposes read-only SHA-256 strings for experiment manifests;
the private binding itself cannot be supplied through public fields.

Grouping produces `ceil(D/g)` **structural rounds**, but that count is not an HE
depth claim. `PlanSchedule` exposes the source-faithful OBO control plus the
frozen four-schedule accounting for every group beginning at depth `d`, with
`h=min(g,D-d)`, `S=2^d`, and
`K=2^h-1`. Here `S` counts candidate/possible supernode states; exactly one
candidate is encrypted-active during evaluation:

- `R0SequentialSourceFaithfulOBO`: the root is one CT--plaintext comparison;
  the remaining `D-1` selected predicates are CT--CT. The root bypasses the
  width-one feature/threshold selector, matching the pinned LCPDTE call graph.
- `R0SequentialActiveCTCT`: an explicit conservative uniform oracle with `h`
  dependent CT--CT comparisons. At relative
  depth `j`, both feature and threshold selection have width `2^(d+j)`.
- `R0EagerActiveCTCT`: `K` width-`S` feature selections, `K` width-`S`
  threshold selections, and `K` CT--CT comparisons. Its selector charge is at
  least `2KS` logical candidate terms before the digit/path graph.
- `R0EagerAllCTPT`: all `SK` predicates are evaluated CT--plaintext, followed
  by a complete width-`S` encrypted result/digit selector.
- `R0StateAwareFusedLUT`: the root uses one LUT only when the request carries a
  structured URI, SHA-256, domain descriptor, and domain size for a
  same-feature finite-domain equivalence-proof artifact. Below the root, the
  caller must choose either all `S` supernode
  LUTs plus a width-`S` selector and provide the corresponding proof reference,
  or one global state-domain LUT with its proof reference and a positive
  declared domain size for every group. The planner records these artifacts as
  `external_unverified`, checks structural same-feature preconditions, and
  marks the row benchmark-ineligible. Only the later integrity stage may verify
  artifact contents and promote eligibility.

The former combined `r0_eager_candidate` and simplified `r0_fused_lut` labels
are rejected. `MetricsForSchedule` remains a logical compatibility view for
the four non-fused schedules (source-faithful OBO, conservative uniform CT--CT,
eager active, and eager all); proof-bearing fused planning uses
`PlanSchedule` directly.

Every group reports provenance-separated comparator charges, logical comparison
and selector lower bounds, selector widths, and predicate/LUT dependency
rounds. End-to-end dependency depth is separately typed `not_measured`.
The issued schedule certificate binds the exact source/radix digests, request,
logical/proof structure, and physical observations; `Validate` rejects any
mutation and `VerifyScheduleAgainst` reconstructs the source/request binding.
Physical packing, comparator streams and per-stream factors, LUT inputs/outputs,
CT--CT and CT--plaintext multiplications, additions, A2B/B2A, rotations,
relinearizations, rescales, key switches, transforms, refreshes, bootstraps,
peak live ciphertexts/bytes, and wall time all use typed observations. An
unexecuted field is serialized as `{"status":"not_measured"}`; it is never
represented by an ambiguous zero. The compatibility `CostVector` labels its
depth as a predicate-stage lower bound and leaves logical bootstraps
`not_derived`; it is not an end-to-end latency claim.

R1 is an explicit multi-threshold interval tree. A radix-`r` node uses `r-1`
strictly ordered thresholds. For a complete uniform tree with `L=r^d` leaves,
the active-path comparison count is

```text
(r - 1) * log_r(L),
```

not merely `log_r(L)`. Training, conversion, and accuracy assessment therefore
belong to the R1 experiment and cannot be reported as R0 equivalence.

## Encrypted routing constraint

The chosen child index is encrypted. It cannot be supplied as a data-dependent
rotation/Galois element: ordinary HE rotations are selected by public indices.
Backends must use an oblivious construction such as one-hot masking, public
diagonal rotations, or a LUT/functional-bootstrap selector. `CostVector` keeps
rotations symbolic for this reason; measured backends must additionally report
their concrete rotations, multiplications, key switches, and bootstraps.

`CostVector` counts one worst-case active route. `LeafTerms` alone records the
width of the final global leaf selector. `LogicalBootstraps` is an ideal planned
refresh-stage count, not a claim that a grouped supernode already has a one-call
Lattigo implementation.
