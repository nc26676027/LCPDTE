# Radix and Integer-Node Innovation Hypotheses

Status: preregistered Stage-2 analysis; no performance claim.

## 1. The comparison-count baseline

For a complete uniform radix-`r` interval tree with `L=r^d` leaves, one active
route evaluates `r-1` ordered thresholds at each of `d=log_r(L)` nodes:

```text
C_r(L) = (r - 1) log_r(L)
       = ln(L) (r - 1) / ln(r).
```

For real `r>1`, `(r-1)/ln(r)` is increasing because
`ln(r) > 1-1/r`. Therefore the naive independent-comparison construction is
minimized at radix two. For `r=2^g` and `L=2^D`,

```text
C_(2^g)(2^D) = (2^g - 1) D/g > D     for g > 1,
rounds         = ceil(D/g).
```

A lower tree depth is consequently not evidence of lower total HE work. Any
radix speedup must amortize the extra predicates or remove another dominant
operation.

## 2. Necessary latency break-even condition

Ignoring the common final leaf accumulation only to expose the condition, let
`T_cmp(1)` be one binary comparison stage, `T_batch(k)` a jointly evaluated
batch of `k=r-1` predicates, `T_digit(r)` construction/selection of an
encrypted radix digit, and `T_refresh` the refresh cost per dependent stage.
For `r=2^g`, a necessary measured break-even condition is

```text
[T_batch(2^g-1) + T_digit(2^g) + T_refresh] / g
    < T_cmp(1) + T_select(2) + T_refresh.
```

The experiment must use measured physical calls, all ciphertext blocks, the
same prediction semantics, and the same security/correctness profile. Planner
rounds or per-ciphertext timings cannot instantiate this inequality.

## 3. R0: exact grouped binary semantics

General consecutive binary splits use different features and thresholds.
Their `g` branch bits cannot be replaced by one ordinary integer interval
comparison. The certified R0 grouping therefore preserves every split and
only changes scheduling.

There is one narrower exact-fusion opportunity. A local binary subtree whose
reachable splits all use the same feature induces a finite interval partition
of that feature. Sorting the reachable cut points and proving the leaf/state
label on every resulting interval can compile the subtree to an equivalent
multi-output LUT or interval node. This remains R0 only when a finite-domain
proof artifact binds:

- the source subtree and supported integer domain;
- all cut points and equality convention;
- every input interval to the identical source leaf/state;
- the exact output digit/selector representation.

The compiler must measure how often this condition occurs in the source
models. A global state-domain LUT for mixed-feature subtrees is a separate
construction whose domain generally grows as a Cartesian product and cannot
be assigned the same cost.

## 4. R1: genuinely trained integer/multiway nodes

An R1 interval node has sorted thresholds `t_1 < ... < t_(r-1)` on one feature
and encrypted branch digit

```text
j = sum_i [x >= t_i] in {0, ..., r-1}.
```

The predicates are nested, which creates three concrete optimization
hypotheses unavailable to an arbitrary mixed-feature radix group:

1. **Shared representation conversion.** Decompose/refresh the feature once
   with A2A/A2B, then reuse that representation across all thresholds instead
   of paying the dominant conversion independently.
2. **Batched predicates.** Pack the `r-1` threshold differences into the
   exact-batch B-A2B interface and charge padding/unused lanes in an outer
   dispatcher.
3. **Unary-to-digit fusion.** Treat the monotone predicate vector as a unary
   branch code and evaluate a proved Boolean-to-arithmetic digit/LUT path,
   rather than materializing an unconstrained one-hot vector through
   data-dependent rotations.

Each is initially a hypothesis. A correct implementation must still account
for private threshold selection, low/high Boolean halves, B2A/A2B calls,
rotations, key switches, rescaling, refresh, live memory, and final leaf
selection.

## 5. Experiment arms

| Arm | Semantics | Required control |
|---|---|---|
| binary OBO | source-faithful R0 | one root CT--PT and `D-1` selected CT--CT comparisons |
| grouped binary | R0 | identical source digest and predictions; `g=1..4` |
| same-feature fused | R0 only after proof | finite-domain exhaustive equivalence and proof digest |
| naive interval | R1 | `r-1` independent comparisons per node |
| shared-A2B interval | R1 | same trained model as naive interval |
| batched B-A2B interval | R1 | same trained model and exact batch/padding charge |
| unary-digit fused | R1 | same trained model and exhaustive node-domain oracle |

R1 arms are compared at matched train/test split, task metric, model size or
explicit Pareto frontier, privacy leakage, CKKS failure tolerance, and
security profile. They are not reproductions of the binary source model.

## 6. Falsification criteria

The multiway hypothesis is rejected for a workload/profile if any of the
following holds after matched measurement:

- end-to-end latency, throughput, or peak memory is not Pareto-improved;
- conversion/selection overhead erases the refresh-round saving;
- prediction quality or leakage changes outside the preregistered tolerance;
- padding makes B-A2B utilization too low;
- same-feature R0 opportunities are too rare to affect the workload;
- correctness margin or failure rate is worse at the matched security level.

The output of these tests is a regime map, not a universal claim that integer
trees dominate binary trees.
