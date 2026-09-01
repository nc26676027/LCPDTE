# Route-B Signed-Int8 Same-Feature Radix-4 Report (C76)

Status: accepted author-side functional and operation-graph evidence; repeated
timing passes the registered direction test on this host but does not meet the
10% innovation-promotion threshold.

## Question and exact scope

C76 tests one narrow, prediction-preserving transformation: a depth-two binary
subtree whose root and both children compare the same signed-int8 feature is
compiled into a four-interval node. The public thresholds and leaves are

```text
thresholds = [-32, 0, 32]
leaves     = [-3.25, -0.75, 2.5, 5.125]
domain     = [-96, 95]
branch     = sum_i [x >= thresholds[i]]
```

The equivalent binary tree tests `0` at the root, `-32` on the left and `32`
on the right, with the same feature at all three nodes and the same `>=`
equality rule. This is an R0 transformation only for a subtree carrying that
same-feature interval semantics. It does not preserve an arbitrary
mixed-feature binary subtree.

The encrypted-input/public-model implementation uses Lattigo `LogN=16`,
`LogSlots=11`, 8-bit triangle words, 170 logical queries, 510 active predicate
words and two padding words. One complete two-round Gao-style A2B conversion is
shared across all 510 predicates. Model privacy is outside this experiment.

## Correctness and provenance

The plaintext proof exhaustively checks all 192 admitted feature values. The
encrypted canonical runs and every repeated benchmark process separately
decrypt only the final output and replay all 2,048 slots against independent
radix and binary oracles.

| Gate | Result |
|---|---:|
| Exhaustive plaintext values | 192 / 192 equivalent |
| Canonical encrypted queries per arm | 170 |
| Canonical radix path counts | `[55,29,30,56]` |
| Canonical equality counts | `[2,2,2]` |
| Radix canonical active/inactive/equivalence mismatches | `0 / 0 / 0` |
| Binary canonical active/inactive/equivalence mismatches | `0 / 0 / 0` |
| Fixed-order measured processes | 14 / 14 accepted |
| Counterbalanced measured processes | 32 / 32 accepted |
| Counterbalanced warmups | 2 / 2 accepted and excluded |

The canonical radix artifact has SHA-256
`5b9bd7ffebf551cd67cea4fc1d0f4ff214b4a2fdcfc1a4dd538743c61d2f7eda`;
the exact binary control has SHA-256
`622e43f99eada89a5bfce505389803d26eb9be1daf4853b1376531ad75f71f0b`.
The counterbalanced summary binds all 32 measured files with manifest digest
`9d22092774a12dc21ef3869f416e08735c4380ce55c25fdd9a005ec81390b8ad`
and summary digest
`9188e9ac0c231cb4c5ab907fd791a7982e29e0f449984478e563c00c309f90a6`.

## Exact circuit ablation

Both arms use the same threshold subtraction, full A2B, broadcast, sign
complement, three role masks/rescales and two alignment rotations. Only the
terminal selector graph changes.

| Terminal operation | Binary control | Radix-4 | Removed |
|---|---:|---:|---:|
| Selector complements | 2 | 0 | 2 |
| Ciphertext-ciphertext path products | 3 | 0 | 3 |
| Relinearizations | 3 | 0 | 3 |
| Path rescales | 3 | 0 | 3 |
| Path ciphertext additions | 1 | 0 | 1 |
| Ciphertext-plaintext leaf products | 3 | 3 | 0 |
| Leaf rescales | 3 | 3 | 0 |
| Leaf ciphertext additions | 2 | 2 | 0 |
| Base-leaf plaintext additions | 1 | 1 | 0 |
| Logical peak wrapper ciphertexts | 16 | 10 | 6 |
| Output level | 0 | 1 | one level retained |

The radix terminal is the telescoping expression

```text
y = l0 + (l1-l0)b0 + (l2-l1)b1 + (l3-l2)b2.
```

No hidden ciphertext product, plaintext branch decision, pre-output
decryption or decrypt/re-encrypt shortcut appears in that graph.

## Repeated timing

### Fixed-order discovery series

The preregistered seven-pair series used one excluded warmup per arm and fresh
processes, but every pair ran binary first and radix second. It produced 7/7
positive circuit and lifecycle deltas. Its fixed-order summary labels the
result `DESCRIPTIVE_ORDER_CONFOUNDED`; it is not the confirmatory timing row.

### Counterbalanced confirmation

The independent confirmation used one excluded warmup per arm and 16 measured
pairs after the eight-pair IQR trigger fired. Odd pairs ran radix then binary;
even pairs ran binary then radix. No observation was removed. Values below use
Hyndman-Fan type-7 quartiles.

| Metric | Binary median / IQR / range | Radix-4 median / IQR / range | Arm-median change |
|---|---:|---:|---:|
| Build wall (s) | `6.362 / 0.469 / 5.967–7.350` | `6.340 / 0.331 / 6.027–6.944` | `−0.35%` |
| Setup wall (s) | `33.107 / 4.823 / 30.937–44.568` | `32.917 / 2.585 / 30.899–43.692` | `−0.58%` |
| Common prefix (s) | `34.641 / 6.905 / 31.476–42.401` | `33.398 / 3.884 / 29.489–43.587` | `−3.59%` |
| Terminal (s) | `0.13499 / 0.04169 / 0.11815–0.19684` | `0.01776 / 0.00306 / 0.01414–0.03289` | `−86.85%` |
| Complete circuit (s) | `34.794 / 6.955 / 31.603–42.603` | `33.423 / 3.889 / 29.511–43.633` | `−3.94%` |
| Lifecycle (s) | `67.298 / 11.906 / 62.757–87.081` | `66.456 / 5.864 / 63.052–85.589` | `−1.25%` |
| Peak RSS (bytes) | `13,207,011,328 / 690,176 / 13,205,569,536–13,379,268,608` | `13,195,804,672 / 587,776 / 13,194,473,472–13,368,049,664` | `−0.085%` |
| Circuit throughput (queries/s) | `4.886 / 0.892 / 3.990–5.379` | `5.086 / 0.568 / 3.896–5.761` | `+4.10%` |
| Lifecycle throughput (queries/s) | `2.526 / 0.405 / 1.952–2.709` | `2.558 / 0.226 / 1.986–2.696` | `+1.26%` |

The registered paired decision also passes:

| Paired estimand, binary minus radix | Aggregate median | Radix-first median | Binary-first median | Positive pairs |
|---|---:|---:|---:|---:|
| Complete circuit | `0.568 s` | `0.116 s` | `0.683 s` | 11 / 16 |
| Lifecycle | `0.645 s` | `0.609 s` | `0.645 s` | 13 / 16 |

The estimate is high-variance. Aggregate paired IQR is `1.114 s` for the
circuit and `1.306 s` for the lifecycle, both larger than their median delta.
Final arm-wise circuit IQR/median remains 20.0% for binary and 11.6% for
radix-4. The result therefore supports a direction on this host and workload,
not a stable universal acceleration factor.

## Memory and serialization trade-off

Input ciphertext, evaluation-key inventory and encoded STC/CTS DFT artifact
sizes are identical across arms: 22,020,734, 3,525,373,686 and 2,641,410,345
bytes. The native binary output is 1,048,894 bytes at level 0; the radix output
is 2,097,486 bytes because it deliberately retains level 1. The extra level is
a composability resource. A terminal-only deployment may modulus-drop it
before transport, but that counterfactual is not measured here. The overlapping
peak-RSS ranges do not support a robust memory-reduction claim.

All sizes are Lattigo allocation-free `BinarySize` counters, not observed
network transfers. Public-model plaintext artifacts outside the encoded DFT
records are not included in a synthetic communication total.

## Security label

C76 uses the parameter and 41-key schedule bound by the C75 application
security profile. Each C76 process encrypts one fresh input ciphertext, a
subset of C75's three-input exposure. The exact profile decision is
`CONDITIONAL-PASS`, not an unconditional 128-bit claim. It depends on the
listed sparse-secret RLWE, KDM/circular and cross-key assumptions and does not
establish private-model, malicious, side-channel or full CKKS failure security.

## Workload relevance and innovation decision

The supplied D8/D10/D12 XGBoost models contain same-feature edges at only
1.45%, 2.87% and 4.82% of internal edges and contain zero complete uniform
same-feature height-two subtrees. C76 therefore validates a real algebraic
optimization but finds no direct R0 application site in those three models.

The terminal network is 7.60 times faster by counterbalanced arm medians and
removes three ciphertext products plus one level. The dominant shared A2B and
broadcast/alignment prefix limits the complete-circuit and lifecycle gains.
The preregistered candidate-promotion rule required at least 10% end-to-end
improvement; C76 reaches 3.94% by arm-median circuit time, 1.25% by lifecycle
time, and smaller paired-median fractions. The same-feature radix candidate is
therefore **not promoted as the main optimization**.

The surviving research direction is R1 operator amortization: train genuine
ordered interval nodes, reuse one converted representation across thresholds,
or fuse threshold predicates into the Gao LUT rounds. Those model-changing
arms require matched predictive-quality, privacy, failure and systems
comparisons before they can support a broader integer-tree claim.
