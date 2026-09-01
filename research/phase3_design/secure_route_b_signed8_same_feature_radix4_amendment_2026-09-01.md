# Secure Route-B Signed-8 Same-Feature Radix-4 Amendment

Status: preregistered before implementation or encrypted measurement.

## Scope and exact semantics

This experiment implements one public-model signed-int8 interval node with
three ordered public thresholds and four public real leaves. It is both an R1
integer/radix node and an exact R0 compilation target for the special case in
which a depth-2 binary subtree tests the same feature at all three nodes.

The frozen radix model is:

```text
thresholds = [-32, 0, 32]
leaves     = [-3.25, -0.75, 2.5, 5.125]
branch j   = sum_i [x >= thresholds[i]]
output     = leaves[j]
```

The exact equivalent binary control has root threshold `0`, left-child
threshold `-32`, right-child threshold `32`, the same four leaves, the same
`>=` equality convention, and the same feature supplied to all three node
words. Exhaustive equivalence over every admitted `x in [-96,95]` is required
before an encrypted result can be accepted. The three no-overflow difference
ranges are respectively `[-64,127]`, `[-96,95]`, and `[-128,63]`.

## Packing and encrypted circuit

One Lattigo `LogN=16`, `LogSlots=11`, 8-bit Route-B ciphertext contains 512
triangle words. The experiment evaluates 170 logical queries, repeats each
encrypted feature in three consecutive words, and charges two padding words.
The threshold vector is packed in ascending order. One complete two-round A2B
conversion is shared across all 510 active predicate words. The recovered
monotone GE predicates are role-masked and aligned to the first word of every
query with the same broadcast, two rotations, and three mask/rescale pairs as
the binary control.

The registered radix terminal is the telescoping selector:

```text
y = l0 + (l1-l0)b0 + (l2-l1)b1 + (l3-l2)b2,
where bi = [x >= ti].
```

It must use exactly three ciphertext-plaintext leaf products, three physical
rescales, two ciphertext additions, and one base-leaf plaintext addition. It
must use zero selector complements, zero ciphertext-ciphertext path products,
zero path relinearizations, and zero path rescales. The output is required at
level 1 and the canonical default scale. No ciphertext scale retagging,
decryption before the final output, plaintext branch decision, or
decrypt/re-encrypt shortcut is allowed.

## Inputs and correctness gates

The canonical 170-query sequence is deterministic, stays in `[-96,95]`, and
includes both endpoints, every threshold, and immediate neighbors of every
threshold. Its exact sequence and digest are frozen by source and tests before
the first encrypted run. Acceptance requires:

- exhaustive plaintext radix/binary equivalence for all 192 admitted values;
- zero active and inactive/padding mismatches at tolerance `5e-4`;
- exact equality-count and four-path-count reconstruction;
- exact level/scale, transform, Galois-key, operation-count, and ciphertext
  payload ledgers;
- no pre-output decryption or plaintext branch decision;
- a fresh-process capacity gate no weaker than the accepted C73 all-node
  depth-2 upper bound.

## Matched comparison and claims

The primary causal comparison is the exact operation graph after the common
A2B/broadcast/alignment prefix. Removing three ciphertext-ciphertext
products, three relinearizations, three path rescales, two complements, and
one path addition while preserving predictions supports an algorithmic
operation-count and one-level saving claim.

Timing superiority requires separate fresh-process binary-control and radix
runs with the identical host, parameter tuple, 170-query sequence, leaves,
thread configuration, capacity policy, and output checks. The registered
protocol is one warmup plus seven timed repetitions per arm, increasing to 15
when `IQR/median > 10%`. Report median, IQR, min/max, setup, common-prefix,
terminal, total wall time, peak RSS, throughput, and serialized online/setup
bytes when available. A single C76 observation may establish correctness and
the physical ledger but cannot establish a speedup.

## Falsification

The optimization is rejected for this workload if exact binary equivalence
fails, the terminal requires a hidden ciphertext-ciphertext selection, output
precision fails, or repeated end-to-end latency/peak memory is not Pareto-
improved. Even on success, the result applies only to same-feature ordered
subtrees or genuinely trained interval nodes; it does not convert arbitrary
mixed-feature binary subtrees into one integer comparison.

## Repeated-series trigger clarification

This clarification was frozen after the two single-run correctness artifacts
and before the repeated benchmark series. Those correctness artifacts are not
members of the timing sample. Each measured observation is a separate process
with freshly generated randomness and is paired only by run index and execution
order; no key material or installed evaluator is reused across arms.

The seven-to-fifteen extension trigger is evaluated independently for each arm
on the two inferential latency metrics: complete encrypted-circuit wall time and
complete lifecycle wall time. If either metric has `IQR / median > 10%` after
seven measured repetitions, both arms are extended to fifteen. Build/setup,
common-prefix, terminal-only, RSS, and throughput rows remain mandatory
descriptive diagnostics but do not trigger extension: the terminal-only radix
timer is intentionally much shorter than the lifecycle and is not the claimed
end-to-end estimand.

The benchmark also records exact allocation-free `BinarySize` values for the
online input and output ciphertexts, the 41-key evaluation-key inventory, and
the encoded STC/CTS DFT artifact. These are serialization-size counters rather
than observed network traffic. Public-model plaintext artifacts outside those
four counters are reported as unmeasured and are not folded into a synthetic
communication total.
