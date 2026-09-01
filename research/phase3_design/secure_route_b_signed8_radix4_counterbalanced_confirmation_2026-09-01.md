# Secure Route-B Signed-8 Radix-4 Counterbalanced Confirmation

Status: preregistered after the first seven-pair AB series and before any
counterbalanced-confirmation measurement.

## Motivation and separation from the first series

The first repeated series executed every pair in fixed `binary -> radix4`
order. Fresh processes prevent evaluator/key reuse, but they do not remove
time-order, thermal, scheduler, or file-cache effects. That series remains a
complete descriptive result and is not pooled into the primary analysis here.
This independent confirmation is registered specifically to close the order
confound identified during integrity review.

## Frozen workload and implementation

Both arms use the already frozen 170-query signed-int8 input, thresholds
`[-32,0,32]`, leaves `[-3.25,-0.75,2.5,5.125]`, Lattigo `LogN=16`,
`LogSlots=11`, the same L11 Route-B parameter tuple and 41-key schedule, one
complete two-round A2B conversion, tolerance `5e-4`, and the same fresh-process
capacity gates. No code, parameter, model, correctness, or measurement-field
change is admitted between arms. Every run must have zero active, inactive,
and binary-equivalence mismatches.

## Order-balanced protocol

One fresh-process warmup per arm is excluded. The measured series contains
eight pairs. Odd-numbered pairs run `radix4 -> binary`; even-numbered pairs run
`binary -> radix4`, producing four observations in each order stratum and
eight observations per arm. New randomness is generated in every process;
keys and evaluators are never reused.

The primary paired estimands are `binary - radix4` complete encrypted-circuit
wall time and complete lifecycle wall time. A timing advantage is accepted
only when all of the following hold:

1. the aggregate median paired delta is positive for both estimands;
2. the median paired delta is positive inside both the radix-first and
   binary-first strata for both estimands;
3. all correctness, lineage, security-profile, and capacity checks pass.

Arm-wise median, type-7 IQR, min/max, setup, common prefix, terminal, peak RSS,
throughput, and serialized-size counters are also reported. Pair deltas are
descriptive; no normality assumption or asymptotic p-value is introduced for
eight pairs.

After eight pairs, both arms extend to sixteen only if either arm has
`IQR/median > 10%` for encrypted-circuit or lifecycle wall time. The extension
rule does not use terminal-only or RSS diagnostics. The confirmation is not
stopped early for a favorable sign.

## Decision boundary

Passing supports a host- and workload-specific timing result plus the already
causal operation-count/level result. Failure makes repeated timing
`INCONCLUSIVE` while leaving correctness and exact circuit ablation intact.
Peak-RSS and communication claims require their own non-overlapping evidence;
a small median difference alone is reported as descriptive rather than as a
robust resource reduction.
