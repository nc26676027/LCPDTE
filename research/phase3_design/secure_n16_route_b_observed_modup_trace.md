# Secure N16 Route-B observed ModUp/Trace contract

## Status and scope

This document freezes the minimum vendored Lattigo seam needed to prove the
actual sparse `ModUp` Trace dispatch prefix used by Route B. It is an
implementation contract only. It does not authorize a Route-B artifact, mint a
permit, authenticate an evaluation key, prove ciphertext correctness, or make
an HE execution result acceptable by itself.

The seam has one purpose: replace a parameter-derived statement that four
Trace rotations *should* run with invocation-local evidence of which real
`rlwe.Evaluator.Automorphism` calls were attempted and which returned
successfully.

The existing stock methods remain source-compatible and behavior-compatible:

```go
func (eval Evaluator) Trace(
    ctIn *Ciphertext,
    logN int,
    opOut *Ciphertext,
) error

func (eval Evaluator) ModUp(
    ctIn *rlwe.Ciphertext,
) (*rlwe.Ciphertext, error)
```

The patch adds exactly two observed entries:

```go
// core/rlwe
func (eval Evaluator) TraceObserved(
    ctIn *Ciphertext,
    logN int,
    opOut *Ciphertext,
) (TraceDispatchReport, error)

// circuits/ckks/bootstrapping
func (eval Evaluator) ModUpObserved(
    ctIn *rlwe.Ciphertext,
) (*rlwe.Ciphertext, ModUpTraceReport, error)
```

The returned report types are exported because `integer/secureeval` consumes
them across package boundaries. Their fields remain private. Slice accessors
return defensive copies. Callers cannot construct a valid success report by
setting fields, providing callbacks, or supplying expected rotations.

## Why the seam is required

The stock bootstrap `ModUp` ends with:

```go
return ctIn, eval.Trace(
    ctIn,
    eval.CoeffsToSlotsParameters.LogSlots,
    ctIn,
)
```

The project can derive the required Galois-key inventory from parameters, but
that inventory is a capacity condition. It is not evidence that this invocation
entered the intended Trace, preserved source order, or completed the expected
automorphisms. A wrapper around stock `ModUp` sees only the final error and
cannot reconstruct an honest failure prefix.

The observation point therefore sits immediately around each actual
`Automorphism` call inside the stock Trace core. It does not sit in Route B, in
the key inventory, or in a second replay of Trace.

## Frozen L11 dispatch

For the canonical standard-ring N16 parameters and `LogSlots=11`, Trace has
`gap = 2^(16-11-1) = 16` and executes four automorphisms in this exact runtime
order:

| Sequence | Exponent | Galois element |
|---:|---:|---:|
| 0 | 2,048 | 122,881 |
| 1 | 4,096 | 114,689 |
| 2 | 8,192 | 98,305 |
| 3 | 16,384 | 65,537 |

The accepted packing/capacity profile stores the same elements as the sorted
set `[65537, 98305, 114689, 122881]`. Runtime validation must compare the
observed sequence against `rlwe.GaloisElementsForTrace(params, 11)` in its
original order. Sorting an observed report before validation is forbidden.

## Report model

### Trace event

Each `TraceDispatchEvent` contains private values exposed by value accessors:

```text
sequence       uint32
kind           trace-automorphism | order-two-automorphism
hasOrdinaryExponent bool
ordinaryExponent    uint64
galoisElement  uint64
completed      bool
```

An ordinary-loop event has `hasOrdinaryExponent=true` and records the exact
power used in `params.GaloisElement(1<<i)`. The standard-ring `logN==0`
order-two event has `hasOrdinaryExponent=false`, `ordinaryExponent=0`, and
`galoisElement=ringQ.NthRoot()-1`. The order-two element is not represented by
a fabricated ordinary exponent: it is outside the ordinary `<5>` subgroup
power path.

### Trace report

`TraceDispatchReport` records:

```text
version
status                  success | failure
failureKind             none | error | panic
failureStage            none | validation | preparation | dispatch | add | finalize
ringLogN
ringType                 standard | conjugate-invariant
requestedLogN
inputOutputAliased
attemptedDispatches
completedDispatches
ordered events
```

It provides:

```go
func (r TraceDispatchReport) Validate() error
func (r TraceDispatchReport) Events() []TraceDispatchEvent
func (r TraceDispatchReport) Digest() [32]byte
```

The digest uses a versioned structural domain and covers every report field and
event. It authenticates neither keys nor ciphertext bytes and cannot serve as a
permit, lineage capability, or correctness certificate.

### ModUp report

`ModUpTraceReport` records:

```text
version
status                  success | failure
failureKind             none | error | panic
failureStage            none | dense-to-sparse | coefficient-lift |
                        sparse-to-dense | scale | trace | finalize
traceStarted
nested TraceDispatchReport
```

It provides the same `Validate` and structural `Digest` pattern plus a
defensive nested-report accessor. A report with `traceStarted=false` has a zero
nested Trace report. A report with `traceStarted=true` must contain the exact
nested report returned by the one real Trace invocation.

## Trace implementation

Stock and observed Trace share one private core:

```go
func (eval Evaluator) traceCore(
    ctIn *Ciphertext,
    logN int,
    opOut *Ciphertext,
    recorder *traceDispatchRecorder,
) error
```

`Trace` calls the core with `nil`. `TraceObserved` creates an invocation-local
recorder and calls the same core. The recorder has no exported constructor and
is never stored globally or in the evaluator.

The only modifications inside the algorithm are adjacent to the two existing
Automorphism call sites. For every ordinary loop step and for the optional
standard-ring order-two step, the sequence is:

```go
recorder.begin(kind, hasExponent, exponent, galEl) // immediately before call
err := eval.Automorphism(opOut, galEl, buff)
if err != nil {
    return err
}
recorder.complete()                   // after nil return, before ringQ.Add
```

With a nil recorder, `begin` and `complete` compile to guarded no-ops. There is
no second Automorphism, ciphertext copy, ciphertext hash, public sink, or
callback.

This linearization point proves completion of the semantic automorphism:
`Automorphism` performs key lookup, gadget product, ring automorphism, and
metadata copy before returning nil. A missing key returns an error and leaves
the last event incomplete. A panic inside that call likewise leaves the last
event incomplete.

The private core preserves all stock behavior:

- degree validation and error text remain equivalent;
- level selection, resize, metadata copy, inverse-gap multiplication and
  NTT/INTT transitions are unchanged;
- `ctIn==opOut` and distinct-output alias behavior are unchanged;
- `gap<=1` still copies only when the operands are distinct and records zero
  dispatches;
- the `logN==0` standard-ring order-two automorphism remains last, while a
  conjugate-invariant report cannot contain that event;
- stock errors remain errors and stock panics remain panics.

Only `TraceObserved` recovers a panic. Recovery seals a failure report and
returns a non-nil error. The output operand may be partially modified; the
caller must discard it.

`TraceDispatchReport.Validate()` uses `ringType` to derive the legal
`logN==0` success shape. Standard-ring success contains the ordinary prefix
followed by exactly one tagged order-two event. Conjugate-invariant success
contains no order-two event. An order-two event with
`hasOrdinaryExponent=true`, or an ordinary event without an exponent, is
invalid.

## Dispatch-prefix invariants

For every report:

| Outcome | Attempted | Completed | Last event |
|---|---:|---:|---|
| validation/preparation failure before dispatch | 0 | 0 | absent |
| kth Automorphism returns error | k | k-1 | kth incomplete |
| kth Automorphism panics | k | k-1 | kth incomplete |
| failure after kth successful Automorphism | k | k | kth complete |
| success | expected count | expected count | all complete |

Events are append-only and contiguous. `sequence` equals the zero-based slice
index. At most one event is incomplete, and it must be last. A success report
contains no incomplete event. A failure report cannot claim more completed than
attempted dispatches.

## ModUp implementation

Stock and observed ModUp share one private core. The stock entry selects the
existing `Trace` call. The observed entry selects `TraceObserved` once at the
same final position. It must not run stock Trace and synthesize a report
afterward.

The observed wrapper records the current ModUp stage before every operation
that can return an error and before entering the final Trace. It recovers only
at the observed public entry, seals a panic report, and returns a nil output.
The stock entry has no recovery and retains existing panic behavior.

When `TraceObserved` recovers an inner Trace panic, it returns a nested report
with `failureKind=panic` plus an error rather than re-panicking. The ModUp
observed core must inspect that nested failure kind and normalize its output to
nil. It must not treat the recovered panic as an ordinary Trace error merely
because the control flow returned normally.

Return semantics are frozen:

| Outcome | Stock `ModUp` | `ModUpObserved` |
|---|---|---|
| success | `ctIn, nil` | `ctIn, success-report, nil` |
| ordinary error before Trace | `nil, err` | `nil, failure-report, err` |
| ordinary Trace error | `ctIn, err` | `ctIn, failure-report, err` |
| panic | panic | `nil, sealed-panic-report, err` |

The ordinary Trace-error output follows the existing `return ctIn,
eval.Trace(...)` contract. Route B nevertheless terminally discards `ctIn` on
every observed error because ModUp and Trace mutate it in place. An observed
panic is never retried.

## Route-B consumption

The private Route-B wrapper accepts an observed ModUp result only when all of
the following hold:

1. the pre-operation installed-evaluator runtime identity and key inventory
   gates pass;
2. `ModUpTraceReport.Validate()` passes and reports success;
3. `traceStarted=true` and the nested report reports success;
4. `ringLogN=16`, `ringType=standard`, `requestedLogN=11`, and input/output
   aliasing is true;
5. exactly four events are attempted and completed;
6. event exponents and Galois elements equal the frozen source-order L11 table;
7. the installed key inventory contains the same elements as a set;
8. the post-operation evaluator runtime-identity snapshot equals the
   pre-operation topology snapshot;
9. no resident degree-3 compatibility-polynomial dispatch occurred;
10. the returned ciphertext is the same in-place object expected by the MR0
    schedule.

Any mismatch is terminal before CoeffsToSlots or the typed A2B degree-46/R2
kernel. Parameter-derived Galois elements may define the expected table and key
capacity, but only the nested observed report supplies runtime dispatch
evidence.

## Required tests

### Core RLWE Trace

- Stock and observed Trace on identical ciphertext copies produce identical
  ciphertext bytes, metadata, level, scale and error behavior.
- Both in-place and distinct-output forms are covered.
- A counting evaluation-key set proves identical lookup count and source order.
- L11 success emits exactly the four frozen events.
- Error and panic injection at dispatches 1 through 4 produces exact `k/k-1`
  prefixes and an incomplete final event.
- The equivalent stock panic still propagates.
- Invalid degrees fail with zero dispatch.
- `gap<=1` succeeds with zero dispatch.
- A standard-ring `logN==0` case records the final order-two event after the
  ordinary loop.
- A conjugate-invariant `logN==0` case contains no order-two event, and
  cross-wiring either ring type into the other report shape fails validation.
- Ordinary events require a present exponent; the order-two event requires an
  absent/zero exponent and `galoisElement=NthRoot-1`.
- Report slices are defensive and a zero or field-mutated report fails
  validation.
- Race testing covers concurrent observed calls on independent evaluators and
  confirms that no process-global attribution state exists.

### Bootstrap ModUp

- Stock and observed ModUp on identical ciphertext/evaluator copies produce
  identical ciphertext bytes, metadata, level and scale on success.
- L11 success returns the exact nested Trace report.
- Dense-to-sparse or other pre-Trace ordinary error returns nil output and zero
  Trace dispatch.
- Trace key errors return the mutated input pointer, an honest failure prefix
  and a non-nil error.
- Pre-Trace and Trace panic injections return nil output only from the observed
  entry; the stock entry still panics.
- Every observed failure is marked terminal by the Route-B caller and the
  ciphertext cannot be reused.
- RLWE evaluator runtime-identity snapshots before and after observation are
  equal, proving that observation did not replace evaluator/key/buffer
  topology.

### Gates

The implementation must pass:

```text
focused tests with count=20
go test for core/rlwe
go test for circuits/ckks/bootstrapping
go vet for both packages
gofmt and git diff --check
a bounded race run over small prefix-injection tests
fresh independent design and code audits
```

## Forbidden implementations

- Synthesizing successful events from parameters or a capacity profile.
- Sorting runtime events before comparison.
- Running Trace twice to obtain evidence.
- Recording completion before `Automorphism` returns nil.
- Recording only after return and thereby losing the failed attempt.
- A global atomic rotation counter or process-global observer.
- A caller-provided callback, sink, event list, expected-count override, or
  report constructor.
- Adding a general `AutomorphismObserved` API and expanding the patch to every
  rotation path.
- Hashing or copying ciphertext payload solely for observation.
- Changing stock error, panic, alias, NTT or output-pointer semantics.
- Treating the structural report digest as a permit, key proof, lineage anchor
  or ciphertext-correctness certificate.
- Continuing after an observed panic or reusing a partially modified
  ciphertext after any observed error.

## Risk register

| Severity | Risk | Required control |
|---|---|---|
| Critical | Expected rotations are synthesized and presented as execution evidence | Record only at the two real Automorphism sites; test missing-key prefixes |
| Critical | Completion is marked before real dispatch returns | Separate `begin` and `complete` around the exact call |
| Critical | Observation executes a second Trace | Stock/observed share one private core; count key lookups |
| Critical | Route B retries or reuses partially modified state | Terminal lineage transition on every observed error or panic |
| Major | Global counters mix concurrent invocations | Invocation-local private recorder only |
| Major | Runtime ordering is erased by sorting | Validate source-order events; keep capacity set separately sorted |
| Major | Stock error, panic or alias behavior drifts | Differential stock/observed tests for every outcome class |
| Major | A general automorphism observer enlarges the trusted patch | Keep the seam inside Trace and ModUp only |
| Minor | Error wrapping or report naming drifts | Freeze validation categories and focused goldens |
| Minor | Report allocation affects the stock path | Nil-recorder stock benchmarks and allocation checks |

## Completion boundary

Passing this contract establishes that the actual sparse ModUp invocation ran
the intended Trace automorphisms in the observed order and completed the
reported prefix. It does not establish DFT payload provenance, evaluation-key
security, ciphertext correctness, application security, or Route-B end-to-end
correctness. Those claims remain gated by the private artifact/receipt lineage,
installed-resident preflight, MR0 differential tests and the accepted secure
circuit profile.
