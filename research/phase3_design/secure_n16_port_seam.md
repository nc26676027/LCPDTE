# Secure `LogN=16` port seam

Status: design constraint record; no secure-circuit or performance claim.

## Problem

The accepted `integer/homchain` slices prove a bounded functional topology at
`LogN=5`, full 16-slot packing, default scale `2^35`, a 21-prime Q chain and a
dense/no-switch refresh evaluator. Their constructors, profiles, state checks
and evidence digests intentionally bind those facts. The exact
`lattigo-gao-compatible-n16-v1` candidate instead has `LogN=16`, 32,768 slots,
default scale `2^43`, exact 904/351/1254-bit Q/P/QP products and a declared
`H=192` main secret plus `h=32` ephemeral bootstrapping secret.

The secure port must therefore be a second adapter at a new seam. Relaxing the
functional constructors in place would erase the distinction between accepted
functional evidence and an unverified secure profile.

## Dependency classification

- Triangle algebra, polynomial artifacts, DFT generation and Lattigo
  evaluation are in-process dependencies. They stay behind the module's
  interface and are tested through encrypted outputs and traces.
- Key generation is local-substitutable: deterministic test fixtures and the
  production key inventory cross the same internal seam. The external module
  accepts keys; it does not silently generate them.
- The estimator transcript is evidence, not an execution dependency. A
  controlled profile verifier consumes its authenticated decision and bundle
  identities before any `secure_profile_verified` promotion.

## Recommended module and interface

Add a deep secure-operator module in new files while leaving every frozen
functional source file unchanged. The external interface should expose the
smallest complete tree-facing surface:

```go
type SecureN16OperatorSet struct { /* private profile, operands, keys */ }

func NewSecureN16OperatorSet(
    profile VerifiedCircuitProfile,
    encoders EncoderSet,
    keys EvaluationKeyInventory,
) (*SecureN16OperatorSet, error)

func (s *SecureN16OperatorSet) A2B(input ArithmeticValue) (BooleanWord, Trace, error)
func (s *SecureN16OperatorSet) B2A(input BooleanWord) (ArithmeticValue, Trace, error)
func (s *SecureN16OperatorSet) CompareSigned8NoOverflow(left, right ArithmeticValue) (Selector, Trace, error)
func (s *SecureN16OperatorSet) Select(selector Selector, left, right ArithmeticValue) (ArithmeticValue, Trace, error)
```

`B2A` remains part of the interface because Gao conformance and selector/tree
composition are independent callers. Selector reraising remains internal
until another caller needs that lower-level schedule. The tree-facing
comparison and selection methods provide greater leverage and keep
representation ordering, exact level/scale transitions and key preflights
behind the seam. Tests exercise the same interface as the tree adapter. A
diagnostic interface may return immutable trace snapshots, but it must not
expose mutable polynomial operands or profile state.

Two adapters justify the seam:

1. the existing frozen functional adapter, used only by small exhaustive
   correctness tests;
2. the new exact-parameter adapter, bound to the `LogN=16` parameter bundle,
   real P basis and explicit sparse-secret switching keys.

Shared pure artifact builders may be called from new files in the same Go
package. Existing functional structs, validators and evaluation methods are
not generalized merely to reduce duplicated orchestration code; preserving
their accepted identities has higher evidentiary value.

## Required profile differences

| State | Frozen functional adapter | Exact-parameter adapter |
|---|---:|---:|
| `LogN` / slots | 5 / 16 | 16 / 32,768 |
| default scale | `2^35` | `2^43` |
| Q / P levels | 21 / 1 prime | 21 / 7 primes |
| A2B refresh message ratio | `2^15` | derive and prove from exact `q0/defaultScale`; expected MR0 candidate, not assumed |
| main secret | iid ternary `P=2/3` | balanced sparse ternary `H=192` |
| ephemeral switch | absent | balanced sparse ternary `h=32`, with dense-to-sparse and sparse-to-dense keys |
| maturity | functional-not-secure | secure-profile-unverified until circuit, samples and estimator evidence close |

The 43-bit prime target is not an exact power of two. The adapter must record
the actual `ScaleDown` `errScale` and prove its exact scale relation rather
than replacing `q0` by `2^43` in a formula. Likewise, a seven-prime P basis
changes key-switch storage and decomposition and must be present in both the
runtime inventory and estimator exposure count.

## Vertical gates

1. **Parameter admission:** reconstruct the exact JSON prime arrays in
   Lattigo, bind the canonical manifest digest, and reject any alternate
   ordering, distribution, scale or bundle status.
2. **Artifact-only capacity:** generate the full-slot transforms and packed
   polynomial operands without keys through an explicitly precision-bound
   builder; record build time, allocation/RSS and exact rotation inventory.
   The stock S43 bootstrap constructor's 53-bit DFT path is not admissible.
   Stop on the preregistered 80% host-memory gate.
3. **Kernel-only encrypted gate:** run exp46, two squares and the shared ID/MSB
   LUT at the exact scale/Q/P profile without claiming refresh correctness.
4. **MR0 refresh gate:** execute the special-`b0`/DFT/ScaleDown/ModUp/Trace
   path with the real P basis and `h=32` switching keys. Bind raw levels,
   scales, `errScale`, input immutability and every key identity.
5. **Complete A2B and comparator:** compose two serial rounds, direct sign
   fusion and the signed no-overflow oracle over a declared range. Zero
   failures are required before any tree call.
6. **Tree seam:** use the secure operator set in the same logical T0 oracle,
   then add selector reraising and multi-depth composition. Report physical
   streams, all key bytes, peak RSS and wall time per matched logical query.

## Artifact-capacity derivation

The 2026-08-30 read-only capacity audit fixes the artifact-only gate before
any full-slot allocation. At `LogN=16`, the profile has `N=65,536`, 32,768
slots and 8,192 packed 8-bit words. The nine transform specifications contain
1,179,648 high-precision complex entries; a conservative 256-byte bound per
entry gives a 288 MiB resident upper bound. The exp46 and two degree-15
polynomial operands, including full slot mappings, remain below 2 MiB and are
not the limiting artifact.

The fixed DFT schedules are the limiting artifacts:

| Artifact | Factor diagonal counts | Encoded QP storage |
|---|---:|---:|
| STC at `LQ18/P6` | `255, 256` | 6.4873046875 GiB |
| CTS at `LQ20/P6` | `32, 63, 63` | 2.16015625 GiB |
| Total |  | 8.6474609375 GiB |

With the specifications, one compiled transform pair, masks and polynomial
operands, the estimated resident artifact set is about 9.15 GiB. The host
snapshot used by the audit had 31.309 GiB physical memory, 15.974 GiB free,
and only 9.712 GiB of additional headroom before the 80% limit. The resident
estimate leaves about 0.56 GiB for ring caches, encoder scratch, garbage
collection and transient construction, so the current host is
`RESOURCE_BLOCKED` before full-slot DFT construction.

The present non-streaming builders make the stop decision stronger. DFT
generation retains all factors, and `digestDFTMatrixNumericPayload` builds and
then copies a hexadecimal textual representation of the complete matrix. The
STC digest alone can require several additional GiB. Neither function is
admissible on the secure N16 path until a streaming construction and streaming
binary digest have their own capacity proof.

The encrypted Route-B constructor must consume a second, opaque construction
permit rather than treating the accepted capacity-v1 permit as authorization.
That construction permit binds the unique post-initialize effective C2S/S2C
literal and scaling digests, generator/encoder precision `256/256`, builder and
streaming-binary-digest versions, exact allocation/release schedule, private
artifact-manifest digest and the accepted capacity-plan/permit digests. The
provider installs only privately owned factors and never constructs the stock
53-bit matrices first. On the accepted L11 estimate, a duplicate default pair
adds 2,641,362,944 B, exceeding the 2,585,547,267 B margin even before further
scratch; this path is deterministically rejected before allocation.

The dry-run policy is:

```text
currentSystemUsed
+ projectedIncrementalPeak
+ max(512 MiB, floor(projectedIncrementalPeak / 10))
<= floor(totalPhysical * 4 / 5)
```

The versioned v1 policy defines the relative guard with integer-floor
division and requires the final sum to be strictly below the floored 80%
limit. Every multiplication and addition in the estimate uses checked `uint64`
arithmetic. An invalid memory snapshot, overflow, stale or foreign permit, or
failure of the inequality returns typed `ErrArtifactCapacityBlocked` before
creating an encoder, transform, key, evaluator or ciphertext. The permit binds
the exact parameter/profile digest, artifact shapes, formula version, policy
and memory snapshot. Passing this dry-run gate establishes resource admission
only; it does not promote `parameter_candidate_unverified` or establish a
secure circuit.

The accepted unblock design is recorded in
`research/phase3_design/secure_n16_capacity_unblock_route.md`. It keeps the
8,192-word profile as the source-faithful target, uses a separately versioned
`LogSlots=11`/512-word sparse-packing adaptation for the first encrypted
vertical gate, and requires both factor streaming and lazy disk-backed
evaluation keys before returning to the full-packed target.

## Stop conditions

- If full-slot transform construction or key generation crosses 80% physical
  memory, emit a resource-blocked artifact and redesign packing before running
  encryption.
- If MR0 does not produce the required raw scale/level state, keep the result
  as a Lattigo adaptation and derive a corrected scale schedule; do not retag
  the functional MR15 profile.
- If the sparse switching-key graph cannot be represented by the accepted
  evaluator wrappers, add a secure-only evaluator graph. Do not disable
  `h=32` to make the test pass.
- If finite sample and evaluation-key exposure accounting is incomplete, the
  profile remains `secure_profile_unverified` even when every ciphertext
  decrypts correctly.
- No latency result enters a secure comparison table until the exact circuit
  profile, manifest, key inventory and estimator record mutually authenticate.
