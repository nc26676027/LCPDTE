# Secure LogN=16 capacity-unblock route

> **2026-08-30 construction-order amendment.** The artifact-bound zero-HE
> object described below is a post-artifact readiness contract, not the permit
> for a first build: actual payload digests cannot exist before that build.
> The authoritative executable state machine is now
> [`secure_n16_route_b_two_stage_construction.md`](secure_n16_route_b_two_stage_construction.md):
> capacity evidence authorizes a payload-free BuildPermit; construction emits
> an observed BuildReceipt; only then can the payload-bound ReadyPermit be
> minted. Earlier capacity numbers and stop conditions are unchanged.

Date: 2026-08-30  
Stage: ARS Stage 2  
Status: `LogSlots=11` no-artifact profile/capacity admission independently
accepted; encrypted sparse-packing execution and full-packed Route A pending  
Scope: capacity derivation and dry-run admission; no DFT, key, evaluator,
ciphertext, or security promotion

## Decision

The exact Gao-compatible `LogN=16`, `LogSlots=15`, 8,192-word profile remains
the source-faithful target. It cannot be constructed safely on the present
31.3-GiB host with the current all-at-once Lattigo builders. The first
encrypted secure-profile vertical gate will therefore use a separately
versioned `LogSlots=11` packing adaptation with 512 eight-bit words. This gate
tests the secure parameter chain, sparse packing, Trace, MR0 refresh and Gao
integer kernel; it is an R1 Lattigo packing experiment, not the paper's
full-packed throughput reproduction.

The final 8,192-word target requires both transform-factor streaming and a
digest-sealed lazy evaluation-key store. Streaming matrices while keeping all
rotation keys resident is still resource-blocked.

## Frozen host boundary

The explicit audit snapshot is:

| Quantity | Bytes |
|---|---:|
| Physical memory | 33,617,782,768 |
| Current system use | 16,465,830,871 |
| Floored 80% limit | 26,894,226,214 |
| Headroom to the limit | 10,428,395,343 |

Every implementation gate must use an explicit snapshot and the accepted
checked-arithmetic capacity policy. No OS probe or HE constructor belongs to
the dry-run admission path.

## Route A: source-faithful 8,192-word target

At `LogSlots=15`, the largest single STC factor has 256 diagonals and requires
3,489,660,928 encoded bytes. A factor-at-a-time construction bound, including
the non-DFT base, high-precision plaintexts, generator tables and encode
pointer buffer, is 6,578,262,024 bytes. This is feasible in isolation.

The online key inventory remains the blocker. An uncompressed Q21/P7
evaluation key is bounded at 88,080,384 bytes. The 71 DFT rotations plus
conjugation, relinearization and dense/sparse switching keys require at least
6,606,028,800 bytes before evaluator buffers (440,926,208 bytes), pre-rotated
ciphertexts (408,944,640 bytes), live ciphertexts, allocator slack and the
loaded transform factor. Consequently, source-faithful execution requires:

1. an isolated builder process that generates one factor, writes it to a
   canonical binary store and exits;
2. a digest-sealed factor manifest and factor-at-a-time evaluator;
3. a disk-backed lazy `EvaluationKeySet` that loads only the active key;
4. a joint capacity plan covering DFT, relinearization, dense-to-sparse and
   sparse-to-dense keys; and
5. small-profile exact differentials against the existing all-at-once
   generator before the streaming path is admitted.

Lattigo's public `EvaluationKeySet` interface is sufficient for lazy key
loading. Source-faithful factor-at-a-time generation needs a vendored callback
or iterator because the public `GenMatrices` API returns all factors. Copying
the private generator into project code would create a second algorithm and is
not the preferred route.

## Route B: reduced-packing vertical gates

The parameter sequence `N/Q/P/S43/H192/h32` is held fixed while only
`LogSlots`, word capacity, DFT schedules, Trace and key inventory change.

| LogSlots | Words | Full artifact peak | Required guarded bytes | Decision |
|---:|---:|---:|---:|---|
| 14 | 4,096 | 9,614,806,784 | 17,262,165,324 | block |
| 13 | 2,048 | 5,650,992,896 | 12,223,751,091 | block |
| 12 | 1,024 | 4,217,491,200 | 9,968,680,268 | pass with only 459,715,075 margin |
| 11 | 512 | 2,968,063,744 | 7,842,848,076 | first gate; 2,585,547,267 margin |

For `LogSlots=11`, the sparse/dense gap is 16 and Lattigo Trace requires the
four actual rotation inputs `[2048,4096,8192,16384]` (the automorphism keys are
derived from these rotations, not from normalized offsets `[1,2,4,8]`). Sparse
CTS may legitimately return `ctImag=nil`. These states need
a secure-only packing adapter: the accepted small functional refresh must keep
its `gap=1` and distinct-imaginary contracts unchanged.

The `LogSlots=11` pre-guard total is fully decomposed as follows:

| Component | Formula | Bytes |
|---|---|---:|
| Full artifact construction peak | reduced-packing DFT plan | 2,968,063,744 |
| DFT/Trace/conjugation keys | `38 * 88,080,384` | 3,347,054,592 |
| Relinearization and dense/sparse keys | `3 * 88,080,384` | 264,241,152 |
| Evaluator fixed buffers | Q21/P7 bound | 440,926,208 |
| Maximum-factor baby-step ciphertexts | `4 * 2 * 65,536 * 8 * (19+7)` | 109,051,904 |
| Ring coefficient scratch | `65,536 * 8` | 524,288 |
| Pre-guard incremental total | sum above | 7,129,861,888 |
| Relative guard | `floor(7,129,861,888 / 10)` | 712,986,188 |
| Guarded requirement | pre-guard plus guard | 7,842,848,076 |

Here the 38-key count is the exact deduplicated union for the existing
`SplitRealAndImag`, `LogBSGSRatio=0` mathematical literals: two-level
HomomorphicDecode STC, three-level HomomorphicEncode CTS, four Trace rotations
and conjugation. It excludes the three fixed relinearization and dense/sparse
switching keys, which are accounted separately. The sorted union is:

```text
[5,25,125,625,3125,5729,7937,15625,27649,28609,31745,37249,
 41473,49409,59393,60833,60961,61313,63489,65537,77185,77953,
 78125,81409,89345,89745,91137,95233,98305,98369,102017,113153,
 114689,117889,122881,126977,128481,131071]
```

The final element is conjugation. `RepackImagAsReal` changes the union to 45
keys and is not silently interchangeable with this route. The deterministic
derivation is retained in `research/scripts/derive_secure_l11_galois.go`; it
constructs no DFT matrix or HE key.

The reduced-packing profile gets new parameter/profile, DFT literal/numeric/
encoded-payload, key-schedule, Trace-schedule and capacity-plan digests. Only
packing-independent polynomial evidence may retain its digest. Results must
be labelled `Lattigo packing adaptation / R1`; they cannot be reported as the
8,192-word Gao source-faithful reproduction.

## Precision-preserving construction gate

The stock Lattigo bootstrap constructor is not an admissible shortcut for the
encrypted Route-B gate. In the pinned vendor code,
`bootstrapping.(*Evaluator).initialize` calls `ckks.NewEncoder(params)` without
an explicit precision, and `ckks.Parameters.EncodingPrecision()` is only 53
bits when the default scale is `2^43`. `dft.NewMatrixFromLiteral` consequently
generates and encodes the DFT factors at that default precision. This differs
from both the already accepted high-precision functional-matrix discipline and
the upstream ALU's fixed high-precision root evidence.

The pinned anchors are
`vendor/github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping/evaluator.go:208`,
`vendor/github.com/tuneinsight/lattigo/v6/schemes/ckks/params.go:187`, and
`vendor/github.com/tuneinsight/lattigo/v6/circuits/ckks/dft/dft.go:169`. The last call passes
`params.EncodingPrecision()` directly to `GenMatrices`, so supplying a
higher-precision encoder only after factor generation cannot repair the
numeric payload.

Route B therefore needs a vendored constructor seam that accepts
capacity-admitted, prebuilt DFT factors generated and encoded at an explicitly
sealed precision. The first implementation uses the existing 256-bit local
matrix path; any later reduction in precision requires a new differential
gate. The seam must not construct the stock 53-bit matrices and then replace
them, because retaining both copies invalidates the accepted peak-memory plan.

The bundle is keyed to the **effective** DFT literals produced after bootstrap
preparation, not directly to the caller's raw literals. The preparation step
must reproduce the scaling changes applied by
`bootstrapping.(*Evaluator).initialize` before matrix generation. The artifact
record stores separate raw-literal and effective-literal digests for both C2S
and S2C, including their effective scaling values. A bundle generated from a
raw literal cannot be admitted merely because its precision and self-digest
are correct.

The accepted capacity-v1 permit remains capacity-only evidence and is not
silently reinterpreted. A new opaque Route-B construction specification and
permit must bind the capacity plan/permit digests, parameter and packing-profile
digests, generator and encoder precision (`256/256`), effective-literal
digests, builder/version identifier, canonical streaming-binary digest
identifier, construction/release schedule, artifact-manifest digest and peak
contract. A mismatch fails before an encoder, DFT factor, key, evaluator or
ciphertext is allocated. In particular, the duplicate-default schedule adds
at least 2,641,362,944 bytes to the accepted construction and exceeds the
current 2,585,547,267-byte margin by 55,815,677 bytes.

Prebuilt matrices are owned by the Route-B module. The provider returns an
opaque bundle into private bootstrap state or transfers exclusive ownership;
the runtime must not retain a caller-controlled alias to public
`dft.Matrix.Matrices`. Numeric and encoded payloads are authenticated again at
installation and before the first HE operation.

Before the `LogSlots=11` encrypted result is admitted, a small-profile test
must compare the new builder coefficient-for-coefficient with the existing
all-at-once high-precision generator, bind generator and encoder precision in
the artifact manifest, compare prepared effective literals against the stock
bootstrap preparation, and include a rounding sentinel that distinguishes the
53-bit path from the admitted path. The runtime evaluator must authenticate the
private prebuilt factor identities and payload digests before its first
homomorphic operation. This gate changes no current capacity decision: the accepted
7,842,848,076-byte figure remains a bound for the planned high-precision
construction, not measured RSS and not encrypted-circuit evidence.

## Ordered vertical gates

1. Implement a no-artifact `LogSlots=11` profile and combined capacity plan.
2. Implement the precision-preserving DFT-construction seam, gap-16 Trace and
   sparse-CTS adapter, then run one MR0 refresh plus special-`b0`/A2B kernel
   with frozen raw levels, scales, rotations, key identities, byte ledger and
   independent residue oracle.
3. Attempt `LogSlots=12` only after measured peak RSS leaves a declared safety
   margin above the accepted estimate.
4. Admit `LogSlots=13` only with factor streaming or lazy key storage.
5. Return to `LogSlots=15` only after the streaming generator, factor store and
   lazy key set pass capacity, payload, mutation and source-differential gates.

## Stop conditions

- Combined artifacts, keys, evaluator buffers, declared live ciphertexts and
  guard are not strictly below the floored 80% limit.
- Sparse Trace changes the required MR0 raw scale, level or residue oracle.
- The `ctImag=nil` layout changes the packed word-block semantics.
- Streaming factors differ coefficient-for-coefficient from `GenMatrices` on
  an admissible small profile.
- A factor or key manifest lacks canonical binary payload authentication.
- Raw and effective DFT literal/scaling digests are missing or differ from the
  unique bootstrap preparation result.
- The construction permit does not bind precision, builder, digest algorithm,
  release schedule, artifact manifest and peak contract to the accepted
  capacity permit.
- A provider retains an externally mutable alias to an admitted DFT matrix.
- Any reduced-packing result is described as full-packed or source-faithful.

Passing Route B is functional and engineering evidence for the secure
parameter path. It does not complete Route A, bind finite sample/key exposure,
or establish 128-bit application security.
