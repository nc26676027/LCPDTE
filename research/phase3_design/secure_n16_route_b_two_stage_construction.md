# Secure N16 Route-B Two-Stage Construction Contract

**Date:** 2026-08-30  
**Status:** design repair v4 accepted; implementation pending  
**Scope:** `LogN=16`, `LogSlots=11`, 512-word R1 packing adaptation only

## Decision

This document is a normative target contract. Every API, trace and counter below
is a required implementation seam unless an acceptance item explicitly records
it as already present; none is a claim that the current stock bootstrap path
already provides the seam.

Route B uses two authorization boundaries. A payload-free build permit
authorizes the first deterministic factor construction. The resulting observed
receipt then supplies the numeric and encoded payload identities required by a
separate readiness permit. Keys, evaluator installation and MR0 remain
unreachable until the readiness permit validates.

```text
AuthorizeBuild [fresh Authority-owned sample -> pure PrepareParameters]
  -> ArtifactBuildSpec -> live ArtifactBuildPermit
BeginBuild [new trusted sample -> pure PrepareParameters -> authorized/building CAS]
  -> STC factorwise build -> drop generator-scratch references
  -> CTS factorwise build -> drop generator-scratch references
  -> seal private artifact -> drop encoder reference
  -> BuildReceipt + private uninstalled artifact
AuthorizeReady [new trusted sample -> pure PrepareParameters -> readying CAS]
  -> resident validation -> ReadySpec -> live ReadyPermit
Install [new trusted sample -> pure PrepareParameters -> installing CAS]
  -> admitted key generation
  -> consume artifact and keys into private evaluator
First-operation [new trusted sample -> preflighting CAS]
  -> resident payload/runtime preflight
  -> sparse MR0
```

This state machine removes the first-build cycle in the earlier construction
contract. Actual payload digests are outputs of construction and therefore do
not appear in `ArtifactBuildSpec` or `ArtifactBuildPermit`. Placeholder,
self-chosen or fixture-only payload digests cannot authorize installation.

The existing `GaoN16RouteBConstructionSpec/Permit` remains historical
post-artifact consistency evidence only. Its frozen fixture margin makes it
non-authoritative for every live gate until migrated to the trusted dynamic
capacity contract. It cannot be converted into the new live Build or Ready
capabilities, and every exposed live seam must reject it.

## Evidence labels

| Object | Authorizes | Excludes |
|---|---|---|
| Capacity permit | bounded host allocation plan and the small pure `PrepareParameters` call | encoder, factors, keys, HE |
| Build permit | one 256-bit encoder and factorwise STC->CTS construction from the sealed prepared value | keys, evaluator installation, ciphertext, HE |
| Build receipt | observed lifecycle and actual payload identity | correctness, RSS acceptance, security |
| Ready permit | admitted key generation followed by private artifact/key installation | MR0 success until runtime preflight passes |
| MR0 evidence | one exact sparse refresh execution | full Gao packing, application security, tree speed |

No Route-B object is source-faithful or full-packed. Those labels remain
reserved for the `LogSlots=15`, 8,192-word Route-A target.

## Pure preparation

`bootstrapping.PrepareParameters(raw)` is the single raw-to-effective
preparation implementation. It constructs no encoder, DFT matrix, key,
evaluator or ciphertext. It deep-copies mutable `Levels`, `Scaling` and
iteration fields and preserves the input byte-for-byte.

The function performs, in the current vendor order:

1. the Standard/ConjugateInvariant branch, including the exact S2C scaling
   override `0.5` for ConjugateInvariant parameters;
2. Mod1 type, degree and circuit-order level checks;
3. `mod1.NewParametersFromLiteral`;
4. `qDiv = ScalingFactor / 2^round(log2(Q0))`, clamped to at most one;
5. `C2Sbase = qDiv / (K*qDiff)`;
6. `S2Cbase = DefaultScale / (ScalingFactor/MessageRatio)`;
7. nil-scaling replacement or the same ordered `big.Float` multiplication used
   by the existing constructor.

The prepared value seals raw and effective C2S/S2C literals and scalings,
derived Mod1 execution parameters, circuit order and parameter digest. Stock
and prebuilt evaluator paths consume this same value.

The role mapping is fixed and is not inferred from abbreviations:

| Receipt role | Lattigo field | DFT type | Installed field | Factors / diagonal counts | Start level |
|---|---|---|---|---|---:|
| STC/S2C | `SlotsToCoeffsParameters` | `HomomorphicDecode` | `S2CDFTMatrix` | `2 / [63,64]` | Q18/P6 |
| CTS/C2S | `CoeffsToSlotsParameters` | `HomomorphicEncode` | `C2SDFTMatrix` | `3 / [16,31,15]` | Q20/P6 |

Both effective literals use `SplitRealAndImag`, `LogSlots=11`,
`LogBSGSRatio=0` and the exact level vectors `[1,1]` and `[1,1,1]`. Route B
does not inherit the stock `RepackImagAsReal` default.

## ArtifactBuildSpec and ArtifactBuildPermit

The build specification binds only facts knowable before allocation:

- exact capacity plan, Authority-generated mint snapshot/report/permit and
  peak-contract digests;
- parameter and `LogSlots=11` packing-profile digests;
- raw and effective C2S/S2C literal and scaling digests;
- generator and encoder precision `256/256`;
- builder ID `lattigo-route-b-prebuilt-dft-streaming-builder-v1`;
- digest ID `sha256-canonical-streaming-binary-v1`;
- allocation ID `stc-then-cts-single-factor-v1`;
- release ID `logical-reference-drop-v1`;
- ownership ID `private-exclusive-transfer-v1`;
- allocation order `STC -> drop STC generator references -> CTS`;
- factor lifecycle and release schedule;
- private exclusive-transfer ownership model;
- zero default, explicit-whole and raw-numeric DFT constructor calls;
- the named streaming-scratch bound below.

It contains no numeric payload, encoded payload, artifact-manifest or receipt
digest. `AuthorizeBuild` obtains an OS sample internally, independently builds
that sample's capacity permit and prepared value, and then mints the opaque
build permit. No live method accepts caller totals, availability, snapshot ID,
report, permit, runtime evidence or sampler. Invalid, stale,
foreign, promoted or resealed values return before the provider, encoder
factory, allocator or factor generator is called.

The full-artifact, pre-guard incremental, guarded-requirement and duplicate-
default byte values are immutable builder bounds. Remaining-below-limit and
duplicate-default excess are dynamic report fields recomputed from each fresh
sample, with `excess=max(2,641,362,944-remaining,0)`. Zero excess is valid and
does not relax the independent default-constructor prohibition. A later gate
validates the anchored mint/Ready record and separately admits its own fresh
runtime sample; it never requires dynamic capacity bytes to equal the fixture,
the mint sample, or another gate.

The production Authority owns the physical-memory adapter, a random 256-bit
secret, a process-local owner cell, a global monotonic generation and the
sampling mutex. The adapter returns raw total/available physical bytes only;
inside one private critical section Authority reserves a generation, samples,
derives the authenticated snapshot ID, evaluates capacity, seals inert runtime
evidence and destroys the one-shot capability. Capabilities never enter wire
records or escape to callers. One lineage requires a fresh generation greater
than its own previous generation, not global adjacency, so interleaved lineages
remain valid. Only a package-private test constructor may inject scripted raw
totals; no exported constructor or live method accepts a sampler or any
snapshot/report/permit field.

## Observed factor lifecycle

The current public factor callback is insufficient for receipt evidence: it
returns before the vendored generator drops its own factor reference. Route B
therefore has two deliberately separate evidence owners:

- an unexported `integer/secureeval` build state machine owns preparation,
  encoder lifetime, artifact sealing and receipt minting;
- a vendor-owned observed streaming entry point owns each transform's factor
  loop, factor/reference transitions, generator return and constructor count.

The vendor entry point invokes a synchronous, non-retaining factor consumer
owned by the private `secureeval` builder. That consumer streams the numeric
digest, encodes the factor and streams the encoded digest; it returns only the
two fixed-size digests, byte counts and encoded transformation. The vendor
validates the returned role/index/count, appends the corresponding digest
events, then clears its factor reference before appending the drop event. No
numeric factor, map, slice or coefficient pointer can be returned or stored by
the consumer. Code inspection, an alias-retention test and a post-callback
mutation test are mandatory acceptance evidence for this non-retention claim.

The public Route-B API accepts neither an event list nor a factor consumer.
Only the unexported builder can combine the two vendor traces with its own
outer events and mint a receipt. Each vendor trace stores its event slice in an
unexported field and exposes only defensive-copy/read-only accessors plus its
canonical digest; no accessor returns a mutable backing slice. The resulting
total synchronous sequence is:

```text
secureeval: prepare-complete
secureeval: encoder-created(precision=256)
vendor: transform-start(STC)
  factor-generated(i)
  numeric-digested(i)
  factor-encoded(i)
  encoded-digested(i)
  numeric-reference-dropped(i)
vendor: transform-end(STC)
vendor: generator-returned(STC)
vendor: transform-start(CTS)
  ... same five events per factor ...
vendor: transform-end(CTS)
vendor: generator-returned(CTS)
secureeval: artifact-sealed
secureeval: encoder-reference-dropped
```

For the frozen L11 literals, STC has two factors and CTS has three. Exactly one
numeric factor may be logically live. `numeric-reference-dropped` occurs only
after the consumer returned, the vendored loop assigned its factor reference
to nil, and the private consumer retained no numeric alias. `generator-returned`
occurs only after the transform generator has returned and its roots, `pow5`
and layer references are unreachable from the builder. These names assert
logical reference reachability, not physical reclamation; only isolated
process RSS can report allocator/GC high-water behavior. A callback error stops
before the next factor and mints neither a receipt nor an installable artifact.
The failure trace records attempted and completed event prefixes; it cannot
claim zero work once construction has started.

`encoder-reference-dropped` is an outer secureeval event. It occurs only after
both observed calls returned, the factor-consumer closure was cleared, and the
builder assigned its sole encoder variable to nil. The encoder is constructed
inside the private builder and is never supplied by or returned to an API
caller.

The vendored DFT package also exposes a monotonic, process-wide atomic
construction-counter snapshot with four fields: `DefaultWhole`,
`ExplicitWhole`, `RawNumeric` and `ObservedStreaming`.
`NewMatrixFromLiteral` increments `DefaultWhole`; both explicit-precision
constructors that return an ordinary whole matrix, including the existing
public streaming constructor, increment `ExplicitWhole`;
`MatrixLiteral.ForEachMatrixFactor` and `MatrixLiteral.GenMatrices` each
increment `RawNumeric`; and the new trace-producing transform entry point
increments `ObservedStreaming`. Each public entry increments exactly one field
on entry before validation, including a failed call, and calls a private common
core directly. Public entries never call one another, so one external call
cannot double count. Internal helpers do not increment.

The observed entry also calls only that private core; it cannot pass through
either raw-numeric wrapper. The isolated builder process has no concurrent DFT
constructors. Build start/end deltas must be `0/0/0/2`; prebuilt assembly
start/end deltas must be `0/0/0/0`. The receipt derives build deltas from two
vendor snapshots and the private assembly validator derives assembly deltas
from another two. Caller-declared constructor counts are rejecting input.

`RawNumeric` is a capacity-critical prohibition, not only an audit convenience.
Under the same conservative `256 B/complex` ledger, `GenMatrices(STC)` can
retain the first 63-diagonal factor (`33,030,144 B`) while the second factor's
two-map merge phase reaches `70,811,912 B`, for a `103,842,056 B` conservative
phase bound. That exceeds the `81,264,640 B` envelope by `22,577,416 B` before
the separate process guard; it is not an observed-RSS or exact-heap claim.

The construction order is mandatory. Reversing CTS and STC is not covered by
the accepted `2,968,063,744`-byte artifact peak.

## Canonical streaming binary v1

Every record begins with the 16 bytes `LCPDTE-RBDFT-v1\x00`, followed by
one record-type byte and one role byte. Record types are `0x01`
numeric-factor, `0x02` encoded-factor, `0x03` numeric-transform-aggregate,
`0x04` encoded-transform-aggregate, `0x05` artifact-pair-aggregate, `0x06`
lifecycle-trace and `0x07` build-receipt. Roles are `0x01` STC/S2C, `0x02`
CTS/C2S and `0x00` only for pair/lifecycle/receipt records (`0x05..0x07`). Any other type/role or an
invalid combination is rejected. This typed subdomain is included in every
SHA-256 input; the common magic alone is not domain separation.

Unsigned integers use fixed-width little-endian encoding. Signed integers use
two's-complement fixed-width little-endian encoding. Booleans are one byte and
must be zero or one. Strings use a `uint32` byte length followed by UTF-8 bytes
and are limited to 256 bytes. Digests are exactly 32 raw SHA-256 bytes, never
hex text. Counts and byte fields use the widths specified below and are checked
before conversion or allocation.

A finite `big.Float` scalar contains, in order:

```text
precision:uint32 | rounding-mode:uint8 | accuracy:int8 | signbit:uint8
exact-hex-length:uint32 | exact-hex bytes from Append('x', -1)
```

Rounding-mode codes `0..5` map exactly to Go `ToNearestEven`,
`ToNearestAway`, `ToZero`, `AwayFromZero`, `ToNegativeInf` and
`ToPositiveInf`. Accuracy must be `-1`, `0` or `+1`. Precision is `1..256` for
both numeric entries and scales; scale serialization preserves the exact
resident precision inside that range. NaN and infinity are rejected. Exact-hex
is lowercase ASCII from `Append('x', -1)` and is limited to 256 bytes. Parsing
must consume the entire string and reproduce precision, mode, accuracy, sign
and value. The implementation reuses one bounded scalar scratch; it never
retains a factor-wide textual or binary copy. A complex value is the real
scalar followed by the imaginary scalar.

A numeric-factor record is:

```text
magic | type=0x01 | role | factor-index:uint32 | factor-count:uint32
generator-precision:uint32 | diagonal-count:uint32
for each numerically sorted diagonal:
  index:int64 | vector-length:uint32
  vector-length times: real-scalar | imaginary-scalar
```

The only admitted counts are STC `2/[63,64]` and CTS `3/[16,31,15]`; every
vector length is exactly `2048`. Factor indexes are zero-based and contiguous.
The record decoder rejects a count before allocating if it differs from these
role-specific constants, and checks every multiplication/addition used to
derive a byte bound for `uint32`, `uint64` and host `int` overflow.

An effective MatrixLiteral record is embedded in every encoded factor in this
exact order:

```text
type:uint8 | log-slots:int32 | level-q:int32 | level-p:int32
levels-count:uint32 | each level:int32
format:uint8 | scaling-present:uint8 | [scaling scalar]
bit-reversed:uint8 | log-bsgs-ratio:int32
```

The type byte is the vendored enum value `0` for CTS/HomomorphicEncode and `1`
for STC/HomomorphicDecode and must agree with the outer role. The format byte is
exactly `1` (`SplitRealAndImag`), `log-slots=11`, `scaling-present=1`,
`bit-reversed=0`, `log-bsgs-ratio=0`; Levels and Q/P values are the exact
role-specific values in the mapping table. Other enum values, nil scalings and
trailing Levels are rejected.

An encoded LinearTransformation metadata record follows in this exact order:

```text
scale-mod-present:uint8 | scale-value scalar
log-dimensions-rows:int32 | log-dimensions-cols:int32
is-batched:uint8 | is-bit-reversed:uint8 | is-ntt:uint8
is-montgomery:uint8 | n1:int32 | level-q:int32 | level-p:int32
log-bsgs-ratio:int32
```

`scale-mod-present` must be zero for this CKKS artifact. Rows/Cols are `0/11`;
`is-batched/is-bit-reversed/is-ntt/is-montgomery` are `1/0/1/1`; Q/P and BSGS
match the literal. `n1` and every scale value are observed fields but must equal
an independently recomputed value from the sorted diagonal list, current Q
chain and frozen factorization. No pointer identity or Go map iteration order is
serialized.

An encoded factor record contains:

```text
magic | type=0x02 | role | factor-index:uint32 | factor-count:uint32
encoder-precision:uint32 | effective MatrixLiteral record
LinearTransformation metadata record
diagonal-count:uint32
for each sorted diagonal:
  index:int64 | poly-binary-size:uint64 | ringqp.Poly.WriteTo bytes
```

`Poly.WriteTo` is streamed directly through a bounded buffered hash writer in
its pinned Q-then-P representation. Those bytes include, for each Q/P
`ring.Poly`, an outer limb-count `uint64 LE`, each limb's coefficient-count
`uint64 LE`, then all coefficient `uint64 LE` values. These length words are
part of canonical v1. For every polynomial,
`poly-binary-size == Poly.BinarySize() == WriteTo returned bytes`; short,
long or partial writes fail. At ring degree `N=65,536`, a Q poly with `L` limbs
has `8 + L*(8 + 8*N)` bytes. STC has 19 Q limbs and 7 P limbs, hence every STC
`ringqp.Poly` is exactly `13,631,712` bytes; CTS has 21 Q limbs and 7 P limbs,
hence every CTS polynomial is exactly `14,680,304` bytes. Q/P levels, ring
degree, admitted diagonal counts and those exact sizes are checked before the
write. No whole-factor `MarshalBinary`, JSON, hex dump or `strings.Builder` is
allowed.

A transform aggregate has the exact grammar:

```text
magic | type=0x03 numeric or 0x04 encoded | nonzero role
factor-count:uint32
for each contiguous factor:
  index:uint32 | factor-digest:32 bytes | factor-record-bytes:uint64
aggregate-record-bytes:uint64
```

The total is checked against the sum of factor record bytes plus the fixed
aggregate framing. The pair aggregate has the exact grammar:

```text
magic | type=0x05 | role=0 | build-permit-digest
stc-numeric-digest | stc-numeric-record-bytes:uint64
stc-encoded-digest | stc-encoded-record-bytes:uint64
cts-numeric-digest | cts-numeric-record-bytes:uint64
cts-encoded-digest | cts-encoded-record-bytes:uint64
```

`artifact-manifest-digest` is exactly SHA-256 of this pair-aggregate record;
there is no second implicit or platform-dependent manifest encoding.

The lifecycle record uses type `0x06`, role zero and:

```text
terminal-status:uint8 | completed-event-count:uint32
attempted-event-lower-bound:uint32 | failure-stage:uint8
then completed-event-count events, each:
  sequence:uint32 | source:uint8 | code:uint8 | role:uint8
  factor-index:int32 | payload-kind:uint8 | payload-digest:32 bytes
  value:uint64
```

Status is `1` success or `2` failure. On success the attempted lower bound
equals the completed count and failure stage is zero. On failure it is at least
the completed count and additionally counts a synchronous event dispatch that
started but did not complete; it is explicitly a lower bound, not a count of
nested encoder primitives. Failure-stage codes are `0` none, `1` prepare, `2`
encoder, `3` STC factor, `4` STC return, `5` CTS factor, `6` CTS return, `7`
seal and `8` encoder drop. Event source is `1` secureeval or `2` vendor. Absent factor/digest/value fields use exactly
`-1`, kind zero, 32 zero bytes and zero.
Event codes are `0x01` prepare-complete, `0x02` encoder-created, `0x03`
transform-start, `0x04` factor-generated, `0x05` numeric-digested, `0x06`
factor-encoded, `0x07` encoded-digested, `0x08`
numeric-reference-dropped, `0x09` transform-end, `0x0a`
generator-returned, `0x0b` artifact-sealed and `0x0c`
encoder-reference-dropped. Payload kinds are zero/none, `0x01`
numeric-factor digest, `0x02` encoded-factor digest, `0x03` artifact-pair
digest and `0x04` precision. Digest events carry their exact digest and record
byte count in `value`; encoder-created carries kind `0x04`, a zero digest and
value `256`; all other events carry kind/value zero. Role and factor-index
constraints follow the event: transform/factor events require role STC or CTS,
factor events require the exact contiguous index, and process-wide events use
role zero/index `-1`. Prepare, encoder, artifact-seal and encoder-drop events
require source secureeval; every transform/factor/generator event requires
source vendor. A success lifecycle has exactly 35 events: four secureeval
events, thirteen STC events and eighteen CTS events.

The build-receipt record uses type `0x07`, role zero and this exact order:

```text
build-permit-digest | prepared-parameter-digest
builder-id | digest-id | allocation-id | release-id | ownership-id
generator-precision:uint32 | encoder-precision:uint32
default-counter-delta:uint64 | explicit-whole-counter-delta:uint64
raw-numeric-counter-delta:uint64
observed-streaming-counter-delta:uint64
lifecycle-digest | max-live-numeric:uint32
stc-factor-count:uint32 | cts-factor-count:uint32
stc-numeric-aggregate | stc-encoded-aggregate
cts-numeric-aggregate | cts-encoded-aggregate
stc-numeric-bytes:uint64 | stc-encoded-bytes:uint64
cts-numeric-bytes:uint64 | cts-encoded-bytes:uint64
build-wall-nanoseconds:uint64 | build-peak-rss-bytes:uint64
artifact-state string | artifact-manifest-digest
```

String identifiers use the bounded string grammar and every named digest is 32
raw bytes. The four receipt byte fields equal the corresponding
`aggregate-record-bytes` values, not an estimate of resident Go heap size. The
artifact-state string is exactly `private-uninstalled`. The receipt digest is SHA-256 over this record and is stored outside
the record to avoid a self-reference. Reordering, omission, duplication,
truncation, precision drift and a one-coefficient mutation must change the
receipt.

## BuildReceipt

The immutable success receipt requires lifecycle status one and binds:

- build-permit and prepared-parameter digests;
- all declared builder/digest/allocation/release/ownership identifiers;
- observed generator and encoder precision;
- vendor counter deltas `default=0`, `explicit-whole=0`, `raw-numeric=0`,
  `observed-streaming=2`;
- ordered lifecycle-event digest and factor counts;
- maximum logically live numeric factors, fixed to one, and all five
  `numeric-reference-dropped` events;
- named STC and CTS numeric per-factor/aggregate digests;
- named STC and CTS encoded per-factor/aggregate digests;
- observed numeric and encoded byte counts;
- build wall time and separately measured peak RSS, neither substituted for
  the derived capacity bound;
- artifact state `private-uninstalled`.

The receipt contains identities, not public matrix references. It is minted
inside `integer/secureeval` only from the private artifact builder, the
vendor-owned value trace and the canonical digest sinks. There is no public
constructor accepting caller event arrays, live counts or constructor deltas.
It is minted only after all factors, reference-drop events and digests complete.

## ReadySpec, ReadyPermit and ownership

`AuthorizeReady` accepts the unique live build permit, receipt and private
artifact from the same lineage. It first admits a newly sampled capacity value
and repeats stored-raw preparation, validates the anchored mint/build evidence,
then lets only the `private-uninstalled -> readying` CAS winner stream the
resident artifact. That winner validates receipt grammar, lifecycle, payload
digests and byte ledger, writes the Ready anchors and publishes `ready`.
`ReadyPermit` binds `BuildPermitDigest`, `BuildReceiptDigest` and the final
artifact manifest. Its CurrentCapacity block describes the ready-time sample;
it need not equal the Build permit's mint-time block.

The project-level `integer/secureeval` package owns the only artifact handle.
Its matrices and underlying bootstrap evaluator are never returned. Install
consumes the artifact, moves it into a private wrapper and marks the original
handle consumed; reuse fails. The opaque handle contains an unexported pointer
to one atomic ownership cell, so copying the Go handle value cannot duplicate
the right to consume it. Deep-copying the approximately 2.64-GB encoded pair is
forbidden by the capacity contract.

Installation and the first HE operation recompute encoded payload digests by
streaming the resident polynomial coefficients. A mutation between build and
execution fails before HE. The consumed handle, resident matrix slices and
underlying polynomial buffers are not returned by any public accessor.

## Named streaming scratch ledger

The accepted capacity-v1 bound remains unchanged and conservative. The
construction receipt names the live generator components that fit inside its
artifact envelope:

| Component | Bound |
|---|---:|
| roots (`8,193 * 256`) | 2,097,408 B |
| `pow5` (`4,097 * 8`) | 32,776 B |
| one `a/b/c` layer (`3 * 2,048 * 256`) | 1,572,864 B |
| largest STC numeric factor (`64 * 2,048 * 256`) | 33,554,432 B |
| largest CTS numeric factor (`31 * 2,048 * 256`) | 16,252,928 B |
| accepted artifact-envelope margin | 81,264,640 B |

The merge helper allocates its replacement map before dropping the previous
map. The phase bound therefore charges two largest factors, not one; this is a
memory upper bound even when the old map has fewer diagonals:

```text
STC = 2,097,408 + 32,776 + 1,572,864 + 2*33,554,432
    = 70,811,912 B
CTS = 2,097,408 + 32,776 + 1,572,864 + 2*16,252,928
    = 36,208,904 B
max = 70,811,912 B < 81,264,640 B
remaining envelope = 10,452,728 B
```

Container headers, allocator slabs and GC high-water behavior are not hidden
inside these coefficient-payload formulas; they are covered conservatively by
the separate `712,986,188`-byte global guard and are reported by measured RSS.
The `440,926,208`-byte fixed-buffer reservation is a phase maximum: during
construction it covers the one 256-bit encoder/encoding buffers; after the
`encoder-reference-dropped` event it is reused by the evaluator. Encoder and
installed evaluator references may not coexist. Before key generation, install
admits a fresh Authority-owned sample and its newly derived remaining margin;
that margin may differ from mint, build-use and ready-time values. Measured
build, post-keygen and MR0 peak RSS values are separate
observations and cannot replace the derived bounds.

## Prebuilt evaluator assembly

The vendor assembler receives a prepared value and the two already encoded
matrices through a consume-on-call move carrier, plus a consume-on-call key
donor. The stock path and prebuilt path share ring/domain switching, x-power
tables, key checks and CKKS/DFT/Mod1 evaluator assembly. The prebuilt path never
calls a matrix or numeric-factor constructor. The isolated child requires the
previously recorded encoder-drop event and no live encoder reference. Before an
install attempt touches the artifact, Authority obtains and admits a fresh OS
sample, repeats stored-raw preparation, and validates the live Ready record and
private anchors. The first artifact-state action is then the owner-bound atomic
`ready -> installing` CAS on the original lineage/artifact cell. Only the
winner may read or stream the resident artifact. While it holds that exclusive
state, it records install-time runtime-capacity evidence, re-streams the
resident encoded payload, generates exactly the admitted keys, moves matrices directly from the same
artifact cell into the carrier, and calls the assembler with the prepared
value, consumed artifact carrier and key donor. The assembler verifies keys
before returning the installed wrapper. Its vendor
construction-counter start/end delta must be `0/0/0/0`; a nonzero delta in any
counter fails without returning a wrapper. The vendor assembler itself
verifies:

- C2S and S2C roles are not swapped;
- each matrix literal equals the prepared effective literal;
- exact factor count, starting `LevelQ`, scale schedule, dimensions, BSGS and
  sorted diagonal topology;
- evaluation-key inventory before returning an installed wrapper.

Generator/encoder precision and resident encoded-payload identity are not
self-authenticating properties of a bare `dft.Matrix`. After the winning
`ready -> installing` CAS and immediately before the move carrier is created,
the owner-bound `integer/secureeval` install gate must therefore revalidate the
complete observed trace and its private
write-once anchors, require the recorded generator/encoder precision to be
exactly `256/256`, stream the resident coefficients with the canonical
`RBDFT-v1` encoder, and compare the recomputed encoded aggregate tuples and
pair manifest with the receipt/lineage anchors. The vendor carrier and
assembler may repeat digest computations as a consistency check, but no
exported constructor argument, caller-selected digest, carrier seal or bare
`Matrix.ValidateAgainst` result is authorization evidence. Only the live
owner-bound Ready lineage can authorize the project wrapper to call this
otherwise general vendor API.

The move carrier contains one unexported shared ownership cell. It can be
created only by moving matrices directly out of the already-exclusive artifact
cell; creating it zeros both source matrix values. Every shallow carrier copy
observes the same terminal CAS. The assembler also receives the generated key
pointer through a donor reference, takes it and nils the donor before key or
matrix validation. Assembly consumes and clears the matrix carrier on both
success and failure. An outermost deferred finalizer covers ordinary errors and
panics. On every failed or panicking assembly, the result is nil, the carrier is
terminal and empty, the key donor is nil, no partially initialized evaluator is
returned, the lineage advances to terminal `failed`, and Ready cannot be
retried. On success, both source matrices are zero, the carrier and key donor
are terminal, the lineage advances to `installed-unverified`, and exactly one
private wrapper owns the evaluator and keys. Thus the uninstalled artifact,
carrier and installed evaluator cannot coexist as independently usable owners.
This is a logical move guarantee for the private audited caller, not a general
proof that arbitrary Go code did not copy a matrix or key before handoff.

The first-operation attempt obtains and admits yet another fresh sample before
its `installed-unverified -> preflighting` CAS. Only the winner records
preflight capacity evidence, re-streams the encoded matrices resident in the
installed private wrapper and compares the same anchored tuples before any HE
dispatch. A loser performs no resident read or HE operation. The install-time
stream cannot substitute for this second check.

All encoded factors retain the existing Lattigo invariant that the
`LinearTransformation.LevelQ` metadata equals the literal's starting
`LevelQ`; only the per-factor scale uses the decreasing local level.

## Sparse L11 execution boundary

The private wrapper exposes typed operations, not its mutable vendor objects.
Its immutable sparse-execution profile records expected fields, while the
first-operation receipt records the independently observed fields:

```text
LogN=16
LogSlots=11
ExpectedTraceGap=16
ExpectedTraceRotationExponents=[2048,4096,8192,16384]
ExpectedTraceGaloisElements=[65537,98305,114689,122881]
ObservedTraceGap=16
ObservedTraceRotationExponents=[2048,4096,8192,16384]
ObservedTraceGaloisElements=[65537,98305,114689,122881]
ExpectedCTImagNil=true
ObservedCTImagNil=true after CoeffsToSlots and before typed A2B kernel dispatch
packing capacity=512 eight-bit words
ExpectedPackingLayoutDigest=8A4F785EAABA8D1DD9EC453DC1D3FCB34AD8C1FD9B3B9BB03CF1AD8D756607B0
ObservedPackingLayoutDigest=<independently recomputed 32-byte digest>
ExpectedEvaluationKeyInventory=the exact list below
ObservedEvaluationKeyInventory=<sorted installed inventory>
```

The expected key inventory contains one relinearization key, the two named
ring-switching keys `dense-to-sparse` and `sparse-to-dense`, and exactly these
38 sorted Galois elements (the final value is conjugation):

```text
[5,25,125,625,3125,5729,7937,15625,27649,28609,31745,37249,
 41473,49409,59393,60833,60961,61313,63489,65537,77185,77953,
 78125,81409,89345,89745,91137,95233,98305,98369,102017,113153,
 114689,117889,122881,126977,128481,131071]
```

Missing, duplicate or extra keys fail; set containment is insufficient.

Packing layout v1 hashes the ASCII magic `LCPDTE-RBLAYOUT-v1\x00`, followed
by `LogN=16`, `LogSlots=11`, `slots=2048`, `wordBits=8`,
`wordCapacity=512`, `ciphertextHalves=2` and `slotsPerWordPerHalf=4` as
`uint32 LE`. For every word `j=0..511` and `k=0..3`, it then writes two mapping
records in word-major order:

```text
word:j | bit:k   | ciphertext-half:0 | slot:4*j+k | component:real
word:j | bit:k+4 | ciphertext-half:1 | slot:4*j+k | component:real
```

Every mapping field is `uint32 LE`; component real is code zero. The resulting
canonical byte string is exactly `81,967` bytes and its SHA-256 is the expected
digest shown above. Imaginary
components are required to be exact zero at encoding admission. The expected
digest is computed once from this formula and sealed in the profile; the
adapter independently enumerates its actual placements to produce the
observed digest.

This layout describes the two Boolean ciphertext halves emitted by the
special-`b0`/A2B boundary and consumed by the integer ALU. It does not relabel
the pre-A2B arithmetic ciphertext as eight already separated bit planes.

The wrapper consumes a vendor-owned observed ModUp/Trace report that records
the physical Galois elements actually dispatched; a list re-derived from
parameters is not runtime evidence. It records `ObservedCTImagNil` from the
real C2S return tuple, not from the expected profile. Any changed gap, non-nil
imaginary output, key-list mismatch or word-layout change fails before the A2B
degree-46/R2 kernel continues. Passing this gate is R1 sparse-packing
engineering evidence, not the full-packed Gao result.

## Acceptance sequence

1. Accept the trusted physical-memory sampler, static/dynamic peak split,
   non-adjacent generation interleaving, five fresh-sample gates, two-stage
   permits and receipt types with zero-allocation mutation matrices.
2. Accept pure preparation against an independent legacy reference.
3. Accept factorwise numeric and encoded construction against the independent
   all-at-once 256-bit reference, including shuffled-map determinism.
4. Accept the vendor-owned lifecycle/counter hook and the prebuilt evaluator
   assembler with build counter delta `0/0/0/2` and assembly delta `0/0/0/0`.
   Direct calls to `ForEachMatrixFactor` and `GenMatrices` must each produce
   exactly `0/0/1/0`, not a nested double count; injecting either into the
   admitted builder must fail without a receipt or artifact.
5. Accept the opaque small-profile build/receipt/install path and mutation
   matrix.
6. Start one isolated child with no concurrent DFT constructors. In that same
   child and without returning the artifact, run capacity/prepare/build,
   artifact seal, encoder-reference drop, receipt, ReadyPermit, fresh capacity
   admission at every live gate, admitted key generation, prebuilt assembly/install, first-operation
   payload/runtime preflight, sparse MR0 and the special-`b0`/A2B kernel.
7. Return only canonical receipt/result records, per-stage RSS samples and the
   process peak RSS to the parent. The child then exits and destroys its private
   artifact/evaluator. There is no disk artifact in v1 and no second L11 build.

## Stop conditions

- A payload digest is required before the build that creates it.
- Any build stage runs before current capacity and build permits revalidate.
- Any exported live method accepts caller-supplied memory totals, snapshot ID,
  generation, sampler, capacity report/permit or runtime evidence; an internal
  one-shot sample capability escapes; or production exposes the test sampler.
- Any dynamic remaining/excess value is required to equal the audit fixture or
  a previous gate, zero duplicate excess is rejected, a sample is reused, or a
  lineage requires globally adjacent generations.
- The default 53-bit matrix constructor is called.
- Factor events are out of order, more than one numeric factor is live, or
  STC generator scratch survives into CTS construction.
- A release event is caller-declared, precedes the vendor reference drop, or
  is described as proof of physical reclamation.
- Vendor build deltas differ from default/explicit/raw-numeric/observed
  `0/0/0/2`, or prebuilt assembly differs from `0/0/0/0`.
- Map traversal, pointer aliasing or bit reversal makes repeated factor output
  non-deterministic.
- A whole-factor serialization or text copy exceeds the bounded writer model.
- Caller-controlled aliases survive artifact sealing or installation.
- The `private-uninstalled -> ready` publication has no exclusive `readying`
  winner that writes Ready anchors before publishing success.
- Ready validation, resident-payload preflight, gap-16 evidence or
  `ctImag=nil` evidence is missing.
- Expected and observed sparse-layout, Trace, key or `ctImag` fields are
  conflated rather than compared.
- Stock `ModUp` is used without an observed actual Trace-dispatch prefix, or
  any stock Bootstrap/Evaluate/EvalMod-family path dispatches the resident
  degree-3 compatibility polynomial.
- A2B and A2A-e kernel identities are cross-wired: Route-B A2B requires the
  degree-46/R2 exponential path, while degree-32/R3 belongs only to A2A-e.
- The guarded or measured construction exceeds the accepted host limit.
- The isolated child exits after build but before Ready/install/MR0, or a
  receipt is treated as if it could reconstruct the in-memory artifact.
- Any L11 result is described as full-packed, source-faithful or sufficient
  for application security.
