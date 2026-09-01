# Secure N16 Route-B authorization wire (`RBAUTH-v1`)

**Date:** 2026-08-30  
**Status:** design repair v4 accepted; implementation pending  
**Scope:** canonical sealing and validation of `ArtifactBuildSpec`,
`ArtifactBuildPermit`, `ReadySpec`, and `ReadyPermit` for the accepted
`LogN=16`, `LogSlots=11` Route-B construction state machine

## Decision and seam

`RBAUTH-v1` is a canonical typed binary grammar separate from
`RBDFT-v1`. It has exactly four top-level record types: build specification,
build permit, ready specification, and ready permit. This document does not
add a record type to `LCPDTE-RBDFT-v1\x00`; the accepted `RBDFT-v1` types
`0x01..0x07` remain numeric factor through build receipt.

The authorization module has a deliberately small live interface. Capacity
inputs are owned by the `Authority`; they are not API parameters:

```text
Authority(stored raw bootstrap parameters, production capacity sampler)
  -> AuthorizeBuild()
  -> generated ArtifactBuildSpec report + live ArtifactBuildPermit

live BuildPermit + live BuildReceipt + live private artifact
  -> AuthorizeReady(...)
  -> generated ReadySpec report + live ReadyPermit
```

`AuthorizeBuild` constructs the capacity snapshot, capacity report, capacity
permit, build specification, and build permit from Authority-owned inputs. It
does not accept caller-provided totals, available bytes, snapshot IDs,
capacity permits, `ArtifactBuildSpec` values, or canonical records. The same
rule applies to `AuthorizeReady`. Callers may serialize or parse the generated
reports for audit, but parsed records remain inert.

Canonical bytes are tamper-evident evidence, not a capability. A live permit
also contains an unexported process-local lineage pointer. The pointer and its
state are never serialized. Consequently, a parser returns an inert report,
never an `ArtifactBuildPermit` or `ReadyPermit` that can cross the live
authorization seam.

The new `integer/secureeval` implementation may reuse only the accepted L11
profile, shape, plan, report, capacity permit, physical-memory snapshot,
capacity policy, prepared parameters, DFT construction counters, and the
accepted scratch/peak arithmetic. The legacy
`GaoN16RouteBArtifactDigests`, `GaoN16RouteBArtifactManifest`,
`GaoN16RouteBConstructionSpec`, `GaoN16RouteBConstructionPermit`, and
`RunAfterValidation` values cannot be converted into, embedded as, or treated
as authorization for this state machine.

The legacy `GaoN16RouteBConstructionSpec`,
`GaoN16RouteBConstructionPermit`, `GaoN16RouteBPeakContract`, and
`RunAfterValidation` implementation is non-authoritative until its frozen
snapshot margin is removed. Its current fixture-only success path cannot mint
or validate a live Route-B capability. Migration must split its immutable
builder bounds from a capacity margin created inside `Evaluate(snapshot)`, put
that dynamic margin in the resulting permit/report, and delete the equality
check against the audit-fixture remaining/excess values. Retaining the legacy
API without this migration requires every live entry point to reject it.

## New domain constants

These constants are new because the accepted two-stage design deliberately
left the authorization wire unfrozen. No new capacity, factor, precision, or
memory number is introduced here.

| Name | Exact value | Reason |
|---|---|---|
| top-level magic | ASCII `LCPDTE-RBAUTH-v1` | Exactly 16 bytes and disjoint from the 16-byte `LCPDTE-RBDFT-v1\x00` magic. `RBAUTH` is six characters, so omitting a terminal NUL preserves a fixed 16-byte magic without abbreviating the domain name. |
| build-spec type | `0x01` | First of four authorization-only top-level types. |
| build-permit type | `0x02` | Separates a value specification from an authorization report. |
| ready-spec type | `0x03` | Payload-bound post-build specification. |
| ready-permit type | `0x04` | Payload-bound live readiness authorization report. |
| literal digest-domain tag | `0x81` | High-bit tag cannot be parsed as a top-level record type. |
| scaling digest-domain tag | `0x82` | Separates a scaling identity from a literal identity. |
| scratch digest-domain tag | `0x83` | Separates the named scratch ledger from all other digests. |
| peak digest-domain tag | `0x84` | Separates the accepted peak contract from all other digests. |
| role STC/S2C | `0x01` | Matches the accepted `RBDFT-v1` role mapping. |
| role CTS/C2S | `0x02` | Matches the accepted `RBDFT-v1` role mapping. |
| phase raw | `0x01` | Prevents a raw/effective digest swap from retaining its identity. |
| phase effective | `0x02` | Prevents a raw/effective digest swap from retaining its identity. |
| construction order | `0x01` | The sole admitted order: STC, drop STC generator references, then CTS. |

The fixed classification strings are:

```text
adaptation-label = "lattigo_packing_adaptation_r1"
build-evidence-scope = "route_b_artifact_build_authorization_only"
ready-evidence-scope = "route_b_artifact_ready_authorization_only"
maturity = "route_b_construction_contract_only_unverified"
source-faithful = false
full-packed = false
```

The two evidence-scope strings are new names needed to prevent a build permit
from being promoted to readiness and either permit from being promoted to an
MR0, full-packed, source-faithful, performance, or application-security
result. The maturity string is the existing Route-B construction-contract
label; reusing it does not make a legacy construction permit valid.

## Primitive canonical framing

Every multi-byte integer is little-endian. Unsigned values use the stated
fixed width. Signed values use fixed-width two's-complement little-endian.
Decoders check every addition, multiplication, `uint64`-to-`uint32`, and
integer-to-host-`int` conversion before allocating or slicing.

- `bool` is one byte and is exactly `0x00` or `0x01`.
- `uint8`, `int8`, `uint32`, `int32`, and `uint64` have widths 1, 1, 4, 4,
  and 8 bytes respectively.
- A string is `byte-length:uint32 | byte-length bytes`. Its byte length is
  `1..256`; bytes must be valid UTF-8. No normalization or case folding is
  performed. The parser enforces this framing only; the typed authorizer later
  requires every frozen identifier to equal its exact ASCII constant.
- A digest is exactly 32 raw SHA-256 bytes, never hexadecimal text. An
  all-zero digest is invalid. Existing lowercase 64-hex capacity digests are
  decoded to 32 bytes at the seam and re-encoded only for human-facing logs.
- A required fixed-count list is `count:uint32 | items`. The count is checked
  against its role-specific constant before allocation. Nil and empty are not
  alternate encodings of a required list.

A nullable finite `big.Float` is:

```text
present:uint8
if present == 1:
  precision:uint32 | rounding-mode:uint8 | accuracy:int8 | signbit:uint8
  exact-hex-length:uint32 | exact-hex bytes from Append('x', -1)
```

`present` is a canonical Boolean. Precision is `1..256`. Rounding codes
`0..5` mean Go `ToNearestEven`, `ToNearestAway`, `ToZero`, `AwayFromZero`,
`ToNegativeInf`, and `ToPositiveInf`. Accuracy is exactly `-1`, `0`, or `+1`.
`signbit` is Boolean and therefore preserves negative zero. The exact-hex
string is non-empty lowercase ASCII, at most 256 bytes, and must be byte-for-
byte equal to a fresh `Append('x', -1)` after parsing at the stated precision
and rounding mode. NaN, infinity, malformed exponents, trailing characters,
metadata/value disagreement, and non-canonical alternative spellings fail.

The raw DFT scaling may encode `present=0` only when the stored raw literal
actually has a nil scaling. Every effective scaling must be present. Nil and a
present numerical zero are distinct identities.

## Seal rule and parser result

Every top-level record has this envelope:

```text
magic:16 | record-type:uint8 | body | seal:32
```

`seal = SHA-256(magic | record-type | body)`. The final seal is excluded from
its own preimage. A decoder consumes the exact body dictated by the type,
requires end-of-input immediately after the 32-byte seal, recomputes the seal,
and returns a typed inert report. There is no generic map, JSON, gob,
reflection-based field order, optional extension area, or unknown-field skip.

`RBAUTHRecordIdentity(record)` is exactly that record's trailing 32-byte
`seal`. It is never `SHA-256(body)` and never a second hash of
`magic | record-type | body | seal`. Accordingly:

- `build-spec-digest` is the trailing seal of the unique type-`0x01` record;
- `build-permit-digest` is the trailing seal of the unique type-`0x02` record;
- `ready-spec-digest` is the trailing seal of the unique type-`0x03` record;
- the identity of a ReadyPermit report is its type-`0x04` trailing seal.

Cross-domain `RBDFT-v1` identities keep the accepted `RBDFT-v1` rule instead:
the receipt digest is `SHA-256` of the complete type-`0x07` record and the pair
manifest digest is `SHA-256` of the complete type-`0x05` record. Those records
have no `RBAUTH-v1` trailing seal. Implementations and golden vectors may not
substitute one identity rule for the other.

A syntactically valid caller can modify a field and recompute the seal. This
is a **resealed report**, not authority. Authorizers rebuild the complete
expected record from trusted inputs and compare canonical bytes and seals;
live permit validation additionally requires the correct lineage pointer and
state.

Before parsing variable fields, the decoder enforces the maximum size derived
from this grammar with every bounded string at 256 bytes:

| Type | Maximum complete record bytes |
|---|---:|
| ArtifactBuildSpec | 3,212 |
| ArtifactBuildPermit | 3,244 |
| ReadySpec | 1,943 |
| ReadyPermit | 1,975 |

These are arithmetic consequences of the field lists below, not resource
estimates. The permit maxima are exactly 32 bytes larger than their
corresponding spec maxima because the permit body prepends the spec digest.
Inputs over the type-specific maximum fail before any string allocation.

Public parsing is capability-safe by type:

```text
ParseArtifactBuildSpec([]byte)   -> ArtifactBuildSpec report
ParseArtifactBuildPermit([]byte) -> ArtifactBuildPermitReport
ParseReadySpec([]byte)           -> ReadySpec report
ParseReadyPermit([]byte)         -> ReadyPermitReport
```

There is no `UnmarshalBinary` method on either live permit type and no public
constructor from either permit report. `MarshalBinary` on a live permit may
return its canonical evidence record, but parsing those same bytes cannot
restore its unexported lineage pointer.

## Canonical identity fragments

The following fragments are digest preimages, not top-level records. A parser
must reject their domain tags after the top-level magic.

### Raw/effective MatrixLiteral identities

For each role and phase, the literal digest is SHA-256 of:

```text
magic | domain=0x81 | role:uint8 | phase:uint8
type:uint8 | log-slots:int32 | level-q:int32 | level-p:int32
levels-count:uint32 | each level:int32
format:uint8 | bit-reversed:bool | log-bsgs-ratio:int32
```

Scaling is deliberately excluded from this digest. Its separate digest is
SHA-256 of:

```text
magic | domain=0x82 | role:uint8 | phase:uint8 | nullable-big.Float
```

The authorizer computes all eight digests from a fresh preparation of its
stored raw parameters, in this fixed field order:

```text
raw-STC-literal-digest
raw-STC-scaling-digest
effective-STC-literal-digest
effective-STC-scaling-digest
raw-CTS-literal-digest
raw-CTS-scaling-digest
effective-CTS-literal-digest
effective-CTS-scaling-digest
```

STC/S2C is `HomomorphicDecode` type `1`, Q18/P6, levels `[1,1]`;
CTS/C2S is `HomomorphicEncode` type `0`, Q20/P6, levels `[1,1,1]`.
Both have `log-slots=11`, `format=1` (`SplitRealAndImag`),
`bit-reversed=false`, and `log-bsgs-ratio=0`. These are accepted design
values, not new constants. Role and phase bytes are inside each digest, so
equal scalar or literal bytes in two positions cannot authorize a role or
raw/effective swap.

### Scratch and peak identities

The scratch-ledger digest is SHA-256 of:

```text
magic | domain=0x83
roots-bytes:uint64 | pow5-bytes:uint64 | abc-layer-bytes:uint64
largest-stc-numeric-factor-bytes:uint64
largest-cts-numeric-factor-bytes:uint64
stc-phase-maximum-bytes:uint64 | cts-phase-maximum-bytes:uint64
artifact-envelope-bytes:uint64 | remaining-envelope-bytes:uint64
```

The exact accepted values, in order, are:

```text
2,097,408 | 32,776 | 1,572,864 | 33,554,432 | 16,252,928
70,811,912 | 36,208,904 | 81,264,640 | 10,452,728
```

The peak-contract digest retains the six-field `RBAUTH-v1` shape and is
SHA-256 of:

```text
magic | domain=0x84
full-artifact-peak-bytes:uint64
pre-guard-incremental-peak-bytes:uint64
guarded-requirement-bytes:uint64
remaining-below-limit-bytes:uint64
forbidden-duplicate-default-bytes:uint64
duplicate-default-excess-bytes:uint64
```

The first, second, third, and fifth fields are immutable builder bounds:

```text
full-artifact-peak = 2,968,063,744
pre-guard-incremental-peak = 7,129,861,888
guarded-requirement = 7,842,848,076
duplicate-default = 2,641,362,944
```

The fourth and sixth fields are snapshot-derived capacity evidence. For an
admitted capacity report, the authorizer computes them with checked integer
arithmetic:

```text
used = total-physical-bytes - available-physical-bytes
limit = floor(total-physical-bytes * 4 / 5)
guard = floor(7,129,861,888 / 10) = 712,986,188
guarded = 7,129,861,888 + 712,986,188 = 7,842,848,076
projected = used + guarded
require projected < limit
remaining-below-limit = limit - projected
DuplicateDefaultExcessBytes = max(2,641,362,944 - remaining-below-limit, 0)
```

`DuplicateDefaultExcessBytes` is the normative semantic name. It replaces
`ForbiddenDuplicateExcessBytes` without changing field position, width,
endianness, record size, domain tag, or `RBAUTH-v1` version. Zero is valid and
means that duplicate residency would fit under this snapshot's policy limit.
The default constructor remains forbidden by the fixed builder ID,
construction order, allocation/release schedule, and expected default counter
delta of zero. Capacity excess is supporting evidence for that prohibition,
not its source.

The audit fixture remains the canonical byte golden because applying the
formula to `total=33,617,782,768` and `available=17,151,951,897` gives:

```text
used=16,465,830,871 | limit=26,894,226,214
projected=24,308,678,947 | remaining=2,585,547,267
DuplicateDefaultExcessBytes=55,815,677
```

The distinct admitted host sample `total=33,618,251,776` and
`available=17,192,038,400` gives:

```text
used=16,426,213,376 | limit=26,894,601,420
projected=24,269,061,452 | remaining=2,625,539,968
DuplicateDefaultExcessBytes=15,822,976
```

The authorizer accepts both reports when they come from its trusted sampler.
Their capacity report, peak, build-specification, and permit identities differ.
At the duplicate threshold, the required behavior is exact:

| Snapshot-derived remaining margin | `DuplicateDefaultExcessBytes` | Capacity statement |
|---:|---:|---|
| `< 2,641,362,944` | `2,641,362,944 - remaining` | duplicate residency exceeds the limit |
| `= 2,641,362,944` | `0` | duplicate residency reaches neither an excess nor an underflow |
| `> 2,641,362,944` | `0` | duplicate residency fits this capacity gate |

The authorizer recomputes both ledgers. It verifies the phase equations, the
`81,264,640 - 70,811,912 = 10,452,728` envelope, the ten-percent guard
relation, the admitted report equality, and the saturating duplicate formula.
A caller-supplied digest is never the source of either ledger.

## Reusable field blocks

The grammar below uses three named blocks. Blocks are inlined byte-for-byte;
they do not have their own envelope or record type.

### Classification block

```text
adaptation-label:string
evidence-scope:string
maturity:string
source-faithful:bool
full-packed:bool
```

The evidence scope is the build value in build records and the ready value in
ready records. Every other classification field has the fixed value above.

### Current-capacity block

```text
snapshot-id:string
total-physical-bytes:uint64
available-physical-bytes:uint64
capacity-plan-digest:32
capacity-probe-digest:32
capacity-report-digest:32
capacity-permit-digest:32
parameter-digest:32
profile-digest:32
shape-digest:32
policy-digest:32
```

This is an explicit snapshot in canonical evidence, but it is not a caller
declaration. The live `Authority` obtains all three fields from its production
capacity sampler inside the operation that consumes them. The pure capacity
module remains OS-independent: it evaluates the Authority-produced snapshot
and returns the unique report and capacity permit. The snapshot ID must satisfy
the existing non-blank rule, total bytes must be nonzero, and available bytes
must not exceed total bytes. The four capacity-chain digests and the four
parameter/profile/shape/policy digests come from a fresh reconstruction of the
accepted L11 profile, default shape and policy, plan, report, and unique
admitted capacity permit for that sample.

### Capacity source, ownership, and freshness

Production `Authority` construction creates a random 256-bit owner secret and
a distinct process-local owner cell. The secret and pointer never enter the
wire. The Authority also owns a monotonic `uint64` sample generation, starting
at one. Every sampler call atomically consumes the next generation even when a
later validation or compare-and-swap fails; generations are never reused or
rolled back.

The production sampler reads total and available physical memory from the
running host during `AuthorizeBuild`, `BeginBuild`, `AuthorizeReady`, install,
and first-operation preflight. The OS adapter returns only a private raw pair
of totals to the Authority; the Authority, not the adapter, wraps that pair in
an unexported capacity capability with:

- Windows uses `GlobalMemoryStatusEx` and reads `ullTotalPhys` plus
  `ullAvailPhys` from one successful call;
- Linux reads one bounded `/proc/meminfo` snapshot and requires `MemTotal` plus
  `MemAvailable`, both canonical decimal KiB converted to bytes with checked
  multiplication; it does not substitute `MemFree`; and
- every other platform is unsupported in v1 and fails closed before
  preparation. Platform files must still leave `go test ./...` buildable under
  their declared build tags.

```text
owner-cell pointer | generation | sample time
total-physical-bytes | available-physical-bytes
snapshot-id = hex(SHA-256(
  "RBAUTH-capacity-snapshot-v1" | owner-secret | generation |
  total-physical-bytes | available-physical-bytes))
```

The generation and integer fields use the same fixed-width canonical integer
encoding as the wire before hashing. The owner secret prevents callers from
minting a valid sample ID, while pointer identity prevents copied or parsed
bytes from becoming a live capacity capability. Freshness does not depend on
wall-clock ordering; sample time is audit metadata, while owner identity and a
one-shot generation establish freshness.

Sampling and capability validation execute inside one Authority-owned critical
section. The Authority reserves the next generation, invokes the OS adapter,
constructs the capability, checks that its owner and generation equal that
exact reservation, recomputes the snapshot ID, evaluates the pure capacity
plan, seals the inert runtime evidence, and then destroys the capability before
leaving the section. The capability is never returned, stored in a permit, or
passed to a caller callback. A lineage requires a newly reserved generation
strictly greater than its own last consumed generation; it does **not** require
adjacency, because another lineage may legitimately consume intervening global
Authority generations. The global counter and critical section prevent the
same generation from being admitted twice.

Totals, availability, IDs, generations, timestamps, reports, and capacity
permits are outputs of this sampler path. No exported live API accepts them
from a caller. Tests may inject a deterministic raw-total sampler through an
unexported, package-private constructor or field in the `secureeval` package;
even this test sampler cannot choose owner, generation, snapshot ID, report, or
permit. Production constructors expose no sampler injection seam.

An unsupported platform, OS query failure, integer conversion failure,
inconsistent sample, exhausted generation, duplicate internal consumption, or capacity-plan error returns
`ErrRBAUTHBlocked` while preserving `errors.Is`/`errors.As` access to the
platform or typed capacity cause. Missing owner capability, foreign owner
pointer, or replayed/non-monotonic generation returns `ErrRBAUTHLineage`.
Malformed serialized evidence remains `ErrRBAUTHMalformed`; a well-formed
record that differs from its write-once canonical anchor remains
`ErrRBAUTHBlocked`. These categories do not depend on error-string matching.

### Actual-payload block

```text
stc-numeric-aggregate-digest:32 | stc-numeric-record-bytes:uint64
stc-encoded-aggregate-digest:32 | stc-encoded-record-bytes:uint64
cts-numeric-aggregate-digest:32 | cts-numeric-record-bytes:uint64
cts-encoded-aggregate-digest:32 | cts-encoded-record-bytes:uint64
```

These are observed `RBDFT-v1` aggregate identities and exact canonical record
byte counts, not estimates of Go heap residency. Their order is role-first,
then numeric-before-encoded, and is not inferred from field values.

## ArtifactBuildSpec (`type=0x01`)

The exact body order is:

```text
Classification(build)
CurrentCapacity
prepared-parameter-digest:32

raw-stc-literal-digest:32
raw-stc-scaling-digest:32
effective-stc-literal-digest:32
effective-stc-scaling-digest:32
raw-cts-literal-digest:32
raw-cts-scaling-digest:32
effective-cts-literal-digest:32
effective-cts-scaling-digest:32

generator-precision-bits:uint32
encoder-precision-bits:uint32
builder-id:string
digest-id:string
allocation-id:string
release-id:string
ownership-id:string
construction-order:uint8

stc-factor-count:uint32
stc-diagonal-count-count:uint32 | each diagonal-count:uint32
cts-factor-count:uint32
cts-diagonal-count-count:uint32 | each diagonal-count:uint32

expected-default-whole-delta:uint64
expected-explicit-whole-delta:uint64
expected-raw-numeric-delta:uint64
expected-observed-streaming-delta:uint64

the nine scratch-ledger uint64 fields in their digest order
scratch-ledger-digest:32
the six peak-contract uint64 fields in their digest order
peak-contract-digest:32
```

The fixed semantics are generator/encoder precision `256/256`, IDs

```text
lattigo-route-b-prebuilt-dft-streaming-builder-v1
sha256-canonical-streaming-binary-v1
stc-then-cts-single-factor-v1
logical-reference-drop-v1
private-exclusive-transfer-v1
```

construction order `0x01`, STC `2/[63,64]`, CTS `3/[16,31,15]`, and expected
DFT counter deltas `(DefaultWhole, ExplicitWhole, RawNumeric,
ObservedStreaming) = (0,0,0,2)`. The five IDs and counts come directly from
the accepted two-stage design. In particular, the allocation/release/
ownership IDs above supersede similarly purposed legacy strings only for this
new authorization chain; a legacy semantics record cannot substitute for
this block.

`CurrentCapacity` and the two snapshot-derived peak fields describe the
mint-time sample generated by the Authority. `AuthorizeBuild` constructs this
body and returns it as an inert report alongside the live permit. An exported
constructor for `ArtifactBuildSpec` is prohibited. A caller-built or parsed
value can exercise canonical framing and mutation checks, but cannot enter the
live authorization path.

An `ArtifactBuildSpec` contains no numeric-factor digest, encoded-factor
digest, numeric or encoded byte count, artifact digest, pair-manifest digest,
artifact handle/state, lifecycle digest, build-receipt digest, wall time, RSS,
or actual constructor delta. Its type has no field capable of carrying any of
them. Appending one is trailing data and fails parsing.

## ArtifactBuildPermit (`type=0x02`)

The exact body order is:

```text
build-spec-digest:32
the complete ArtifactBuildSpec body, byte-for-byte and in the same order
```

`build-spec-digest` is `RBAUTHRecordIdentity` of the reconstructed type-`0x01`
record whose body is embedded here. The permit therefore binds every pre-allocation fact both through the build-
spec digest and through an independently comparable self-contained copy. It
inherits the same strict prohibition on payload, artifact, manifest,
lifecycle, and receipt fields. The duplication is bounded small metadata and
allows the authorizer to reject a digest pointing to one spec while the
permit body describes another.

The live Go value additionally holds `lineage *lineageCell`; that pointer is
not in the body, the seal preimage, logs, equality reports, or any accessor.
The authorizer constructs the expected build spec and permit from trusted
inputs, compares complete canonical bytes, then creates the sole lineage cell
in state `authorized` and attaches it to the returned live permit. A parsed
permit report has identical bytes and seal but no lineage and fails before an
encoder, allocator, or DFT constructor can run.

The build-permit record remains permanently bound to its mint-time capacity
sample. Later runtime gates do not rewrite this record and do not require a
new capacity report to reproduce its bytes. They validate the anchored permit
and separately require a fresh admitted runtime sample.

## ReadySpec (`type=0x03`)

The exact body order is:

```text
Classification(ready)
CurrentCapacity
prepared-parameter-digest:32
build-spec-digest:32
build-permit-digest:32
build-receipt-digest:32
artifact-pair-manifest-digest:32
ActualPayload
artifact-state:string
```

The first two build links are the trailing seals of the exact type-`0x01` and
type-`0x02` records. The receipt and pair-manifest links use their accepted
`RBDFT-v1` whole-record SHA-256 identities, not an `RBAUTH-v1` seal.

`artifact-state` is exactly `private-uninstalled`. The build-receipt digest is
the SHA-256 identity of the accepted `RBDFT-v1` type-`0x07` success record.
The pair-manifest digest is exactly SHA-256 of the accepted `RBDFT-v1`
type-`0x05` pair aggregate containing this build-permit digest and these four
payload identities and byte counts. There is no second manifest encoding.

Only a ready object binds the build permit, build receipt, pair manifest, and
actual payload identities. A `ReadySpec` is created from the live build
permit, live receipt, and private artifact belonging to one lineage. It is a
value report and carries no transferable ownership capability. The ready
authorizer separately streams the resident encoded artifact and checks its
identities against the receipt and pair manifest; it does not trust the
ReadySpec's copies.

## ReadyPermit (`type=0x04`)

The exact body order is:

```text
ready-spec-digest:32
the complete ReadySpec body, byte-for-byte and in the same order
```

`ready-spec-digest` is the trailing seal of the reconstructed type-`0x03`
record whose body is embedded here.

The live value contains the same unexported `lineage *lineageCell` as its
build permit, build receipt, and private artifact. It is minted only after the
ready authorizer rebuilds current capacity and preparation, validates all
three live inputs against one pointer, wins the
`private-uninstalled -> readying` transition, recomputes the resident evidence
and unique ReadySpec/ReadyPermit records, verifies their embedded and
cross-record identities, writes the Ready anchors, and publishes `ready`. A
parsed `ReadyPermitReport`, a copied report, and a correctly
resealed foreign record all have nil lineage and cannot authorize key
generation or installation.

## Lineage, authority and state semantics

The lineage cell is more than an atomic state word. It contains these
unserialized, unexported, write-once anchors:

```text
authorizer-owner identity (a process-local pointer owned by one Authority)
build-spec identity | build-permit identity
mint-capacity sample generation | report identity | permit identity
last-consumed runtime-capacity generation
build-use capacity-evidence identity
build-receipt identity | artifact-pair-manifest identity
the four actual payload digest/byte tuples
ready-spec identity | ready-permit identity
ready-use capacity-evidence identity | install capacity-evidence identity
preflight capacity-evidence identity
```

The owner identity is not a caller nonce or serialized identifier. Each live
`Authority` instance owns a distinct private cell even when two authorities
have byte-identical raw parameters and capacity inputs. `BeginBuild`,
`AuthorizeReady`, ready-use, install and preflight all require pointer identity
with that owner as well as the expected lineage state.

Build-spec and build-permit anchors are written before the authorized cell is
published. After both observed transforms, the builder writes the receipt,
pair-manifest and actual-payload anchors before publishing
`private-uninstalled`. Ready authorization first wins the
`private-uninstalled -> readying` CAS, then recomputes the resident encoded
identities, validates the historical numeric identities against the
vendor-authored receipt/trace and these private anchors, writes the two Ready
identities, and only then publishes `ready`. A losing ready attempt never reads
the resident artifact or writes an anchor. No accessor returns an anchor or a
mutable view of the cell.

Each use-time admission also creates an inert `RuntimeCapacityEvidence` value
containing the operation tag, snapshot, generation, sample time, plan/report/
permit identities, decision, and the owning lineage identity. Its digest is
stored in the private cell before the corresponding state is published.
`BeginBuild` attaches the build-use value to the live receipt object and may
return its sealed capacity report as an audit sidecar. This value is runtime
evidence, not a fifth `RBAUTH-v1` record and not a capability. Parsed sidecars
cannot satisfy the owner-pointer or monotonic-generation checks.

The unexported lineage cell has the accepted one-way states:

```text
authorized
  -> building
  -> private-uninstalled
  -> readying
  -> ready
  -> installing
  -> installed-unverified
  -> preflighting
  -> operational
```

For every consuming transition, one-shot sampling, capacity evaluation,
canonical anchor validation, and owner/generation checks occur before
compare-and-swap.
Only an admitted sample may reach the CAS. The runtime evidence is computed
and sealed locally before CAS; only the CAS winner writes its digest to the
lineage, immediately after entering the transient state and before the gated
side effect or final success state is published. A CAS loser may already have
performed its read-only OS sample, pure capacity evaluation, stored-raw
`PrepareParameters`, and canonical validation because those gates precede CAS.
It performs no encoder/DFT allocation, artifact read, key generation, install,
or HE operation. The sampled generation remains consumed and is not reused.

After `building`, `readying`, `installing`, or `preflighting` begins, any
corresponding constructor, trace, seal, readiness,
installation, or preflight failure advances to terminal `failed`. Before a
construction transition begins, malformed/stale authorization input produces
an error without allocating and without fabricating progress. State changes
use compare-and-swap. A Go value copy shares the same cell; exactly one copy
can win each consuming transition. No state can move backward, skip a gate,
or leave `failed`.

Same digest does not imply same lineage or authority. Two authorizations over identical
metadata can have identical canonical permit bytes but distinct cells. A
receipt or artifact from one is foreign to the other and fails pointer
identity even if every serialized digest is equal. Conversely, the pointer
never replaces canonical validation or the write-once anchors: a same-cell
object with a changed or resealed record also fails even when the submitted
objects are changed coherently.

## Independent reconstruction by the authorizers

### Build authorization

For every structurally valid build-authorization attempt, the authorizer:

1. rebuilds `GaoN16PackingL11Profile`, the default L11 shape and capacity
   policy, and `GaoN16PackingL11CapacityPlan`;
2. invokes its production sampler, validates the process-local sample
   capability, and evaluates that snapshot to the unique admitted report and
   capacity permit;
3. only after capacity admission, starts from its privately stored raw
   bootstrap parameters, calls `bootstrapping.PrepareParameters`, calls
   `Verify`, and derives the prepared digest plus all eight role/phase literal
   and scaling digests; it never accepts a caller-prepared value;
4. recomputes the fixed IDs, counts, counter expectations, scratch ledger,
   immutable peak bounds, snapshot-derived remaining/excess fields, and their
   digests with checked arithmetic;
5. constructs and returns the sole BuildSpec report and BuildPermit canonical
   bytes; and
6. only then creates the owner-bound `authorized` lineage, writes the build
   identity anchors and returns a live permit.

These steps construct no encoder, DFT factor/matrix, key, evaluator,
ciphertext, payload digest, manifest, lifecycle trace, or receipt. A submitted
seal is never accepted as a substitute for reconstruction.

Mint-time validation is not the construction-time gate. Immediately before
the `authorized -> building` CAS, `BeginBuild` obtains a new Authority-owned
sample and requires its independently rebuilt report to be admitted under the
same immutable profile, shape, policy, plan, and builder bounds. It then
repeats stored-raw preparation, validates the live permit record against its
mint-time write-once anchors, and checks the authorizer-owner pointer. The new
snapshot is allowed to differ in total, available bytes, ID, report, permit,
remaining margin, and duplicate excess. It is not used to reconstruct or
rewrite the mint-time BuildSpec/BuildPermit record. Its admitted report becomes
build-use runtime-capacity evidence. A blocked or failed sample leaves the
lineage `authorized` and performs no preparation, CAS, encoder creation,
allocation, or DFT call. Only the successful CAS admits creation of the encoder
and the two observed DFT calls.

### Ready authorization

For every structurally valid ready-authorization attempt, the authorizer:

1. obtains a new Authority-owned sample and independently reconstructs its
   admitted L11 capacity plan/report/permit;
2. only after capacity admission, repeats the same stored-raw
   `PrepareParameters`/`Verify` derivation;
3. validates the live BuildPermit record and its private build anchors,
   requires the same owner-bound lineage cell in state
   `private-uninstalled` on permit, receipt, and artifact, then atomically
   advances only the winning attempt to `readying` before any resident read;
4. as the sole `readying` winner, validates the complete `RBDFT-v1` receipt and successful lifecycle against
   the private receipt/payload anchors, reconstructs the two historical
   numeric aggregate records only from the vendor-authored per-factor
   digest/byte events and compares them with the write-once numeric anchors,
   streams the resident private artifact to recompute only the STC/CTS encoded
   aggregate identities and byte counts, and recomputes the unique
   pair-manifest record/digest from the validated anchored numeric tuples plus
   the recomputed resident encoded tuples;
5. constructs the expected ReadySpec and ReadyPermit bytes from the new
   ready-time capacity evidence, rejecting any caller-provided substitute; and
6. writes the runtime-capacity and Ready anchors, then publishes `ready` before
   returning the live ReadyPermit. Any failure after winning `readying` is
   terminal `failed`; a CAS loser performs no resident read or anchor write.

Every install attempt checks the owner/lineage pointer, obtains and admits a
new Authority-owned sample, repeats stored-raw preparation, and validates the
complete live ReadyPermit against both Ready anchors and the private artifact/
payload anchors before the `ready -> installing` CAS. Only the CAS winner may
read or stream the artifact, generate keys, move matrices, or call the vendor
assembler. The install-time sample may differ from the ready-time sample and
becomes install runtime-capacity evidence; it does not rewrite the ReadyPermit.
The winner re-streams the resident encoded payload, moves matrices directly
from that same cell into the one-shot vendor carrier, passes generated keys
through a one-shot donor, and installs. Any error or panic after the CAS advances to terminal
`failed`, empties both donors, returns no partial evaluator and cannot restore
`ready`. Success advances to `installed-unverified` with exactly one private
wrapper owner. The first-operation preflight obtains another admitted sample,
validates installed anchors, and lets only the
`installed-unverified -> preflighting` CAS winner re-stream the installed
resident payload before any HE dispatch; a loser performs no resident read.
Ready-time or install-time checks do not replace it. The gate never regenerates or retains a numeric factor
to re-prove a historical numeric tuple; those tuples remain fixed-size
trace/receipt/anchor evidence. Thus neither mint-time evidence nor an old
self-consistent seal can substitute for current admission at the first side
effect, and concurrent shallow handles cannot overlap hash with move/zero.

No legacy Route-B construction value, decoded report, caller event array,
caller constructor count, placeholder digest, or caller-selected manifest is
an input to either reconstruction.

## Rejection and error semantics

The implementation exposes stable typed categories, while detailed messages
may add context:

- `ErrRBAUTHMalformed`: bad magic/type/framing, non-canonical primitive,
  truncation, trailing data, overflow, or seal mismatch;
- `ErrRBAUTHBlocked`: a well-formed record is zero, stale, foreign, resealed,
  role-swapped, semantically inconsistent, capacity-blocked, or promoted;
- `ErrRBAUTHLineage`: nil/foreign lineage, wrong state, double consume, skipped
  transition, or failed lineage; and
- the existing typed capacity/preparation error is wrapped so `errors.Is` or
  `errors.As` retains its cause.

No error path returns a partially live permit. Parse errors return the zero
report. Authorization errors return a zero live permit. The implementation
does not promise which individual field is checked first, so callers must not
branch on error strings.

The following cases are mandatory failures:

- **stale:** any snapshot field, capacity-chain digest, prepared identity, or
  current trusted input differs from the independently rebuilt value;
- **foreign:** a different plan/raw-parameter authority or a different
  lineage supplies an otherwise valid record;
- **resealed:** any changed field with a recomputed trailing seal still differs
  from the authorizer's unique expected record;
- **promotion:** either Boolean becomes true, a scope/maturity/adaptation label
  changes, or a build record is interpreted as ready/MR0/security evidence;
- **role/phase swap:** STC and CTS, raw and effective, numeric and encoded, or
  their byte counts exchange positions, including swaps followed by reseal;
- **trailing/unknown:** one extra byte, an unknown top-level type, a digest
  fragment tag used as a type, or an `RBDFT-v1` record passed to this parser;
- **overflow:** an excessive length/count, cumulative-length wrap, invalid
  host conversion, `available > total`, or capacity/scratch/peak arithmetic
  overflow;
- **nil/empty:** nil or zero-length input, empty required string/list, all-zero
  digest, zero live permit, nil lineage, missing effective scaling, missing
  receipt/artifact, or nil capacity input; and
- **state:** reuse after a consuming CAS, ready-before-build, install-before-
  ready, or any operation after `failed`.

`present=0` for a genuinely nil raw scaling is the only admitted optional
value. It is not equivalent to absent bytes. Callback/build errors after the
`building` transition produce no receipt, no ready object, no installable
artifact, and a terminal failed lineage.

## TDD acceptance matrix

### Independent golden vectors

Use the existing `l11-audit-fixture-2026-08-30` snapshot and the frozen Route-B
raw parameters for the four canonical wire goldens; do not replace those
goldens with a second snapshot. Separate live-sampler tests below must use the
distinct admitted host sample and threshold cases, because dynamic capacity
evidence is not a fixture invariant. For each of the four types:

1. an independent test encoder, which shares no production write helpers,
   emits the complete expected byte string and final seal;
2. the exact byte string and SHA-256 are frozen as test constants;
3. production marshal equals the constant byte-for-byte;
4. the inert parser round-trips to the same canonical bytes; and
5. a second process/architecture-independent run produces the same bytes.

Each cross-record link is also asserted directly against the referenced
record's trailing seal. Negative vectors substitute `SHA-256(body)` and
`SHA-256(magic|type|body|seal)` and must fail, preventing a locally
self-consistent alternate `RecordIdentity` implementation.

The golden Ready vectors use a small deterministic in-memory fixture with
`RBDFT-v1`-valid receipt/aggregate records, not a claim that the L11 artifact
has been built. The test label must remain `wire_fixture_only`.

### Framing and semantic reseal mutation matrices

The acceptance suite separates mutations that cannot produce a typed report
from canonical-but-wrong reports. Both classes have exact-zero
encoder/allocator/DFT/key/evaluator calls.

The **framing/primitive matrix** covers every magic/type byte, truncation,
before-seal insertion, seal suffix, non-canonical Boolean, invalid UTF-8,
zero/oversized string, invalid required count, all-zero digest, invalid
`big.Float` mode/accuracy/sign/precision/hex and every unchecked-length or
conversion boundary. Recomputing a seal cannot make such bytes canonical:
the parser returns `ErrRBAUTHMalformed`, returns a zero report and the
authorizer is not called.

The **semantic reseal matrix** changes one canonically encoded field to a
different canonically encoded value: nonzero digests, valid strings, canonical
promotion Booleans, numeric scalar/list elements within the grammar and
well-formed payload tuples. Without a new seal the parser returns
`ErrRBAUTHMalformed`; with a recomputed seal the parser returns an inert report
and the relevant authorizer returns `ErrRBAUTHBlocked`, no live permit and
zero side effects. A row belongs to this matrix only if its mutated bytes pass
the primitive grammar.

Required named rows include:

- all snapshot and capacity-chain fields;
- prepared digest and every one of the eight role/phase transform digests;
- `255/256/257` precision boundaries and generator/encoder mismatch;
- every byte of the five fixed IDs, construction order, factor/diagonal
  counts, four expected counter deltas, nine scratch fields/digest, and six
  peak fields/digest;
- each classification label and both promotion Booleans;
- build-spec digest/body disagreement inside BuildPermit;
- build-spec, build-permit, receipt, and pair-manifest links in Ready;
- every actual aggregate digest and byte count, numeric/encoded swaps,
  STC/CTS swaps, and artifact-state drift; and
- ready-spec digest/body disagreement inside ReadyPermit.

Insert each forbidden Ready-only field, one at a time, immediately before the
seal of each valid BuildSpec and BuildPermit, then recompute the seal over the
extended body. Repeat the before-seal insertion for ReadySpec and ReadyPermit
with one unknown well-formed scalar. Every case is rejected as unknown body
data rather than being ignored. Compile-time/reflection tests also assert that
build record types have no payload, artifact, manifest, lifecycle, receipt,
timing, RSS, or actual-delta field.

### Capability and state matrix

- Marshal a live BuildPermit/ReadyPermit, parse its bytes, and prove the
  resulting report cannot call build, keygen, install, or preflight.
- Construct zero and nil-lineage test values inside the package; all fail
  before side effects.
- Drift each write-once private anchor inside same-package tests while leaving
  the public record and state unchanged; build/ready/use gates fail before
  their next side effect.
- Assert by type inspection and the observed-consumer alias test that lineage
  anchors contain only fixed-size numeric digests/counts, never a numeric
  map, slice, coefficient or generator root. Ready and ready-use must show
  zero numeric-factor generation calls while re-streaming both encoded roles.
- Give two independent authorizations identical inputs. Their canonical bytes
  may match; their private owner identities differ, and cross-authorizer
  `BeginBuild` plus cross-use of receipt/artifact/permit fail as foreign
  authority or lineage.
- Copy each live Go handle and race the copies at every consuming transition.
  Exactly one CAS succeeds; the loser receives `ErrRBAUTHLineage`.
- Inject a failure at every transition after `building`; state becomes
  `failed`, no later transition succeeds, and no success receipt/permit leaks.
- Mutate/reseal a same-lineage record and use an unmodified foreign-lineage
  record; both fail, proving canonical, private anchor, owner and lineage
  checks are conjunctive. A named test coherently mutates and reseals a
  fixed-cell ReadyPermit and its submitted Ready report while retaining the
  original private anchors; ready-use rejects it before key generation.
- Pass each legacy `GaoN16RouteB*` object or its digest through every exposed
  adapter-shaped seam. No conversion exists and no live permit is minted.

### Trusted live-capacity matrix

- Through the package-private deterministic raw-total sampler, admit both the
  audit pair `33,617,782,768/17,151,951,897` and the distinct pair
  `33,618,251,776/17,192,038,400`. Require their respective remaining/excess
  values `2,585,547,267/55,815,677` and
  `2,625,539,968/15,822,976`; their report, peak, specification and permit
  identities must differ while the immutable builder bounds remain equal.
- Exercise remaining margin immediately below, exactly at, and immediately
  above `2,641,362,944`. Duplicate excess is respectively positive, zero and
  zero. Zero is admitted and never relaxes the independent zero-default-
  constructor counter and builder-ID prohibitions.
- Use a scripted sequence of distinct raw samples for `AuthorizeBuild`,
  `BeginBuild`, `AuthorizeReady`, install and preflight. Each gate consumes
  exactly one new global generation and records its own dynamic evidence; no
  gate requires its total, availability, snapshot ID, remaining margin,
  duplicate excess, report or permit bytes to equal an earlier gate.
- Interleave two lineages under one Authority. Generations remain globally
  unique and strictly increase, while each lineage accepts a later
  non-adjacent generation. Reusing one capability internally, rolling the
  counter backward, exhausting `uint64`, or presenting a foreign owner fails
  before a consuming CAS or side effect.
- Make the OS adapter fail, return `available > total`, or overflow a checked
  conversion at each live gate. The generation is consumed, the current state
  is unchanged before `building`, and no preparation/construction/key/install/
  HE side effect occurs. After a consuming CAS, the existing terminal-failure
  rules remain in force.
- Reflect over every exported Authority constructor and live method: none may
  accept a snapshot, total, available bytes, snapshot ID, generation, sampler,
  capacity report, capacity permit, or runtime evidence. The only injectable
  sampler constructor/field is package-private, and it supplies raw totals
  rather than an already authenticated capability.
- Unit-test the bounded Linux parser against missing/duplicate keys, bad units,
  negative/non-decimal values and checked KiB overflow. Unit-test the Windows
  adapter behind a package-private syscall seam and require one successful
  `GlobalMemoryStatusEx` result. A production smoke test asserts only
  `0 < total`, `available <= total` and authenticated one-shot sampling; host
  admission is intentionally not a deterministic test expectation.

### Framing, boundary, and property tests

- Reject nil, empty, every strict prefix, every one-byte suffix, wrong magic,
  all top-level types except `0x01..0x04`, and all digest-domain tags as types.
- For all four record types, insert one byte immediately before the seal,
  recompute the seal over the extended body, and require malformed rejection;
  this is distinct from appending bytes after a valid seal.
- Confirm the existing `RBDFT-v1` parser still accepts only its frozen seven
  types and rejects every `RBAUTH-v1` record; the converse also holds.
- Exercise string lengths `0,1,255,256,257,MaxUint32`, invalid UTF-8, and exact
  frozen identifier comparison.
- Exercise list counts `0`, expected, expected±1, and `MaxUint32` without an
  allocation proportional to rejected input.
- Exercise all six `big.Float` rounding modes, three accuracy codes, positive
  and negative zero, nil versus present zero, precision `1,255,256`, and reject
  precision `0/257`, invalid sign/accuracy/mode, non-canonical hex, NaN,
  infinity, truncation, and trailing scalar bytes.
- Add exact-equal finite fixtures that vary only precision, only rounding mode
  and only accuracy in turn; each isolated metadata change must alter the
  canonical scaling identity while value and the other metadata remain equal.
- Property-test `Marshal(Parse(Marshal(x))) == Marshal(x)` for inert reports
  and deterministic seal recomputation. Fuzz every parser with an allocation
  ceiling derived from its bounded field grammar; no input may panic, hang, or
  allocate from an unchecked length.
- Property-test that a change in any trusted raw parameter, prepared result,
  capacity snapshot/plan, role/phase, accepted numeric constant, receipt
  identity, or resident payload produces a different expected record or a
  typed rejection.

### Authorizer reconstruction counters

Instrument only test seams. A structurally valid successful build or ready
authorization must show one fresh capacity reconstruction followed by one
fresh `PrepareParameters` call by that authorizer. No path calls a
caller-supplied prepare/capacity closure. Malformed inputs fail before both
pure calls. A structurally valid but blocked, stale or foreign capacity input
shows the required capacity reconstruction and **zero** Prepare calls. Only
after the independently rebuilt capacity permit is admitted may a
well-formed-but-stale/resealed prepared or authorization candidate show one
Prepare call. `BeginBuild` and ready-use enforce the same ordering. Every
invalid case has zero encoder, artifact allocator, observed/default/explicit/
raw DFT constructor, key, evaluator, and ciphertext calls. Successful build
authorization also has all of those side-effect counts at zero; it authorizes,
but does not perform, construction.

## Acceptance stop conditions

Implementation cannot pass this design gate if any of the following occurs:

- a build record contains an actual payload, artifact/manifest, lifecycle, or
  receipt identity;
- a ready record omits the build-permit, receipt, pair-manifest, or any one of
  the four actual aggregate identities and byte counts;
- `RBDFT-v1` is extended to carry an authorization record;
- a permit can be unmarshaled into a live capability or lineage data appears
  in canonical bytes;
- an authorizer validates only caller seals/digests instead of independently
  rebuilding current capacity and preparation;
- an exported live API accepts caller capacity totals, snapshot/permit/report
  data, a sampler, or runtime evidence; a production path exposes the private
  test sampler seam; or a sampler-created capability escapes its one-shot
  Authority critical section;
- a snapshot-derived remaining margin or duplicate excess is compared with
  the audit fixture or a prior gate instead of being recomputed from the fresh
  sample; zero duplicate excess is rejected; or a lineage incorrectly demands
  globally adjacent generations;
- stale, foreign, resealed, promoted, role-swapped, trailing, overflow, or
  nil/empty cases reach a construction/key/install side effect;
- identical canonical bytes are treated as proof of identical lineage; or
  state can be reused, skipped, reversed, or recovered from `failed`.

Passing this wire gate establishes only deterministic authorization metadata
and live-capability confinement. It does not establish an observed factor
build, artifact correctness, measured RSS, encrypted MR0, full-packed Gao
reproduction, decision-tree performance, or application security.
