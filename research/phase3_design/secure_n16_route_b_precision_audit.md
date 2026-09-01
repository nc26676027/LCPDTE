# Secure N16 Route-B Precision-Construction Audit

> **2026-08-30 reachability amendment.** The artifact-bound permit in this
> record is now classified as a post-build ReadyPermit. A later independent
> audit identified a first-construction cycle because numeric and encoded
> payload digests are produced by the builder that the permit was supposed to
> authorize. The two-stage repair and canonical streaming grammar are frozen
> in
> [`secure_n16_route_b_two_stage_construction.md`](secure_n16_route_b_two_stage_construction.md).
> This narrows the earlier acceptance; it does not alter the 53/256-bit
> precision finding or the duplicate-memory calculation.

**Date:** 2026-08-30  
**Scope:** read-only design and pinned-vendor audit; no large artifact construction  
**Verdict:** **REVISE — 0 Critical / 2 Major / 1 minor**

## Confirmed source facts

For the exact S43 candidate, the stock bootstrap path is numerically a 53-bit
DFT generator. `bootstrapping.NewEvaluator` reaches `initialize`, which calls
`ckks.NewEncoder(params)` without a precision argument
(`vendor/.../bootstrapping/evaluator.go:208`). The default is
`params.EncodingPrecision()` (`vendor/.../schemes/ckks/encoder.go:84-89`), and
that function returns `max(53, log2(DefaultScale))`; at S43 it is 53
(`vendor/.../schemes/ckks/params.go:185-194`). Independently,
`dft.NewMatrixFromLiteral` calls `GenMatrices(params.LogN(),
params.EncodingPrecision())` before using the supplied encoder
(`vendor/.../circuits/ckks/dft/dft.go:169,203`). Passing a 256-bit encoder only
at encoding time therefore does not recover 256-bit numeric factors.

The L11 estimate also proves that constructing stock factors and replacing
them is inadmissible. The encoded STC and CTS sets occupy 1,731,198,976 B and
910,163,968 B, respectively. A duplicate pair adds 2,641,362,944 B to a plan
with only 2,585,547,267 B of margin, exceeding it by 55,815,677 B before any
additional scratch.

## Major 1 — artifact identity omits effective bootstrap literals

Bootstrap initialization modifies the DFT literals before generation: Mod1
preparation derives the C2S/S2C scale and offset and applies them in
`bootstrapping/evaluator.go:183-228`; matrices are generated only afterward at
lines 231-235. A 256-bit bundle generated from raw literals can therefore have
valid precision and payload self-digests while carrying the wrong effective
scaling.

**Required repair:** factor preparation must be a single reusable function.
The artifact identity records separate raw and effective C2S/S2C literal
digests, including effective scaling. The small-profile differential uses the
effective literals, and a raw-literal bundle is an explicit RED.

## Major 2 — no digest edge from capacity permit to construction semantics

The accepted capacity profile binds byte bounds but not generator precision,
encoder precision, builder/version, binary digest algorithm, allocation/release
schedule or artifact-manifest digest. It cannot distinguish a compliant
256-bit streaming builder from a 512-bit builder, textual duplicate digest, or
default-then-replace schedule with a different peak.

**Required repair:** retain capacity-v1 as capacity-only evidence and introduce
an opaque `RouteBConstructionSpec/Permit` binding:

```text
capacity-plan digest + capacity-permit digest
+ parameter/profile digests
+ generator/encoder precision = 256/256
+ effective C2S/S2C literal digests
+ builder and streaming-binary-digest algorithm IDs
+ allocation/release schedule and peak contract
+ private artifact-manifest digest
```

Every mismatch returns before encoder, DFT, key, evaluator or ciphertext
allocation.

## Minor — ownership and immutability are underspecified

`dft.Matrix.Matrices` and the bootstrap matrices are public. A provider may
retain an alias and modify a matrix after admission. The Route-B module must
construct/load an opaque private bundle or accept exclusive ownership and
eliminate external aliases. It authenticates numeric and encoded payloads at
installation and again before the first HE operation.

## Minimal seam

The constructor first validates the capacity and construction permits, derives
the unique effective literals, asks a provider for a private bundle keyed to
those literals, verifies its precision and canonical binary payloads, and then
constructs CKKS/DFT/Mod1 evaluators without ever invoking the default factor
provider. A narrow matrix builder accepts an explicit precision and requires
`generatorPrecision == encoder.Prec() == 256`, passing that precision to
`GenMatrices`.

## Acceptance tests

- raw-literal bundle RED; effective-literal preparation equals the stock small
  profile and does not mutate its input;
- canonical numeric and encoded payload digests cover precision, order,
  diagonals, Q/P limbs, level, scale, dimensions and BSGS metadata;
- explicit-53 equals stock S43 and differs from explicit-256 at a frozen
  coefficient and encoded-payload sentinel;
- explicit-256 streaming output equals an independent all-at-once
  `GenMatrices(LogN,256)+Encode` reference coefficient-for-coefficient;
- stale/foreign permit causes zero provider calls and zero HE allocations;
- duplicate-default schedule is rejected with the explicit
  `+2,641,362,944 B` delta;
- the only full L11 run occurs in an isolated process and reports measured peak
  RSS separately from the derived capacity bound.

Route A still needs its own factor iterator and lazy evaluation-key store.
Passing this Route-B repair cannot be reported as the 8,192-word full-packed
Gao reproduction or as application-security evidence.
