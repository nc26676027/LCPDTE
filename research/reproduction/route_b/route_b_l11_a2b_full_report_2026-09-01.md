# Route-B L11 complete 8-bit A2B reproduction report

**Run date:** 2026-09-01  
**Status:** success  
**Scope:** one fresh-process Route-B lifecycle followed by the complete serial
low-then-high Gao A2B conversion over two copies of every byte value

## Result

The Lattigo N16/L11 implementation completed both nibble rounds and decoded
all 4,096 Boolean output slots with zero mismatches.  The low and high
ciphertexts each contain four LSB-first bits for 512 encrypted byte words; the
input sequence is `0..255` repeated twice.

Canonical artifact:

- file: `route_b_l11_a2b_full_2026-09-01.json`;
- bytes: `455,026`;
- SHA-256:
  `e97f81488cb6f042046379121b53c6fbefb208d417bfbd18fa3845839eef785d`;
- full-A2B report digest:
  `764715f2e34c85cc379b0815744642f9ba55a3dcb058c99ed45c7b73d6919d42`;
- supplemental-STC report digest:
  `bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a`.

The command writes no JSON until lifecycle, report, and exhaustive slot
validation all succeed.

## Measured row

| Measurement | Result |
|---|---:|
| artifact-build peak RSS | 3,273,900,032 B |
| post-install process peak RSS | 6,569,345,024 B |
| post-full-A2B process peak RSS | 12,827,648,000 B |
| total lifecycle wall time | 54.2973214 s |
| full serial circuit wall time | 25.8302408 s |
| first MR0 wall time | 4.1537684 s |
| second MR0 wall time | 4.0521683 s |
| maximum low-half absolute error | 1.3688218578875624e-7 |
| maximum high-half absolute error | 8.4026492208622017e-8 |
| maximum imaginary magnitude | 8.5500948344336645e-11 |
| tolerance | 5e-4 |
| checked real Boolean slots | 4,096 |
| mismatches | 0 |
| DFT-construction delta | `[0, 0, 0, 3]` |

Relative to the accepted first-round run, the complete run adds
14.4369322 s of total lifecycle time and 3,007,815,680 B to the observed
process peak.  This is a same-host paired observation, not a distributional
performance claim.

## Capacity admission

The execution selected the separately registered `a2b-full` phase before any
supplemental construction or HE dispatch.

| Capacity field | Bytes |
|---|---:|
| sampled total physical memory | 33,618,251,776 |
| sampled available physical memory | 13,125,046,272 |
| pre-guard incremental requirement | 2,381,123,328 |
| guarded requirement | 2,917,994,240 |
| remaining below strict 80% boundary | 3,483,401,676 |
| capacity-plan digest | `77a10014ceb20204ace65393e5f7d99cbf3171883345d298e1c6b0b693ef56ec` |

The corresponding pre-run amendment is
`research/phase3_design/secure_n16_route_b_a2b_full_capacity_and_second_stc_amendment_2026-09-01.md`.

## Authenticated supplemental STC

The installed STC remains the sealed `L18 -> L16` artifact.  The second nibble
round constructs an independent observed-streaming `L3 -> L1` STC with
`LevelP=6`, depths `[1,1]`, diagonal counts `[63,64]`, vector length 2,048,
and 5,767,272 binary bytes per encoded polynomial.

Source identities:

| Identity | SHA-256 |
|---|---|
| raw supplemental literal | `e9b6bfe3180d090adc5344625d444e97953a00cd4475a9b53eb7d4ddc5e332e4` |
| raw scaling | `ca2fd7688b462df6336d04bdbf0e324723e490fc7afa7808822df3e10a7681ff` |
| effective supplemental literal | `7639927ea7baae9ba8aabbc47f1b5843dca13a79449fad433c3b9237a6fc2565` |
| effective scaling | `58b7bebf46c178efaf34a42a723ebfa05ad770a948ed8efa607b7161871650d0` |
| observed-streaming trace | `da09c270d38aaf5117628ae09ec7487480f7b3a8562ec8a76502ecf35f8b4a83` |

Factor evidence:

| Factor | Diagonals | Numeric bytes / SHA-256 | Encoded bytes / SHA-256 |
|---:|---:|---|---|
| 0 | 63 | 12,971,990 / `bf8fbcb7774e62cab94c9ab07fcbbdf0894753379749872469bbd3538f5bdd81` | 363,339,287 / `28045ac2cd0e3ea2c4d634fe7d4123f0d0ec96d8c8b344f96461492dcabc7e9a` |
| 1 | 64 | 21,566,574 / `81d9c29e88fb959829ebcad8a45e19f2646269957583bf1dd881311cb2b1fd1a` | 369,106,575 / `2324862950916738884c9e6561f77240c929e587af54308a3ea15b3e7d3d5332` |

The trace contains 13 completed success events, zero cleanup events, and one
observed-streaming construction.  Both factors are frozen in code after this
canonical observation.  Their key union exactly matches the installed STC
union; the 38-key Route-B inventory is unchanged.

## Serial circuit and exact state ledger

The charged graph is:

`special-b0 -> low mask -> STC18:16 -> MR0 -> kernel0 -> ID0/16 ->`
`high-ID0/16 -> high mask -> STC3:1 -> MR0 -> kernel1`.

The report binds 32 ciphertext boundaries.  Its decisive levels are:

- input `L20`, special halves `L19`;
- first mask `L18`, installed STC output `L16`, shared CTS output `L17`,
  kernel outputs `L5`;
- `ID0/16`, aligned high, and updated high at `L4`;
- aligned/self-removed low at `L5`;
- second mask `L3`, supplemental STC output `L1`, shared CTS output `L17`,
  second kernel outputs `L5`;
- aligned `ID1` and final high residual at `L4`.

Both CTS outputs have the same registered raw scale
`0x1.0000000000000002f2901f1f8cf04128p+43`.  Each is normalized only in
metadata to `0x1p+43`; the exact absolute log2 drift is
`2.3052091909425391e-19`, below the fixed `2^-40` bound.  Ciphertext
coefficients and all non-scale metadata remain unchanged.

The serial operation ledger is
`special-b0/masks/refreshes/kernels/ID-scale/drops/subtractions/rotations/shared-CTS`
`= 1/2/2/2/1/3/3/0/2`.  Each Gao kernel independently records
`exp/squares/multi-poly/shared-basis/generic-LUT/conjugations/recoveries`
`= 1/2/1/1/0/2/2`.

## Reproduction and replay

Canonical execution:

```powershell
go run ./cmd/route-b-l11-a2b-full `
  -out research/reproduction/route_b/route_b_l11_a2b_full_2026-09-01.json
```

Hash-locked exhaustive replay:

```powershell
go test ./cmd/route-b-l11-a2b-full `
  -run TestAcceptedRouteBL11A2BFullArtifactReplaysEverySlot -count=20
```

The 20-fold replay passed.  `go test ./integer/secureeval ./integer/secureprofile`
and `go vet ./integer/secureeval ./integer/secureprofile` also passed after the
run.

## Evidence boundary

This artifact establishes the registered Lattigo N16/L11 functional claim for
the complete two-round 8-bit A2B conversion on the exhaustive canonical input
layout.  The result does not yet establish the final private decision-tree
composition, a radix-tree speedup, an independent cryptanalytic security
claim, or performance superiority.  Those claims remain separate downstream
gates.
