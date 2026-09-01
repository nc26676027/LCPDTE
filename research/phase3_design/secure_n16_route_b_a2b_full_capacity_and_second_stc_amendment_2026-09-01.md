# Secure N16 Route-B full-A2B capacity and second-STC amendment

**Date:** 2026-09-01  
**Stage:** ARS Stage 2 engineering gate  
**Status:** registered before the first canonical complete 8-bit Route-B A2B run  
**Scope:** the serial second nibble round and its supplemental `L3 -> L1`
Slots-to-Coefficients transform; the accepted MR0 and first-round artifacts,
schemas, reports, files, and hashes remain unchanged

## Trigger and immutable seam

The accepted low-nibble run ends with `ID0` and `MSB0` at level 5.  A complete
8-bit Gao conversion must then evaluate the serial recurrence

`highUpdated = specialHigh - ID0/16`,

refresh the masked high half, run the same degree-46/shared-LUT kernel a second
time, and return `MSB1`.  After the second mask and rescale, the refresh input
is at level 3.  The installed Route-B STC is a sealed `L18 -> L16` resident
artifact.  Relabelling its metadata would break both its encoded polynomial
levels and its admitted artifact identity.  The second round therefore owns a
separate observed-streaming STC with the following closed schedule.

| Field | Supplemental STC value |
|---|---:|
| role/type | Slots-to-Coefficients / `HomomorphicDecode` |
| format | `SplitRealAndImag` |
| `LogSlots` | 11 |
| `LevelQ` / `LevelP` | 3 / 6 |
| factor depths | `[1, 1]` |
| diagonal counts | `[63, 64]` |
| vector length | 2,048 |
| precision | 256 bits for generation and encoding |
| expected binary bytes per encoded polynomial | 5,767,272 |
| input/output level | 3 / 1 |

The raw and effective supplemental literals are independently cloned from the
canonical raw and prepared-effective STC literals and then changed only at
`LevelQ`.  Their level vectors and big-float scaling values are deep copies.
The implementation must bind separate literal and scaling digests for both
views, the two numeric-factor digests, the two encoded-factor digests and
physical byte counts, and the observed-streaming trace digest.  It must reject
any changed role, order, precision, topology, scale schedule, polynomial size,
ownership transition, or matrix/literal validation result.

The supplemental STC uses the same STC rotation/Galois topology as the
installed transform.  Consequently it requires no new evaluation key.  The
frozen 38-element Route-B key inventory and all cryptographic parameters stay
unchanged.

## Registered `a2b-full` phase

The new phase retains every conservative component of `a2b-first-round` and
adds the resources unique to the serial second round.

| Incremental component | Bytes |
|---|---:|
| accepted first-round envelope | 1,227,427,584 |
| supplemental L3/P6 STC encoded resident factors | 732,430,336 |
| supplemental STC high-precision numeric factor | 66,584,576 |
| supplemental STC numeric/encoded digest text | 99,876,864 |
| serial `ID0/16` plaintext | 3,145,728 |
| conservative serial retained-ciphertext envelope | 251,658,240 |
| **pre-guard incremental peak** | **2,381,123,328** |
| minimum guard | 536,870,912 |
| **guarded requirement** | **2,917,994,240** |

The five new terms are computed from the sealed L11 capacity shape:

- encoded STC: `(63+64) * N * 8 * ((3+1)+(6+1))`;
- numeric STC: `(63+64) * 2048 * 256`;
- digest text: `(63+64) * 2048 * 192 * 2`;
- ID-scale plaintext: `N * 8 * (5+1)`;
- retained ciphertexts: `12 * 2 * N * 8 * (19+1)`.

Admission remains strict:

`current system use + 2,917,994,240 < floor(4 * total physical memory / 5)`.

The distinct runtime operation is `a2b-full`.  Sampling and admission precede
resident reads, circuit construction, supplemental matrix generation, or HE.
A pre-admission block leaves the installed-unverified lineage available; any
failure after exclusive lineage transition is terminal and clears the private
installed evaluator.

## Dispatch, construction, and claim rules

1. The original artifact build must continue to observe exactly two streaming
   DFT constructions: installed STC and installed CTS.
2. One complete A2B run observes exactly one additional streaming
   construction for the supplemental STC.  Its process-local construction
   delta is therefore `default=0`, `explicit-whole=0`, `raw-numeric=0`,
   `observed-streaming=3` across build plus execution.
3. The installed STC/CTS matrices and their accepted payload records are never
   mutated, retagged, or republished.  Supplemental evidence belongs only to
   the full-A2B execution report.
4. Both refreshes reuse the installed CTS after their own `ScaleDown -> ModUp`
   prefixes.  Both kernel inputs may use only the registered exact metadata
   normalization pair and bound already established for the first round.
5. The full report must bind every serial arithmetic boundary, the first and
   second kernel provenance, exact operation counts, supplemental STC
   evidence, capacity-plan identity, and wall time.
6. Success establishes a complete two-round 8-bit A2B conversion for the
   registered exhaustive input layout.  It does not by itself establish a
   private decision-tree evaluator, comparison correctness, security level,
   asymptotic improvement, or performance superiority; those require their
   own composed experiments and evidence.
