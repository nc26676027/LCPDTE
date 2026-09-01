# Canonical Route-B L11 first-A2B-round reproduction report

**Run date:** 2026-09-01  
**Platform:** Windows, 33,618,251,776 bytes physical memory  
**Classification:** Lattigo packing adaptation / R1, `LogN=16`,
`LogSlots=11`, 512 eight-bit words  
**Verdict:** **PASS AUTHOR-SIDE FUNCTIONAL GATE — complete low-nibble Gao
A2B round; independent audit pending**

## Frozen artifact

The accepted one-process run is
[`route_b_l11_a2b_first_round_2026-09-01.json`](route_b_l11_a2b_first_round_2026-09-01.json),
SHA-256
`2728FC0B5E8084FB56573AD87EF7DA9F64A6CA87517E87744CEA309EC6F572A0`
(446,637 bytes). The command was:

```text
go run ./cmd/route-b-l11-a2b-first-round \
  -out research/reproduction/route_b/route_b_l11_a2b_first_round_2026-09-01.json
```

The frozen replay test verifies the file digest, unmarshals the complete
evidence graph, reruns every inert lifecycle/capacity/round validator, and
recomputes the oracle for all 4,096 decoded ID/MSB values:

```text
go test ./cmd/route-b-l11-a2b-first-round -count=20
ok  dt_go/cmd/route-b-l11-a2b-first-round  1.114s
```

## Functional outcome

The input contains 512 words with the sequence `0..255` repeated twice.
Special-b0 exposes four low-nibble lanes per word, so the result checks 2,048
identity values and 2,048 extracted MSB values.  Validation reconstructs every
expected value independently through `A2BBooleanHalvesOracle` and
`A2BTwoLUTOracle`; no decoded value is accepted only by aggregate statistics.

| Measurement | Observed value |
|---|---:|
| Input words / distinct residues | `512 / 256` |
| Checked ID slots / checked MSB slots | `2,048 / 2,048` |
| Accuracy tolerance | `5e-4` |
| Maximum identity absolute error | `9.1463878420219515e-08` |
| Maximum MSB absolute error | `9.2368428526136832e-08` |
| Maximum absolute imaginary component | `8.9380092211797199e-11` |
| Mismatching slots | `0` |
| Total one-process wall time | `39,860,389,200 ns` |
| Artifact construction wall time | `5,397,607,200 ns` |
| Observed ModUp/C2S prefix wall time | `4,510,219,100 ns` |
| Composed first-round wall time | `13,503,677,500 ns` |
| Build-time process peak RSS | `3,202,564,096 bytes` |
| Process peak RSS after install | `6,568,886,272 bytes` |
| Process peak RSS after first round | `9,819,832,320 bytes` |
| DFT constructor delta `(default/explicit/raw/observed-streaming)` | `0/0/0/2` |

Peak RSS is the operating system's cumulative process high-water mark, not an
isolated phase allocation.  This is one author-side run, so the wall/RSS row is
reproduction evidence rather than a repeated-performance estimate.

The input pattern digest is
`9af5fe0deda53bb1feeb9e210960da39c70bda47de48425238bb7cfd91b1df57`.
The first-round report digest is
`364484ba05658deb20a6915840a8cfe130238f9be90b8a980f83b04c01d05729`.

## Executed circuit and provenance

The encrypted path is:

```text
arithmetic input L20
  -> special-b0 low/high L19
  -> low mask L18
  -> SlotsToCoeffs L16
  -> observed ScaleDown/ModUp/Trace/C2S L17
  -> metadata-only registered scale normalization L17
  -> degree-46 exponential L11
  -> two MulRelin+Rescale squares L10/L9
  -> shared-power identity/MSB degree-15 LUTs L5
  -> two conjugate-add real recoveries L5
```

The operation ledger records one exponential polynomial evaluation, two
complex squarings, one multi-polynomial evaluation with one shared power basis,
zero generic LUT calls, two conjugations and two real recoveries.  The special-
b0 transform uses BSGS ratio 2, `N1=4/4`, rotations `[1,2,3,2044]` and Galois
elements `[5,25,125,89745,131071]`; every element is inside the frozen 38-key
inventory.

The bound identities are:

| Artifact | SHA-256 identity |
|---|---|
| Gao N16/L11 kernel profile | `13ed99b7fc9321ce195a10d9fe297d17ea842b2ba0fd586c305b3a2e7e09e216` |
| degree-46 exponential artifact | `a960edc18c4c7dee294d0f452eb3ef377c1d2094dadc0a046f49a68902e36e4d` |
| shared ID/MSB LUT table | `f3aa5c55fa47acd6c5a0f96d362d442948c6b2999d3bd4a6061870d3d21564e3` |
| special-b0 transform source | `fbfccbd8e12142bcafc2bcf2326283506a76fbf2d9dbd27d74769e0866cc270f` |
| first-round mask source | `cef4d67cb95eb7a192a446d31340772ef23a7f2ea54615a7fb47bbc68901904a` |
| first-round capacity plan | `e77d1be0b7f08a7ef0b18eaefb1b8c8614d3eb203640d467e28752b846c2654d` |

## Exact scale boundary

The raw MR0 output state is preserved in the report before normalization.  Its
scale is `0x1.0000000000000002f2901f1f8cf04128p+43`, compared with the frozen
kernel input `0x1p+43`; the measured absolute log2 drift is
`2.3052091909425391e-19`, below the registered `2^-40` bound.  The dispatcher
accepts only this exact pair and proves that assigning the target changes no
ciphertext coefficient or non-scale metadata.  The Gao kernel's exact target-
scale gate remains active.

The two explicit squaring states retain their actual canonical scales rather
than being mislabeled as default-scale states:

```text
square0  0x1.ffffbe8008211efdf347fefcaa62c434p+42
square1  0x1.ffff41802e86b69715852fbfcc0f84ecp+42
```

The scale-normalization amendment was registered before success at SHA-256
`15E145CB3F132B66A1D0F4E126EFFB0CB17E12F4713E30A79C06EE98A911A67F`.

## Live capacity evidence

Every consuming gate sampled current physical memory before preparation or HE.
Admission remained `projected < floor(4*total/5) = 26,894,601,420 bytes`.

| Gate | Used at sample | Pre-guard increment | Guarded requirement | Projected use | Remaining |
|---|---:|---:|---:|---:|---:|
| AuthorizeBuild | 14,151,348,224 | 7,129,861,888 | 7,842,848,076 | 21,994,196,300 | 4,900,405,120 |
| BeginBuild | 14,151,880,704 | 2,968,063,744 | 3,504,934,656 | 17,656,815,360 | 9,237,786,060 |
| AuthorizeReady | 16,762,343,424 | 872,939,520 | 1,409,810,432 | 18,172,153,856 | 8,722,447,564 |
| Install | 16,813,068,288 | 5,034,213,376 | 5,571,084,288 | 22,384,152,576 | 4,510,448,844 |
| First A2B round | 20,376,924,160 | 1,227,427,584 | 1,764,298,496 | 22,141,222,656 | 4,753,378,764 |

The final phase uses the capacity amendment registered before the first A2B
attempt, SHA-256
`51E68479F624BBDBBC91ACFA386DECE1DDFD2518AA6CCD6553932D5CDB2C6246`.

## Failure-to-success trail

1. The first composition attempt reached the prefix, then rejected a
   bootstrapping wrapper where the strict Gao adapter required the authenticated
   memory-key view.  The repair derives that view only from the installed
   evaluator and proves the wrapper remains unchanged.
2. The next two attempts stopped at the exact kernel input-scale gate.  They
   established the single observed metadata source value and motivated the
   preregistered bounded normalization above.
3. The fourth attempt executed the Gao kernel, then exposed an outer-report bug
   that required the default scale at the two explicit rescale states.  The
   kernel had already validated the correct recurrence
   `s_next = s_previous^2 / Q_level`; the report now binds the same exact values.
4. The fifth attempt passed capacity, lineage, all fourteen state boundaries,
   operation provenance and every decoded-slot oracle, then emitted the frozen
   JSON.

No failed attempt emitted an accepted result file.  Each fresh process rebuilt
its private artifact, keys and evaluator.

## Claim boundary and next gate

This artifact establishes functional correctness for the first, low-nibble
Gao A2B round inside the local Route-B Lattigo lifecycle.  It is stronger than
the earlier C69 prefix diagnostic because it executes the degree-46/R2 kernel
and verifies both encrypted outputs exhaustively over the 8-bit residue set.

It is not a complete 8-bit A2B conversion.  The high-nibble second round still
requires a level-compatible `SlotsToCoeffs`/refresh schedule and composition of
the two Boolean halves.  The run also does not establish source-faithful 8,192-
word throughput, B-A2B, comparator/tree correctness, repeated performance,
128-bit application security, or superiority over BFV/BGV LCPDTE.  Those remain
separate evidence gates.
