# Canonical Route-B L11 MR0 reproduction report

**Run date:** 2026-09-01  
**Platform:** Windows, 33,618,251,776 bytes physical memory  
**Classification:** Lattigo packing adaptation / R1, `LogN=16`,
`LogSlots=11`, 512 eight-bit words  
**Verdict:** **PASS — complete live artifact lifecycle and observed sparse
ModUp/C2S prefix**

## Accepted artifact

The accepted one-process run is
[`route_b_l11_mr0_2026-09-01.json`](route_b_l11_mr0_2026-09-01.json),
SHA-256
`4F963B88BCA8DBB078362483D38B06699DAAE93F53D929E1810435FEF8221B28`
(59,231 bytes). The command was:

```text
go run ./cmd/route-b-l11-mr0 \
  -out research/reproduction/route_b/route_b_l11_mr0_2026-09-01.json
```

The frozen replay test unmarshals the result, reruns every inert semantic,
lineage and phase-capacity validator, checks the file digest and freezes the
measured row:

```text
go test ./cmd/route-b-l11-mr0 -count=20
```

## Outcome

| Measurement | Observed value |
|---|---:|
| Total one-process wall time | 34,996,007,900 ns |
| Artifact construction wall time | 6,339,778,500 ns |
| First sparse ModUp/C2S wall time | 5,892,370,100 ns |
| Build-time process peak RSS | 3,273,887,744 bytes |
| Process peak RSS after install | 6,568,656,896 bytes |
| Process peak RSS after first MR0 | 7,184,281,600 bytes |
| DFT constructor delta `(default/explicit/raw/observed-streaming)` | `0/0/0/2` |
| Raised level / C2S output level | `20 / 17` |
| Sparse C2S imaginary output | `nil` |
| Packing | 2,048 slots / 8 bits / 512 words |

Peak RSS is the process-wide monotonic peak reported by the operating system;
the three readings are cumulative checkpoints, not isolated phase costs.

The resident artifact links the following canonical streamed payloads:

| Payload | Record bytes |
|---|---:|
| STC numeric aggregate | 34,538,682 |
| STC encoded aggregate | 1,731,229,860 |
| CTS numeric aggregate | 14,890,392 |
| CTS encoded aggregate | 910,180,485 |

The observed Trace dispatch retained source order:

```text
rotations = [2048, 4096, 8192, 16384]
galois    = [122881, 114689, 98305, 65537]
```

The evaluator held the exact sorted 38-key DFT/Trace/conjugation inventory,
plus the separately validated relinearization and dense/sparse switching
keys. Its C2S path returned a real ciphertext and `ctImag=nil`, as required
for this reduced sparse packing.

## Live capacity evidence

Every gate sampled physical memory through the Authority immediately before
its own preparation or side effect. Admission remained strict:
`projected < floor(4*total/5) = 26,894,601,420` bytes.

| Gate | Used at sample | Pre-guard increment | Guarded requirement | Projected use | Remaining |
|---|---:|---:|---:|---:|---:|
| AuthorizeBuild | 13,837,549,568 | 7,129,861,888 | 7,842,848,076 | 21,680,397,644 | 5,214,203,776 |
| BeginBuild | 13,836,972,032 | 2,968,063,744 | 3,504,934,656 | 17,341,906,688 | 9,552,694,732 |
| AuthorizeReady | 16,488,878,080 | 872,939,520 | 1,409,810,432 | 17,898,688,512 | 8,995,912,908 |
| Install | 16,555,073,536 | 5,034,213,376 | 5,571,084,288 | 22,126,157,824 | 4,768,443,596 |
| Preflight/MR0 | 20,105,080,832 | 981,991,424 | 1,518,862,336 | 21,623,943,168 | 5,270,658,252 |

The corresponding plan digests are:

```text
AuthorizeBuild  9c73127d0a0427a2eb7123cdeb6ad3e2f607470c9e4826635d3fefd7c1bd06b6
BeginBuild      e88392b45df3e7b1b20de77945b6162a557b416327d13c8a94215aa6cd0f63eb
AuthorizeReady  acc9bf2b822abacc067085326c0ff54fadf7b133441b906d93eae1fb4608cd5b
Install         e597a522005aed2ce58866dbdd4bf11db7d5b8856c2e6198fad1ce280b398c6d
Preflight       c48795b7c219390d0a1ea8fec2bc476f6bcafe87c813a93e5397556152c63645
```

The phase-capacity amendment was registered before the successful run and is
frozen at SHA-256
`2132BA29A6449BF26C909A95450F63F952C997B653AE15CEB5D31DAB74AAEF51`.

## Failure-to-success audit trail

1. The first attempt was blocked by whole-lifecycle capacity admission before
   any DFT artifact or HE object existed.
2. The second attempt completed artifact construction and installation, then
   blocked before MR0 because preflight re-added the entire from-zero 7.843 GB
   requirement to already resident objects. It produced the phase-capacity
   amendment; the 80% limit and guard policy were not relaxed.
3. The third attempt crossed all capacity gates and executed Trace/C2S, then
   rejected its report because implementation validation compared the
   source-ordered Galois events with the sorted key set. The pre-existing
   observed-Trace design already forbade this sorting. An independent
   `5^rotation mod 2N` red test exposed the mismatch.
4. The accepted attempt used the corrected event pairs, passed all live gates,
   retired the evaluator before diagnostic decryption and emitted the frozen
   JSON result.

No failed attempt emitted an accepted result file. Each process exit destroyed
its private artifact, keys and evaluator; a later attempt necessarily rebuilt
them.

## Claim boundary

This result establishes that the local Lattigo fork can construct the exact
256-bit Route-B DFT factors once, authenticate them while resident, transfer
them into a prebuilt evaluator without a second matrix build, generate and
validate the exact key inventory, execute sparse observed ModUp/Trace and C2S,
and stay below the registered live-memory boundary.

The decrypted zero-prefix diagnostic has
`max_abs=0.37500000002891437`; its first eight real values lie near multiples
of `1/16`, with imaginary parts below `4.6e-11`. This prefix deliberately omits
EvalMod, so the diagnostic proves finite decryptability, sparse layout and
level flow—not zero-message preservation or integer-operator correctness.

The run does not establish Gao's source-faithful 8,192-word throughput,
complete EvalMod, A2A/A2B/B2A correctness, private decision-tree correctness,
security level or comparative performance. Those remain subsequent gates.

