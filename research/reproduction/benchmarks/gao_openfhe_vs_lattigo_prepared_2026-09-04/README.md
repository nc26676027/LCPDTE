# Prepared Route-B A2B benchmark, 2026-09-04

This run diagnoses the earlier Lattigo/OpenFHE gap with reusable evaluators,
raw samples, correctness checks after every call, and explicit packing
metadata. Both implementations ran serially in the same WSL2 instance on an
AMD Ryzen 7 H 255. Lattigo used Go 1.23.11; OpenFHE used Ubuntu Clang 14 in
Release mode with Intel HEXL and native optimizations.

## Result

| implementation | native useful words | untimed setup envelope | online mean | median | range | native throughput | max RSS |
|---|---:|---:|---:|---:|---:|---:|---:|
| Lattigo Route-B sparse L11 | 512 | 37.674 s | 25.224348 s | 25.080238 s | 24.436183--26.298586 s | 20.297849 words/s | 14.40 GiB |
| Gao/OpenFHE canonical full | 8,192 | 148.275 s | 22.039306 s | 22.027394 s | 21.505279--22.612969 s | 371.699539 words/s | 22.95 GiB |

The repaired Lattigo prepared-online mean is 22.85% lower than the previous
32.693328-second cold one-shot result. At each implementation's native packing,
OpenFHE's full call is 12.63% lower latency. Its 18.31x throughput figure is
not a matched-workload speedup: the full OpenFHE configuration carries 16x as
many useful words per call.

The raw online samples, in nanoseconds, are:

```text
Lattigo:     25080237627 26298585630 24436183473 25039048162 25267682842
Gao/OpenFHE: 21505279292 21592824670 22458065312 22027393699 22612968783
```

Every warmup and all five measured calls produced zero mismatches. Setup,
encryption, decryption, result verification, and Lattigo's one-time circuit
preparation are outside the online samples.

## Why the old comparison looked too slow

The old Lattigo path rebuilt immutable circuit material and bound both Gao
kernels inside a one-shot call. The repaired server prepares those objects on
the first call and reuses them for later sequential evaluations. Prepared
requests also no longer re-hash the 2.64-GiB resident DFT artifact or validate
the same full result report twice. They reuse the first operation's capacity
admission instead of forcing Go to return reusable heap pages to the OS before
every sample. Installation and the first operation still perform the complete
validation and capacity gate.

A tracked two-call [CPU profile](PROFILE.md) shows that copies, equality checks,
trace snapshots, and state bookkeeping account for less than 1% of
Lattigo's online time.
The actual online hotspots are the two STC/CTS and ModRaise/Trace stages plus
the two Gao polynomial kernels. OpenFHE's full path additionally uses a 32,768
complex-slot layout and optimized C++/HEXL arithmetic, while this Lattigo path
uses 2,048 complex slots and pure-Go NTT/Montgomery kernels. A faster generic
Lattigo bootstrap therefore does not imply that this complete two-round,
packing-adapted integer circuit must beat Gao's native full configuration.

## Matched-shape admission

The focused OpenFHE sparse driver uses the same `N=65536`, 512 useful words,
2,048 complex slots, `zN=8`, and `w=4` as Lattigo. Its independent sparse
encoder/decryptor self-check passes all 4,096 bits, but pinned upstream commit
`08f1eb87434e7be072cba889270a8400bbffc08e` fails the A2B warmup with 2,107 of
4,096 bits mismatching. It exits before timed samples and emits no artifact.

Consequently there is no valid shape-matched performance ratio. The strict
comparator also rejects the two successful native artifacts with:

```text
packing_slots mismatch: OpenFHE=32768 Lattigo=2048
```

This prevents native packing throughput from being mislabeled as an
implementation speedup.

## Reproduction

Lattigo:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && env GOMAXPROCS=1 go run ./cmd/benchmark-ckksint-a2b -host-id laptop-a8eol5vm-wsl2 -out research/reproduction/benchmarks/gao_openfhe_vs_lattigo_prepared_2026-09-04/lattigo.json'
```

Gao/OpenFHE canonical full:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && env GAO_BUILD_JOBS=1 bash research/benchmarks/gao_openfhe_a2b_full/run_wsl.sh -host-id laptop-a8eol5vm-wsl2 -out research/reproduction/benchmarks/gao_openfhe_vs_lattigo_prepared_2026-09-04/openfhe-full.json'
```

Matched sparse correctness gate:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && env GAO_BUILD_JOBS=1 bash research/benchmarks/gao_openfhe_a2b_matched/run_wsl.sh -host-id laptop-a8eol5vm-wsl2 -out research/benchmarks/gao_openfhe_a2b_matched/results/openfhe.json'
```

The canonical JSON files contain the complete protocol identities and raw
samples. The adjacent `.time` files record whole-process resource usage.
