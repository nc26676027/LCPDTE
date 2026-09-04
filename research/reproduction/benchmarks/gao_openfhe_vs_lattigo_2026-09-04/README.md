# Gao/OpenFHE versus Lattigo Route-B: complete 8-bit A2B

This acceptance case compares the complete 8-bit arithmetic-to-Boolean call at
the same CKKS ring dimension (`N=65536`). It records both call latency and
effective packed-integer throughput because the two implementations use
different lane counts.

## Replay the tracked comparison

From the repository root:

```powershell
go run ./cmd/compare-ckksint `
  -openfhe-log research/reproduction/benchmarks/gao_openfhe_vs_lattigo_2026-09-04/gao_openfhe_bench8_local.log `
  -lattigo-json research/reproduction/benchmarks/gao_openfhe_vs_lattigo_2026-09-04/lattigo_route_b_a2b_local.json `
  -out research/reproduction/benchmarks/gao_openfhe_vs_lattigo_2026-09-04/comparison_replayed.json
```

The command exits nonzero when the word width or ring dimension differs, when
the Gao correctness warmup is absent or contains `Error in ...`, or when the
Lattigo artifact reports a mismatch. It also requires the canonical Route-B
shape: `LogN=16`, `PackingSlots=2048`, `WordBits=8`, `WordCapacity=512`, and
`input_words=WordCapacity`.

## Same-host result

Both implementations were executed sequentially in Ubuntu 22.04.5 on WSL2 on
the same Ryzen 7 H 255 host. OpenFHE used `OMP_NUM_THREADS=1`; Lattigo used
`GOMAXPROCS=1`. Both runs used `N=65536` and complete 8-bit A2B.

| Implementation | Complete A2B | Packed integers | Effective throughput | Peak RSS | Result |
|---|---:|---:|---:|---:|---|
| Gao et al. OpenFHE | 19.5693 s | 8,192 | 418.614871 words/s | 22.94 GiB | exit 0, no `Error in` |
| Lattigo Route-B | 32.693327852 s | 512 | 15.660688 words/s | 12.11 GiB | exit 0, 0 mismatches |

OpenFHE completed one call `1.670644x` faster and delivered `26.730299x` the
effective packed-integer throughput. The throughput ratio combines the
`16x` packing difference with the call-latency ratio.

The machine-readable result is `comparison_same_host.json`. The preserved
OpenFHE log and resource record are `gao_openfhe_bench8_local.log` and
`gao_openfhe_bench8_local_time.txt`; the corresponding Lattigo console and
resource records are `lattigo_route_b_a2b_local_stdout.txt` and
`lattigo_route_b_a2b_local_time.txt`. The complete Lattigo result envelope is
`lattigo_route_b_a2b_local.json`.

The local Lattigo raw JSON reported `low_max_error=1.13697188e-7`,
`high_max_error=1.14325848e-7`, `imag_max=8.59127848e-11`, and zero
mismatches. Its SHA-256 is
`8870ed61206be72ec19fac057f9157c4df0d98f8b4d35970c9fd46d87994400b`.

## Build and machine record

Both measurements ran under Ubuntu 22.04.5 LTS on WSL2, Linux
`6.18.33.1-microsoft-standard-WSL2`, on an AMD Ryzen 7 H 255 with Radeon 780M
Graphics (8 cores, 16 hardware threads). The WSL VM exposed 23 GiB RAM and
8 GiB swap. The runs were sequential.

The Gao/OpenFHE source checkout was commit
`08f1eb87434e7be072cba889270a8400bbffc08e`. Its pinned submodules were:

| Submodule | Commit |
|---|---|
| `third-party/cereal` | `984e3f194862b17916536b5fade40cba6e47a6fe` |
| `third-party/google-benchmark` | `eddb0241389718a23a42db6af5f0164b6e0139af` |
| `third-party/google-test` | `52eb8108c5bdec04579160ae17225d66034bd723` |
| `third-party/gperftools` | `83edb60836d87cf1b406e8846b9059c03031e8f5` |

OpenFHE was compiled with Ubuntu Clang/Clang++ 14.0.0 in Release mode
(`-O3 -DNDEBUG`), 64-bit native integers, math backend 6, native
optimizations, NTL, tcmalloc, OpenMP, and Intel HEXL enabled. Examples,
benchmarks, and unit tests were enabled. The timed command fixed OpenMP to one
thread:

```bash
cd /mnt/d/WorkSpace/LCPDTE/research/upstream/fhe-simd-alu/build-acceptance/clean-build
/usr/bin/time -v -o bench-time.txt \
  env OMP_NUM_THREADS=1 ./bin/examples/pke/benchmark-full 8 bench \
  > bench.log
```

The Lattigo runner was `cmd/route-b-l11-a2b-full` at LCPDTE HEAD
`2619d31cba960896cd406452675cd551993bdcd9`, using the repository's patched
Lattigo v6.1.1 source and Go 1.23.11 linux/amd64. Its single-process run fixed
the Go scheduler to one logical processor:

```bash
cd /mnt/d/WorkSpace/LCPDTE
/usr/bin/time -v \
  -o research/upstream/fhe-simd-alu/build-acceptance/lattigo-wsl-a2b.time.log \
  env GOMAXPROCS=1 /home/niuchao/.local/bin/go run ./cmd/route-b-l11-a2b-full \
  -out /mnt/d/WorkSpace/LCPDTE/research/upstream/fhe-simd-alu/build-acceptance/lattigo-wsl-a2b.json \
  > research/upstream/fhe-simd-alu/build-acceptance/lattigo-wsl-a2b.stdout.log \
  2> research/upstream/fhe-simd-alu/build-acceptance/lattigo-wsl-a2b.stderr.log
```

The raw benchmark command reported zero mismatches; the comparison tool reads
the complete tracked JSON, checks its canonical shape, and computes throughput
from its 512 input words and measured complete-A2B wall time.

## Source-artifact result

| Implementation | Complete A2B | Packed integers | Effective throughput | Timing protocol |
|---|---:|---:|---:|---|
| Gao et al. OpenFHE | 10.1368 s | 8,192 | 808.144582 words/s | 1 correctness warmup, mean of 5 calls |
| Lattigo Route-B | 25.8302408 s | 512 | 19.821728 words/s | 1 measured call |

For these artifacts, OpenFHE completes the call `2.548165x` faster and delivers
`40.770643x` the effective packed-integer throughput. The source-artifact table
is retained separately from the same-host table above.

`gao_openfhe_bench8_source.log` preserves the pinned Gao et al. checkout's log
content with line endings and trailing spaces normalized. The source checkout
is commit `08f1eb87434e7be072cba889270a8400bbffc08e`; the raw log SHA-256 is
`3deaa36302df252cf5011204eb36416ccc1fbb1c2dbee255aff874918ef07b7e`.
The Lattigo input is the canonical zero-mismatch Route-B artifact generated on
the current acceptance host. `comparison_source_artifacts.json` is the stable
machine output for these two inputs.
