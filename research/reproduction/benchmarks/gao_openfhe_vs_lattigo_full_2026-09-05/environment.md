# Acceptance environment

## Host and toolchains

- Physical CPU: AMD Ryzen 7 H 255 with Radeon 780M Graphics; 16 logical CPUs exposed to WSL.
- WSL: Ubuntu 22.04.5 LTS, kernel `6.18.33.1-microsoft-standard-WSL2`, x86_64.
- WSL limit: 24 GiB memory and 8 GiB swap (`C:\Users\26676\.wslconfig`).
- Linux memory view: `MemTotal=24,608,408 KiB`, `SwapTotal=8,388,608 KiB`.
- Go: `go1.23.11 linux/amd64`; compiler `gc`; Lattigo build used `GOAMD64=v4`.
- C++: `/usr/bin/clang++`, Ubuntu Clang 14.0.0; OpenFHE 1.4.0 with Intel HEXL
  1.2.6, Release, `-march=native -O3 -DNDEBUG`, native optimization and one OpenMP thread.

## Source and binary identity

- LCPDTE source revision: `cda2a24a57a8ba1a6d36bd24c7b48bb1c400e07a`;
  `vcs.modified=false` in the built binary.
- Lattigo benchmark runtime/compiler: `go1.23.11` / `gc`.
- Lattigo benchmark binary SHA-256:
  `f4ddf602278207757ffbf510220cf7e82df9edca5066248a4b520dbdc3727a00`.
- Pinned fhe-simd-alu source revision:
  `08f1eb87434e7be072cba889270a8400bbffc08e`; clean before and after driver injection.
- OpenFHE runtime/compiler: `OpenFHE-1.4.0;HEXL-1.2.6` /
  `/usr/bin/clang++ :: Ubuntu clang version 14.0.0-1ubuntu1.1`.
- Focused OpenFHE driver SHA-256:
  `da65098414828ce59b35965a5fb13732a8fcbb76a238127d6d98bbb9d2c388a6`.
- Focused OpenFHE binary SHA-256:
  `b5b6b4518fecf56ee3e539cabde30cfb25b33674a5fd3f36c7f5b43fee90118c`.

The source revisions, runtimes, compilers and build profiles above are also embedded in
the two benchmark JSON artifacts. The OpenFHE driver and executable hashes are bound by
`gao-openfhe-a2b-full.build-stamp` and revalidated by the run script.

## UTC sequence

1. Lattigo clean build: `2026-09-04T18:55:27Z`–`2026-09-04T18:55:35Z`.
2. Local OpenFHE rebuild and SHA validation: `2026-09-04T18:55:48Z`–`2026-09-04T18:56:33Z`.
3. OpenFHE benchmark: `2026-09-04T18:56:48Z`–`2026-09-04T19:04:30Z`.
4. Lattigo benchmark: `2026-09-04T19:04:55Z`–`2026-09-04T19:09:11Z`.

Both binaries were therefore ready after the local OpenFHE rebuild, and the measured
producer processes ran serially in the required OpenFHE→Lattigo order without concurrent
repository tests or other benchmark workloads.

## Measured lifecycle resources

| Phase | Wall time | Maximum RSS | Exit status |
|---|---:|---:|---:|
| OpenFHE rebuild | 0:45.79 | 314,924 KiB | 0 |
| Lattigo build | 0:08.33 | 217,368 KiB | 0 |
| OpenFHE benchmark process | 7:42.65 | 24,014,088 KiB | 0 |
| Lattigo benchmark process | 4:15.59 | 16,496,620 KiB | 0 |

The whole-process values include setup, the verified warmup, five timed-and-verified
evaluations and producer overhead. They are recorded separately from the prepared-online
sample statistics. OpenFHE setup was `147.090130973 s`; Lattigo setup was
`111.388395217 s`.

## Exact comparison identity

Both artifacts use `n65536-cslots32768-zslots8192-w4`: 32,768 complex slots pack 8,192
8-bit words and produce two ciphertexts carrying low4/high4 outputs. Their ordered Q/P
chains are identical (Q `21/904 bits`, P `7/350 bits`), and actual first Q is 44 bits on
both backends. Both use sigma 3.19 and effective integer bound 39. OpenFHE retains its
native DGG with `error_configured_bound=null`; Lattigo retains its bounded discrete
Gaussian with `error_configured_bound=39`. This native field difference does not change
the matched effective bound used by the strict comparator.
