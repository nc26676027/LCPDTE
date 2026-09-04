# Canonical Gao/OpenFHE full 8-bit A2B benchmark

This focused driver measures Gao--Zheng's canonical
`FHEZImpl::EvalArithToBooleanFull` workload. It emits an artifact only after a
correctness warmup and five independently timed and verified evaluations.

The fixed benchmark shape is:

- pinned source commit `08f1eb87434e7be072cba889270a8400bbffc08e`;
- ring dimension 65,536, `zN=8`, `zSlots=8192`, `w=4`, cutoff `-24`;
- 8,192 useful 8-bit words (`0..255`, repeated 32 times);
- 32,768 complex packing slots and two full Boolean output ciphertexts;
- Gao parameter semantics: 21 Q moduli / 904 aggregate bits, 7 P moduli /
  350 aggregate bits, 43-bit scaling and first moduli, depth 20, 3 large
  digits, weight-32 ephemeral bootstrap key, level budget `[3,2]`, and BSGS
  request `[0,0]` (OpenFHE automatic selection);
- public-key encryption, resident bootstrap precomputation,
  `FLEXIBLEMANUAL`'s native scale schedule, and the recorded backend plan
  `openfhe-auto-dim1-0`;
- one OpenMP thread;
- setup, key generation, bootstrapping precomputation, encoding and encryption
  outside the online timer;
- one correctness warmup followed by five separately timed evaluations;
- official `PKEZImpl::Decrypt` reconstruction and all 65,536 result bits
  checked after every evaluation, outside the timer.

The build helper copies the tracked driver into the ignored clean-source
example directory and links it with the existing Release/HEXL/native/OpenMP
`build-acceptance/clean-build` configuration. It does not modify the pinned
OpenFHE implementation. `run_wsl.sh` rechecks the clean pinned revision, reads
the compiler and enabled build options from that CMake cache, and passes those
values to the driver for inclusion in the artifact together with the runtime,
OS, and architecture.

From PowerShell, compile without running the heavy benchmark:

```powershell
wsl.exe bash -lc "cd /mnt/d/WorkSpace/LCPDTE && bash research/benchmarks/gao_openfhe_a2b_full/build_wsl.sh"
```

Run the benchmark and write its canonical-v2 artifact:

```powershell
wsl.exe bash -lc "cd /mnt/d/WorkSpace/LCPDTE && mkdir -p research/benchmarks/gao_openfhe_a2b_full/results && bash research/benchmarks/gao_openfhe_a2b_full/run_wsl.sh -host-id ryzen-7-h-255 -out research/benchmarks/gao_openfhe_a2b_full/results/openfhe-full.json"
```

Validate a result:

```powershell
wsl.exe bash -lc "cd /mnt/d/WorkSpace/LCPDTE && python3 research/benchmarks/gao_openfhe_a2b_full/validate_output.py research/benchmarks/gao_openfhe_a2b_full/results/openfhe-full.json"
```

`setup_nanoseconds` records the untimed preparation. The five server-side
evaluation samples are in `timed_samples_nanoseconds`; decryption and
verification are excluded from those samples.

For an admitted comparison, run this OpenFHE benchmark locally immediately
before the final Lattigo run, use the same physical host identifier and one
thread for both, then compare the two validated JSON files:

```powershell
go run ./cmd/compare-ckksint -openfhe-json <openfhe.json> -lattigo-json <lattigo.json> -out <comparison.json>
```

The command recomputes mean, median, and useful-word throughput from the five
verified samples. It exits nonzero unless both Lattigo/OpenFHE latency ratios
are at most 1. The parameter match covers algorithm settings and aggregate
modulus bit lengths. Both backends implement the same mathematical DFT target
with their native scale schedules and execution plans; the comparison does not
assert identical generated RNS primes or identical backend BSGS decompositions.
The admitted Lattigo artifact records its live optimized plan as
`lattigo-dft-log-bsgs-ratio-2-special-b0-ratio-2-live-output-optimized`, while
the OpenFHE artifact records `openfhe-auto-dim1-0`.
