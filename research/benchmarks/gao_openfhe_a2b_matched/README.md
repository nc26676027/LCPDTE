# Matched Gao/OpenFHE 8-bit A2B benchmark

This driver tests Gao--Zheng's `FHEZImpl::EvalArithToBooleanSparse` at the same
logical shape as the Lattigo Route-B workload. It emits a benchmark artifact
only if the pinned upstream implementation passes the warmup and all timed
correctness checks.

The candidate benchmark shape is:

- ring dimension: 65,536;
- 512 useful 8-bit words (`0..255`, repeated twice);
- 2,048 arithmetic input complex slots;
- one sparse Boolean output ciphertext;
- one OpenMP thread;
- setup, key generation, precomputation, encoding and encryption outside the
  online timer;
- one correctness warmup followed by five separately timed calls;
- all 4,096 logical result bits checked after every call, outside the timer.

At pinned commit `08f1eb87434e7be072cba889270a8400bbffc08e`, the
512-word sparse warmup currently fails correctness. The driver therefore exits
before collecting timed samples and does not publish a benchmark artifact.
Gao's canonical full-packing A2B remains the valid OpenFHE performance baseline.

The source checkout is pinned to
`08f1eb87434e7be072cba889270a8400bbffc08e`. The build helper copies the
tracked driver into the ignored clean-source example directory so it links with
the existing Release/HEXL/native `build-acceptance/clean-build` configuration.
It does not edit the pinned OpenFHE implementation.

From PowerShell, build without running the heavy benchmark:

```powershell
wsl.exe bash -lc "cd /mnt/d/WorkSpace/LCPDTE && bash research/benchmarks/gao_openfhe_a2b_matched/build_wsl.sh"
```

Run the benchmark and write its canonical-v2 artifact:

```powershell
wsl.exe bash -lc "cd /mnt/d/WorkSpace/LCPDTE && mkdir -p research/benchmarks/gao_openfhe_a2b_matched/results && bash research/benchmarks/gao_openfhe_a2b_matched/run_wsl.sh -host-id ryzen-7-h-255 -out research/benchmarks/gao_openfhe_a2b_matched/results/openfhe.json"
```

Validate the result:

```powershell
wsl.exe bash -lc "cd /mnt/d/WorkSpace/LCPDTE && python3 research/benchmarks/gao_openfhe_a2b_matched/validate_output.py research/benchmarks/gao_openfhe_a2b_matched/results/openfhe.json"
```

The setup duration is reported as `setup_nanoseconds`; the five online samples
are reported as `timed_samples_nanoseconds`. `warmup_verified` records the
separate correctness warmup, while `verified_evaluations=5` records that every
timed result was also checked.
