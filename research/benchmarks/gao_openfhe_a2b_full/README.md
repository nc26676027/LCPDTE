# Canonical Gao/OpenFHE full 8-bit A2B benchmark

This focused driver measures Gao--Zheng's canonical
`FHEZImpl::EvalArithToBooleanFull` workload. It emits an artifact only after a
correctness warmup and five independently timed and verified evaluations.

The fixed benchmark shape is:

- pinned source commit `08f1eb87434e7be072cba889270a8400bbffc08e`;
- ring dimension 65,536, `zN=8`, `zSlots=8192`, `w=4`, cutoff `-24`;
- 8,192 useful 8-bit words (`0..255`, repeated 32 times);
- 32,768 complex packing slots and two full Boolean output ciphertexts;
- one OpenMP thread;
- setup, key generation, bootstrapping precomputation, encoding and encryption
  outside the online timer;
- one correctness warmup followed by five separately timed evaluations;
- official `PKEZImpl::Decrypt` reconstruction and all 65,536 result bits
  checked after every evaluation, outside the timer.

The build helper copies the tracked driver into the ignored clean-source
example directory and links it with the existing Release/HEXL/native
`build-acceptance/clean-build` configuration. It does not modify the pinned
OpenFHE implementation.

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
