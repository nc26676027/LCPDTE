# Lattigo prepared-A2B CPU profile

The profile covers setup, the first prepared evaluation, and one reuse of the
same public `ckksint` evaluator before the steady-state validation cleanup. It
was generated from the repository root with:

```powershell
$env:LCPDTE_ROUTE_B_A2B_E2E = "1"
go test -run '^TestCanonicalRouteBA2BReusesPreparedEvaluator$' -count=1 -timeout=10m -cpuprofile "$env:TEMP\lcpdte_a2b_cpu.pprof" ./ckksint
Remove-Item Env:LCPDTE_ROUTE_B_A2B_E2E
```

The test passed in 88.199 seconds. The profile duration is 86.22 seconds with
85.35 seconds of CPU samples. Inspect the tracked profile with:

```powershell
go tool pprof -top -cum research/reproduction/benchmarks/gao_openfhe_vs_lattigo_prepared_2026-09-04/lattigo_a2b_cpu.pprof
go tool pprof -list='routeBA2BFullPreparedEvaluator.*evaluateNew' research/reproduction/benchmarks/gao_openfhe_vs_lattigo_prepared_2026-09-04/lattigo_a2b_cpu.pprof
go tool pprof -list='RunSparseA2BFull' research/reproduction/benchmarks/gao_openfhe_vs_lattigo_prepared_2026-09-04/lattigo_a2b_cpu.pprof
go tool pprof -list='runOperationalA2BFullWithHooks' research/reproduction/benchmarks/gao_openfhe_vs_lattigo_prepared_2026-09-04/lattigo_a2b_cpu.pprof
```

Selected cumulative samples across the two evaluations:

```text
routeBA2BFullPreparedEvaluator.evaluateNew  47.08s
runCanonicalRouteBFirstSparseMR0           18.87s
GaoA2BKernelN16L11Evaluator.EvaluateNew    15.63s
common/lintrans.Evaluator.EvaluateMany     21.09s
dft.Evaluator.dft                          20.07s
Ciphertext.CopyNew                          0.17s
RLWE Evaluator.RuntimeIdentitySnapshot      0.14s
```

Source-line attribution inside the two prepared evaluations:

```text
special ZToC             2.43s
iter0 STC                6.55s
iter0 MR0                9.45s
iter0 Gao kernel         7.66s
iter1 STC                1.39s
iter1 MR0                9.42s
iter1 Gao kernel         7.97s
retained Equal checks    0.01s
```

Before the steady-state cleanup, the wrapper also spent 1.50 seconds
revalidating the resident artifact and 0.91 seconds on a duplicate full-report
validation during the prepared repeat. Those calls were outside the reported
operator wall time and have been removed from subsequent prepared requests.

Profile SHA-256:
`b9d1cea6df550fb390f4c76ba5d59a9f8cdff5068ac77a7fa43c679587b90e56`.
