# `ckksint` canonical Route-B depth-2 acceptance

Run from the repository root:

```powershell
go run ./examples/ckksint/routeb_depth2
```

The 2026-09-04 acceptance run completed with exit code 0 in 106.183339
seconds. It exercised all four root/child paths, including equality at the
root, left child and right child. Decryption returned all four expected leaves
with maximum absolute error `2.88e-7`, zero mismatches and a non-empty circuit
trace digest.

The measured server evaluation time was 68.5201695 seconds. A 500 ms process
sampler observed a peak process-tree working set of 13.700573 GiB. `stdout.txt`
is the exact program output; `metrics.json` records the command, exit code,
wall time and memory sample.
