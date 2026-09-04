# Canonical Lattigo A2B benchmark

This command runs the Lattigo side of the matched Gao/OpenFHE 8-bit A2B
benchmark through the public `ckksint` API:

```powershell
go run ./cmd/benchmark-ckksint-a2b `
  -host-id <stable-host-id> `
  -out lattigo-a2b.json
```

The workload is 8,192 bytes (`0..255` repeated 32 times) at `N=65536`. Every
input occupies all 32,768 complex slots and each evaluation returns two
ciphertexts containing low bits 0--3 and high bits 4--7. The command encrypts
once with a public key, performs one verified warmup, and then records five
separately verified evaluations. All 65,536 output bits must match.

Each timed sample is the complete public `EvaluateA2B` server-call wall time.
Parameter construction, keys, resident/prevalidated DFT factors, encryption,
decryption, and correctness checks remain outside the prepared-online samples.
The process fixes `GOMAXPROCS=1` while it runs.

`setup_nanoseconds` is the complete untimed envelope before the warmup:
parameters, public/secret keys, reusable server construction, resident factor
preparation, and encryption. The warmup is excluded from that field.

The artifact derives packing and modulus-chain fields from the live session and
records the Go VCS revision, clean/modified flag, runtime, compiler, build
profile, OS, architecture, scale schedule, factor-storage mode, and the actual
Lattigo BSGS plan. The command refuses to benchmark a dirty build.

For comparison, build and run this command inside the same WSL/Linux environment
used by the OpenFHE driver, immediately after the local OpenFHE run, and use the
same `-host-id`. `compare-ckksint` rejects different host/OS/architecture,
packing, parameters, output shape, timing protocol, or correctness status, and
passes only when both Lattigo/OpenFHE mean and median ratios are at most 1.
