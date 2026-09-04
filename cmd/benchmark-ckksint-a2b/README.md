# Canonical Lattigo A2B benchmark

This command runs the Lattigo side of the matched Gao/OpenFHE 8-bit A2B
benchmark through the public `ckksint` API:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && GOAMD64=v4 go build -o /tmp/lcpdte-benchmark-ckksint-a2b ./cmd/benchmark-ckksint-a2b'
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && GOAMD64=v4 GOMAXPROCS=1 GOGC=100 GOMEMLIMIT=20GiB POST_WARMUP_GC=on LCPDTE_GAO_CPU_PROFILE= /tmp/lcpdte-benchmark-ckksint-a2b -host-id local-wsl-host -out /tmp/lattigo-v3.json'
```

The workload is 8,192 bytes (`0..255` repeated 32 times) at `N=65536`. Every
input occupies all 32,768 complex slots and each evaluation returns two
ciphertexts containing low bits 0--3 and high bits 4--7. The command encrypts
once with a public key, performs one verified warmup, and then records five
separately verified evaluations. All 65,536 output bits must match.

Each timed sample is the complete public `EvaluateA2B` server-call wall time.
Parameter construction, keys, resident/prevalidated DFT factors, encryption,
decryption, and correctness checks remain outside the prepared-online samples.
The command admits only the fixed acceptance process profile
`GOAMD64=v4`, `GOMAXPROCS=1`, `GOGC=100`, `GOMEMLIMIT=20GiB`, and
`POST_WARMUP_GC=on`, with CPU profiling off. It verifies `GOAMD64=v4` from the executable's embedded
Go build settings, checks the live scheduler and GC/memory-limit state, and
requires `LCPDTE_GAO_CPU_PROFILE` to be empty. It exits before constructing the
HE session when any value differs. `POST_WARMUP_GC=on` enables the complete
fixed lifecycle: a collection runs after the verified warmup and between
consecutive verified timed samples. All collections, output release,
decryption, and validation are outside the timed
`EvaluateA2B` call; no separate inter-sample GC environment variable is needed.
The acceptance path uses an explicit `go build`: on this toolchain `go run`
does not embed the required `vcs.revision` and is rejected before setup.

`setup_nanoseconds` is the complete untimed envelope before the warmup:
parameters, public/secret keys, reusable server construction, resident factor
preparation, client encoder/session construction, and encryption. The warmup
is excluded from that field.

The v3 artifact derives packing and the complete ordered Q/P modulus chains
from the live session. Its shared `parameters` object records constructor
targets and matched semantics (including main/ephemeral secret weights and
key-switch decomposition settings). Its required `native_parameters` object
records the actual first-Q width, every decimal modulus and recomputed bit
length, the bounded Gaussian sampler, secret distributions, key-switch
technique, and the profile-specific security selector/evidence status. The
full-packed Lattigo path reports `full-packed-profile-not-assessed`; it does not
reuse the circuit-specific C75 `CONDITIONAL-PASS`. The comparison parser
recomputes chain counts and product bit lengths rather than trusting emitted
aggregates. Cross-backend comparison requires the exact ordered Q/P values,
namely all 21 Q and 7 P decimal moduli in order, with 904/350 aggregate bits,
43-bit scale/first-modulus requests, an actual 44-bit first Q, depth 20,
three large digits, H=192/H=32, sigma=3.19/effective bound=39, 3/0 RNS/base-two
decomposition, level budget `[3,2]`, automatic-BSGS request `[0,0]`, chunk
width 4, and cutoff -24. Backend-native sampling algorithms, key switching,
security selection, scale schedules, and planners remain explicit.

The artifact also records the Go VCS revision, clean/modified flag, runtime,
compiler, build profile, OS, architecture, scale schedule, factor-storage
mode, and the actual Lattigo BSGS plan. The command refuses to benchmark a
dirty build.

For comparison, build and run this command inside the same WSL/Linux environment
used by the OpenFHE driver, immediately after the local OpenFHE run, and use the
same `-host-id`. `compare-ckksint` rejects different host/OS/architecture,
packing, parameters, output shape, timing protocol, or correctness status, and
passes only when both Lattigo/OpenFHE mean and median ratios are at most 1.
