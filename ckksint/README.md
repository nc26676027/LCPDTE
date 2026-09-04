# `ckksint`

`ckksint` is the supported library boundary for packed modular integers over
Lattigo CKKS. Applications import this package instead of assembling research
graphs from `integer/homchain` or `integer/secureeval`.

The patched Lattigo v6.1.1 implementation is part of this Go module under
`github.com/nc26676027/LCPDTE/lattigo`, so consumers do not need this
repository's `vendor` mode or a separate fork replacement.

## API map

- `Context` provides packed `Z/(2^n)` arithmetic for `n = 8, 16, 32, 64`:
  encryption/decryption, add, subtract, negate, public add/subtract, full
  multiply, and arithmetic-by-short multiply.
- `Functional8` provides a compact four-word profile for A2B, B2A, signed
  public-threshold comparison, and selected-child depth-2 evaluation.
- `NewCanonicalRouteBA2B` provides reusable full 8-bit A2B for batches of
  1--512 bytes as separate client and server objects.
- `NewGaoFullPackedA2B` provides Gao-compatible full-packed A2B for 1--8,192
  bytes in all 32,768 complex slots, returning separate low4/high4
  ciphertexts. Short batches use zero padding; the canonical 8,192-word batch
  is never repeated.
- `NewCanonicalRouteBDepth2` provides the full Gao-compatible N=2^16,
  logSlots=11 Route-B workflow as separate client and server objects.
- `LattigoCiphertext`, `LattigoHalves`, `ImportTrustedCiphertext`, and
  `LattigoParameters` are explicit copy boundaries for Lattigo interoperation.

## Canonical Route-B A2B workflow

```go
client, server, setup, err := ckksint.NewCanonicalRouteBA2B()
if err != nil {
    return err
}
defer server.Close()

input, encryption, err := client.EncryptA2B([]uint8{0, 1, 15, 16, 127, 255})
if err != nil {
    return err
}
output, evaluation, err := server.EvaluateA2B(input)
if err != nil {
    return err
}
bits, decryption, err := client.DecryptA2B(output)
if err != nil {
    return err
}

_, _, _, _, _ = setup, encryption, evaluation, decryption, bits
```

The first evaluation prepares the immutable circuit and reports that cost in
`PreparationWallTime`. Later calls reuse the same evaluator and report zero
preparation time. `OnlineWallTime` covers the homomorphic A2B graph;
`WallTime` covers the complete public server call. Run the executable example
with `go run ./examples/ckksint/routeb_a2b`.

## Gao full-packed A2B workflow

This API matches the Gao/OpenFHE benchmark shape: `N=65536`, `logSlots=15`,
`zN=8`, `zSlots=8192`, and `w=4`. Construction prepares the full reusable
server graph, so every evaluation reports zero `PreparationWallTime` and its
homomorphic interval in `OnlineWallTime`.

```go
client, server, setup, err := ckksint.NewGaoFullPackedA2B()
if err != nil {
    return err
}
defer server.Close()

words := make([]uint8, ckksint.GaoFullPackedA2BMaxWords)
for i := range words {
    words[i] = uint8(i)
}
input, encryption, err := client.EncryptA2B(words)
if err != nil {
    return err
}
output, evaluation, err := server.EvaluateA2B(input)
if err != nil {
    return err
}
bits, decryption, err := client.DecryptA2B(output)
if err != nil {
    return err
}

_, _, _, _, _ = setup, encryption, evaluation, decryption, bits
```

Run the verified end-to-end example from the repository root:

```powershell
go run ./examples/ckksint/gao_full_a2b
```

It evaluates the canonical `0..255` sequence repeated 32 times, verifies all
65,536 result bits, and exits nonzero on any mismatch. It prints setup,
prepared-online time, throughput, and the mismatch count.

## Canonical Route-B depth-2 workflow

Inputs are feature-major: `features[featureID][query]`. A `Depth2Model` supplies
the three internal-node feature IDs and thresholds plus four real leaves. One
session evaluates one batch of 1--512 signed-int8 queries; smaller batches are
padded internally and trimmed after decryption.

```go
request, err := ckksint.ValidateCanonicalRouteBDepth2Request(features, model)
if err != nil {
    return err
}

client, server, setup, err := ckksint.NewCanonicalRouteBDepth2()
if err != nil {
    return err
}
defer server.Close()

encrypted, encryption, err := client.EncryptDepth2(features, model)
if err != nil {
    return err
}
evaluated, evaluation, err := server.EvaluateDepth2(encrypted)
if err != nil {
    return err
}
values, decryption, err := client.DecryptDepth2(evaluated)
if err != nil {
    return err
}

_, _, _, _, _ = request, setup, encryption, evaluation, decryption
_ = values
```

The client owns encoding, encryption, decryption, and secret-key state. The
server owns the installed evaluator. Requests and results are opaque and bound
to the session that created them. Setup and all three online calls return
wall-clock timing records; evaluation also returns the circuit trace digest.

Run the complete executable example:

```powershell
go run ./examples/ckksint/routeb_depth2
```

It covers all four tree paths, checks equality behavior at all three nodes,
compares every decrypted value with an independent plaintext evaluator, and
prints setup, encryption, evaluation, decryption, effective-query/s,
packed-query/s, maximum error, and mismatch count. The recorded 2026-09-04 run
finished in 106.18 seconds with maximum error `2.88e-7` and zero mismatches.

## Gao/OpenFHE A2B comparison

Generate the Lattigo side from the repository root:

```powershell
go run ./cmd/benchmark-ckksint-a2b -host-id <host-id> -out lattigo-a2b.json
```

The canonical Gao/OpenFHE driver is in
`research/benchmarks/gao_openfhe_a2b_full`. Both implementations evaluate the
same 8,192-word input (`0..255` repeated 32 times), use all 32,768 complex
slots at `N=65536`, return low4/high4 ciphertexts, and verify all 65,536 bits
after one warmup and each of five timed calls.

`compare-ckksint` accepts only two verified canonical-v3 artifacts with
identical protocol, workload, packing, host, single-thread setting, and
warmup/repeat policy:

```powershell
go run ./cmd/compare-ckksint `
  -openfhe-json openfhe-matched.json `
  -lattigo-json lattigo-a2b.json `
  -out comparison.json
```

Run both producers serially on the same physical machine and in the same WSL
environment, with the OpenFHE run immediately before the final Lattigo run.
The artifacts bind both the shared Gao algorithm contract and each backend's
native parameters: complete Q/P modulus chains, actual first-Q width, main and
ephemeral secret distributions, error sampler, key-switch decomposition and
security selector/evidence. They also bind public-key encryption, resident
transform factors, backend-native scale/BSGS plans, clean source revisions,
compiler/runtime/build profile, OS and architecture. The comparator passes only
when both the Lattigo/OpenFHE mean and median latency ratios are at most 1.
The Lattigo full-packed artifact reports `full-packed-profile-not-assessed`;
the separate C75 `CONDITIONAL-PASS` remains bound to its selected-child circuit
and is not reused as evidence for this benchmark profile.

The accepted 2026-09-05 same-host run is preserved in
[`research/reproduction/benchmarks/gao_openfhe_vs_lattigo_full_2026-09-05`](../research/reproduction/benchmarks/gao_openfhe_vs_lattigo_full_2026-09-05):
Lattigo/OpenFHE mean and median latency ratios are `0.973112` and `0.950047`,
and all five evaluations on both backends have zero bit mismatches.

## Profiles and interoperation

`NewDemo` and `NewDemoFunctional8` use small profiles intended for examples and
unit tests. `NewCanonicalRouteBDepth2` uses the fixed Route-B N=2^16 parameter,
artifact, and evaluation-key lifecycle.

For an application-supplied arithmetic profile, construct `Parameters` and
`KeyMaterial` and call `New`. `SecurityBoundary` records how that tuple was
validated by the caller.

`Value` and `ShortValue` belong to the context that created them. Lattigo
interop accessors return detached copies. `ImportTrustedCiphertext` is the
explicit boundary for importing a ciphertext that already uses the destination
context's keys and packing.

Signed comparison requires a `Signed8Range` whose complete difference interval
fits in int8. Branch convention is `0 = <` and `1 = >=`. A B2A result is
decryptable but is not a fresh A2B/comparison input. One `Context` must not be
used concurrently because its evaluator owns scratch state; `Functional8` and
the Route-B session serialize their public calls.

## Tests

```powershell
go test -count=1 ./ckksint ./integer/secureeval
go test -count=1 ./internal/benchcmp ./cmd/compare-ckksint ./cmd/benchmark-ckksint-a2b
go test -mod=mod -count=1 ./ckksint -run TestExternalModuleImportsCKKSIntWithoutVendor
```

The real Route-B test is opt-in because it executes the full N=2^16 graph:

```powershell
$env:LCPDTE_ROUTE_B_E2E = "1"
go test -count=1 ./ckksint -run TestCanonicalRouteBDepth2EndToEnd -v
Remove-Item Env:LCPDTE_ROUTE_B_E2E
```

The reusable A2B acceptance test is also opt-in:

```powershell
$env:LCPDTE_ROUTE_B_A2B_E2E = "1"
go test -count=1 ./ckksint -run TestCanonicalRouteBA2BReusesPreparedEvaluator -v
Remove-Item Env:LCPDTE_ROUTE_B_A2B_E2E
```

The Gao full-packed acceptance test uses all 8,192 words and is opt-in:

```powershell
$env:LCPDTE_GAO_FULL_A2B_E2E = "1"
go test -count=1 ./ckksint -run TestGaoFullPackedA2BEndToEnd -v
Remove-Item Env:LCPDTE_GAO_FULL_A2B_E2E
```
