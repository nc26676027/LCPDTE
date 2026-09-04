# `ckksint`

`ckksint` is the supported library boundary for packed modular integers over
Lattigo CKKS. Applications import this package instead of assembling research
graphs from `integer/homchain` or `integer/secureeval`.

## API map

- `Context` provides packed `Z/(2^n)` arithmetic for `n = 8, 16, 32, 64`:
  encryption/decryption, add, subtract, negate, public add/subtract, full
  multiply, and arithmetic-by-short multiply.
- `Functional8` provides a compact four-word profile for A2B, B2A, signed
  public-threshold comparison, and selected-child depth-2 evaluation.
- `NewCanonicalRouteBDepth2` provides the full Gao-compatible N=2^16,
  logSlots=11 Route-B workflow as separate client and server objects.
- `LattigoCiphertext`, `LattigoHalves`, `ImportTrustedCiphertext`, and
  `LattigoParameters` are explicit copy boundaries for Lattigo interoperation.

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

From the repository root:

```powershell
go run ./cmd/compare-ckksint `
  -openfhe-log research/reproduction/benchmarks/gao_openfhe_vs_lattigo_2026-09-04/gao_openfhe_bench8_source.log `
  -lattigo-json research/reproduction/route_b/route_b_l11_a2b_full_2026-09-01.json `
  -out comparison.json
```

The command compares complete 8-bit A2B calls and reports both latency and
effective words/second. It also exposes the packing difference: Gao/OpenFHE
uses 8,192 lanes while the current Lattigo Route-B profile uses 512 words. An
OpenFHE `Error in ...` line or a nonzero Lattigo mismatch count fails the run.

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
go test -count=1 ./internal/benchcmp ./cmd/compare-ckksint
```

The real Route-B test is opt-in because it executes the full N=2^16 graph:

```powershell
$env:LCPDTE_ROUTE_B_E2E = "1"
go test -count=1 ./ckksint -run TestCanonicalRouteBDepth2EndToEnd -v
Remove-Item Env:LCPDTE_ROUTE_B_E2E
```
