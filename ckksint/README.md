# `ckksint`

`ckksint` is the supported library boundary for packed modular integers over
Lattigo CKKS. Applications import this package instead of constructing the
research graphs under `integer/homchain` or `integer/secureeval` directly.

## Public entry points

- `Context` supports packed `Z/(2^n)` words for `n = 8, 16, 32, 64`: encrypt,
  decrypt, add, subtract, negate, public add/subtract, full multiply, and
  arithmetic-by-short multiply. `Value` and `ShortValue` prevent accidental
  representation mixing and are bound to the key context that created them.
- `Functional8` hides the complete four-lane functional circuit: signed-int8
  encryption, full A2B, B2A, public-threshold `>=`, and source-faithful
  selected-child depth-2 tree evaluation.
- `LattigoCiphertext`, `LattigoHalves`, `ImportCiphertext`, and
  `LattigoParameters` are explicit copy boundaries for Lattigo interoperation.

The public facade owns all ciphertexts. Interoperation accessors return
detached copies, and operations reject values created by another key context.

## Security and parameter boundary

`NewDemo` uses `LogN=10` functional parameters. `NewDemoFunctional8` uses the
fixed `LogN=5` A2B chain. Both are labeled `DemoOnly` and make no RLWE security
claim.

For an application parameter set, construct `Parameters` and `KeyMaterial`
explicitly and call `New`. Set `SecurityBoundary` to `ExternallyValidated` only
after validating the complete tuple outside this library. The current
`Functional8` graph has no production-security constructor.

Signed comparison requires a `Signed8Range` whose complete difference interval
fits in int8. The four-lane circuit uses the branch convention `0 = <` and
`1 = >=`. A B2A result exits at a lower modulus level and is decryptable, but
is not accepted as a fresh A2B/comparison ingress.

Lattigo evaluators own scratch buffers. Do not invoke methods on one `Context`
concurrently. `Functional8` serializes its methods internally.

## Examples and acceptance commands

```powershell
go test -count=1 ./ckksint
go run ./examples/ckksint/basic
go run ./examples/ckksint/conversion
go run ./examples/ckksint/depth2
```

The depth-2 example executes the complete homomorphic selected-child graph and
can take roughly two minutes on a desktop CPU. See `examples/ckksint/README.md`
for the example map.
