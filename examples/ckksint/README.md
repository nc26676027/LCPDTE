# Integer CKKS examples

These programs follow Lattigo's executable-example style: each directory is a
self-contained `main` package that constructs its parameters, runs a complete
operation, decrypts the result, and prints the active security boundary.

- `basic`: modular arithmetic through `ckksint.Context`.
- `conversion`: fixed four-lane signed-int8 A2B, B2A, and public comparison.
- `depth2`: the complete selected-child depth-2 tree path.

All three use `DemoOnly` parameters. They demonstrate API and circuit
correctness, not production security or benchmark performance.
