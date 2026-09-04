# Integer CKKS examples

These programs follow Lattigo's executable-example style: each directory is a
self-contained `main` package that constructs its parameters, runs a complete
operation, decrypts the result, and checks the output.

- `basic`: modular arithmetic through `ckksint.Context`.
- `conversion`: fixed four-lane signed-int8 A2B, B2A, and public comparison.
- `depth2`: the complete selected-child depth-2 tree path.
- `routeb_a2b`: the canonical N=2^16 reusable 8-bit A2B client/server flow.
- `routeb_depth2`: the canonical N=2^16 Route-B client/server workflow for a
  batch of encrypted signed-int8 queries. It covers setup, key generation,
  encryption, evaluation, decryption, an independent plaintext oracle, phase
  timings, effective and packed throughput, and numerical error.

The first three use the small `DemoOnly` profile and finish quickly. Run the
full Route-B examples from the repository root:

```bash
go run ./examples/ckksint/routeb_a2b
go run ./examples/ckksint/routeb_depth2
```

`routeb_a2b` encrypts representative bytes, evaluates the complete A2B graph,
decrypts all eight LSB-first bits, reconstructs every input byte, and prints
setup, one-time preparation, homomorphic online, complete server-call,
encryption, and decryption timings.

It accepts one batch of 1--512 queries, pads the encrypted layout to 512 words,
and returns only the requested outputs. The example uses four deterministic
queries to exercise all four leaves and equality at the root and both child
nodes. It is compute- and memory-intensive; allow roughly two minutes and
about 14 GiB of available memory on a desktop-class machine. The recorded
acceptance run is under
`research/reproduction/ckksint/routeb_depth2_example_2026-09-04`.
