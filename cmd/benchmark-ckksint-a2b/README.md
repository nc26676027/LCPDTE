# Canonical Lattigo A2B benchmark

This command runs the Lattigo side of the matched Gao/OpenFHE 8-bit A2B
benchmark through the public `ckksint` API:

```powershell
go run ./cmd/benchmark-ckksint-a2b `
  -host-id <stable-host-id> `
  -out lattigo-a2b.json
```

The workload is 512 bytes (`0..255` twice) at `N=65536`, with one verified
warmup followed by five verified evaluations. The ciphertext is encrypted once.
Each timed sample is only `RouteBA2BPhaseInfo.OnlineWallTime`; setup, reusable
circuit preparation, encryption, decryption, and correctness checks remain
outside the prepared-online samples. The process fixes `GOMAXPROCS=1` while the
benchmark runs so the emitted `threads=1` metadata describes the execution.

`setup_nanoseconds` is the complete untimed envelope before the warmup's
homomorphic graph: session/parameter/key setup, encryption, reusable circuit
preparation, and first-call validation. The warmup's A2B online interval is
excluded from that field.

Use the same `-host-id` for the OpenFHE artifact produced on the same machine,
then compare the two v2 artifacts with `compare-ckksint`.
