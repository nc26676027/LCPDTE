# Upstream `fhe-simd-alu` provenance, build status, and source map

## Provenance verdict

The authoritative repository, `https://github.com/tsinghua-ideal/fhe-simd-alu.git`, is pinned at the remote's default branch `fhe-simd-alu`, commit `08f1eb87434e7be072cba889270a8400bbffc08e` (tree `9b1ac19b19b70dd9f6a1510e4660a73ed3ca1e72`, 2026-02-25). It identifies itself as an OpenFHE 1.4.0 fork and carries the BSD 2-Clause license with OpenFHE's 2022 copyright notice.

Pinned submodules:

| Path | Commit |
|---|---|
| `third-party/cereal` | `984e3f194862b17916536b5fade40cba6e47a6fe` |
| `third-party/google-benchmark` | `eddb0241389718a23a42db6af5f0164b6e0139af` |
| `third-party/google-test` | `52eb8108c5bdec04579160ae17225d66034bd723` |
| `third-party/gperftools` | `83edb60836d87cf1b406e8846b9059c03031e8f5` |

Local checkout: `D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu`.

## What the implementation represents

The fork does not encode an integer as an ordinary scalar CKKS slot. It embeds each `zN`-bit residue in a polynomial block and packs many such blocks into one RLWE ciphertext:

- `ZPolynomial` works modulo `X^zN - X + 2`. The element `t = X - 2` is represented by coefficients `[-2, 1]`.
- Arithmetic encoding computes `encodeBinary(m) * t^{-1}` in that quotient, representing a residue modulo `2^zN` as `[m]_t / t`.
- `ZMode` holds arithmetic residues. `BModeFull` holds the lower and upper `zN/2` bit halves in two ciphertexts. `BModeSparse` concatenates both halves in one ciphertext when capacity permits.
- Full packing provides `zSlots = ringDimension / zN` independent integer lanes. The corresponding CKKS complex-slot footprint is `zN/2` complex slots per integer lane.

Authoritative implementation anchors:

- Ring and encoding algebra: `src/core/include/math/z-polynomial.h:9-153,158-405`.
- CKKS/RLWE encoder: `src/pke/include/encoding/z-encoding.h` and `src/pke/lib/encoding/z-encoding.cpp`.
- Encoding metadata embedded in ciphertexts: `src/pke/include/ciphertext.h:335-339,542`.
- Prototype encryption/decryption and noise/overflow diagnostics: `src/pke/lib/scheme/ckksrns/z-pke.cpp:79-172`.

## Operator-to-code map

| Operator family | Public entry point(s) | Core implementation and semantics |
|---|---|---|
| Arithmetic add/sub/negate | `UserZImpl::EvalAddInZ`, `EvalSubInZ`, `EvalNegateInZ` | `z-leveledshe-arith.cpp:11-24`; adjusted CKKS arithmetic preserving `ZMode`. |
| Arithmetic plaintext ops | `EvalAddPtInZ`, `EvalSubPtInZ`, `EvalMultPtInZ`; vector variants | `z-leveledshe-arith.cpp:26-58,110-157`; multiplication deliberately uses binary encoding, giving the short product path. |
| Ciphertext multiplication | `EvalMultShortInZ`, `EvalMultFullInZ` | `z-leveledshe-arith.cpp:60-107`; short product consumes one rescale and assumes one binary-encoded factor; full product consumes the product rescale plus multiplication by `t`, hence two rescale levels. |
| Boolean AND/OR/XOR/NOT | `EvalBooleanAND`, `OR`, `XOR`, `NOT` and plaintext/vector variants | `z-leveledshe-bool.cpp:7-267`; evaluates `ab`, `a+b-ab`, `a+b-2ab`, and `1-a` lane-wise. |
| Bit shifts/rotations | `EvalBooleanShiftLeft`, `ShiftRight`, `RotateLeft`, `RotateRight` | `z-leveledshe-bool.cpp:273-553`; masks and CKKS rotations across the two boolean halves; required rotation keys are enumerated by `UserZImpl::Setup` in `z-user-advanced.cpp:5-140`. |
| Integer-lane rotation | `UserZAdvancedImpl::EvalRotateInZ` | `z-user-advanced.cpp:154-169`; rotates by `index * (zN/2)` CKKS slots; sparse boolean rotation is explicitly unsupported. |
| Signed less-than | `UserZAdvancedImpl::EvalLessThan` | `z-user-advanced.cpp:142-152`: subtract in `ZMode`, convert arithmetic to boolean, then extract the most-significant bit using `EvalSignExtract` (`z-leveledshe-bool.cpp:555-560`). This is a two's-complement sign test; the committed example covers nearby positive operands, not wraparound/overflow boundaries. Equality is commented out and unimplemented. |
| Arithmetic refresh (high part) | `FHEZImpl::EvalArithToArithHigh` (`A2AI`) | `z-fhe.cpp:299-319`; `Z -> R`, modulus raise/partial sum, and high-precision `R -> Z`, resetting the integer-overflow component `I`. |
| Arithmetic refresh (noise part) | `FHEZImpl::EvalArithToArithNoise` (`A2Ae`) | `z-fhe.cpp:330-382`; special `Z -> R`, modulus raise, `R -> C`, Chebyshev sine plus double-angle iterations, `C -> Z`, then subtraction to remove approximate noise. |
| Full arithmetic refresh | `FHEZImpl::EvalArithToArith` (`A2A`) | `z-fhe.cpp:384-389`; runs `A2AI` before `A2Ae` because a large `I` degrades linear-transform precision. |
| Arithmetic-to-boolean | `EvalArithToBooleanSparse`, `Full`, `Batched`, dispatcher | `z-fhe.cpp:391-813,1039-1081`; digit extraction uses width `w` (examples set `w=4`), two LUTs for identity/MSB, iterative subtraction of recovered low digits, and reconstruction of the bit halves. Batched mode requires or pads to exactly `zN/w` input ciphertexts and supports full packing only. |
| Boolean refresh | `EvalBooleanToBooleanSparse/Full` (`B2B`) | `z-fhe.cpp:958-1026`; coefficient/slot transforms followed by a cosine approximation and `1-cos^2(pi x)`, identified in code as the `p=2`, order-1 AKP25 identity LUT. |
| Boolean-to-arithmetic | `EvalBooleanToArith` (`B2A`) | `z-fhe.cpp:1028-1037`; special `C -> Z` transform and metadata reset to `ZMode`. |
| Bootstrap setup and transforms | `EvalBootstrapSetup`, `EvalBootstrapKeyGen`, `EvalZ2C`, `EvalC2Z`, `EvalZ2R`, `EvalR2Z` | Precomputation in `z-fhe-precompute.cpp`; rotation-key discovery in `src/pke/lib/scheme/z-fhe-keygen.cpp`; BSGS/FFT-like transforms in `z-fhe-lt.cpp`; orchestration in `z-fhe.cpp`. |
| Polynomial/LUT approximation | `AdvancedZImpl` | `z-advancedshe.*`; Paterson-Stockmeyer-style Chebyshev/power evaluation used by the sine, cosine, exponential, and two-LUT bootstrap stages. Coefficients are in `z-fhe-constants.h`. |

The example constructs the helper objects manually on top of a standard `CryptoContextCKKSRNS`; there is no cohesive production `CryptoContext` facade. `PKEZImpl` stores both public and secret keys, and `pkeZ_global` is explicitly marked temporary. Treat this checkout as a research oracle, not a deployable client/server library.

## Executables and validation coverage

The CMake graph exposes the intended targets `example`, `benchmark-full`, `noise-test`, `mul-depth-test`, and `tcm`.

| Target | Purpose | Parameter modes |
|---|---|---|
| `example` | Demonstrates arithmetic, boolean logic, shifts/rotations, comparison, and all conversions | Always toy: ring dimension `2^10`, security disabled, `zN=64`, full packing. |
| `benchmark-full` | Correctness warmup followed by timing of MultFull, OR, B2A, B2B, A2AI, A2Ae, A2A, batched A2B, A2B | `test`: toy ring `2^10`, one timed repeat. `verify`: HEStd-128/ring `2^16`, zero timed repeats but still runs each warmup. `bench`: HEStd-128/ring `2^16`, five repeats. |
| `noise-test` | Repeated noise and integer-overflow growth for full/short multiplication after A2A | Same `test` versus HEStd-128 modes; committed shell script uses 16 OpenMP threads. |
| `mul-depth-test` | Three chained full products and three chained plaintext/short products | Same parameter split; prints failures. |

Shared example parameters are CKKS `FLEXIBLEMANUAL`, 43-bit scaling/first moduli, 50-bit auxiliary primes, multiplicative depth 20, bootstrap level budget `{3,2}`, and full packing. The secure benchmark sets a sparse encapsulated secret, `HEStd_128_classic`, and ring dimension `65536`; committed logs report `log2(Q)=904`, `log2(P)=350`.

There are no dedicated GoogleTest cases for the new Z operators. The example programs print `Error in ...` messages but do not aggregate failures into a nonzero process exit. Most simple arithmetic/boolean checks inspect only slot 0; conversion checks use `valuesEqual`, and the comparison demo checks every lane but only on small nearby positive values. A Lattigo port should therefore use independently specified modular test vectors rather than treating a zero exit status as a correctness oracle.

## Committed benchmark evidence (not locally reproduced)

The repository commits logs for `zN` in `{8,16,32,64,128,256}` at ring dimension `65536`. `log/run-all.sh` uses `OMP_NUM_THREADS=1`; each reported time is the mean of five calls after one correctness warmup. Examples from the committed logs:

| `zN` | lanes | MultFull | B2A | B2B | A2A | batched A2B | A2B |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 8192 | 0.0942 s | 0.665 s | 5.91 s | 10.05 s | 13.13 s | 10.14 s |
| 16 | 4096 | 0.0925 s | 1.13 s | 5.74 s | 10.82 s | 27.09 s | 20.05 s |
| 32 | 2048 | 0.0929 s | 1.68 s | 5.85 s | 11.69 s | 57.69 s | 40.63 s |
| 64 | 1024 | 0.0928 s | 2.75 s | 5.84 s | 13.31 s | 127.53 s | 80.57 s |
| 128 | 512 | 0.0938 s | 4.13 s | 5.87 s | 15.63 s | 308.94 s | 163.61 s |
| 256 | 256 | 0.0942 s | 6.38 s | 5.73 s | 19.13 s | 823.39 s | 327.13 s |

These are source-provided observations with no hardware metadata in the logs. They are useful for operator scaling hypotheses, not as local reproduction results.

## Local build verdict

Status: **source pinned and partially compiled; executable not produced**.

The diagnostic build compiled the core library and reached the new Z bootstrap/operator objects. It first failed because GCC 11 turns a signed/unsigned comparison in `z-fhe-precompute.cpp:251` into an error under the repository's global `-Werror`. After narrowly disabling only that warning-as-error, compilation exposed the intended dependency contract:

1. The shift/rotation code uses NTL-style `BigInteger` bitwise OR and does not compile with fallback `MATHBACKEND=4`.
2. `LeveledZImpl::EvalMultScalarInPlace` calls Intel HEXL unconditionally, so `WITH_INTEL_HEXL=OFF` is not a supported configuration for this branch.
3. The prototype PKE/diagnostic layer also names `NTL::ZZ` directly in `z-pke.cpp:177`, independently confirming NTL as a source-level dependency.
4. The README-faithful environment needs Clang, NTL and GMP development packages, HEXL 1.2.6, and the separate `tcm` build. Clang and NTL/GMP headers are absent in the current WSL image; passwordless sudo is unavailable.

No upstream source was changed, and no high-memory or 128-bit benchmark run was started. Exact commands and compiler diagnostics are preserved in `build_commands_and_outputs.md`.

## Porting consequences for Lattigo

- Port behavior and algebra, not OpenFHE classes. The stable seams are `ZMode` arithmetic values, boolean bit groups, and explicit conversion/refresh operations.
- Encode modulus width (`zN`), lane count, mode, level, scale, and an error/overflow budget in the Lattigo-side value type; the upstream code relies on ciphertext metadata for these invariants.
- Implement modular arithmetic and full/short multiplication before bootstraps. They provide deterministic cleartext-oracle tests independent of OpenFHE.
- Treat `A2B` as the expensive comparison boundary. `EvalLessThan` is `sub -> A2B -> MSB`, so a decision-tree design should batch comparisons or preserve boolean mode when possible rather than repeatedly converting individual nodes.
- Add exhaustive small-width tests and boundary vectors for signed comparison, shifts, wraparound, and full/short multiplication. The upstream examples do not cover these failure surfaces.
