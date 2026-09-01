# Registered amendment: Route-B signed-int8 depth-2 node batch

Date: 2026-09-01  
Status: preregistered before any encrypted depth-2 execution  
Scope: R1 quantized, public-model, 512-word sparse-packing adaptation

## Question

Can one Route-B complete A2B invocation evaluate every internal node of a
depth-2 binary tree by using the SIMD word dimension for nodes as well as
queries, thereby avoiding the unresolved L3-to-high-level selector refresh?

## Declared semantics

- Each query supplies three encrypted signed-int8 feature values in adjacent
  arithmetic-root words: root, left child, right child.
- The server model contains three public signed-int8 thresholds and four
  finite public real leaves.
- Branch convention is `0 = feature < threshold`, `1 = feature >= threshold`.
- Each node has an independent trusted endpoint certificate proving that its
  admitted feature interval and fixed threshold keep same-width subtraction
  in `[-128,127]`. This is admission metadata, not an encrypted range proof.
- The client-facing packing contains 170 queries (`170 * 3 = 510` words) and
  two authenticated padding words. Feature-gather compilation from a general
  encrypted feature bank is outside this first slice.
- The workload is an R1 quantized/retrained arm. It is not the CCS evaluator's
  exact ordered-float32 model semantics and does not make the public model
  private.

## Registered circuit

1. Subtract one node-role threshold plaintext from the encrypted 512-word
   feature batch at L20/S43.
2. Invoke the already frozen serial 8-bit Route-B A2B once.
3. Broadcast each word's high-half column 3 (`b7`) with the frozen four-
   diagonal transform and rescale L4 to L3/S43.
4. Complement to obtain `ge = 1-b7` for every word.
5. Apply Q3-scale plaintext masks for root/left/right node roles and rescale
   each product to L2/S43. Rotate the left role by `+4` slots and the right
   role by `+8` slots so all three selectors occupy the four slots of each
   root word. Both rotations and their Galois keys already belong to the
   frozen 38-key union.
6. Form three path selectors at L2:

   ```text
   p01 = (1-b0) * bL
   p10 = b0 * (1-bR)
   p11 = b0 * bR
   ```

   Each multiplication is CT--CT with relinearization; one rescale by `q2`
   yields L1 at exact scale `P = S^2/q2`.
7. Let `dL=l01-l00`, `dX=l10-l00`, and `dR=l11-l10`. Encode the three
   plaintext deltas at L1 with exact scale `q1*S/P = q1*q2/S`. Then

   ```text
   y = l00 + p01*dL + (p10+p11)*dX + p11*dR.
   ```

   Three parallel CT--PT products followed by rescale by `q1` return L0/S43.
   The base-leaf plaintext is nonzero only in root-word slots, so all padding
   and non-output words remain zero.

No ciphertext level is increased, no ciphertext scale metadata is retagged,
and the resident compatibility-only degree-3 bootstrap polynomial is not
called as an identity refresh.

## Exact operation hypothesis

Outside the nested complete A2B report, the wrapper must record exactly:

- one CT--PT threshold subtraction;
- one four-diagonal word broadcast, two broadcast rotations/key switches and
  one broadcast rescale;
- one negation and one plaintext addition for `ge`;
- three Q3-scale role-mask products and three rescales;
- two role-alignment rotations/key switches (`+4`, `+8`);
- two path complements;
- three CT--CT multiplications, three relinearizations and three rescales;
- one path-selector addition;
- three leaf CT--PT multiplications and three rescales;
- two ciphertext additions and one base-leaf plaintext addition.

## Capacity amendment

The phase reuses all `a2b-full` components (`2,381,123,328 B` pre-guard) and
adds the following conservative envelope:

| Component | Bytes |
|---|---:|
| L20 threshold plaintext | 11,010,048 |
| 2,048 high-precision threshold values | 524,288 |
| Four Q4/P6 broadcast diagonals | 25,165,824 |
| Four high-precision broadcast source diagonals | 2,097,152 |
| L3 global-one plaintext | 2,097,152 |
| L2 root-output-one plaintext | 1,572,864 |
| Three L3 Q3-scale role masks | 6,291,456 |
| Three L1 leaf-delta plaintexts | 3,145,728 |
| One L0 root-word base-leaf plaintext | 524,288 |
| Sixteen conservative wrapper ciphertexts through L4 | 83,886,080 |
| **Depth-2 wrapper subtotal** | **136,314,880** |

Registered `signed8-depth2-node-batch` pre-guard requirement:
`2,517,438,208 B`. The unchanged 512 MiB minimum guard produces a guarded
requirement of `3,054,309,120 B`.

### Pre-HE correction: role-mask encoding scale

The first pure artifact test encoded the three role masks at scale one. CKKS
encoding maps a sparse slot mask through an inverse FFT; its fractional
coefficients rounded at scale one, and all three serialized plaintexts became
identical. This falsified the scale-one assumption before any ciphertext
execution. The corrected schedule above uses scale `q3`, physically rescales
each masked selector to L2/S43, and shifts the remaining path/leaf schedule
down by one level to the exact L0 endpoint. The correction introduces no
reraising, metadata retag or new key, and the capacity numbers above replace
the initial values.

## Acceptance gates

1. Pure model/oracle tests cover all eight root/child path combinations,
   equality and signed endpoints; malformed models and overflow-admitting
   certificates fail closed.
2. A plaintext packing/alignment oracle proves that `+4/+8` align child roles
   to root words and leave non-output/padding words zero.
3. The compiled transform and all four runtime rotations use only the frozen
   installed key union.
4. Exact state and operation ledgers reconstruct independently from canonical
   parameters and reject self-consistent report mutation.
5. A fresh-process encrypted run checks every active output slot against an
   independent plaintext depth-2 oracle, checks every inactive slot against
   zero, freezes JSON and hashes it, and passes count-20 artifact replay.

## Stop conditions and claim boundary

- Stop if any required rotation falls outside the installed 38-key union, if
  the measured scale/level schedule differs, if any output path is missing,
  or if an inactive/padding slot is nonzero beyond the registered tolerance.
- A successful run supports only a public-model node-batched depth-2
  functional claim. It does not establish the source-faithful selected-child
  LCPDTE schedule, model privacy, float32 equivalence, application security,
  repeated performance, or superiority.
- Latency and throughput must be reported separately: one A2B per 170-query
  batch is a latency hypothesis, while the selected-child baseline processes
  up to 512 queries with two serial A2B calls. No speedup is claimed without
  matched measurements.
