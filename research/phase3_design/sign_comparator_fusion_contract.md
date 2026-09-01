# Signed Comparison and MSB-to-Arithmetic Fusion Contract

Status: Stage-2 implementation contract. The range proof is exact; the
tree-specific encrypted fusion and end-to-end comparator remain unimplemented
until their ciphertext gates pass.

## 1. First bounded comparator slice

The first concrete encrypted tree comparator is deliberately narrow:

```text
word width: n=8
interpretation: two's-complement signed
feature range: closed [x_min,x_max]
threshold range: closed [t_min,t_max]
proof obligation: -128 <= x_min-t_max and x_max-t_min <= 127
predicate: x >= t
```

The endpoint calculation is performed in a widened host type. If the complete
difference interval does not fit `[-128,127]`, the signed-no-overflow circuit
rejects before encryption/evaluation. It must not silently wrap and inspect
the wrapped sign bit. Unsigned borrow, widened unsigned, and sign-corrected
full-range comparison remain separate physical circuits.

For an admitted pair, arithmetic subtraction produces the exact residue of
`d=x-t` in `Z_(2^8)`. Full A2B returns its little-endian Boolean halves

```text
low  = [b0,b1,b2,b3]
high = [b4,b5,b6,b7].
```

Because `d` lies in the signed interval, `b7=1` exactly when `d<0`. Therefore

```text
[x >= t] = 1 - b7.
```

This proof does not apply to an arbitrary same-width subtraction.

## 2. Generic composition control

The explicit control path constructs Boolean halves for the one-bit word
`b7`, then calls the same-chain B2A adapter:

```text
high A2B half at L5/S35
-> isolate local slot 3 into low-half local slot 0
-> zero the other seven Boolean positions
-> fused-tInv B2A
-> arithmetic sign word at L4 or below, depending on isolation schedule
-> arithmetic one minus sign
```

Every rotation, plaintext mask, rescale, and temporary ciphertext used for
isolation is charged. A plaintext rearrangement of decrypted bits is only an
oracle and cannot instantiate this encrypted baseline.

## 3. Direct rank-one fusion

Let `U0_tInv` be Gao's existing fused-`t^-1` low-half matrix. Its first column
maps Boolean coefficient `b0` to the arithmetic root-slot encoding of the word
`b0`. For each four-slot word block, define a new matrix `M_sign` by

```text
M_sign[row,col] = U0_tInv[row,0], if col=3
                  0,              otherwise.
```

Applied directly to the A2B high half, this gives

```text
M_sign * [b4,b5,b6,b7]^T
  = ArithmeticRootSlots(b7).
```

The transform is block diagonal across all four words. It is compiled at the
measured Boolean output level 5 with matrix scale `q_5`; its one rescale must
return level 4 at the exact default S35 scale. The branch result is obtained by
subtracting this arithmetic sign word from a correctly block-encoded public
arithmetic word one.

This is a tree-specific Lattigo optimization, not an upstream Gao operator.
Its admissible fidelity label is `lattigo_tree_fusion`, and its security
maturity remains `functional_not_secure` on the current LogN=5 profile.

## 4. Mandatory ciphertext gates

1. Exhaust all 256 `n=8` words over repeated four-word full-packed batches;
   fused output must decode to `(word>>7)&1` for every block.
2. Compare fused output against the generic B2A semantic control and an
   independent exact `Z_(2^8)` oracle.
3. Assert input immutability, output `L4/S35`, degree one, full dimensions,
   transform/profile digest, and defensive-copy accessors.
4. Reject nil/mismatched encoders, wrong ingress level/scale/dimensions/half
   role, every missing Galois key, and any mutable evaluator/key swap before
   the first operation.
5. Distinguish normal `U1`, full fused-`U1`, conventional slot-three masking
   without block-boundary correction, low/high swapping, and MSB-first layout.
6. Run signed comparison over every admitted endpoint pair and every `x,t` in
   at least one exhaustive nontrivial range; reject a deliberately overflowing
   policy such as full `[-128,127] x [-128,127]`.

## 5. Measured comparison

The generic and fused paths are compared with the same inputs, keys, parameter
profile, output certificate, and correctness tolerance. Report:

```text
linear transforms, rotations, CT-PT multiplies, rescales, key switches,
peak live ciphertexts, serialized key bytes, wall time, and maximum error.
```

A fused-path speed claim requires lower measured end-to-end comparator cost;
one fewer named API call or one fewer logical stage is not sufficient.

## 6. Tree integration boundary

The branch output is an arithmetic triangle word in each four-slot block. It
may enter `treeeval.Backend.Mul` only after the common integer certificate
binds:

- `selector_digit`, `root_slots`, no half role;
- two's-complement source width 8 and output range `[0,1]`;
- exact level/scale/dimensions and full-dense packing;
- signed-no-overflow policy/range-evidence digest;
- A2B and sign-fusion profile digests; and
- functional-not-secure maturity.

This boundary proves neither a full CCS-model reproduction nor a radix-tree
speedup. It is the first executable comparator seam needed by both the binary
OBO control and later integer-node experiments.
