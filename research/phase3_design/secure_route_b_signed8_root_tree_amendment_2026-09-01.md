# Secure Route-B signed-int8 root-tree amendment

Status: preregistered implementation and falsification contract. This document
does not claim secure parameters, a complete multi-depth LCPDTE reproduction,
or a performance improvement.

## 1. Scope and source schedule

The first Route-B tree slice evaluates one SIMD root node with:

- an encrypted signed-int8 feature word in each four-slot Gao block;
- one server-public signed-int8 threshold;
- two server-public finite real leaves;
- branch convention `0 = x < t`, `1 = x >= t`.

It follows the LCPDTE root schedule: the feature is ciphertext, the root
threshold is plaintext, and the comparison is performed once for all packed
queries. It is an R1 quantized-model experiment relative to the repository's
float32 XGBoost models; it is not an exact float32 replacement.

## 2. Arithmetic and no-overflow contract

For a registered endpoint interval,

```text
d = x - t
[x_min - t_max, x_max - t_min] subset [-128, 127].
```

The subtraction is therefore the mathematical signed-int8 difference. The
complete Route-B A2B circuit returns the high Boolean half
`[b4,b5,b6,b7]`, where `b7 = [d < 0]`. The right-branch selector is

```text
ge = 1 - b7 = [x >= t].
```

The endpoint certificate is a trusted input-admission statement, not an
encrypted range proof. The public threshold must be the single value bound by
the certificate.

## 3. Direct scalar selector bridge

The accepted complete Route-B A2B high output is ordinary Boolean data at
L5/default scale in 512 independent four-slot blocks. A fixed rank-one
block-diagonal transform copies column three to every column:

```text
[b4,b5,b6,b7] -> [b7,b7,b7,b7].
```

The transform is encoded at Q4/P6 with scale `Q[4]`; evaluation consumes the
L5 input at the transform's Q4 level and returns L4 before one physical
rescale to L3/default scale. Its only non-zero block diagonals are offsets 0,
1, 2, and 3. All required rotations must already belong to the installed
Route-B key union; no new evaluation key is admitted.

This bridge is intentionally different from the older S35 rank-one
`M_sign` transform, which produces Gao arithmetic-root slots and then needs a
periodic reraiser before real leaf selection. Here the A2B Boolean bit is
already an ordinary scalar, so direct broadcast preserves its representation.

## 4. Real-leaf selection

For public finite leaves `left` and `right`, with the registered magnitude
bound, evaluate

```text
delta  = right - left
output = left + ge * delta.
```

`delta` is encoded at L3 with scale `Q[3]`; one ciphertext-plaintext product
and one rescale produce L2/default scale. `left` is added as an L2/default
scale plaintext. The output repeats the selected real leaf in all four slots
of each word block.

## 5. Exact online state ledger

```text
encrypted feature                         L20 / default scale
feature - public threshold                L20 / default scale
complete two-round A2B high half           L5 / default scale
column-3 broadcast, before rescale         L4 / default*Q[4]
repeated sign                              L3 / default scale
repeated GE selector                       L3 / default scale
leaf-delta product, before rescale         L3 / default*Q[3]
selected real leaf                         L2 / default scale
```

The wrapper additionally charges one CT-PT subtraction, one linear
transformation, its runtime-derived diagonal/rotation/key-switch counts, two
rescales, one ciphertext negation, two plaintext additions, and one leaf
CT-PT multiplication. The nested complete A2B ledger remains separately
reported.

## 6. Capacity amendment

The operation receives a distinct `signed8-root-tree` runtime phase. It is the
complete A2B phase plus these conservative live bounds:

| Component | Bytes |
|---|---:|
| L20 threshold plaintext | 11,010,048 |
| 512 high-precision threshold word blocks | 524,288 |
| four Q4/P6 broadcast diagonals | 25,165,824 |
| high-precision broadcast source | 2,097,152 |
| L3 scalar-one plaintext | 2,097,152 |
| L3 leaf-delta plaintext | 2,097,152 |
| L2 left-leaf plaintext | 1,572,864 |
| five retained wrapper ciphertexts at an L4 envelope | 26,214,400 |

The additional bound is 70,778,880 bytes. With the accepted complete-A2B
incremental peak of 2,381,123,328 bytes, the new pre-guard requirement is
2,451,902,208 bytes. The unchanged minimum guard is 536,870,912 bytes, giving
a guarded requirement of 2,988,773,120 bytes. Runtime admission must occur
before transform construction or any HE dispatch.

## 7. Acceptance and negative controls

Acceptance requires:

1. all 256 signed-int8 inputs at threshold zero, packed twice across 512 word
   blocks, match an independent plaintext tree oracle in every output slot;
2. equality selects the right leaf;
3. input ciphertext immutability and exact L20/L11/default-scale admission;
4. reconstructed range, model, plaintext, transform, key, state, operation,
   capacity, and nested A2B identities validate;
5. low/high swap, a non-fixed threshold certificate, overflow-admitting
   ranges, wrong bit column/order, scalar-one scale drift, missing rotation
   keys, and report mutation fail closed;
6. canonical JSON replay, targeted repetition, package tests, vet, and
   formatting checks pass.

The resulting evidence supports only a functional Route-B root-tree slice.
Multi-depth private threshold selection, selector refresh, complete LCPDTE
orchestration, matched security estimation, and speedup claims remain open.
