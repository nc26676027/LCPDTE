# Route-B C75 Application-Security Exposure Report

Decision: **CONDITIONAL-PASS** at a 128-bit classical attack-sensitivity
threshold. `unconditional_128_bit_claim=false`.

## Bound circuit and exact inventory

The profile binds C75 artifact SHA-256
`4a7fbd447dc8e127ff5392c3b3f22bf4a9f420edf4c30622445db76e965abbb2`,
report digest
`93876cd488dc3b9b7d9e1535ceec34c82a80a537391a2240fd52b31ca5036d1d`
and parameter manifest digest
`e2dc7b14f041589be98f27f0634dab1bc77b910babcc9a8c7775f81d498b3f3d`.

| Exposure class | Keys | Ring-RLWE samples/key | Total | Secret role | Modulus role |
|---|---:|---:|---:|---|---|
| Galois | 38 | 3 | 114 | main h=192 | full QP |
| Relinearization | 1 | 3 | 3 | main h=192 | full QP |
| Dense-to-sparse | 1 | 1 | 1 | ephemeral h=32 output secret | Q0P0 |
| Sparse-to-dense | 1 | 3 | 3 | main h=192 output secret | full QP |
| Fresh symmetric C75 inputs | 3 | 1 | 3 | main h=192 | full Q |

Totals are 41 evaluation keys, 121 evaluation-key ring samples and 124 fresh
structured ring-RLWE samples: 123 expose the main secret and one exposes the
ephemeral secret. A gadget cell counts as one structured ring sample; the
ledger does not silently multiply it by ring dimension N.

## Authenticated estimator evidence

The estimator is pinned at commit
`53da5982597709ba0fdf94ea37a84d822310fd84`, tree
`7cb765baf3bb401580c08f678dcee8c6f35e66d1`, with unlimited-sample
coefficient-embedding LWE sensitivity and `n=N`. Selected uSVP and
dual-hybrid Core-SVP rows give:

| Secret/modulus role | Classical minimum | Quantum minimum |
|---|---:|---:|
| Main secret, exact Q/ QP exposure minimum | 150.672 bits | 136.740 bits |
| Ephemeral h=32, exact Q0P0 | `+Infinity` | `+Infinity` |
| LogN=5 negative control | 11.680 bits | 10.600 bits |

The main transcript SHA-256 is
`690a66c23ddcdc778da4e2f5ce7b02b028db5e8bb26efa8e3d197c039956db02`.
Two ephemeral runs are byte-identical at SHA-256
`22c47027e866843fdedadbd59d5390d350cbefcc697340f4ab9e26495eee5bf6`.
The negative control failing the threshold confirms that the estimator path is
not hard-coded to accept every input.

These estimates are attack sensitivity, not a protocol proof. `+Infinity`
means the selected attacks did not return a finite cost under the pinned
model; it is not interpreted as information-theoretic security.

## Assumptions retained by the decision

The conditional promotion requires:

- decisional sparse-secret RLWE for the exact main and ephemeral roles;
- KDM/circular security for Galois and relinearization keys;
- cross-key KDM security for dense/sparse switching keys;
- honest parameter, secret, error and evaluation-key generation; and
- semi-honest public-model evaluation with no leakage beyond the declared
  ciphertext interface.

The profile does not establish an unconditional 128-bit protocol proof,
KDM/circular security itself, malicious security, side-channel resistance,
private-model security or a formal complete-application CKKS failure bound.
Those boundaries are part of the decision rather than post-hoc disclaimers.

## Artifact identity

The canonical profile JSON has file SHA-256
`5c29142ef861b02750a1dac50cdd5ec8d8b546773188bb2713d235927dde8fd8`
and canonical payload digest
`49db539532bd31000918b8417bcd36a80412c9062e9435e6e3e0d0a125fadefb`.
Its source bindings cover the Lattigo bootstrapping key schedule, key
generator, gadget ciphertext layout and RLWE parameters source files.
