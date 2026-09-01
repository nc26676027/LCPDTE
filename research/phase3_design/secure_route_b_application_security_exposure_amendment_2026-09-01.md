# Secure Route-B Application-Security Exposure Amendment

Status: preregistered before the finite-exposure/key-structure audit and before
the ephemeral-secret estimator run.

## Question and bound circuit

This amendment closes the remaining application-security evidence gap for the
accepted Route-B source-ordered depth-2 selected-child circuit. The circuit is
bound to the canonical C75 artifact whose file SHA-256 is
`4a7fbd447dc8e127ff5392c3b3f22bf4a9f420edf4c30622445db76e965abbb2`
and whose validated report digest is
`93876cd488dc3b9b7d9e1535ceec34c82a80a537391a2240fd52b31ca5036d1d`.
No result from a different parameter tuple, key schedule, Galois-key list, or
circuit profile can satisfy this amendment.

## Exposure inventory to be audited

The implementation uses the exact Lattigo tuple `N=65536`, 21 Q primes, seven
P primes, main sparse ternary weight 192, ephemeral sparse ternary weight 32,
and bounded discrete Gaussian error with sigma 3.2 and implementation bound
19.2. The audit must inspect the actual key structures or reconstruct them
from the exact authenticated Lattigo constructors and then verify all of the
following expected records:

1. 38 Galois keys at full QP, each with three RNS gadget rows and one base-two
   element per row: 114 ring-RLWE encryptions under the main secret.
2. One full-QP relinearization key with the same `3 x 1` gadget shape: three
   ring-RLWE encryptions under the main secret.
3. One dense-to-sparse key at `Q[0]P[0]` with shape `1 x 1`: one ring-RLWE
   encryption under the ephemeral weight-32 secret.
4. One sparse-to-dense key at full QP with shape `3 x 1`: three ring-RLWE
   encryptions under the main secret.
5. Three symmetric input ciphertexts at full Q and no generated public key:
   three ordinary ring-RLWE encryptions under the main secret.
6. No ring-degree swap or conjugate-invariant/standard-ring swap keys.

The expected totals are therefore 41 evaluation keys, 121 evaluation-key
ring samples, 124 total fresh ring samples, 123 exposures under the main
secret (120 at QP and three at Q), and one `Q[0]P[0]` exposure under the
ephemeral secret. A ring sample is not silently counted as `N` independent
scalar LWE samples. If a coefficient-embedding LWE proxy is reported, its
mapping and structured-RLWE limitation must remain explicit.

## Estimation and decision rule

The existing authenticated unlimited-sample exact-Q/exact-QP sensitivity
rows for the main secret remain the conservative lattice-estimator boundary:
150.672 classical bits and 136.740 quantum bits at exact QP. A new
unlimited-sample sensitivity row must be run for the weight-32 ephemeral
secret at exactly `Q[0]P[0]`, using the same pinned estimator commit, Sage
environment, ADPS16 classical and quantum cost models, and selected uSVP and
dual-hybrid attack paths. The functional `N=32` negative control remains
mandatory.

The decision vocabulary is fixed before seeing the new row:

- `FAIL`: either secret has a modeled classical minimum below 128 bits, the
  negative control does not fail, or the structural exposure inventory drifts.
- `CONDITIONAL-PASS`: both secret-role sensitivity minima meet the 128-bit
  classical threshold and the exact inventory/circuit binding passes. This
  conclusion is conditional on the standard RLWE assumptions plus the
  key-dependent-message/circular and cross-key assumptions required by
  relinearization, Galois, and dense/sparse switching keys.
- `INCONCLUSIVE`: the measurements pass but any required exposure, estimator
  row, circuit binding, or assumption statement remains absent.

An unconditional statement that the application is “128-bit secure” is not
authorized by this experiment. The estimator does not prove KDM/circular
security, CKKS decryption-failure bounds, side-channel resistance, malicious
security, or private-model security. These limits must be stated once in the
security section and must not be scattered as generic caveats across result
claims.

## Acceptance evidence

The audit artifact must be canonical JSON with a self-verifying digest, exact
ordered Galois inventory, exact modulus identities and bit lengths, gadget
shapes, per-class and aggregate sample counts, C75 bindings, estimator/tool
digests, explicit assumptions, and the decision. Unit tests must reject
self-consistent mutations to a key count, gadget shape, secret role, modulus,
artifact binding, estimator minimum, negative-control result, assumption set,
or decision.

