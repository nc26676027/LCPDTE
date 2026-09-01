# Public Integer Ciphertext Metadata Contract

Status: Stage-2 P0 draft; implementation and independent audit are required
before this contract is frozen.

## Purpose

The public seam must reject representation-confused compositions even when
two ciphertexts have the same decoded residues, level, and approximate scale.
It also separates caller declarations from evidence that this repository has
actually verified. Green decryption tests cannot promote fidelity, security,
range safety, or measured cost.

## Orthogonal state axes

One immutable metadata certificate binds all of the following axes to a
ciphertext-state digest. They are independent rather than combined into one
open-ended mode enum.

| Axis | Closed initial values | Required invariant |
|---|---|---|
| integer semantics | `arithmetic`, `short_boolean`, `code_domain`, `selector_digit` | fixes the Gao representation and legal consumers |
| algebraic domain | `root_slots`, `z2c_low`, `z2c_high`, `rlwe_coefficients` | prevents root-slot values from being passed to coefficient-half operators |
| half role | `none`, `low`, `high` | `low/high` is required exactly for split domains |
| signedness | `unsigned_residue`, `twos_complement` | interpretation only; arithmetic remains modulo `2^n` |
| packing | `full_dense`, `sparse_gap` | binds word count, slots per word, `LogSlots`, gap, and active-slot count |
| fidelity | `upstream_faithful`, `lattigo_adaptation`, `exploratory` | promotion to faithful requires a controlled differential gate |
| maturity | `functional_not_secure`, `secure_profile_unverified`, `secure_profile_verified` | verification requires a locally checked estimator transcript and full parameter digest |

The first implementation admits only values needed by the current vertical
slices. Unsupported combinations fail validation; callers cannot register new
enum strings.

## Integer and range certificate

The certificate records:

- word width `n` and the exact modulus identity `2^n`;
- a closed decimal interval for each operand interpretation;
- the operation boundary at which that interval holds;
- proof status `internally_verified` or `external_unverified`;
- the SHA-256 identity of the range evidence;
- for comparison, a separately derived subtraction interval and an explicit
  no-overflow result.

An arbitrary caller string can remain `external_unverified`; it cannot unlock
the signed fast comparator. Only the controlled interval constructor may emit
`internally_verified`, and it must compute the result from closed input
intervals without machine-integer overflow.

## CKKS state

Every public boundary records ciphertext degree, level, `LogN`, exact
`LogDimensions`, NTT/batched flags, and an exact scale snapshot containing the
hexadecimal `big.Float` value, precision, rounding mode, and optional modulus.
The snapshot has a public deterministic projection and JSON round trip; an
exported trace must never serialize the scale as `{}`.

The metadata certificate is bound to an immutable profile digest. An operator
returns a new certificate and cannot mutate or retag its input certificate.
Raw ciphertext bytes remain outside the digest because randomized encryption
and in-place Lattigo internals make such a digest unsuitable as a semantic
identity; input immutability is checked independently in operator tests.

## Evidence and provenance

The operator record contains a closed operator identifier, implementation
version, source commit or local profile digest, input certificate digests,
output certificate digest, and fidelity/maturity states. Promotion rules are
one-way and controlled:

```text
exploratory -> lattigo_adaptation -> upstream_faithful
functional_not_secure -> secure_profile_unverified -> secure_profile_verified
```

No public constructor accepts a target promoted state. A controlled verifier
creates the next state only after checking the required raw-state differential
or archived security transcript. Inline caller text is integrity-checkable but
remains `external_unverified` evidence.

## Logical and physical observations

Logical algorithm counts and physical HE observations are distinct records.
Every physical scalar is an option `{known, value}` so known zero differs from
unknown. The initial physical tuple contains:

- ciphertext--ciphertext and ciphertext--plaintext multiplications;
- additions, rotations, relinearizations, rescales, and key switches;
- Z2C/C2Z, raw DFT, refresh, and bootstrap invocations;
- peak live ciphertexts and peak bytes;
- end-to-end wall time.

A measurement attachment is accepted only when its profile, operator,
workload, input-certificate, and output-certificate identities all match.
Symbolic planning may populate logical counts but cannot populate physical
fields.

## Precision diagnostics

Diagnostics name the metric, unit/domain, observed value, predeclared
threshold, comparison direction, and evidence digest. At minimum the current
slice carries maximum root error, minimum coefficient-rounding margin, and
ScaleDown `errScale` when applicable. A missing observation is unknown, never
zero or pass.

## Required negative tests

1. Arithmetic root slots cannot be rebound as Boolean coefficient halves.
2. B2A low/high halves cannot be swapped or duplicated without a producer-
   bound role certificate.
3. Normal C2Z output cannot pass the standalone fused-`t^-1` B2A boundary.
4. Equal decoded residues with different raw representatives retain distinct
   representation/provenance identities.
5. Exact scale snapshots survive JSON round trip and reject tampering.
6. Caller-supplied evidence cannot promote fidelity, range-proof, or security
   status.
7. Unknown physical values remain unknown after serialization; known zero
   round-trips as known zero.
8. A measurement for another profile/workload/certificate is rejected.

## Integration order

1. Implement and audit the immutable common certificate package.
2. Adapt A2A-I and standalone B2A result traces without changing their
   mathematical paths.
3. Require the certificate at A2A-e/A2B/B-A2B and comparison boundaries.
4. Require representation-tagged branch bits and measurement identity in the
   encrypted tree backend.
5. Remove or quarantine caller-promotable legacy security declarations only
   after current codec users migrate.

This contract does not itself establish upstream fidelity, 128-bit security,
range-safe comparison, or measured performance.
