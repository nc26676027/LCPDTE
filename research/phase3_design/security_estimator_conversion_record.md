# Exact CKKS estimator-conversion record

## Status

`ESTIMATOR-SENSITIVITY-COMPLETE / APPLICATION-SECURITY-INCONCLUSIVE`

The exact Lattigo Gao-compatible candidate has deterministic classical and
quantum Core-SVP sensitivity transcripts. Its decision remains
`INCONCLUSIVE`; these rows do not establish 128-bit application security.
The fixed `LogN=5` functional profile is an independent negative control and
correctly returns `FAIL` below 128 bits.

## Authenticated inputs

- Candidate tuple: `lattigo-gao-compatible-n16-v1`
  - manifest file SHA-256:
    `4ca0e01e74271e889b233cfd729b8f45894e37fca2018fbc4cf173a1c4542882`
  - canonical manifest SHA-256:
    `e2dc7b14f041589be98f27f0634dab1bc77b910babcc9a8c7775f81d498b3f3d`
  - exact products: `log2(Q)` integer bit length 904; `log2(QP)` integer
    bit length 1254
  - dimension and distributions: `N=65536`,
    `Xs=ND.SparseTernary(96,96,n=65536)`,
    `Xe=ND.DiscreteGaussian(3.2,n=65536)`, with estimator bounds
    `[-52,52]`; the manifest truncation bound `19.2` is retained as auxiliary
    evidence
- Negative-control tuple: `lattigo-functional-a2b-n8-v1`
  - manifest file SHA-256:
    `dd7a97b130320db9b5c133f51eb9af79e21cc88a7d8568c3987711e09c0b39a3`
  - canonical manifest SHA-256:
    `d01835f4e15c2426d8f5c77667b93d30e7563ac37d4533f8b61685e412e463d5`
  - exact products: Q bit length 750; QP bit length 800
  - dimension and secret: `N=32`, estimator `ND.Ternary`, matching iid
    ternary nonzero probability `2/3`; `Xe=ND.DiscreteGaussian(3.2,n=32)`
    with estimator bounds `[-16,16]`
- Estimator commit:
  `53da5982597709ba0fdf94ea37a84d822310fd84`
- Git tree: `7cb765baf3bb401580c08f678dcee8c6f35e66d1`
- Normalized tracked-content listing SHA-256:
  `84c6c1667ced51c46afc7dfe856f68821ee249d3fcce2de326e4e6ed9f09bd27`
- Authenticated `git archive` SHA-256:
  `d838a23842bbe6d399e3f742847e0df28cc15108369390a159d864225b62c1c3`
- SageMath: `10.9`; canonical 389-package environment-lock SHA-256:
  `9f5fb0b9e49d71352b40e64adca1955fe4b874999a5c817112b2eaabcc2f0d5d`
- Normalized URL-and-SHA package-record digest, matched byte-for-byte against
  a live micromamba export of the running prefix:
  `0f697ecee9df0466154ba842591dd90afd917b60c29b7f3f2f7d8f2667d601d4`
- Running prefix and interpreter:
  `/var/tmp/lcpdte-research-toolchains/sage` and
  `/var/tmp/lcpdte-research-toolchains/sage/bin/python3.12`
- micromamba 2.8.1 binary SHA-256:
  `9689782d863c05a1bf5d2d371ba527104e7a4eb4310c1637d8653b751aed9c82`
- Conversion script SHA-256:
  `d62de51c6d74f3c49ab4db391bb68cb51e4c728102334da5c51524206f325fa3`

The converter rejects duplicate JSON keys, schema/key-order drift, changed
manifest bytes or canonical digests, altered prime arrays or products,
composite/non-NTT primes, parameter/distribution drift, an unexpected
estimator `HEAD` or tree, semantic tracked changes beyond CRLF representation,
untracked non-ignored estimator files, a changed normalized tree/archive, or a
changed Sage version/lock. Estimator imports come from the authenticated Git
archive rather than the platform checkout. The lock check also authenticates
the actual interpreter prefix and micromamba binary, exports the live package
inventory with URL+SHA records, and requires exact equality with the tracked
389-package lock.

## Conversion and cost models

Each RLWE exposure is mapped heuristically to LWE dimension `n=N`. The
candidate rows expose the exact Q and exact QP products separately. All rows
use `m=+Infinity`, so they are conservative unlimited-sample sensitivities,
not substitutes for the missing finite sample inventory.

Classical estimates invoke exactly the two attack paths selected by the pinned
rough estimator, `usvp` and `dual_hybrid`, with
`ADPS16(mode='classical')`, namely `2^(0.2920*beta)`. Selecting those paths
explicitly prevents the finite-support `Xe` representation from adding the
non-preregistered `arora-gb` path. Quantum sensitivities invoke the same two
attacks with `ADPS16(mode='quantum')`, namely `2^(0.2650*beta)`. In this
estimator revision, `dual_hybrid` resolves to the MATZOV implementation. The
canonical transcript records every returned cost field, exact problem
parameters, per-attack `rop` bits, cost representations, invocation names,
and captured estimator stdout/stderr. The complete candidate-and-negative
attack-result payload is authenticated by SHA-256
`87e176bc0a9d1877080910f89038e44729f4713b51d8bc322f45472f063b4daf`.

## Results

| Exposure | Mode | uSVP rop bits | dual_hybrid rop bits | Minimum |
|---|---:|---:|---:|---:|
| exact Q | classical | 235.644 | 235.060 | 235.060 |
| exact Q | quantum | 213.855 | 213.325 | 213.325 |
| exact QP | classical | 150.964 | 150.672 | 150.672 |
| exact QP | quantum | 137.005 | 136.740 | 136.740 |

The candidate-wide minima are 150.672 classical bits and 136.740 quantum
bits, both from the exact-QP `dual_hybrid` row. They are sensitivity values,
not a security promotion.

The negative control returns 11.680 classical bits and 10.600 quantum bits as
its minima (uSVP), for both its exact-Q and exact-QP exposures. Its gate is
therefore `FAIL` at the 128-bit threshold. This negative result is independent
of the candidate decision.

## Decision boundary

The candidate decision is `INCONCLUSIVE`, even though the modeled unlimited-
sample rows exceed 128 classical bits. A `PASS` is forbidden until the
following evidence is attached and re-estimated:

1. finite main-secret RLWE sample counts;
2. the complete evaluation-key inventory and exact modulus/sample exposures;
3. the ephemeral `h=32` secret's exact exposure modulus and sample count; and
4. an accepted secure circuit profile bound to this exact parameter bundle.

No secure-performance table may consume this transcript as a passing
application-security result.

## Reproduction commands

Run from PowerShell. The executable is the Python interpreter inside the
pinned Sage 10.9 environment.

```powershell
wsl.exe bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && LCPDTE_REPOSITORY=/mnt/d/WorkSpace/LCPDTE /var/tmp/lcpdte-research-toolchains/sage/bin/python /mnt/d/WorkSpace/LCPDTE/research/scripts/run_ckks_security_estimates.sage.py --self-test --repository /mnt/d/WorkSpace/LCPDTE'
wsl.exe bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && LCPDTE_REPOSITORY=/mnt/d/WorkSpace/LCPDTE /var/tmp/lcpdte-research-toolchains/sage/bin/python /mnt/d/WorkSpace/LCPDTE/research/scripts/run_ckks_security_estimates.sage.py --repository /mnt/d/WorkSpace/LCPDTE --run-id run-1'
wsl.exe bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && LCPDTE_REPOSITORY=/mnt/d/WorkSpace/LCPDTE /var/tmp/lcpdte-research-toolchains/sage/bin/python /mnt/d/WorkSpace/LCPDTE/research/scripts/run_ckks_security_estimates.sage.py --repository /mnt/d/WorkSpace/LCPDTE --run-id run-2'
wsl.exe bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && /var/tmp/lcpdte-research-toolchains/sage/bin/python /mnt/d/WorkSpace/LCPDTE/research/scripts/run_ckks_security_estimates.sage.py --repository /mnt/d/WorkSpace/LCPDTE --verify-repeat --first-run run-1 --second-run run-2'
```

Observed self-test result:

```text
SELF_TEST_OK manifest=e2dc7b14f041589be98f27f0634dab1bc77b910babcc9a8c7775f81d498b3f3d negative=d01835f4e15c2426d8f5c77667b93d30e7563ac37d4533f8b61685e412e463d5 estimator_tree=7cb765baf3bb401580c08f678dcee8c6f35e66d1 sage=10.9
```

Both workers exited 0 with empty stderr. Their measured wall times were
19.958259 and 20.037517 seconds and are stored only in the two run-metadata
files. Both 54,188-byte stdout transcripts are byte-identical with SHA-256
`690a66c23ddcdc778da4e2f5ce7b02b028db5e8bb26efa8e3d197c039956db02`.
The repeat verifier independently re-authenticates both metadata files, exit
codes, commands, environments, stdout/stderr paths and hashes, canonical
transcript and input files, fixed schemas, embedded manifest/toolchain/script
digests, decisions and attack rows before issuing its determinism record.
Read-only in-memory negative tests confirmed rejection of mutated exact
moduli, sample counts, empty/duplicate/reordered row inventories, cost models,
attack costs, row/global minima, Python prefix, live-export exit status,
estimator source digests and micromamba version. Additional consistent-tamper
probes cover non-minimum attack costs, `cost_repr`, every returned cost field,
and exact nested metadata schemas.

## Artifact hashes

- deterministic estimator input:
  `44b867cee31262fb87be00dade95ab5e742a09030ad2db96c64c2f9f14eb0e6b`
- canonical transcript and each successful worker stdout:
  `690a66c23ddcdc778da4e2f5ce7b02b028db5e8bb26efa8e3d197c039956db02`
- complete estimator-result payload:
  `87e176bc0a9d1877080910f89038e44729f4713b51d8bc322f45472f063b4daf`
- determinism record:
  `f6983004adc3915ae422e58acc62c6f700dde14c2eab25a1e5812ac613e982fc`
- run-1 metadata:
  `43a44c1e0e8d17226b6977d5303f536e197ec3b82cc79e2b5279eb39d052fab2`
- run-2 metadata:
  `c8fb61bc5a3d1db7500e3e18c9cc8fe80616a614a5c5886cc910d6df9e56b2e4`
- each empty stderr:
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
