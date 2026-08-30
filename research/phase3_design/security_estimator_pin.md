# Security Estimator Pin and Execution Contract

## Pinned tool

- Repository: `https://github.com/malb/lattice-estimator`
- Commit: `53da5982597709ba0fdf94ea37a84d822310fd84`
- Commit tree: `7cb765baf3bb401580c08f678dcee8c6f35e66d1`
- Commit date: 2026-08-19
- Local checkout: `research/upstream/lattice-estimator`
- Package metadata: `lattice-estimator` 0.1.0, Python 3.9 or later, Sage module
- License declared by upstream: LGPLv3+

Checkout commands:

```powershell
git clone --filter=blob:none --no-checkout https://github.com/malb/lattice-estimator.git research/upstream/lattice-estimator
git -C research/upstream/lattice-estimator checkout --detach 53da5982597709ba0fdf94ea37a84d822310fd84
git -C research/upstream/lattice-estimator rev-parse HEAD
git -C research/upstream/lattice-estimator rev-parse "HEAD^{tree}"
```

The exact commit and tree are evidence inputs because upstream states that
estimates may change between revisions and does not promise API stability.
The executable smoke authenticates both values and rejects semantic working
tree changes before importing the estimator from an exact Git archive of the
pinned commit. Pure LF-to-CRLF representation changes in a Windows checkout
are admitted; other tracked changes and all non-ignored untracked files are
rejected. Importing the archive also prevents ignored bytecode or platform-only
files from changing the executed estimator semantics.

## Frozen Sage environment

- micromamba release/runtime: `2.8.1-0` / `2.8.1`
- micromamba SHA-256:
  `9689782d863c05a1bf5d2d371ba527104e7a4eb4310c1637d8653b751aed9c82`
- SageMath: `10.9`
- Canonical Sage version-record SHA-256 (exact content `10.9\n`, with CRLF
  normalized to LF):
  `65c57161b58002a9784f3b056b693ebe515469e80c9a11afe3d4423e671af8a0`
- Explicit package records: 389
- Canonical explicit-lock SHA-256 (CRLF normalized to LF):
  `9f5fb0b9e49d71352b40e64adca1955fe4b874999a5c817112b2eaabcc2f0d5d`
- Canonical URL-and-hash package-record SHA-256:
  `0f697ecee9df0466154ba842591dd90afd917b60c29b7f3f2f7d8f2667d601d4`

Normal installation/verification is fail-closed and does not rewrite the lock
or version record:

```powershell
wsl.exe bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && bash research/scripts/install_sage_wsl.sh'
```

On every normal invocation the script verifies the existing or newly
downloaded micromamba binary against the fixed hash and runtime version. It
requires the tracked explicit lock and its fixed hash, creates a missing Sage
prefix only from that lock, compares an existing prefix's complete URL+SHA
export with the lock, and checks the runtime Sage version against the tracked
record. The record and runtime output are both authenticated as exactly one
`10.9` line with a terminating newline. The lock grammar and hashes admit only
Git's LF/CRLF representation difference; any other content mismatch fails
without changing a tracked artifact.

Generating a replacement lock is a separate, explicit maintenance operation:

```powershell
wsl.exe bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && LCPDTE_TOOLCHAIN_DIR=/var/tmp/lcpdte-research-toolchains-refresh-YYYYMMDD bash research/scripts/install_sage_wsl.sh --refresh-lock'
```

Refresh mode requires a fresh Sage prefix, solves the declared Sage
10.9/Python 3.12 environment, and is the only mode allowed to update the lock
and Sage version record. The same full-file version validator gates generated
output before either record is published. Its printed digest must be reviewed
and pinned in the installer and this document before normal mode can consume a
changed lock. Refresh is dependency maintenance, not a security-estimator
result.

## Current execution boundary

The independently rerun smoke command is self-contained with respect to the
repository path:

```powershell
wsl.exe bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && LCPDTE_REPOSITORY=/mnt/d/WorkSpace/LCPDTE /var/tmp/lcpdte-research-toolchains/sage/bin/sage /mnt/d/WorkSpace/LCPDTE/research/reproduction/security/toolchain/estimator_smoke.sage.py'
```

On 2026-08-30 it authenticated the pinned commit/tree and CRLF-tolerant
semantic worktree, imported the estimator under Sage 10.9, returned the rough
attack keys `dual_hybrid,usvp`, matched the frozen expected stdout, emitted no
stderr, and exited zero.

Current status is:

- `ENVIRONMENT-READY`: the pinned runtime and estimator import gate pass;
- `PARAMETER-CONVERSION-PENDING`: no deterministic benchmark-JSON-to-estimator
  conversion script or eligible parameter transcript exists;
- every CKKS parameter tuple remains `pending-estimator`.

The smoke is not a CKKS parameter estimate and is not a security pass.

## Required input record for each parameter family

Before an estimator run, the benchmark binary must emit the following values
rather than accepting a paper-level `logQP` summary:

1. RLWE dimension and corresponding LWE dimension used by the estimator;
2. every ciphertext-modulus and special-prime value, their product, and exact
   bit length;
3. encryption and ephemeral secret distributions, including sparse Hamming
   weights and sign split;
4. error distribution and standard deviation;
5. the number and type of public RLWE samples exposed by the public key and
   every evaluation key;
6. decomposition bases/digits, all Galois elements, relinearization keys, and
   bootstrapping keys;
7. any sparse-secret encapsulation or application-aware assumption applied
   outside the estimator.

Dense and sparse keys must be estimated separately. Treating a sparse
ephemeral key as a dense ternary secret, or using only ciphertext modulus `Q`
while omitting special modulus `P`, is not an eligible transcript.

## Transcript contract

For each frozen tuple, commit:

- the generated estimator input script;
- stdout and stderr without manual editing;
- the pinned estimator commit/tree and Sage environment-lock digest;
- classical and quantum cost-model outputs;
- the minimum reported attack cost and the attack that attained it;
- an explicit `PASS`, `FAIL`, or `INCONCLUSIVE` decision against the declared
  target.

Until all fields exist, tables may report the tuple and functional results but
must label security as `pending-estimator`. A lattice-estimator pass establishes
only the modeled RLWE hardness. It does not by itself establish
application-aware CKKS correctness, sparse-key bootstrapping safety,
side-channel resistance, or protocol security.

## Decision threshold and conversion freeze

The preregistered hard gate is a minimum classical modeled attack cost of 128
bits over every effective secret/parameter exposure. Quantum estimates are
mandatory reporting and sensitivity analysis; this study does not choose a
quantum pass threshold after observing results.

Before the first estimate, commit a deterministic parameter-to-estimator
conversion script that consumes the benchmark binary's emitted JSON and maps
every declared secret/error distribution and sample count into explicit
`LWEParameters`/noise-distribution constructors. The script, input JSON,
pinned estimator commit/tree, Sage version, and environment-lock digest form
one immutable transcript bundle. Until that script exists, status remains
`pending-estimator` even though the Sage environment is ready.
