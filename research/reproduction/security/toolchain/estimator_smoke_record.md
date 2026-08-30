# Lattice-estimator environment smoke

- Date: 2026-08-30
- Estimator commit: `53da5982597709ba0fdf94ea37a84d822310fd84`
- Estimator tree: `7cb765baf3bb401580c08f678dcee8c6f35e66d1`
- SageMath: `10.9`
- micromamba release/runtime: `2.8.1-0` / `2.8.1`
- micromamba SHA-256:
  `9689782d863c05a1bf5d2d371ba527104e7a4eb4310c1637d8653b751aed9c82`
- Environment lock: `sage-conda-linux-64-explicit.txt` (389 unique package
  URLs, each suffixed with exactly one SHA-256)
- Canonical lock SHA-256 (CRLF normalized to LF):
  `9f5fb0b9e49d71352b40e64adca1955fe4b874999a5c817112b2eaabcc2f0d5d`
- Canonical URL-and-hash package-record SHA-256:
  `0f697ecee9df0466154ba842591dd90afd917b60c29b7f3f2f7d8f2667d601d4`
- Input: `estimator_smoke.sage.py`
- Expected standard output: `estimator_smoke_stdout.txt`
- Standard error: empty
- Exit status: 0

Self-contained command from PowerShell/WSL:

```powershell
wsl.exe bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && LCPDTE_REPOSITORY=/mnt/d/WorkSpace/LCPDTE /var/tmp/lcpdte-research-toolchains/sage/bin/sage /mnt/d/WorkSpace/LCPDTE/research/reproduction/security/toolchain/estimator_smoke.sage.py'
```

Expected standard output:

```text
ESTIMATOR_PIN_OK commit=53da5982597709ba0fdf94ea37a84d822310fd84 tree=7cb765baf3bb401580c08f678dcee8c6f35e66d1
ESTIMATOR_WORKTREE_OK semantic=exact-or-crlf-only untracked=0
ESTIMATOR_IMPORT_OK source=pinned-git-archive
attacks=dual_hybrid,usvp
```

The executable input authenticates `HEAD` and the pinned Git tree before
import. It rejects every semantic tracked change and every non-ignored
untracked file. It then imports from an exact `git archive` of the authenticated
commit, so ignored bytecode or platform-only files cannot influence executed
semantics. The tracked-content check ignores only carriage returns at end of
line, because a Windows checkout may represent the pinned LF files as CRLF.
The current checkout exhibits that CRLF-only representation difference and
passes the semantic-content check.

Repository discovery is explicit in the command through both `cd` and
`LCPDTE_REPOSITORY`; the input fails closed when neither resolves a repository
containing `go.mod` and the estimator checkout.

This gate verifies only that the authenticated estimator imports and executes
under the frozen Sage environment. It does not estimate a CKKS parameter tuple
and does not change any `pending-estimator` security label. Current readiness
is `ENVIRONMENT-READY / PARAMETER-CONVERSION-PENDING`.
