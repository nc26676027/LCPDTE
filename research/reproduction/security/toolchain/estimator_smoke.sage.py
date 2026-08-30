import io
import os
import subprocess
import sys
import tarfile
import tempfile


PINNED_ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"
PINNED_ESTIMATOR_TREE = "7cb765baf3bb401580c08f678dcee8c6f35e66d1"


def run_git(checkout, *arguments, text=True):
    completed = subprocess.run(
        ["git", "-C", checkout, *arguments],
        check=False,
        capture_output=True,
        text=text,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() if text else completed.stderr.decode(errors="replace").strip()
        raise RuntimeError(
            "git authentication command failed: "
            + " ".join(arguments)
            + (f": {stderr}" if stderr else "")
        )
    return completed.stdout


repository = os.path.realpath(os.path.abspath(os.environ.get("LCPDTE_REPOSITORY", os.getcwd())))
estimator_checkout = os.path.join(repository, "research", "upstream", "lattice-estimator")
if not os.path.isfile(os.path.join(repository, "go.mod")) or not os.path.isdir(
    os.path.join(estimator_checkout, "estimator")
):
    raise RuntimeError("could not resolve the LCPDTE repository and pinned estimator checkout")

checkout_root = os.path.realpath(run_git(estimator_checkout, "rev-parse", "--show-toplevel").strip())
if checkout_root != os.path.realpath(estimator_checkout):
    raise RuntimeError(f"estimator checkout root mismatch: got {checkout_root}")

actual_commit = run_git(estimator_checkout, "rev-parse", "HEAD").strip()
if actual_commit != PINNED_ESTIMATOR_COMMIT:
    raise RuntimeError(
        f"estimator commit mismatch: got {actual_commit}, want {PINNED_ESTIMATOR_COMMIT}"
    )
actual_tree = run_git(
    estimator_checkout, "rev-parse", f"{PINNED_ESTIMATOR_COMMIT}^{{tree}}"
).strip()
if actual_tree != PINNED_ESTIMATOR_TREE:
    raise RuntimeError(f"estimator tree mismatch: got {actual_tree}, want {PINNED_ESTIMATOR_TREE}")

# A Windows checkout may rewrite tracked LF line endings to CRLF. Ignore only
# that byte-level representation change; reject every semantic tracked change.
semantic_diff = subprocess.run(
    [
        "git",
        "-C",
        estimator_checkout,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-cr-at-eol",
        "--quiet",
        PINNED_ESTIMATOR_COMMIT,
        "--",
    ],
    check=False,
    capture_output=True,
    env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
)
if semantic_diff.returncode == 1:
    raise RuntimeError("estimator checkout has semantic tracked changes beyond CRLF conversion")
if semantic_diff.returncode != 0:
    raise RuntimeError(
        "could not authenticate estimator tracked contents: "
        + semantic_diff.stderr.decode(errors="replace").strip()
    )

untracked = run_git(
    estimator_checkout, "ls-files", "--others", "--exclude-standard", "-z", text=False
)
untracked_paths = [path for path in untracked.split(b"\0") if path]
if untracked_paths:
    names = ", ".join(path.decode(errors="replace") for path in untracked_paths[:5])
    raise RuntimeError(f"estimator checkout has untracked, non-ignored files: {names}")

# Import from Git's exact object snapshot, not from ignored bytecode or other
# files that may exist in the platform checkout. Keep the snapshot alive until
# the estimate completes because imports can be lazy.
archive = run_git(
    estimator_checkout, "archive", "--format=tar", PINNED_ESTIMATOR_COMMIT, text=False
)
with tempfile.TemporaryDirectory(prefix="lcpdte-estimator-") as authenticated_snapshot:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as snapshot_tar:
        snapshot_tar.extractall(authenticated_snapshot, filter="data")
    sys.path.insert(0, authenticated_snapshot)
    import estimator as authenticated_estimator  # noqa: E402

    estimator_module_path = os.path.realpath(authenticated_estimator.__file__)
    if os.path.commonpath([authenticated_snapshot, estimator_module_path]) != os.path.realpath(
        authenticated_snapshot
    ):
        raise RuntimeError(f"estimator import escaped pinned archive: {estimator_module_path}")
    from estimator import LWE, ND  # noqa: E402

    # This tiny instance verifies the authenticated estimator's executable path
    # and API. It is deliberately not a CKKS security estimate and cannot
    # satisfy any parameter-family security gate.
    parameters = LWE.Parameters(
        n=64,
        q=4093,
        Xs=ND.UniformMod(3),
        Xe=ND.DiscreteGaussian(1.0),
        m=64,
        tag="lcpdte-environment-smoke",
    )
    result = LWE.estimate.rough(parameters, quiet=True)

    print(f"ESTIMATOR_PIN_OK commit={actual_commit} tree={actual_tree}")
    print("ESTIMATOR_WORKTREE_OK semantic=exact-or-crlf-only untracked=0")
    print("ESTIMATOR_IMPORT_OK source=pinned-git-archive")
    print("attacks=" + ",".join(sorted(result)))
