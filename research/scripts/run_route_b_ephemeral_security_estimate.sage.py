#!/usr/bin/env python3
"""Estimate the exact Route-B weight-32 encapsulation-key exposure.

The output is deterministic and intentionally contains no wall clock or
timestamp. It authenticates and imports the same pinned lattice-estimator Git
archive and Sage environment as the main-secret transcript.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import inspect
import io
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path


SCHEMA = "lcpdte-route-b-ephemeral-security-estimate-v1"
EXPECTED_RESULTS_SHA256 = "04ed7b994aa17a94d313ce721f697fbcaa04b650cee05bbe42afd4ea3486cf2a"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def load_authenticated_driver(repository):
    path = repository / "research" / "scripts" / "run_ckks_security_estimates.sage.py"
    spec = importlib.util.spec_from_file_location("lcpdte_security_driver", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the authenticated main security driver")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path


def build_transcript(repository, script_path):
    from sage.all import RealField, is_prime, oo

    driver, driver_path = load_authenticated_driver(repository)
    sage_record = driver.authenticate_sage_toolchain(repository)
    estimator_record = driver.authenticate_estimator(repository)
    manifest_path = (
        repository
        / "research"
        / "reproduction"
        / "security"
        / "parameters"
        / "lattigo-gao-compatible-n16-v1.json"
    )
    negative_path = (
        repository
        / "research"
        / "reproduction"
        / "security"
        / "parameters"
        / "lattigo-functional-a2b-n8-v1.json"
    )
    manifest = driver.verify_manifest_bytes(manifest_path.read_bytes(), is_prime)
    negative = driver.verify_negative_manifest_bytes(negative_path.read_bytes(), is_prime)

    q0 = manifest["q_primes"][0]
    p0 = manifest["p_primes"][0]
    exposure_modulus = q0 * p0
    if exposure_modulus.bit_length() != 93:
        raise RuntimeError("ephemeral Q[0]P[0] modulus bit length drifted")

    # The pinned driver rejects infinite attack cost because its full-QP main
    # rows are expected to be finite. The much smaller Q[0]P[0] exposure can
    # legitimately make a selected attack return +Infinity. Preserve that
    # result explicitly; Python's float ordering still selects any finite
    # competing attack as the minimum.
    driver_rop_bits = driver.rop_bits

    def rop_bits_allow_infinity(value):
        numeric = RealField(256)(value)
        if numeric.is_infinity() and numeric > 0:
            return "+Infinity"
        return driver_rop_bits(value)

    driver.rop_bits = rop_bits_allow_infinity

    archive = estimator_record["archive"]
    with tempfile.TemporaryDirectory(prefix="lcpdte-route-b-ephemeral-estimator-") as temporary:
        snapshot = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as snapshot_tar:
            snapshot_tar.extractall(snapshot, filter="data")
        sys.path.insert(0, str(snapshot))
        try:
            from estimator import LWE, ND, RC
            from estimator.reduction import ADPS16
            import estimator

            estimator_module_path = Path(inspect.getfile(estimator)).resolve()
            if snapshot.resolve() not in estimator_module_path.parents:
                raise RuntimeError("estimator import escaped authenticated snapshot")
            if getattr(RC.ADPS16, "mode", None) != "classical":
                raise RuntimeError("classical ADPS16 alias drifted")
            source_digests = driver.source_digests_from_snapshot(snapshot)

            ephemeral_problem = LWE.Parameters(
                n=65536,
                q=exposure_modulus,
                Xs=ND.SparseTernary(16, 16, 65536),
                Xe=ND.DiscreteGaussian(3.2, n=65536),
                m=oo,
                tag="ephemeral-secret-q0p0-unlimited",
            )
            if (
                ephemeral_problem.n != 65536
                or ephemeral_problem.Xs.p != 16
                or ephemeral_problem.Xs.m != 16
                or ephemeral_problem.m != oo
            ):
                raise RuntimeError("ephemeral estimator parameters drifted")
            ephemeral_rows = driver.estimate_parameter_rows(
                LWE,
                ADPS16,
                RC,
                ephemeral_problem,
                "ephemeral-secret-q0p0-unlimited",
            )

            negative_rows = []
            for exposure_id, modulus in (
                ("negative-control-exact-q-unlimited", negative["q_product"]),
                ("negative-control-exact-qp-unlimited", negative["qp_product"]),
            ):
                problem = LWE.Parameters(
                    n=32,
                    q=modulus,
                    Xs=ND.Ternary,
                    Xe=ND.DiscreteGaussian(3.2, n=32),
                    m=oo,
                    tag=exposure_id,
                )
                negative_rows.extend(
                    driver.estimate_parameter_rows(
                        LWE, ADPS16, RC, problem, exposure_id
                    )
                )
        finally:
            sys.path.remove(str(snapshot))

    ephemeral_minima = driver.compute_global_minima(ephemeral_rows)
    negative_minima = driver.compute_global_minima(negative_rows)
    if float(negative_minima["classical"]["rop_bits"]) >= 128:
        raise RuntimeError("negative control did not fail the 128-bit gate")
    results = {
        "ephemeral_estimates": ephemeral_rows,
        "ephemeral_global_minima": ephemeral_minima,
        "negative_estimates": negative_rows,
        "negative_global_minima": negative_minima,
    }
    results_sha256 = sha256_bytes(driver.canonical_json_bytes(results))
    if EXPECTED_RESULTS_SHA256 and results_sha256 != EXPECTED_RESULTS_SHA256:
        raise RuntimeError(
            "estimate result payload drifted: "
            f"got {results_sha256}, want {EXPECTED_RESULTS_SHA256}"
        )

    return {
        "schema_version": SCHEMA,
        "purpose": "Route-B dense-to-sparse encapsulation-key output-secret sensitivity",
        "bound_parameter_manifest_sha256": manifest["canonical_sha256"],
        "exposure": {
            "secret_role": "ephemeral-output-secret",
            "secret_distribution": "balanced-sparse-ternary",
            "positive_weight": 16,
            "negative_weight": 16,
            "total_weight": 32,
            "ring_dimension": 65536,
            "modulus": "Q[0]P[0]",
            "q0_decimal": str(q0),
            "p0_decimal": str(p0),
            "product_decimal": str(exposure_modulus),
            "product_bit_length": exposure_modulus.bit_length(),
            "fresh_ring_rlwe_samples": 1,
            "estimator_samples": "+Infinity",
            "conversion": "coefficient-embedding LWE sensitivity proxy with n=N; structured RLWE limitation retained",
        },
        "cost_models": {
            "classical": "ADPS16 2^(0.2920*beta); selected uSVP and dual-hybrid",
            "quantum": "ADPS16 2^(0.2650*beta); selected uSVP and dual-hybrid",
        },
        "toolchain": {
            "sage_version": sage_record["sage_version"],
            "sage_prefix": sage_record["sage_prefix"],
            "sage_lock_sha256": sage_record["sage_lock_canonical_sha256"],
            "estimator_commit": estimator_record["commit"],
            "estimator_tree": estimator_record["tree"],
            "estimator_archive_sha256": estimator_record["archive_sha256"],
            "estimator_source_sha256": source_digests,
            "main_driver_sha256": sha256_bytes(driver_path.read_bytes()),
            "this_script_sha256": sha256_bytes(script_path.read_bytes()),
        },
        "results_sha256": results_sha256,
        "results": results,
        "interpretation": "Unlimited-sample Core-SVP sensitivity; not a KDM/circular-security proof.",
    }


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository")
    parser.add_argument("--out", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    repository = Path(
        args.repository or os.environ.get("LCPDTE_REPOSITORY") or os.getcwd()
    ).resolve()
    script_path = Path(__file__).resolve()
    transcript = build_transcript(repository, script_path)
    encoded = json.dumps(
        transcript, ensure_ascii=False, allow_nan=False, indent=2
    ).encode("utf-8") + b"\n"
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as handle:
        handle.write(encoded)
    print(f"output={output}")
    print(f"results_sha256={transcript['results_sha256']}")
    print(
        "ephemeral_minima="
        + json.dumps(transcript["results"]["ephemeral_global_minima"], separators=(",", ":"))
    )


if __name__ == "__main__":
    main()
