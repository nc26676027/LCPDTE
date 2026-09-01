#!/usr/bin/env python3
"""Authenticate and estimate the exact Lattigo Gao-compatible CKKS tuple.

The deterministic transcript deliberately contains no timestamps or timings.
Each normal invocation runs an isolated worker, stores its exact stdout/stderr,
and writes timing and exit status to a separate run-metadata file.
"""

import argparse
import contextlib
import copy
import hashlib
import inspect
import io
import json
import math
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import OrderedDict
from pathlib import Path


PINNED_ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"
PINNED_ESTIMATOR_TREE = "7cb765baf3bb401580c08f678dcee8c6f35e66d1"
PINNED_ESTIMATOR_LS_TREE_SHA256 = (
    "84c6c1667ced51c46afc7dfe856f68821ee249d3fcce2de326e4e6ed9f09bd27"
)
PINNED_ESTIMATOR_ARCHIVE_SHA256 = (
    "d838a23842bbe6d399e3f742847e0df28cc15108369390a159d864225b62c1c3"
)
PINNED_MANIFEST_FILE_SHA256 = (
    "4ca0e01e74271e889b233cfd729b8f45894e37fca2018fbc4cf173a1c4542882"
)
PINNED_MANIFEST_CANONICAL_SHA256 = (
    "e2dc7b14f041589be98f27f0634dab1bc77b910babcc9a8c7775f81d498b3f3d"
)
PINNED_NEGATIVE_MANIFEST_FILE_SHA256 = (
    "dd7a97b130320db9b5c133f51eb9af79e21cc88a7d8568c3987711e09c0b39a3"
)
PINNED_NEGATIVE_MANIFEST_CANONICAL_SHA256 = (
    "d01835f4e15c2426d8f5c77667b93d30e7563ac37d4533f8b61685e412e463d5"
)
PINNED_SAGE_VERSION = "10.9"
PINNED_SAGE_VERSION_FILE_SHA256 = (
    "65c57161b58002a9784f3b056b693ebe515469e80c9a11afe3d4423e671af8a0"
)
PINNED_SAGE_LOCK_SHA256 = (
    "9f5fb0b9e49d71352b40e64adca1955fe4b874999a5c817112b2eaabcc2f0d5d"
)
PINNED_SAGE_PACKAGE_RECORDS_SHA256 = (
    "0f697ecee9df0466154ba842591dd90afd917b60c29b7f3f2f7d8f2667d601d4"
)
PINNED_MICROMAMBA_VERSION = "2.8.1"
PINNED_MICROMAMBA_SHA256 = (
    "9689782d863c05a1bf5d2d371ba527104e7a4eb4310c1637d8653b751aed9c82"
)
PINNED_ESTIMATE_RESULTS_SHA256 = (
    "87e176bc0a9d1877080910f89038e44729f4713b51d8bc322f45472f063b4daf"
)
PINNED_TOOLCHAIN_ROOT = Path("/var/tmp/lcpdte-research-toolchains")
PINNED_SAGE_PREFIX = PINNED_TOOLCHAIN_ROOT / "sage"
PINNED_MICROMAMBA_PATH = PINNED_TOOLCHAIN_ROOT / "micromamba" / "micromamba"
TUPLE_ID = "lattigo-gao-compatible-n16-v1"
NEGATIVE_TUPLE_ID = "lattigo-functional-a2b-n8-v1"
TRANSCRIPT_STEM = TUPLE_ID + ".security-estimate"

TOP_LEVEL_KEYS = [
    "schema_version",
    "tuple_id",
    "status",
    "provenance",
    "ring_type",
    "log_n",
    "n",
    "max_slots",
    "log_default_scale",
    "q",
    "p",
    "q_product",
    "p_product",
    "qp_product",
    "main_secret",
    "ephemeral_secret",
    "error",
    "estimator_eligible",
    "missing_evidence",
    "canonical_json_sha256",
]
PRIME_KEYS = ["decimal", "hex", "bit_length"]
PRODUCT_KEYS = ["decimal", "hex", "bit_length", "sha256_decimal_ascii"]
SECRET_KEYS = ["type", "weight"]
ERROR_KEYS = ["type", "sigma", "bound"]
IID_TERNARY_KEYS = ["type", "nonzero_probability"]
TYPE_ONLY_KEYS = ["type"]
EXPECTED_MISSING_EVIDENCE = [
    "accepted-secure-circuit-profile",
    "evaluation-key-inventory",
    "finite-rlwe-sample-exposures",
    "bootstrapping-secret-switch-profile",
    "classical-and-quantum-estimator-transcripts",
]
TRANSCRIPT_TOP_LEVEL_KEYS = [
    "schema_version",
    "decision",
    "toolchain",
    "manifest_authentication",
    "negative_control_manifest_authentication",
    "estimator_input_sha256",
    "estimator_input",
    "estimate_results_sha256",
    "estimates",
    "global_minima",
    "negative_control",
    "eligibility",
]
RUN_METADATA_KEYS = [
    "schema_version",
    "run_id",
    "worker_command",
    "worker_environment",
    "exit_code",
    "wall_time_seconds",
    "stdout",
    "stderr",
    "conversion_script_sha256",
    "canonical_transcript",
    "deterministic_input",
    "decision",
]
ESTIMATOR_SOURCE_FILES = (
    "estimator/lwe.py",
    "estimator/lwe_primal.py",
    "estimator/lwe_dual.py",
    "estimator/lwe_parameters.py",
    "estimator/nd.py",
    "estimator/reduction.py",
)
ESTIMATE_ROW_KEYS = [
    "exposure_id",
    "cost_model_id",
    "cost_model",
    "invocation",
    "parameters",
    "attacks",
    "minimum",
    "estimator_stdout",
    "estimator_stderr",
]
SERIALIZED_PARAMETER_KEYS = [
    "type",
    "repr",
    "n",
    "q_decimal",
    "q_bit_length",
    "Xs",
    "Xe",
    "samples",
    "tag",
]
ATTACK_RESULT_KEYS = ["rop_bits", "cost_repr", "returned_fields"]


class AuthenticationError(RuntimeError):
    """Raised when a pinned input or tool identity fails authentication."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value):
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def pretty_json_bytes(value):
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
        ).encode("utf-8")
        + b"\n"
    )


def duplicate_rejecting_object(pairs):
    result = OrderedDict()
    for key, value in pairs:
        if key in result:
            raise AuthenticationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_nonfinite_json(token):
    raise AuthenticationError(f"non-finite JSON number: {token}")


def decode_json_strict(data):
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=duplicate_rejecting_object,
            parse_constant=reject_nonfinite_json,
        )
    except UnicodeDecodeError as error:
        raise AuthenticationError("JSON is not UTF-8") from error
    except json.JSONDecodeError as error:
        raise AuthenticationError(f"invalid JSON: {error}") from error


def require_exact_keys(value, keys, label):
    if not isinstance(value, dict):
        raise AuthenticationError(f"{label} is not an object")
    actual = list(value.keys())
    if actual != keys:
        raise AuthenticationError(
            f"{label} key order/schema mismatch: got {actual}, want {keys}"
        )


def require_exact_type(value, expected_type, label):
    if type(value) is not expected_type:
        raise AuthenticationError(
            f"{label} type mismatch: got {type(value).__name__}, want {expected_type.__name__}"
        )


def require_equal(value, expected, label):
    if value != expected:
        raise AuthenticationError(f"{label} mismatch: got {value!r}, want {expected!r}")


def parse_canonical_decimal(value, label):
    require_exact_type(value, str, label)
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise AuthenticationError(f"{label} is not a canonical positive decimal integer")
    return int(value, 10)


def verify_prime_records(records, expected_length, n, label, is_prime):
    if not isinstance(records, list) or len(records) != expected_length:
        raise AuthenticationError(
            f"{label} prime count mismatch: got {len(records) if isinstance(records, list) else 'non-list'}, "
            f"want {expected_length}"
        )
    primes = []
    for index, record in enumerate(records):
        item_label = f"{label}[{index}]"
        require_exact_keys(record, PRIME_KEYS, item_label)
        prime = parse_canonical_decimal(record["decimal"], item_label + ".decimal")
        require_exact_type(record["hex"], str, item_label + ".hex")
        require_equal(record["hex"], f"0x{prime:x}", item_label + ".hex")
        require_exact_type(record["bit_length"], int, item_label + ".bit_length")
        require_equal(record["bit_length"], prime.bit_length(), item_label + ".bit_length")
        if prime % (2 * n) != 1:
            raise AuthenticationError(f"{item_label} is not 1 mod 2N")
        if not bool(is_prime(prime)):
            raise AuthenticationError(f"{item_label} is composite")
        primes.append(prime)
    if len(set(primes)) != len(primes):
        raise AuthenticationError(f"{label} contains duplicate primes")
    return primes


def verify_product_record(record, product, label):
    require_exact_keys(record, PRODUCT_KEYS, label)
    decimal = str(product)
    require_equal(
        parse_canonical_decimal(record["decimal"], label + ".decimal"),
        product,
        label + ".decimal",
    )
    require_exact_type(record["hex"], str, label + ".hex")
    require_equal(record["hex"], f"0x{product:x}", label + ".hex")
    require_exact_type(record["bit_length"], int, label + ".bit_length")
    require_equal(record["bit_length"], product.bit_length(), label + ".bit_length")
    require_exact_type(
        record["sha256_decimal_ascii"], str, label + ".sha256_decimal_ascii"
    )
    require_equal(
        record["sha256_decimal_ascii"],
        sha256_bytes(decimal.encode("ascii")),
        label + ".sha256_decimal_ascii",
    )


def verify_manifest_bytes(data, is_prime):
    file_digest = sha256_bytes(data)
    require_equal(file_digest, PINNED_MANIFEST_FILE_SHA256, "manifest file SHA-256")
    manifest = decode_json_strict(data)
    require_exact_keys(manifest, TOP_LEVEL_KEYS, "manifest")

    require_equal(manifest["schema_version"], "ckks-security-parameter-manifest-v1", "schema_version")
    require_equal(manifest["tuple_id"], TUPLE_ID, "tuple_id")
    require_equal(manifest["status"], "PENDING-IMPLEMENTATION/PENDING-ESTIMATOR", "status")
    require_equal(
        manifest["provenance"],
        "independent-lattigo-candidate;aggregate-compatible-not-openfhe-prime-identical",
        "provenance",
    )
    require_equal(manifest["ring_type"], "Standard", "ring_type")
    require_exact_type(manifest["log_n"], int, "log_n")
    require_equal(manifest["log_n"], 16, "log_n")
    require_exact_type(manifest["n"], int, "n")
    require_equal(manifest["n"], 65536, "n")
    require_equal(1 << manifest["log_n"], manifest["n"], "2^log_n")
    require_exact_type(manifest["max_slots"], int, "max_slots")
    require_equal(manifest["max_slots"], 32768, "max_slots")
    require_exact_type(manifest["log_default_scale"], int, "log_default_scale")
    require_equal(manifest["log_default_scale"], 43, "log_default_scale")

    q_primes = verify_prime_records(manifest["q"], 21, manifest["n"], "q", is_prime)
    p_primes = verify_prime_records(manifest["p"], 7, manifest["n"], "p", is_prime)
    if set(q_primes).intersection(p_primes):
        raise AuthenticationError("Q and P prime arrays overlap")
    q_product = math.prod(q_primes)
    p_product = math.prod(p_primes)
    qp_product = q_product * p_product
    verify_product_record(manifest["q_product"], q_product, "q_product")
    verify_product_record(manifest["p_product"], p_product, "p_product")
    verify_product_record(manifest["qp_product"], qp_product, "qp_product")

    require_exact_keys(manifest["main_secret"], SECRET_KEYS, "main_secret")
    require_equal(
        manifest["main_secret"],
        OrderedDict([("type", "balanced-sparse-ternary"), ("weight", 192)]),
        "main_secret",
    )
    require_exact_keys(manifest["ephemeral_secret"], SECRET_KEYS, "ephemeral_secret")
    require_equal(
        manifest["ephemeral_secret"],
        OrderedDict([("type", "balanced-sparse-ternary"), ("weight", 32)]),
        "ephemeral_secret",
    )
    require_exact_keys(manifest["error"], ERROR_KEYS, "error")
    require_equal(manifest["error"]["type"], "bounded-discrete-gaussian", "error.type")
    require_exact_type(manifest["error"]["sigma"], float, "error.sigma")
    require_equal(manifest["error"]["sigma"], 3.2, "error.sigma")
    require_exact_type(manifest["error"]["bound"], float, "error.bound")
    require_equal(manifest["error"]["bound"], 19.2, "error.bound")
    require_exact_type(manifest["estimator_eligible"], bool, "estimator_eligible")
    require_equal(manifest["estimator_eligible"], False, "estimator_eligible")
    require_equal(manifest["missing_evidence"], EXPECTED_MISSING_EVIDENCE, "missing_evidence")
    require_exact_type(
        manifest["canonical_json_sha256"], str, "canonical_json_sha256"
    )
    require_equal(
        manifest["canonical_json_sha256"],
        PINNED_MANIFEST_CANONICAL_SHA256,
        "canonical_json_sha256",
    )

    without_digest = copy.deepcopy(manifest)
    without_digest["canonical_json_sha256"] = ""
    go_compatible_json = json.dumps(
        without_digest,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    require_equal(
        sha256_bytes(go_compatible_json),
        PINNED_MANIFEST_CANONICAL_SHA256,
        "recomputed canonical manifest SHA-256",
    )
    return {
        "manifest": manifest,
        "file_sha256": file_digest,
        "canonical_sha256": PINNED_MANIFEST_CANONICAL_SHA256,
        "q_primes": q_primes,
        "p_primes": p_primes,
        "q_product": q_product,
        "p_product": p_product,
        "qp_product": qp_product,
    }


def verify_negative_manifest_bytes(data, is_prime):
    file_digest = sha256_bytes(data)
    require_equal(
        file_digest,
        PINNED_NEGATIVE_MANIFEST_FILE_SHA256,
        "negative-control manifest file SHA-256",
    )
    manifest = decode_json_strict(data)
    require_exact_keys(manifest, TOP_LEVEL_KEYS, "negative-control manifest")
    require_equal(manifest["schema_version"], "ckks-security-parameter-manifest-v1", "negative schema_version")
    require_equal(manifest["tuple_id"], NEGATIVE_TUPLE_ID, "negative tuple_id")
    require_equal(manifest["status"], "FUNCTIONAL-NOT-SECURE", "negative status")
    require_equal(
        manifest["provenance"],
        "accepted-fixed-n8-functional-circuit-parameter-profile",
        "negative provenance",
    )
    require_equal(manifest["ring_type"], "Standard", "negative ring_type")
    require_exact_type(manifest["log_n"], int, "negative log_n")
    require_equal(manifest["log_n"], 5, "negative log_n")
    require_exact_type(manifest["n"], int, "negative n")
    require_equal(manifest["n"], 32, "negative n")
    require_equal(1 << manifest["log_n"], manifest["n"], "negative 2^log_n")
    require_exact_type(manifest["max_slots"], int, "negative max_slots")
    require_equal(manifest["max_slots"], 16, "negative max_slots")
    require_exact_type(manifest["log_default_scale"], int, "negative log_default_scale")
    require_equal(manifest["log_default_scale"], 35, "negative log_default_scale")

    q_primes = verify_prime_records(manifest["q"], 21, manifest["n"], "negative q", is_prime)
    p_primes = verify_prime_records(manifest["p"], 1, manifest["n"], "negative p", is_prime)
    if set(q_primes).intersection(p_primes):
        raise AuthenticationError("negative-control Q and P prime arrays overlap")
    q_product = math.prod(q_primes)
    p_product = math.prod(p_primes)
    qp_product = q_product * p_product
    verify_product_record(manifest["q_product"], q_product, "negative q_product")
    verify_product_record(manifest["p_product"], p_product, "negative p_product")
    verify_product_record(manifest["qp_product"], qp_product, "negative qp_product")

    require_exact_keys(manifest["main_secret"], IID_TERNARY_KEYS, "negative main_secret")
    require_equal(manifest["main_secret"]["type"], "iid-ternary", "negative main_secret.type")
    require_exact_type(
        manifest["main_secret"]["nonzero_probability"],
        float,
        "negative main_secret.nonzero_probability",
    )
    require_equal(
        manifest["main_secret"]["nonzero_probability"],
        0.6666666666666666,
        "negative main_secret.nonzero_probability",
    )
    require_exact_keys(
        manifest["ephemeral_secret"], TYPE_ONLY_KEYS, "negative ephemeral_secret"
    )
    require_equal(
        manifest["ephemeral_secret"]["type"],
        "not-instantiated-in-dense-functional-profile",
        "negative ephemeral_secret.type",
    )
    require_exact_keys(manifest["error"], ERROR_KEYS, "negative error")
    require_equal(manifest["error"]["type"], "bounded-discrete-gaussian", "negative error.type")
    require_exact_type(manifest["error"]["sigma"], float, "negative error.sigma")
    require_equal(manifest["error"]["sigma"], 3.2, "negative error.sigma")
    require_exact_type(manifest["error"]["bound"], float, "negative error.bound")
    require_equal(manifest["error"]["bound"], 19.2, "negative error.bound")
    require_exact_type(manifest["estimator_eligible"], bool, "negative estimator_eligible")
    require_equal(manifest["estimator_eligible"], False, "negative estimator_eligible")
    require_equal(
        manifest["missing_evidence"],
        [
            "secure-ring-dimension",
            "secure-circuit-profile",
            "evaluation-key-inventory",
            "finite-rlwe-sample-exposures",
        ],
        "negative missing_evidence",
    )
    require_exact_type(
        manifest["canonical_json_sha256"], str, "negative canonical_json_sha256"
    )
    require_equal(
        manifest["canonical_json_sha256"],
        PINNED_NEGATIVE_MANIFEST_CANONICAL_SHA256,
        "negative canonical_json_sha256",
    )
    without_digest = copy.deepcopy(manifest)
    without_digest["canonical_json_sha256"] = ""
    go_compatible_json = json.dumps(
        without_digest,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    require_equal(
        sha256_bytes(go_compatible_json),
        PINNED_NEGATIVE_MANIFEST_CANONICAL_SHA256,
        "recomputed negative canonical manifest SHA-256",
    )
    return {
        "manifest": manifest,
        "file_sha256": file_digest,
        "canonical_sha256": PINNED_NEGATIVE_MANIFEST_CANONICAL_SHA256,
        "q_primes": q_primes,
        "p_primes": p_primes,
        "q_product": q_product,
        "p_product": p_product,
        "qp_product": qp_product,
    }


def run_git(checkout, *arguments, text=False):
    completed = subprocess.run(
        ["git", "-C", str(checkout), *arguments],
        check=False,
        capture_output=True,
        text=text,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    if completed.returncode != 0:
        stderr = completed.stderr
        if not text:
            stderr = stderr.decode("utf-8", errors="replace")
        raise AuthenticationError(
            "git authentication command failed: "
            + " ".join(arguments)
            + (f": {stderr.strip()}" if stderr else "")
        )
    return completed.stdout


def authenticate_estimator(repository):
    checkout = repository / "research" / "upstream" / "lattice-estimator"
    if not (checkout / "estimator").is_dir():
        raise AuthenticationError("pinned estimator checkout is missing")
    checkout_root = Path(
        run_git(checkout, "rev-parse", "--show-toplevel", text=True).strip()
    ).resolve()
    if checkout_root != checkout.resolve():
        raise AuthenticationError(
            f"estimator checkout root mismatch: got {checkout_root}, want {checkout.resolve()}"
        )
    actual_commit = run_git(checkout, "rev-parse", "HEAD", text=True).strip()
    require_equal(actual_commit, PINNED_ESTIMATOR_COMMIT, "estimator HEAD")
    actual_tree = run_git(
        checkout, "rev-parse", f"{PINNED_ESTIMATOR_COMMIT}^{{tree}}", text=True
    ).strip()
    require_equal(actual_tree, PINNED_ESTIMATOR_TREE, "estimator Git tree")

    semantic_diff = subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
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
        raise AuthenticationError(
            "estimator checkout has semantic tracked changes beyond CRLF conversion"
        )
    if semantic_diff.returncode != 0:
        raise AuthenticationError(
            "could not authenticate estimator tracked contents: "
            + semantic_diff.stderr.decode("utf-8", errors="replace").strip()
        )

    untracked = run_git(
        checkout, "ls-files", "--others", "--exclude-standard", "-z", text=False
    )
    untracked_paths = [path for path in untracked.split(b"\0") if path]
    if untracked_paths:
        names = ", ".join(path.decode(errors="replace") for path in untracked_paths[:5])
        raise AuthenticationError(
            f"estimator checkout has untracked, non-ignored files: {names}"
        )

    ls_tree = run_git(
        checkout, "ls-tree", "-r", "-z", PINNED_ESTIMATOR_COMMIT, text=False
    )
    ls_tree_digest = sha256_bytes(ls_tree)
    require_equal(
        ls_tree_digest,
        PINNED_ESTIMATOR_LS_TREE_SHA256,
        "normalized tracked-content listing SHA-256",
    )
    archive = run_git(
        checkout,
        "archive",
        "--format=tar",
        PINNED_ESTIMATOR_COMMIT,
        text=False,
    )
    archive_digest = sha256_bytes(archive)
    require_equal(
        archive_digest,
        PINNED_ESTIMATOR_ARCHIVE_SHA256,
        "authenticated estimator archive SHA-256",
    )
    return {
        "checkout": checkout,
        "commit": actual_commit,
        "tree": actual_tree,
        "normalized_ls_tree_sha256": ls_tree_digest,
        "archive_sha256": archive_digest,
        "archive": archive,
    }


def normalize_lf(data, label):
    normalized = data.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise AuthenticationError(f"{label} contains a lone carriage return")
    return normalized


def parse_explicit_package_records(data, label):
    normalized = normalize_lf(data, label)
    try:
        lines = normalized.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AuthenticationError(f"{label} is not UTF-8") from error
    package_lines = []
    seen_urls = set()
    for line in lines:
        if not line or line.startswith("List of packages in environment:"):
            continue
        if not re.fullmatch(r"https://[^#]+#[0-9a-f]{64}", line):
            raise AuthenticationError(f"{label} contains an invalid record: {line!r}")
        package_url = line.split("#", 1)[0]
        if package_url in seen_urls:
            raise AuthenticationError(f"{label} contains duplicate URL: {package_url}")
        seen_urls.add(package_url)
        package_lines.append(line)
    if len(package_lines) != 389:
        raise AuthenticationError(
            f"{label} package inventory mismatch: got {len(package_lines)}, want 389"
        )
    package_bytes = ("\n".join(package_lines) + "\n").encode("utf-8")
    return package_lines, package_bytes, normalized


def authenticate_sage_toolchain(repository):
    from sage.env import SAGE_VERSION

    require_equal(str(SAGE_VERSION), PINNED_SAGE_VERSION, "running Sage version")
    actual_prefix = Path(sys.prefix).resolve()
    require_equal(actual_prefix, PINNED_SAGE_PREFIX, "running Sage prefix")
    require_equal(Path(sys.base_prefix).resolve(), PINNED_SAGE_PREFIX, "base Sage prefix")
    executable = Path(sys.executable)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise AuthenticationError(f"running Sage Python is not executable: {executable}")
    executable_realpath = executable.resolve()
    require_equal(
        executable_realpath.parent.parent,
        PINNED_SAGE_PREFIX,
        "running Sage Python prefix",
    )
    require_equal(
        executable_realpath.name,
        "python3.12",
        "running Sage Python executable",
    )

    micromamba_path = PINNED_MICROMAMBA_PATH
    if not micromamba_path.is_file() or not os.access(micromamba_path, os.X_OK):
        raise AuthenticationError(f"pinned micromamba is not executable: {micromamba_path}")
    micromamba_digest = sha256_bytes(micromamba_path.read_bytes())
    require_equal(
        micromamba_digest,
        PINNED_MICROMAMBA_SHA256,
        "micromamba binary SHA-256",
    )
    micromamba_version_result = subprocess.run(
        [str(micromamba_path), "--version"],
        check=False,
        capture_output=True,
        env={**os.environ, "MAMBA_ROOT_PREFIX": str(PINNED_TOOLCHAIN_ROOT / "mamba-root")},
    )
    if micromamba_version_result.returncode != 0 or micromamba_version_result.stderr:
        raise AuthenticationError("could not authenticate micromamba runtime version")
    try:
        micromamba_version = micromamba_version_result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise AuthenticationError("micromamba version output is not ASCII") from error
    require_equal(
        micromamba_version,
        PINNED_MICROMAMBA_VERSION,
        "micromamba runtime version",
    )

    toolchain = repository / "research" / "reproduction" / "security" / "toolchain"
    version_path = toolchain / "sage-version.txt"
    lock_path = toolchain / "sage-conda-linux-64-explicit.txt"
    version_bytes = version_path.read_bytes()
    lock_bytes = lock_path.read_bytes()
    require_equal(
        sha256_bytes(version_bytes),
        PINNED_SAGE_VERSION_FILE_SHA256,
        "Sage version-file SHA-256",
    )
    require_equal(
        normalize_lf(version_bytes, "Sage version file").decode("ascii").strip(),
        PINNED_SAGE_VERSION,
        "Sage version-file content",
    )
    normalized_lock = normalize_lf(lock_bytes, "Sage environment lock")
    require_equal(
        sha256_bytes(normalized_lock),
        PINNED_SAGE_LOCK_SHA256,
        "canonical Sage lock SHA-256",
    )
    package_lines, package_bytes, _ = parse_explicit_package_records(
        lock_bytes, "tracked Sage environment lock"
    )
    package_digest = sha256_bytes(package_bytes)
    require_equal(
        package_digest,
        PINNED_SAGE_PACKAGE_RECORDS_SHA256,
        "tracked Sage package-record SHA-256",
    )

    live_export_result = subprocess.run(
        [
            str(micromamba_path),
            "list",
            "--prefix",
            str(PINNED_SAGE_PREFIX),
            "--explicit",
            "--sha256",
        ],
        check=False,
        capture_output=True,
        env={**os.environ, "MAMBA_ROOT_PREFIX": str(PINNED_TOOLCHAIN_ROOT / "mamba-root")},
    )
    if live_export_result.returncode != 0:
        raise AuthenticationError(
            "micromamba live explicit export failed: "
            + live_export_result.stderr.decode("utf-8", errors="replace").strip()
        )
    if live_export_result.stderr:
        raise AuthenticationError(
            "micromamba live explicit export wrote stderr: "
            + live_export_result.stderr.decode("utf-8", errors="replace").strip()
        )
    live_lines, live_package_bytes, live_normalized = parse_explicit_package_records(
        live_export_result.stdout, "live Sage prefix export"
    )
    live_package_digest = sha256_bytes(live_package_bytes)
    require_equal(
        live_package_digest,
        PINNED_SAGE_PACKAGE_RECORDS_SHA256,
        "live Sage package-record SHA-256",
    )
    if live_package_bytes != package_bytes or live_lines != package_lines:
        raise AuthenticationError("live Sage prefix differs from the tracked explicit lock")
    return {
        "sage_version": str(SAGE_VERSION),
        "sage_prefix": PINNED_SAGE_PREFIX.as_posix(),
        "sage_python_realpath": executable_realpath.as_posix(),
        "sage_version_file_sha256": sha256_bytes(version_bytes),
        "sage_lock_canonical_sha256": sha256_bytes(normalized_lock),
        "sage_lock_package_records_sha256": package_digest,
        "sage_lock_package_count": len(package_lines),
        "sage_live_export_sha256": sha256_bytes(live_normalized),
        "sage_live_package_records_sha256": live_package_digest,
        "sage_live_export_stdout_bytes": len(live_export_result.stdout),
        "sage_live_export_stderr_sha256": sha256_bytes(live_export_result.stderr),
        "sage_live_export_exit_code": live_export_result.returncode,
        "micromamba_version": micromamba_version,
        "micromamba_binary_sha256": micromamba_digest,
    }


def repository_from_argument(value):
    repository = Path(
        value or os.environ.get("LCPDTE_REPOSITORY") or os.getcwd()
    ).resolve()
    if not (repository / "go.mod").is_file():
        raise AuthenticationError(
            "repository root must be supplied explicitly or resolve from LCPDTE_REPOSITORY/cwd"
        )
    return repository


def script_path_from_argv():
    path = Path(sys.argv[0]).resolve()
    if not path.is_file() or path.name != "run_ckks_security_estimates.sage.py":
        raise AuthenticationError(f"could not authenticate executing script path: {path}")
    return path


def qualified_type(value):
    cls = type(value)
    return f"{cls.__module__}.{cls.__name__}"


def serialize_problem(problem):
    from sage.all import oo

    if problem.m == oo:
        sample_count = "+Infinity"
    else:
        sample_count = str(problem.m)
    xs = problem.Xs
    xe = problem.Xe
    xs_record = {
        "type": qualified_type(xs),
        "n": int(xs.n),
        "repr": repr(xs),
    }
    if hasattr(xs, "p") and hasattr(xs, "m"):
        xs_record["p"] = int(xs.p)
        xs_record["m"] = int(xs.m)
    if hasattr(xs, "bounds"):
        xs_record["bounds_repr"] = repr(xs.bounds)
    if hasattr(xs, "stddev"):
        xs_record["stddev_repr"] = repr(xs.stddev)
    return {
        "type": qualified_type(problem),
        "repr": repr(problem),
        "n": int(problem.n),
        "q_decimal": str(problem.q),
        "q_bit_length": int(problem.q).bit_length(),
        "Xs": xs_record,
        "Xe": {
            "type": qualified_type(xe),
            "n": int(xe.n),
            "bounds_repr": repr(xe.bounds),
            "stddev_repr": repr(xe.stddev),
            "mean_repr": repr(xe.mean),
            "repr": repr(xe),
        },
        "samples": sample_count,
        "tag": problem.tag,
    }


def serialize_cost_value(value, lwe_parameters_type):
    if isinstance(value, lwe_parameters_type):
        return serialize_problem(value)
    if isinstance(value, str):
        return {"type": qualified_type(value), "value": value, "repr": repr(value)}
    if isinstance(value, bool):
        return {"type": qualified_type(value), "value": value, "repr": repr(value)}
    return {"type": qualified_type(value), "repr": repr(value)}


def rop_bits(value):
    from sage.all import RealField

    real_field = RealField(256)
    numeric = real_field(value)
    if numeric.is_infinity() or numeric != numeric or numeric <= 0:
        raise RuntimeError(f"non-finite or non-positive rop: {value!r}")
    bits = numeric.log2()
    return format(float(bits), ".12f")


def serialize_attack_result(result, lwe_parameters_type):
    if "rop" not in result:
        raise RuntimeError("attack result is missing rop")
    fields = OrderedDict()
    for key in sorted(result.keys(), key=lambda item: str(item)):
        fields[str(key)] = serialize_cost_value(result[key], lwe_parameters_type)
    return {
        "rop_bits": rop_bits(result["rop"]),
        "cost_repr": repr(result),
        "returned_fields": fields,
    }


def build_estimator_input(manifest_authentication, negative_authentication):
    manifest = manifest_authentication["manifest"]
    exposures = []
    for exposure_id, product_key in (
        ("main-secret-exact-q-unlimited", "q_product"),
        ("main-secret-exact-qp-unlimited", "qp_product"),
    ):
        product = manifest[product_key]
        exposures.append(
            {
                "exposure_id": exposure_id,
                "secret_role": "main",
                "rlwe_to_lwe_mapping": "coefficient-embedding-heuristic;n=N",
                "n": manifest["n"],
                "q_decimal": product["decimal"],
                "q_hex": product["hex"],
                "q_bit_length": product["bit_length"],
                "q_decimal_sha256": product["sha256_decimal_ascii"],
                "Xs": {
                    "estimator_constructor": "ND.SparseTernary(96,96,n=65536)",
                    "type": "balanced-sparse-ternary",
                    "positive_weight": 96,
                    "negative_weight": 96,
                    "total_weight": 192,
                },
                "Xe": {
                    "estimator_constructor": "ND.DiscreteGaussian(3.2,n=65536)",
                    "type": "discrete-gaussian",
                    "sigma": 3.2,
                    "implementation_truncation_bound_auxiliary": 19.2,
                },
                "samples": "+Infinity",
                "sample_scope": "conservative-unlimited-sample-sensitivity",
            }
        )
    negative_manifest = negative_authentication["manifest"]
    negative_exposures = []
    for exposure_id, product_key in (
        ("negative-control-exact-q-unlimited", "q_product"),
        ("negative-control-exact-qp-unlimited", "qp_product"),
    ):
        product = negative_manifest[product_key]
        negative_exposures.append(
            {
                "exposure_id": exposure_id,
                "secret_role": "main",
                "rlwe_to_lwe_mapping": "coefficient-embedding-heuristic;n=N",
                "n": negative_manifest["n"],
                "q_decimal": product["decimal"],
                "q_hex": product["hex"],
                "q_bit_length": product["bit_length"],
                "q_decimal_sha256": product["sha256_decimal_ascii"],
                "Xs": {
                    "estimator_constructor": "ND.Ternary",
                    "type": "iid-ternary",
                    "nonzero_probability": 0.6666666666666666,
                },
                "Xe": {
                    "estimator_constructor": "ND.DiscreteGaussian(3.2,n=32)",
                    "type": "discrete-gaussian",
                    "sigma": 3.2,
                    "implementation_truncation_bound_auxiliary": 19.2,
                },
                "samples": "+Infinity",
                "sample_scope": "conservative-unlimited-sample-negative-control",
            }
        )
    return {
        "schema_version": "lcpdte-lwe-estimator-input-v1",
        "tuple_id": TUPLE_ID,
        "manifest_canonical_sha256": PINNED_MANIFEST_CANONICAL_SHA256,
        "manifest_file_sha256": PINNED_MANIFEST_FILE_SHA256,
        "estimator_commit": PINNED_ESTIMATOR_COMMIT,
        "estimator_tree": PINNED_ESTIMATOR_TREE,
        "conversion": {
            "source_problem": "RLWE",
            "target_problem": "LWE",
            "dimension_rule": "n=N",
            "dimension": 65536,
            "scope": "heuristic sensitivity;not a protocol-security proof",
        },
        "cost_models": [
            {
                "model_id": "ADPS16-classical-rough",
                "implementation": "estimator.reduction.ADPS16(mode='classical')",
                "formula": "2^(0.2920*beta)",
                "attacks": ["usvp", "dual_hybrid"],
                "attack_implementations": {
                    "usvp": "estimator.lwe.primal_usvp",
                    "dual_hybrid": "estimator.lwe.dual_hybrid (rough alias of estimator.lwe_dual.MATZOV)",
                },
                "api": "rough-equivalent selected paths: LWE.primal_usvp(...,red_cost_model=RC.ADPS16,red_shape_model='gsa');LWE.dual_hybrid(...,red_cost_model=RC.ADPS16)",
            },
            {
                "model_id": "ADPS16-quantum-rough-sensitivity",
                "implementation": "estimator.reduction.ADPS16(mode='quantum')",
                "formula": "2^(0.2650*beta)",
                "attacks": ["usvp", "dual_hybrid"],
                "attack_implementations": {
                    "usvp": "estimator.lwe.primal_usvp",
                    "dual_hybrid": "estimator.lwe.dual_hybrid (rough alias of estimator.lwe_dual.MATZOV)",
                },
                "api": "LWE.primal_usvp(...,red_shape_model='gsa');LWE.dual_hybrid(...)",
            },
        ],
        "exposures": exposures,
        "negative_control": {
            "tuple_id": NEGATIVE_TUPLE_ID,
            "manifest_canonical_sha256": PINNED_NEGATIVE_MANIFEST_CANONICAL_SHA256,
            "manifest_file_sha256": PINNED_NEGATIVE_MANIFEST_FILE_SHA256,
            "expected_gate": "FAIL",
            "threshold_bits": 128,
            "exposures": negative_exposures,
        },
        "intentionally_unestimated": [
            {
                "secret_role": "main",
                "reason": "finite RLWE sample counts are absent",
            },
            {
                "secret_role": "ephemeral",
                "declared_weight": 32,
                "reason": "the ephemeral-secret exposure modulus and sample inventory are absent",
            },
        ],
    }


def estimate_parameter_rows(LWE, ADPS16, RC, parameters, exposure_id):
    from estimator.lwe_parameters import LWEParameters

    classical_stdout = io.StringIO()
    classical_stderr = io.StringIO()
    with contextlib.redirect_stdout(classical_stdout), contextlib.redirect_stderr(
        classical_stderr
    ):
        classical_result = {
            "usvp": LWE.primal_usvp(
                parameters,
                red_cost_model=RC.ADPS16,
                red_shape_model="gsa",
            ),
            "dual_hybrid": LWE.dual_hybrid(
                parameters,
                red_cost_model=RC.ADPS16,
            ),
        }
    classical_attacks = OrderedDict(
        (
            attack,
            serialize_attack_result(classical_result[attack], LWEParameters),
        )
        for attack in ("usvp", "dual_hybrid")
    )
    classical_minimum = min(
        (
            (float(result["rop_bits"]), attack)
            for attack, result in classical_attacks.items()
        ),
        key=lambda item: (item[0], item[1]),
    )
    rows = [
        {
            "exposure_id": exposure_id,
            "cost_model_id": "ADPS16-classical-rough",
            "cost_model": {
                "class": "estimator.reduction.ADPS16",
                "mode": "classical",
                "formula": "2^(0.2920*beta)",
            },
            "invocation": "rough-equivalent:LWE.primal_usvp(red_cost_model=RC.ADPS16,red_shape_model='gsa');LWE.dual_hybrid(red_cost_model=RC.ADPS16)",
            "parameters": serialize_problem(parameters),
            "attacks": classical_attacks,
            "minimum": {
                "attack": classical_minimum[1],
                "rop_bits": f"{classical_minimum[0]:.12f}",
            },
            "estimator_stdout": classical_stdout.getvalue(),
            "estimator_stderr": classical_stderr.getvalue(),
        }
    ]

    quantum_model = ADPS16(mode="quantum")
    quantum_stdout = io.StringIO()
    quantum_stderr = io.StringIO()
    with contextlib.redirect_stdout(quantum_stdout), contextlib.redirect_stderr(
        quantum_stderr
    ):
        quantum_result = {
            "usvp": LWE.primal_usvp(
                parameters,
                red_cost_model=quantum_model,
                red_shape_model="gsa",
            ),
            "dual_hybrid": LWE.dual_hybrid(
                parameters,
                red_cost_model=quantum_model,
            ),
        }
    quantum_attacks = OrderedDict(
        (
            attack,
            serialize_attack_result(quantum_result[attack], LWEParameters),
        )
        for attack in ("usvp", "dual_hybrid")
    )
    quantum_minimum = min(
        (
            (float(result["rop_bits"]), attack)
            for attack, result in quantum_attacks.items()
        ),
        key=lambda item: (item[0], item[1]),
    )
    rows.append(
        {
            "exposure_id": exposure_id,
            "cost_model_id": "ADPS16-quantum-rough-sensitivity",
            "cost_model": {
                "class": "estimator.reduction.ADPS16",
                "mode": "quantum",
                "formula": "2^(0.2650*beta)",
            },
            "invocation": "LWE.primal_usvp(red_shape_model='gsa');LWE.dual_hybrid;ADPS16(mode='quantum')",
            "parameters": serialize_problem(parameters),
            "attacks": quantum_attacks,
            "minimum": {
                "attack": quantum_minimum[1],
                "rop_bits": f"{quantum_minimum[0]:.12f}",
            },
            "estimator_stdout": quantum_stdout.getvalue(),
            "estimator_stderr": quantum_stderr.getvalue(),
        }
    )
    return rows


def run_estimates(LWE, ND, ADPS16, RC, estimator_input):
    from sage.all import oo

    candidate_rows = []
    for exposure in estimator_input["exposures"]:
        parameters = LWE.Parameters(
            n=exposure["n"],
            q=int(exposure["q_decimal"]),
            Xs=ND.SparseTernary(96, 96, exposure["n"]),
            Xe=ND.DiscreteGaussian(3.2, n=exposure["n"]),
            m=oo,
            tag=exposure["exposure_id"],
        )
        if (
            parameters.n != 65536
            or parameters.Xs.p != 96
            or parameters.Xs.m != 96
            or parameters.Xe.n != 65536
        ):
            raise RuntimeError("constructed candidate estimator parameters drifted")
        if parameters.m != oo:
            raise RuntimeError("candidate sensitivity row is not unlimited-sample")
        candidate_rows.extend(
            estimate_parameter_rows(
                LWE, ADPS16, RC, parameters, exposure["exposure_id"]
            )
        )

    negative_rows = []
    for exposure in estimator_input["negative_control"]["exposures"]:
        parameters = LWE.Parameters(
            n=exposure["n"],
            q=int(exposure["q_decimal"]),
            Xs=ND.Ternary,
            Xe=ND.DiscreteGaussian(3.2, n=exposure["n"]),
            m=oo,
            tag=exposure["exposure_id"],
        )
        if (
            parameters.n != 32
            or tuple(parameters.Xs.bounds) != (-1, 1)
            or parameters.Xe.n != 32
        ):
            raise RuntimeError("constructed negative-control estimator parameters drifted")
        if parameters.m != oo:
            raise RuntimeError("negative-control sensitivity row is not unlimited-sample")
        negative_rows.extend(
            estimate_parameter_rows(
                LWE, ADPS16, RC, parameters, exposure["exposure_id"]
            )
        )
    return candidate_rows, negative_rows


def compute_global_minima(rows):
    minima = OrderedDict()
    for mode in ("classical", "quantum"):
        candidates = []
        for row in rows:
            if row["cost_model"]["mode"] != mode:
                continue
            for attack, result in row["attacks"].items():
                candidates.append(
                    (
                        float(result["rop_bits"]),
                        row["exposure_id"],
                        attack,
                        result["rop_bits"],
                    )
                )
        if not candidates:
            raise RuntimeError(f"no {mode} result candidates")
        minimum = min(candidates, key=lambda item: (item[0], item[1], item[2]))
        minima[mode] = {
            "exposure_id": minimum[1],
            "attack": minimum[2],
            "rop_bits": minimum[3],
        }
    return minima


def estimate_results_payload(candidate_rows, negative_rows):
    return {
        "candidate_estimates": candidate_rows,
        "candidate_global_minima": compute_global_minima(candidate_rows),
        "negative_estimates": negative_rows,
        "negative_global_minima": compute_global_minima(negative_rows),
    }


def estimate_results_digest(candidate_rows, negative_rows):
    return sha256_bytes(
        canonical_json_bytes(estimate_results_payload(candidate_rows, negative_rows))
    )


def source_digests_from_snapshot(snapshot):
    return OrderedDict(
        (relative, sha256_bytes((snapshot / relative).read_bytes()))
        for relative in ESTIMATOR_SOURCE_FILES
    )


def source_digests_from_archive(archive):
    with tempfile.TemporaryDirectory(prefix="lcpdte-estimator-sources-") as temporary:
        snapshot = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as snapshot_tar:
            snapshot_tar.extractall(snapshot, filter="data")
        return source_digests_from_snapshot(snapshot)


def toolchain_transcript_record(
    sage_authentication,
    estimator_authentication,
    source_digests,
    script_digest,
):
    return {
        **sage_authentication,
        "estimator_commit": estimator_authentication["commit"],
        "estimator_tree": estimator_authentication["tree"],
        "estimator_normalized_ls_tree_sha256": estimator_authentication[
            "normalized_ls_tree_sha256"
        ],
        "estimator_archive_sha256": estimator_authentication["archive_sha256"],
        "estimator_import": "authenticated-pinned-git-archive",
        "estimator_source_sha256": source_digests,
        "conversion_script_sha256": script_digest,
    }


def manifest_transcript_record(authentication, tuple_id):
    return {
        "path": f"research/reproduction/security/parameters/{tuple_id}.json",
        "file_sha256": authentication["file_sha256"],
        "canonical_json_sha256": authentication["canonical_sha256"],
        "q_prime_count": len(authentication["q_primes"]),
        "p_prime_count": len(authentication["p_primes"]),
        "q_product_decimal": str(authentication["q_product"]),
        "p_product_decimal": str(authentication["p_product"]),
        "qp_product_decimal": str(authentication["qp_product"]),
        "q_product_bit_length": authentication["q_product"].bit_length(),
        "p_product_bit_length": authentication["p_product"].bit_length(),
        "qp_product_bit_length": authentication["qp_product"].bit_length(),
        "prime_checks": "all exact Q/P entries are distinct primes congruent to 1 mod 2N",
    }


def build_transcript(repository, script_path):
    from sage.all import is_prime

    toolchain = authenticate_sage_toolchain(repository)
    estimator_authentication = authenticate_estimator(repository)
    manifest_path = (
        repository
        / "research"
        / "reproduction"
        / "security"
        / "parameters"
        / f"{TUPLE_ID}.json"
    )
    manifest_authentication = verify_manifest_bytes(manifest_path.read_bytes(), is_prime)
    negative_manifest_path = (
        repository
        / "research"
        / "reproduction"
        / "security"
        / "parameters"
        / f"{NEGATIVE_TUPLE_ID}.json"
    )
    negative_authentication = verify_negative_manifest_bytes(
        negative_manifest_path.read_bytes(), is_prime
    )
    estimator_input = build_estimator_input(
        manifest_authentication, negative_authentication
    )
    input_bytes = canonical_json_bytes(estimator_input)

    archive = estimator_authentication["archive"]
    with tempfile.TemporaryDirectory(prefix="lcpdte-estimator-") as temporary:
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
                raise AuthenticationError(
                    f"estimator import escaped authenticated snapshot: {estimator_module_path}"
                )
            if getattr(RC.ADPS16, "mode", None) != "classical":
                raise AuthenticationError("rough classical RC.ADPS16 mode drifted")
            source_digests = source_digests_from_snapshot(snapshot)
            rows, negative_rows = run_estimates(
                LWE, ND, ADPS16, RC, estimator_input
            )
        finally:
            sys.path.remove(str(snapshot))

    negative_minima = compute_global_minima(negative_rows)
    if float(negative_minima["classical"]["rop_bits"]) >= 128:
        raise RuntimeError(
            "functional negative control did not demonstrate classical cost below 128 bits"
        )
    results_digest = estimate_results_digest(rows, negative_rows)
    if results_digest != PINNED_ESTIMATE_RESULTS_SHA256:
        raise AuthenticationError(
            "estimator result payload drifted: "
            f"got {results_digest}, want {PINNED_ESTIMATE_RESULTS_SHA256}"
        )
    transcript = {
        "schema_version": "lcpdte-lwe-estimator-transcript-v1",
        "decision": {
            "status": "INCONCLUSIVE",
            "not_pass": True,
            "reasons": [
                "finite main-secret RLWE sample counts are absent",
                "the evaluation-key inventory and its exact exposures are absent",
                "the ephemeral h=32 secret exposure modulus and sample count are absent",
                "an accepted secure circuit profile bound to this tuple is absent",
            ],
            "interpretation": "The rows are unlimited-sample Core-SVP sensitivity estimates, not a 128-bit application-security claim.",
        },
        "toolchain": toolchain_transcript_record(
            toolchain,
            estimator_authentication,
            source_digests,
            sha256_bytes(script_path.read_bytes()),
        ),
        "manifest_authentication": manifest_transcript_record(
            manifest_authentication, TUPLE_ID
        ),
        "negative_control_manifest_authentication": manifest_transcript_record(
            negative_authentication, NEGATIVE_TUPLE_ID
        ),
        "estimator_input_sha256": sha256_bytes(input_bytes),
        "estimator_input": estimator_input,
        "estimate_results_sha256": results_digest,
        "estimates": rows,
        "global_minima": compute_global_minima(rows),
        "negative_control": {
            "tuple_id": NEGATIVE_TUPLE_ID,
            "decision": "FAIL",
            "threshold_bits": 128,
            "classical_below_threshold": True,
            "global_minima": negative_minima,
            "estimates": negative_rows,
            "effect_on_candidate_decision": "none;the exact candidate remains INCONCLUSIVE",
        },
        "eligibility": {
            "secure_performance_table": False,
            "estimator_gate": "INCONCLUSIVE",
            "conditional_sensitivity_only": True,
        },
    }
    return transcript


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def worker_main(repository):
    transcript = build_transcript(repository, script_path_from_argv())
    sys.stdout.buffer.write(canonical_json_bytes(transcript))
    sys.stdout.buffer.flush()
    return 0


def parent_main(repository, output_directory, run_id):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", run_id):
        raise AuthenticationError("run-id must match [a-z0-9][a-z0-9-]{0,31}")
    script_path = script_path_from_argv()
    output_directory.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(script_path),
        "--worker",
        "--repository",
        str(repository),
    ]
    environment = dict(os.environ)
    for key in ("PYTHONHOME", "PYTHONPATH"):
        environment.pop(key, None)
    environment.update(
        {
            "LCPDTE_REPOSITORY": str(repository),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "TZ": "UTC",
        }
    )
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        env=environment,
        cwd=repository,
    )
    wall_time = time.perf_counter() - started

    stdout_path = output_directory / f"{TRANSCRIPT_STEM}.{run_id}.stdout.json"
    stderr_path = output_directory / f"{TRANSCRIPT_STEM}.{run_id}.stderr.txt"
    metadata_path = output_directory / f"{TRANSCRIPT_STEM}.{run_id}.metadata.json"
    atomic_write(stdout_path, completed.stdout)
    atomic_write(stderr_path, completed.stderr)

    metadata = {
        "schema_version": "lcpdte-estimator-run-metadata-v1",
        "run_id": run_id,
        "worker_command": command,
        "worker_environment": {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "TZ": "UTC",
        },
        "exit_code": completed.returncode,
        "wall_time_seconds": f"{wall_time:.6f}",
        "stdout": {
            "path": stdout_path.relative_to(repository).as_posix(),
            "bytes": len(completed.stdout),
            "sha256": sha256_bytes(completed.stdout),
        },
        "stderr": {
            "path": stderr_path.relative_to(repository).as_posix(),
            "bytes": len(completed.stderr),
            "sha256": sha256_bytes(completed.stderr),
        },
        "conversion_script_sha256": sha256_bytes(script_path.read_bytes()),
    }

    if completed.returncode == 0:
        transcript = decode_json_strict(completed.stdout)
        if transcript.get("schema_version") != "lcpdte-lwe-estimator-transcript-v1":
            raise AuthenticationError("worker transcript schema mismatch")
        if transcript["decision"]["status"] != "INCONCLUSIVE":
            raise AuthenticationError("worker attempted a non-INCONCLUSIVE decision")
        require_equal(
            transcript["toolchain"]["conversion_script_sha256"],
            sha256_bytes(script_path.read_bytes()),
            "worker conversion-script SHA-256",
        )
        transcript_bytes = canonical_json_bytes(transcript)
        if transcript_bytes != completed.stdout:
            raise AuthenticationError("worker stdout is not canonical JSON")
        estimator_input = transcript["estimator_input"]
        input_bytes = canonical_json_bytes(estimator_input)
        require_equal(
            sha256_bytes(input_bytes),
            transcript["estimator_input_sha256"],
            "worker estimator-input SHA-256",
        )
        transcript_path = output_directory / f"{TRANSCRIPT_STEM}.transcript.json"
        input_path = output_directory / f"{TRANSCRIPT_STEM}.input.json"
        atomic_write(transcript_path, transcript_bytes)
        atomic_write(input_path, input_bytes)
        metadata["canonical_transcript"] = {
            "path": transcript_path.relative_to(repository).as_posix(),
            "sha256": sha256_bytes(transcript_bytes),
        }
        metadata["deterministic_input"] = {
            "path": input_path.relative_to(repository).as_posix(),
            "sha256": sha256_bytes(input_bytes),
        }
        metadata["decision"] = "INCONCLUSIVE"

    atomic_write(metadata_path, pretty_json_bytes(metadata))
    if completed.returncode != 0:
        sys.stderr.write(
            f"estimator worker failed with exit {completed.returncode}; see {metadata_path}\n"
        )
        return completed.returncode
    print(
        "ESTIMATE_RUN_OK "
        f"run_id={run_id} decision=INCONCLUSIVE "
        f"transcript_sha256={metadata['canonical_transcript']['sha256']}"
    )
    return 0


def build_repeat_expected_context(repository, script_path):
    from sage.all import is_prime

    sage_authentication = authenticate_sage_toolchain(repository)
    estimator_authentication = authenticate_estimator(repository)
    manifest_path = (
        repository
        / "research"
        / "reproduction"
        / "security"
        / "parameters"
        / f"{TUPLE_ID}.json"
    )
    negative_manifest_path = (
        repository
        / "research"
        / "reproduction"
        / "security"
        / "parameters"
        / f"{NEGATIVE_TUPLE_ID}.json"
    )
    manifest_authentication = verify_manifest_bytes(manifest_path.read_bytes(), is_prime)
    negative_authentication = verify_negative_manifest_bytes(
        negative_manifest_path.read_bytes(), is_prime
    )
    source_digests = source_digests_from_archive(estimator_authentication["archive"])
    script_digest = sha256_bytes(script_path.read_bytes())
    return {
        "script_digest": script_digest,
        "toolchain": toolchain_transcript_record(
            sage_authentication,
            estimator_authentication,
            source_digests,
            script_digest,
        ),
        "manifest_authentication": manifest_transcript_record(
            manifest_authentication, TUPLE_ID
        ),
        "negative_manifest_authentication": manifest_transcript_record(
            negative_authentication, NEGATIVE_TUPLE_ID
        ),
        "estimator_input": build_estimator_input(
            manifest_authentication, negative_authentication
        ),
    }


def validate_serialized_parameters(parameters, exposure, negative_control):
    require_exact_keys(parameters, SERIALIZED_PARAMETER_KEYS, "serialized parameters")
    exposure_id = exposure["exposure_id"]
    require_equal(
        parameters["type"],
        "estimator.lwe_parameters.LWEParameters",
        f"{exposure_id} parameter type",
    )
    require_equal(parameters["n"], exposure["n"], f"{exposure_id} n")
    require_equal(
        parameters["q_decimal"], exposure["q_decimal"], f"{exposure_id} exact modulus"
    )
    require_equal(
        parameters["q_bit_length"],
        exposure["q_bit_length"],
        f"{exposure_id} modulus bit length",
    )
    require_equal(parameters["samples"], "+Infinity", f"{exposure_id} samples")
    require_equal(parameters["tag"], exposure_id, f"{exposure_id} tag")
    expected_xe = {
        "type": "estimator.nd.DiscreteGaussian",
        "n": exposure["n"],
        "bounds_repr": "(-16, 16)" if negative_control else "(-52, 52)",
        "stddev_repr": "3.20000000000000",
        "mean_repr": "0.000000000000000",
        "repr": "D(σ=3.20)",
    }
    require_equal(parameters["Xe"], expected_xe, f"{exposure_id} Xe")
    if negative_control:
        expected_xs = {
            "type": "estimator.nd.Uniform",
            "n": 32,
            "repr": "D(σ=0.82)",
            "bounds_repr": "(-1, 1)",
            "stddev_repr": "0.816496580927726",
        }
        xs_repr = "D(σ=0.82)"
    else:
        expected_xs = {
            "type": "estimator.nd.SparseTernary",
            "n": 65536,
            "repr": "T(p=96, m=96, n=65536)",
            "p": 96,
            "m": 96,
            "bounds_repr": "(-1, 1)",
            "stddev_repr": "0.0541265877365274",
        }
        xs_repr = "T(p=96, m=96, n=65536)"
    require_equal(parameters["Xs"], expected_xs, f"{exposure_id} Xs")
    expected_repr = (
        f"LWEParameters(n={exposure['n']}, q={exposure['q_decimal']}, "
        f"Xs={xs_repr}, Xe=D(σ=3.20), m=+Infinity, tag='{exposure_id}')"
    )
    require_equal(parameters["repr"], expected_repr, f"{exposure_id} parameter repr")


def validate_attack_result(attack_name, result, parameters, exposure_id):
    from sage.all import RealField

    require_exact_keys(result, ATTACK_RESULT_KEYS, f"{exposure_id} {attack_name} result")
    if not isinstance(result["cost_repr"], str) or not result["cost_repr"]:
        raise AuthenticationError(f"{exposure_id} {attack_name} cost repr is empty")
    returned_fields = result["returned_fields"]
    if attack_name == "usvp":
        expected_fields = ["beta", "d", "delta", "problem", "red", "rop", "tag"]
    else:
        expected_fields = [
            "N",
            "beta",
            "beta_",
            "guess",
            "m",
            "p",
            "problem",
            "red",
            "rop",
            "t",
            "zeta",
        ]
    require_exact_keys(
        returned_fields,
        expected_fields,
        f"{exposure_id} {attack_name} returned fields",
    )
    require_equal(
        returned_fields["problem"],
        parameters,
        f"{exposure_id} {attack_name} returned problem",
    )
    for field, value in returned_fields.items():
        if field == "problem":
            continue
        if not isinstance(value, dict):
            raise AuthenticationError(
                f"{exposure_id} {attack_name} field {field} is not serialized"
            )
        expected_value_keys = ["type", "value", "repr"] if "value" in value else ["type", "repr"]
        require_exact_keys(
            value,
            expected_value_keys,
            f"{exposure_id} {attack_name} field {field}",
        )
    rop_repr = returned_fields["rop"]["repr"]
    try:
        rop = RealField(256)(rop_repr)
    except (TypeError, ValueError) as error:
        raise AuthenticationError(
            f"{exposure_id} {attack_name} rop repr is not numeric"
        ) from error
    if rop.is_infinity() or rop != rop or rop <= 0:
        raise AuthenticationError(f"{exposure_id} {attack_name} rop is invalid")
    expected_bits = format(float(rop.log2()), ".12f")
    require_equal(
        result["rop_bits"],
        expected_bits,
        f"{exposure_id} {attack_name} recomputed rop bits",
    )


def validate_estimate_rows(rows, exposures, negative_control):
    expected_inventory = [
        (exposure["exposure_id"], mode)
        for exposure in exposures
        for mode in ("classical", "quantum")
    ]
    if not isinstance(rows, list):
        raise AuthenticationError("estimate rows are not an array")
    actual_inventory = []
    for row in rows:
        require_exact_keys(row, ESTIMATE_ROW_KEYS, "estimate row")
        actual_inventory.append((row["exposure_id"], row["cost_model"]["mode"]))
    require_equal(actual_inventory, expected_inventory, "ordered estimate-row inventory")

    exposure_by_id = {exposure["exposure_id"]: exposure for exposure in exposures}
    for row in rows:
        exposure_id = row["exposure_id"]
        exposure = exposure_by_id[exposure_id]
        mode = row["cost_model"]["mode"]
        if mode == "classical":
            expected_model_id = "ADPS16-classical-rough"
            expected_model = {
                "class": "estimator.reduction.ADPS16",
                "mode": "classical",
                "formula": "2^(0.2920*beta)",
            }
            expected_invocation = (
                "rough-equivalent:LWE.primal_usvp(red_cost_model=RC.ADPS16,"
                "red_shape_model='gsa');LWE.dual_hybrid(red_cost_model=RC.ADPS16)"
            )
        else:
            expected_model_id = "ADPS16-quantum-rough-sensitivity"
            expected_model = {
                "class": "estimator.reduction.ADPS16",
                "mode": "quantum",
                "formula": "2^(0.2650*beta)",
            }
            expected_invocation = (
                "LWE.primal_usvp(red_shape_model='gsa');"
                "LWE.dual_hybrid;ADPS16(mode='quantum')"
            )
        require_equal(row["cost_model_id"], expected_model_id, f"{exposure_id} model id")
        require_equal(row["cost_model"], expected_model, f"{exposure_id} cost model")
        require_equal(row["invocation"], expected_invocation, f"{exposure_id} invocation")
        require_equal(row["estimator_stdout"], "", f"{exposure_id} estimator stdout")
        require_equal(row["estimator_stderr"], "", f"{exposure_id} estimator stderr")
        validate_serialized_parameters(row["parameters"], exposure, negative_control)
        require_exact_keys(row["attacks"], ["usvp", "dual_hybrid"], f"{exposure_id} attacks")
        for attack_name, attack in row["attacks"].items():
            validate_attack_result(
                attack_name, attack, row["parameters"], exposure_id
            )
        minimum = min(
            (
                (float(attack["rop_bits"]), attack_name, attack["rop_bits"])
                for attack_name, attack in row["attacks"].items()
            ),
            key=lambda value: (value[0], value[1]),
        )
        require_equal(
            row["minimum"],
            {"attack": minimum[1], "rop_bits": minimum[2]},
            f"{exposure_id} row minimum",
        )


def validate_transcript_bytes(transcript_bytes, expected_context):
    if not transcript_bytes:
        raise AuthenticationError("successful-run transcript is empty")
    transcript = decode_json_strict(transcript_bytes)
    require_exact_keys(transcript, TRANSCRIPT_TOP_LEVEL_KEYS, "estimator transcript")
    require_equal(
        transcript["schema_version"],
        "lcpdte-lwe-estimator-transcript-v1",
        "transcript schema_version",
    )
    if canonical_json_bytes(transcript) != transcript_bytes:
        raise AuthenticationError("successful-run transcript is not canonical JSON")
    expected_decision = {
        "status": "INCONCLUSIVE",
        "not_pass": True,
        "reasons": [
            "finite main-secret RLWE sample counts are absent",
            "the evaluation-key inventory and its exact exposures are absent",
            "the ephemeral h=32 secret exposure modulus and sample count are absent",
            "an accepted secure circuit profile bound to this tuple is absent",
        ],
        "interpretation": "The rows are unlimited-sample Core-SVP sensitivity estimates, not a 128-bit application-security claim.",
    }
    require_equal(transcript["decision"], expected_decision, "candidate decision record")
    require_exact_keys(
        transcript["toolchain"],
        list(expected_context["toolchain"].keys()),
        "transcript toolchain",
    )
    require_equal(
        transcript["toolchain"], expected_context["toolchain"], "transcript toolchain"
    )
    require_equal(
        transcript["manifest_authentication"],
        expected_context["manifest_authentication"],
        "transcript manifest authentication",
    )
    require_equal(
        transcript["negative_control_manifest_authentication"],
        expected_context["negative_manifest_authentication"],
        "transcript negative manifest authentication",
    )

    estimator_input = transcript["estimator_input"]
    require_equal(
        estimator_input,
        expected_context["estimator_input"],
        "complete deterministic estimator input",
    )
    input_bytes = canonical_json_bytes(estimator_input)
    require_equal(
        sha256_bytes(input_bytes),
        transcript["estimator_input_sha256"],
        "transcript embedded-input SHA-256",
    )
    validate_estimate_rows(
        transcript["estimates"], estimator_input["exposures"], negative_control=False
    )
    negative = transcript["negative_control"]
    require_exact_keys(
        negative,
        [
            "tuple_id",
            "decision",
            "threshold_bits",
            "classical_below_threshold",
            "global_minima",
            "estimates",
            "effect_on_candidate_decision",
        ],
        "negative-control transcript",
    )
    require_equal(negative["tuple_id"], NEGATIVE_TUPLE_ID, "negative-control tuple")
    require_equal(negative["decision"], "FAIL", "negative-control decision")
    require_equal(negative["threshold_bits"], 128, "negative-control threshold")
    require_equal(
        negative["classical_below_threshold"],
        True,
        "negative-control threshold result",
    )
    require_equal(
        negative["effect_on_candidate_decision"],
        "none;the exact candidate remains INCONCLUSIVE",
        "negative-control decision separation",
    )
    validate_estimate_rows(
        negative["estimates"],
        estimator_input["negative_control"]["exposures"],
        negative_control=True,
    )
    candidate_minima = compute_global_minima(transcript["estimates"])
    negative_minima = compute_global_minima(negative["estimates"])
    require_equal(transcript["global_minima"], candidate_minima, "candidate global minima")
    require_equal(negative["global_minima"], negative_minima, "negative global minima")
    observed_results_digest = estimate_results_digest(
        transcript["estimates"], negative["estimates"]
    )
    require_equal(
        transcript["estimate_results_sha256"],
        observed_results_digest,
        "transcript estimator-result SHA-256",
    )
    require_equal(
        observed_results_digest,
        PINNED_ESTIMATE_RESULTS_SHA256,
        "pinned estimator-result SHA-256",
    )
    if float(negative_minima["classical"]["rop_bits"]) >= 128:
        raise AuthenticationError("negative-control classical minimum is not below 128 bits")
    require_equal(
        transcript["eligibility"],
        {
            "secure_performance_table": False,
            "estimator_gate": "INCONCLUSIVE",
            "conditional_sensitivity_only": True,
        },
        "transcript eligibility",
    )
    return transcript, input_bytes


def validate_successful_run(
    repository, output_directory, run_id, script_path, expected_context
):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", run_id):
        raise AuthenticationError(f"invalid repeat run-id: {run_id}")
    stdout_path = output_directory / f"{TRANSCRIPT_STEM}.{run_id}.stdout.json"
    stderr_path = output_directory / f"{TRANSCRIPT_STEM}.{run_id}.stderr.txt"
    metadata_path = output_directory / f"{TRANSCRIPT_STEM}.{run_id}.metadata.json"
    stdout_bytes = stdout_path.read_bytes()
    stderr_bytes = stderr_path.read_bytes()
    metadata_bytes = metadata_path.read_bytes()
    metadata = decode_json_strict(metadata_bytes)
    require_exact_keys(metadata, RUN_METADATA_KEYS, f"{run_id} metadata")
    require_equal(
        metadata["schema_version"],
        "lcpdte-estimator-run-metadata-v1",
        f"{run_id} metadata schema",
    )
    require_equal(metadata["run_id"], run_id, f"{run_id} metadata run-id")
    require_equal(metadata["exit_code"], 0, f"{run_id} worker exit code")
    if not re.fullmatch(r"[0-9]+\.[0-9]{6}", metadata["wall_time_seconds"]):
        raise AuthenticationError(f"{run_id} wall time is not a six-decimal non-negative value")
    script_digest = expected_context["script_digest"]
    require_equal(
        metadata["conversion_script_sha256"],
        script_digest,
        f"{run_id} metadata script SHA-256",
    )
    expected_command = [
        sys.executable,
        str(script_path),
        "--worker",
        "--repository",
        str(repository),
    ]
    require_equal(metadata["worker_command"], expected_command, f"{run_id} worker command")
    require_equal(
        metadata["worker_environment"],
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "TZ": "UTC",
        },
        f"{run_id} worker environment",
    )
    expected_stdout_relative = stdout_path.relative_to(repository).as_posix()
    expected_stderr_relative = stderr_path.relative_to(repository).as_posix()
    require_exact_keys(metadata["stdout"], ["path", "bytes", "sha256"], f"{run_id} stdout")
    require_exact_keys(metadata["stderr"], ["path", "bytes", "sha256"], f"{run_id} stderr")
    require_exact_keys(
        metadata["canonical_transcript"],
        ["path", "sha256"],
        f"{run_id} canonical transcript",
    )
    require_exact_keys(
        metadata["deterministic_input"],
        ["path", "sha256"],
        f"{run_id} deterministic input",
    )
    require_equal(metadata["stdout"]["path"], expected_stdout_relative, f"{run_id} stdout path")
    require_equal(metadata["stdout"]["bytes"], len(stdout_bytes), f"{run_id} stdout bytes")
    require_equal(
        metadata["stdout"]["sha256"], sha256_bytes(stdout_bytes), f"{run_id} stdout SHA-256"
    )
    require_equal(metadata["stderr"]["path"], expected_stderr_relative, f"{run_id} stderr path")
    require_equal(metadata["stderr"]["bytes"], len(stderr_bytes), f"{run_id} stderr bytes")
    require_equal(
        metadata["stderr"]["sha256"], sha256_bytes(stderr_bytes), f"{run_id} stderr SHA-256"
    )
    if stderr_bytes:
        raise AuthenticationError(f"{run_id} successful worker stderr is not empty")

    transcript, input_bytes = validate_transcript_bytes(stdout_bytes, expected_context)
    transcript_path = output_directory / f"{TRANSCRIPT_STEM}.transcript.json"
    input_path = output_directory / f"{TRANSCRIPT_STEM}.input.json"
    require_equal(
        metadata["canonical_transcript"]["path"],
        transcript_path.relative_to(repository).as_posix(),
        f"{run_id} canonical-transcript path",
    )
    require_equal(
        metadata["canonical_transcript"]["sha256"],
        sha256_bytes(stdout_bytes),
        f"{run_id} canonical-transcript SHA-256",
    )
    require_equal(transcript_path.read_bytes(), stdout_bytes, f"{run_id} canonical transcript bytes")
    require_equal(
        metadata["deterministic_input"]["path"],
        input_path.relative_to(repository).as_posix(),
        f"{run_id} deterministic-input path",
    )
    require_equal(
        metadata["deterministic_input"]["sha256"],
        sha256_bytes(input_bytes),
        f"{run_id} deterministic-input SHA-256",
    )
    require_equal(input_path.read_bytes(), input_bytes, f"{run_id} deterministic input bytes")
    require_equal(metadata["decision"], "INCONCLUSIVE", f"{run_id} metadata decision")
    return {
        "stdout": stdout_bytes,
        "stderr": stderr_bytes,
        "metadata": metadata_bytes,
        "transcript": transcript,
        "input": input_bytes,
    }


def verify_repeat(repository, output_directory, first_run, second_run):
    if first_run == second_run:
        raise AuthenticationError("repeat verification requires two distinct run-ids")
    script_path = script_path_from_argv()
    expected_context = build_repeat_expected_context(repository, script_path)
    first = validate_successful_run(
        repository, output_directory, first_run, script_path, expected_context
    )
    second = validate_successful_run(
        repository, output_directory, second_run, script_path, expected_context
    )
    first_bytes = first["stdout"]
    second_bytes = second["stdout"]
    if first_bytes != second_bytes:
        raise AuthenticationError("repeat-run stdout transcripts are not byte-identical")
    transcript = first["transcript"]
    record = {
        "schema_version": "lcpdte-estimator-determinism-record-v1",
        "first_run": first_run,
        "second_run": second_run,
        "byte_identical": True,
        "bytes": len(first_bytes),
        "sha256": sha256_bytes(first_bytes),
        "decision": transcript["decision"]["status"],
        "negative_control_decision": transcript["negative_control"]["decision"],
        "deterministic_input_sha256": sha256_bytes(first["input"]),
        "conversion_script_sha256": sha256_bytes(script_path.read_bytes()),
        "first_metadata_sha256": sha256_bytes(first["metadata"]),
        "second_metadata_sha256": sha256_bytes(second["metadata"]),
        "stderr_sha256": sha256_bytes(first["stderr"]),
        "validated_exit_codes": [0, 0],
        "volatile_wall_times_are_separate": True,
    }
    path = output_directory / f"{TRANSCRIPT_STEM}.determinism.json"
    atomic_write(path, pretty_json_bytes(record))
    print(
        "DETERMINISM_OK "
        f"runs={first_run},{second_run} sha256={record['sha256']}"
    )
    return 0


def self_test(repository):
    from sage.all import is_prime

    toolchain = authenticate_sage_toolchain(repository)
    estimator = authenticate_estimator(repository)
    manifest_path = (
        repository
        / "research"
        / "reproduction"
        / "security"
        / "parameters"
        / f"{TUPLE_ID}.json"
    )
    manifest_bytes = manifest_path.read_bytes()
    verified = verify_manifest_bytes(manifest_bytes, is_prime)
    negative_manifest_path = (
        repository
        / "research"
        / "reproduction"
        / "security"
        / "parameters"
        / f"{NEGATIVE_TUPLE_ID}.json"
    )
    negative_bytes = negative_manifest_path.read_bytes()
    negative_verified = verify_negative_manifest_bytes(negative_bytes, is_prime)

    tampered = bytearray(manifest_bytes)
    needle = b'"weight": 192'
    replacement = b'"weight": 191'
    position = tampered.find(needle)
    if position < 0:
        raise RuntimeError("self-test could not locate manifest tamper target")
    tampered[position : position + len(needle)] = replacement
    try:
        verify_manifest_bytes(bytes(tampered), is_prime)
    except AuthenticationError:
        pass
    else:
        raise RuntimeError("tampered manifest was accepted")

    negative_tampered = bytearray(negative_bytes)
    negative_needle = b'"log_n": 5'
    negative_replacement = b'"log_n": 6'
    negative_position = negative_tampered.find(negative_needle)
    if negative_position < 0:
        raise RuntimeError("self-test could not locate negative manifest tamper target")
    negative_tampered[
        negative_position : negative_position + len(negative_needle)
    ] = negative_replacement
    try:
        verify_negative_manifest_bytes(bytes(negative_tampered), is_prime)
    except AuthenticationError:
        pass
    else:
        raise RuntimeError("tampered negative-control manifest was accepted")

    try:
        decode_json_strict(b'{"a":1,"a":2}')
    except AuthenticationError:
        pass
    else:
        raise RuntimeError("duplicate JSON key was accepted")

    print(
        "SELF_TEST_OK "
        f"manifest={verified['canonical_sha256']} "
        f"negative={negative_verified['canonical_sha256']} "
        f"estimator_tree={estimator['tree']} sage={toolchain['sage_version']}"
    )
    return 0


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository")
    parser.add_argument("--output-directory")
    parser.add_argument("--run-id", default="run")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--verify-repeat", action="store_true")
    parser.add_argument("--first-run", default="run-1")
    parser.add_argument("--second-run", default="run-2")
    return parser.parse_args()


def main():
    arguments = parse_arguments()
    repository = repository_from_argument(arguments.repository)
    output_directory = Path(
        arguments.output_directory
        or repository / "research" / "reproduction" / "security" / "estimates"
    ).resolve()
    modes = sum((arguments.worker, arguments.self_test, arguments.verify_repeat))
    if modes > 1:
        raise AuthenticationError("worker, self-test and verify-repeat modes are exclusive")
    if arguments.worker:
        return worker_main(repository)
    if arguments.self_test:
        return self_test(repository)
    if arguments.verify_repeat:
        return verify_repeat(
            repository,
            output_directory,
            arguments.first_run,
            arguments.second_run,
        )
    return parent_main(repository, output_directory, arguments.run_id)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthenticationError, RuntimeError, OSError, ValueError) as error:
        sys.stderr.write(f"FAIL_CLOSED: {error}\n")
        raise SystemExit(1)
