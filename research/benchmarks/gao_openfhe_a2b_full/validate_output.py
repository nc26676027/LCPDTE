#!/usr/bin/env python3
"""Validate one canonical Gao/OpenFHE full-A2B benchmark artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


EXPECTED = {
    "schema": "lcpdte-ckksint-a2b-benchmark-v3",
    "implementation": "gao-openfhe-a2b-full",
    "encryption_mode": "public-key",
    "factor_storage_mode": "resident-precomputed",
    "scale_schedule": "openfhe-flexiblemanual-native",
    "backend_bsgs_plan": "openfhe-auto-dim1-0",
    "source_revision": "08f1eb87434e7be072cba889270a8400bbffc08e",
    "source_modified": False,
    "runtime": "OpenFHE-1.4.0;HEXL-1.2.6",
    "build_profile": "CMAKE_BUILD_TYPE=Release;CXX_FLAGS=-march=native,-O3,-DNDEBUG,-fopenmp=libomp;MATHBACKEND=6;OPENFHE_VERSION=1.4.0;HEXL_VERSION=1.2.6;WITH_INTEL_HEXL=ON;WITH_NATIVEOPT=ON;WITH_NTL=ON;WITH_TCM=ON;WITH_OPENMP=ON;OMP_NUM_THREADS=1",
    "os": "linux",
    "arch": "amd64",
    "protocol": "gao-a2b-full-z8-w4-v1",
    "workload_id": "uint8-0to255-x32",
    "packing_id": "n65536-cslots32768-zslots8192-w4",
    "output_container": "two-ciphertexts-low4-high4",
    "word_bits": 8,
    "ring_dimension": 65536,
    "packing_slots": 32768,
    "useful_words": 8192,
    "threads": 1,
    "timing_scope": "prepared-online",
    "warmup_count": 1,
    "repeat_count": 5,
    "warmup_verified": True,
    "verified_evaluations": 5,
    "mismatch_count": 0,
}

EXPECTED_PARAMETERS = {
    "comparison_scope": "gao-algorithm-exact-q-p-and-numerical-parameters",
    "q_moduli_count": 21,
    "q_log2_aggregate": 904,
    "p_moduli_count": 7,
    "p_log2_aggregate": 350,
    "scaling_modulus_bits": 43,
    "first_modulus_bits": 43,
    "multiplicative_depth": 20,
    "large_digits": 3,
    "main_secret_hamming_weight": 192,
    "ephemeral_secret_hamming_weight": 32,
    "rns_decomposition_components": 3,
    "base_two_decomposition": 0,
    "level_budget": [3, 2],
    "openfhe_requested_bsgs_dimensions": [0, 0],
    "chunk_width": 4,
    "cutoff_bits": -24,
}

EXPECTED_NATIVE_PARAMETERS = {
    "actual_first_q_modulus_bits": 44,
    "main_secret_distribution": "balanced-sparse-ternary",
    "main_secret_hamming_weight": 192,
    "ephemeral_secret_distribution": "balanced-sparse-ternary",
    "ephemeral_secret_hamming_weight": 32,
    "error_sampler": "openfhe-dgg",
    "error_sigma": 3.19,
    "error_configured_bound": None,
    "error_effective_integer_bound": 39,
    "key_switch_technique": "openfhe-hybrid",
    "key_switch_rns_decomposition_components": 3,
    "key_switch_base_two_decomposition": 0,
    "security_selector": "HEStd_128_classic",
    "security_evidence": "openfhe-he-standard-ternary-table",
    "q_moduli": [
        "8796103114753",
        "8796120416257",
        "8796142305281",
        "8796131819521",
        "8796137586689",
        "8796135227393",
        "8796142043137",
        "8796136144897",
        "8796141649921",
        "8796137717761",
        "8796139159553",
        "8796122644481",
        "8796134178817",
        "8796123824129",
        "8796130508801",
        "8796087386113",
        "8796114124801",
        "8796110192641",
        "8796112814081",
        "8796090007553",
        "8796105342977",
    ],
    "q_moduli_bit_lengths": [
        44,
        44,
        44,
        44,
        44,
        44,
        44,
        44,
        44,
        44,
        44,
        44,
        44,
        44,
        44,
        43,
        44,
        44,
        44,
        43,
        44,
    ],
    "p_moduli": [
        "1125899903827969",
        "1125899902124033",
        "1125899887312897",
        "1125899886395393",
        "1125899885740033",
        "1125899884167169",
        "1125899884036097",
    ],
    "p_moduli_bit_lengths": [50, 50, 50, 50, 50, 50, 50],
}


def exactly_typed_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            exactly_typed_equal(actual_value, expected_value)
            for actual_value, expected_value in zip(actual, expected)
        )
    return actual == expected


def validate_exact_object(name: str, actual: Any, expected: dict[str, Any]) -> None:
    if not isinstance(actual, dict):
        raise ValueError(f"{name} must be a JSON object")
    actual_fields = set(actual)
    expected_fields = set(expected)
    missing = sorted(expected_fields - actual_fields)
    if missing:
        raise ValueError(f"{name} is missing fields: {missing!r}")
    unexpected = sorted(actual_fields - expected_fields)
    if unexpected:
        raise ValueError(f"{name} contains unexpected fields: {unexpected!r}")
    for field, expected_value in expected.items():
        actual_value = actual.get(field)
        if not exactly_typed_equal(actual_value, expected_value):
            raise ValueError(
                f"{name}.{field}={actual_value!r}, want {expected_value!r}"
            )


def validate(document: Any) -> None:
    if not isinstance(document, dict):
        raise ValueError("artifact must be a JSON object")
    expected_fields = set(EXPECTED) | {
        "host_id",
        "compiler",
        "parameters",
        "native_parameters",
        "setup_nanoseconds",
        "timed_samples_nanoseconds",
    }
    unexpected = sorted(set(document) - expected_fields)
    if unexpected:
        raise ValueError(f"artifact contains unexpected fields: {unexpected!r}")
    for field, expected in EXPECTED.items():
        actual = document.get(field)
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError(f"{field}={actual!r}, want {expected!r}")

    validate_exact_object("parameters", document.get("parameters"), EXPECTED_PARAMETERS)
    validate_exact_object(
        "native_parameters",
        document.get("native_parameters"),
        EXPECTED_NATIVE_PARAMETERS,
    )

    for field in ("host_id", "compiler"):
        value = document.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")
    compiler = document["compiler"]
    if not compiler.startswith("/usr/bin/clang++ :: ") or "clang version 14." not in compiler:
        raise ValueError(f"compiler={compiler!r}, want cached /usr/bin/clang++ Clang 14")

    setup_ns = document.get("setup_nanoseconds")
    if not isinstance(setup_ns, int) or isinstance(setup_ns, bool) or setup_ns <= 0:
        raise ValueError("setup_nanoseconds must be a positive integer")

    samples = document.get("timed_samples_nanoseconds")
    if not isinstance(samples, list) or len(samples) != EXPECTED["repeat_count"]:
        raise ValueError("timed_samples_nanoseconds must contain exactly 5 samples")
    if any(
        not isinstance(sample, int) or isinstance(sample, bool) or sample <= 0
        for sample in samples
    ):
        raise ValueError("every timed sample must be a positive integer")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.artifact.read_text(encoding="utf-8"))
        validate(document)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"invalid benchmark artifact: {error}", file=sys.stderr)
        return 1

    print("validated 8192 words, 65536 bits, 1 warmup + 5 timed evaluations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
