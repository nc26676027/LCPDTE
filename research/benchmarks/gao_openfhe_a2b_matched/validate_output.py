#!/usr/bin/env python3
"""Validate one matched Gao/OpenFHE A2B benchmark artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


EXPECTED = {
    "schema": "lcpdte-ckksint-a2b-benchmark-v2",
    "implementation": "gao-openfhe-a2b-sparse",
    "protocol": "gao-a2b-sparse-z8-w4-v1",
    "workload_id": "uint8-0to255-twice",
    "packing_id": "n65536-cslots2048-zslots512-w4",
    "output_container": "one-bmodesparse-ciphertext-4096-bits",
    "word_bits": 8,
    "ring_dimension": 65536,
    "packing_slots": 2048,
    "useful_words": 512,
    "threads": 1,
    "timing_scope": "prepared-online",
    "warmup_count": 1,
    "repeat_count": 5,
    "warmup_verified": True,
    "verified_evaluations": 5,
    "mismatch_count": 0,
}


def validate(document: Any) -> None:
    if not isinstance(document, dict):
        raise ValueError("artifact must be a JSON object")
    for field, expected in EXPECTED.items():
        actual = document.get(field)
        if actual != expected:
            raise ValueError(f"{field}={actual!r}, want {expected!r}")

    host_id = document.get("host_id")
    if not isinstance(host_id, str) or not host_id.strip():
        raise ValueError("host_id must be a non-empty string")

    setup_ns = document.get("setup_nanoseconds")
    if not isinstance(setup_ns, int) or isinstance(setup_ns, bool) or setup_ns <= 0:
        raise ValueError("setup_nanoseconds must be a positive integer")

    samples = document.get("timed_samples_nanoseconds")
    if not isinstance(samples, list) or len(samples) != EXPECTED["repeat_count"]:
        raise ValueError("timed_samples_nanoseconds must contain exactly 5 samples")
    if any(not isinstance(sample, int) or isinstance(sample, bool) or sample <= 0 for sample in samples):
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

    print("validated 512 words, 4096 bits, 1 warmup + 5 timed evaluations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
