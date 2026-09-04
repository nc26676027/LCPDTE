import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "validate_output.py"


def canonical_artifact() -> dict:
    return {
        "schema": "lcpdte-ckksint-a2b-benchmark-v2",
        "implementation": "gao-openfhe-a2b-full",
        "host_id": "test-host",
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
        "setup_nanoseconds": 123,
        "warmup_count": 1,
        "repeat_count": 5,
        "timed_samples_nanoseconds": [11, 12, 13, 14, 15],
        "warmup_verified": True,
        "verified_evaluations": 5,
        "mismatch_count": 0,
    }


class ValidateOutputTest(unittest.TestCase):
    def test_accepts_the_canonical_full_prepared_online_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "result.json"
            artifact.write_text(json.dumps(canonical_artifact()), encoding="utf-8")

            completed = subprocess.run(
                [sys.executable, str(VALIDATOR), str(artifact)],
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "validated 8192 words, 65536 bits, 1 warmup + 5 timed evaluations",
            completed.stdout,
        )

    def test_rejects_boolean_mismatch_count(self) -> None:
        document = canonical_artifact()
        document["mismatch_count"] = False
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "result.json"
            artifact.write_text(json.dumps(document), encoding="utf-8")

            completed = subprocess.run(
                [sys.executable, str(VALIDATOR), str(artifact)],
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("mismatch_count", completed.stderr)


if __name__ == "__main__":
    unittest.main()
