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
        "implementation": "gao-openfhe-a2b-sparse",
        "host_id": "test-host",
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
        "setup_nanoseconds": 123,
        "warmup_count": 1,
        "repeat_count": 5,
        "timed_samples_nanoseconds": [11, 12, 13, 14, 15],
        "warmup_verified": True,
        "verified_evaluations": 5,
        "mismatch_count": 0,
    }


class ValidateOutputTest(unittest.TestCase):
    def test_accepts_the_matched_prepared_online_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "result.json"
            artifact.write_text(json.dumps(canonical_artifact()), encoding="utf-8")

            completed = subprocess.run(
                [sys.executable, str(VALIDATOR), str(artifact)],
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("validated 512 words, 4096 bits, 1 warmup + 5 timed evaluations", completed.stdout)


if __name__ == "__main__":
    unittest.main()
