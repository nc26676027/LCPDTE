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
        "encryption_mode": "public-key",
        "factor_storage_mode": "resident-precomputed",
        "scale_schedule": "openfhe-flexiblemanual-native",
        "backend_bsgs_plan": "openfhe-auto-dim1-0",
        "source_revision": "08f1eb87434e7be072cba889270a8400bbffc08e",
        "source_modified": False,
        "runtime": "openfhe-fhe-simd-alu",
        "compiler": "/usr/bin/clang++ :: Ubuntu clang version 14.0.0-1ubuntu1.1",
        "build_profile": "CMAKE_BUILD_TYPE=Release;WITH_INTEL_HEXL=ON;WITH_NATIVEOPT=ON;WITH_OPENMP=ON",
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
        "parameters": {
            "comparison_scope": "gao-algorithm-and-aggregate-modulus-bits",
            "q_moduli_count": 21,
            "q_log2_aggregate": 904,
            "p_moduli_count": 7,
            "p_log2_aggregate": 350,
            "scaling_modulus_bits": 43,
            "first_modulus_bits": 43,
            "multiplicative_depth": 20,
            "large_digits": 3,
            "ephemeral_secret_hamming_weight": 32,
            "level_budget": [3, 2],
            "openfhe_requested_bsgs_dimensions": [0, 0],
            "chunk_width": 4,
            "cutoff_bits": -24,
        },
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

    def run_validator(self, document: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "result.json"
            artifact.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(artifact)],
                capture_output=True,
                text=True,
            )

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
        completed = self.run_validator(document)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("mismatch_count", completed.stderr)

    def test_rejects_missing_execution_metadata(self) -> None:
        for field in (
            "encryption_mode",
            "factor_storage_mode",
            "scale_schedule",
            "backend_bsgs_plan",
            "source_revision",
            "source_modified",
            "runtime",
            "compiler",
            "build_profile",
            "os",
            "arch",
        ):
            with self.subTest(field=field):
                document = canonical_artifact()
                del document[field]

                completed = self.run_validator(document)

                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(field, completed.stderr)

    def test_rejects_unreproducible_execution_metadata(self) -> None:
        invalid_values = (
            ("encryption_mode", "secret-key"),
            ("factor_storage_mode", "streamed"),
            ("scale_schedule", "shared-synthetic"),
            ("backend_bsgs_plan", "openfhe-explicit-dim1-1"),
            ("source_revision", "not-the-pinned-revision"),
            ("source_modified", True),
            ("source_modified", 0),
            ("runtime", ""),
            ("compiler", ""),
            ("build_profile", "Release"),
            ("os", ""),
            ("arch", ""),
        )
        for field, invalid in invalid_values:
            with self.subTest(field=field, invalid=invalid):
                document = canonical_artifact()
                document[field] = invalid

                completed = self.run_validator(document)

                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(field, completed.stderr)

    def test_rejects_missing_parameter_contract(self) -> None:
        document = canonical_artifact()
        del document["parameters"]

        completed = self.run_validator(document)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("parameters", completed.stderr)

    def test_rejects_every_unmatched_gao_parameter(self) -> None:
        invalid_values = {
            "comparison_scope": "prime-identical",
            "q_moduli_count": 20,
            "q_log2_aggregate": 903,
            "p_moduli_count": 6,
            "p_log2_aggregate": 349,
            "scaling_modulus_bits": 42,
            "first_modulus_bits": 42,
            "multiplicative_depth": 19,
            "large_digits": 2,
            "ephemeral_secret_hamming_weight": 31,
            "level_budget": [2, 3],
            "openfhe_requested_bsgs_dimensions": [1, 0],
            "chunk_width": 3,
            "cutoff_bits": -23,
        }
        for field, invalid in invalid_values.items():
            with self.subTest(field=field):
                document = canonical_artifact()
                document["parameters"][field] = invalid

                completed = self.run_validator(document)

                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(field, completed.stderr)

    def test_rejects_legacy_bsgs_dimensions_name(self) -> None:
        document = canonical_artifact()
        requested = document["parameters"].pop("openfhe_requested_bsgs_dimensions")
        document["parameters"]["bsgs_dimensions"] = requested

        completed = self.run_validator(document)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("bsgs_dimensions", completed.stderr)


if __name__ == "__main__":
    unittest.main()
