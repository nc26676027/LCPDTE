import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "validate_output.py"

OPENFHE_Q_MODULI = [
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
]
OPENFHE_Q_MODULI_BIT_LENGTHS = [
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
]
OPENFHE_P_MODULI = [
    "1125899903827969",
    "1125899902124033",
    "1125899887312897",
    "1125899886395393",
    "1125899885740033",
    "1125899884167169",
    "1125899884036097",
]
OPENFHE_P_MODULI_BIT_LENGTHS = [50, 50, 50, 50, 50, 50, 50]


def canonical_artifact() -> dict:
    return {
        "schema": "lcpdte-ckksint-a2b-benchmark-v3",
        "implementation": "gao-openfhe-a2b-full",
        "host_id": "test-host",
        "encryption_mode": "public-key",
        "factor_storage_mode": "resident-precomputed",
        "scale_schedule": "openfhe-flexiblemanual-native",
        "backend_bsgs_plan": "openfhe-auto-dim1-0",
        "source_revision": "08f1eb87434e7be072cba889270a8400bbffc08e",
        "source_modified": False,
        "runtime": "OpenFHE-1.4.0;HEXL-1.2.6",
        "compiler": "/usr/bin/clang++ :: Ubuntu clang version 14.0.0-1ubuntu1.1",
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
        "parameters": {
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
        },
        "native_parameters": {
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
            "q_moduli": OPENFHE_Q_MODULI.copy(),
            "q_moduli_bit_lengths": OPENFHE_Q_MODULI_BIT_LENGTHS.copy(),
            "p_moduli": OPENFHE_P_MODULI.copy(),
            "p_moduli_bit_lengths": OPENFHE_P_MODULI_BIT_LENGTHS.copy(),
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

    def test_rejects_unexpected_top_level_field(self) -> None:
        document = canonical_artifact()
        document["unverified_claim"] = True

        completed = self.run_validator(document)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unexpected fields", completed.stderr)

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
            ("compiler", "/usr/bin/g++ :: g++ 11"),
            ("build_profile", "Release"),
            ("os", "windows"),
            ("arch", "arm64"),
        )
        for field, invalid in invalid_values:
            with self.subTest(field=field, invalid=invalid):
                document = canonical_artifact()
                document[field] = invalid

                completed = self.run_validator(document)

                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(field, completed.stderr)

    def test_scripts_driver_and_validator_share_complete_build_profile(self) -> None:
        profile = canonical_artifact()["build_profile"]
        for relative in (
            "build_wsl.sh",
            "run_wsl.sh",
            "gao-openfhe-a2b-full.cpp",
            "validate_output.py",
        ):
            with self.subTest(relative=relative):
                self.assertIn(profile, (ROOT / relative).read_text(encoding="utf-8"))

        build_script = (ROOT / "build_wsl.sh").read_text(encoding="utf-8")
        for required in (
            "CMAKE_CXX_FLAGS_RELEASE",
            "MATHBACKEND",
            "WITH_INTEL_HEXL",
            "WITH_NATIVEOPT",
            "WITH_NTL",
            "WITH_TCM",
            "WITH_OPENMP",
            "flags.make",
            "HEXLConfigVersion.cmake",
        ):
            with self.subTest(required=required):
                self.assertIn(required, build_script)

    def test_driver_emits_the_runtime_native_parameter_contract(self) -> None:
        source = (ROOT / "gao-openfhe-a2b-full.cpp").read_text(encoding="utf-8")
        for required in (
            "lcpdte-ckksint-a2b-benchmark-v3",
            "SetKeySwitchTechnique(HYBRID)",
            "GetDistributionParameter()",
            "GetKeySwitchTechnique()",
            "GetStdLevel()",
            "GetNumPartQ()",
            "GetDigitSize()",
            "native_parameters",
            "actual_first_q_modulus_bits",
            "main_secret_distribution",
            "main_secret_hamming_weight",
            "ephemeral_secret_distribution",
            "ephemeral_secret_hamming_weight",
            "error_sampler",
            "error_sigma",
            "error_configured_bound",
            "error_effective_integer_bound",
            "key_switch_technique",
            "key_switch_rns_decomposition_components",
            "key_switch_base_two_decomposition",
            "security_selector",
            "security_evidence",
            "q_moduli",
            "q_moduli_bit_lengths",
            "p_moduli",
            "p_moduli_bit_lengths",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)

    def test_scripts_support_sha_bound_prebuilt_execution(self) -> None:
        build_script = (ROOT / "build_wsl.sh").read_text(encoding="utf-8")
        run_script = (ROOT / "run_wsl.sh").read_text(encoding="utf-8")

        for required in (
            "driver_sha256_stamp",
            "driver_sha256_before",
            "driver_sha256_after",
            "binary_sha256",
            "status --porcelain=v1 --untracked-files=all",
            "sha256sum",
            "mv --",
        ):
            with self.subTest(script="build_wsl.sh", required=required):
                self.assertIn(required, build_script)

        for required in (
            "LCPDTE_GAO_SKIP_BUILD",
            "driver_sha256_stamp",
            "binary_sha256",
            "status --porcelain=v1 --untracked-files=all",
            "prebuilt driver SHA-256 stamp",
            "prebuilt binary SHA-256",
            "prebuilt focused-driver binary",
        ):
            with self.subTest(script="run_wsl.sh", required=required):
                self.assertIn(required, run_script)

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
            "main_secret_hamming_weight": 191,
            "ephemeral_secret_hamming_weight": 31,
            "rns_decomposition_components": 2,
            "base_two_decomposition": 1,
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

    def test_rejects_missing_native_parameter_contract(self) -> None:
        document = canonical_artifact()
        del document["native_parameters"]

        completed = self.run_validator(document)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("native_parameters", completed.stderr)

    def test_rejects_every_unmatched_openfhe_native_parameter(self) -> None:
        invalid_values = {
            "actual_first_q_modulus_bits": 43,
            "main_secret_distribution": "uniform-ternary",
            "main_secret_hamming_weight": 191,
            "ephemeral_secret_distribution": "uniform-ternary",
            "ephemeral_secret_hamming_weight": 31,
            "error_sampler": "rounded-normal",
            "error_sigma": 3.2,
            "error_configured_bound": 39,
            "error_effective_integer_bound": 38,
            "key_switch_technique": "bv",
            "key_switch_rns_decomposition_components": 2,
            "key_switch_base_two_decomposition": 1,
            "security_selector": "HEStd_NotSet",
            "security_evidence": "external-estimator",
            "q_moduli": list(reversed(OPENFHE_Q_MODULI)),
            "q_moduli_bit_lengths": [43] * 21,
            "p_moduli": list(reversed(OPENFHE_P_MODULI)),
            "p_moduli_bit_lengths": [49] * 7,
        }
        for field, invalid in invalid_values.items():
            with self.subTest(field=field):
                document = canonical_artifact()
                document["native_parameters"][field] = invalid

                completed = self.run_validator(document)

                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(field, completed.stderr)

    def test_rejects_every_missing_openfhe_native_parameter(self) -> None:
        for field in canonical_artifact()["native_parameters"]:
            with self.subTest(field=field):
                document = canonical_artifact()
                del document["native_parameters"][field]

                completed = self.run_validator(document)

                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(field, completed.stderr)

    def test_rejects_unexpected_openfhe_native_parameter(self) -> None:
        document = canonical_artifact()
        document["native_parameters"]["unverified_native_claim"] = True

        completed = self.run_validator(document)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unexpected fields", completed.stderr)

    def test_rejects_legacy_bsgs_dimensions_name(self) -> None:
        document = canonical_artifact()
        requested = document["parameters"].pop("openfhe_requested_bsgs_dimensions")
        document["parameters"]["bsgs_dimensions"] = requested

        completed = self.run_validator(document)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("bsgs_dimensions", completed.stderr)


if __name__ == "__main__":
    unittest.main()
