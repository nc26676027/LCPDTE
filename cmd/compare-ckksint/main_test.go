package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/internal/benchcmp"
)

func TestCLIComparesCanonicalArtifactsAndWritesJSON(t *testing.T) {
	openfhe := writeCanonicalArtifact(t, "gao-openfhe-a2b-full", "two-ciphertexts-low4-high4", canonicalSamples(10_000_000_000))
	lattigo := writeCanonicalArtifact(t, "lattigo-gao-a2b-full", "two-ciphertexts-low4-high4", canonicalSamples(8_000_000_000))
	output := filepath.Join(t.TempDir(), "comparison.json")

	command := exec.Command("go", "run", ".", "-openfhe-json", openfhe, "-lattigo-json", lattigo, "-out", output)
	stdout, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, stdout)
	}
	text := string(stdout)
	if !strings.Contains(text, "schema=lcpdte-ckksint-a2b-comparison-v3") ||
		!strings.Contains(text, "mean_latency_ratio_lattigo_over_openfhe=0.800000") {
		t.Fatalf("stdout:\n%s", text)
	}

	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Schema  string `json:"schema"`
		OpenFHE struct {
			Provenance string `json:"provenance"`
		} `json:"openfhe"`
		Lattigo struct {
			Provenance string `json:"provenance"`
		} `json:"lattigo"`
		Comparison struct {
			MeanRatio       float64 `json:"mean_latency_ratio_lattigo_over_openfhe"`
			ThroughputRatio float64 `json:"effective_throughput_ratio_lattigo_over_openfhe"`
			Pass            bool    `json:"pass"`
		} `json:"comparison"`
	}
	if err = json.Unmarshal(payload, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Schema != "lcpdte-ckksint-a2b-comparison-v3" ||
		summary.OpenFHE.Provenance != openfhe || summary.Lattigo.Provenance != lattigo ||
		summary.Comparison.MeanRatio != 0.8 || summary.Comparison.ThroughputRatio != 1.25 || !summary.Comparison.Pass {
		t.Fatalf("JSON summary=%+v", summary)
	}
}

func TestCLIExitsNonzeroForUnmatchedCanonicalArtifacts(t *testing.T) {
	openfhe := writeCanonicalArtifact(t, "gao-openfhe-a2b-full", "two-ciphertexts-low4-high4", canonicalSamples(10_000_000_000))
	lattigo := writeCanonicalArtifact(t, "lattigo-gao-a2b-full", "two-ciphertexts-low4-high4", canonicalSamples(8_000_000_000))
	payload, err := os.ReadFile(lattigo)
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), `"useful_words":8192`, `"useful_words":4096`, 1))
	if err = os.WriteFile(lattigo, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("go", "run", ".", "-openfhe-json", openfhe, "-lattigo-json", lattigo)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("command succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "useful_words=4096, want 8192") {
		t.Fatalf("output:\n%s", output)
	}
}

func TestCLIExitsNonzeroWhenLattigoFailsPerformanceParity(t *testing.T) {
	openfhe := writeCanonicalArtifact(t, "gao-openfhe-a2b-full", "two-ciphertexts-low4-high4", canonicalSamples(10_000_000_000))
	lattigo := writeCanonicalArtifact(t, "lattigo-gao-a2b-full", "two-ciphertexts-low4-high4", canonicalSamples(12_000_000_000))

	command := exec.Command("go", "run", ".", "-openfhe-json", openfhe, "-lattigo-json", lattigo)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("command succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "performance parity gate failed") ||
		!strings.Contains(string(output), "both must be <=1") {
		t.Fatalf("output:\n%s", output)
	}
}

func TestCLIRefusesLegacyArtifactsForV3Ratios(t *testing.T) {
	command := exec.Command("go", "run", ".", "-openfhe-log", "legacy.log", "-lattigo-json", "legacy.json")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("command succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "legacy artifacts are descriptive-only") {
		t.Fatalf("output:\n%s", output)
	}
}

func TestCLIExitsNonzeroForTruncatedCanonicalJSON(t *testing.T) {
	openfhe := filepath.Join(t.TempDir(), "truncated.json")
	if err := os.WriteFile(openfhe, []byte(`{"schema":"lcpdte-ckksint-a2b-benchmark-v3"`), 0o644); err != nil {
		t.Fatal(err)
	}
	lattigo := writeCanonicalArtifact(t, "lattigo-gao-a2b-full", "two-ciphertexts-low4-high4", canonicalSamples(8_000_000_000))

	command := exec.Command("go", "run", ".", "-openfhe-json", openfhe, "-lattigo-json", lattigo)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("command succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "parse canonical A2B benchmark JSON") {
		t.Fatalf("output:\n%s", output)
	}
}

func canonicalSamples(center uint64) []uint64 {
	return []uint64{center - 1_000_000_000, center + 1_000_000_000, center, center + 2_000_000_000, center - 2_000_000_000}
}

func TestCLIRejectsSerialOutputContainer(t *testing.T) {
	openfhe := writeCanonicalArtifact(t, "gao-openfhe-a2b-full", "two-ciphertexts-low4-high4", canonicalSamples(10_000_000_000))
	lattigo := writeCanonicalArtifact(t, "lattigo-gao-a2b-full", "two-serial-ciphertexts-low4-high4", canonicalSamples(8_000_000_000))

	command := exec.Command("go", "run", ".", "-openfhe-json", openfhe, "-lattigo-json", lattigo)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("command succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "two-ciphertexts-low4-high4") {
		t.Fatalf("output:\n%s", output)
	}
}

func writeCanonicalArtifact(t *testing.T, implementation, outputContainer string, samples []uint64) string {
	t.Helper()
	payload := struct {
		Schema                  string                          `json:"schema"`
		Implementation          string                          `json:"implementation"`
		HostID                  string                          `json:"host_id"`
		EncryptionMode          string                          `json:"encryption_mode"`
		FactorStorageMode       string                          `json:"factor_storage_mode"`
		ScaleSchedule           string                          `json:"scale_schedule"`
		BackendBSGSPlan         string                          `json:"backend_bsgs_plan"`
		SourceRevision          string                          `json:"source_revision"`
		SourceModified          bool                            `json:"source_modified"`
		Runtime                 string                          `json:"runtime"`
		Compiler                string                          `json:"compiler"`
		BuildProfile            string                          `json:"build_profile"`
		OS                      string                          `json:"os"`
		Arch                    string                          `json:"arch"`
		Protocol                string                          `json:"protocol"`
		WorkloadID              string                          `json:"workload_id"`
		PackingID               string                          `json:"packing_id"`
		OutputContainer         string                          `json:"output_container"`
		WordBits                uint32                          `json:"word_bits"`
		RingDimension           uint32                          `json:"ring_dimension"`
		PackingSlots            uint32                          `json:"packing_slots"`
		UsefulWords             uint32                          `json:"useful_words"`
		Parameters              *benchcmp.GaoParameterSemantics `json:"parameters"`
		NativeParameters        *benchcmp.NativeParameters      `json:"native_parameters"`
		Threads                 uint32                          `json:"threads"`
		TimingScope             string                          `json:"timing_scope"`
		SetupNanoseconds        uint64                          `json:"setup_nanoseconds"`
		WarmupCount             uint32                          `json:"warmup_count"`
		WarmupVerified          bool                            `json:"warmup_verified"`
		RepeatCount             uint32                          `json:"repeat_count"`
		TimedSamplesNanoseconds []uint64                        `json:"timed_samples_nanoseconds"`
		MismatchCount           uint64                          `json:"mismatch_count"`
		VerifiedEvaluations     uint32                          `json:"verified_evaluations"`
	}{
		Schema: benchcmp.CanonicalBenchmarkSchema, Implementation: implementation,
		HostID: "ryzen-7-h-255", EncryptionMode: "public-key",
		FactorStorageMode: "resident-precomputed", ScaleSchedule: "openfhe-flexiblemanual-native",
		BackendBSGSPlan: "openfhe-auto-dim1-0", SourceRevision: "08f1eb87434e7be072cba889270a8400bbffc08e",
		Runtime: benchcmp.OpenFHERuntime, Compiler: "/usr/bin/clang++ :: Ubuntu clang version 14.0.0-1ubuntu1.1",
		BuildProfile: benchcmp.OpenFHEBuildProfile,
		OS:           "linux", Arch: "amd64", Protocol: "gao-a2b-full-z8-w4-v1", WorkloadID: "uint8-0to255-x32",
		PackingID: "n65536-cslots32768-zslots8192-w4", OutputContainer: outputContainer,
		WordBits: 8, RingDimension: 65_536, PackingSlots: 32_768, UsefulWords: 8_192,
		Parameters: benchcmp.CanonicalGaoParameters(), NativeParameters: comparisonNativeParameters(implementation), Threads: 1,
		TimingScope: "prepared-online", SetupNanoseconds: 2_000_000_000, WarmupCount: 1, WarmupVerified: true,
		RepeatCount: uint32(len(samples)), TimedSamplesNanoseconds: samples, VerifiedEvaluations: uint32(len(samples)),
	}
	if implementation == "lattigo-gao-a2b-full" {
		payload.FactorStorageMode = "resident-prevalidated"
		payload.ScaleSchedule = "lattigo-explicit-level-scale-native"
		payload.BackendBSGSPlan = benchcmp.LattigoBackendBSGSPlan
		payload.SourceRevision = "lattigo-test-revision"
		payload.Runtime = "go1.25.0"
		payload.Compiler = "gc"
		payload.BuildProfile = benchcmp.LattigoAcceptanceBuildProfile
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), implementation+".json")
	if err = os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func comparisonNativeParameters(implementation string) *benchcmp.NativeParameters {
	openFHEQBits := []uint32{44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 43, 44, 44, 44, 43, 44}
	openFHEPBits := []uint32{50, 50, 50, 50, 50, 50, 50}
	native := &benchcmp.NativeParameters{
		MainSecretDistribution: "balanced-sparse-ternary", MainSecretHammingWeight: 192,
		EphemeralSecretDistribution: "balanced-sparse-ternary", EphemeralSecretHammingWeight: 32,
		KeySwitchRNSComponents: 3,
	}
	if implementation == benchcmp.FocusedLattigoSource {
		bound := 39.0
		native.MainSecretDistribution = "fixed-h-symmetric-sparse-ternary"
		native.EphemeralSecretDistribution = "fixed-h-symmetric-sparse-ternary"
		native.ActualFirstQModulusBits = 44
		native.ErrorSampler, native.ErrorSigma, native.ErrorConfiguredBound = "lattigo-bounded-discrete-gaussian", 3.19, &bound
		native.ErrorEffectiveIntegerBound = 39
		native.KeySwitchTechnique = "lattigo-rns-qp-gadget"
		native.SecuritySelector, native.SecurityEvidence = "external-estimator", "full-packed-profile-not-assessed"
		native.QModuliBitLengths, native.PModuliBitLengths = openFHEQBits, openFHEPBits
		native.QModuli = comparisonSyntheticModuli(openFHEQBits, 43, 1)
		native.PModuli = comparisonSyntheticModuli(openFHEPBits, 50, 1)
		return native
	}
	native.ActualFirstQModulusBits = 44
	native.ErrorSampler, native.ErrorSigma = "openfhe-dgg", 3.19
	native.ErrorEffectiveIntegerBound = 39
	native.KeySwitchTechnique = "openfhe-hybrid"
	native.SecuritySelector, native.SecurityEvidence = "HEStd_128_classic", "openfhe-he-standard-ternary-table"
	native.QModuliBitLengths, native.PModuliBitLengths = openFHEQBits, openFHEPBits
	native.QModuli = comparisonSyntheticModuli(openFHEQBits, 43, 1)
	native.PModuli = comparisonSyntheticModuli(openFHEPBits, 50, 1)
	return native
}

func comparisonSyntheticModuli(profile []uint32, target uint32, positiveDelta uint64) []string {
	result := make([]string, len(profile))
	pivot := uint64(1) << target
	for index, bitLength := range profile {
		value := pivot - 1
		if bitLength == target+1 {
			value = pivot + positiveDelta + uint64(index)
		} else if bitLength == target-1 {
			value = (pivot >> 1) - 1
		}
		result[index] = strconv.FormatUint(value, 10)
	}
	return result
}
