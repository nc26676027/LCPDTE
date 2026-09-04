package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIComparesCanonicalArtifactsAndWritesJSON(t *testing.T) {
	openfhe := writeCanonicalArtifact(t, "gao-openfhe-a2b-sparse", "one-ciphertext", canonicalSamples(10_000_000_000))
	lattigo := writeCanonicalArtifact(t, "lattigo-route-b", "two-serial-ciphertexts", canonicalSamples(8_000_000_000))
	output := filepath.Join(t.TempDir(), "comparison.json")

	command := exec.Command("go", "run", ".", "-openfhe-json", openfhe, "-lattigo-json", lattigo, "-out", output)
	stdout, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, stdout)
	}
	text := string(stdout)
	if !strings.Contains(text, "schema=lcpdte-ckksint-a2b-comparison-v2") ||
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
		} `json:"comparison"`
	}
	if err = json.Unmarshal(payload, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Schema != "lcpdte-ckksint-a2b-comparison-v2" ||
		summary.OpenFHE.Provenance != openfhe || summary.Lattigo.Provenance != lattigo ||
		summary.Comparison.MeanRatio != 0.8 || summary.Comparison.ThroughputRatio != 1.25 {
		t.Fatalf("JSON summary=%+v", summary)
	}
}

func TestCLIExitsNonzeroForUnmatchedCanonicalArtifacts(t *testing.T) {
	openfhe := writeCanonicalArtifact(t, "gao-openfhe-a2b-sparse", "one-ciphertext", canonicalSamples(10_000_000_000))
	lattigo := writeCanonicalArtifact(t, "lattigo-route-b", "two-serial-ciphertexts", canonicalSamples(8_000_000_000))
	payload, err := os.ReadFile(lattigo)
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), `"useful_words":512`, `"useful_words":256`, 1))
	if err = os.WriteFile(lattigo, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("go", "run", ".", "-openfhe-json", openfhe, "-lattigo-json", lattigo)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("command succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "useful_words mismatch") {
		t.Fatalf("output:\n%s", output)
	}
}

func TestCLIRefusesLegacyArtifactsForV2Ratios(t *testing.T) {
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
	if err := os.WriteFile(openfhe, []byte(`{"schema":"lcpdte-ckksint-a2b-benchmark-v2"`), 0o644); err != nil {
		t.Fatal(err)
	}
	lattigo := writeCanonicalArtifact(t, "lattigo-route-b", "two-serial-ciphertexts", canonicalSamples(8_000_000_000))

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

func writeCanonicalArtifact(t *testing.T, implementation, outputContainer string, samples []uint64) string {
	t.Helper()
	payload := struct {
		Schema                  string   `json:"schema"`
		Implementation          string   `json:"implementation"`
		HostID                  string   `json:"host_id"`
		Protocol                string   `json:"protocol"`
		WorkloadID              string   `json:"workload_id"`
		PackingID               string   `json:"packing_id"`
		OutputContainer         string   `json:"output_container"`
		WordBits                uint32   `json:"word_bits"`
		RingDimension           uint32   `json:"ring_dimension"`
		PackingSlots            uint32   `json:"packing_slots"`
		UsefulWords             uint32   `json:"useful_words"`
		Threads                 uint32   `json:"threads"`
		TimingScope             string   `json:"timing_scope"`
		SetupNanoseconds        uint64   `json:"setup_nanoseconds"`
		WarmupCount             uint32   `json:"warmup_count"`
		WarmupVerified          bool     `json:"warmup_verified"`
		RepeatCount             uint32   `json:"repeat_count"`
		TimedSamplesNanoseconds []uint64 `json:"timed_samples_nanoseconds"`
		MismatchCount           uint64   `json:"mismatch_count"`
		VerifiedEvaluations     uint32   `json:"verified_evaluations"`
	}{
		Schema: "lcpdte-ckksint-a2b-benchmark-v2", Implementation: implementation,
		HostID: "ryzen-7-h-255", Protocol: "gao-zheng-int8-a2b-n8-w4", WorkloadID: "signed-int8-512-fixed-v1",
		PackingID: "complex-slots-2048-words-512-v1", OutputContainer: outputContainer,
		WordBits: 8, RingDimension: 65_536, PackingSlots: 2_048, UsefulWords: 512, Threads: 1,
		TimingScope: "prepared-online", SetupNanoseconds: 2_000_000_000, WarmupCount: 1, WarmupVerified: true,
		RepeatCount: uint32(len(samples)), TimedSamplesNanoseconds: samples, VerifiedEvaluations: uint32(len(samples)),
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
