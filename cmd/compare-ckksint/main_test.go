package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIComparesArtifactsAndWritesJSON(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	openfhe, err := filepath.Abs(filepath.Join(workingDirectory, "..", "..", "internal", "benchcmp", "testdata", "openfhe_bench8.log"))
	if err != nil {
		t.Fatal(err)
	}
	lattigo, err := filepath.Abs(filepath.Join(workingDirectory, "..", "..", "internal", "benchcmp", "testdata", "lattigo_route_b.json"))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "comparison.json")

	command := exec.Command("go", "run", ".", "-openfhe-log", openfhe, "-lattigo-json", lattigo, "-out", output)
	stdout, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, stdout)
	}
	text := string(stdout)
	if !strings.Contains(text, "schema=lcpdte-ckksint-a2b-comparison-v1") ||
		!strings.Contains(text, "comparison lane_mismatch=true") ||
		!strings.Contains(text, "openfhe_lanes_per_lattigo_lane=16.000000") {
		t.Fatalf("stdout:\n%s", text)
	}

	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Schema  string `json:"schema"`
		OpenFHE struct {
			Provenance string  `json:"provenance"`
			Lanes      uint32  `json:"lanes"`
			Throughput float64 `json:"effective_words_per_second"`
		} `json:"openfhe"`
		Lattigo struct {
			Provenance string `json:"provenance"`
			Lanes      uint32 `json:"lanes"`
		} `json:"lattigo"`
		Comparison struct {
			LaneMismatch bool `json:"lane_mismatch"`
		} `json:"comparison"`
	}
	if err = json.Unmarshal(payload, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Schema != "lcpdte-ckksint-a2b-comparison-v1" ||
		summary.OpenFHE.Provenance != openfhe || summary.Lattigo.Provenance != lattigo ||
		summary.OpenFHE.Lanes != 8192 || summary.Lattigo.Lanes != 512 ||
		summary.OpenFHE.Throughput <= 0 || !summary.Comparison.LaneMismatch {
		t.Fatalf("JSON summary=%+v", summary)
	}
}

func TestCLIExitsNonzeroForNonCanonicalRouteBShape(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	openfhe := filepath.Join(workingDirectory, "..", "..", "internal", "benchcmp", "testdata", "openfhe_bench8.log")
	validLattigo := filepath.Join(workingDirectory, "..", "..", "internal", "benchcmp", "testdata", "lattigo_route_b.json")
	payload, err := os.ReadFile(validLattigo)
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), `"WordBits": 8`, `"WordBits": 16`, 1))
	mismatched := filepath.Join(t.TempDir(), "lattigo_wordbits16.json")
	if err = os.WriteFile(mismatched, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("go", "run", ".", "-openfhe-log", openfhe, "-lattigo-json", mismatched)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("command succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "WordBits=16, want 8") {
		t.Fatalf("output:\n%s", output)
	}
}

func TestCLIExitsNonzeroForTruncatedOpenFHELog(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	lattigo := filepath.Join(workingDirectory, "..", "..", "internal", "benchcmp", "testdata", "lattigo_route_b.json")
	truncated := filepath.Join(t.TempDir(), "truncated.log")
	log := "CKKS scheme ring dimension: 65536\n" +
		"Bootstrapping parameters: zN = 8, zSlots = 8192\n" +
		"Time for A2B : 10.1368 s\n"
	if err = os.WriteFile(truncated, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("go", "run", ".", "-openfhe-log", truncated, "-lattigo-json", lattigo)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("command succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "missing Finished Warmup for A2B") {
		t.Fatalf("output:\n%s", output)
	}
}
