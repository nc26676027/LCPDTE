package benchcmp_test

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/internal/benchcmp"
)

const lattigoFullArtifact = "../../research/reproduction/route_b/route_b_l11_a2b_full_2026-09-01.json"

func TestParseGaoOpenFHEBenchmarkFullA2B(t *testing.T) {
	input, err := os.Open("testdata/openfhe_bench8.log")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	got, err := benchcmp.ParseGaoOpenFHE(input, "openfhe_bench8.log")
	if err != nil {
		t.Fatal(err)
	}

	if got.Source != "gao-openfhe-benchmark-full" {
		t.Fatalf("source=%q", got.Source)
	}
	if got.Provenance != "openfhe_bench8.log" {
		t.Fatalf("provenance=%q", got.Provenance)
	}
	if got.A2BLatencyNanoseconds != 10_136_800_000 {
		t.Fatalf("latency=%d ns", got.A2BLatencyNanoseconds)
	}
	if got.WordBits != 8 || got.RingDimension != 65_536 || got.Lanes != 8_192 {
		t.Fatalf("shape=%+v", got)
	}
	if got.Warmup != 1 || got.Repeats != 5 {
		t.Fatalf("timing protocol=%+v", got)
	}
	wantThroughput := 8192.0 / 10.1368
	if math.Abs(got.EffectiveWordsPerSecond-wantThroughput) > 1e-9 {
		t.Fatalf("words/s=%.12f, want %.12f", got.EffectiveWordsPerSecond, wantThroughput)
	}
}

func TestParseGaoOpenFHERejectsCorrectnessError(t *testing.T) {
	log := `CKKS scheme ring dimension: 65536
Bootstrapping parameters: zN = 8, zSlots = 8192
Error in A2B!
Time for A2B : 10.1368 s`

	_, err := benchcmp.ParseGaoOpenFHE(strings.NewReader(log), "failed.log")
	if err == nil || !strings.Contains(err.Error(), "Error in A2B") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseGaoOpenFHERejectsTruncatedLogWithoutWarmupMarker(t *testing.T) {
	log := `CKKS scheme ring dimension: 65536
Bootstrapping parameters: zN = 8, zSlots = 8192
Time for A2B : 10.1368 s`

	_, err := benchcmp.ParseGaoOpenFHE(strings.NewReader(log), "truncated.log")
	if err == nil || !strings.Contains(err.Error(), "missing Finished Warmup for A2B") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseLattigoRouteBA2B(t *testing.T) {
	input, err := os.Open(lattigoFullArtifact)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	got, err := benchcmp.ParseLattigoRouteB(input, "lattigo_route_b.json")
	if err != nil {
		t.Fatal(err)
	}

	if got.Source != "lattigo-route-b-l11-a2b-full" {
		t.Fatalf("source=%q", got.Source)
	}
	if got.Provenance != "lattigo_route_b.json" {
		t.Fatalf("provenance=%q", got.Provenance)
	}
	if got.A2BLatencyNanoseconds != 25_830_240_800 {
		t.Fatalf("latency=%d ns", got.A2BLatencyNanoseconds)
	}
	if got.WordBits != 8 || got.RingDimension != 65_536 || got.Lanes != 512 {
		t.Fatalf("shape=%+v", got)
	}
	if got.Warmup != 0 || got.Repeats != 1 {
		t.Fatalf("timing protocol=%+v", got)
	}
	wantThroughput := 512.0 / 25.8302408
	if math.Abs(got.EffectiveWordsPerSecond-wantThroughput) > 1e-9 {
		t.Fatalf("words/s=%.12f, want %.12f", got.EffectiveWordsPerSecond, wantThroughput)
	}
}

func TestParseLattigoRouteBRejectsTruncatedSummary(t *testing.T) {
	input, err := os.Open("testdata/lattigo_route_b_truncated.json")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	_, err = benchcmp.ParseLattigoRouteB(input, "truncated.json")
	if err == nil {
		t.Fatal("accepted a field-only summary without the full correctness envelope")
	}
}

func TestParseLattigoRouteBRejectsMissingMismatchCount(t *testing.T) {
	payload := mustReadLattigoArtifact(t)
	needle := []byte(",\n    \"mismatch_count\": 0")
	withoutField := bytes.Replace(payload, needle, nil, 1)
	if bytes.Equal(withoutField, payload) {
		t.Fatal("mismatch_count fixture field not found")
	}

	_, err := benchcmp.ParseLattigoRouteB(bytes.NewReader(withoutField), "missing-mismatch.json")
	if err == nil || !strings.Contains(err.Error(), "missing mismatch_count") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseLattigoRouteBRejectsZeroCompletedAt(t *testing.T) {
	payload := mustReadLattigoArtifact(t)
	completedAt := []byte("2026-09-01T03:43:23.4393245Z")
	zero := bytes.Replace(payload, completedAt, []byte("0001-01-01T00:00:00Z"), 1)
	if bytes.Equal(zero, payload) {
		t.Fatal("completed_at fixture field not found")
	}

	_, err := benchcmp.ParseLattigoRouteB(bytes.NewReader(zero), "zero-completed-at.json")
	if err == nil || !strings.Contains(err.Error(), "completed_at") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseLattigoRouteBRejectsTrailingJSON(t *testing.T) {
	payload := append(mustReadLattigoArtifact(t), []byte("{}\n")...)

	_, err := benchcmp.ParseLattigoRouteB(bytes.NewReader(payload), "trailing.json")
	if err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseLattigoRouteBRejectsMismatch(t *testing.T) {
	payload := mustReadLattigoArtifact(t)
	result := bytes.Replace(payload, []byte(`"mismatch_count": 0`), []byte(`"mismatch_count": 1`), 1)
	if bytes.Equal(result, payload) {
		t.Fatal("mismatch_count fixture field not found")
	}

	_, err := benchcmp.ParseLattigoRouteB(bytes.NewReader(result), "failed.json")
	if err == nil || !strings.Contains(err.Error(), "mismatch_count=1") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseLattigoRouteBRejectsNonCanonicalShape(t *testing.T) {
	tests := []struct {
		name          string
		replacements  [][2]string
		wantErrorPart string
	}{
		{name: "log N", replacements: [][2]string{{`"LogN": 16`, `"LogN": 15`}}, wantErrorPart: "LogN=15, want 16"},
		{name: "packing slots", replacements: [][2]string{{`"PackingSlots": 2048`, `"PackingSlots": 1024`}}, wantErrorPart: "PackingSlots=1024, want 2048"},
		{name: "word bits", replacements: [][2]string{{`"WordBits": 8`, `"WordBits": 16`}}, wantErrorPart: "WordBits=16, want 8"},
		{name: "word capacity", replacements: [][2]string{{`"WordCapacity": 512`, `"WordCapacity": 256`}, {`"input_words": 512`, `"input_words": 256`}}, wantErrorPart: "WordCapacity=256, want 512"},
		{name: "partial workload", replacements: [][2]string{{`"input_words": 512`, `"input_words": 256`}}, wantErrorPart: "input_words=256, want WordCapacity=512"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := mustReadLattigoArtifact(t)
			for _, replacement := range test.replacements {
				updated := bytes.Replace(result, []byte(replacement[0]), []byte(replacement[1]), 1)
				if bytes.Equal(updated, result) {
					t.Fatalf("fixture field %q not found", replacement[0])
				}
				result = updated
			}

			_, err := benchcmp.ParseLattigoRouteB(bytes.NewReader(result), "forged.json")
			if err == nil || !strings.Contains(err.Error(), test.wantErrorPart) {
				t.Fatalf("error=%v, want substring %q", err, test.wantErrorPart)
			}
		})
	}
}

func TestParseCanonicalDerivesStatisticsFromVerifiedSamples(t *testing.T) {
	got, err := benchcmp.ParseCanonical(strings.NewReader(canonicalArtifactJSON("openfhe", []uint64{
		9_000_000_000, 11_000_000_000, 10_000_000_000, 12_000_000_000, 8_000_000_000,
	})), "openfhe.json")
	if err != nil {
		t.Fatal(err)
	}

	if got.Source != "openfhe" || got.Provenance != "openfhe.json" {
		t.Fatalf("identity=%+v", got)
	}
	if got.A2BMeanNanoseconds != 10_000_000_000 || got.A2BMedianNanoseconds != 10_000_000_000 {
		t.Fatalf("aggregates=%+v", got)
	}
	if math.Abs(got.EffectiveWordsPerSecond-51.2) > 1e-12 {
		t.Fatalf("words/s=%.12f", got.EffectiveWordsPerSecond)
	}
	if got.Repeats != 5 || got.VerifiedEvaluations != 5 || len(got.TimedSamplesNanoseconds) != 5 {
		t.Fatalf("sample protocol=%+v", got)
	}
}

func TestParseCanonicalDerivesEvenSampleMedian(t *testing.T) {
	got, err := benchcmp.ParseCanonical(
		strings.NewReader(canonicalArtifactJSON("openfhe", []uint64{1, 2, 3, 100})),
		"openfhe.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.A2BMeanNanoseconds != 26.5 || got.A2BMedianNanoseconds != 2.5 {
		t.Fatalf("mean=%f median=%f", got.A2BMeanNanoseconds, got.A2BMedianNanoseconds)
	}
}

func TestParseCanonicalRejectsUnverifiedOrZeroTimedSamples(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		wantMessage string
	}{
		{
			name:        "zero sample",
			payload:     canonicalArtifactJSON("openfhe", []uint64{9_000_000_000, 0, 10_000_000_000, 12_000_000_000, 8_000_000_000}),
			wantMessage: "timed_samples_nanoseconds[1] must be nonzero",
		},
		{
			name:        "verification count",
			payload:     strings.Replace(canonicalArtifactJSON("openfhe", canonicalSamples()), `"verified_evaluations":5`, `"verified_evaluations":4`, 1),
			wantMessage: "verified_evaluations=4, want repeat_count=5",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := benchcmp.ParseCanonical(strings.NewReader(test.payload), "invalid.json")
			if err == nil || !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("error=%v, want substring %q", err, test.wantMessage)
			}
		})
	}
}

func TestComparisonUsesOnlyMatchedCanonicalMeasurements(t *testing.T) {
	openfhe := mustParseCanonical(t, "gao-openfhe-a2b-sparse", []uint64{
		9_000_000_000, 11_000_000_000, 10_000_000_000, 12_000_000_000, 8_000_000_000,
	})
	lattigo := mustParseCanonical(t, "lattigo-route-b", []uint64{
		7_000_000_000, 9_000_000_000, 8_000_000_000, 10_000_000_000, 6_000_000_000,
	})
	lattigo.OutputContainer = "two-serial-ciphertexts"

	got, err := benchcmp.Compare(openfhe, lattigo)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != "lcpdte-ckksint-a2b-comparison-v2" {
		t.Fatalf("schema=%q", got.Schema)
	}
	if math.Abs(got.Comparison.MeanLatencyRatioLattigoOverOpenFHE-0.8) > 1e-12 ||
		math.Abs(got.Comparison.MedianLatencyRatioLattigoOverOpenFHE-0.8) > 1e-12 ||
		math.Abs(got.Comparison.EffectiveThroughputRatioLattigoOverOpenFHE-1.25) > 1e-12 {
		t.Fatalf("comparison=%+v", got.Comparison)
	}
	if !strings.Contains(benchcmp.FormatText(got), "mean_latency_ratio_lattigo_over_openfhe=0.800000") {
		t.Fatalf("text summary:\n%s", benchcmp.FormatText(got))
	}

	first, err := benchcmp.MarshalJSON(got)
	if err != nil {
		t.Fatal(err)
	}
	second, err := benchcmp.MarshalJSON(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || !json.Valid(first) || first[len(first)-1] != '\n' {
		t.Fatalf("unstable JSON summary:\n%s", first)
	}
	if bytes.Contains(first, []byte(`"a2b_latency_nanoseconds"`)) || bytes.Contains(first, []byte(`"lanes"`)) {
		t.Fatalf("v2 summary leaked legacy aggregate fields:\n%s", first)
	}
}

func TestComparisonRejectsSwappedOrDuplicatedImplementationRoles(t *testing.T) {
	openfhe := mustParseCanonical(t, "gao-openfhe-a2b-sparse", canonicalSamples())
	lattigo := mustParseCanonical(t, "lattigo-route-b", canonicalSamples())

	if _, err := benchcmp.Compare(lattigo, openfhe); err == nil || !strings.Contains(err.Error(), "OpenFHE implementation") {
		t.Fatalf("swapped roles error=%v", err)
	}
	if _, err := benchcmp.Compare(lattigo, lattigo); err == nil || !strings.Contains(err.Error(), "OpenFHE implementation") {
		t.Fatalf("duplicated Lattigo role error=%v", err)
	}
	if _, err := benchcmp.Compare(openfhe, openfhe); err == nil || !strings.Contains(err.Error(), "Lattigo implementation") {
		t.Fatalf("duplicated OpenFHE role error=%v", err)
	}
}

func TestComparisonRejectsAnyUnmatchedOrNonCanonicalProtocolDimension(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(openfhe, lattigo *benchcmp.Measurement)
		wantMessage string
	}{
		{name: "eight bit only", mutate: func(a, b *benchcmp.Measurement) { a.WordBits, b.WordBits = 16, 16 }, wantMessage: "word_bits must be 8"},
		{name: "word bits", mutate: func(a, b *benchcmp.Measurement) { b.WordBits = 16 }, wantMessage: "word_bits mismatch"},
		{name: "ring", mutate: func(a, b *benchcmp.Measurement) { b.RingDimension /= 2 }, wantMessage: "ring_dimension mismatch"},
		{name: "packing slots", mutate: func(a, b *benchcmp.Measurement) { b.PackingSlots /= 2 }, wantMessage: "packing_slots mismatch"},
		{name: "useful words", mutate: func(a, b *benchcmp.Measurement) { b.UsefulWords /= 2 }, wantMessage: "useful_words mismatch"},
		{name: "warmup", mutate: func(a, b *benchcmp.Measurement) { b.Warmup++ }, wantMessage: "timing protocol mismatch"},
		{name: "repeats", mutate: func(a, b *benchcmp.Measurement) {
			b.Repeats = 4
			b.TimedSamplesNanoseconds = b.TimedSamplesNanoseconds[:4]
			b.VerifiedEvaluations = 4
		}, wantMessage: "timing protocol mismatch"},
		{name: "threads", mutate: func(a, b *benchcmp.Measurement) { b.Threads = 2 }, wantMessage: "threads must be 1"},
		{name: "host", mutate: func(a, b *benchcmp.Measurement) { b.HostID = "other-host" }, wantMessage: "host_id mismatch"},
		{name: "protocol", mutate: func(a, b *benchcmp.Measurement) { b.Protocol = "other-protocol" }, wantMessage: "protocol mismatch"},
		{name: "workload", mutate: func(a, b *benchcmp.Measurement) { b.WorkloadID = "other-workload" }, wantMessage: "workload_id mismatch"},
		{name: "packing id", mutate: func(a, b *benchcmp.Measurement) { b.PackingID = "other-packing" }, wantMessage: "packing_id mismatch"},
		{name: "scope", mutate: func(a, b *benchcmp.Measurement) { b.TimingScope = "setup-and-online" }, wantMessage: "timing scope"},
		{name: "warmup verification", mutate: func(a, b *benchcmp.Measurement) { b.WarmupVerified = false }, wantMessage: "warmup_verified"},
		{name: "verification", mutate: func(a, b *benchcmp.Measurement) { b.VerifiedEvaluations = 4 }, wantMessage: "verified_evaluations"},
		{name: "zero sample", mutate: func(a, b *benchcmp.Measurement) { b.TimedSamplesNanoseconds[2] = 0 }, wantMessage: "must be nonzero"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			openfhe := mustParseCanonical(t, "gao-openfhe-a2b-sparse", canonicalSamples())
			lattigo := mustParseCanonical(t, "lattigo-route-b", canonicalSamples())
			test.mutate(&openfhe, &lattigo)
			_, err := benchcmp.Compare(openfhe, lattigo)
			if err == nil || !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("error=%v, want substring %q", err, test.wantMessage)
			}
		})
	}
}

func mustParseCanonical(t *testing.T, implementation string, samples []uint64) benchcmp.Measurement {
	t.Helper()
	measurement, err := benchcmp.ParseCanonical(strings.NewReader(canonicalArtifactJSON(implementation, samples)), implementation+".json")
	if err != nil {
		t.Fatal(err)
	}
	return measurement
}

func canonicalSamples() []uint64 {
	return []uint64{9_000_000_000, 11_000_000_000, 10_000_000_000, 12_000_000_000, 8_000_000_000}
}

func canonicalArtifactJSON(implementation string, samples []uint64) string {
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
		PackingID: "complex-slots-2048-words-512-v1", OutputContainer: "one-ciphertext",
		WordBits: 8, RingDimension: 65_536, PackingSlots: 2_048, UsefulWords: 512, Threads: 1,
		TimingScope: "prepared-online", SetupNanoseconds: 2_000_000_000, WarmupCount: 1, WarmupVerified: true,
		RepeatCount: uint32(len(samples)), TimedSamplesNanoseconds: samples, VerifiedEvaluations: uint32(len(samples)),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func mustParseOpenFHE(t *testing.T) benchcmp.Measurement {
	t.Helper()
	input, err := os.Open("testdata/openfhe_bench8.log")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	measurement, err := benchcmp.ParseGaoOpenFHE(input, "testdata/openfhe_bench8.log")
	if err != nil {
		t.Fatal(err)
	}
	return measurement
}

func mustParseLattigo(t *testing.T) benchcmp.Measurement {
	t.Helper()
	input, err := os.Open(lattigoFullArtifact)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	measurement, err := benchcmp.ParseLattigoRouteB(input, "testdata/lattigo_route_b.json")
	if err != nil {
		t.Fatal(err)
	}
	return measurement
}

func mustReadLattigoArtifact(t *testing.T) []byte {
	t.Helper()
	payload, err := os.ReadFile(lattigoFullArtifact)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
