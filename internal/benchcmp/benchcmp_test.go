package benchcmp_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/internal/benchcmp"
)

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
	input, err := os.Open("testdata/lattigo_route_b.json")
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

func TestParseLattigoRouteBRejectsMismatch(t *testing.T) {
	result := `{
  "schema": "lcpdte-route-b-l11-a2b-full-result-v1",
  "result": {
    "first_operation": {"LogN": 16, "PackingSlots": 2048, "WordBits": 8, "WordCapacity": 512},
    "full_a2b": {"wall_nanoseconds": 25830240800},
    "input_words": 512,
    "mismatch_count": 1
  }
}`

	_, err := benchcmp.ParseLattigoRouteB(strings.NewReader(result), "failed.json")
	if err == nil || !strings.Contains(err.Error(), "mismatch_count=1") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseLattigoRouteBRejectsNonCanonicalShape(t *testing.T) {
	tests := []struct {
		name          string
		logN          uint32
		packingSlots  uint32
		wordBits      uint32
		wordCapacity  uint32
		inputWords    uint32
		wantErrorPart string
	}{
		{name: "log N", logN: 15, packingSlots: 2048, wordBits: 8, wordCapacity: 512, inputWords: 512, wantErrorPart: "LogN=15, want 16"},
		{name: "packing slots", logN: 16, packingSlots: 1024, wordBits: 8, wordCapacity: 512, inputWords: 512, wantErrorPart: "PackingSlots=1024, want 2048"},
		{name: "word bits", logN: 16, packingSlots: 2048, wordBits: 16, wordCapacity: 512, inputWords: 512, wantErrorPart: "WordBits=16, want 8"},
		{name: "word capacity", logN: 16, packingSlots: 2048, wordBits: 8, wordCapacity: 256, inputWords: 256, wantErrorPart: "WordCapacity=256, want 512"},
		{name: "partial workload", logN: 16, packingSlots: 2048, wordBits: 8, wordCapacity: 512, inputWords: 256, wantErrorPart: "input_words=256, want WordCapacity=512"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := fmt.Sprintf(`{
  "schema": "lcpdte-route-b-l11-a2b-full-result-v1",
  "result": {
    "first_operation": {
      "LogN": %d,
      "PackingSlots": %d,
      "WordBits": %d,
      "WordCapacity": %d
    },
    "full_a2b": {"wall_nanoseconds": 25830240800},
    "input_words": %d,
    "mismatch_count": 0
  }
}`, test.logN, test.packingSlots, test.wordBits, test.wordCapacity, test.inputWords)

			_, err := benchcmp.ParseLattigoRouteB(strings.NewReader(result), "forged.json")
			if err == nil || !strings.Contains(err.Error(), test.wantErrorPart) {
				t.Fatalf("error=%v, want substring %q", err, test.wantErrorPart)
			}
		})
	}
}

func TestComparisonMakesLaneMismatchExplicit(t *testing.T) {
	openfhe := mustParseOpenFHE(t)
	lattigo := mustParseLattigo(t)

	got, err := benchcmp.Compare(openfhe, lattigo)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != "lcpdte-ckksint-a2b-comparison-v1" {
		t.Fatalf("schema=%q", got.Schema)
	}
	if !got.Comparison.LaneMismatch || got.Comparison.OpenFHELanesPerLattigoLane != 16 {
		t.Fatalf("lane comparison=%+v", got.Comparison)
	}
	if !got.Comparison.SameWordBits || !got.Comparison.SameRingDimension {
		t.Fatalf("shape comparison=%+v", got.Comparison)
	}
	if math.Abs(got.Comparison.WholeCallLatencyRatioLattigoOverOpenFHE-2.548165) > 1e-6 {
		t.Fatalf("latency ratio=%f", got.Comparison.WholeCallLatencyRatioLattigoOverOpenFHE)
	}
	if math.Abs(got.Comparison.EffectiveThroughputRatioLattigoOverOpenFHE-0.024527) > 1e-6 {
		t.Fatalf("throughput ratio=%f", got.Comparison.EffectiveThroughputRatioLattigoOverOpenFHE)
	}

	wantText := "schema=lcpdte-ckksint-a2b-comparison-v1\n" +
		"openfhe source=gao-openfhe-benchmark-full provenance=\"testdata/openfhe_bench8.log\" a2b_latency_ns=10136800000 a2b_latency_seconds=10.136800 effective_words_per_second=808.144582 word_bits=8 ring_dimension=65536 lanes=8192 warmup=1 repeats=5 mismatch_count=0\n" +
		"lattigo source=lattigo-route-b-l11-a2b-full provenance=\"testdata/lattigo_route_b.json\" a2b_latency_ns=25830240800 a2b_latency_seconds=25.830241 effective_words_per_second=19.821728 word_bits=8 ring_dimension=65536 lanes=512 warmup=0 repeats=1 mismatch_count=0\n" +
		"comparison lane_mismatch=true openfhe_lanes_per_lattigo_lane=16.000000 same_word_bits=true same_ring_dimension=true whole_call_latency_ratio_lattigo_over_openfhe=2.548165 effective_throughput_ratio_lattigo_over_openfhe=0.024527\n"
	if text := benchcmp.FormatText(got); text != wantText {
		t.Fatalf("text summary:\n%s\nwant:\n%s", text, wantText)
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
	if !bytes.Contains(first, []byte(`"provenance": "testdata/openfhe_bench8.log"`)) ||
		!bytes.Contains(first, []byte(`"provenance": "testdata/lattigo_route_b.json"`)) {
		t.Fatalf("JSON summary lacks input provenance:\n%s", first)
	}
}

func TestComparisonRejectsDifferentWordBits(t *testing.T) {
	openfhe := mustParseOpenFHE(t)
	lattigo := mustParseLattigo(t)
	lattigo.WordBits = 16

	_, err := benchcmp.Compare(openfhe, lattigo)
	if err == nil || !strings.Contains(err.Error(), "word_bits mismatch") {
		t.Fatalf("error=%v", err)
	}
}

func TestComparisonRejectsDifferentRingDimensions(t *testing.T) {
	openfhe := mustParseOpenFHE(t)
	lattigo := mustParseLattigo(t)
	lattigo.RingDimension = 32_768

	_, err := benchcmp.Compare(openfhe, lattigo)
	if err == nil || !strings.Contains(err.Error(), "ring_dimension mismatch") {
		t.Fatalf("error=%v", err)
	}
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
	input, err := os.Open("testdata/lattigo_route_b.json")
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
