// Package benchcmp parses and compares A2B benchmark artifacts.
package benchcmp

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
)

const (
	GaoOpenFHESource    = "gao-openfhe-benchmark-full"
	LattigoRouteBSource = "lattigo-route-b-l11-a2b-full"
	ComparisonSchema    = "lcpdte-ckksint-a2b-comparison-v1"
	lattigoRouteBSchema = "lcpdte-route-b-l11-a2b-full-result-v1"
	gaoWarmupCount      = 1
	gaoRepeatCount      = 5
	lattigoWarmupCount  = 0
	lattigoRepeatCount  = 1
)

var (
	openFHERingDimensionPattern = regexp.MustCompile(`CKKS scheme ring dimension:\s*(\d+)`)
	openFHEPackingPattern       = regexp.MustCompile(`Bootstrapping parameters:\s*zN\s*=\s*(\d+)\s*,\s*zSlots\s*=\s*(\d+)`)
	openFHEA2BWarmupPattern     = regexp.MustCompile(`Finished Warmup for A2B(?:\s+[0-9]+(?:\.[0-9]*)?(?:[eE][+-]?\d+)?\s*s)?`)
	openFHEA2BTimePattern       = regexp.MustCompile(`Time for A2B\s*:\s*([0-9]+(?:\.[0-9]*)?(?:[eE][+-]?\d+)?)\s*s`)
	openFHEErrorPattern         = regexp.MustCompile(`Error in[^\r\n]*`)
)

// Measurement is one whole-call A2B timing and its effective packed workload.
type Measurement struct {
	Source                  string  `json:"source"`
	Provenance              string  `json:"provenance"`
	A2BLatencyNanoseconds   uint64  `json:"a2b_latency_nanoseconds"`
	EffectiveWordsPerSecond float64 `json:"effective_words_per_second"`
	WordBits                uint32  `json:"word_bits"`
	RingDimension           uint32  `json:"ring_dimension"`
	Lanes                   uint32  `json:"lanes"`
	Warmup                  uint32  `json:"warmup"`
	Repeats                 uint32  `json:"repeats"`
	MismatchCount           uint64  `json:"mismatch_count"`
}

// Comparison records direct call latency alongside lane-normalized throughput.
type Comparison struct {
	LaneMismatch                               bool    `json:"lane_mismatch"`
	OpenFHELanesPerLattigoLane                 float64 `json:"openfhe_lanes_per_lattigo_lane"`
	SameWordBits                               bool    `json:"same_word_bits"`
	SameRingDimension                          bool    `json:"same_ring_dimension"`
	WholeCallLatencyRatioLattigoOverOpenFHE    float64 `json:"whole_call_latency_ratio_lattigo_over_openfhe"`
	EffectiveThroughputRatioLattigoOverOpenFHE float64 `json:"effective_throughput_ratio_lattigo_over_openfhe"`
}

// Summary is the stable comparison document emitted by compare-ckksint.
type Summary struct {
	Schema     string      `json:"schema"`
	OpenFHE    Measurement `json:"openfhe"`
	Lattigo    Measurement `json:"lattigo"`
	Comparison Comparison  `json:"comparison"`
}

// Compare builds call-level and lane-normalized comparisons for matched shapes.
func Compare(openfhe, lattigo Measurement) (Summary, error) {
	if openfhe.WordBits != lattigo.WordBits {
		return Summary{}, fmt.Errorf("compare A2B artifacts: word_bits mismatch: OpenFHE=%d Lattigo=%d", openfhe.WordBits, lattigo.WordBits)
	}
	if openfhe.RingDimension != lattigo.RingDimension {
		return Summary{}, fmt.Errorf("compare A2B artifacts: ring_dimension mismatch: OpenFHE=%d Lattigo=%d", openfhe.RingDimension, lattigo.RingDimension)
	}
	return Summary{
		Schema:  ComparisonSchema,
		OpenFHE: openfhe,
		Lattigo: lattigo,
		Comparison: Comparison{
			LaneMismatch:                               openfhe.Lanes != lattigo.Lanes,
			OpenFHELanesPerLattigoLane:                 float64(openfhe.Lanes) / float64(lattigo.Lanes),
			SameWordBits:                               openfhe.WordBits == lattigo.WordBits,
			SameRingDimension:                          openfhe.RingDimension == lattigo.RingDimension,
			WholeCallLatencyRatioLattigoOverOpenFHE:    float64(lattigo.A2BLatencyNanoseconds) / float64(openfhe.A2BLatencyNanoseconds),
			EffectiveThroughputRatioLattigoOverOpenFHE: lattigo.EffectiveWordsPerSecond / openfhe.EffectiveWordsPerSecond,
		},
	}, nil
}

// FormatText renders a deterministic, line-oriented human summary.
func FormatText(summary Summary) string {
	return fmt.Sprintf(
		"schema=%s\n%s\n%s\ncomparison lane_mismatch=%t openfhe_lanes_per_lattigo_lane=%.6f same_word_bits=%t same_ring_dimension=%t whole_call_latency_ratio_lattigo_over_openfhe=%.6f effective_throughput_ratio_lattigo_over_openfhe=%.6f\n",
		summary.Schema,
		formatMeasurement("openfhe", summary.OpenFHE),
		formatMeasurement("lattigo", summary.Lattigo),
		summary.Comparison.LaneMismatch,
		summary.Comparison.OpenFHELanesPerLattigoLane,
		summary.Comparison.SameWordBits,
		summary.Comparison.SameRingDimension,
		summary.Comparison.WholeCallLatencyRatioLattigoOverOpenFHE,
		summary.Comparison.EffectiveThroughputRatioLattigoOverOpenFHE,
	)
}

func formatMeasurement(label string, measurement Measurement) string {
	return fmt.Sprintf(
		"%s source=%s provenance=%q a2b_latency_ns=%d a2b_latency_seconds=%.6f effective_words_per_second=%.6f word_bits=%d ring_dimension=%d lanes=%d warmup=%d repeats=%d mismatch_count=%d",
		label, measurement.Source, measurement.Provenance, measurement.A2BLatencyNanoseconds,
		float64(measurement.A2BLatencyNanoseconds)/1e9, measurement.EffectiveWordsPerSecond,
		measurement.WordBits, measurement.RingDimension, measurement.Lanes,
		measurement.Warmup, measurement.Repeats, measurement.MismatchCount,
	)
}

// MarshalJSON renders a deterministic indented JSON document with a final newline.
func MarshalJSON(summary Summary) ([]byte, error) {
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal A2B comparison summary: %w", err)
	}
	return append(encoded, '\n'), nil
}

// ParseGaoOpenFHE parses the output of Gao et al.'s benchmark-full in bench mode.
func ParseGaoOpenFHE(input io.Reader, provenance string) (Measurement, error) {
	payload, err := io.ReadAll(input)
	if err != nil {
		return Measurement{}, fmt.Errorf("read Gao OpenFHE benchmark log: %w", err)
	}
	if failure := openFHEErrorPattern.Find(payload); failure != nil {
		return Measurement{}, fmt.Errorf("Gao OpenFHE benchmark correctness failure: %s", failure)
	}
	warmupMarker := openFHEA2BWarmupPattern.FindIndex(payload)
	if warmupMarker == nil {
		return Measurement{}, fmt.Errorf("parse Gao OpenFHE benchmark log: missing Finished Warmup for A2B")
	}

	ringDimension, err := parseUint32(openFHERingDimensionPattern, payload, "ring dimension")
	if err != nil {
		return Measurement{}, err
	}
	packing := openFHEPackingPattern.FindSubmatch(payload)
	if packing == nil {
		return Measurement{}, fmt.Errorf("parse Gao OpenFHE benchmark log: missing zN/zSlots")
	}
	wordBits, err := parseUint32Literal(packing[1], "zN")
	if err != nil {
		return Measurement{}, err
	}
	lanes, err := parseUint32Literal(packing[2], "zSlots")
	if err != nil {
		return Measurement{}, err
	}
	timing := openFHEA2BTimePattern.FindSubmatch(payload)
	if timing == nil {
		return Measurement{}, fmt.Errorf("parse Gao OpenFHE benchmark log: missing Time for A2B")
	}
	if timingMarker := openFHEA2BTimePattern.FindIndex(payload); timingMarker[0] < warmupMarker[1] {
		return Measurement{}, fmt.Errorf("parse Gao OpenFHE benchmark log: Time for A2B precedes Finished Warmup for A2B")
	}
	seconds, err := strconv.ParseFloat(string(timing[1]), 64)
	if err != nil || seconds <= 0 {
		return Measurement{}, fmt.Errorf("parse Gao OpenFHE benchmark log: invalid A2B time %q", timing[1])
	}
	latency := uint64(math.Round(seconds * 1e9))

	return Measurement{
		Source:                  GaoOpenFHESource,
		Provenance:              provenance,
		A2BLatencyNanoseconds:   latency,
		EffectiveWordsPerSecond: float64(lanes) / seconds,
		WordBits:                wordBits,
		RingDimension:           ringDimension,
		Lanes:                   lanes,
		Warmup:                  gaoWarmupCount,
		Repeats:                 gaoRepeatCount,
	}, nil
}

// ParseLattigoRouteB parses a route-b-l11-a2b-full JSON result envelope.
func ParseLattigoRouteB(input io.Reader, provenance string) (Measurement, error) {
	var envelope struct {
		Schema string `json:"schema"`
		Result struct {
			FirstOperation struct {
				LogN         uint32 `json:"LogN"`
				PackingSlots uint32 `json:"PackingSlots"`
				WordBits     uint32 `json:"WordBits"`
				WordCapacity uint32 `json:"WordCapacity"`
			} `json:"first_operation"`
			FullA2B struct {
				WallNanoseconds uint64 `json:"wall_nanoseconds"`
			} `json:"full_a2b"`
			InputWords    uint32 `json:"input_words"`
			MismatchCount uint64 `json:"mismatch_count"`
		} `json:"result"`
	}
	if err := json.NewDecoder(input).Decode(&envelope); err != nil {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: %w", err)
	}
	if envelope.Schema != lattigoRouteBSchema {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: schema=%q, want %q", envelope.Schema, lattigoRouteBSchema)
	}
	result := envelope.Result
	if result.FullA2B.WallNanoseconds == 0 || result.InputWords == 0 ||
		result.FirstOperation.LogN == 0 || result.FirstOperation.WordBits == 0 {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: incomplete A2B timing or workload")
	}
	if result.MismatchCount != 0 {
		return Measurement{}, fmt.Errorf("Lattigo Route-B correctness failure: mismatch_count=%d", result.MismatchCount)
	}
	seconds := float64(result.FullA2B.WallNanoseconds) / 1e9

	return Measurement{
		Source:                  LattigoRouteBSource,
		Provenance:              provenance,
		A2BLatencyNanoseconds:   result.FullA2B.WallNanoseconds,
		EffectiveWordsPerSecond: float64(result.InputWords) / seconds,
		WordBits:                result.FirstOperation.WordBits,
		RingDimension:           uint32(1) << result.FirstOperation.LogN,
		Lanes:                   result.InputWords,
		Warmup:                  lattigoWarmupCount,
		Repeats:                 lattigoRepeatCount,
		MismatchCount:           result.MismatchCount,
	}, nil
}

func parseUint32(pattern *regexp.Regexp, payload []byte, name string) (uint32, error) {
	match := pattern.FindSubmatch(payload)
	if match == nil {
		return 0, fmt.Errorf("parse Gao OpenFHE benchmark log: missing %s", name)
	}
	return parseUint32Literal(match[1], name)
}

func parseUint32Literal(value []byte, name string) (uint32, error) {
	parsed, err := strconv.ParseUint(string(value), 10, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("parse Gao OpenFHE benchmark log: invalid %s %q", name, value)
	}
	return uint32(parsed), nil
}
