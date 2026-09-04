// Package benchcmp parses and compares A2B benchmark artifacts.
package benchcmp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureeval"
)

const (
	GaoOpenFHESource          = "gao-openfhe-benchmark-full"
	LattigoRouteBSource       = "lattigo-route-b-l11-a2b-full"
	CanonicalBenchmarkSchema  = "lcpdte-ckksint-a2b-benchmark-v2"
	ComparisonSchema          = "lcpdte-ckksint-a2b-comparison-v2"
	TimingScopePreparedOnline = "prepared-online"
	lattigoRouteBSchema       = "lcpdte-route-b-l11-a2b-full-result-v1"
	gaoWarmupCount            = 1
	gaoRepeatCount            = 5
	lattigoWarmupCount        = 0
	lattigoRepeatCount        = 1
	canonicalLogN             = 16
	canonicalWordBits         = 8
	canonicalSlots            = 2048
	canonicalWords            = 512
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
	Source                  string   `json:"source"`
	Provenance              string   `json:"provenance"`
	HostID                  string   `json:"host_id"`
	Protocol                string   `json:"protocol"`
	WorkloadID              string   `json:"workload_id"`
	PackingID               string   `json:"packing_id"`
	OutputContainer         string   `json:"output_container,omitempty"`
	WordBits                uint32   `json:"word_bits"`
	RingDimension           uint32   `json:"ring_dimension"`
	PackingSlots            uint32   `json:"packing_slots"`
	UsefulWords             uint32   `json:"useful_words"`
	Threads                 uint32   `json:"threads"`
	TimingScope             string   `json:"timing_scope"`
	SetupNanoseconds        uint64   `json:"setup_nanoseconds"`
	Warmup                  uint32   `json:"warmup_count"`
	WarmupVerified          bool     `json:"warmup_verified"`
	Repeats                 uint32   `json:"repeat_count"`
	TimedSamplesNanoseconds []uint64 `json:"timed_samples_nanoseconds"`
	VerifiedEvaluations     uint32   `json:"verified_evaluations"`
	MismatchCount           uint64   `json:"mismatch_count"`
	A2BMeanNanoseconds      float64  `json:"a2b_mean_nanoseconds"`
	A2BMedianNanoseconds    float64  `json:"a2b_median_nanoseconds"`
	EffectiveWordsPerSecond float64  `json:"effective_words_per_second"`
	A2BLatencyNanoseconds   uint64   `json:"a2b_latency_nanoseconds,omitempty"`
	Lanes                   uint32   `json:"lanes,omitempty"`
}

// Comparison records ratios derived from matched, verified online samples.
type Comparison struct {
	MeanLatencyRatioLattigoOverOpenFHE         float64 `json:"mean_latency_ratio_lattigo_over_openfhe"`
	MedianLatencyRatioLattigoOverOpenFHE       float64 `json:"median_latency_ratio_lattigo_over_openfhe"`
	EffectiveThroughputRatioLattigoOverOpenFHE float64 `json:"effective_throughput_ratio_lattigo_over_openfhe"`
}

// Summary is the stable comparison document emitted by compare-ckksint.
type Summary struct {
	Schema     string      `json:"schema"`
	OpenFHE    Measurement `json:"openfhe"`
	Lattigo    Measurement `json:"lattigo"`
	Comparison Comparison  `json:"comparison"`
}

// Compare admits only matched single-thread prepared-online measurements and
// derives every aggregate from their verified, nonzero timed samples.
func Compare(openfhe, lattigo Measurement) (Summary, error) {
	if !strings.HasPrefix(openfhe.Source, "gao-openfhe-a2b-") {
		return Summary{}, fmt.Errorf("compare A2B artifacts: OpenFHE implementation=%q, want gao-openfhe-a2b-*", openfhe.Source)
	}
	if lattigo.Source != "lattigo-route-b" {
		return Summary{}, fmt.Errorf("compare A2B artifacts: Lattigo implementation=%q, want lattigo-route-b", lattigo.Source)
	}
	if openfhe.WordBits != lattigo.WordBits {
		return Summary{}, fmt.Errorf("compare A2B artifacts: word_bits mismatch: OpenFHE=%d Lattigo=%d", openfhe.WordBits, lattigo.WordBits)
	}
	if openfhe.WordBits != canonicalWordBits {
		return Summary{}, fmt.Errorf("compare A2B artifacts: word_bits must be %d: OpenFHE=%d Lattigo=%d", canonicalWordBits, openfhe.WordBits, lattigo.WordBits)
	}
	if openfhe.RingDimension != lattigo.RingDimension {
		return Summary{}, fmt.Errorf("compare A2B artifacts: ring_dimension mismatch: OpenFHE=%d Lattigo=%d", openfhe.RingDimension, lattigo.RingDimension)
	}
	if openfhe.PackingSlots != lattigo.PackingSlots {
		return Summary{}, fmt.Errorf("compare A2B artifacts: packing_slots mismatch: OpenFHE=%d Lattigo=%d", openfhe.PackingSlots, lattigo.PackingSlots)
	}
	if openfhe.UsefulWords != lattigo.UsefulWords {
		return Summary{}, fmt.Errorf("compare A2B artifacts: useful_words mismatch: OpenFHE=%d Lattigo=%d", openfhe.UsefulWords, lattigo.UsefulWords)
	}
	if openfhe.Warmup != lattigo.Warmup || openfhe.Repeats != lattigo.Repeats {
		return Summary{}, fmt.Errorf(
			"compare A2B artifacts: timing protocol mismatch: OpenFHE=warmup%d/repeats%d Lattigo=warmup%d/repeats%d",
			openfhe.Warmup, openfhe.Repeats, lattigo.Warmup, lattigo.Repeats,
		)
	}
	if openfhe.Threads != 1 || lattigo.Threads != 1 {
		return Summary{}, fmt.Errorf("compare A2B artifacts: threads must be 1: OpenFHE=%d Lattigo=%d", openfhe.Threads, lattigo.Threads)
	}
	if openfhe.HostID != lattigo.HostID {
		return Summary{}, fmt.Errorf("compare A2B artifacts: host_id mismatch: OpenFHE=%q Lattigo=%q", openfhe.HostID, lattigo.HostID)
	}
	if openfhe.Protocol != lattigo.Protocol {
		return Summary{}, fmt.Errorf("compare A2B artifacts: protocol mismatch: OpenFHE=%q Lattigo=%q", openfhe.Protocol, lattigo.Protocol)
	}
	if openfhe.WorkloadID != lattigo.WorkloadID {
		return Summary{}, fmt.Errorf("compare A2B artifacts: workload_id mismatch: OpenFHE=%q Lattigo=%q", openfhe.WorkloadID, lattigo.WorkloadID)
	}
	if openfhe.PackingID != lattigo.PackingID {
		return Summary{}, fmt.Errorf("compare A2B artifacts: packing_id mismatch: OpenFHE=%q Lattigo=%q", openfhe.PackingID, lattigo.PackingID)
	}
	if openfhe.TimingScope != TimingScopePreparedOnline || lattigo.TimingScope != TimingScopePreparedOnline {
		return Summary{}, fmt.Errorf(
			"compare A2B artifacts: timing scope must be %q: OpenFHE=%q Lattigo=%q",
			TimingScopePreparedOnline, openfhe.TimingScope, lattigo.TimingScope,
		)
	}
	var err error
	if openfhe, err = normalizeMeasurement(openfhe); err != nil {
		return Summary{}, fmt.Errorf("compare A2B artifacts: OpenFHE: %w", err)
	}
	if lattigo, err = normalizeMeasurement(lattigo); err != nil {
		return Summary{}, fmt.Errorf("compare A2B artifacts: Lattigo: %w", err)
	}
	return Summary{
		Schema:  ComparisonSchema,
		OpenFHE: openfhe,
		Lattigo: lattigo,
		Comparison: Comparison{
			MeanLatencyRatioLattigoOverOpenFHE:         lattigo.A2BMeanNanoseconds / openfhe.A2BMeanNanoseconds,
			MedianLatencyRatioLattigoOverOpenFHE:       lattigo.A2BMedianNanoseconds / openfhe.A2BMedianNanoseconds,
			EffectiveThroughputRatioLattigoOverOpenFHE: lattigo.EffectiveWordsPerSecond / openfhe.EffectiveWordsPerSecond,
		},
	}, nil
}

// FormatText renders a deterministic, line-oriented human summary.
func FormatText(summary Summary) string {
	return fmt.Sprintf(
		"schema=%s\n%s\n%s\ncomparison mean_latency_ratio_lattigo_over_openfhe=%.6f median_latency_ratio_lattigo_over_openfhe=%.6f effective_throughput_ratio_lattigo_over_openfhe=%.6f\n",
		summary.Schema,
		formatMeasurement("openfhe", summary.OpenFHE),
		formatMeasurement("lattigo", summary.Lattigo),
		summary.Comparison.MeanLatencyRatioLattigoOverOpenFHE,
		summary.Comparison.MedianLatencyRatioLattigoOverOpenFHE,
		summary.Comparison.EffectiveThroughputRatioLattigoOverOpenFHE,
	)
}

func formatMeasurement(label string, measurement Measurement) string {
	return fmt.Sprintf(
		"%s implementation=%s provenance=%q host_id=%q protocol=%q workload_id=%q packing_id=%q output_container=%q word_bits=%d ring_dimension=%d packing_slots=%d useful_words=%d threads=%d timing_scope=%s setup_ns=%d warmup=%d warmup_verified=%t repeats=%d verified_evaluations=%d mean_ns=%.3f median_ns=%.3f effective_words_per_second=%.6f mismatch_count=%d samples_ns=%v",
		label, measurement.Source, measurement.Provenance, measurement.HostID, measurement.Protocol,
		measurement.WorkloadID, measurement.PackingID, measurement.OutputContainer,
		measurement.WordBits, measurement.RingDimension, measurement.PackingSlots, measurement.UsefulWords,
		measurement.Threads, measurement.TimingScope, measurement.SetupNanoseconds,
		measurement.Warmup, measurement.WarmupVerified, measurement.Repeats, measurement.VerifiedEvaluations,
		measurement.A2BMeanNanoseconds, measurement.A2BMedianNanoseconds,
		measurement.EffectiveWordsPerSecond, measurement.MismatchCount, measurement.TimedSamplesNanoseconds,
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

// CanonicalArtifact is the aggregate-free interchange format emitted by both
// focused implementations. Statistics are deliberately absent: consumers
// derive them from TimedSamplesNanoseconds after validating the protocol.
type CanonicalArtifact struct {
	Schema                  string     `json:"schema"`
	Implementation          string     `json:"implementation"`
	CompletedAt             *time.Time `json:"completed_at,omitempty"`
	HostID                  string     `json:"host_id"`
	Protocol                string     `json:"protocol"`
	WorkloadID              string     `json:"workload_id"`
	PackingID               string     `json:"packing_id"`
	OutputContainer         string     `json:"output_container,omitempty"`
	WordBits                uint32     `json:"word_bits"`
	RingDimension           uint32     `json:"ring_dimension"`
	PackingSlots            uint32     `json:"packing_slots"`
	UsefulWords             uint32     `json:"useful_words"`
	Threads                 uint32     `json:"threads"`
	TimingScope             string     `json:"timing_scope"`
	SetupNanoseconds        uint64     `json:"setup_nanoseconds"`
	WarmupCount             uint32     `json:"warmup_count"`
	WarmupVerified          bool       `json:"warmup_verified"`
	RepeatCount             uint32     `json:"repeat_count"`
	TimedSamplesNanoseconds []uint64   `json:"timed_samples_nanoseconds"`
	MismatchCount           uint64     `json:"mismatch_count"`
	VerifiedEvaluations     uint32     `json:"verified_evaluations"`
}

// ParseCanonical parses and validates a v2 focused A2B benchmark artifact.
func ParseCanonical(input io.Reader, provenance string) (Measurement, error) {
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var artifact CanonicalArtifact
	if err := decoder.Decode(&artifact); err != nil {
		return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: trailing JSON value")
		}
		return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: trailing data: %w", err)
	}
	if artifact.Schema != CanonicalBenchmarkSchema {
		return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: schema=%q, want %q", artifact.Schema, CanonicalBenchmarkSchema)
	}

	measurement, err := normalizeMeasurement(Measurement{
		Source: artifact.Implementation, Provenance: provenance, HostID: artifact.HostID,
		Protocol: artifact.Protocol, WorkloadID: artifact.WorkloadID, PackingID: artifact.PackingID,
		OutputContainer: artifact.OutputContainer, WordBits: artifact.WordBits,
		RingDimension: artifact.RingDimension, PackingSlots: artifact.PackingSlots,
		UsefulWords: artifact.UsefulWords, Threads: artifact.Threads, TimingScope: artifact.TimingScope,
		SetupNanoseconds: artifact.SetupNanoseconds, Warmup: artifact.WarmupCount,
		WarmupVerified: artifact.WarmupVerified, Repeats: artifact.RepeatCount,
		TimedSamplesNanoseconds: artifact.TimedSamplesNanoseconds,
		VerifiedEvaluations:     artifact.VerifiedEvaluations, MismatchCount: artifact.MismatchCount,
	})
	if err != nil {
		return Measurement{}, fmt.Errorf("validate canonical A2B benchmark JSON: %w", err)
	}
	return measurement, nil
}

func normalizeMeasurement(measurement Measurement) (Measurement, error) {
	if strings.TrimSpace(measurement.Source) == "" {
		return Measurement{}, fmt.Errorf("implementation is required")
	}
	if strings.TrimSpace(measurement.Provenance) == "" {
		return Measurement{}, fmt.Errorf("provenance is required")
	}
	if strings.TrimSpace(measurement.HostID) == "" {
		return Measurement{}, fmt.Errorf("host_id is required")
	}
	if strings.TrimSpace(measurement.Protocol) == "" {
		return Measurement{}, fmt.Errorf("protocol is required")
	}
	if strings.TrimSpace(measurement.WorkloadID) == "" {
		return Measurement{}, fmt.Errorf("workload_id is required")
	}
	if strings.TrimSpace(measurement.PackingID) == "" {
		return Measurement{}, fmt.Errorf("packing_id is required")
	}
	if measurement.WordBits != canonicalWordBits {
		return Measurement{}, fmt.Errorf("word_bits=%d, want %d", measurement.WordBits, canonicalWordBits)
	}
	if measurement.RingDimension == 0 {
		return Measurement{}, fmt.Errorf("ring_dimension must be nonzero")
	}
	if measurement.PackingSlots == 0 {
		return Measurement{}, fmt.Errorf("packing_slots must be nonzero")
	}
	if measurement.UsefulWords == 0 || measurement.UsefulWords > measurement.PackingSlots {
		return Measurement{}, fmt.Errorf("useful_words=%d, want 1..%d", measurement.UsefulWords, measurement.PackingSlots)
	}
	if measurement.Threads != 1 {
		return Measurement{}, fmt.Errorf("threads must be 1, got %d", measurement.Threads)
	}
	if measurement.TimingScope != TimingScopePreparedOnline {
		return Measurement{}, fmt.Errorf("timing scope must be %q, got %q", TimingScopePreparedOnline, measurement.TimingScope)
	}
	if measurement.SetupNanoseconds == 0 {
		return Measurement{}, fmt.Errorf("setup_nanoseconds must be nonzero")
	}
	if measurement.Warmup == 0 {
		return Measurement{}, fmt.Errorf("warmup_count must be nonzero")
	}
	if !measurement.WarmupVerified {
		return Measurement{}, fmt.Errorf("warmup_verified must be true")
	}
	if measurement.Repeats == 0 {
		return Measurement{}, fmt.Errorf("repeat_count must be nonzero")
	}
	if uint32(len(measurement.TimedSamplesNanoseconds)) != measurement.Repeats {
		return Measurement{}, fmt.Errorf("timed sample count=%d, want repeat_count=%d", len(measurement.TimedSamplesNanoseconds), measurement.Repeats)
	}
	if measurement.VerifiedEvaluations != measurement.Repeats {
		return Measurement{}, fmt.Errorf("verified_evaluations=%d, want repeat_count=%d", measurement.VerifiedEvaluations, measurement.Repeats)
	}
	if measurement.MismatchCount != 0 {
		return Measurement{}, fmt.Errorf("mismatch_count=%d, want 0", measurement.MismatchCount)
	}

	samples := append([]uint64(nil), measurement.TimedSamplesNanoseconds...)
	var total float64
	for index, sample := range samples {
		if sample == 0 {
			return Measurement{}, fmt.Errorf("timed_samples_nanoseconds[%d] must be nonzero", index)
		}
		total += float64(sample)
	}
	sortedSamples := append([]uint64(nil), samples...)
	sort.Slice(sortedSamples, func(i, j int) bool { return sortedSamples[i] < sortedSamples[j] })
	median := float64(sortedSamples[len(sortedSamples)/2])
	if len(sortedSamples)%2 == 0 {
		left := float64(sortedSamples[len(sortedSamples)/2-1])
		median = left + (median-left)/2
	}
	mean := total / float64(len(samples))

	measurement.TimedSamplesNanoseconds = samples
	measurement.A2BMeanNanoseconds = mean
	measurement.A2BMedianNanoseconds = median
	measurement.EffectiveWordsPerSecond = float64(measurement.UsefulWords) * 1e9 / mean
	measurement.A2BLatencyNanoseconds = 0
	measurement.Lanes = 0
	return measurement, nil
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
	payload, err := io.ReadAll(input)
	if err != nil {
		return Measurement{}, fmt.Errorf("read Lattigo Route-B JSON: %w", err)
	}
	var envelope struct {
		Schema      string                                     `json:"schema"`
		CompletedAt *time.Time                                 `json:"completed_at"`
		Result      secureeval.RouteBCanonicalL11A2BFullResult `json:"result"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: trailing JSON value")
		}
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: trailing data: %w", err)
	}
	if envelope.Schema != lattigoRouteBSchema {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: schema=%q, want %q", envelope.Schema, lattigoRouteBSchema)
	}
	if envelope.CompletedAt == nil || envelope.CompletedAt.IsZero() {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: missing or zero completed_at")
	}
	var required struct {
		Result *struct {
			MismatchCount *uint64 `json:"mismatch_count"`
		} `json:"result"`
	}
	if err := json.Unmarshal(payload, &required); err != nil {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B required fields: %w", err)
	}
	if required.Result == nil || required.Result.MismatchCount == nil {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: missing mismatch_count")
	}
	result := envelope.Result
	if result.FullA2B.WallNanoseconds == 0 || result.InputWords == 0 ||
		result.FirstOperation.LogN == 0 || result.FirstOperation.WordBits == 0 {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: incomplete A2B timing or workload")
	}
	if result.FirstOperation.LogN != canonicalLogN {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: LogN=%d, want %d", result.FirstOperation.LogN, canonicalLogN)
	}
	if result.FirstOperation.PackingSlots != canonicalSlots {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: PackingSlots=%d, want %d", result.FirstOperation.PackingSlots, canonicalSlots)
	}
	if result.FirstOperation.WordBits != canonicalWordBits {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: WordBits=%d, want %d", result.FirstOperation.WordBits, canonicalWordBits)
	}
	if result.FirstOperation.WordCapacity != canonicalWords {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: WordCapacity=%d, want %d", result.FirstOperation.WordCapacity, canonicalWords)
	}
	if result.InputWords != result.FirstOperation.WordCapacity {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: input_words=%d, want WordCapacity=%d", result.InputWords, result.FirstOperation.WordCapacity)
	}
	if result.MismatchCount != 0 {
		return Measurement{}, fmt.Errorf("Lattigo Route-B correctness failure: mismatch_count=%d", result.MismatchCount)
	}
	if err := result.Validate(); err != nil {
		return Measurement{}, fmt.Errorf("validate complete Lattigo Route-B result: %w", err)
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
