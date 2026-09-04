// Package benchcmp parses and compares A2B benchmark artifacts.
package benchcmp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureeval"
)

const (
	GaoOpenFHESource              = "gao-openfhe-benchmark-full"
	LattigoRouteBSource           = "lattigo-route-b-l11-a2b-full"
	CanonicalBenchmarkSchema      = "lcpdte-ckksint-a2b-benchmark-v3"
	ComparisonSchema              = "lcpdte-ckksint-a2b-comparison-v3"
	TimingScopePreparedOnline     = "prepared-online"
	GaoParameterComparisonScope   = "gao-algorithm-and-aggregate-modulus-bits"
	GaoFullProtocol               = "gao-a2b-full-z8-w4-v1"
	GaoFullWorkloadID             = "uint8-0to255-x32"
	GaoFullPackingID              = "n65536-cslots32768-zslots8192-w4"
	GaoFullOutputContainer        = "two-ciphertexts-low4-high4"
	FocusedOpenFHESource          = "gao-openfhe-a2b-full"
	FocusedLattigoSource          = "lattigo-gao-a2b-full"
	EncryptionModePublicKey       = "public-key"
	OpenFHEFactorStorageMode      = "resident-precomputed"
	LattigoFactorStorageMode      = "resident-prevalidated"
	OpenFHEScaleSchedule          = "openfhe-flexiblemanual-native"
	LattigoScaleSchedule          = "lattigo-explicit-level-scale-native"
	OpenFHEBackendBSGSPlan        = "openfhe-auto-dim1-0"
	LattigoBackendBSGSPlan        = "lattigo-dft-log-bsgs-ratio-2-special-b0-ratio-2-live-output-identity-mask-drop-complex-lut-optimized"
	OpenFHEPinnedSourceRevision   = "08f1eb87434e7be072cba889270a8400bbffc08e"
	OpenFHERuntime                = "OpenFHE-1.4.0;HEXL-1.2.6"
	OpenFHEBuildProfile           = "CMAKE_BUILD_TYPE=Release;CXX_FLAGS=-march=native,-O3,-DNDEBUG,-fopenmp=libomp;MATHBACKEND=6;OPENFHE_VERSION=1.4.0;HEXL_VERSION=1.2.6;WITH_INTEL_HEXL=ON;WITH_NATIVEOPT=ON;WITH_NTL=ON;WITH_TCM=ON;WITH_OPENMP=ON;OMP_NUM_THREADS=1"
	LattigoAcceptanceBuildProfile = "GOOS=linux;GOARCH=amd64;GOAMD64=v4;GOMAXPROCS=1;GOGC=100;GOMEMLIMIT=20GiB;POST_WARMUP_GC=on;CPU_PROFILE=off"
	lattigoRouteBSchema           = "lcpdte-route-b-l11-a2b-full-result-v1"
	gaoWarmupCount                = 1
	gaoRepeatCount                = 5
	lattigoWarmupCount            = 0
	lattigoRepeatCount            = 1
	canonicalLogN                 = 16
	canonicalWordBits             = 8
	canonicalRingDimension        = 1 << canonicalLogN
	canonicalPackingSlots         = 32768
	canonicalUsefulWords          = 8192
	legacyRouteBSlots             = 2048
	legacyRouteBWords             = 512
)

var (
	openFHERingDimensionPattern = regexp.MustCompile(`CKKS scheme ring dimension:\s*(\d+)`)
	openFHEPackingPattern       = regexp.MustCompile(`Bootstrapping parameters:\s*zN\s*=\s*(\d+)\s*,\s*zSlots\s*=\s*(\d+)`)
	openFHEA2BWarmupPattern     = regexp.MustCompile(`Finished Warmup for A2B(?:\s+[0-9]+(?:\.[0-9]*)?(?:[eE][+-]?\d+)?\s*s)?`)
	openFHEA2BTimePattern       = regexp.MustCompile(`Time for A2B\s*:\s*([0-9]+(?:\.[0-9]*)?(?:[eE][+-]?\d+)?)\s*s`)
	openFHEErrorPattern         = regexp.MustCompile(`Error in[^\r\n]*`)
	gaoParameterFieldNames      = []string{
		"comparison_scope", "q_moduli_count", "q_log2_aggregate", "p_moduli_count", "p_log2_aggregate",
		"scaling_modulus_bits", "first_modulus_bits", "multiplicative_depth", "large_digits",
		"main_secret_hamming_weight", "ephemeral_secret_hamming_weight",
		"rns_decomposition_components", "base_two_decomposition", "level_budget",
		"openfhe_requested_bsgs_dimensions", "chunk_width", "cutoff_bits",
	}
	nativeParameterFieldNames = []string{
		"actual_first_q_modulus_bits",
		"main_secret_distribution", "main_secret_hamming_weight",
		"ephemeral_secret_distribution", "ephemeral_secret_hamming_weight",
		"error_sampler", "error_sigma", "error_configured_bound", "error_effective_integer_bound",
		"key_switch_technique", "key_switch_rns_decomposition_components", "key_switch_base_two_decomposition",
		"security_selector", "security_evidence",
		"q_moduli", "q_moduli_bit_lengths", "p_moduli", "p_moduli_bit_lengths",
	}
)

// Measurement is one whole-call A2B timing and its effective packed workload.
type Measurement struct {
	Source                  string                 `json:"source"`
	Provenance              string                 `json:"provenance"`
	HostID                  string                 `json:"host_id"`
	EncryptionMode          string                 `json:"encryption_mode"`
	FactorStorageMode       string                 `json:"factor_storage_mode"`
	ScaleSchedule           string                 `json:"scale_schedule"`
	BackendBSGSPlan         string                 `json:"backend_bsgs_plan"`
	SourceRevision          string                 `json:"source_revision"`
	SourceModified          bool                   `json:"source_modified"`
	Runtime                 string                 `json:"runtime"`
	Compiler                string                 `json:"compiler"`
	BuildProfile            string                 `json:"build_profile"`
	OS                      string                 `json:"os"`
	Arch                    string                 `json:"arch"`
	Protocol                string                 `json:"protocol"`
	WorkloadID              string                 `json:"workload_id"`
	PackingID               string                 `json:"packing_id"`
	OutputContainer         string                 `json:"output_container,omitempty"`
	WordBits                uint32                 `json:"word_bits"`
	RingDimension           uint32                 `json:"ring_dimension"`
	PackingSlots            uint32                 `json:"packing_slots"`
	UsefulWords             uint32                 `json:"useful_words"`
	Parameters              *GaoParameterSemantics `json:"parameters"`
	NativeParameters        *NativeParameters      `json:"native_parameters"`
	Threads                 uint32                 `json:"threads"`
	TimingScope             string                 `json:"timing_scope"`
	SetupNanoseconds        uint64                 `json:"setup_nanoseconds"`
	Warmup                  uint32                 `json:"warmup_count"`
	WarmupVerified          bool                   `json:"warmup_verified"`
	Repeats                 uint32                 `json:"repeat_count"`
	TimedSamplesNanoseconds []uint64               `json:"timed_samples_nanoseconds"`
	VerifiedEvaluations     uint32                 `json:"verified_evaluations"`
	MismatchCount           uint64                 `json:"mismatch_count"`
	A2BMeanNanoseconds      float64                `json:"a2b_mean_nanoseconds"`
	A2BMedianNanoseconds    float64                `json:"a2b_median_nanoseconds"`
	EffectiveWordsPerSecond float64                `json:"effective_words_per_second"`
	A2BLatencyNanoseconds   uint64                 `json:"a2b_latency_nanoseconds,omitempty"`
	Lanes                   uint32                 `json:"lanes,omitempty"`
}

// GaoParameterSemantics records the algorithm targets and aggregate modulus
// sizes that must match across backends. ScalingModulusBits and
// FirstModulusBits are constructor targets; NativeParameters records the
// resulting first-prime width and complete backend-native RNS chains.
type GaoParameterSemantics struct {
	ComparisonScope                string    `json:"comparison_scope"`
	QModuliCount                   uint32    `json:"q_moduli_count"`
	QLog2Aggregate                 uint32    `json:"q_log2_aggregate"`
	PModuliCount                   uint32    `json:"p_moduli_count"`
	PLog2Aggregate                 uint32    `json:"p_log2_aggregate"`
	ScalingModulusBits             uint32    `json:"scaling_modulus_bits"`
	FirstModulusBits               uint32    `json:"first_modulus_bits"`
	MultiplicativeDepth            uint32    `json:"multiplicative_depth"`
	LargeDigits                    uint32    `json:"large_digits"`
	MainSecretHammingWeight        uint32    `json:"main_secret_hamming_weight"`
	EphemeralSecretHammingWeight   uint32    `json:"ephemeral_secret_hamming_weight"`
	KeySwitchRNSComponents         uint32    `json:"rns_decomposition_components"`
	KeySwitchBaseTwoDecomposition  uint32    `json:"base_two_decomposition"`
	LevelBudget                    [2]uint32 `json:"level_budget"`
	OpenFHERequestedBSGSDimensions [2]uint32 `json:"openfhe_requested_bsgs_dimensions"`
	ChunkWidth                     uint32    `json:"chunk_width"`
	CutoffBits                     int32     `json:"cutoff_bits"`
}

// NativeParameters is lossless backend-specific evidence for the parameters
// that produced a focused benchmark measurement. Native values are validated
// per backend and are intentionally not required to be identical across them.
type NativeParameters struct {
	ActualFirstQModulusBits       uint32   `json:"actual_first_q_modulus_bits"`
	MainSecretDistribution        string   `json:"main_secret_distribution"`
	MainSecretHammingWeight       uint32   `json:"main_secret_hamming_weight"`
	EphemeralSecretDistribution   string   `json:"ephemeral_secret_distribution"`
	EphemeralSecretHammingWeight  uint32   `json:"ephemeral_secret_hamming_weight"`
	ErrorSampler                  string   `json:"error_sampler"`
	ErrorSigma                    float64  `json:"error_sigma"`
	ErrorConfiguredBound          *float64 `json:"error_configured_bound"`
	ErrorEffectiveIntegerBound    uint32   `json:"error_effective_integer_bound"`
	KeySwitchTechnique            string   `json:"key_switch_technique"`
	KeySwitchRNSComponents        uint32   `json:"key_switch_rns_decomposition_components"`
	KeySwitchBaseTwoDecomposition uint32   `json:"key_switch_base_two_decomposition"`
	SecuritySelector              string   `json:"security_selector"`
	SecurityEvidence              string   `json:"security_evidence"`
	QModuli                       []string `json:"q_moduli"`
	QModuliBitLengths             []uint32 `json:"q_moduli_bit_lengths"`
	PModuli                       []string `json:"p_moduli"`
	PModuliBitLengths             []uint32 `json:"p_moduli_bit_lengths"`
}

// CanonicalGaoParameters returns the parameter contract shared by the focused
// Gao/OpenFHE and Lattigo full-packed A2B benchmarks.
func CanonicalGaoParameters() *GaoParameterSemantics {
	return &GaoParameterSemantics{
		ComparisonScope:                GaoParameterComparisonScope,
		QModuliCount:                   21,
		QLog2Aggregate:                 904,
		PModuliCount:                   7,
		PLog2Aggregate:                 350,
		ScalingModulusBits:             43,
		FirstModulusBits:               43,
		MultiplicativeDepth:            20,
		LargeDigits:                    3,
		MainSecretHammingWeight:        192,
		EphemeralSecretHammingWeight:   32,
		KeySwitchRNSComponents:         3,
		KeySwitchBaseTwoDecomposition:  0,
		LevelBudget:                    [2]uint32{3, 2},
		OpenFHERequestedBSGSDimensions: [2]uint32{0, 0},
		ChunkWidth:                     4,
		CutoffBits:                     -24,
	}
}

// Comparison records ratios derived from matched, verified online samples.
type Comparison struct {
	MeanLatencyRatioLattigoOverOpenFHE         float64 `json:"mean_latency_ratio_lattigo_over_openfhe"`
	MedianLatencyRatioLattigoOverOpenFHE       float64 `json:"median_latency_ratio_lattigo_over_openfhe"`
	EffectiveThroughputRatioLattigoOverOpenFHE float64 `json:"effective_throughput_ratio_lattigo_over_openfhe"`
	MeanNotSlower                              bool    `json:"mean_not_slower"`
	MedianNotSlower                            bool    `json:"median_not_slower"`
	Pass                                       bool    `json:"pass"`
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
	if openfhe.Source != FocusedOpenFHESource {
		return Summary{}, fmt.Errorf("compare A2B artifacts: OpenFHE implementation=%q, want %q", openfhe.Source, FocusedOpenFHESource)
	}
	if lattigo.Source != FocusedLattigoSource {
		return Summary{}, fmt.Errorf("compare A2B artifacts: Lattigo implementation=%q, want %q", lattigo.Source, FocusedLattigoSource)
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
	if openfhe.OS != lattigo.OS {
		return Summary{}, fmt.Errorf("compare A2B artifacts: os mismatch: OpenFHE=%q Lattigo=%q", openfhe.OS, lattigo.OS)
	}
	if openfhe.Arch != lattigo.Arch {
		return Summary{}, fmt.Errorf("compare A2B artifacts: arch mismatch: OpenFHE=%q Lattigo=%q", openfhe.Arch, lattigo.Arch)
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
	if openfhe.OutputContainer != GaoFullOutputContainer {
		return Summary{}, fmt.Errorf("compare A2B artifacts: OpenFHE output_container=%q, want %q", openfhe.OutputContainer, GaoFullOutputContainer)
	}
	if lattigo.OutputContainer != GaoFullOutputContainer {
		return Summary{}, fmt.Errorf("compare A2B artifacts: Lattigo output_container=%q, want %q", lattigo.OutputContainer, GaoFullOutputContainer)
	}
	if err = validateMatchedNativeParameters(*openfhe.NativeParameters, *lattigo.NativeParameters); err != nil {
		return Summary{}, fmt.Errorf("compare A2B artifacts: %w", err)
	}

	meanRatio := lattigo.A2BMeanNanoseconds / openfhe.A2BMeanNanoseconds
	medianRatio := lattigo.A2BMedianNanoseconds / openfhe.A2BMedianNanoseconds
	meanPass := meanRatio <= 1
	medianPass := medianRatio <= 1
	summary := Summary{
		Schema:  ComparisonSchema,
		OpenFHE: openfhe,
		Lattigo: lattigo,
		Comparison: Comparison{
			MeanLatencyRatioLattigoOverOpenFHE:         meanRatio,
			MedianLatencyRatioLattigoOverOpenFHE:       medianRatio,
			EffectiveThroughputRatioLattigoOverOpenFHE: lattigo.EffectiveWordsPerSecond / openfhe.EffectiveWordsPerSecond,
			MeanNotSlower:   meanPass,
			MedianNotSlower: medianPass,
			Pass:            meanPass && medianPass,
		},
	}
	if !summary.Comparison.Pass {
		return summary, fmt.Errorf(
			"performance parity gate failed: Lattigo/OpenFHE mean ratio=%.6f (pass=%t), median ratio=%.6f (pass=%t); both must be <=1",
			meanRatio, meanPass, medianRatio, medianPass,
		)
	}
	return summary, nil
}

func validateMatchedNativeParameters(openfhe, lattigo NativeParameters) error {
	if !slices.Equal(openfhe.QModuli, lattigo.QModuli) {
		return fmt.Errorf("native q_moduli mismatch between OpenFHE and Lattigo")
	}
	if !slices.Equal(openfhe.PModuli, lattigo.PModuli) {
		return fmt.Errorf("native p_moduli mismatch between OpenFHE and Lattigo")
	}
	if openfhe.ActualFirstQModulusBits != lattigo.ActualFirstQModulusBits {
		return fmt.Errorf(
			"native actual_first_q_modulus_bits mismatch: OpenFHE=%d Lattigo=%d",
			openfhe.ActualFirstQModulusBits, lattigo.ActualFirstQModulusBits,
		)
	}
	if openfhe.MainSecretHammingWeight != lattigo.MainSecretHammingWeight ||
		openfhe.EphemeralSecretHammingWeight != lattigo.EphemeralSecretHammingWeight {
		return fmt.Errorf("native secret Hamming weights mismatch between OpenFHE and Lattigo")
	}
	if openfhe.ErrorSigma != lattigo.ErrorSigma ||
		openfhe.ErrorEffectiveIntegerBound != lattigo.ErrorEffectiveIntegerBound {
		return fmt.Errorf(
			"native error parameters mismatch: OpenFHE=sigma %g/bound %d Lattigo=sigma %g/bound %d",
			openfhe.ErrorSigma, openfhe.ErrorEffectiveIntegerBound,
			lattigo.ErrorSigma, lattigo.ErrorEffectiveIntegerBound,
		)
	}
	if openfhe.KeySwitchRNSComponents != lattigo.KeySwitchRNSComponents ||
		openfhe.KeySwitchBaseTwoDecomposition != lattigo.KeySwitchBaseTwoDecomposition {
		return fmt.Errorf("native key-switch decomposition mismatch between OpenFHE and Lattigo")
	}
	return nil
}

// FormatText renders a deterministic, line-oriented human summary.
func FormatText(summary Summary) string {
	return fmt.Sprintf(
		"schema=%s\n%s\n%s\ncomparison mean_latency_ratio_lattigo_over_openfhe=%.6f median_latency_ratio_lattigo_over_openfhe=%.6f effective_throughput_ratio_lattigo_over_openfhe=%.6f mean_not_slower=%t median_not_slower=%t pass=%t\n",
		summary.Schema,
		formatMeasurement("openfhe", summary.OpenFHE),
		formatMeasurement("lattigo", summary.Lattigo),
		summary.Comparison.MeanLatencyRatioLattigoOverOpenFHE,
		summary.Comparison.MedianLatencyRatioLattigoOverOpenFHE,
		summary.Comparison.EffectiveThroughputRatioLattigoOverOpenFHE,
		summary.Comparison.MeanNotSlower,
		summary.Comparison.MedianNotSlower,
		summary.Comparison.Pass,
	)
}

func formatMeasurement(label string, measurement Measurement) string {
	return fmt.Sprintf(
		"%s implementation=%s provenance=%q host_id=%q os=%q arch=%q encryption_mode=%q factor_storage_mode=%q scale_schedule=%q backend_bsgs_plan=%q source_revision=%q source_modified=%t runtime=%q compiler=%q build_profile=%q protocol=%q workload_id=%q packing_id=%q output_container=%q word_bits=%d ring_dimension=%d packing_slots=%d useful_words=%d threads=%d timing_scope=%s setup_ns=%d warmup=%d warmup_verified=%t repeats=%d verified_evaluations=%d mean_ns=%.3f median_ns=%.3f effective_words_per_second=%.6f mismatch_count=%d samples_ns=%v",
		label, measurement.Source, measurement.Provenance, measurement.HostID,
		measurement.OS, measurement.Arch, measurement.EncryptionMode, measurement.FactorStorageMode,
		measurement.ScaleSchedule, measurement.BackendBSGSPlan, measurement.SourceRevision,
		measurement.SourceModified, measurement.Runtime, measurement.Compiler, measurement.BuildProfile,
		measurement.Protocol, measurement.WorkloadID, measurement.PackingID, measurement.OutputContainer,
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
	Schema                  string                 `json:"schema"`
	Implementation          string                 `json:"implementation"`
	CompletedAt             *time.Time             `json:"completed_at,omitempty"`
	HostID                  string                 `json:"host_id"`
	EncryptionMode          string                 `json:"encryption_mode"`
	FactorStorageMode       string                 `json:"factor_storage_mode"`
	ScaleSchedule           string                 `json:"scale_schedule"`
	BackendBSGSPlan         string                 `json:"backend_bsgs_plan"`
	SourceRevision          string                 `json:"source_revision"`
	SourceModified          bool                   `json:"source_modified"`
	Runtime                 string                 `json:"runtime"`
	Compiler                string                 `json:"compiler"`
	BuildProfile            string                 `json:"build_profile"`
	OS                      string                 `json:"os"`
	Arch                    string                 `json:"arch"`
	Protocol                string                 `json:"protocol"`
	WorkloadID              string                 `json:"workload_id"`
	PackingID               string                 `json:"packing_id"`
	OutputContainer         string                 `json:"output_container,omitempty"`
	WordBits                uint32                 `json:"word_bits"`
	RingDimension           uint32                 `json:"ring_dimension"`
	PackingSlots            uint32                 `json:"packing_slots"`
	UsefulWords             uint32                 `json:"useful_words"`
	Parameters              *GaoParameterSemantics `json:"parameters"`
	NativeParameters        *NativeParameters      `json:"native_parameters"`
	Threads                 uint32                 `json:"threads"`
	TimingScope             string                 `json:"timing_scope"`
	SetupNanoseconds        uint64                 `json:"setup_nanoseconds"`
	WarmupCount             uint32                 `json:"warmup_count"`
	WarmupVerified          bool                   `json:"warmup_verified"`
	RepeatCount             uint32                 `json:"repeat_count"`
	TimedSamplesNanoseconds []uint64               `json:"timed_samples_nanoseconds"`
	MismatchCount           uint64                 `json:"mismatch_count"`
	VerifiedEvaluations     uint32                 `json:"verified_evaluations"`
}

// ParseCanonical parses and validates a v3 focused A2B benchmark artifact.
func ParseCanonical(input io.Reader, provenance string) (Measurement, error) {
	payload, err := io.ReadAll(input)
	if err != nil {
		return Measurement{}, fmt.Errorf("read canonical A2B benchmark JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
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
	var present map[string]json.RawMessage
	if err := json.Unmarshal(payload, &present); err != nil {
		return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON fields: %w", err)
	}
	for _, field := range []string{
		"encryption_mode", "factor_storage_mode", "scale_schedule", "backend_bsgs_plan",
		"source_revision", "source_modified", "runtime", "compiler", "build_profile", "os", "arch",
		"parameters", "native_parameters", "mismatch_count",
	} {
		if _, ok := present[field]; !ok {
			return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: %s is required", field)
		}
	}
	if !bytes.Equal(bytes.TrimSpace(present["source_modified"]), []byte("false")) {
		return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: source_modified must be boolean false")
	}
	var parameterFields map[string]json.RawMessage
	if err := json.Unmarshal(present["parameters"], &parameterFields); err != nil || parameterFields == nil {
		return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: parameters must be an object")
	}
	for _, field := range gaoParameterFieldNames {
		if _, ok := parameterFields[field]; !ok {
			return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: parameters.%s is required", field)
		}
	}
	if bytes.Equal(bytes.TrimSpace(present["native_parameters"]), []byte("null")) {
		return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: native_parameters must be an object")
	}
	var nativeFields map[string]json.RawMessage
	if err := json.Unmarshal(present["native_parameters"], &nativeFields); err != nil || nativeFields == nil {
		return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: native_parameters must be an object")
	}
	for _, field := range nativeParameterFieldNames {
		if _, ok := nativeFields[field]; !ok {
			return Measurement{}, fmt.Errorf("parse canonical A2B benchmark JSON: native_parameters.%s is required", field)
		}
	}

	measurement, err := normalizeMeasurement(Measurement{
		Source: artifact.Implementation, Provenance: provenance, HostID: artifact.HostID,
		EncryptionMode: artifact.EncryptionMode, FactorStorageMode: artifact.FactorStorageMode,
		ScaleSchedule: artifact.ScaleSchedule, BackendBSGSPlan: artifact.BackendBSGSPlan,
		SourceRevision: artifact.SourceRevision, SourceModified: artifact.SourceModified,
		Runtime: artifact.Runtime, Compiler: artifact.Compiler, BuildProfile: artifact.BuildProfile,
		OS: artifact.OS, Arch: artifact.Arch,
		Protocol: artifact.Protocol, WorkloadID: artifact.WorkloadID, PackingID: artifact.PackingID,
		OutputContainer: artifact.OutputContainer, WordBits: artifact.WordBits,
		RingDimension: artifact.RingDimension, PackingSlots: artifact.PackingSlots,
		UsefulWords: artifact.UsefulWords, Parameters: artifact.Parameters,
		NativeParameters: artifact.NativeParameters,
		Threads:          artifact.Threads, TimingScope: artifact.TimingScope,
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
	if err := validateExecutionMetadata(measurement); err != nil {
		return Measurement{}, err
	}
	if strings.TrimSpace(measurement.Protocol) == "" {
		return Measurement{}, fmt.Errorf("protocol is required")
	}
	if measurement.Protocol != GaoFullProtocol {
		return Measurement{}, fmt.Errorf("protocol=%q, want %q", measurement.Protocol, GaoFullProtocol)
	}
	if strings.TrimSpace(measurement.WorkloadID) == "" {
		return Measurement{}, fmt.Errorf("workload_id is required")
	}
	if measurement.WorkloadID != GaoFullWorkloadID {
		return Measurement{}, fmt.Errorf("workload_id=%q, want %q", measurement.WorkloadID, GaoFullWorkloadID)
	}
	if strings.TrimSpace(measurement.PackingID) == "" {
		return Measurement{}, fmt.Errorf("packing_id is required")
	}
	if measurement.PackingID != GaoFullPackingID {
		return Measurement{}, fmt.Errorf("packing_id=%q, want %q", measurement.PackingID, GaoFullPackingID)
	}
	if measurement.OutputContainer != GaoFullOutputContainer {
		return Measurement{}, fmt.Errorf("output_container=%q, want %q", measurement.OutputContainer, GaoFullOutputContainer)
	}
	if measurement.WordBits != canonicalWordBits {
		return Measurement{}, fmt.Errorf("word_bits=%d, want %d", measurement.WordBits, canonicalWordBits)
	}
	if measurement.RingDimension != canonicalRingDimension {
		return Measurement{}, fmt.Errorf("ring_dimension=%d, want %d", measurement.RingDimension, canonicalRingDimension)
	}
	if measurement.PackingSlots != canonicalPackingSlots {
		return Measurement{}, fmt.Errorf("packing_slots=%d, want %d", measurement.PackingSlots, canonicalPackingSlots)
	}
	if measurement.UsefulWords != canonicalUsefulWords {
		return Measurement{}, fmt.Errorf("useful_words=%d, want %d", measurement.UsefulWords, canonicalUsefulWords)
	}
	if measurement.Parameters == nil {
		return Measurement{}, fmt.Errorf("parameters are required")
	}
	if err := validateGaoParameters(*measurement.Parameters); err != nil {
		return Measurement{}, err
	}
	if measurement.NativeParameters == nil {
		return Measurement{}, fmt.Errorf("native_parameters are required")
	}
	if err := validateNativeParameters(measurement.Source, *measurement.NativeParameters, *measurement.Parameters); err != nil {
		return Measurement{}, err
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
	if measurement.Warmup != gaoWarmupCount {
		return Measurement{}, fmt.Errorf("warmup_count=%d, want %d", measurement.Warmup, gaoWarmupCount)
	}
	if !measurement.WarmupVerified {
		return Measurement{}, fmt.Errorf("warmup_verified must be true")
	}
	if measurement.Repeats != gaoRepeatCount {
		return Measurement{}, fmt.Errorf("repeat_count=%d, want %d", measurement.Repeats, gaoRepeatCount)
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

func validateExecutionMetadata(measurement Measurement) error {
	if measurement.EncryptionMode != EncryptionModePublicKey {
		return fmt.Errorf("encryption_mode=%q, want %q", measurement.EncryptionMode, EncryptionModePublicKey)
	}
	for field, value := range map[string]string{
		"factor_storage_mode": measurement.FactorStorageMode,
		"scale_schedule":      measurement.ScaleSchedule,
		"backend_bsgs_plan":   measurement.BackendBSGSPlan,
		"source_revision":     measurement.SourceRevision,
		"runtime":             measurement.Runtime,
		"compiler":            measurement.Compiler,
		"build_profile":       measurement.BuildProfile,
		"os":                  measurement.OS,
		"arch":                measurement.Arch,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if measurement.SourceModified {
		return fmt.Errorf("source_modified must be false")
	}

	switch measurement.Source {
	case FocusedOpenFHESource:
		if measurement.FactorStorageMode != OpenFHEFactorStorageMode {
			return fmt.Errorf("factor_storage_mode=%q, want %q for %s", measurement.FactorStorageMode, OpenFHEFactorStorageMode, FocusedOpenFHESource)
		}
		if measurement.ScaleSchedule != OpenFHEScaleSchedule {
			return fmt.Errorf("scale_schedule=%q, want %q for %s", measurement.ScaleSchedule, OpenFHEScaleSchedule, FocusedOpenFHESource)
		}
		if measurement.BackendBSGSPlan != OpenFHEBackendBSGSPlan {
			return fmt.Errorf("backend_bsgs_plan=%q, want %q for %s", measurement.BackendBSGSPlan, OpenFHEBackendBSGSPlan, FocusedOpenFHESource)
		}
		if measurement.SourceRevision != OpenFHEPinnedSourceRevision {
			return fmt.Errorf("source_revision=%q, want pinned OpenFHE revision %q", measurement.SourceRevision, OpenFHEPinnedSourceRevision)
		}
		if measurement.Runtime != OpenFHERuntime {
			return fmt.Errorf("runtime=%q, want %q for %s", measurement.Runtime, OpenFHERuntime, FocusedOpenFHESource)
		}
		if measurement.BuildProfile != OpenFHEBuildProfile {
			return fmt.Errorf("build_profile=%q, want %q for %s", measurement.BuildProfile, OpenFHEBuildProfile, FocusedOpenFHESource)
		}
		if !strings.Contains(measurement.Compiler, "/usr/bin/clang++") ||
			!strings.Contains(measurement.Compiler, "clang version 14.") {
			return fmt.Errorf("compiler=%q, want the cached /usr/bin/clang++ Clang 14 toolchain", measurement.Compiler)
		}
		if measurement.OS != "linux" || measurement.Arch != "amd64" {
			return fmt.Errorf("OpenFHE target=%s/%s, want linux/amd64", measurement.OS, measurement.Arch)
		}
	case FocusedLattigoSource:
		if measurement.FactorStorageMode != LattigoFactorStorageMode {
			return fmt.Errorf("factor_storage_mode=%q, want %q for %s", measurement.FactorStorageMode, LattigoFactorStorageMode, FocusedLattigoSource)
		}
		if measurement.ScaleSchedule != LattigoScaleSchedule {
			return fmt.Errorf("scale_schedule=%q, want %q for %s", measurement.ScaleSchedule, LattigoScaleSchedule, FocusedLattigoSource)
		}
		if measurement.BackendBSGSPlan != LattigoBackendBSGSPlan {
			return fmt.Errorf("backend_bsgs_plan=%q, want %q for %s", measurement.BackendBSGSPlan, LattigoBackendBSGSPlan, FocusedLattigoSource)
		}
		if measurement.BuildProfile != LattigoAcceptanceBuildProfile {
			return fmt.Errorf("build_profile=%q, want %q for %s", measurement.BuildProfile, LattigoAcceptanceBuildProfile, FocusedLattigoSource)
		}
		if measurement.Compiler != "gc" {
			return fmt.Errorf("compiler=%q, want gc for %s", measurement.Compiler, FocusedLattigoSource)
		}
		if !strings.HasPrefix(measurement.Runtime, "go1.") {
			return fmt.Errorf("runtime=%q, want a recorded Go 1.x runtime", measurement.Runtime)
		}
		if measurement.OS != "linux" || measurement.Arch != "amd64" {
			return fmt.Errorf("Lattigo target=%s/%s, want linux/amd64", measurement.OS, measurement.Arch)
		}
	default:
		return fmt.Errorf(
			"implementation=%q, want %q or %q",
			measurement.Source, FocusedOpenFHESource, FocusedLattigoSource,
		)
	}
	return nil
}

func validateGaoParameters(actual GaoParameterSemantics) error {
	expected := *CanonicalGaoParameters()
	if actual.ComparisonScope != expected.ComparisonScope {
		return fmt.Errorf("parameters.comparison_scope=%q, want %q", actual.ComparisonScope, expected.ComparisonScope)
	}
	if actual.QModuliCount != expected.QModuliCount {
		return fmt.Errorf("parameters.q_moduli_count=%d, want %d", actual.QModuliCount, expected.QModuliCount)
	}
	if actual.QLog2Aggregate != expected.QLog2Aggregate {
		return fmt.Errorf("parameters.q_log2_aggregate=%d, want %d", actual.QLog2Aggregate, expected.QLog2Aggregate)
	}
	if actual.PModuliCount != expected.PModuliCount {
		return fmt.Errorf("parameters.p_moduli_count=%d, want %d", actual.PModuliCount, expected.PModuliCount)
	}
	if actual.PLog2Aggregate != expected.PLog2Aggregate {
		return fmt.Errorf("parameters.p_log2_aggregate=%d, want %d", actual.PLog2Aggregate, expected.PLog2Aggregate)
	}
	if actual.ScalingModulusBits != expected.ScalingModulusBits {
		return fmt.Errorf("parameters.scaling_modulus_bits=%d, want %d", actual.ScalingModulusBits, expected.ScalingModulusBits)
	}
	if actual.FirstModulusBits != expected.FirstModulusBits {
		return fmt.Errorf("parameters.first_modulus_bits=%d, want %d", actual.FirstModulusBits, expected.FirstModulusBits)
	}
	if actual.MultiplicativeDepth != expected.MultiplicativeDepth {
		return fmt.Errorf("parameters.multiplicative_depth=%d, want %d", actual.MultiplicativeDepth, expected.MultiplicativeDepth)
	}
	if actual.LargeDigits != expected.LargeDigits {
		return fmt.Errorf("parameters.large_digits=%d, want %d", actual.LargeDigits, expected.LargeDigits)
	}
	if actual.MainSecretHammingWeight != expected.MainSecretHammingWeight {
		return fmt.Errorf("parameters.main_secret_hamming_weight=%d, want %d", actual.MainSecretHammingWeight, expected.MainSecretHammingWeight)
	}
	if actual.EphemeralSecretHammingWeight != expected.EphemeralSecretHammingWeight {
		return fmt.Errorf("parameters.ephemeral_secret_hamming_weight=%d, want %d", actual.EphemeralSecretHammingWeight, expected.EphemeralSecretHammingWeight)
	}
	if actual.KeySwitchRNSComponents != expected.KeySwitchRNSComponents {
		return fmt.Errorf("parameters.rns_decomposition_components=%d, want %d", actual.KeySwitchRNSComponents, expected.KeySwitchRNSComponents)
	}
	if actual.KeySwitchBaseTwoDecomposition != expected.KeySwitchBaseTwoDecomposition {
		return fmt.Errorf("parameters.base_two_decomposition=%d, want %d", actual.KeySwitchBaseTwoDecomposition, expected.KeySwitchBaseTwoDecomposition)
	}
	if actual.LevelBudget != expected.LevelBudget {
		return fmt.Errorf("parameters.level_budget=%v, want %v", actual.LevelBudget, expected.LevelBudget)
	}
	if actual.OpenFHERequestedBSGSDimensions != expected.OpenFHERequestedBSGSDimensions {
		return fmt.Errorf("parameters.openfhe_requested_bsgs_dimensions=%v, want %v", actual.OpenFHERequestedBSGSDimensions, expected.OpenFHERequestedBSGSDimensions)
	}
	if actual.ChunkWidth != expected.ChunkWidth {
		return fmt.Errorf("parameters.chunk_width=%d, want %d", actual.ChunkWidth, expected.ChunkWidth)
	}
	if actual.CutoffBits != expected.CutoffBits {
		return fmt.Errorf("parameters.cutoff_bits=%d, want %d", actual.CutoffBits, expected.CutoffBits)
	}
	return nil
}

type expectedNativeParameters struct {
	mainSecretDistribution      string
	ephemeralSecretDistribution string
	errorSampler                string
	errorSigma                  float64
	errorConfiguredBound        *float64
	errorEffectiveIntegerBound  uint32
	keySwitchTechnique          string
	securitySelector            string
	securityEvidence            string
	qModuliBitLengths           []uint32
	pModuliBitLengths           []uint32
}

func validateNativeParameters(source string, actual NativeParameters, shared GaoParameterSemantics) error {
	expected, err := nativeProfileFor(source)
	if err != nil {
		return err
	}
	if actual.MainSecretDistribution != expected.mainSecretDistribution {
		return fmt.Errorf("native_parameters.main_secret_distribution=%q, want %q for %s", actual.MainSecretDistribution, expected.mainSecretDistribution, source)
	}
	if actual.MainSecretHammingWeight != shared.MainSecretHammingWeight {
		return fmt.Errorf("native_parameters.main_secret_hamming_weight=%d, want shared value %d", actual.MainSecretHammingWeight, shared.MainSecretHammingWeight)
	}
	if actual.EphemeralSecretDistribution != expected.ephemeralSecretDistribution {
		return fmt.Errorf("native_parameters.ephemeral_secret_distribution=%q, want %q for %s", actual.EphemeralSecretDistribution, expected.ephemeralSecretDistribution, source)
	}
	if actual.EphemeralSecretHammingWeight != shared.EphemeralSecretHammingWeight {
		return fmt.Errorf("native_parameters.ephemeral_secret_hamming_weight=%d, want shared value %d", actual.EphemeralSecretHammingWeight, shared.EphemeralSecretHammingWeight)
	}
	if actual.ErrorSampler != expected.errorSampler {
		return fmt.Errorf("native_parameters.error_sampler=%q, want %q for %s", actual.ErrorSampler, expected.errorSampler, source)
	}
	if actual.ErrorSigma != expected.errorSigma {
		return fmt.Errorf("native_parameters.error_sigma=%g, want %g for %s", actual.ErrorSigma, expected.errorSigma, source)
	}
	if err := validateConfiguredBound(actual.ErrorConfiguredBound, expected.errorConfiguredBound, source); err != nil {
		return err
	}
	if actual.ErrorEffectiveIntegerBound != expected.errorEffectiveIntegerBound {
		return fmt.Errorf("native_parameters.error_effective_integer_bound=%d, want %d for %s", actual.ErrorEffectiveIntegerBound, expected.errorEffectiveIntegerBound, source)
	}
	if actual.KeySwitchTechnique != expected.keySwitchTechnique {
		return fmt.Errorf("native_parameters.key_switch_technique=%q, want %q for %s", actual.KeySwitchTechnique, expected.keySwitchTechnique, source)
	}
	if actual.KeySwitchRNSComponents != shared.KeySwitchRNSComponents {
		return fmt.Errorf("native_parameters.key_switch_rns_decomposition_components=%d, want shared value %d", actual.KeySwitchRNSComponents, shared.KeySwitchRNSComponents)
	}
	if actual.KeySwitchBaseTwoDecomposition != shared.KeySwitchBaseTwoDecomposition {
		return fmt.Errorf("native_parameters.key_switch_base_two_decomposition=%d, want shared value %d", actual.KeySwitchBaseTwoDecomposition, shared.KeySwitchBaseTwoDecomposition)
	}
	if actual.SecuritySelector != expected.securitySelector {
		return fmt.Errorf("native_parameters.security_selector=%q, want %q for %s", actual.SecuritySelector, expected.securitySelector, source)
	}
	if actual.SecurityEvidence != expected.securityEvidence {
		return fmt.Errorf("native_parameters.security_evidence=%q, want %q for %s", actual.SecurityEvidence, expected.securityEvidence, source)
	}

	qBits, err := validateModulusChain("q", actual.QModuli, actual.QModuliBitLengths, expected.qModuliBitLengths, shared.QModuliCount, shared.QLog2Aggregate)
	if err != nil {
		return err
	}
	if actual.ActualFirstQModulusBits != qBits[0] {
		return fmt.Errorf("native_parameters.actual_first_q_modulus_bits=%d, want recomputed q_moduli[0] bit length %d", actual.ActualFirstQModulusBits, qBits[0])
	}
	if _, err = validateModulusChain("p", actual.PModuli, actual.PModuliBitLengths, expected.pModuliBitLengths, shared.PModuliCount, shared.PLog2Aggregate); err != nil {
		return err
	}
	return nil
}

func validateConfiguredBound(actual, expected *float64, source string) error {
	if expected == nil {
		if actual != nil {
			return fmt.Errorf("native_parameters.error_configured_bound=%g, want null for %s", *actual, source)
		}
		return nil
	}
	if actual == nil || *actual != *expected {
		if actual == nil {
			return fmt.Errorf("native_parameters.error_configured_bound=null, want %g for %s", *expected, source)
		}
		return fmt.Errorf("native_parameters.error_configured_bound=%g, want %g for %s", *actual, *expected, source)
	}
	return nil
}

func validateModulusChain(
	name string,
	decimal []string,
	declared, expected []uint32,
	wantCount, wantAggregate uint32,
) ([]uint32, error) {
	if uint32(len(decimal)) != wantCount {
		return nil, fmt.Errorf("native_parameters.%s_moduli count=%d, want parameters.%s_moduli_count=%d", name, len(decimal), name, wantCount)
	}
	if len(declared) != len(decimal) {
		return nil, fmt.Errorf("native_parameters.%s_moduli_bit_lengths count=%d, want %d", name, len(declared), len(decimal))
	}
	if len(expected) != len(decimal) {
		return nil, fmt.Errorf("native_parameters.%s_moduli backend profile count=%d, want %d", name, len(decimal), len(expected))
	}

	product := big.NewInt(1)
	recomputed := make([]uint32, len(decimal))
	for index, encoded := range decimal {
		value, err := strconv.ParseUint(encoded, 10, 64)
		if err != nil || value < 2 || strconv.FormatUint(value, 10) != encoded {
			return nil, fmt.Errorf("native_parameters.%s_moduli[%d]=%q is not a canonical decimal uint64 modulus", name, index, encoded)
		}
		bitLength := uint32(bits.Len64(value))
		recomputed[index] = bitLength
		if declared[index] != bitLength {
			return nil, fmt.Errorf("native_parameters.%s_moduli_bit_lengths[%d]=%d, recomputed %d", name, index, declared[index], bitLength)
		}
		if expected[index] != bitLength {
			return nil, fmt.Errorf("native_parameters.%s_moduli_bit_lengths[%d]=%d, want backend profile %d", name, index, bitLength, expected[index])
		}
		product.Mul(product, new(big.Int).SetUint64(value))
	}
	if got := uint32(product.BitLen()); got != wantAggregate {
		return nil, fmt.Errorf("native_parameters.%s_moduli product bit length=%d, want parameters.%s_log2_aggregate=%d", name, got, name, wantAggregate)
	}
	return recomputed, nil
}

func nativeProfileFor(source string) (expectedNativeParameters, error) {
	common := expectedNativeParameters{
		mainSecretDistribution:      "balanced-sparse-ternary",
		ephemeralSecretDistribution: "balanced-sparse-ternary",
	}
	switch source {
	case FocusedOpenFHESource:
		common.errorSampler = "openfhe-dgg"
		common.errorSigma = 3.19
		common.errorEffectiveIntegerBound = 39
		common.keySwitchTechnique = "openfhe-hybrid"
		common.securitySelector = "HEStd_128_classic"
		common.securityEvidence = "openfhe-he-standard-ternary-table"
		common.qModuliBitLengths = []uint32{44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 43, 44, 44, 44, 43, 44}
		common.pModuliBitLengths = []uint32{50, 50, 50, 50, 50, 50, 50}
		return common, nil
	case FocusedLattigoSource:
		bound := 39.0
		common.mainSecretDistribution = "fixed-h-symmetric-sparse-ternary"
		common.ephemeralSecretDistribution = "fixed-h-symmetric-sparse-ternary"
		common.errorSampler = "lattigo-bounded-discrete-gaussian"
		common.errorSigma = 3.19
		common.errorConfiguredBound = &bound
		common.errorEffectiveIntegerBound = 39
		common.keySwitchTechnique = "lattigo-rns-qp-gadget"
		common.securitySelector = "external-estimator"
		common.securityEvidence = "full-packed-profile-not-assessed"
		common.qModuliBitLengths = []uint32{44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 43, 44, 44, 44, 43, 44}
		common.pModuliBitLengths = []uint32{50, 50, 50, 50, 50, 50, 50}
		return common, nil
	default:
		return expectedNativeParameters{}, fmt.Errorf(
			"native_parameters cannot validate implementation=%q; want %q or %q",
			source, FocusedOpenFHESource, FocusedLattigoSource,
		)
	}
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
	if result.FirstOperation.PackingSlots != legacyRouteBSlots {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: PackingSlots=%d, want %d", result.FirstOperation.PackingSlots, legacyRouteBSlots)
	}
	if result.FirstOperation.WordBits != canonicalWordBits {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: WordBits=%d, want %d", result.FirstOperation.WordBits, canonicalWordBits)
	}
	if result.FirstOperation.WordCapacity != legacyRouteBWords {
		return Measurement{}, fmt.Errorf("parse Lattigo Route-B JSON: WordCapacity=%d, want %d", result.FirstOperation.WordCapacity, legacyRouteBWords)
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
