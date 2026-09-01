package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureeval"
)

const (
	summarySchema = "lcpdte-route-b-signed8-radix4-benchmark-summary-v1"
	binarySchema  = "lcpdte-route-b-signed8-same-feature-binary-result-v1"
	radixSchema   = "lcpdte-route-b-signed8-radix4-result-v1"
)

type binaryEnvelope struct {
	Schema      string                                                   `json:"schema"`
	CompletedAt time.Time                                                `json:"completed_at"`
	Result      secureeval.RouteBCanonicalSigned8SameFeatureBinaryResult `json:"result"`
}

type radixEnvelope struct {
	Schema      string                                        `json:"schema"`
	CompletedAt time.Time                                     `json:"completed_at"`
	Result      secureeval.RouteBCanonicalSigned8Radix4Result `json:"result"`
}

type observation struct {
	Arm                         string  `json:"arm"`
	Run                         int     `json:"run"`
	RelativePath                string  `json:"relative_path"`
	FileBytes                   uint64  `json:"file_bytes"`
	FileSHA256                  string  `json:"file_sha256"`
	CompletedAt                 string  `json:"completed_at"`
	BuildWallNanoseconds        uint64  `json:"build_wall_nanoseconds"`
	SetupWallNanoseconds        uint64  `json:"setup_wall_nanoseconds"`
	CommonPrefixWallNanoseconds uint64  `json:"common_prefix_wall_nanoseconds"`
	TerminalWallNanoseconds     uint64  `json:"terminal_wall_nanoseconds"`
	CircuitWallNanoseconds      uint64  `json:"circuit_wall_nanoseconds"`
	TotalWallNanoseconds        uint64  `json:"total_wall_nanoseconds"`
	PeakRSSBytes                uint64  `json:"peak_rss_bytes"`
	CircuitQueriesPerSecond     float64 `json:"circuit_queries_per_second"`
	LifecycleQueriesPerSecond   float64 `json:"lifecycle_queries_per_second"`
	InputCiphertextBytes        uint64  `json:"input_ciphertext_serialized_bytes"`
	OutputCiphertextBytes       uint64  `json:"output_ciphertext_serialized_bytes"`
	EvaluationKeyBytes          uint64  `json:"evaluation_key_serialized_bytes"`
	DFTArtifactBytes            uint64  `json:"dft_artifact_encoded_bytes"`
	ActiveMismatchCount         uint64  `json:"active_mismatch_count"`
	InactiveMismatchCount       uint64  `json:"inactive_mismatch_count"`
	EquivalenceMismatchCount    uint64  `json:"equivalence_mismatch_count"`
}

type distribution struct {
	Count          int     `json:"count"`
	Minimum        float64 `json:"minimum"`
	Q1             float64 `json:"q1_type7"`
	Median         float64 `json:"median_type7"`
	Q3             float64 `json:"q3_type7"`
	Maximum        float64 `json:"maximum"`
	IQR            float64 `json:"iqr"`
	IQRToMedian    float64 `json:"iqr_to_median"`
	ArithmeticMean float64 `json:"arithmetic_mean"`
}

type armSummary struct {
	Arm     string                  `json:"arm"`
	Metrics map[string]distribution `json:"metrics"`
}

type medianComparison struct {
	Metric                 string  `json:"metric"`
	BinaryMedian           float64 `json:"binary_median"`
	Radix4Median           float64 `json:"radix4_median"`
	BinaryMinusRadix4      float64 `json:"binary_minus_radix4"`
	Radix4ReductionPercent float64 `json:"radix4_reduction_percent"`
	Radix4ToBinaryRatio    float64 `json:"radix4_to_binary_ratio"`
}

type pairDelta struct {
	Run                        int   `json:"run"`
	CircuitBinaryMinusRadix4NS int64 `json:"circuit_binary_minus_radix4_ns"`
	TotalBinaryMinusRadix4NS   int64 `json:"total_binary_minus_radix4_ns"`
	PeakBinaryMinusRadix4Bytes int64 `json:"peak_binary_minus_radix4_bytes"`
}

type operationAblation struct {
	BinaryOutputLevel              int `json:"binary_output_level"`
	Radix4OutputLevel              int `json:"radix4_output_level"`
	LevelsSaved                    int `json:"levels_saved"`
	CiphertextProductsRemoved      int `json:"ciphertext_products_removed"`
	RelinearizationsRemoved        int `json:"relinearizations_removed"`
	PathRescalesRemoved            int `json:"path_rescales_removed"`
	SelectorComplementsRemoved     int `json:"selector_complements_removed"`
	PathCiphertextAdditionsRemoved int `json:"path_ciphertext_additions_removed"`
	BinaryLogicalPeakWrappers      int `json:"binary_logical_peak_wrapper_ciphertexts"`
	Radix4LogicalPeakWrappers      int `json:"radix4_logical_peak_wrapper_ciphertexts"`
}

type orderStratumSummary struct {
	Order                    string       `json:"order"`
	Runs                     []int        `json:"runs"`
	CircuitBinaryMinusRadix4 distribution `json:"circuit_binary_minus_radix4_nanoseconds"`
	TotalBinaryMinusRadix4   distribution `json:"total_binary_minus_radix4_nanoseconds"`
}

type timingDecision struct {
	AggregateCircuitBinaryMinusRadix4 distribution          `json:"aggregate_circuit_binary_minus_radix4_nanoseconds"`
	AggregateTotalBinaryMinusRadix4   distribution          `json:"aggregate_total_binary_minus_radix4_nanoseconds"`
	OrderStrata                       []orderStratumSummary `json:"order_strata,omitempty"`
	RegisteredCriteriaPassed          bool                  `json:"registered_criteria_passed"`
	Decision                          string                `json:"decision"`
}

type benchmarkSummary struct {
	Schema                         string             `json:"schema"`
	Design                         string             `json:"design"`
	GeneratedAt                    string             `json:"generated_at"`
	QuantileMethod                 string             `json:"quantile_method"`
	RepetitionsPerArm              int                `json:"repetitions_per_arm"`
	WarmupsPerArm                  int                `json:"warmups_per_arm"`
	WarmupsExcluded                bool               `json:"warmups_excluded"`
	InitialRepetitionsPerArm       int                `json:"initial_repetitions_per_arm"`
	ExtensionTriggerThreshold      float64            `json:"extension_trigger_threshold"`
	ExtensionTriggered             bool               `json:"extension_triggered"`
	ExtensionCompleted             bool               `json:"extension_completed"`
	TriggerMetrics                 []string           `json:"trigger_metrics"`
	Observations                   []observation      `json:"observations"`
	Arms                           []armSummary       `json:"arms"`
	MedianComparisons              []medianComparison `json:"median_comparisons"`
	PairDeltas                     []pairDelta        `json:"pair_deltas"`
	PairsRadix4FasterCircuit       int                `json:"pairs_radix4_faster_circuit"`
	PairsRadix4FasterTotal         int                `json:"pairs_radix4_faster_total"`
	MedianLatencyAndPeakParetoGain bool               `json:"median_latency_and_peak_pareto_gain"`
	Ablation                       operationAblation  `json:"operation_ablation"`
	TimingDecision                 timingDecision     `json:"timing_decision"`
	SerializedSizeInterpretation   string             `json:"serialized_size_interpretation"`
	UnmeasuredSerializedMaterial   string             `json:"unmeasured_serialized_material"`
	ExecutionOrder                 string             `json:"execution_order"`
	TimingInferenceBoundary        string             `json:"timing_inference_boundary"`
	ArtifactManifestDigest         string             `json:"artifact_manifest_digest"`
	SummaryDigest                  string             `json:"summary_digest"`
}

func main() {
	directory := flag.String("dir", "", "benchmark artifact directory")
	output := flag.String("out", "", "new JSON summary path")
	design := flag.String("design", "fixed-ab", "fixed-ab or counterbalanced")
	repetitions := flag.Int("repetitions", 0, "number of measured runs per arm; zero auto-detects")
	flag.Parse()
	if *directory == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "summarize-route-b-radix4-benchmark: -dir and -out are required")
		os.Exit(2)
	}
	summary, err := summarize(*directory, *design, *repetitions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "summarize-route-b-radix4-benchmark: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "summarize-route-b-radix4-benchmark: encode: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	absolute, err := filepath.Abs(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "summarize-route-b-radix4-benchmark: output path: %v\n", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "summarize-route-b-radix4-benchmark: output directory: %v\n", err)
		os.Exit(1)
	}
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "summarize-route-b-radix4-benchmark: create without overwrite: %v\n", err)
		os.Exit(1)
	}
	if _, err = file.Write(encoded); err != nil {
		_ = file.Close()
		fmt.Fprintf(os.Stderr, "summarize-route-b-radix4-benchmark: write: %v\n", err)
		os.Exit(1)
	}
	if err = file.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "summarize-route-b-radix4-benchmark: close: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ROUTE_B_RADIX4_BENCHMARK_SUMMARY_OK path=%s repetitions=%d trigger=%t circuit_pairs=%d total_pairs=%d digest=%s\n",
		absolute, summary.RepetitionsPerArm, summary.ExtensionTriggered,
		summary.PairsRadix4FasterCircuit, summary.PairsRadix4FasterTotal, summary.SummaryDigest)
}

func summarize(directory, design string, requestedRepetitions int) (benchmarkSummary, error) {
	absoluteDirectory, err := filepath.Abs(directory)
	if err != nil {
		return benchmarkSummary{}, err
	}
	if design != "fixed-ab" && design != "counterbalanced" {
		return benchmarkSummary{}, fmt.Errorf("unsupported design %q", design)
	}
	available := 0
	for run := 1; run <= 16; run++ {
		binaryExists, binaryErr := fileExists(filepath.Join(absoluteDirectory, fmt.Sprintf("binary_run_%02d.json", run)))
		radixExists, radixErr := fileExists(filepath.Join(absoluteDirectory, fmt.Sprintf("radix4_run_%02d.json", run)))
		if binaryErr != nil || radixErr != nil {
			return benchmarkSummary{}, errors.Join(binaryErr, radixErr)
		}
		if binaryExists != radixExists {
			return benchmarkSummary{}, fmt.Errorf("run %02d is present for only one arm", run)
		}
		if !binaryExists {
			break
		}
		available = run
	}
	repetitions := requestedRepetitions
	if repetitions == 0 {
		repetitions = available
	}
	if repetitions <= 0 || repetitions > available {
		return benchmarkSummary{}, fmt.Errorf("requested repetitions=%d, available=%d", repetitions, available)
	}
	observations := make([]observation, 0, 2*repetitions)
	manifestHash := sha256.New()
	for run := 1; run <= repetitions; run++ {
		binaryPath := filepath.Join(absoluteDirectory, fmt.Sprintf("binary_run_%02d.json", run))
		binary, err := loadBinary(binaryPath, absoluteDirectory, run)
		if err != nil {
			return benchmarkSummary{}, err
		}
		radixPath := filepath.Join(absoluteDirectory, fmt.Sprintf("radix4_run_%02d.json", run))
		radix, err := loadRadix(radixPath, absoluteDirectory, run)
		if err != nil {
			return benchmarkSummary{}, err
		}
		observations = append(observations, binary, radix)
		for _, item := range []observation{binary, radix} {
			_, _ = manifestHash.Write([]byte(item.RelativePath))
			_, _ = manifestHash.Write([]byte{0})
			_, _ = manifestHash.Write([]byte(item.FileSHA256))
			_, _ = manifestHash.Write([]byte{'\n'})
		}
	}
	binaryObservations, radixObservations := selectArm(observations, "binary"), selectArm(observations, "radix4")
	binarySummary := summarizeArm("binary", binaryObservations)
	radixSummary := summarizeArm("radix4", radixObservations)
	initialRepetitions, extendedRepetitions := 7, 15
	if design == "counterbalanced" {
		initialRepetitions, extendedRepetitions = 8, 16
	}
	if repetitions != initialRepetitions && repetitions != extendedRepetitions {
		return benchmarkSummary{}, fmt.Errorf("design %s admits %d or %d repetitions, got %d", design, initialRepetitions, extendedRepetitions, repetitions)
	}
	initialBinarySummary := summarizeArm("binary", binaryObservations[:initialRepetitions])
	initialRadixSummary := summarizeArm("radix4", radixObservations[:initialRepetitions])
	triggerMetrics := []string{"circuit_wall_nanoseconds", "total_wall_nanoseconds"}
	triggered := false
	for _, metric := range triggerMetrics {
		if initialBinarySummary.Metrics[metric].IQRToMedian > 0.10 || initialRadixSummary.Metrics[metric].IQRToMedian > 0.10 {
			triggered = true
		}
	}
	if triggered && repetitions != extendedRepetitions {
		return benchmarkSummary{}, fmt.Errorf("extension trigger fired but only %d repetitions were selected", repetitions)
	}
	if !triggered && repetitions != initialRepetitions {
		return benchmarkSummary{}, fmt.Errorf("extension did not trigger but %d repetitions were selected", repetitions)
	}
	comparisons := make([]medianComparison, 0, len(binarySummary.Metrics))
	metricNames := make([]string, 0, len(binarySummary.Metrics))
	for metric := range binarySummary.Metrics {
		metricNames = append(metricNames, metric)
	}
	sort.Strings(metricNames)
	for _, metric := range metricNames {
		binaryMedian := binarySummary.Metrics[metric].Median
		radixMedian := radixSummary.Metrics[metric].Median
		comparisons = append(comparisons, medianComparison{
			Metric: metric, BinaryMedian: binaryMedian, Radix4Median: radixMedian,
			BinaryMinusRadix4:      binaryMedian - radixMedian,
			Radix4ReductionPercent: 100 * (binaryMedian - radixMedian) / binaryMedian,
			Radix4ToBinaryRatio:    radixMedian / binaryMedian,
		})
	}
	pairs := make([]pairDelta, repetitions)
	fasterCircuit, fasterTotal := 0, 0
	for index := range pairs {
		binary, radix := binaryObservations[index], radixObservations[index]
		pairs[index] = pairDelta{
			Run:                        index + 1,
			CircuitBinaryMinusRadix4NS: int64(binary.CircuitWallNanoseconds) - int64(radix.CircuitWallNanoseconds),
			TotalBinaryMinusRadix4NS:   int64(binary.TotalWallNanoseconds) - int64(radix.TotalWallNanoseconds),
			PeakBinaryMinusRadix4Bytes: int64(binary.PeakRSSBytes) - int64(radix.PeakRSSBytes),
		}
		if pairs[index].CircuitBinaryMinusRadix4NS > 0 {
			fasterCircuit++
		}
		if pairs[index].TotalBinaryMinusRadix4NS > 0 {
			fasterTotal++
		}
	}
	decision := summarizeTimingDecision(pairs, design)
	executionOrder := "within every pair the binary process ran first and the radix4 process ran second"
	inferenceBoundary := "fresh-process descriptive comparison; fixed AB order can confound paired timing, so operation-count savings are causal but timing deltas are not treated as an order-randomized estimate"
	if design == "counterbalanced" {
		executionOrder = "odd pairs ran radix4 then binary; even pairs ran binary then radix4"
		inferenceBoundary = "fresh-process order-balanced paired confirmation; timing applies to this host and workload, while exact operation-count savings are implementation-graph identities"
	}
	summary := benchmarkSummary{
		Schema: summarySchema, Design: design, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		QuantileMethod:    "Hyndman-Fan type 7: h=(n-1)p+1 with linear interpolation",
		RepetitionsPerArm: repetitions, WarmupsPerArm: 1, WarmupsExcluded: true, InitialRepetitionsPerArm: initialRepetitions,
		ExtensionTriggerThreshold: 0.10, ExtensionTriggered: triggered,
		ExtensionCompleted: triggered && repetitions == extendedRepetitions, TriggerMetrics: triggerMetrics,
		Observations: observations, Arms: []armSummary{binarySummary, radixSummary},
		MedianComparisons: comparisons, PairDeltas: pairs,
		PairsRadix4FasterCircuit: fasterCircuit, PairsRadix4FasterTotal: fasterTotal,
		MedianLatencyAndPeakParetoGain: radixSummary.Metrics["circuit_wall_nanoseconds"].Median < binarySummary.Metrics["circuit_wall_nanoseconds"].Median &&
			radixSummary.Metrics["total_wall_nanoseconds"].Median < binarySummary.Metrics["total_wall_nanoseconds"].Median &&
			radixSummary.Metrics["peak_rss_bytes"].Median < binarySummary.Metrics["peak_rss_bytes"].Median,
		Ablation: operationAblation{
			BinaryOutputLevel: 0, Radix4OutputLevel: 1, LevelsSaved: 1,
			CiphertextProductsRemoved: 3, RelinearizationsRemoved: 3, PathRescalesRemoved: 3,
			SelectorComplementsRemoved: 2, PathCiphertextAdditionsRemoved: 1,
			BinaryLogicalPeakWrappers: 16, Radix4LogicalPeakWrappers: 10,
		},
		TimingDecision:               decision,
		SerializedSizeInterpretation: "allocation-free Lattigo BinarySize counters; sizes are serialization capacities, not observed traffic",
		UnmeasuredSerializedMaterial: "public-model plaintext artifacts other than encoded STC/CTS DFT records are not included",
		ExecutionOrder:               executionOrder, TimingInferenceBoundary: inferenceBoundary,
		ArtifactManifestDigest: hex.EncodeToString(manifestHash.Sum(nil)),
	}
	digestCopy := summary
	digestCopy.GeneratedAt = ""
	digestCopy.SummaryDigest = ""
	payload, err := json.Marshal(digestCopy)
	if err != nil {
		return benchmarkSummary{}, err
	}
	digest := sha256.Sum256(payload)
	summary.SummaryDigest = hex.EncodeToString(digest[:])
	return summary, nil
}

func loadBinary(path, root string, run int) (observation, error) {
	payload, fileDigest, relative, err := readArtifact(path, root)
	if err != nil {
		return observation{}, err
	}
	var envelope binaryEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		return observation{}, fmt.Errorf("%s: %w", path, err)
	}
	if envelope.Schema != binarySchema || envelope.CompletedAt.IsZero() {
		return observation{}, fmt.Errorf("%s: binary envelope identity changed", path)
	}
	if err = envelope.Result.Validate(); err != nil {
		return observation{}, fmt.Errorf("%s: %w", path, err)
	}
	result := envelope.Result
	return newObservation("binary", run, relative, payload, fileDigest, envelope.CompletedAt,
		result.BuildReceipt.BuildWallNanoseconds, result.SameFeatureBinary.CommonPrefixWallNanoseconds,
		result.SameFeatureBinary.TerminalWallNanoseconds, result.SameFeatureBinary.WallNanoseconds,
		result.TotalWallNanoseconds, result.PostBinaryPeakRSSBytes, result.QueryCount,
		result.InputCiphertextSerializedBytes, result.OutputCiphertextSerializedBytes,
		result.EvaluationKeySerializedBytes, result.DFTArtifactEncodedBytes,
		result.ActiveMismatchCount, result.InactiveMismatchCount, result.BinaryEquivalenceMismatchCount)
}

func loadRadix(path, root string, run int) (observation, error) {
	payload, fileDigest, relative, err := readArtifact(path, root)
	if err != nil {
		return observation{}, err
	}
	var envelope radixEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		return observation{}, fmt.Errorf("%s: %w", path, err)
	}
	if envelope.Schema != radixSchema || envelope.CompletedAt.IsZero() {
		return observation{}, fmt.Errorf("%s: radix envelope identity changed", path)
	}
	if err = envelope.Result.Validate(); err != nil {
		return observation{}, fmt.Errorf("%s: %w", path, err)
	}
	result := envelope.Result
	return newObservation("radix4", run, relative, payload, fileDigest, envelope.CompletedAt,
		result.BuildReceipt.BuildWallNanoseconds, result.Radix4.CommonPrefixWallNanoseconds,
		result.Radix4.TerminalWallNanoseconds, result.Radix4.WallNanoseconds,
		result.TotalWallNanoseconds, result.PostRadixPeakRSSBytes, result.QueryCount,
		result.InputCiphertextSerializedBytes, result.OutputCiphertextSerializedBytes,
		result.EvaluationKeySerializedBytes, result.DFTArtifactEncodedBytes,
		result.ActiveMismatchCount, result.InactiveMismatchCount, result.BinaryEquivalenceMismatchCount)
}

func newObservation(
	arm string, run int, relative string, payload []byte, fileDigest string, completedAt time.Time,
	build, prefix, terminal, circuit, total, peak uint64, queries uint32,
	inputBytes, outputBytes, keyBytes, dftBytes, active, inactive, equivalence uint64,
) (observation, error) {
	if circuit == 0 || total < circuit || queries == 0 || inputBytes == 0 || outputBytes == 0 || keyBytes == 0 || dftBytes == 0 ||
		active != 0 || inactive != 0 || equivalence != 0 {
		return observation{}, fmt.Errorf("%s run %d has incomplete timing, size, or correctness evidence", arm, run)
	}
	return observation{
		Arm: arm, Run: run, RelativePath: filepath.ToSlash(relative), FileBytes: uint64(len(payload)), FileSHA256: fileDigest,
		CompletedAt: completedAt.UTC().Format(time.RFC3339Nano), BuildWallNanoseconds: build,
		SetupWallNanoseconds: total - circuit, CommonPrefixWallNanoseconds: prefix,
		TerminalWallNanoseconds: terminal, CircuitWallNanoseconds: circuit, TotalWallNanoseconds: total,
		PeakRSSBytes: peak, CircuitQueriesPerSecond: float64(queries) * 1e9 / float64(circuit),
		LifecycleQueriesPerSecond: float64(queries) * 1e9 / float64(total),
		InputCiphertextBytes:      inputBytes, OutputCiphertextBytes: outputBytes,
		EvaluationKeyBytes: keyBytes, DFTArtifactBytes: dftBytes,
		ActiveMismatchCount: active, InactiveMismatchCount: inactive, EquivalenceMismatchCount: equivalence,
	}, nil
}

func readArtifact(path, root string) ([]byte, string, string, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, "", "", err
	}
	digest := sha256.Sum256(payload)
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return nil, "", "", err
	}
	return payload, hex.EncodeToString(digest[:]), relative, nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func summarizeTimingDecision(pairs []pairDelta, design string) timingDecision {
	allCircuit := make([]float64, len(pairs))
	allTotal := make([]float64, len(pairs))
	for index, pair := range pairs {
		allCircuit[index] = float64(pair.CircuitBinaryMinusRadix4NS)
		allTotal[index] = float64(pair.TotalBinaryMinusRadix4NS)
	}
	decision := timingDecision{
		AggregateCircuitBinaryMinusRadix4: summarizeDistribution(allCircuit),
		AggregateTotalBinaryMinusRadix4:   summarizeDistribution(allTotal),
		Decision:                          "DESCRIPTIVE_ORDER_CONFOUNDED",
	}
	if design != "counterbalanced" {
		return decision
	}
	strata := []struct {
		name   string
		parity int
	}{
		{name: "radix4-first", parity: 1},
		{name: "binary-first", parity: 0},
	}
	passed := decision.AggregateCircuitBinaryMinusRadix4.Median > 0 &&
		decision.AggregateTotalBinaryMinusRadix4.Median > 0
	for _, stratum := range strata {
		runs := make([]int, 0, len(pairs)/2)
		circuit := make([]float64, 0, len(pairs)/2)
		total := make([]float64, 0, len(pairs)/2)
		for _, pair := range pairs {
			if pair.Run%2 == stratum.parity {
				runs = append(runs, pair.Run)
				circuit = append(circuit, float64(pair.CircuitBinaryMinusRadix4NS))
				total = append(total, float64(pair.TotalBinaryMinusRadix4NS))
			}
		}
		item := orderStratumSummary{
			Order: stratum.name, Runs: runs,
			CircuitBinaryMinusRadix4: summarizeDistribution(circuit),
			TotalBinaryMinusRadix4:   summarizeDistribution(total),
		}
		decision.OrderStrata = append(decision.OrderStrata, item)
		passed = passed && item.CircuitBinaryMinusRadix4.Median > 0 && item.TotalBinaryMinusRadix4.Median > 0
	}
	decision.RegisteredCriteriaPassed = passed
	decision.Decision = "INCONCLUSIVE"
	if passed {
		decision.Decision = "PASS"
	}
	return decision
}

func selectArm(observations []observation, arm string) []observation {
	selected := make([]observation, 0, len(observations)/2)
	for _, item := range observations {
		if item.Arm == arm {
			selected = append(selected, item)
		}
	}
	return selected
}

func summarizeArm(arm string, observations []observation) armSummary {
	metricValues := map[string][]float64{
		"build_wall_nanoseconds": {}, "setup_wall_nanoseconds": {}, "common_prefix_wall_nanoseconds": {},
		"terminal_wall_nanoseconds": {}, "circuit_wall_nanoseconds": {}, "total_wall_nanoseconds": {},
		"peak_rss_bytes": {}, "circuit_queries_per_second": {}, "lifecycle_queries_per_second": {},
		"input_ciphertext_serialized_bytes": {}, "output_ciphertext_serialized_bytes": {},
		"evaluation_key_serialized_bytes": {}, "dft_artifact_encoded_bytes": {},
	}
	for _, item := range observations {
		metricValues["build_wall_nanoseconds"] = append(metricValues["build_wall_nanoseconds"], float64(item.BuildWallNanoseconds))
		metricValues["setup_wall_nanoseconds"] = append(metricValues["setup_wall_nanoseconds"], float64(item.SetupWallNanoseconds))
		metricValues["common_prefix_wall_nanoseconds"] = append(metricValues["common_prefix_wall_nanoseconds"], float64(item.CommonPrefixWallNanoseconds))
		metricValues["terminal_wall_nanoseconds"] = append(metricValues["terminal_wall_nanoseconds"], float64(item.TerminalWallNanoseconds))
		metricValues["circuit_wall_nanoseconds"] = append(metricValues["circuit_wall_nanoseconds"], float64(item.CircuitWallNanoseconds))
		metricValues["total_wall_nanoseconds"] = append(metricValues["total_wall_nanoseconds"], float64(item.TotalWallNanoseconds))
		metricValues["peak_rss_bytes"] = append(metricValues["peak_rss_bytes"], float64(item.PeakRSSBytes))
		metricValues["circuit_queries_per_second"] = append(metricValues["circuit_queries_per_second"], item.CircuitQueriesPerSecond)
		metricValues["lifecycle_queries_per_second"] = append(metricValues["lifecycle_queries_per_second"], item.LifecycleQueriesPerSecond)
		metricValues["input_ciphertext_serialized_bytes"] = append(metricValues["input_ciphertext_serialized_bytes"], float64(item.InputCiphertextBytes))
		metricValues["output_ciphertext_serialized_bytes"] = append(metricValues["output_ciphertext_serialized_bytes"], float64(item.OutputCiphertextBytes))
		metricValues["evaluation_key_serialized_bytes"] = append(metricValues["evaluation_key_serialized_bytes"], float64(item.EvaluationKeyBytes))
		metricValues["dft_artifact_encoded_bytes"] = append(metricValues["dft_artifact_encoded_bytes"], float64(item.DFTArtifactBytes))
	}
	metrics := make(map[string]distribution, len(metricValues))
	for name, values := range metricValues {
		metrics[name] = summarizeDistribution(values)
	}
	return armSummary{Arm: arm, Metrics: metrics}
}

func summarizeDistribution(values []float64) distribution {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mean := 0.0
	for _, value := range sorted {
		mean += value
	}
	mean /= float64(len(sorted))
	q1, median, q3 := type7Quantile(sorted, 0.25), type7Quantile(sorted, 0.5), type7Quantile(sorted, 0.75)
	iqrRatio := 0.0
	if median != 0 {
		iqrRatio = (q3 - q1) / math.Abs(median)
	}
	return distribution{
		Count: len(sorted), Minimum: sorted[0], Q1: q1, Median: median, Q3: q3, Maximum: sorted[len(sorted)-1],
		IQR: q3 - q1, IQRToMedian: iqrRatio, ArithmeticMean: mean,
	}
}

func type7Quantile(sorted []float64, probability float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	h := float64(len(sorted)-1)*probability + 1
	j := int(math.Floor(h))
	g := h - float64(j)
	if j >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	return sorted[j-1] + g*(sorted[j]-sorted[j-1])
}
