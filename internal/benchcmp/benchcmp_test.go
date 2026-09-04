package benchcmp_test

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strconv"
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
	got, err := benchcmp.ParseCanonical(strings.NewReader(canonicalArtifactJSON(benchcmp.FocusedOpenFHESource, []uint64{
		9_000_000_000, 11_000_000_000, 10_000_000_000, 12_000_000_000, 8_000_000_000,
	})), "openfhe.json")
	if err != nil {
		t.Fatal(err)
	}

	if got.Source != benchcmp.FocusedOpenFHESource || got.Provenance != "openfhe.json" {
		t.Fatalf("identity=%+v", got)
	}
	if got.EncryptionMode != "public-key" || got.FactorStorageMode != "resident-precomputed" ||
		got.ScaleSchedule != "openfhe-flexiblemanual-native" || got.BackendBSGSPlan != "openfhe-auto-dim1-0" ||
		got.SourceRevision != "08f1eb87434e7be072cba889270a8400bbffc08e" || got.SourceModified ||
		got.Runtime != benchcmp.OpenFHERuntime || got.Compiler == "" || got.BuildProfile != benchcmp.OpenFHEBuildProfile ||
		got.OS != "linux" || got.Arch != "amd64" {
		t.Fatalf("execution metadata=%+v", got)
	}
	if got.A2BMeanNanoseconds != 10_000_000_000 || got.A2BMedianNanoseconds != 10_000_000_000 {
		t.Fatalf("aggregates=%+v", got)
	}
	if math.Abs(got.EffectiveWordsPerSecond-819.2) > 1e-12 {
		t.Fatalf("words/s=%.12f", got.EffectiveWordsPerSecond)
	}
	if got.Repeats != 5 || got.VerifiedEvaluations != 5 || len(got.TimedSamplesNanoseconds) != 5 {
		t.Fatalf("sample protocol=%+v", got)
	}
}

func TestCanonicalV3RequiresNativeParameterEvidence(t *testing.T) {
	if benchcmp.CanonicalBenchmarkSchema != "lcpdte-ckksint-a2b-benchmark-v3" {
		t.Fatalf("schema=%q", benchcmp.CanonicalBenchmarkSchema)
	}
	payload := canonicalArtifactJSON("gao-openfhe-a2b-full", canonicalSamples())
	var document map[string]any
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "native_parameters")
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = benchcmp.ParseCanonical(bytes.NewReader(encoded), "missing-native.json"); err == nil ||
		!strings.Contains(err.Error(), "native_parameters") {
		t.Fatalf("error=%v, want required native_parameters", err)
	}
}

func TestCanonicalV3RequiresMismatchCount(t *testing.T) {
	payload := canonicalArtifactJSON(benchcmp.FocusedOpenFHESource, canonicalSamples())
	var document map[string]any
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "mismatch_count")
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = benchcmp.ParseCanonical(bytes.NewReader(encoded), "missing-mismatch-count.json"); err == nil ||
		!strings.Contains(err.Error(), "mismatch_count is required") {
		t.Fatalf("error=%v, want required mismatch_count", err)
	}
}

func TestParseCanonicalRequiresZeroValuedSharedParameterFields(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal([]byte(canonicalArtifactJSON(benchcmp.FocusedOpenFHESource, canonicalSamples())), &document); err != nil {
		t.Fatal(err)
	}
	parameters := document["parameters"].(map[string]any)
	delete(parameters, "base_two_decomposition")
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = benchcmp.ParseCanonical(bytes.NewReader(payload), "missing-base-two.json"); err == nil ||
		!strings.Contains(err.Error(), "parameters.base_two_decomposition is required") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseCanonicalRequiresEveryNativeParameterField(t *testing.T) {
	fields := []string{
		"actual_first_q_modulus_bits",
		"main_secret_distribution", "main_secret_hamming_weight",
		"ephemeral_secret_distribution", "ephemeral_secret_hamming_weight",
		"error_sampler", "error_sigma", "error_configured_bound", "error_effective_integer_bound",
		"key_switch_technique", "key_switch_rns_decomposition_components", "key_switch_base_two_decomposition",
		"security_selector", "security_evidence",
		"q_moduli", "q_moduli_bit_lengths", "p_moduli", "p_moduli_bit_lengths",
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			payload := mutateCanonicalNative(t, benchcmp.FocusedOpenFHESource, func(native map[string]any) {
				delete(native, field)
			})
			_, err := benchcmp.ParseCanonical(bytes.NewReader(payload), "missing-native-field.json")
			if err == nil || !strings.Contains(err.Error(), "native_parameters."+field+" is required") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestParseCanonicalRejectsForgedNativeParameterProfile(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value any
		want  string
	}{
		{name: "main distribution", field: "main_secret_distribution", value: "uniform-ternary", want: "main_secret_distribution"},
		{name: "main weight", field: "main_secret_hamming_weight", value: 191, want: "main_secret_hamming_weight"},
		{name: "ephemeral distribution", field: "ephemeral_secret_distribution", value: "uniform-ternary", want: "ephemeral_secret_distribution"},
		{name: "ephemeral weight", field: "ephemeral_secret_hamming_weight", value: 31, want: "ephemeral_secret_hamming_weight"},
		{name: "error sampler", field: "error_sampler", value: "other", want: "error_sampler"},
		{name: "error sigma", field: "error_sigma", value: 3.2, want: "error_sigma"},
		{name: "configured bound", field: "error_configured_bound", value: 19.2, want: "error_configured_bound"},
		{name: "effective bound", field: "error_effective_integer_bound", value: 38, want: "error_effective_integer_bound"},
		{name: "key switch", field: "key_switch_technique", value: "other", want: "key_switch_technique"},
		{name: "RNS components", field: "key_switch_rns_decomposition_components", value: 2, want: "key_switch_rns_decomposition_components"},
		{name: "base two", field: "key_switch_base_two_decomposition", value: 1, want: "key_switch_base_two_decomposition"},
		{name: "security selector", field: "security_selector", value: "other", want: "security_selector"},
		{name: "security evidence", field: "security_evidence", value: "other", want: "security_evidence"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := mutateCanonicalNative(t, benchcmp.FocusedOpenFHESource, func(native map[string]any) {
				native[test.field] = test.value
			})
			_, err := benchcmp.ParseCanonical(bytes.NewReader(payload), "forged-native.json")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestParseCanonicalRecomputesNativeModulusEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "noncanonical decimal",
			mutate: func(native map[string]any) {
				q := native["q_moduli"].([]any)
				q[0] = "0" + q[0].(string)
			},
			want: "canonical decimal uint64",
		},
		{
			name: "uint64 overflow",
			mutate: func(native map[string]any) {
				native["q_moduli"].([]any)[0] = "18446744073709551616"
			},
			want: "canonical decimal uint64",
		},
		{
			name: "declared bit length",
			mutate: func(native map[string]any) {
				native["q_moduli_bit_lengths"].([]any)[0] = float64(43)
			},
			want: "recomputed 44",
		},
		{
			name: "backend bit profile",
			mutate: func(native map[string]any) {
				native["q_moduli"].([]any)[0] = strconv.FormatUint((uint64(1)<<43)-1, 10)
				native["q_moduli_bit_lengths"].([]any)[0] = float64(43)
			},
			want: "backend profile 44",
		},
		{
			name: "actual first Q width",
			mutate: func(native map[string]any) {
				native["actual_first_q_modulus_bits"] = float64(43)
			},
			want: "recomputed q_moduli[0] bit length 44",
		},
		{
			name: "Q product aggregate",
			mutate: func(native map[string]any) {
				q := native["q_moduli"].([]any)
				profile := native["q_moduli_bit_lengths"].([]any)
				for index := range q {
					bitLength := uint32(profile[index].(float64))
					q[index] = strconv.FormatUint(uint64(1)<<(bitLength-1), 10)
				}
			},
			want: "q_moduli product bit length",
		},
		{
			name: "P count",
			mutate: func(native map[string]any) {
				p := native["p_moduli"].([]any)
				native["p_moduli"] = p[:len(p)-1]
			},
			want: "p_moduli count=6",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := mutateCanonicalNative(t, benchcmp.FocusedOpenFHESource, test.mutate)
			_, err := benchcmp.ParseCanonical(bytes.NewReader(payload), "forged-modulus.json")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestParseCanonicalRequiresAcceptanceBuildProfiles(t *testing.T) {
	tests := []struct {
		name           string
		implementation string
		profile        string
		want           string
	}{
		{name: "OpenFHE incomplete release profile", implementation: benchcmp.FocusedOpenFHESource, profile: "CMAKE_BUILD_TYPE=Release;WITH_INTEL_HEXL=ON", want: "build_profile"},
		{name: "Lattigo non-v4 profile", implementation: benchcmp.FocusedLattigoSource, profile: strings.Replace(benchcmp.LattigoAcceptanceBuildProfile, "GOAMD64=v4", "GOAMD64=v3", 1), want: "build_profile"},
		{name: "Lattigo profiled run", implementation: benchcmp.FocusedLattigoSource, profile: strings.Replace(benchcmp.LattigoAcceptanceBuildProfile, "CPU_PROFILE=off", "CPU_PROFILE=on", 1), want: "build_profile"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal([]byte(canonicalArtifactJSON(test.implementation, canonicalSamples())), &document); err != nil {
				t.Fatal(err)
			}
			document["build_profile"] = test.profile
			payload, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = benchcmp.ParseCanonical(bytes.NewReader(payload), "wrong-build.json"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseCanonicalDerivesMedianFromFiveSamples(t *testing.T) {
	got, err := benchcmp.ParseCanonical(
		strings.NewReader(canonicalArtifactJSON("openfhe", []uint64{1, 2, 3, 4, 100})),
		"openfhe.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.A2BMeanNanoseconds != 22 || got.A2BMedianNanoseconds != 3 {
		t.Fatalf("mean=%f median=%f", got.A2BMeanNanoseconds, got.A2BMedianNanoseconds)
	}
}

func TestParseCanonicalRequiresReproducibleExecutionMetadata(t *testing.T) {
	for _, field := range []string{
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
	} {
		t.Run(field, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal([]byte(canonicalArtifactJSON("gao-openfhe-a2b-full", canonicalSamples())), &document); err != nil {
				t.Fatal(err)
			}
			delete(document, field)
			payload, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}

			_, err = benchcmp.ParseCanonical(strings.NewReader(string(payload)), "missing-execution-metadata.json")
			if err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("error=%v, want missing %s", err, field)
			}
		})
	}
}

func TestParseCanonicalRejectsUnreproducibleExecutionMetadata(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		want        string
	}{
		{name: "encryption", old: `"encryption_mode":"public-key"`, replacement: `"encryption_mode":"secret-key"`, want: "encryption_mode"},
		{name: "OpenFHE factor storage", old: `"factor_storage_mode":"resident-precomputed"`, replacement: `"factor_storage_mode":"streamed"`, want: "factor_storage_mode"},
		{name: "OpenFHE scale schedule", old: `"scale_schedule":"openfhe-flexiblemanual-native"`, replacement: `"scale_schedule":"synthetic-shared"`, want: "scale_schedule"},
		{name: "OpenFHE BSGS plan", old: `"backend_bsgs_plan":"openfhe-auto-dim1-0"`, replacement: `"backend_bsgs_plan":"openfhe-explicit-dim1-1"`, want: "backend_bsgs_plan"},
		{name: "OpenFHE pinned revision", old: `"source_revision":"08f1eb87434e7be072cba889270a8400bbffc08e"`, replacement: `"source_revision":"other"`, want: "source_revision"},
		{name: "modified source", old: `"source_modified":false`, replacement: `"source_modified":true`, want: "source_modified"},
		{name: "runtime", old: `"runtime":"` + benchcmp.OpenFHERuntime + `"`, replacement: `"runtime":"other-openfhe-runtime"`, want: "runtime"},
		{name: "compiler", old: `"compiler":"/usr/bin/clang++ :: Ubuntu clang version 14.0.0-1ubuntu1.1"`, replacement: `"compiler":""`, want: "compiler"},
		{name: "build profile", old: `"build_profile":"` + benchcmp.OpenFHEBuildProfile + `"`, replacement: `"build_profile":"Release"`, want: "build_profile"},
		{name: "os", old: `"os":"linux"`, replacement: `"os":""`, want: "os"},
		{name: "arch", old: `"arch":"amd64"`, replacement: `"arch":""`, want: "arch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			valid := canonicalArtifactJSON("gao-openfhe-a2b-full", canonicalSamples())
			payload := strings.Replace(valid, test.old, test.replacement, 1)
			if payload == valid {
				t.Fatalf("fixture field %q not found", test.old)
			}
			_, err := benchcmp.ParseCanonical(strings.NewReader(payload), "unreproducible.json")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}

	lattigo := canonicalArtifactJSON("lattigo-gao-a2b-full", canonicalSamples())
	lattigo = strings.Replace(lattigo, `"factor_storage_mode":"resident-prevalidated"`, `"factor_storage_mode":"streamed"`, 1)
	if _, err := benchcmp.ParseCanonical(strings.NewReader(lattigo), "lattigo.json"); err == nil || !strings.Contains(err.Error(), "factor_storage_mode") {
		t.Fatalf("Lattigo factor storage error=%v", err)
	}
	lattigo = canonicalArtifactJSON("lattigo-gao-a2b-full", canonicalSamples())
	lattigo = strings.Replace(
		lattigo,
		`"backend_bsgs_plan":"`+benchcmp.LattigoBackendBSGSPlan+`"`,
		`"backend_bsgs_plan":"lattigo-dft-unverified"`,
		1,
	)
	if _, err := benchcmp.ParseCanonical(strings.NewReader(lattigo), "lattigo.json"); err == nil || !strings.Contains(err.Error(), "backend_bsgs_plan") {
		t.Fatalf("Lattigo BSGS plan error=%v", err)
	}
}

func TestParseCanonicalRejectsNullSourceModified(t *testing.T) {
	payload := strings.Replace(
		canonicalArtifactJSON("gao-openfhe-a2b-full", canonicalSamples()),
		`"source_modified":false`,
		`"source_modified":null`,
		1,
	)
	_, err := benchcmp.ParseCanonical(strings.NewReader(payload), "null-source-modified.json")
	if err == nil || !strings.Contains(err.Error(), "source_modified") {
		t.Fatalf("error=%v, want source_modified type rejection", err)
	}
}

func TestParseCanonicalRejectsNonFullOrUnmatchedProtocolShape(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		want        string
	}{
		{name: "protocol", old: `"protocol":"gao-a2b-full-z8-w4-v1"`, replacement: `"protocol":"sparse-route-b"`, want: "protocol"},
		{name: "workload", old: `"workload_id":"uint8-0to255-x32"`, replacement: `"workload_id":"uint8-512"`, want: "workload_id"},
		{name: "packing id", old: `"packing_id":"n65536-cslots32768-zslots8192-w4"`, replacement: `"packing_id":"sparse"`, want: "packing_id"},
		{name: "output shape", old: `"output_container":"two-ciphertexts-low4-high4"`, replacement: `"output_container":"one-ciphertext"`, want: "output_container"},
		{name: "ring dimension", old: `"ring_dimension":65536`, replacement: `"ring_dimension":32768`, want: "ring_dimension"},
		{name: "complex slots", old: `"packing_slots":32768`, replacement: `"packing_slots":2048`, want: "packing_slots"},
		{name: "useful words", old: `"useful_words":8192`, replacement: `"useful_words":512`, want: "useful_words"},
		{name: "warmup", old: `"warmup_count":1`, replacement: `"warmup_count":2`, want: "warmup_count"},
		{name: "repeat count", old: `"repeat_count":5`, replacement: `"repeat_count":4`, want: "repeat_count"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			valid := canonicalArtifactJSON("openfhe", canonicalSamples())
			payload := strings.Replace(valid, test.old, test.replacement, 1)
			if payload == valid {
				t.Fatalf("fixture field %s not found", test.old)
			}
			_, err := benchcmp.ParseCanonical(strings.NewReader(payload), "invalid-shape.json")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
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

func TestParseCanonicalRejectsArtifactWithoutGaoParameterSemantics(t *testing.T) {
	payload := strings.Replace(
		canonicalArtifactJSON("openfhe", canonicalSamples()),
		`,"parameters":`+canonicalParametersJSON(),
		"",
		1,
	)
	_, err := benchcmp.ParseCanonical(
		strings.NewReader(payload),
		"missing-parameters.json",
	)
	if err == nil || !strings.Contains(err.Error(), "parameters") {
		t.Fatalf("error=%v, want missing parameters", err)
	}
}

func TestParseCanonicalRejectsUnmatchedGaoParameterSemantics(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		want        string
	}{
		{name: "comparison scope", old: `"comparison_scope":"gao-algorithm-and-aggregate-modulus-bits"`, replacement: `"comparison_scope":"prime-identical"`, want: "comparison_scope"},
		{name: "Q count", old: `"q_moduli_count":21`, replacement: `"q_moduli_count":20`, want: "q_moduli_count"},
		{name: "Q aggregate", old: `"q_log2_aggregate":904`, replacement: `"q_log2_aggregate":903`, want: "q_log2_aggregate"},
		{name: "P count", old: `"p_moduli_count":7`, replacement: `"p_moduli_count":6`, want: "p_moduli_count"},
		{name: "P aggregate", old: `"p_log2_aggregate":350`, replacement: `"p_log2_aggregate":349`, want: "p_log2_aggregate"},
		{name: "scaling modulus", old: `"scaling_modulus_bits":43`, replacement: `"scaling_modulus_bits":42`, want: "scaling_modulus_bits"},
		{name: "first modulus", old: `"first_modulus_bits":43`, replacement: `"first_modulus_bits":42`, want: "first_modulus_bits"},
		{name: "depth", old: `"multiplicative_depth":20`, replacement: `"multiplicative_depth":19`, want: "multiplicative_depth"},
		{name: "large digits", old: `"large_digits":3`, replacement: `"large_digits":2`, want: "large_digits"},
		{name: "main weight", old: `"main_secret_hamming_weight":192`, replacement: `"main_secret_hamming_weight":191`, want: "main_secret_hamming_weight"},
		{name: "ephemeral weight", old: `"ephemeral_secret_hamming_weight":32`, replacement: `"ephemeral_secret_hamming_weight":31`, want: "ephemeral_secret_hamming_weight"},
		{name: "RNS components", old: `"rns_decomposition_components":3`, replacement: `"rns_decomposition_components":2`, want: "rns_decomposition_components"},
		{name: "base two", old: `"base_two_decomposition":0`, replacement: `"base_two_decomposition":1`, want: "base_two_decomposition"},
		{name: "level budget", old: `"level_budget":[3,2]`, replacement: `"level_budget":[2,3]`, want: "level_budget"},
		{name: "OpenFHE requested BSGS", old: `"openfhe_requested_bsgs_dimensions":[0,0]`, replacement: `"openfhe_requested_bsgs_dimensions":[1,0]`, want: "openfhe_requested_bsgs_dimensions"},
		{name: "chunk width", old: `"chunk_width":4`, replacement: `"chunk_width":3`, want: "chunk_width"},
		{name: "cutoff", old: `"cutoff_bits":-24`, replacement: `"cutoff_bits":-23`, want: "cutoff_bits"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := strings.Replace(canonicalArtifactJSON("openfhe", canonicalSamples()), test.old, test.replacement, 1)
			if payload == canonicalArtifactJSON("openfhe", canonicalSamples()) {
				t.Fatalf("fixture field %s not found", test.old)
			}
			_, err := benchcmp.ParseCanonical(strings.NewReader(payload), "unmatched-parameters.json")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestParseCanonicalRejectsAmbiguousLegacyBSGSDimensions(t *testing.T) {
	payload := strings.Replace(
		canonicalArtifactJSON("gao-openfhe-a2b-full", canonicalSamples()),
		`"openfhe_requested_bsgs_dimensions":[0,0]`,
		`"bsgs_dimensions":[0,0]`,
		1,
	)
	_, err := benchcmp.ParseCanonical(strings.NewReader(payload), "legacy-bsgs-name.json")
	if err == nil || !strings.Contains(err.Error(), `unknown field "bsgs_dimensions"`) {
		t.Fatalf("error=%v, want legacy bsgs_dimensions rejection", err)
	}
}

func TestComparisonUsesOnlyMatchedCanonicalMeasurements(t *testing.T) {
	openfhe := mustParseCanonical(t, "gao-openfhe-a2b-full", []uint64{
		9_000_000_000, 11_000_000_000, 10_000_000_000, 12_000_000_000, 8_000_000_000,
	})
	lattigo := mustParseCanonical(t, "lattigo-gao-a2b-full", []uint64{
		7_000_000_000, 9_000_000_000, 8_000_000_000, 10_000_000_000, 6_000_000_000,
	})
	openfhe.A2BMeanNanoseconds, openfhe.A2BMedianNanoseconds, openfhe.EffectiveWordsPerSecond = 1, 1, 1
	lattigo.A2BMeanNanoseconds, lattigo.A2BMedianNanoseconds, lattigo.EffectiveWordsPerSecond = 1, 1, 1

	got, err := benchcmp.Compare(openfhe, lattigo)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != "lcpdte-ckksint-a2b-comparison-v3" {
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
		t.Fatalf("v3 summary leaked legacy aggregate fields:\n%s", first)
	}
}

func TestComparisonRejectsSerialOutputContainer(t *testing.T) {
	openfhe := mustParseCanonical(t, "gao-openfhe-a2b-full", canonicalSamples())
	lattigo := mustParseCanonical(t, "lattigo-gao-a2b-full", canonicalSamples())
	lattigo.OutputContainer = "two-serial-ciphertexts-low4-high4"

	_, err := benchcmp.Compare(openfhe, lattigo)
	if err == nil || !strings.Contains(err.Error(), "two-ciphertexts-low4-high4") {
		t.Fatalf("error=%v, want strict two-ciphertext output rejection", err)
	}
}

func TestComparisonRejectsSwappedOrDuplicatedImplementationRoles(t *testing.T) {
	openfhe := mustParseCanonical(t, "gao-openfhe-a2b-full", canonicalSamples())
	lattigo := mustParseCanonical(t, "lattigo-gao-a2b-full", canonicalSamples())

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

func TestComparisonRejectsLegacyLattigoRole(t *testing.T) {
	openfhe := mustParseCanonical(t, "gao-openfhe-a2b-full", canonicalSamples())
	legacy := mustParseCanonical(t, "lattigo-gao-a2b-full", canonicalSamples())
	legacy.Source = "lattigo-route-b"

	_, err := benchcmp.Compare(openfhe, legacy)
	if err == nil || !strings.Contains(err.Error(), "lattigo-gao-a2b-full") {
		t.Fatalf("error=%v", err)
	}
}

func TestComparisonFailsWhenMeanOrMedianIsSlowerThanOpenFHE(t *testing.T) {
	tests := []struct {
		name           string
		openFHESamples []uint64
		lattigoSamples []uint64
		wantMetric     string
	}{
		{
			name:           "mean",
			openFHESamples: []uint64{10, 10, 10, 10, 10},
			lattigoSamples: []uint64{9, 9, 9, 9, 20},
			wantMetric:     "mean",
		},
		{
			name:           "median",
			openFHESamples: []uint64{10, 10, 10, 10, 20},
			lattigoSamples: []uint64{1, 11, 11, 11, 11},
			wantMetric:     "median",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			openfhe := mustParseCanonical(t, "gao-openfhe-a2b-full", test.openFHESamples)
			lattigo := mustParseCanonical(t, "lattigo-gao-a2b-full", test.lattigoSamples)
			summary, err := benchcmp.Compare(openfhe, lattigo)
			if err == nil || !strings.Contains(err.Error(), "performance parity gate failed") ||
				!strings.Contains(err.Error(), test.wantMetric) {
				t.Fatalf("summary=%+v error=%v", summary, err)
			}
		})
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
		{name: "os", mutate: func(a, b *benchcmp.Measurement) { b.OS = "windows" }, wantMessage: "os mismatch"},
		{name: "arch", mutate: func(a, b *benchcmp.Measurement) { b.Arch = "arm64" }, wantMessage: "arch mismatch"},
		{name: "public key", mutate: func(a, b *benchcmp.Measurement) { b.EncryptionMode = "secret-key" }, wantMessage: "encryption_mode"},
		{name: "resident factors", mutate: func(a, b *benchcmp.Measurement) { b.FactorStorageMode = "streamed" }, wantMessage: "factor_storage_mode"},
		{name: "native scale schedule", mutate: func(a, b *benchcmp.Measurement) { b.ScaleSchedule = "synthetic-shared" }, wantMessage: "scale_schedule"},
		{name: "backend BSGS plan", mutate: func(a, b *benchcmp.Measurement) { b.BackendBSGSPlan = "" }, wantMessage: "backend_bsgs_plan"},
		{name: "source revision", mutate: func(a, b *benchcmp.Measurement) { b.SourceRevision = "" }, wantMessage: "source_revision"},
		{name: "source modified", mutate: func(a, b *benchcmp.Measurement) { b.SourceModified = true }, wantMessage: "source_modified"},
		{name: "runtime", mutate: func(a, b *benchcmp.Measurement) { b.Runtime = "" }, wantMessage: "runtime"},
		{name: "compiler", mutate: func(a, b *benchcmp.Measurement) { b.Compiler = "" }, wantMessage: "compiler"},
		{name: "build profile", mutate: func(a, b *benchcmp.Measurement) { b.BuildProfile = "" }, wantMessage: "build_profile"},
		{name: "protocol", mutate: func(a, b *benchcmp.Measurement) { b.Protocol = "other-protocol" }, wantMessage: "protocol mismatch"},
		{name: "workload", mutate: func(a, b *benchcmp.Measurement) { b.WorkloadID = "other-workload" }, wantMessage: "workload_id mismatch"},
		{name: "packing id", mutate: func(a, b *benchcmp.Measurement) { b.PackingID = "other-packing" }, wantMessage: "packing_id mismatch"},
		{name: "exact Q chain", mutate: func(a, b *benchcmp.Measurement) { b.NativeParameters.QModuli[0] = "8796093022211" }, wantMessage: "q_moduli mismatch"},
		{name: "exact P chain", mutate: func(a, b *benchcmp.Measurement) { b.NativeParameters.PModuli[0] = "1125899906842621" }, wantMessage: "p_moduli mismatch"},
		{name: "scope", mutate: func(a, b *benchcmp.Measurement) { b.TimingScope = "setup-and-online" }, wantMessage: "timing scope"},
		{name: "warmup verification", mutate: func(a, b *benchcmp.Measurement) { b.WarmupVerified = false }, wantMessage: "warmup_verified"},
		{name: "verification", mutate: func(a, b *benchcmp.Measurement) { b.VerifiedEvaluations = 4 }, wantMessage: "verified_evaluations"},
		{name: "zero sample", mutate: func(a, b *benchcmp.Measurement) { b.TimedSamplesNanoseconds[2] = 0 }, wantMessage: "must be nonzero"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			openfhe := mustParseCanonical(t, "gao-openfhe-a2b-full", canonicalSamples())
			lattigo := mustParseCanonical(t, "lattigo-gao-a2b-full", canonicalSamples())
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
	if implementation == "openfhe" {
		implementation = benchcmp.FocusedOpenFHESource
	}
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
		BuildProfile: benchcmp.OpenFHEBuildProfile, OS: "linux", Arch: "amd64",
		Protocol: "gao-a2b-full-z8-w4-v1", WorkloadID: "uint8-0to255-x32",
		PackingID: "n65536-cslots32768-zslots8192-w4", OutputContainer: "two-ciphertexts-low4-high4",
		WordBits: 8, RingDimension: 65_536, PackingSlots: 32_768, UsefulWords: 8_192,
		Parameters: canonicalParameters(), NativeParameters: canonicalNativeParameters(implementation), Threads: 1,
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
		panic(err)
	}
	return string(encoded)
}

func canonicalParameters() *benchcmp.GaoParameterSemantics {
	return &benchcmp.GaoParameterSemantics{
		ComparisonScope: "gao-algorithm-and-aggregate-modulus-bits",
		QModuliCount:    21, QLog2Aggregate: 904,
		PModuliCount: 7, PLog2Aggregate: 350,
		ScalingModulusBits: 43, FirstModulusBits: 43,
		MultiplicativeDepth: 20, LargeDigits: 3,
		MainSecretHammingWeight:      192,
		EphemeralSecretHammingWeight: 32,
		KeySwitchRNSComponents:       3, KeySwitchBaseTwoDecomposition: 0,
		LevelBudget: [2]uint32{3, 2}, OpenFHERequestedBSGSDimensions: [2]uint32{0, 0},
		ChunkWidth: 4, CutoffBits: -24,
	}
}

func canonicalNativeParameters(implementation string) *benchcmp.NativeParameters {
	openFHEQBits := []uint32{44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 43, 44, 44, 44, 43, 44}
	openFHEPBits := []uint32{50, 50, 50, 50, 50, 50, 50}

	native := &benchcmp.NativeParameters{
		MainSecretDistribution:        "balanced-sparse-ternary",
		MainSecretHammingWeight:       192,
		EphemeralSecretDistribution:   "balanced-sparse-ternary",
		EphemeralSecretHammingWeight:  32,
		KeySwitchRNSComponents:        3,
		KeySwitchBaseTwoDecomposition: 0,
	}
	if implementation == benchcmp.FocusedLattigoSource {
		bound := 39.0
		native.MainSecretDistribution = "fixed-h-symmetric-sparse-ternary"
		native.EphemeralSecretDistribution = "fixed-h-symmetric-sparse-ternary"
		native.ActualFirstQModulusBits = 44
		native.ErrorSampler = "lattigo-bounded-discrete-gaussian"
		native.ErrorSigma = 3.19
		native.ErrorConfiguredBound = &bound
		native.ErrorEffectiveIntegerBound = 39
		native.KeySwitchTechnique = "lattigo-rns-qp-gadget"
		native.SecuritySelector = "external-estimator"
		native.SecurityEvidence = "full-packed-profile-not-assessed"
		native.QModuliBitLengths = openFHEQBits
		native.PModuliBitLengths = openFHEPBits
		native.QModuli = syntheticModuli(openFHEQBits, 43, 1)
		native.PModuli = syntheticModuli(openFHEPBits, 50, 1)
		return native
	}
	native.ActualFirstQModulusBits = 44
	native.ErrorSampler = "openfhe-dgg"
	native.ErrorSigma = 3.19
	native.ErrorEffectiveIntegerBound = 39
	native.KeySwitchTechnique = "openfhe-hybrid"
	native.SecuritySelector = "HEStd_128_classic"
	native.SecurityEvidence = "openfhe-he-standard-ternary-table"
	native.QModuliBitLengths = openFHEQBits
	native.PModuliBitLengths = openFHEPBits
	native.QModuli = syntheticModuli(openFHEQBits, 43, 1)
	native.PModuli = syntheticModuli(openFHEPBits, 50, 1)
	return native
}

func syntheticModuli(profile []uint32, target uint32, positiveDelta uint64) []string {
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

func canonicalParametersJSON() string {
	encoded, err := json.Marshal(canonicalParameters())
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func mutateCanonicalNative(t *testing.T, implementation string, mutate func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(canonicalArtifactJSON(implementation, canonicalSamples())), &document); err != nil {
		t.Fatal(err)
	}
	native, ok := document["native_parameters"].(map[string]any)
	if !ok {
		t.Fatalf("native_parameters type=%T", document["native_parameters"])
	}
	mutate(native)
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return payload
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
