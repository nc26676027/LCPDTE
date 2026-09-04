package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/ckksint"
	"github.com/nc26676027/LCPDTE/internal/benchcmp"
)

func testExecutionMetadata() benchmarkExecutionMetadata {
	return benchmarkExecutionMetadata{
		SourceRevision: "0123456789abcdef0123456789abcdef01234567",
		Runtime:        "go1.25.0",
		Compiler:       "gc",
		BuildProfile:   benchcmp.LattigoAcceptanceBuildProfile,
		OS:             "linux",
		Arch:           "amd64",
	}
}

func canonicalAcceptanceRuntime() lattigoAcceptanceRuntime {
	return lattigoAcceptanceRuntime{
		BuildGOAMD64:       "v4",
		EnvironmentGOAMD64: "v4",
		GOMAXPROCSValue:    "1",
		GOGCValue:          "100",
		GOMEMLIMITValue:    "20GiB",
		PostWarmupGCValue:  "on",
		CPUProfileValue:    "",
		RuntimeGOMAXPROCS:  1,
		RuntimeGOGC:        100,
		RuntimeMemoryLimit: 20 * 1024 * 1024 * 1024,
		GOOS:               "linux",
		GOARCH:             "amd64",
	}
}

func TestLattigoAcceptanceRuntimeRequiresExactFairBuild(t *testing.T) {
	canonical := canonicalAcceptanceRuntime()
	if err := validateLattigoAcceptanceRuntime(canonical); err != nil {
		t.Fatalf("canonical runtime rejected: %v", err)
	}
	if got := canonical.lattigoBuildProfile(); got != benchcmp.LattigoAcceptanceBuildProfile {
		t.Fatalf("build profile=%q, want %q", got, benchcmp.LattigoAcceptanceBuildProfile)
	}

	tests := []struct {
		name   string
		mutate func(*lattigoAcceptanceRuntime)
		want   string
	}{
		{name: "embedded GOAMD64", mutate: func(state *lattigoAcceptanceRuntime) { state.BuildGOAMD64 = "v3" }, want: "embedded GOAMD64"},
		{name: "environment GOAMD64", mutate: func(state *lattigoAcceptanceRuntime) { state.EnvironmentGOAMD64 = "v3" }, want: "GOAMD64"},
		{name: "GOMAXPROCS environment", mutate: func(state *lattigoAcceptanceRuntime) { state.GOMAXPROCSValue = "2" }, want: "GOMAXPROCS"},
		{name: "GOMAXPROCS runtime", mutate: func(state *lattigoAcceptanceRuntime) { state.RuntimeGOMAXPROCS = 2 }, want: "GOMAXPROCS"},
		{name: "GOGC environment", mutate: func(state *lattigoAcceptanceRuntime) { state.GOGCValue = "off" }, want: "GOGC"},
		{name: "GOGC runtime", mutate: func(state *lattigoAcceptanceRuntime) { state.RuntimeGOGC = 99 }, want: "GOGC"},
		{name: "GOMEMLIMIT environment", mutate: func(state *lattigoAcceptanceRuntime) { state.GOMEMLIMITValue = "24GiB" }, want: "GOMEMLIMIT"},
		{name: "GOMEMLIMIT runtime", mutate: func(state *lattigoAcceptanceRuntime) { state.RuntimeMemoryLimit-- }, want: "GOMEMLIMIT"},
		{name: "post warmup GC", mutate: func(state *lattigoAcceptanceRuntime) { state.PostWarmupGCValue = "off" }, want: "POST_WARMUP_GC"},
		{name: "CPU profile", mutate: func(state *lattigoAcceptanceRuntime) { state.CPUProfileValue = "cpu.pprof" }, want: "LCPDTE_GAO_CPU_PROFILE"},
		{name: "operating system", mutate: func(state *lattigoAcceptanceRuntime) { state.GOOS = "windows" }, want: "GOOS"},
		{name: "architecture", mutate: func(state *lattigoAcceptanceRuntime) { state.GOARCH = "arm64" }, want: "GOARCH"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := canonical
			test.mutate(&state)
			if err := validateLattigoAcceptanceRuntime(state); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestBenchmarkRejectsNonAcceptanceBuildBeforeSessionConstruction(t *testing.T) {
	metadata := testExecutionMetadata()
	metadata.BuildProfile = "GOOS=linux;GOARCH=amd64;GOAMD64=v3;GOMAXPROCS=1"
	constructed := false
	_, err := runCanonicalBenchmarkWithFactory(
		"same-host",
		func() (sessionOps, ckksint.GaoFullPackedA2BSetupInfo, error) {
			constructed = true
			return sessionOps{}, ckksint.GaoFullPackedA2BSetupInfo{}, nil
		},
		func() (benchmarkExecutionMetadata, error) { return metadata, nil },
		time.Now,
	)
	if err == nil || !strings.Contains(err.Error(), "build_profile") || constructed {
		t.Fatalf("error=%v session_constructed=%t", err, constructed)
	}
}

func testSetupInfo() ckksint.GaoFullPackedA2BSetupInfo {
	qBits := []int{43, 43, 43, 43, 44, 43, 44, 43, 43, 43, 44, 44, 44, 44, 44, 44, 44, 44, 43, 44, 43}
	pBits := []int{51, 50, 51, 50, 51, 51, 49}
	return ckksint.GaoFullPackedA2BSetupInfo{
		ParameterWallTime:          2 * time.Second,
		KeyGenerationWallTime:      3 * time.Second,
		ServerConstructionWallTime: 4 * time.Second,
		ClientConstructionWallTime: 5 * time.Second,
		Parameters: ckksint.GaoFullPackedA2BParameterInfo{
			RingDimension: 65_536, PackingSlots: 32_768, UsefulWords: 8_192,
			QModuliCount: 21, QLog2Aggregate: 904, PModuliCount: 7, PLog2Aggregate: 350,
			ScalingModulusBits: 43, FirstModulusBits: 43, MultiplicativeDepth: 20,
			ActualFirstQModulusBits: 43,
			QModuli:                 syntheticSetupModuli(qBits, 43, 1_000), PModuli: syntheticSetupModuli(pBits, 50, 1_000),
			QModuliBitLengths: qBits, PModuliBitLengths: pBits,
			LargeDigits: 3, MainSecretDistribution: "balanced-sparse-ternary", MainSecretHammingWeight: 192,
			EphemeralSecretDistribution: "balanced-sparse-ternary", EphemeralSecretHammingWeight: 32,
			ErrorSampler: "lattigo-bounded-discrete-gaussian", ErrorSigma: 3.2,
			ErrorConfiguredBound: 19.2, ErrorEffectiveIntegerBound: 19,
			KeySwitchTechnique: "lattigo-rns-qp-gadget", RNSDecompositionComponents: 3,
			BaseTwoDecomposition: 0, SecuritySelector: "external-estimator", SecurityEvidence: "full-packed-profile-not-assessed",
			LevelBudget: [2]int{3, 2}, OpenFHERequestedBSGSDimensions: [2]int{0, 0},
			ChunkWidth: 4, CutoffBits: -24,
			STCLogBSGSRatio: 2, CTSLogBSGSRatio: 2, SpecialB0LogBSGSRatio: 2,
			EncryptionMode: "public-key", FactorStorageMode: "resident-prevalidated",
			ScaleSchedule: "lattigo-explicit-level-scale-native",
		},
	}
}

func syntheticSetupModuli(profile []int, target int, positiveDelta uint64) []string {
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

func TestCanonicalInputContainsThirtyTwoByteCycles(t *testing.T) {
	got := canonicalInput()
	if len(got) != 8_192 {
		t.Fatalf("len(input)=%d, want 8192", len(got))
	}
	for index, word := range got {
		if want := uint8(index % 256); word != want {
			t.Fatalf("input[%d]=%d, want %d", index, word, want)
		}
	}
}

func TestCanonicalArtifactRecordsPreparedOnlineProtocol(t *testing.T) {
	setup := testSetupInfo()
	warmup := ckksint.GaoFullPackedA2BPhaseInfo{}
	encryption := ckksint.GaoFullPackedA2BPhaseInfo{WallTime: 6 * time.Second}
	warmup.WallTime = 12 * time.Second
	warmup.OnlineWallTime = 4 * time.Second
	samples := []uint64{11, 12, 13, 14, 15}

	got, err := canonicalArtifact("same-host", setup, encryption, warmup, samples, testExecutionMetadata())
	if err != nil {
		t.Fatal(err)
	}

	if got.Schema != "lcpdte-ckksint-a2b-benchmark-v3" || got.Implementation != "lattigo-gao-a2b-full" {
		t.Fatalf("identity=%+v", got)
	}
	if got.HostID != "same-host" || got.Protocol != "gao-a2b-full-z8-w4-v1" ||
		got.WorkloadID != "uint8-0to255-x32" ||
		got.PackingID != "n65536-cslots32768-zslots8192-w4" {
		t.Fatalf("protocol identity=%+v", got)
	}
	if got.WordBits != 8 || got.RingDimension != 65_536 || got.PackingSlots != 32_768 || got.UsefulWords != 8_192 {
		t.Fatalf("shape=%+v", got)
	}
	if got.Threads != 1 || got.TimingScope != "prepared-online" || got.SetupNanoseconds != 20_000_000_000 {
		t.Fatalf("scope=%+v", got)
	}
	if got.Parameters == nil || *got.Parameters != *benchcmp.CanonicalGaoParameters() {
		t.Fatalf("parameters=%+v", got.Parameters)
	}
	if got.NativeParameters == nil || got.NativeParameters.ActualFirstQModulusBits != 43 ||
		got.NativeParameters.MainSecretDistribution != "balanced-sparse-ternary" ||
		got.NativeParameters.MainSecretHammingWeight != 192 ||
		got.NativeParameters.ErrorSampler != "lattigo-bounded-discrete-gaussian" ||
		got.NativeParameters.ErrorConfiguredBound == nil || *got.NativeParameters.ErrorConfiguredBound != 19.2 ||
		got.NativeParameters.KeySwitchTechnique != "lattigo-rns-qp-gadget" ||
		!reflect.DeepEqual(got.NativeParameters.QModuli, setup.Parameters.QModuli) ||
		!reflect.DeepEqual(got.NativeParameters.PModuli, setup.Parameters.PModuli) {
		t.Fatalf("native parameters=%+v", got.NativeParameters)
	}
	if got.EncryptionMode != "public-key" || got.FactorStorageMode != "resident-prevalidated" ||
		got.ScaleSchedule != "lattigo-explicit-level-scale-native" ||
		got.BackendBSGSPlan != benchcmp.LattigoBackendBSGSPlan ||
		got.SourceRevision != testExecutionMetadata().SourceRevision || got.SourceModified ||
		got.Runtime != "go1.25.0" || got.Compiler != "gc" || got.BuildProfile != benchcmp.LattigoAcceptanceBuildProfile ||
		got.OS != "linux" || got.Arch != "amd64" {
		t.Fatalf("execution metadata=%+v", got)
	}
	if got.WarmupCount != 1 || !got.WarmupVerified || got.RepeatCount != 5 || got.VerifiedEvaluations != 5 {
		t.Fatalf("repetition protocol=%+v", got)
	}
	if got.MismatchCount != 0 || got.OutputContainer != "two-ciphertexts-low4-high4" ||
		!reflect.DeepEqual(got.TimedSamplesNanoseconds, samples) {
		t.Fatalf("result=%+v", got)
	}
}

func TestCountBitMismatchesChecksEveryOutputBit(t *testing.T) {
	words := []uint8{0x00, 0xA5, 0xFF}
	bits := [][8]uint8{
		{0, 0, 0, 0, 0, 0, 0, 0},
		{1, 0, 1, 0, 0, 1, 0, 1},
		{1, 1, 1, 1, 1, 1, 1, 1},
	}
	if got := countBitMismatches(words, bits); got != 0 {
		t.Fatalf("mismatches=%d, want 0", got)
	}
	bits[1][6] = 1
	if got := countBitMismatches(words, bits); got != 1 {
		t.Fatalf("mismatches=%d, want 1", got)
	}
}

func TestCLIRequiresHostIDBeforeBenchmarking(t *testing.T) {
	var stderr bytes.Buffer
	called := false
	exitCode := run(
		[]string{"-out", "result.json"},
		&stderr,
		func(string) (benchcmp.CanonicalArtifact, error) {
			called = true
			return benchcmp.CanonicalArtifact{}, nil
		},
		func(string, benchcmp.CanonicalArtifact) error { return nil },
	)
	if exitCode == 0 || called {
		t.Fatalf("exit=%d benchmark_called=%t", exitCode, called)
	}
	if !strings.Contains(stderr.String(), "-host-id is required") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestCLIRequiresOutputPathBeforeBenchmarking(t *testing.T) {
	var stderr bytes.Buffer
	called := false
	exitCode := run(
		[]string{"-host-id", "same-host"},
		&stderr,
		func(string) (benchcmp.CanonicalArtifact, error) {
			called = true
			return benchcmp.CanonicalArtifact{}, nil
		},
		func(string, benchcmp.CanonicalArtifact) error { return nil },
	)
	if exitCode == 0 || called {
		t.Fatalf("exit=%d benchmark_called=%t", exitCode, called)
	}
	if !strings.Contains(stderr.String(), "-out is required") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestCLIHelpDoesNotStartBenchmark(t *testing.T) {
	var stderr bytes.Buffer
	called := false
	exitCode := run(
		[]string{"-h"},
		&stderr,
		func(string) (benchcmp.CanonicalArtifact, error) {
			called = true
			return benchcmp.CanonicalArtifact{}, nil
		},
		func(string, benchcmp.CanonicalArtifact) error { return nil },
	)
	if exitCode != 0 || called {
		t.Fatalf("exit=%d benchmark_called=%t", exitCode, called)
	}
	if !strings.Contains(stderr.String(), "-host-id") || !strings.Contains(stderr.String(), "-out") {
		t.Fatalf("help=%q", stderr.String())
	}
}

func TestBenchmarkRecordsOnlyPreparedOnlineSamples(t *testing.T) {
	evaluations := 0
	encryptions := 0
	decryptions := 0
	encryptedWords := 0
	factory := func() (sessionOps, ckksint.GaoFullPackedA2BSetupInfo, error) {
		return sessionOps{
				close: func() {},
				encrypt: func(words []uint8) (*ckksint.GaoFullPackedA2BEncryptedInput, ckksint.GaoFullPackedA2BPhaseInfo, error) {
					encryptions++
					encryptedWords = len(words)
					return nil, ckksint.GaoFullPackedA2BPhaseInfo{WallTime: 6 * time.Nanosecond}, nil
				},
				evaluate: func(*ckksint.GaoFullPackedA2BEncryptedInput) (*ckksint.GaoFullPackedA2BEncryptedOutput, ckksint.GaoFullPackedA2BPhaseInfo, error) {
					evaluations++
					info := ckksint.GaoFullPackedA2BPhaseInfo{
						OnlineWallTime: time.Duration(100+evaluations) * time.Nanosecond,
						WallTime:       time.Duration(110+evaluations) * time.Nanosecond,
					}
					return nil, info, nil
				},
				decrypt: func(*ckksint.GaoFullPackedA2BEncryptedOutput) ([][8]uint8, error) {
					decryptions++
					return expectedBits(canonicalInput()), nil
				},
			}, func() ckksint.GaoFullPackedA2BSetupInfo {
				setup := testSetupInfo()
				setup.ParameterWallTime = 2 * time.Nanosecond
				setup.KeyGenerationWallTime = 3 * time.Nanosecond
				setup.ServerConstructionWallTime = 4 * time.Nanosecond
				setup.ClientConstructionWallTime = 5 * time.Nanosecond
				return setup
			}(), nil
	}

	base := time.Unix(1_700_000_000, 0)
	clockValues := make([]time.Time, 0, 2*benchmarkRepeats)
	for repeat := 0; repeat < benchmarkRepeats; repeat++ {
		started := base.Add(time.Duration(repeat) * time.Second)
		clockValues = append(clockValues, started, started.Add(time.Duration(201+repeat)*time.Nanosecond))
	}
	clockIndex := 0
	now := func() time.Time {
		if clockIndex >= len(clockValues) {
			t.Fatal("benchmark clock read beyond the five timed public calls")
		}
		value := clockValues[clockIndex]
		clockIndex++
		return value
	}
	got, err := runCanonicalBenchmarkWithFactory(
		"same-host",
		factory,
		func() (benchmarkExecutionMetadata, error) { return testExecutionMetadata(), nil },
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if encryptions != 1 || encryptedWords != 8_192 || evaluations != 6 || decryptions != 6 {
		t.Fatalf("encryptions=%d encrypted_words=%d evaluations=%d decryptions=%d", encryptions, encryptedWords, evaluations, decryptions)
	}
	if got.SetupNanoseconds != 20 {
		t.Fatalf("setup_ns=%d, want 20", got.SetupNanoseconds)
	}
	// The canonical samples wrap the complete prepared public Evaluate call,
	// matching the OpenFHE driver's call-boundary timer. The narrower internal
	// OnlineWallTime values above must not be emitted.
	wantSamples := []uint64{201, 202, 203, 204, 205}
	if !reflect.DeepEqual(got.TimedSamplesNanoseconds, wantSamples) {
		t.Fatalf("samples=%v, want %v", got.TimedSamplesNanoseconds, wantSamples)
	}
}

func expectedBits(words []uint8) [][8]uint8 {
	bits := make([][8]uint8, len(words))
	for wordIndex, word := range words {
		for bitIndex := 0; bitIndex < 8; bitIndex++ {
			bits[wordIndex][bitIndex] = (word >> bitIndex) & 1
		}
	}
	return bits
}

func TestWriteCanonicalArtifactProducesParseableV3JSON(t *testing.T) {
	artifact, err := canonicalArtifact(
		"same-host",
		func() ckksint.GaoFullPackedA2BSetupInfo {
			setup := testSetupInfo()
			setup.ParameterWallTime = time.Nanosecond
			setup.KeyGenerationWallTime = 0
			setup.ServerConstructionWallTime = 0
			return setup
		}(),
		ckksint.GaoFullPackedA2BPhaseInfo{WallTime: time.Nanosecond},
		ckksint.GaoFullPackedA2BPhaseInfo{
			WallTime:       2 * time.Nanosecond,
			OnlineWallTime: time.Nanosecond,
		},
		[]uint64{1, 2, 3, 4, 5}, testExecutionMetadata(),
	)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "lattigo.json")
	if err := writeCanonicalArtifact(path, artifact); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		t.Fatalf("artifact must end with newline: %q", payload)
	}
	if _, err := benchcmp.ParseCanonical(bytes.NewReader(payload), path); err != nil {
		t.Fatalf("parse emitted artifact: %v\n%s", err, payload)
	}
}

func TestCanonicalArtifactRejectsIncompleteTimingProtocol(t *testing.T) {
	_, err := canonicalArtifact(
		"same-host",
		testSetupInfo(),
		ckksint.GaoFullPackedA2BPhaseInfo{WallTime: time.Nanosecond},
		ckksint.GaoFullPackedA2BPhaseInfo{
			WallTime:       2 * time.Nanosecond,
			OnlineWallTime: time.Nanosecond,
		},
		[]uint64{1, 2, 3, 4}, testExecutionMetadata(),
	)
	if err == nil || !strings.Contains(err.Error(), "five nonzero samples") {
		t.Fatalf("error=%v", err)
	}
}
