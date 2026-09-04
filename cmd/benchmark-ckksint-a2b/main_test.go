package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/ckksint"
	"github.com/nc26676027/LCPDTE/internal/benchcmp"
)

func testExecutionMetadata() benchmarkExecutionMetadata {
	return benchmarkExecutionMetadata{
		SourceRevision: "0123456789abcdef0123456789abcdef01234567",
		Runtime:        "go-test",
		Compiler:       "gc",
		BuildProfile:   "GOOS=linux;GOARCH=amd64;GOAMD64=v1;GOMAXPROCS=1",
		OS:             "linux",
		Arch:           "amd64",
	}
}

func testSetupInfo() ckksint.GaoFullPackedA2BSetupInfo {
	return ckksint.GaoFullPackedA2BSetupInfo{
		ParameterWallTime:          2 * time.Second,
		KeyGenerationWallTime:      3 * time.Second,
		ServerConstructionWallTime: 4 * time.Second,
		Parameters: ckksint.GaoFullPackedA2BParameterInfo{
			RingDimension: 65_536, PackingSlots: 32_768, UsefulWords: 8_192,
			QModuliCount: 21, QLog2Aggregate: 904, PModuliCount: 7, PLog2Aggregate: 350,
			ScalingModulusBits: 43, FirstModulusBits: 43, MultiplicativeDepth: 20,
			LargeDigits: 3, EphemeralSecretHammingWeight: 32,
			LevelBudget: [2]int{3, 2}, OpenFHERequestedBSGSDimensions: [2]int{0, 0},
			ChunkWidth: 4, CutoffBits: -24,
			STCLogBSGSRatio: 2, CTSLogBSGSRatio: 2, SpecialB0LogBSGSRatio: 2,
			EncryptionMode: "public-key", FactorStorageMode: "resident-prevalidated",
			ScaleSchedule: "lattigo-explicit-level-scale-native",
		},
	}
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

	if got.Schema != "lcpdte-ckksint-a2b-benchmark-v2" || got.Implementation != "lattigo-gao-a2b-full" {
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
	if got.Threads != 1 || got.TimingScope != "prepared-online" || got.SetupNanoseconds != 15_000_000_000 {
		t.Fatalf("scope=%+v", got)
	}
	if got.Parameters == nil || *got.Parameters != *benchcmp.CanonicalGaoParameters() {
		t.Fatalf("parameters=%+v", got.Parameters)
	}
	if got.EncryptionMode != "public-key" || got.FactorStorageMode != "resident-prevalidated" ||
		got.ScaleSchedule != "lattigo-explicit-level-scale-native" ||
		got.BackendBSGSPlan != "lattigo-dft-log-bsgs-ratio-2-special-b0-ratio-2-live-output-optimized" ||
		got.SourceRevision != testExecutionMetadata().SourceRevision || got.SourceModified ||
		got.Runtime != "go-test" || got.Compiler != "gc" || got.OS != "linux" || got.Arch != "amd64" {
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
				return setup
			}(), nil
	}

	got, err := runCanonicalBenchmarkWithFactory("same-host", factory, func() (benchmarkExecutionMetadata, error) {
		return testExecutionMetadata(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if encryptions != 1 || encryptedWords != 8_192 || evaluations != 6 || decryptions != 6 {
		t.Fatalf("encryptions=%d encrypted_words=%d evaluations=%d decryptions=%d", encryptions, encryptedWords, evaluations, decryptions)
	}
	if got.SetupNanoseconds != 15 {
		t.Fatalf("setup_ns=%d, want 15", got.SetupNanoseconds)
	}
	// The canonical samples wrap the complete prepared public Evaluate call,
	// matching the OpenFHE driver's call-boundary timer. The narrower internal
	// OnlineWallTime values above must not be emitted.
	wantSamples := []uint64{112, 113, 114, 115, 116}
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

func TestWriteCanonicalArtifactProducesParseableV2JSON(t *testing.T) {
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
