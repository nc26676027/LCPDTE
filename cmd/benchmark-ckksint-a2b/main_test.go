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

func TestCanonicalInputContainsTwoByteCycles(t *testing.T) {
	got := canonicalInput()
	if len(got) != 512 {
		t.Fatalf("len(input)=%d, want 512", len(got))
	}
	for index, word := range got {
		if want := uint8(index % 256); word != want {
			t.Fatalf("input[%d]=%d, want %d", index, word, want)
		}
	}
}

func TestCanonicalArtifactRecordsPreparedOnlineProtocol(t *testing.T) {
	setup := ckksint.RouteBA2BSetupInfo{
		ParameterArtifactWallTime: 2 * time.Second,
		KeyGenerationWallTime:     3 * time.Second,
		ServerInstallWallTime:     4 * time.Second,
	}
	warmup := ckksint.RouteBA2BPhaseInfo{PreparationWallTime: 5 * time.Second}
	encryption := ckksint.RouteBA2BPhaseInfo{WallTime: 6 * time.Second}
	warmup.WallTime = 12 * time.Second
	warmup.OnlineWallTime = 4 * time.Second
	samples := []uint64{11, 12, 13, 14, 15}

	got, err := canonicalArtifact("same-host", setup, encryption, warmup, samples)
	if err != nil {
		t.Fatal(err)
	}

	if got.Schema != "lcpdte-ckksint-a2b-benchmark-v2" || got.Implementation != "lattigo-route-b" {
		t.Fatalf("identity=%+v", got)
	}
	if got.HostID != "same-host" || got.Protocol != "gao-a2b-sparse-z8-w4-v1" ||
		got.WorkloadID != "uint8-0to255-twice" ||
		got.PackingID != "n65536-cslots2048-zslots512-w4" {
		t.Fatalf("protocol identity=%+v", got)
	}
	if got.WordBits != 8 || got.RingDimension != 65_536 || got.PackingSlots != 2_048 || got.UsefulWords != 512 {
		t.Fatalf("shape=%+v", got)
	}
	if got.Threads != 1 || got.TimingScope != "prepared-online" || got.SetupNanoseconds != 23_000_000_000 {
		t.Fatalf("scope=%+v", got)
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
	factory := func() (sessionOps, ckksint.RouteBA2BSetupInfo, error) {
		return sessionOps{
				close: func() {},
				encrypt: func(words []uint8) (*ckksint.RouteBA2BEncryptedInput, ckksint.RouteBA2BPhaseInfo, error) {
					encryptions++
					return nil, ckksint.RouteBA2BPhaseInfo{WallTime: 6 * time.Nanosecond}, nil
				},
				evaluate: func(*ckksint.RouteBA2BEncryptedInput) (*ckksint.RouteBA2BEncryptedOutput, ckksint.RouteBA2BPhaseInfo, error) {
					evaluations++
					info := ckksint.RouteBA2BPhaseInfo{
						OnlineWallTime: time.Duration(100+evaluations) * time.Nanosecond,
						WallTime:       time.Duration(110+evaluations) * time.Nanosecond,
					}
					if evaluations == 1 {
						info.PreparationWallTime = 5 * time.Nanosecond
					}
					return nil, info, nil
				},
				decrypt: func(*ckksint.RouteBA2BEncryptedOutput) ([][8]uint8, error) {
					decryptions++
					return expectedBits(canonicalInput()), nil
				},
			}, ckksint.RouteBA2BSetupInfo{
				ParameterArtifactWallTime: 2 * time.Nanosecond,
				KeyGenerationWallTime:     3 * time.Nanosecond,
				ServerInstallWallTime:     4 * time.Nanosecond,
			}, nil
	}

	got, err := runCanonicalBenchmarkWithFactory("same-host", factory)
	if err != nil {
		t.Fatal(err)
	}
	if encryptions != 1 || evaluations != 6 || decryptions != 6 {
		t.Fatalf("encryptions=%d evaluations=%d decryptions=%d", encryptions, evaluations, decryptions)
	}
	if got.SetupNanoseconds != 25 {
		t.Fatalf("setup_ns=%d, want 25", got.SetupNanoseconds)
	}
	wantSamples := []uint64{102, 103, 104, 105, 106}
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
		ckksint.RouteBA2BSetupInfo{ParameterArtifactWallTime: time.Nanosecond},
		ckksint.RouteBA2BPhaseInfo{WallTime: time.Nanosecond},
		ckksint.RouteBA2BPhaseInfo{
			WallTime:            2 * time.Nanosecond,
			PreparationWallTime: time.Nanosecond,
			OnlineWallTime:      time.Nanosecond,
		},
		[]uint64{1, 2, 3, 4, 5},
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
		ckksint.RouteBA2BSetupInfo{},
		ckksint.RouteBA2BPhaseInfo{WallTime: time.Nanosecond},
		ckksint.RouteBA2BPhaseInfo{
			WallTime:            2 * time.Nanosecond,
			PreparationWallTime: time.Nanosecond,
			OnlineWallTime:      time.Nanosecond,
		},
		[]uint64{1, 2, 3, 4},
	)
	if err == nil || !strings.Contains(err.Error(), "five nonzero samples") {
		t.Fatalf("error=%v", err)
	}
}
