package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/nc26676027/LCPDTE/ckksint"
	"github.com/nc26676027/LCPDTE/internal/benchcmp"
)

type benchmarkFunc func(hostID string) (benchcmp.CanonicalArtifact, error)
type artifactWriter func(path string, artifact benchcmp.CanonicalArtifact) error
type sessionFactory func() (sessionOps, ckksint.RouteBA2BSetupInfo, error)

type sessionOps struct {
	close    func()
	encrypt  func([]uint8) (*ckksint.RouteBA2BEncryptedInput, ckksint.RouteBA2BPhaseInfo, error)
	evaluate func(*ckksint.RouteBA2BEncryptedInput) (*ckksint.RouteBA2BEncryptedOutput, ckksint.RouteBA2BPhaseInfo, error)
	decrypt  func(*ckksint.RouteBA2BEncryptedOutput) ([][8]uint8, error)
}

const (
	benchmarkProtocol        = "gao-a2b-sparse-z8-w4-v1"
	benchmarkWorkloadID      = "uint8-0to255-twice"
	benchmarkPackingID       = "n65536-cslots2048-zslots512-w4"
	benchmarkOutputContainer = "two-ciphertexts-low4-high4"
	benchmarkRepeats         = 5
)

func canonicalInput() []uint8 {
	words := make([]uint8, 512)
	for index := range words {
		words[index] = uint8(index % 256)
	}
	return words
}

func countBitMismatches(words []uint8, got [][8]uint8) uint64 {
	count := len(words)
	if len(got) < count {
		count = len(got)
	}
	var mismatches uint64
	for wordIndex := 0; wordIndex < count; wordIndex++ {
		for bitIndex := 0; bitIndex < 8; bitIndex++ {
			want := (words[wordIndex] >> bitIndex) & 1
			if got[wordIndex][bitIndex] != want {
				mismatches++
			}
		}
	}
	if len(words) > count {
		mismatches += uint64(len(words)-count) * 8
	}
	if len(got) > count {
		mismatches += uint64(len(got)-count) * 8
	}
	return mismatches
}

func canonicalArtifact(
	hostID string,
	setup ckksint.RouteBA2BSetupInfo,
	encryption ckksint.RouteBA2BPhaseInfo,
	warmup ckksint.RouteBA2BPhaseInfo,
	samples []uint64,
) (benchcmp.CanonicalArtifact, error) {
	if strings.TrimSpace(hostID) == "" {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("host_id is required")
	}
	if encryption.WallTime <= 0 || warmup.WallTime <= 0 || warmup.OnlineWallTime <= 0 ||
		warmup.PreparationWallTime <= 0 || warmup.WallTime < warmup.OnlineWallTime ||
		warmup.PreparationWallTime > warmup.WallTime-warmup.OnlineWallTime {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark requires complete encryption and warmup timing")
	}
	setupWallTime := setup.ParameterArtifactWallTime + setup.KeyGenerationWallTime +
		setup.ServerInstallWallTime + encryption.WallTime + warmup.WallTime - warmup.OnlineWallTime
	if setupWallTime <= 0 || len(samples) != benchmarkRepeats {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark requires positive setup time and five nonzero samples")
	}
	for _, sample := range samples {
		if sample == 0 {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark requires positive setup time and five nonzero samples")
		}
	}
	return benchcmp.CanonicalArtifact{
		Schema:                  benchcmp.CanonicalBenchmarkSchema,
		Implementation:          "lattigo-route-b",
		HostID:                  strings.TrimSpace(hostID),
		Protocol:                benchmarkProtocol,
		WorkloadID:              benchmarkWorkloadID,
		PackingID:               benchmarkPackingID,
		OutputContainer:         benchmarkOutputContainer,
		WordBits:                8,
		RingDimension:           65_536,
		PackingSlots:            2_048,
		UsefulWords:             512,
		Threads:                 1,
		TimingScope:             benchcmp.TimingScopePreparedOnline,
		SetupNanoseconds:        uint64(setupWallTime / time.Nanosecond),
		WarmupCount:             1,
		WarmupVerified:          true,
		RepeatCount:             benchmarkRepeats,
		TimedSamplesNanoseconds: append([]uint64(nil), samples...),
		MismatchCount:           0,
		VerifiedEvaluations:     benchmarkRepeats,
	}, nil
}

func runCanonicalBenchmark(hostID string) (benchcmp.CanonicalArtifact, error) {
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	return runCanonicalBenchmarkWithFactory(hostID, newSession)
}

func runCanonicalBenchmarkWithFactory(hostID string, factory sessionFactory) (benchcmp.CanonicalArtifact, error) {
	session, setup, err := factory()
	if err != nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("create canonical Route-B A2B session: %w", err)
	}
	defer session.close()

	words := canonicalInput()
	input, encryption, err := session.encrypt(words)
	if err != nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("encrypt canonical input: %w", err)
	}

	warmupOutput, warmupInfo, err := session.evaluate(input)
	if err != nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate warmup: %w", err)
	}
	if warmupInfo.OnlineWallTime <= 0 {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate warmup: online wall time must be positive")
	}
	warmupBits, err := session.decrypt(warmupOutput)
	if err != nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("decrypt warmup: %w", err)
	}
	if mismatches := countBitMismatches(words, warmupBits); mismatches != 0 {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("verify warmup: mismatch_count=%d", mismatches)
	}

	samples := make([]uint64, benchmarkRepeats)
	for repeat := 0; repeat < benchmarkRepeats; repeat++ {
		output, phase, err := session.evaluate(input)
		if err != nil {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate repeat %d: %w", repeat+1, err)
		}
		if phase.OnlineWallTime <= 0 {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate repeat %d: online wall time must be positive", repeat+1)
		}
		samples[repeat] = uint64(phase.OnlineWallTime / time.Nanosecond)

		bits, err := session.decrypt(output)
		if err != nil {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("decrypt repeat %d: %w", repeat+1, err)
		}
		if mismatches := countBitMismatches(words, bits); mismatches != 0 {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("verify repeat %d: mismatch_count=%d", repeat+1, mismatches)
		}
	}

	artifact, err := canonicalArtifact(hostID, setup, encryption, warmupInfo, samples)
	if err != nil {
		return benchcmp.CanonicalArtifact{}, err
	}
	completedAt := time.Now().UTC()
	artifact.CompletedAt = &completedAt
	return artifact, nil
}

func newSession() (sessionOps, ckksint.RouteBA2BSetupInfo, error) {
	client, server, setup, err := ckksint.NewCanonicalRouteBA2B()
	if err != nil {
		return sessionOps{}, ckksint.RouteBA2BSetupInfo{}, err
	}
	return sessionOps{
		close: server.Close,
		encrypt: func(words []uint8) (*ckksint.RouteBA2BEncryptedInput, ckksint.RouteBA2BPhaseInfo, error) {
			return client.EncryptA2B(words)
		},
		evaluate: server.EvaluateA2B,
		decrypt: func(output *ckksint.RouteBA2BEncryptedOutput) ([][8]uint8, error) {
			bits, _, err := client.DecryptA2B(output)
			return bits, err
		},
	}, setup, nil
}

func run(args []string, stderr io.Writer, benchmark benchmarkFunc, writeArtifact artifactWriter) int {
	flags := flag.NewFlagSet("benchmark-ckksint-a2b", flag.ContinueOnError)
	flags.SetOutput(stderr)
	hostID := flags.String("host-id", "", "stable identifier for the benchmark host")
	outputPath := flags.String("out", "", "output JSON artifact path")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if strings.TrimSpace(*hostID) == "" {
		_, _ = fmt.Fprintln(stderr, "benchmark-ckksint-a2b: -host-id is required")
		return 2
	}
	if strings.TrimSpace(*outputPath) == "" {
		_, _ = fmt.Fprintln(stderr, "benchmark-ckksint-a2b: -out is required")
		return 2
	}
	artifact, err := benchmark(strings.TrimSpace(*hostID))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "benchmark-ckksint-a2b: %v\n", err)
		return 1
	}
	if err := writeArtifact(*outputPath, artifact); err != nil {
		_, _ = fmt.Fprintf(stderr, "benchmark-ckksint-a2b: %v\n", err)
		return 1
	}
	return 0
}

func writeCanonicalArtifact(path string, artifact benchcmp.CanonicalArtifact) error {
	payload, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal benchmark artifact: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := benchcmp.ParseCanonical(bytes.NewReader(payload), path); err != nil {
		return fmt.Errorf("validate benchmark artifact: %w", err)
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return fmt.Errorf("write benchmark artifact %q: %w", path, err)
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr, runCanonicalBenchmark, writeCanonicalArtifact))
}
