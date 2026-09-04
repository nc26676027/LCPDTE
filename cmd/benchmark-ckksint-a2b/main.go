package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/nc26676027/LCPDTE/ckksint"
	"github.com/nc26676027/LCPDTE/internal/benchcmp"
)

type benchmarkFunc func(hostID string) (benchcmp.CanonicalArtifact, error)
type artifactWriter func(path string, artifact benchcmp.CanonicalArtifact) error
type sessionFactory func() (sessionOps, ckksint.GaoFullPackedA2BSetupInfo, error)
type executionMetadataReader func() (benchmarkExecutionMetadata, error)

type benchmarkExecutionMetadata struct {
	SourceRevision string
	SourceModified bool
	Runtime        string
	Compiler       string
	BuildProfile   string
	OS             string
	Arch           string
}

type sessionOps struct {
	close    func()
	encrypt  func([]uint8) (*ckksint.GaoFullPackedA2BEncryptedInput, ckksint.GaoFullPackedA2BPhaseInfo, error)
	evaluate func(*ckksint.GaoFullPackedA2BEncryptedInput) (*ckksint.GaoFullPackedA2BEncryptedOutput, ckksint.GaoFullPackedA2BPhaseInfo, error)
	decrypt  func(*ckksint.GaoFullPackedA2BEncryptedOutput) ([][8]uint8, error)
}

const (
	benchmarkProtocol        = "gao-a2b-full-z8-w4-v1"
	benchmarkWorkloadID      = "uint8-0to255-x32"
	benchmarkPackingID       = "n65536-cslots32768-zslots8192-w4"
	benchmarkOutputContainer = "two-ciphertexts-low4-high4"
	benchmarkRepeats         = 5
)

func canonicalInput() []uint8 {
	words := make([]uint8, 8_192)
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
	setup ckksint.GaoFullPackedA2BSetupInfo,
	encryption ckksint.GaoFullPackedA2BPhaseInfo,
	warmup ckksint.GaoFullPackedA2BPhaseInfo,
	samples []uint64,
	execution benchmarkExecutionMetadata,
) (benchcmp.CanonicalArtifact, error) {
	if strings.TrimSpace(hostID) == "" {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("host_id is required")
	}
	if encryption.WallTime <= 0 || warmup.WallTime <= 0 || warmup.OnlineWallTime <= 0 ||
		warmup.PreparationWallTime != 0 || warmup.WallTime < warmup.OnlineWallTime {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark requires complete encryption and warmup timing")
	}
	setupWallTime := setup.ParameterWallTime + setup.KeyGenerationWallTime +
		setup.ServerConstructionWallTime + encryption.WallTime
	if setupWallTime <= 0 || len(samples) != benchmarkRepeats {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark requires positive setup time and five nonzero samples")
	}
	for _, sample := range samples {
		if sample == 0 {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark requires positive setup time and five nonzero samples")
		}
	}
	parameters, err := canonicalParametersFromSetup(setup.Parameters)
	if err != nil {
		return benchcmp.CanonicalArtifact{}, err
	}
	if execution.SourceModified {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark requires a clean Lattigo source revision")
	}
	for field, value := range map[string]string{
		"source_revision": execution.SourceRevision,
		"runtime":         execution.Runtime,
		"compiler":        execution.Compiler,
		"build_profile":   execution.BuildProfile,
		"os":              execution.OS,
		"arch":            execution.Arch,
	} {
		if strings.TrimSpace(value) == "" {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark execution metadata %s is required", field)
		}
	}
	return benchcmp.CanonicalArtifact{
		Schema:                  benchcmp.CanonicalBenchmarkSchema,
		Implementation:          "lattigo-gao-a2b-full",
		HostID:                  strings.TrimSpace(hostID),
		EncryptionMode:          setup.Parameters.EncryptionMode,
		FactorStorageMode:       setup.Parameters.FactorStorageMode,
		ScaleSchedule:           setup.Parameters.ScaleSchedule,
		BackendBSGSPlan:         benchcmp.LattigoBackendBSGSPlan,
		SourceRevision:          strings.TrimSpace(execution.SourceRevision),
		SourceModified:          execution.SourceModified,
		Runtime:                 strings.TrimSpace(execution.Runtime),
		Compiler:                strings.TrimSpace(execution.Compiler),
		BuildProfile:            strings.TrimSpace(execution.BuildProfile),
		OS:                      strings.TrimSpace(execution.OS),
		Arch:                    strings.TrimSpace(execution.Arch),
		Protocol:                benchmarkProtocol,
		WorkloadID:              benchmarkWorkloadID,
		PackingID:               benchmarkPackingID,
		OutputContainer:         benchmarkOutputContainer,
		WordBits:                8,
		RingDimension:           uint32(setup.Parameters.RingDimension),
		PackingSlots:            uint32(setup.Parameters.PackingSlots),
		UsefulWords:             uint32(setup.Parameters.UsefulWords),
		Parameters:              parameters,
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

func canonicalParametersFromSetup(info ckksint.GaoFullPackedA2BParameterInfo) (*benchcmp.GaoParameterSemantics, error) {
	if info.STCLogBSGSRatio != 2 || info.CTSLogBSGSRatio != 2 || info.SpecialB0LogBSGSRatio != 2 {
		return nil, fmt.Errorf(
			"benchmark live Lattigo BSGS ratios changed: stc=%d cts=%d special_b0=%d",
			info.STCLogBSGSRatio, info.CTSLogBSGSRatio, info.SpecialB0LogBSGSRatio,
		)
	}
	parameters := &benchcmp.GaoParameterSemantics{
		ComparisonScope:                benchcmp.GaoParameterComparisonScope,
		QModuliCount:                   uint32(info.QModuliCount),
		QLog2Aggregate:                 uint32(info.QLog2Aggregate),
		PModuliCount:                   uint32(info.PModuliCount),
		PLog2Aggregate:                 uint32(info.PLog2Aggregate),
		ScalingModulusBits:             uint32(info.ScalingModulusBits),
		FirstModulusBits:               uint32(info.FirstModulusBits),
		MultiplicativeDepth:            uint32(info.MultiplicativeDepth),
		LargeDigits:                    uint32(info.LargeDigits),
		EphemeralSecretHammingWeight:   uint32(info.EphemeralSecretHammingWeight),
		LevelBudget:                    [2]uint32{uint32(info.LevelBudget[0]), uint32(info.LevelBudget[1])},
		OpenFHERequestedBSGSDimensions: [2]uint32{uint32(info.OpenFHERequestedBSGSDimensions[0]), uint32(info.OpenFHERequestedBSGSDimensions[1])},
		ChunkWidth:                     uint32(info.ChunkWidth),
		CutoffBits:                     int32(info.CutoffBits),
	}
	if *parameters != *benchcmp.CanonicalGaoParameters() {
		return nil, fmt.Errorf("benchmark live Gao parameters differ from the admitted OpenFHE contract: got=%+v", *parameters)
	}
	if info.RingDimension != 65_536 || info.PackingSlots != 32_768 || info.UsefulWords != 8_192 {
		return nil, fmt.Errorf(
			"benchmark live packing differs from the admitted OpenFHE contract: ring=%d slots=%d words=%d",
			info.RingDimension, info.PackingSlots, info.UsefulWords,
		)
	}
	if info.EncryptionMode != benchcmp.EncryptionModePublicKey ||
		info.FactorStorageMode != benchcmp.LattigoFactorStorageMode ||
		info.ScaleSchedule != benchcmp.LattigoScaleSchedule {
		return nil, fmt.Errorf(
			"benchmark live execution profile changed: encryption=%q factor_storage=%q scale_schedule=%q",
			info.EncryptionMode, info.FactorStorageMode, info.ScaleSchedule,
		)
	}
	return parameters, nil
}

func currentExecutionMetadata() (benchmarkExecutionMetadata, error) {
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return benchmarkExecutionMetadata{}, fmt.Errorf("read Go build provenance")
	}
	settings := make(map[string]string, len(build.Settings))
	for _, setting := range build.Settings {
		settings[setting.Key] = setting.Value
	}
	revision := strings.TrimSpace(settings["vcs.revision"])
	if revision == "" {
		return benchmarkExecutionMetadata{}, fmt.Errorf("Go build is missing vcs.revision")
	}
	modified, err := parseBuildBool(settings["vcs.modified"])
	if err != nil {
		return benchmarkExecutionMetadata{}, err
	}
	goamd64 := strings.TrimSpace(settings["GOAMD64"])
	if goamd64 == "" {
		goamd64 = "unspecified"
	}
	return benchmarkExecutionMetadata{
		SourceRevision: revision,
		SourceModified: modified,
		Runtime:        build.GoVersion,
		Compiler:       runtime.Compiler,
		BuildProfile: fmt.Sprintf(
			"GOOS=%s;GOARCH=%s;GOAMD64=%s;GOMAXPROCS=1",
			runtime.GOOS, runtime.GOARCH, goamd64,
		),
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}, nil
}

func parseBuildBool(value string) (bool, error) {
	switch strings.TrimSpace(value) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("Go build has invalid vcs.modified=%q", value)
	}
}

func runCanonicalBenchmark(hostID string) (benchcmp.CanonicalArtifact, error) {
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	return runCanonicalBenchmarkWithFactory(hostID, newSession, currentExecutionMetadata)
}

func runCanonicalBenchmarkWithFactory(
	hostID string,
	factory sessionFactory,
	readMetadata executionMetadataReader,
) (benchcmp.CanonicalArtifact, error) {
	execution, err := readMetadata()
	if err != nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("read benchmark execution metadata: %w", err)
	}
	if execution.SourceModified {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark requires a clean Lattigo source revision")
	}
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
	if warmupInfo.PreparationWallTime != 0 || warmupInfo.OnlineWallTime <= 0 ||
		warmupInfo.WallTime <= 0 || warmupInfo.WallTime < warmupInfo.OnlineWallTime {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate warmup: prepared call timing is invalid")
	}
	warmupBits, err := session.decrypt(warmupOutput)
	if err != nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("decrypt warmup: %w", err)
	}
	if mismatches := countBitMismatches(words, warmupBits); mismatches != 0 {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("verify warmup: mismatch_count=%d", mismatches)
	}
	warmupOutput = nil
	warmupBits = nil
	runtime.GC()
	var profileFile *os.File
	if profilePath := strings.TrimSpace(os.Getenv("LCPDTE_GAO_CPU_PROFILE")); profilePath != "" {
		profileFile, err = os.Create(profilePath)
		if err != nil {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("create CPU profile: %w", err)
		}
		if err = pprof.StartCPUProfile(profileFile); err != nil {
			_ = profileFile.Close()
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("start CPU profile: %w", err)
		}
		defer func() {
			pprof.StopCPUProfile()
			_ = profileFile.Close()
		}()
	}

	samples := make([]uint64, benchmarkRepeats)
	for repeat := 0; repeat < benchmarkRepeats; repeat++ {
		output, phase, err := session.evaluate(input)
		if err != nil {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate repeat %d: %w", repeat+1, err)
		}
		if phase.PreparationWallTime != 0 || phase.OnlineWallTime <= 0 ||
			phase.WallTime <= 0 || phase.WallTime < phase.OnlineWallTime {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate repeat %d: prepared call timing is invalid", repeat+1)
		}
		samples[repeat] = uint64(phase.WallTime / time.Nanosecond)

		bits, err := session.decrypt(output)
		if err != nil {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("decrypt repeat %d: %w", repeat+1, err)
		}
		if mismatches := countBitMismatches(words, bits); mismatches != 0 {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("verify repeat %d: mismatch_count=%d", repeat+1, mismatches)
		}
	}

	artifact, err := canonicalArtifact(hostID, setup, encryption, warmupInfo, samples, execution)
	if err != nil {
		return benchcmp.CanonicalArtifact{}, err
	}
	completedAt := time.Now().UTC()
	artifact.CompletedAt = &completedAt
	return artifact, nil
}

func newSession() (sessionOps, ckksint.GaoFullPackedA2BSetupInfo, error) {
	client, server, setup, err := ckksint.NewGaoFullPackedA2B()
	if err != nil {
		return sessionOps{}, ckksint.GaoFullPackedA2BSetupInfo{}, err
	}
	return sessionOps{
		close: server.Close,
		encrypt: func(words []uint8) (*ckksint.GaoFullPackedA2BEncryptedInput, ckksint.GaoFullPackedA2BPhaseInfo, error) {
			return client.EncryptA2B(words)
		},
		evaluate: server.EvaluateA2B,
		decrypt: func(output *ckksint.GaoFullPackedA2BEncryptedOutput) ([][8]uint8, error) {
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
