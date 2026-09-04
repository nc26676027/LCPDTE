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
	"runtime/metrics"
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

type lattigoAcceptanceRuntime struct {
	BuildGOAMD64       string
	EnvironmentGOAMD64 string
	GOMAXPROCSValue    string
	GOGCValue          string
	GOMEMLIMITValue    string
	PostWarmupGCValue  string
	CPUProfileValue    string
	RuntimeGOMAXPROCS  int
	RuntimeGOGC        uint64
	RuntimeMemoryLimit uint64
	GOOS               string
	GOARCH             string
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
		setup.ServerConstructionWallTime + setup.ClientConstructionWallTime + encryption.WallTime
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
	nativeParameters, err := nativeParametersFromSetup(setup.Parameters)
	if err != nil {
		return benchcmp.CanonicalArtifact{}, err
	}
	if err = validateLattigoExecutionMetadata(execution); err != nil {
		return benchcmp.CanonicalArtifact{}, err
	}
	artifact := benchcmp.CanonicalArtifact{
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
		NativeParameters:        nativeParameters,
		Threads:                 1,
		TimingScope:             benchcmp.TimingScopePreparedOnline,
		SetupNanoseconds:        uint64(setupWallTime / time.Nanosecond),
		WarmupCount:             1,
		WarmupVerified:          true,
		RepeatCount:             benchmarkRepeats,
		TimedSamplesNanoseconds: append([]uint64(nil), samples...),
		MismatchCount:           0,
		VerifiedEvaluations:     benchmarkRepeats,
	}
	payload, err := json.Marshal(artifact)
	if err != nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("marshal generated benchmark artifact: %w", err)
	}
	if _, err = benchcmp.ParseCanonical(bytes.NewReader(payload), "generated-lattigo-artifact"); err != nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("validate generated benchmark artifact: %w", err)
	}
	return artifact, nil
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
		MainSecretHammingWeight:        uint32(info.MainSecretHammingWeight),
		EphemeralSecretHammingWeight:   uint32(info.EphemeralSecretHammingWeight),
		KeySwitchRNSComponents:         uint32(info.RNSDecompositionComponents),
		KeySwitchBaseTwoDecomposition:  uint32(info.BaseTwoDecomposition),
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

func nativeParametersFromSetup(info ckksint.GaoFullPackedA2BParameterInfo) (*benchcmp.NativeParameters, error) {
	qBits, err := uint32SliceFromInts("QModuliBitLengths", info.QModuliBitLengths)
	if err != nil {
		return nil, err
	}
	pBits, err := uint32SliceFromInts("PModuliBitLengths", info.PModuliBitLengths)
	if err != nil {
		return nil, err
	}
	actualFirst, err := uint32FromInt("ActualFirstQModulusBits", info.ActualFirstQModulusBits)
	if err != nil {
		return nil, err
	}
	mainWeight, err := uint32FromInt("MainSecretHammingWeight", info.MainSecretHammingWeight)
	if err != nil {
		return nil, err
	}
	ephemeralWeight, err := uint32FromInt("EphemeralSecretHammingWeight", info.EphemeralSecretHammingWeight)
	if err != nil {
		return nil, err
	}
	effectiveBound, err := uint32FromInt("ErrorEffectiveIntegerBound", info.ErrorEffectiveIntegerBound)
	if err != nil {
		return nil, err
	}
	rnsComponents, err := uint32FromInt("RNSDecompositionComponents", info.RNSDecompositionComponents)
	if err != nil {
		return nil, err
	}
	baseTwo, err := uint32FromInt("BaseTwoDecomposition", info.BaseTwoDecomposition)
	if err != nil {
		return nil, err
	}
	configuredBound := info.ErrorConfiguredBound
	return &benchcmp.NativeParameters{
		ActualFirstQModulusBits:       actualFirst,
		MainSecretDistribution:        info.MainSecretDistribution,
		MainSecretHammingWeight:       mainWeight,
		EphemeralSecretDistribution:   info.EphemeralSecretDistribution,
		EphemeralSecretHammingWeight:  ephemeralWeight,
		ErrorSampler:                  info.ErrorSampler,
		ErrorSigma:                    info.ErrorSigma,
		ErrorConfiguredBound:          &configuredBound,
		ErrorEffectiveIntegerBound:    effectiveBound,
		KeySwitchTechnique:            info.KeySwitchTechnique,
		KeySwitchRNSComponents:        rnsComponents,
		KeySwitchBaseTwoDecomposition: baseTwo,
		SecuritySelector:              info.SecuritySelector,
		SecurityEvidence:              info.SecurityEvidence,
		QModuli:                       append([]string(nil), info.QModuli...),
		QModuliBitLengths:             qBits,
		PModuli:                       append([]string(nil), info.PModuli...),
		PModuliBitLengths:             pBits,
	}, nil
}

func uint32SliceFromInts(name string, values []int) ([]uint32, error) {
	result := make([]uint32, len(values))
	for index, value := range values {
		converted, err := uint32FromInt(fmt.Sprintf("%s[%d]", name, index), value)
		if err != nil {
			return nil, err
		}
		result[index] = converted
	}
	return result, nil
}

func uint32FromInt(name string, value int) (uint32, error) {
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		return 0, fmt.Errorf("benchmark live %s=%d cannot be represented as uint32", name, value)
	}
	return uint32(value), nil
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
		return benchmarkExecutionMetadata{}, fmt.Errorf("Go build is missing vcs.revision; build the acceptance executable with go build (go run is not admitted)")
	}
	modified, err := parseBuildBool(settings["vcs.modified"])
	if err != nil {
		return benchmarkExecutionMetadata{}, err
	}
	runtimeGOGC, runtimeMemoryLimit, err := currentRuntimeGCLimits()
	if err != nil {
		return benchmarkExecutionMetadata{}, err
	}
	acceptance := lattigoAcceptanceRuntime{
		BuildGOAMD64:       strings.TrimSpace(settings["GOAMD64"]),
		EnvironmentGOAMD64: strings.TrimSpace(os.Getenv("GOAMD64")),
		GOMAXPROCSValue:    strings.TrimSpace(os.Getenv("GOMAXPROCS")),
		GOGCValue:          strings.TrimSpace(os.Getenv("GOGC")),
		GOMEMLIMITValue:    strings.TrimSpace(os.Getenv("GOMEMLIMIT")),
		PostWarmupGCValue:  strings.TrimSpace(os.Getenv("POST_WARMUP_GC")),
		CPUProfileValue:    strings.TrimSpace(os.Getenv("LCPDTE_GAO_CPU_PROFILE")),
		RuntimeGOMAXPROCS:  runtime.GOMAXPROCS(0),
		RuntimeGOGC:        runtimeGOGC,
		RuntimeMemoryLimit: runtimeMemoryLimit,
		GOOS:               runtime.GOOS,
		GOARCH:             runtime.GOARCH,
	}
	if err = validateLattigoAcceptanceRuntime(acceptance); err != nil {
		return benchmarkExecutionMetadata{}, err
	}
	return benchmarkExecutionMetadata{
		SourceRevision: revision,
		SourceModified: modified,
		Runtime:        build.GoVersion,
		Compiler:       runtime.Compiler,
		BuildProfile:   acceptance.lattigoBuildProfile(),
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
	}, nil
}

func currentRuntimeGCLimits() (gogc, memoryLimit uint64, err error) {
	samples := []metrics.Sample{
		{Name: "/gc/gogc:percent"},
		{Name: "/gc/gomemlimit:bytes"},
	}
	metrics.Read(samples)
	for index := range samples {
		if samples[index].Value.Kind() != metrics.KindUint64 {
			return 0, 0, fmt.Errorf("Go runtime metric %s is unavailable", samples[index].Name)
		}
	}
	return samples[0].Value.Uint64(), samples[1].Value.Uint64(), nil
}

func (state lattigoAcceptanceRuntime) lattigoBuildProfile() string {
	cpuProfile := "off"
	if state.CPUProfileValue != "" {
		cpuProfile = "on"
	}
	return fmt.Sprintf(
		"GOOS=%s;GOARCH=%s;GOAMD64=%s;GOMAXPROCS=%s;GOGC=%s;GOMEMLIMIT=%s;POST_WARMUP_GC=%s;CPU_PROFILE=%s",
		state.GOOS, state.GOARCH, state.BuildGOAMD64, state.GOMAXPROCSValue,
		state.GOGCValue, state.GOMEMLIMITValue, state.PostWarmupGCValue, cpuProfile,
	)
}

func validateLattigoAcceptanceRuntime(state lattigoAcceptanceRuntime) error {
	if state.BuildGOAMD64 != "v4" {
		return fmt.Errorf("embedded GOAMD64=%q, want v4", state.BuildGOAMD64)
	}
	if state.EnvironmentGOAMD64 != "v4" {
		return fmt.Errorf("GOAMD64=%q, want v4", state.EnvironmentGOAMD64)
	}
	if state.GOMAXPROCSValue != "1" || state.RuntimeGOMAXPROCS != 1 {
		return fmt.Errorf("GOMAXPROCS environment/runtime=%q/%d, want 1/1", state.GOMAXPROCSValue, state.RuntimeGOMAXPROCS)
	}
	if state.GOGCValue != "100" || state.RuntimeGOGC != 100 {
		return fmt.Errorf("GOGC environment/runtime=%q/%d, want 100/100", state.GOGCValue, state.RuntimeGOGC)
	}
	const memoryLimit = uint64(20 * 1024 * 1024 * 1024)
	if state.GOMEMLIMITValue != "20GiB" || state.RuntimeMemoryLimit != memoryLimit {
		return fmt.Errorf(
			"GOMEMLIMIT environment/runtime=%q/%d, want 20GiB/%d",
			state.GOMEMLIMITValue, state.RuntimeMemoryLimit, memoryLimit,
		)
	}
	if state.PostWarmupGCValue != "on" {
		return fmt.Errorf("POST_WARMUP_GC=%q, want on", state.PostWarmupGCValue)
	}
	if state.CPUProfileValue != "" {
		return fmt.Errorf("LCPDTE_GAO_CPU_PROFILE must be empty for CPU_PROFILE=off")
	}
	if state.GOOS != "linux" {
		return fmt.Errorf("GOOS=%q, want linux", state.GOOS)
	}
	if state.GOARCH != "amd64" {
		return fmt.Errorf("GOARCH=%q, want amd64", state.GOARCH)
	}
	if got := state.lattigoBuildProfile(); got != benchcmp.LattigoAcceptanceBuildProfile {
		return fmt.Errorf("build_profile=%q, want %q", got, benchcmp.LattigoAcceptanceBuildProfile)
	}
	return nil
}

func validateLattigoExecutionMetadata(execution benchmarkExecutionMetadata) error {
	if execution.SourceModified {
		return fmt.Errorf("benchmark requires a clean Lattigo source revision")
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
			return fmt.Errorf("benchmark execution metadata %s is required", field)
		}
	}
	if execution.BuildProfile != benchcmp.LattigoAcceptanceBuildProfile {
		return fmt.Errorf("benchmark execution metadata build_profile=%q, want %q", execution.BuildProfile, benchcmp.LattigoAcceptanceBuildProfile)
	}
	if execution.Compiler != "gc" || !strings.HasPrefix(execution.Runtime, "go1.") ||
		execution.OS != "linux" || execution.Arch != "amd64" {
		return fmt.Errorf(
			"benchmark execution metadata runtime/compiler/target=%q/%q/%s/%s is not the admitted Go linux/amd64 build",
			execution.Runtime, execution.Compiler, execution.OS, execution.Arch,
		)
	}
	return nil
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
	return runCanonicalBenchmarkWithFactory(hostID, newSession, currentExecutionMetadata, time.Now)
}

func runCanonicalBenchmarkWithFactory(
	hostID string,
	factory sessionFactory,
	readMetadata executionMetadataReader,
	now func() time.Time,
) (benchcmp.CanonicalArtifact, error) {
	if now == nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("benchmark clock is required")
	}
	execution, err := readMetadata()
	if err != nil {
		return benchcmp.CanonicalArtifact{}, fmt.Errorf("read benchmark execution metadata: %w", err)
	}
	if err = validateLattigoExecutionMetadata(execution); err != nil {
		return benchcmp.CanonicalArtifact{}, err
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
		callStarted := now()
		output, phase, err := session.evaluate(input)
		callWallTime := now().Sub(callStarted)
		if err != nil {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate repeat %d: %w", repeat+1, err)
		}
		if phase.PreparationWallTime != 0 || phase.OnlineWallTime <= 0 ||
			phase.WallTime <= 0 || phase.WallTime < phase.OnlineWallTime {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate repeat %d: prepared call timing is invalid", repeat+1)
		}
		if callWallTime <= 0 {
			return benchcmp.CanonicalArtifact{}, fmt.Errorf("evaluate repeat %d: public call wall time is invalid", repeat+1)
		}
		samples[repeat] = uint64(callWallTime / time.Nanosecond)

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
