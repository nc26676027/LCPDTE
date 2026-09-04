package ckksint

import (
	"fmt"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureeval"
)

// GaoFullPackedA2BMaxWords is the canonical capacity of one Gao-compatible
// N=65536, logSlots=15 ciphertext.
const GaoFullPackedA2BMaxWords = secureeval.GaoFullPackedA2BMaxWords

// GaoFullPackedA2BSetupInfo reports work completed before prepared-online
// evaluation begins. ServerConstructionWallTime includes DFT/polynomial
// preparation and evaluation-key generation. ClientConstructionWallTime
// includes encoder and final session-object assembly.
type GaoFullPackedA2BSetupInfo struct {
	ParameterWallTime          time.Duration
	KeyGenerationWallTime      time.Duration
	ServerConstructionWallTime time.Duration
	ClientConstructionWallTime time.Duration
	Parameters                 GaoFullPackedA2BParameterInfo
}

// GaoFullPackedA2BParameterInfo reports the live full-packing, modulus-chain,
// encryption, DFT residency, scale, and BSGS settings used by a session.
type GaoFullPackedA2BParameterInfo struct {
	RingDimension      int
	PackingSlots       int
	UsefulWords        int
	QModuliCount       int
	QLog2Aggregate     int
	PModuliCount       int
	PLog2Aggregate     int
	ScalingModulusBits int
	// FirstModulusBits is the canonical requested first-Q target. The generated
	// prime's actual size is reported separately by ActualFirstQModulusBits.
	FirstModulusBits               int
	ActualFirstQModulusBits        int
	QModuli                        []string
	PModuli                        []string
	QModuliBitLengths              []int
	PModuliBitLengths              []int
	MultiplicativeDepth            int
	LargeDigits                    int
	MainSecretDistribution         string
	MainSecretHammingWeight        int
	EphemeralSecretDistribution    string
	EphemeralSecretHammingWeight   int
	ErrorSampler                   string
	ErrorSigma                     float64
	ErrorConfiguredBound           float64
	ErrorEffectiveIntegerBound     int
	KeySwitchTechnique             string
	RNSDecompositionComponents     int
	BaseTwoDecomposition           int
	SecuritySelector               string
	SecurityEvidence               string
	LevelBudget                    [2]int
	OpenFHERequestedBSGSDimensions [2]int
	ChunkWidth                     int
	CutoffBits                     int
	STCLogBSGSRatio                int
	CTSLogBSGSRatio                int
	SpecialB0LogBSGSRatio          int
	EncryptionMode                 string
	FactorStorageMode              string
	ScaleSchedule                  string
}

// GaoFullPackedA2BPhaseInfo reports one client or server phase. For every
// evaluation, PreparationWallTime is zero and OnlineWallTime covers only the
// prepared homomorphic graph.
type GaoFullPackedA2BPhaseInfo struct {
	Phase               string
	WordCount           int
	WallTime            time.Duration
	PreparationWallTime time.Duration
	OnlineWallTime      time.Duration
	TraceDigest         string
}

// GaoFullPackedA2BClient owns encryption and decryption state for one session.
type GaoFullPackedA2BClient struct {
	inner *secureeval.GaoFullPackedA2BClient
}

// GaoFullPackedA2BServer owns the fully prepared evaluator for one session.
type GaoFullPackedA2BServer struct {
	inner *secureeval.GaoFullPackedA2BServer
}

// GaoFullPackedA2BEncryptedInput is an opaque, session-bound arithmetic input.
type GaoFullPackedA2BEncryptedInput struct {
	inner *secureeval.GaoFullPackedA2BEncryptedInput
}

// GaoFullPackedA2BEncryptedOutput is an opaque, session-bound low4/high4
// Boolean output pair.
type GaoFullPackedA2BEncryptedOutput struct {
	inner *secureeval.GaoFullPackedA2BEncryptedOutput
}

// NewGaoFullPackedA2B constructs a reusable Gao-compatible full-packed A2B
// client/server session. Setup is complete when this function returns.
func NewGaoFullPackedA2B() (
	*GaoFullPackedA2BClient,
	*GaoFullPackedA2BServer,
	GaoFullPackedA2BSetupInfo,
	error,
) {
	client, server, report, err := secureeval.NewGaoFullPackedA2BSession()
	if err != nil {
		return nil, nil, GaoFullPackedA2BSetupInfo{}, fmt.Errorf("ckksint: create Gao full-packed A2B session: %w", err)
	}
	return &GaoFullPackedA2BClient{inner: client}, &GaoFullPackedA2BServer{inner: server}, gaoFullPackedA2BSetupInfo(report), nil
}

func gaoFullPackedA2BSetupInfo(report secureeval.GaoFullPackedA2BSetupReport) GaoFullPackedA2BSetupInfo {
	return GaoFullPackedA2BSetupInfo{
		ParameterWallTime:          report.ParameterWallTime,
		KeyGenerationWallTime:      report.KeyGenerationWallTime,
		ServerConstructionWallTime: report.ServerConstructionWallTime,
		ClientConstructionWallTime: report.ClientConstructionWallTime,
		Parameters:                 gaoFullPackedA2BParameterInfo(report.Parameters),
	}
}

func gaoFullPackedA2BParameterInfo(report secureeval.GaoFullPackedA2BParameterReport) GaoFullPackedA2BParameterInfo {
	return GaoFullPackedA2BParameterInfo{
		RingDimension:                  report.RingDimension,
		PackingSlots:                   report.PackingSlots,
		UsefulWords:                    report.UsefulWords,
		QModuliCount:                   report.QModuliCount,
		QLog2Aggregate:                 report.QLog2Aggregate,
		PModuliCount:                   report.PModuliCount,
		PLog2Aggregate:                 report.PLog2Aggregate,
		ScalingModulusBits:             report.ScalingModulusBits,
		FirstModulusBits:               report.FirstModulusBits,
		ActualFirstQModulusBits:        report.ActualFirstQModulusBits,
		QModuli:                        append([]string(nil), report.QModuli...),
		PModuli:                        append([]string(nil), report.PModuli...),
		QModuliBitLengths:              append([]int(nil), report.QModuliBitLengths...),
		PModuliBitLengths:              append([]int(nil), report.PModuliBitLengths...),
		MultiplicativeDepth:            report.MultiplicativeDepth,
		LargeDigits:                    report.LargeDigits,
		MainSecretDistribution:         report.MainSecretDistribution,
		MainSecretHammingWeight:        report.MainSecretHammingWeight,
		EphemeralSecretDistribution:    report.EphemeralSecretDistribution,
		EphemeralSecretHammingWeight:   report.EphemeralSecretHammingWeight,
		ErrorSampler:                   report.ErrorSampler,
		ErrorSigma:                     report.ErrorSigma,
		ErrorConfiguredBound:           report.ErrorConfiguredBound,
		ErrorEffectiveIntegerBound:     report.ErrorEffectiveIntegerBound,
		KeySwitchTechnique:             report.KeySwitchTechnique,
		RNSDecompositionComponents:     report.RNSDecompositionComponents,
		BaseTwoDecomposition:           report.BaseTwoDecomposition,
		SecuritySelector:               report.SecuritySelector,
		SecurityEvidence:               report.SecurityEvidence,
		LevelBudget:                    report.LevelBudget,
		OpenFHERequestedBSGSDimensions: report.OpenFHERequestedBSGSDimensions,
		ChunkWidth:                     report.ChunkWidth,
		CutoffBits:                     report.CutoffBits,
		STCLogBSGSRatio:                report.STCLogBSGSRatio,
		CTSLogBSGSRatio:                report.CTSLogBSGSRatio,
		SpecialB0LogBSGSRatio:          report.SpecialB0LogBSGSRatio,
		EncryptionMode:                 report.EncryptionMode,
		FactorStorageMode:              report.FactorStorageMode,
		ScaleSchedule:                  report.ScaleSchedule,
	}
}

// EncryptA2B encrypts 1..8192 uint8 words. Short batches are zero-padded in
// unused physical slots and trimmed back to their original length at decrypt.
func (client *GaoFullPackedA2BClient) EncryptA2B(
	words []uint8,
) (*GaoFullPackedA2BEncryptedInput, GaoFullPackedA2BPhaseInfo, error) {
	if client == nil || client.inner == nil {
		return nil, GaoFullPackedA2BPhaseInfo{}, fmt.Errorf("ckksint: Gao full-packed A2B client is nil")
	}
	input, report, err := client.inner.EncryptA2B(words)
	if err != nil {
		return nil, GaoFullPackedA2BPhaseInfo{}, fmt.Errorf("ckksint: encrypt Gao full-packed A2B input: %w", err)
	}
	return &GaoFullPackedA2BEncryptedInput{inner: input}, gaoFullPackedA2BPhaseInfo(report), nil
}

// EvaluateA2B executes Gao's complete two-round 8-bit A2B graph. Calls are
// serialized and reuse the evaluator prepared by NewGaoFullPackedA2B.
func (server *GaoFullPackedA2BServer) EvaluateA2B(
	input *GaoFullPackedA2BEncryptedInput,
) (*GaoFullPackedA2BEncryptedOutput, GaoFullPackedA2BPhaseInfo, error) {
	if server == nil || server.inner == nil {
		return nil, GaoFullPackedA2BPhaseInfo{}, fmt.Errorf("ckksint: Gao full-packed A2B server is nil")
	}
	if input == nil || input.inner == nil {
		return nil, GaoFullPackedA2BPhaseInfo{}, fmt.Errorf("ckksint: Gao full-packed A2B encrypted input is nil")
	}
	output, report, err := server.inner.EvaluateA2B(input.inner)
	if err != nil {
		return nil, GaoFullPackedA2BPhaseInfo{}, fmt.Errorf("ckksint: evaluate Gao full-packed A2B input: %w", err)
	}
	return &GaoFullPackedA2BEncryptedOutput{inner: output}, gaoFullPackedA2BPhaseInfo(report), nil
}

// DecryptA2B returns one LSB-first eight-bit vector per input word.
func (client *GaoFullPackedA2BClient) DecryptA2B(
	output *GaoFullPackedA2BEncryptedOutput,
) ([][8]uint8, GaoFullPackedA2BPhaseInfo, error) {
	if client == nil || client.inner == nil {
		return nil, GaoFullPackedA2BPhaseInfo{}, fmt.Errorf("ckksint: Gao full-packed A2B client is nil")
	}
	if output == nil || output.inner == nil {
		return nil, GaoFullPackedA2BPhaseInfo{}, fmt.Errorf("ckksint: Gao full-packed A2B encrypted output is nil")
	}
	bits, report, err := client.inner.DecryptA2B(output.inner)
	if err != nil {
		return nil, GaoFullPackedA2BPhaseInfo{}, fmt.Errorf("ckksint: decrypt Gao full-packed A2B output: %w", err)
	}
	return bits, gaoFullPackedA2BPhaseInfo(report), nil
}

// Close releases the server-side evaluator. It is safe to call repeatedly.
func (server *GaoFullPackedA2BServer) Close() {
	if server == nil || server.inner == nil {
		return
	}
	server.inner.Close()
	server.inner = nil
}

func gaoFullPackedA2BPhaseInfo(report secureeval.GaoFullPackedA2BPhaseReport) GaoFullPackedA2BPhaseInfo {
	return GaoFullPackedA2BPhaseInfo{
		Phase: report.Phase, WordCount: report.WordCount, WallTime: report.WallTime,
		PreparationWallTime: report.PreparationWallTime, OnlineWallTime: report.OnlineWallTime,
		TraceDigest: report.TraceDigest,
	}
}
