package secureeval

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/securityparams"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	commonlintrans "github.com/tuneinsight/lattigo/v6/circuits/common/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	routeBA2BFirstRoundReportSchema      = "lcpdte-route-b-gao-a2b-first-round-report-v1"
	routeBA2BFirstRoundBSGSRatio         = 2
	routeBA2BFirstRoundWords             = 512
	routeBA2BFirstRoundSlots             = 2048
	routeBA2BFirstRoundKernelDigest      = "13ed99b7fc9321ce195a10d9fe297d17ea842b2ba0fd586c305b3a2e7e09e216"
	routeBA2BFirstRoundExpDigest         = "a960edc18c4c7dee294d0f452eb3ef377c1d2094dadc0a046f49a68902e36e4d"
	routeBA2BFirstRoundLUTDigest         = "f3aa5c55fa47acd6c5a0f96d362d442948c6b2999d3bd4a6061870d3d21564e3"
	routeBA2BFirstRoundPlanDigest        = "e77d1be0b7f08a7ef0b18eaefb1b8c8614d3eb203640d467e28752b846c2654d"
	routeBA2BFirstRoundSourceDigest      = "fbfccbd8e12142bcafc2bcf2326283506a76fbf2d9dbd27d74769e0866cc270f"
	routeBA2BFirstRoundMaskDigest        = "cef4d67cb95eb7a192a446d31340772ef23a7f2ea54615a7fb47bbc68901904a"
	routeBA2BFirstRoundScaleHex          = "0x1p+43"
	routeBA2BFirstRoundObservedScaleHex  = "0x1.0000000000000002f2901f1f8cf04128p+43"
	routeBA2BFirstRoundMaxScaleLog2Drift = 9.094947017729282e-13 // 2^-40
)

// RouteBA2BFirstRoundState is a JSON-safe, detached ciphertext boundary.
type RouteBA2BFirstRoundState struct {
	Stage      string `json:"stage"`
	Level      int    `json:"level"`
	Degree     int    `json:"degree"`
	LogRows    int    `json:"log_rows"`
	LogColumns int    `json:"log_columns"`
	ScaleHex   string `json:"scale_hex"`
	ScaleExact bool   `json:"scale_exact"`
}

// RouteBA2BFirstRoundReport proves the special-b0 -> mask -> STC -> observed
// MR0 -> Gao degree-46/R2 -> shared ID/MSB path. It is one A2B round, not the
// complete two-round 8-bit conversion.
type RouteBA2BFirstRoundReport struct {
	SchemaVersion                  string                               `json:"schema_version"`
	Claim                          string                               `json:"claim"`
	KernelProfileDigest            string                               `json:"kernel_profile_digest"`
	ExponentialArtifactDigest      string                               `json:"exponential_artifact_digest"`
	LUTTableDigest                 string                               `json:"lut_table_digest"`
	CapacityPlanDigest             string                               `json:"capacity_plan_digest"`
	TransformSourceDigest          string                               `json:"transform_source_digest"`
	MaskSourceDigest               string                               `json:"mask_source_digest"`
	TransformRotationIndexes       []int                                `json:"transform_rotation_indexes"`
	TransformGaloisElements        []uint64                             `json:"transform_galois_elements"`
	LogBabyStepGiantStepRatio      int                                  `json:"log_baby_step_giant_step_ratio"`
	LowN1                          int                                  `json:"low_n1"`
	HighN1                         int                                  `json:"high_n1"`
	ScaleNormalizationSource       string                               `json:"scale_normalization_source"`
	ScaleNormalizationTarget       string                               `json:"scale_normalization_target"`
	ScaleNormalizationAbsLog2      float64                              `json:"scale_normalization_abs_log2"`
	ScaleNormalizationBound        float64                              `json:"scale_normalization_bound"`
	ScaleNormalizationMetadataOnly bool                                 `json:"scale_normalization_metadata_only"`
	States                         []RouteBA2BFirstRoundState           `json:"states"`
	OperationCounts                homchain.GaoA2BKernelOperationCounts `json:"operation_counts"`
	WallNanoseconds                uint64                               `json:"wall_nanoseconds"`
	Digest                         string                               `json:"digest"`
}

func (report RouteBA2BFirstRoundReport) Validate() error {
	if report.SchemaVersion != routeBA2BFirstRoundReportSchema ||
		report.Claim != string(homchain.GaoA2BKernelN16L11KernelOnlyUnverified) ||
		report.KernelProfileDigest == "" || report.ExponentialArtifactDigest == "" ||
		report.LUTTableDigest == "" || report.CapacityPlanDigest == "" ||
		report.TransformSourceDigest == "" || report.MaskSourceDigest == "" ||
		report.LogBabyStepGiantStepRatio != routeBA2BFirstRoundBSGSRatio ||
		report.LowN1 <= 0 || report.HighN1 <= 0 || report.WallNanoseconds == 0 ||
		len(report.TransformRotationIndexes) == 0 || len(report.TransformGaloisElements) == 0 ||
		len(report.States) != 14 || report.Digest == "" {
		return lineagef("Route-B first A2B-round report identity or shape changed")
	}
	if report.KernelProfileDigest != routeBA2BFirstRoundKernelDigest ||
		report.ExponentialArtifactDigest != routeBA2BFirstRoundExpDigest ||
		report.LUTTableDigest != routeBA2BFirstRoundLUTDigest {
		return lineagef("Route-B first A2B-round kernel identity changed")
	}
	if report.TransformSourceDigest != routeBA2BFirstRoundSourceDigest ||
		report.MaskSourceDigest != routeBA2BFirstRoundMaskDigest ||
		!slices.Equal(report.TransformRotationIndexes, []int{1, 2, 3, 2044}) ||
		!slices.Equal(report.TransformGaloisElements, []uint64{5, 25, 125, 89745, 131071}) ||
		report.LowN1 != 4 || report.HighN1 != 4 {
		return lineagef("Route-B first A2B-round transform or mask identity changed")
	}
	if report.CapacityPlanDigest != routeBA2BFirstRoundPlanDigest {
		return lineagef("Route-B first A2B-round capacity-plan identity changed")
	}
	wantScaleDrift, err := routeBA2BFirstRoundExpectedScaleLog2Drift()
	if err != nil {
		return err
	}
	if report.ScaleNormalizationSource != routeBA2BFirstRoundObservedScaleHex ||
		report.ScaleNormalizationTarget != routeBA2BFirstRoundScaleHex ||
		report.ScaleNormalizationAbsLog2 != wantScaleDrift ||
		report.ScaleNormalizationBound != routeBA2BFirstRoundMaxScaleLog2Drift ||
		!report.ScaleNormalizationMetadataOnly {
		return lineagef("Route-B first A2B-round scale-normalization evidence changed")
	}
	wantCounts := homchain.GaoA2BKernelOperationCounts{
		ExpPolynomialEvaluations: 1, ComplexSquarings: 2,
		MultiPolynomialEvaluations: 1, SharedPowerBases: 1,
		GenericLUTEvaluations: 0, Conjugations: 2, RealRecoveries: 2,
	}
	if report.OperationCounts != wantCounts {
		return lineagef("Route-B first A2B-round kernel operation ledger changed")
	}
	wantStages := []string{
		"arithmetic-input", "special-b0-low", "special-b0-high", "iter0-low-mask", "iter0-stc", "iter0-mr0-output",
		string(homchain.GaoA2BKernelStageInput), string(homchain.GaoA2BKernelStageExponential),
		string(homchain.GaoA2BKernelStageSquare0), string(homchain.GaoA2BKernelStageRootOfUnity),
		string(homchain.GaoA2BKernelStageIdentityLUT), string(homchain.GaoA2BKernelStageMSBLUT),
		string(homchain.GaoA2BKernelStageIdentityOutput),
		string(homchain.GaoA2BKernelStageMSBOutput),
	}
	wantLevels := []int{20, 19, 19, 18, 16, 17, 17, 11, 10, 9, 5, 5, 5, 5}
	wantStateScales, err := routeBA2BFirstRoundExpectedStateScales()
	if err != nil {
		return err
	}
	for index := range wantStages {
		state := report.States[index]
		wantScaleExact := true
		if index == 5 {
			wantScaleExact = false
		}
		if state.Stage != wantStages[index] || state.Level != wantLevels[index] || state.Degree != 1 ||
			state.LogRows != 0 || state.LogColumns != 11 ||
			state.ScaleHex != wantStateScales[index] || state.ScaleExact != wantScaleExact {
			return lineagef(
				"Route-B first A2B-round state %d changed: got=%+v want-stage=%s want-level=%d want-scale=%s want-scale-exact=%t",
				index, state, wantStages[index], wantLevels[index], wantStateScales[index], wantScaleExact,
			)
		}
	}
	wantDigest, err := digestRouteBA2BFirstRoundReport(report)
	if err != nil || report.Digest != wantDigest {
		return lineagef("Route-B first A2B-round report digest changed")
	}
	return nil
}

// RouteBA2BFirstRoundResult owns the two named kernel outputs.
type RouteBA2BFirstRoundResult struct {
	identity *rlwe.Ciphertext
	msb      *rlwe.Ciphertext
}

func (result RouteBA2BFirstRoundResult) IDCiphertext() *rlwe.Ciphertext {
	if result.identity == nil {
		return nil
	}
	return result.identity.CopyNew()
}

func (result RouteBA2BFirstRoundResult) MSBCiphertext() *rlwe.Ciphertext {
	if result.msb == nil {
		return nil
	}
	return result.msb.CopyNew()
}

type routeBA2BFirstRoundCircuit struct {
	triangle              *homchain.Evaluator
	specialB0             homchain.CompiledPair
	lowMask               *rlwe.Plaintext
	kernel                *homchain.GaoA2BKernelN16L11Circuit
	transformSourceDigest string
	maskSourceDigest      string
	rotationIndexes       []int
	galoisElements        []uint64
}

type routeBA2BFirstRoundTransformPlan struct {
	source          homchain.PairSpec
	options         homchain.CompileOptions
	rotationIndexes []int
	galoisElements  []uint64
	lowN1, highN1   int
}

type routeBA2BFirstRoundScaleNormalizationEvidence struct {
	SourceScaleHex, TargetScaleHex string
	AbsLog2Drift                   float64
	MetadataOnly                   bool
}

func routeBA2BFirstRoundExpectedScaleLog2Drift() (float64, error) {
	source, _, err := big.ParseFloat(routeBA2BFirstRoundObservedScaleHex, 0, 256, big.ToNearestEven)
	if err != nil {
		return 0, fmt.Errorf("secureeval: parse registered Route-B first A2B-round source scale: %w", err)
	}
	target, _, err := big.ParseFloat(routeBA2BFirstRoundScaleHex, 0, 256, big.ToNearestEven)
	if err != nil {
		return 0, fmt.Errorf("secureeval: parse registered Route-B first A2B-round target scale: %w", err)
	}
	return math.Abs(rlwe.NewScale(source).Div(rlwe.NewScale(target)).Log2()), nil
}

func routeBA2BFirstRoundExpectedStateScales() ([]string, error) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		return nil, fmt.Errorf("secureeval: construct canonical Route-B first A2B-round state scales: %w", err)
	}
	defaultScale := params.DefaultScale()
	square0Scale := defaultScale.Mul(defaultScale).Div(rlwe.NewScale(params.Q()[11]))
	rootScale := square0Scale.Mul(square0Scale).Div(rlwe.NewScale(params.Q()[10]))
	defaultSnapshot, err := homchain.NewExactScaleSnapshot(defaultScale)
	if err != nil {
		return nil, err
	}
	square0Snapshot, err := homchain.NewExactScaleSnapshot(square0Scale)
	if err != nil {
		return nil, err
	}
	rootSnapshot, err := homchain.NewExactScaleSnapshot(rootScale)
	if err != nil {
		return nil, err
	}
	scales := make([]string, 14)
	for index := range scales {
		scales[index] = defaultSnapshot.ValueHex()
	}
	scales[5] = routeBA2BFirstRoundObservedScaleHex
	scales[8] = square0Snapshot.ValueHex()
	scales[9] = rootSnapshot.ValueHex()
	return scales, nil
}

func normalizeRouteBA2BFirstRoundKernelScale(
	ciphertext *rlwe.Ciphertext,
	target rlwe.Scale,
) (routeBA2BFirstRoundScaleNormalizationEvidence, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return routeBA2BFirstRoundScaleNormalizationEvidence{}, lineagef("Route-B first A2B-round scale-normalization input is nil")
	}
	sourceSnapshot, err := homchain.NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return routeBA2BFirstRoundScaleNormalizationEvidence{}, err
	}
	targetSnapshot, err := homchain.NewExactScaleSnapshot(target)
	if err != nil {
		return routeBA2BFirstRoundScaleNormalizationEvidence{}, err
	}
	if sourceSnapshot.ValueHex() != routeBA2BFirstRoundObservedScaleHex ||
		targetSnapshot.ValueHex() != routeBA2BFirstRoundScaleHex {
		return routeBA2BFirstRoundScaleNormalizationEvidence{}, lineagef(
			"Route-B first A2B-round scale-normalization source or target is outside the registered pair",
		)
	}
	absLog2Drift := math.Abs(ciphertext.Scale.Div(target).Log2())
	if math.IsNaN(absLog2Drift) || math.IsInf(absLog2Drift, 0) ||
		absLog2Drift > routeBA2BFirstRoundMaxScaleLog2Drift {
		return routeBA2BFirstRoundScaleNormalizationEvidence{}, lineagef(
			"Route-B first A2B-round |log2(scale/target)|=%g exceeds 2^-40", absLog2Drift,
		)
	}
	before := ciphertext.CopyNew()
	ciphertext.Scale = target
	before.Scale = target
	if !ciphertext.Equal(before) {
		ciphertext.Scale, _ = sourceSnapshot.Scale()
		return routeBA2BFirstRoundScaleNormalizationEvidence{}, lineagef("Route-B first A2B-round scale normalization changed ciphertext data or non-scale metadata")
	}
	return routeBA2BFirstRoundScaleNormalizationEvidence{
		SourceScaleHex: sourceSnapshot.ValueHex(), TargetScaleHex: targetSnapshot.ValueHex(),
		AbsLog2Drift: absLog2Drift, MetadataOnly: true,
	}, nil
}

// RunFirstSparseA2BFirstRound performs the mandatory installed preflight and
// one complete low-nibble Gao A2B round. It deliberately does not expose the
// resident Lattigo evaluator or any intermediate mutable artifact.
func (installed *RouteBInstalledEvaluator) RunFirstSparseA2BFirstRound(
	input *rlwe.Ciphertext,
) (
	result RouteBA2BFirstRoundResult,
	firstOperation RouteBFirstOperationReport,
	roundReport RouteBA2BFirstRoundReport,
	err error,
) {
	var capturedMSB *rlwe.Ciphertext
	runner := func(
		evaluator *bootstrapping.Evaluator,
		ciphertext *rlwe.Ciphertext,
	) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		identity, msb, observation, report, runErr := runCanonicalRouteBFirstSparseA2BFirstRound(evaluator, ciphertext)
		if runErr != nil {
			return nil, routeBFirstOperationObservation{}, runErr
		}
		if reportErr := report.Validate(); reportErr != nil {
			return nil, routeBFirstOperationObservation{}, reportErr
		}
		capturedMSB = msb
		roundReport = report
		return identity, observation, nil
	}
	identity, firstOperation, err := installed.runFirstOperationWithHooks(
		input, routeBCapacityGateA2BFirstRound, routeBRuntimeOperationA2BFirstRound,
		validateCanonicalRouteBInstalledResident,
		validateCanonicalRouteBInstalledEvaluator,
		runner,
	)
	if err != nil {
		return RouteBA2BFirstRoundResult{}, RouteBFirstOperationReport{}, RouteBA2BFirstRoundReport{}, err
	}
	if identity == nil || capturedMSB == nil {
		return RouteBA2BFirstRoundResult{}, RouteBFirstOperationReport{}, RouteBA2BFirstRoundReport{}, lineagef("Route-B first A2B round returned a nil ID or MSB")
	}
	return RouteBA2BFirstRoundResult{identity: identity, msb: capturedMSB}, firstOperation, roundReport, nil
}

func runCanonicalRouteBFirstSparseA2BFirstRound(
	evaluator *bootstrapping.Evaluator,
	input *rlwe.Ciphertext,
) (
	identity *rlwe.Ciphertext,
	msb *rlwe.Ciphertext,
	observation routeBFirstOperationObservation,
	report RouteBA2BFirstRoundReport,
	err error,
) {
	started := time.Now()
	if evaluator == nil || evaluator.Evaluator == nil || input == nil {
		return nil, nil, observation, report, lineagef("Route-B first A2B-round evaluator or input is nil")
	}
	circuit, err := newRouteBA2BFirstRoundCircuit(evaluator)
	if err != nil {
		return nil, nil, observation, report, err
	}
	if input.Level() != 20 || input.Degree() != 1 || input.LogN() != 16 ||
		input.LogDimensions != (ring.Dimensions{Rows: 0, Cols: 11}) ||
		!input.Scale.Equal(evaluator.BootstrappingParameters.DefaultScale()) {
		return nil, nil, observation, report, lineagef("Route-B first A2B-round arithmetic input state changed")
	}
	inputBefore := input.CopyNew()
	states := make([]RouteBA2BFirstRoundState, 0, 14)
	if state, stateErr := snapshotRouteBA2BFirstRoundState("arithmetic-input", input, input.Scale); stateErr != nil {
		return nil, nil, observation, report, stateErr
	} else {
		states = append(states, state)
	}

	halves, err := circuit.triangle.ZToCNew(input.CopyNew(), circuit.specialB0)
	if err != nil {
		return nil, nil, observation, report, fmt.Errorf("secureeval: Route-B special-b0 Z-To-C: %w", err)
	}
	if halves[0] == nil || halves[1] == nil || halves[0].Level() != 19 || halves[1].Level() != 19 ||
		!halves[0].Scale.Equal(input.Scale) || !halves[1].Scale.Equal(input.Scale) {
		return nil, nil, observation, report, lineagef("Route-B special-b0 output state changed")
	}
	for index, stage := range []string{"special-b0-low", "special-b0-high"} {
		state, stateErr := snapshotRouteBA2BFirstRoundState(stage, halves[index], input.Scale)
		if stateErr != nil {
			return nil, nil, observation, report, stateErr
		}
		states = append(states, state)
	}

	masked, err := evaluator.Evaluator.MulNew(halves[0], circuit.lowMask)
	if err != nil {
		return nil, nil, observation, report, fmt.Errorf("secureeval: Route-B iter0 low mask multiply: %w", err)
	}
	if err = evaluator.Evaluator.Rescale(masked, masked); err != nil {
		return nil, nil, observation, report, fmt.Errorf("secureeval: Route-B iter0 low mask rescale: %w", err)
	}
	if masked.Level() != 18 || !masked.Scale.Equal(input.Scale) {
		return nil, nil, observation, report, lineagef("Route-B iter0 low mask output state changed")
	}
	if state, stateErr := snapshotRouteBA2BFirstRoundState("iter0-low-mask", masked, input.Scale); stateErr != nil {
		return nil, nil, observation, report, stateErr
	} else {
		states = append(states, state)
	}

	stc, err := evaluator.SlotsToCoeffs(masked, nil)
	if err != nil {
		return nil, nil, observation, report, fmt.Errorf("secureeval: Route-B iter0 Slots-To-Coeffs: %w", err)
	}
	if stc == nil || stc.Level() != 16 || !stc.Scale.Equal(input.Scale) {
		return nil, nil, observation, report, lineagef("Route-B iter0 STC output state changed")
	}
	if state, stateErr := snapshotRouteBA2BFirstRoundState("iter0-stc", stc, input.Scale); stateErr != nil {
		return nil, nil, observation, report, stateErr
	} else {
		states = append(states, state)
	}

	normalized, observation, err := runCanonicalRouteBFirstSparseMR0(evaluator, stc)
	if err != nil {
		return nil, nil, routeBFirstOperationObservation{}, report, fmt.Errorf("secureeval: Route-B iter0 observed MR0: %w", err)
	}
	if state, stateErr := snapshotRouteBA2BFirstRoundState("iter0-mr0-output", normalized, input.Scale); stateErr != nil {
		return nil, nil, observation, report, stateErr
	} else {
		states = append(states, state)
	}
	scaleNormalization, err := normalizeRouteBA2BFirstRoundKernelScale(normalized, input.Scale)
	if err != nil {
		return nil, nil, observation, report, err
	}
	kernelEvaluator, err := bindRouteBA2BFirstRoundKernel(circuit.kernel, evaluator)
	if err != nil {
		return nil, nil, observation, report, fmt.Errorf("secureeval: bind Route-B N16/L11 Gao kernel: %w", err)
	}
	kernelResult, err := kernelEvaluator.EvaluateNew(normalized)
	if err != nil {
		return nil, nil, observation, report, fmt.Errorf("secureeval: execute Route-B N16/L11 Gao kernel: %w", err)
	}
	provenance := kernelResult.Provenance()
	for _, kernelState := range provenance.States() {
		states = append(states, RouteBA2BFirstRoundState{
			Stage: string(kernelState.Stage), Level: kernelState.Level, Degree: kernelState.Degree,
			LogRows: 0, LogColumns: 11, ScaleHex: kernelState.Scale.ValueHex(), ScaleExact: kernelState.ScaleExact,
		})
	}
	identity = kernelResult.IDCiphertext()
	msb = kernelResult.MSBCiphertext()
	if identity == nil || msb == nil || !input.Equal(inputBefore) {
		return nil, nil, observation, report, lineagef("Route-B first A2B round returned nil output or mutated its arithmetic input")
	}
	profile := circuit.kernel.Profile()
	capacityPlan, err := canonicalRouteBCapacityPlan(routeBCapacityGateA2BFirstRound)
	if err != nil {
		return nil, nil, observation, RouteBA2BFirstRoundReport{}, err
	}
	wall := uint64(time.Since(started).Nanoseconds())
	if wall == 0 {
		wall = 1
	}
	report = RouteBA2BFirstRoundReport{
		SchemaVersion: routeBA2BFirstRoundReportSchema,
		Claim:         string(profile.Claim()), KernelProfileDigest: profile.Digest(),
		ExponentialArtifactDigest: profile.ExponentialArtifactDigest(), LUTTableDigest: profile.LUTTableDigest(),
		CapacityPlanDigest:    capacityPlan.Digest(),
		TransformSourceDigest: circuit.transformSourceDigest, MaskSourceDigest: circuit.maskSourceDigest,
		TransformRotationIndexes:  append([]int(nil), circuit.rotationIndexes...),
		TransformGaloisElements:   append([]uint64(nil), circuit.galoisElements...),
		LogBabyStepGiantStepRatio: routeBA2BFirstRoundBSGSRatio,
		LowN1:                     circuit.specialB0.Low.N1, HighN1: circuit.specialB0.High.N1,
		ScaleNormalizationSource:       scaleNormalization.SourceScaleHex,
		ScaleNormalizationTarget:       scaleNormalization.TargetScaleHex,
		ScaleNormalizationAbsLog2:      scaleNormalization.AbsLog2Drift,
		ScaleNormalizationBound:        routeBA2BFirstRoundMaxScaleLog2Drift,
		ScaleNormalizationMetadataOnly: scaleNormalization.MetadataOnly,
		States:                         states, OperationCounts: provenance.OperationCounts(), WallNanoseconds: wall,
	}
	report.Digest, err = digestRouteBA2BFirstRoundReport(report)
	if err != nil {
		return nil, nil, observation, RouteBA2BFirstRoundReport{}, err
	}
	return identity, msb, observation, report, nil
}

func bindRouteBA2BFirstRoundKernel(
	circuit *homchain.GaoA2BKernelN16L11Circuit,
	evaluator *bootstrapping.Evaluator,
) (*homchain.GaoA2BKernelN16L11Evaluator, error) {
	if circuit == nil || evaluator == nil || evaluator.Evaluator == nil ||
		evaluator.EvaluationKeys == nil || evaluator.MemEvaluationKeySet == nil {
		return nil, lineagef("Route-B N16/L11 kernel or installed key graph is incomplete")
	}
	if evaluator.Evaluator.EvaluationKeySet != evaluator.EvaluationKeys {
		return nil, lineagef("Route-B installed CKKS evaluator is not bound to its bootstrapping key wrapper")
	}
	memKeyView := evaluator.Evaluator.WithKey(evaluator.MemEvaluationKeySet)
	if memKeyView == nil || memKeyView.EvaluationKeySet != evaluator.MemEvaluationKeySet ||
		evaluator.Evaluator.EvaluationKeySet != evaluator.EvaluationKeys {
		return nil, lineagef("Route-B installed memory-key rebind changed the key graph")
	}
	bound, err := circuit.BindEvaluator(memKeyView)
	if err != nil {
		return nil, err
	}
	return bound, nil
}

func newRouteBA2BFirstRoundCircuit(evaluator *bootstrapping.Evaluator) (*routeBA2BFirstRoundCircuit, error) {
	if evaluator == nil || evaluator.Evaluator == nil || evaluator.MemEvaluationKeySet == nil {
		return nil, lineagef("Route-B first A2B-round evaluator graph is incomplete")
	}
	params := evaluator.BootstrappingParameters
	if params.LogN() != 16 || params.MaxLevel() != 20 || params.MaxLevelP() != 6 || params.LogDefaultScale() != 43 {
		return nil, lineagef("Route-B first A2B-round parameter profile changed")
	}
	encoder := ckks.NewEncoder(params, 256)
	transformPlan, err := deriveRouteBA2BFirstRoundTransformPlan(params)
	if err != nil {
		return nil, err
	}
	specialB0, err := homchain.CompilePair(params, encoder, transformPlan.source, transformPlan.options)
	if err != nil {
		return nil, fmt.Errorf("secureeval: compile Route-B special-b0 pair: %w", err)
	}
	rotations := specialB0.RotationIndexes()
	galois := homchain.GaloisElementsForZToC(params, specialB0)
	if !slices.Equal(rotations, transformPlan.rotationIndexes) ||
		!slices.Equal(galois, transformPlan.galoisElements) ||
		specialB0.Low.N1 != transformPlan.lowN1 || specialB0.High.N1 != transformPlan.highN1 {
		return nil, lineagef("Route-B special-b0 compiled transform differs from its preflight plan")
	}
	for _, element := range galois {
		if key, keyErr := evaluator.MemEvaluationKeySet.GetGaloisKey(element); keyErr != nil || key == nil {
			return nil, lineagef("Route-B special-b0 Galois key %d is missing", element)
		}
	}
	if key, keyErr := evaluator.MemEvaluationKeySet.GetRelinearizationKey(); keyErr != nil || key == nil {
		return nil, lineagef("Route-B first A2B-round relinearization key is missing")
	}
	mask := ckks.NewPlaintext(params, 19)
	mask.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	mask.Scale = rlwe.NewScale(params.Q()[19])
	maskValues := make([]*big.Float, routeBA2BFirstRoundSlots)
	for index := range maskValues {
		maskValues[index] = new(big.Float).SetPrec(256).SetInt64(1)
	}
	if err = encoder.Encode(maskValues, mask); err != nil {
		return nil, fmt.Errorf("secureeval: encode Route-B iter0 mask: %w", err)
	}
	kernel, err := homchain.NewGaoA2BKernelN16L11Circuit(params, encoder)
	if err != nil {
		return nil, err
	}
	transformDigest, err := digestRouteBA2BTransformSource(
		transformPlan.source, transformPlan.options, rotations, galois,
	)
	if err != nil {
		return nil, err
	}
	maskDigest, err := digestRouteBA2BFirstRoundMask(params)
	if err != nil {
		return nil, err
	}
	return &routeBA2BFirstRoundCircuit{
		triangle: homchain.NewEvaluator(evaluator.Evaluator), specialB0: specialB0, lowMask: mask, kernel: kernel,
		transformSourceDigest: transformDigest, maskSourceDigest: maskDigest,
		rotationIndexes: rotations, galoisElements: galois,
	}, nil
}

func digestRouteBA2BFirstRoundMask(params ckks.Parameters) (string, error) {
	if params.LogN() != 16 || params.MaxLevel() < 19 {
		return "", lineagef("Route-B first A2B-round mask parameter profile changed")
	}
	maskScale, err := homchain.NewExactScaleSnapshot(rlwe.NewScale(params.Q()[19]))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"route-b-a2b-iter0-mask-v1|slots=%d|level=19|dimensions=0,11|value=1|precision=256|scale=%s",
		routeBA2BFirstRoundSlots, maskScale.ValueHex(),
	)))
	return hex.EncodeToString(digest[:]), nil
}

func deriveRouteBA2BFirstRoundTransformPlan(params ckks.Parameters) (routeBA2BFirstRoundTransformPlan, error) {
	if params.LogN() != 16 || params.MaxLevel() != 20 || params.MaxLevelP() != 6 || params.LogDefaultScale() != 43 {
		return routeBA2BFirstRoundTransformPlan{}, lineagef("Route-B special-b0 preflight parameter profile changed")
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, 256)
	if err != nil {
		return routeBA2BFirstRoundTransformPlan{}, err
	}
	specifications, err := homchain.NewSpecificationsFromRing(ringZ, routeBA2BFirstRoundWords)
	if err != nil {
		return routeBA2BFirstRoundTransformPlan{}, fmt.Errorf("secureeval: construct Route-B special-b0 specifications: %w", err)
	}
	source := specifications.VSpecialB0Pair()
	options := homchain.CompileOptions{
		LevelQ: params.MaxLevel(), LevelP: params.MaxLevelP(), Scale: rlwe.NewScale(params.Q()[params.MaxLevel()]),
		LogBabyStepGiantStepRatio: routeBA2BFirstRoundBSGSRatio,
	}
	rotations := make([]int, 0, 8)
	n1s := [2]int{}
	for index, specification := range [...]homchain.TransformSpec{source.Low, source.High} {
		parameters, parameterErr := specification.Parameters(options)
		if parameterErr != nil {
			return routeBA2BFirstRoundTransformPlan{}, parameterErr
		}
		slots := 1 << parameters.LogDimensions.Cols
		n1 := commonlintrans.FindBestBSGSRatio(
			parameters.DiagonalsIndexList, slots, parameters.LogBabyStepGiantStepRatio,
		)
		_, babySteps, giantSteps := commonlintrans.BSGSIndex(parameters.DiagonalsIndexList, slots, n1)
		rotations = append(rotations, babySteps...)
		rotations = append(rotations, giantSteps...)
		n1s[index] = n1
	}
	slices.Sort(rotations)
	rotations = slices.Compact(rotations)
	if len(rotations) != 0 && rotations[0] == 0 {
		rotations = rotations[1:]
	}
	galois := params.GaloisElements(rotations)
	galois = append(galois, params.GaloisElementForComplexConjugation())
	slices.Sort(galois)
	galois = slices.Compact(galois)
	return routeBA2BFirstRoundTransformPlan{
		source: source, options: options,
		rotationIndexes: append([]int(nil), rotations...), galoisElements: append([]uint64(nil), galois...),
		lowN1: n1s[0], highN1: n1s[1],
	}, nil
}

func snapshotRouteBA2BFirstRoundState(stage string, ciphertext *rlwe.Ciphertext, target rlwe.Scale) (RouteBA2BFirstRoundState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return RouteBA2BFirstRoundState{}, lineagef("cannot snapshot nil Route-B first A2B-round state")
	}
	scale, err := homchain.NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return RouteBA2BFirstRoundState{}, err
	}
	targetScale, err := homchain.NewExactScaleSnapshot(target)
	if err != nil {
		return RouteBA2BFirstRoundState{}, err
	}
	return RouteBA2BFirstRoundState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogRows: ciphertext.LogDimensions.Rows, LogColumns: ciphertext.LogDimensions.Cols,
		ScaleHex: scale.ValueHex(), ScaleExact: scale.Equal(targetScale),
	}, nil
}

func digestRouteBA2BTransformSource(
	source homchain.PairSpec,
	options homchain.CompileOptions,
	rotations []int,
	galois []uint64,
) (string, error) {
	var canonical strings.Builder
	fmt.Fprintf(&canonical,
		"route-b-a2b-special-b0-v1|Q=%d|P=%d|scale=%s|bsgs=%d|rotations=%v|galois=%v",
		options.LevelQ, options.LevelP, options.Scale.Value.Text('x', -1), options.LogBabyStepGiantStepRatio,
		rotations, galois,
	)
	for _, specification := range []homchain.TransformSpec{source.Low, source.High} {
		fmt.Fprintf(&canonical, "|name=%s|layout=%s|words=%d|half=%d|dimensions=%d,%d|matrix=",
			specification.Name(), specification.Layout(), specification.Words(), specification.HalfWidth(),
			specification.LogDimensions().Rows, specification.LogDimensions().Cols,
		)
		for _, row := range specification.Matrix() {
			for _, value := range row {
				if value == nil || value.Real() == nil || value.Imag() == nil {
					return "", lineagef("Route-B special-b0 source contains a nil value")
				}
				fmt.Fprintf(&canonical, "%s@%d/%d,%s@%d/%d;",
					value.Real().Text('x', -1), value.Real().Prec(), value.Real().Mode(),
					value.Imag().Text('x', -1), value.Imag().Prec(), value.Imag().Mode(),
				)
			}
		}
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:]), nil
}

func digestRouteBA2BFirstRoundReport(report RouteBA2BFirstRoundReport) (string, error) {
	var canonical strings.Builder
	fmt.Fprintf(&canonical,
		"%s|claim=%s|kernel=%s|exp=%s|lut=%s|capacity=%s|transform=%s|mask=%s|rot=%v|gal=%v|bsgs=%d|n1=%d,%d|scale-normalization=%s,%s,%.17g,%.17g,%t|counts=%+v|wall=%d",
		report.SchemaVersion, report.Claim, report.KernelProfileDigest, report.ExponentialArtifactDigest,
		report.LUTTableDigest, report.CapacityPlanDigest, report.TransformSourceDigest, report.MaskSourceDigest,
		report.TransformRotationIndexes, report.TransformGaloisElements,
		report.LogBabyStepGiantStepRatio, report.LowN1, report.HighN1,
		report.ScaleNormalizationSource, report.ScaleNormalizationTarget,
		report.ScaleNormalizationAbsLog2, report.ScaleNormalizationBound, report.ScaleNormalizationMetadataOnly,
		report.OperationCounts,
		report.WallNanoseconds,
	)
	for _, state := range report.States {
		fmt.Fprintf(&canonical, "|state=%s,%d,%d,%d,%d,%s,%t",
			state.Stage, state.Level, state.Degree, state.LogRows, state.LogColumns, state.ScaleHex, state.ScaleExact,
		)
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:]), nil
}
