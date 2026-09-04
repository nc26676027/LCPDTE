package secureeval

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/securityparams"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

const (
	routeBA2BFullSecondSTCLevelQ       = 3
	routeBA2BFullSecondSTCReportSchema = "lcpdte-route-b-a2b-full-second-stc-report-v1"
	routeBA2BFullSecondSTCClaim        = "observed_streaming_independent_l3_to_l1_stc_only"
	routeBA2BFullReportSchema          = "lcpdte-route-b-gao-a2b-full-report-v1"
	routeBA2BFullClaim                 = "lattigo_n16_l11_sparse_complete_8bit_a2b_security_unverified"

	routeBA2BFullSecondSTCRawLiteralDigest       = "e9b6bfe3180d090adc5344625d444e97953a00cd4475a9b53eb7d4ddc5e332e4"
	routeBA2BFullSecondSTCRawScalingDigest       = "ca2fd7688b462df6336d04bdbf0e324723e490fc7afa7808822df3e10a7681ff"
	routeBA2BFullSecondSTCEffectiveLiteralDigest = "7639927ea7baae9ba8aabbc47f1b5843dca13a79449fad433c3b9237a6fc2565"
	routeBA2BFullSecondSTCEffectiveScalingDigest = "58b7bebf46c178efaf34a42a723ebfa05ad770a948ed8efa607b7161871650d0"
	routeBA2BFullSecondSTCTraceDigest            = "da09c270d38aaf5117628ae09ec7487480f7b3a8562ec8a76502ecf35f8b4a83"
	routeBA2BFullSecondSTCReportDigest           = "bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a"
)

var routeBA2BFullSecondSTCFrozenFactors = [2]RouteBA2BFullSecondSTCFactorReport{
	{
		Index: 0, DiagonalCount: 63,
		NumericDigest: "bf8fbcb7774e62cab94c9ab07fcbbdf0894753379749872469bbd3538f5bdd81",
		NumericBytes:  12_971_990,
		EncodedDigest: "28045ac2cd0e3ea2c4d634fe7d4123f0d0ec96d8c8b344f96461492dcabc7e9a",
		EncodedBytes:  363_339_287,
	},
	{
		Index: 1, DiagonalCount: 64,
		NumericDigest: "81d9c29e88fb959829ebcad8a45e19f2646269957583bf1dd881311cb2b1fd1a",
		NumericBytes:  21_566_574,
		EncodedDigest: "2324862950916738884c9e6561f77240c929e587af54308a3ea15b3e7d3d5332",
		EncodedBytes:  369_106_575,
	},
}

// RouteBA2BFullState is an exact detached ciphertext boundary in the serial
// two-round graph.
type RouteBA2BFullState struct {
	Stage      string `json:"stage"`
	Level      int    `json:"level"`
	Degree     int    `json:"degree"`
	LogRows    int    `json:"log_rows"`
	LogColumns int    `json:"log_columns"`
	ScaleHex   string `json:"scale_hex"`
	ScaleExact bool   `json:"scale_exact"`
}

// RouteBA2BFullScaleNormalizationReport records one exact-pair-only metadata
// normalization at a shared-CTS output.
type RouteBA2BFullScaleNormalizationReport struct {
	Iteration      int     `json:"iteration"`
	SourceScaleHex string  `json:"source_scale_hex"`
	TargetScaleHex string  `json:"target_scale_hex"`
	AbsLog2Drift   float64 `json:"abs_log2_drift"`
	Bound          float64 `json:"bound"`
	MetadataOnly   bool    `json:"metadata_only"`
}

// RouteBA2BFullMR0Report binds the second refresh prefix. The first prefix is
// already bound by RouteBFirstOperationReport.
type RouteBA2BFullMR0Report struct {
	TraceGap                uint32                           `json:"trace_gap"`
	TraceRotationExponents  [routeBTraceDispatchCount]uint64 `json:"trace_rotation_exponents"`
	TraceGaloisElements     [routeBTraceDispatchCount]uint64 `json:"trace_galois_elements"`
	TraceDigest             string                           `json:"trace_digest"`
	ModUpInputOutputAliased bool                             `json:"mod_up_input_output_aliased"`
	CTImagNil               bool                             `json:"ct_imag_nil"`
	RaisedLevel             int                              `json:"raised_level"`
	OutputLevel             int                              `json:"output_level"`
	WallNanoseconds         uint64                           `json:"wall_nanoseconds"`
}

func (report RouteBA2BFullMR0Report) validate() error {
	if report.TraceGap != 16 || report.TraceRotationExponents != routeBExpectedTraceRotationExponents ||
		report.TraceGaloisElements != routeBExpectedTraceGaloisElements ||
		!routeBA2BFullIsSHA256(report.TraceDigest) || !report.ModUpInputOutputAliased || !report.CTImagNil ||
		report.RaisedLevel != 20 || report.OutputLevel != 17 || report.WallNanoseconds == 0 {
		return lineagef("Route-B full A2B second MR0 evidence changed")
	}
	return nil
}

// RouteBA2BFullReport proves the complete serial low-then-high conversion. It
// remains a functional/security-unverified claim until the security estimator
// and composed decision-tree stages are closed separately.
type RouteBA2BFullReport struct {
	SchemaVersion string `json:"schema_version"`
	Claim         string `json:"claim"`

	CapacityPlanDigest        string `json:"capacity_plan_digest"`
	KernelProfileDigest       string `json:"kernel_profile_digest"`
	ExponentialArtifactDigest string `json:"exponential_artifact_digest"`
	LUTTableDigest            string `json:"lut_table_digest"`
	TransformSourceDigest     string `json:"transform_source_digest"`
	Iter0MaskSourceDigest     string `json:"iter0_mask_source_digest"`
	Iter1MaskSourceDigest     string `json:"iter1_mask_source_digest"`
	IDScaleSourceDigest       string `json:"id_scale_source_digest"`

	TransformRotationIndexes  []int    `json:"transform_rotation_indexes"`
	TransformGaloisElements   []uint64 `json:"transform_galois_elements"`
	LogBabyStepGiantStepRatio int      `json:"log_baby_step_giant_step_ratio"`
	LowN1                     int      `json:"low_n1"`
	HighN1                    int      `json:"high_n1"`

	SecondSTC             RouteBA2BFullSecondSTCReport            `json:"second_stc"`
	SecondMR0             RouteBA2BFullMR0Report                  `json:"second_mr0"`
	ScaleNormalizations   []RouteBA2BFullScaleNormalizationReport `json:"scale_normalizations"`
	States                []RouteBA2BFullState                    `json:"states"`
	KernelOperationCounts [2]homchain.GaoA2BKernelOperationCounts `json:"kernel_operation_counts"`
	OperationCounts       homchain.A2BFullOperationCounts         `json:"operation_counts"`
	WallNanoseconds       uint64                                  `json:"wall_nanoseconds"`
	Digest                string                                  `json:"digest"`
}

func (report RouteBA2BFullReport) Validate() error {
	if report.SchemaVersion != routeBA2BFullReportSchema || report.Claim != routeBA2BFullClaim ||
		report.WallNanoseconds == 0 || report.Digest == "" {
		return lineagef("Route-B full A2B report identity, wall time, or digest is empty")
	}
	capacity, err := canonicalRouteBCapacityPlan(routeBCapacityGateA2BFull)
	if err != nil {
		return err
	}
	if report.CapacityPlanDigest != capacity.Digest() ||
		report.KernelProfileDigest != routeBA2BFirstRoundKernelDigest ||
		report.ExponentialArtifactDigest != routeBA2BFirstRoundExpDigest ||
		report.LUTTableDigest != routeBA2BFirstRoundLUTDigest ||
		report.TransformSourceDigest != routeBA2BFirstRoundSourceDigest ||
		report.Iter0MaskSourceDigest != routeBA2BFirstRoundMaskDigest ||
		!slices.Equal(report.TransformRotationIndexes, []int{1, 2, 3, 2044}) ||
		!slices.Equal(report.TransformGaloisElements, []uint64{5, 25, 125, 89745, 131071}) ||
		report.LogBabyStepGiantStepRatio != routeBA2BFirstRoundBSGSRatio ||
		report.LowN1 != 4 || report.HighN1 != 4 {
		return lineagef("Route-B full A2B capacity, kernel, or special-b0 identity changed")
	}
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		return err
	}
	_, _, iter1MaskDigest, idScaleDigest, err := newRouteBA2BFullOperands(params)
	if err != nil {
		return err
	}
	if report.Iter1MaskSourceDigest != iter1MaskDigest || report.IDScaleSourceDigest != idScaleDigest {
		return lineagef("Route-B full A2B serial plaintext operand identity changed")
	}
	if err = report.SecondSTC.Validate(); err != nil {
		return err
	}
	if err = report.SecondMR0.validate(); err != nil {
		return err
	}
	drift, err := routeBA2BFirstRoundExpectedScaleLog2Drift()
	if err != nil {
		return err
	}
	if len(report.ScaleNormalizations) != 2 {
		return lineagef("Route-B full A2B scale-normalization count changed")
	}
	for index, normalization := range report.ScaleNormalizations {
		if normalization.Iteration != index || normalization.SourceScaleHex != routeBA2BFirstRoundObservedScaleHex ||
			normalization.TargetScaleHex != routeBA2BFirstRoundScaleHex || normalization.AbsLog2Drift != drift ||
			normalization.Bound != routeBA2BFirstRoundMaxScaleLog2Drift || !normalization.MetadataOnly {
			return lineagef("Route-B full A2B scale-normalization evidence %d changed", index)
		}
	}
	stages, levels, scales, exact, err := routeBA2BFullExpectedStateLedger()
	if err != nil {
		return err
	}
	if len(report.States) != len(stages) {
		return lineagef("Route-B full A2B state count is %d, want %d", len(report.States), len(stages))
	}
	for index, state := range report.States {
		if state.Stage != stages[index] || state.Level != levels[index] || state.Degree != 1 ||
			state.LogRows != 0 || state.LogColumns != 11 || state.ScaleHex != scales[index] ||
			state.ScaleExact != exact[index] {
			return lineagef("Route-B full A2B state %d changed: %+v", index, state)
		}
	}
	wantKernelCounts := homchain.GaoA2BKernelOperationCounts{
		ExpPolynomialEvaluations: 1, ComplexSquarings: 2,
		MultiPolynomialEvaluations: 1, SharedPowerBases: 1,
		GenericLUTEvaluations: 0, Conjugations: 2, RealRecoveries: 2,
	}
	if report.KernelOperationCounts != [2]homchain.GaoA2BKernelOperationCounts{wantKernelCounts, wantKernelCounts} ||
		report.OperationCounts != (homchain.A2BFullOperationCounts{
			SpecialB0Transforms: 1, MaskMulRescales: 2, RefreshInvocations: 2,
			KernelInvocations: 2, IDScaleMulRescales: 1, AlignmentDrops: 3,
			Subtractions: 3, ResidualRotations: 0, SharedCTSUses: 2,
		}) {
		return lineagef("Route-B full A2B operation ledger changed")
	}
	wantDigest, err := digestRouteBA2BFullReport(report)
	if err != nil || report.Digest != wantDigest {
		return lineagef("Route-B full A2B report digest changed")
	}
	return nil
}

func routeBA2BFullExpectedStateLedger() (stages []string, levels []int, scales []string, exact []bool, err error) {
	kernelStages := []string{
		string(homchain.GaoA2BKernelStageInput), string(homchain.GaoA2BKernelStageExponential),
		string(homchain.GaoA2BKernelStageSquare0), string(homchain.GaoA2BKernelStageRootOfUnity),
		string(homchain.GaoA2BKernelStageIdentityLUT), string(homchain.GaoA2BKernelStageMSBLUT),
		string(homchain.GaoA2BKernelStageIdentityOutput), string(homchain.GaoA2BKernelStageMSBOutput),
	}
	stages = []string{"arithmetic-input", "special-b0-low", "special-b0-high", "iter0-low-mask", "iter0-stc", "iter0-mr0-output"}
	for _, stage := range kernelStages {
		stages = append(stages, "iter0-kernel-"+stage)
	}
	stages = append(stages,
		"id0-over-16", "high-core-aligned", "high-core-minus-id0-over-16",
		"low-core-aligned", "low-core-minus-id0", "iter1-high-mask", "iter1-stc", "iter1-mr0-output",
	)
	for _, stage := range kernelStages {
		stages = append(stages, "iter1-kernel-"+stage)
	}
	stages = append(stages, "id1-aligned", "high-core-minus-id0-over-16-minus-id1")
	levels = []int{
		20, 19, 19, 18, 16, 17,
		17, 11, 10, 9, 5, 5, 5, 5,
		4, 4, 4, 5, 5, 3, 1, 17,
		17, 11, 10, 9, 5, 5, 5, 5,
		4, 4,
	}
	firstScales, err := routeBA2BFirstRoundExpectedStateScales()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	scales = make([]string, len(stages))
	exact = make([]bool, len(stages))
	for index := range scales {
		scales[index] = routeBA2BFirstRoundScaleHex
		exact[index] = true
	}
	scales[5], exact[5] = routeBA2BFirstRoundObservedScaleHex, false
	copy(scales[6:14], firstScales[6:14])
	scales[21], exact[21] = routeBA2BFirstRoundObservedScaleHex, false
	copy(scales[22:30], firstScales[6:14])
	if len(stages) != 32 || len(levels) != len(stages) {
		return nil, nil, nil, nil, lineagef("Route-B full A2B registered state ledger shape changed")
	}
	return stages, levels, scales, exact, nil
}

func newRouteBA2BFullOperands(
	params ckks.Parameters,
) (iter1Mask, idScale *rlwe.Plaintext, iter1MaskDigest, idScaleDigest string, err error) {
	if params.LogN() != 16 || params.MaxLevel() != 20 || params.MaxLevelP() != 6 || params.LogDefaultScale() != 43 {
		return nil, nil, "", "", lineagef("Route-B full A2B serial operand parameter profile changed")
	}
	encoder := ckks.NewEncoder(params, rbdftGeneratorPrecision)
	encode := func(level, mantissaExponent int) (*rlwe.Plaintext, error) {
		plaintext := ckks.NewPlaintext(params, level)
		plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
		plaintext.Scale = rlwe.NewScale(params.Q()[level])
		values := make([]*big.Float, routeBA2BFirstRoundSlots)
		for index := range values {
			values[index] = new(big.Float).SetPrec(rbdftGeneratorPrecision).SetMode(big.ToNearestEven).SetInt64(1)
			values[index].SetMantExp(values[index], mantissaExponent)
		}
		if encodeErr := encoder.Encode(values, plaintext); encodeErr != nil {
			return nil, encodeErr
		}
		return plaintext, nil
	}
	iter1Mask, err = encode(4, 0)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("secureeval: encode Route-B full A2B iter1 mask: %w", err)
	}
	idScale, err = encode(5, -4)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("secureeval: encode Route-B full A2B ID0/16 operand: %w", err)
	}
	digestOperand := func(name string, plaintext *rlwe.Plaintext, level, exponent int) (string, error) {
		payload, marshalErr := plaintext.MarshalBinary()
		if marshalErr != nil {
			return "", marshalErr
		}
		payloadDigest := sha256.Sum256(payload)
		scale, scaleErr := homchain.NewExactScaleSnapshot(plaintext.Scale)
		if scaleErr != nil {
			return "", scaleErr
		}
		identity := sha256.Sum256([]byte(fmt.Sprintf(
			"route-b-a2b-full-%s-v1|slots=2048|dimensions=0,11|level=%d|output=%d|mantissa-exponent=%d|precision=256|scale=%s|payload=%x",
			name, level, level-1, exponent, scale.ValueHex(), payloadDigest,
		)))
		return hex.EncodeToString(identity[:]), nil
	}
	iter1MaskDigest, err = digestOperand("iter1-mask", iter1Mask, 4, 0)
	if err != nil {
		return nil, nil, "", "", err
	}
	idScaleDigest, err = digestOperand("id0-over-16", idScale, 5, -4)
	if err != nil {
		return nil, nil, "", "", err
	}
	return iter1Mask, idScale, iter1MaskDigest, idScaleDigest, nil
}

func digestRouteBA2BFullReport(report RouteBA2BFullReport) (string, error) {
	var canonical strings.Builder
	fmt.Fprintf(&canonical,
		"%s|claim=%s|capacity=%s|kernel=%s|exp=%s|lut=%s|transform=%s|masks=%s,%s|id-scale=%s|rot=%v|gal=%v|bsgs=%d|n1=%d,%d|second-stc=%s|second-mr0=%+v|normalizations=%+v|kernel-counts=%+v|counts=%+v|wall=%d",
		report.SchemaVersion, report.Claim, report.CapacityPlanDigest, report.KernelProfileDigest,
		report.ExponentialArtifactDigest, report.LUTTableDigest, report.TransformSourceDigest,
		report.Iter0MaskSourceDigest, report.Iter1MaskSourceDigest, report.IDScaleSourceDigest,
		report.TransformRotationIndexes, report.TransformGaloisElements,
		report.LogBabyStepGiantStepRatio, report.LowN1, report.HighN1,
		report.SecondSTC.Digest, report.SecondMR0, report.ScaleNormalizations,
		report.KernelOperationCounts, report.OperationCounts, report.WallNanoseconds,
	)
	for _, state := range report.States {
		fmt.Fprintf(&canonical, "|state=%s,%d,%d,%d,%d,%s,%t",
			state.Stage, state.Level, state.Degree, state.LogRows, state.LogColumns,
			state.ScaleHex, state.ScaleExact,
		)
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:]), nil
}

// RouteBA2BFullSecondSTCFactorReport is detached evidence for one numeric
// DFT factor and the encoded linear transformation that took ownership of it.
type RouteBA2BFullSecondSTCFactorReport struct {
	Index         uint32 `json:"index"`
	DiagonalCount uint32 `json:"diagonal_count"`
	NumericDigest string `json:"numeric_digest"`
	NumericBytes  uint64 `json:"numeric_bytes"`
	EncodedDigest string `json:"encoded_digest"`
	EncodedBytes  uint64 `json:"encoded_bytes"`
}

// RouteBA2BFullSecondSTCReport authenticates the supplemental transform
// construction. It is inert evidence and cannot install or authorize a DFT.
type RouteBA2BFullSecondSTCReport struct {
	SchemaVersion string `json:"schema_version"`
	Claim         string `json:"claim"`

	SourceLevelQ           int   `json:"source_level_q"`
	InputLevel             int   `json:"input_level"`
	OutputLevel            int   `json:"output_level"`
	LevelP                 int   `json:"level_p"`
	LogSlots               int   `json:"log_slots"`
	Levels                 []int `json:"levels"`
	TransformType          int   `json:"transform_type"`
	Format                 int   `json:"format"`
	GeneratorPrecisionBits uint  `json:"generator_precision_bits"`
	EncoderPrecisionBits   uint  `json:"encoder_precision_bits"`

	RawLiteralDigest       string   `json:"raw_literal_digest"`
	RawScalingDigest       string   `json:"raw_scaling_digest"`
	EffectiveLiteralDigest string   `json:"effective_literal_digest"`
	EffectiveScalingDigest string   `json:"effective_scaling_digest"`
	GaloisElements         []uint64 `json:"galois_elements"`

	FactorCount          uint32   `json:"factor_count"`
	FactorDiagonalCounts []uint32 `json:"factor_diagonal_counts"`
	VectorLength         uint32   `json:"vector_length"`
	ExpectedPolyBytes    uint64   `json:"expected_poly_bytes"`

	TraceStatus          string `json:"trace_status"`
	TraceDigest          string `json:"trace_digest"`
	TraceCompletedEvents uint32 `json:"trace_completed_events"`
	TraceCleanupEvents   uint32 `json:"trace_cleanup_events"`

	DefaultWholeCounterDelta      uint64 `json:"default_whole_counter_delta"`
	ExplicitWholeCounterDelta     uint64 `json:"explicit_whole_counter_delta"`
	RawNumericCounterDelta        uint64 `json:"raw_numeric_counter_delta"`
	ObservedStreamingCounterDelta uint64 `json:"observed_streaming_counter_delta"`

	Factors []RouteBA2BFullSecondSTCFactorReport `json:"factors"`
	Digest  string                               `json:"digest"`
}

func (report RouteBA2BFullSecondSTCReport) Validate() error {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		return err
	}
	plan, err := deriveRouteBA2BFullSecondSTCPlan(params)
	if err != nil {
		return err
	}
	if report.SchemaVersion != routeBA2BFullSecondSTCReportSchema ||
		report.Claim != routeBA2BFullSecondSTCClaim ||
		report.SourceLevelQ != plan.sourceEffectiveLiteral.LevelQ ||
		report.InputLevel != routeBA2BFullSecondSTCLevelQ || report.OutputLevel != 1 ||
		report.LevelP != plan.effectiveLiteral.LevelP || report.LogSlots != plan.effectiveLiteral.LogSlots ||
		!slices.Equal(report.Levels, plan.effectiveLiteral.Levels) ||
		report.TransformType != int(plan.effectiveLiteral.Type) || report.Format != int(plan.effectiveLiteral.Format) ||
		report.GeneratorPrecisionBits != rbdftGeneratorPrecision ||
		report.EncoderPrecisionBits != rbdftGeneratorPrecision {
		return lineagef("Route-B full A2B second-STC report schedule or precision changed")
	}
	if report.RawLiteralDigest != hex.EncodeToString(plan.rawLiteralDigest[:]) ||
		report.RawScalingDigest != hex.EncodeToString(plan.rawScalingDigest[:]) ||
		report.EffectiveLiteralDigest != hex.EncodeToString(plan.effectiveLiteralDigest[:]) ||
		report.EffectiveScalingDigest != hex.EncodeToString(plan.effectiveScalingDigest[:]) ||
		!slices.Equal(report.GaloisElements, plan.galoisElements) {
		return lineagef("Route-B full A2B second-STC source or key identity changed")
	}
	if report.RawLiteralDigest != routeBA2BFullSecondSTCRawLiteralDigest ||
		report.RawScalingDigest != routeBA2BFullSecondSTCRawScalingDigest ||
		report.EffectiveLiteralDigest != routeBA2BFullSecondSTCEffectiveLiteralDigest ||
		report.EffectiveScalingDigest != routeBA2BFullSecondSTCEffectiveScalingDigest {
		return lineagef("Route-B full A2B second-STC frozen source identity changed")
	}
	wantDiagonals := []uint32{plan.profile.diagonalCounts[0], plan.profile.diagonalCounts[1]}
	if report.FactorCount != uint32(plan.profile.factorCount) ||
		!slices.Equal(report.FactorDiagonalCounts, wantDiagonals) ||
		report.VectorLength != plan.profile.vectorLength ||
		report.ExpectedPolyBytes != plan.profile.expectedPolyBytes || len(report.Factors) != 2 {
		return lineagef("Route-B full A2B second-STC factor profile changed")
	}
	if report.TraceStatus != "success" || report.TraceDigest != routeBA2BFullSecondSTCTraceDigest ||
		report.TraceCompletedEvents != 13 || report.TraceCleanupEvents != 0 ||
		report.DefaultWholeCounterDelta != 0 || report.ExplicitWholeCounterDelta != 0 ||
		report.RawNumericCounterDelta != 0 || report.ObservedStreamingCounterDelta != 1 {
		return lineagef("Route-B full A2B second-STC trace or construction ledger changed")
	}
	seenNumeric := make(map[string]struct{}, len(report.Factors))
	seenEncoded := make(map[string]struct{}, len(report.Factors))
	for index, factor := range report.Factors {
		minimumEncodedBytes := uint64(wantDiagonals[index]) * plan.profile.expectedPolyBytes
		if factor.Index != uint32(index) || factor.DiagonalCount != wantDiagonals[index] ||
			!routeBA2BFullIsSHA256(factor.NumericDigest) || factor.NumericBytes == 0 ||
			!routeBA2BFullIsSHA256(factor.EncodedDigest) || factor.EncodedBytes <= minimumEncodedBytes {
			return lineagef("Route-B full A2B second-STC factor %d evidence changed", index)
		}
		if _, exists := seenNumeric[factor.NumericDigest]; exists {
			return lineagef("Route-B full A2B second-STC numeric factor digest is duplicated")
		}
		if _, exists := seenEncoded[factor.EncodedDigest]; exists {
			return lineagef("Route-B full A2B second-STC encoded factor digest is duplicated")
		}
		seenNumeric[factor.NumericDigest] = struct{}{}
		seenEncoded[factor.EncodedDigest] = struct{}{}
		if factor != routeBA2BFullSecondSTCFrozenFactors[index] {
			return lineagef("Route-B full A2B second-STC frozen factor %d changed", index)
		}
	}
	wantDigest, err := digestRouteBA2BFullSecondSTCReport(report)
	if err != nil || report.Digest != routeBA2BFullSecondSTCReportDigest || report.Digest != wantDigest {
		return lineagef("Route-B full A2B second-STC report digest changed")
	}
	return nil
}

func routeBA2BFullIsSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	var nonzero byte
	for _, item := range decoded {
		nonzero |= item
	}
	return nonzero != 0
}

func digestRouteBA2BFullSecondSTCReport(report RouteBA2BFullSecondSTCReport) (string, error) {
	var canonical strings.Builder
	fmt.Fprintf(&canonical,
		"%s|claim=%s|source-q=%d|levels=%d,%d,%d|P=%d|log-slots=%d|depths=%v|type=%d|format=%d|precision=%d,%d|raw=%s,%s|effective=%s,%s|galois=%v|factor-profile=%d,%v,%d,%d|trace=%s,%s,%d,%d|counters=%d,%d,%d,%d",
		report.SchemaVersion, report.Claim, report.SourceLevelQ,
		report.InputLevel, report.OutputLevel, routeBA2BFullSecondSTCLevelQ,
		report.LevelP, report.LogSlots, report.Levels, report.TransformType, report.Format,
		report.GeneratorPrecisionBits, report.EncoderPrecisionBits,
		report.RawLiteralDigest, report.RawScalingDigest,
		report.EffectiveLiteralDigest, report.EffectiveScalingDigest,
		report.GaloisElements, report.FactorCount, report.FactorDiagonalCounts,
		report.VectorLength, report.ExpectedPolyBytes,
		report.TraceStatus, report.TraceDigest, report.TraceCompletedEvents, report.TraceCleanupEvents,
		report.DefaultWholeCounterDelta, report.ExplicitWholeCounterDelta,
		report.RawNumericCounterDelta, report.ObservedStreamingCounterDelta,
	)
	for _, factor := range report.Factors {
		fmt.Fprintf(&canonical, "|factor=%d,%d,%s,%d,%s,%d",
			factor.Index, factor.DiagonalCount, factor.NumericDigest, factor.NumericBytes,
			factor.EncodedDigest, factor.EncodedBytes,
		)
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:]), nil
}

func buildRouteBA2BFullSecondSTC(
	evaluator *bootstrapping.Evaluator,
) (matrix dft.Matrix, report RouteBA2BFullSecondSTCReport, err error) {
	if evaluator == nil || evaluator.Evaluator == nil || evaluator.DFTEvaluator == nil ||
		evaluator.MemEvaluationKeySet == nil {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B second-STC evaluator graph is incomplete")
	}
	params := evaluator.BootstrappingParameters
	plan, err := deriveRouteBA2BFullSecondSTCPlan(params)
	if err != nil {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, err
	}
	if !rbdftEqualLiteralExact(evaluator.SlotsToCoeffsParameters, plan.sourceEffectiveLiteral) {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B installed STC literal differs from the supplemental source anchor")
	}
	if err = evaluator.S2CDFTMatrix.ValidateAgainst(params, plan.sourceEffectiveLiteral); err != nil {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, fmt.Errorf("secureeval: validate Route-B full A2B installed STC anchor: %w", err)
	}
	if len(evaluator.S2CDFTMatrix.Matrices) != 2 {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B installed STC factor count changed")
	}
	residentPointers := make(map[uintptr]struct{}, len(evaluator.S2CDFTMatrix.Matrices))
	for _, factor := range evaluator.S2CDFTMatrix.Matrices {
		pointer := reflect.ValueOf(factor.Vec).Pointer()
		if pointer == 0 {
			return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B installed STC contains an empty factor")
		}
		residentPointers[pointer] = struct{}{}
	}
	for _, element := range plan.galoisElements {
		key, keyErr := evaluator.MemEvaluationKeySet.GetGaloisKey(element)
		if keyErr != nil || key == nil {
			return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B second-STC Galois key %d is missing", element)
		}
	}

	var encoder *ckks.Encoder
	var consumer *routeBRBDFTFactorConsumer
	defer func() {
		if consumer != nil {
			consumer.dropEncoderReference()
		}
		encoder = nil
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("secureeval: Route-B full A2B second-STC builder panicked: %v", recovered)
		}
		if err != nil {
			matrix = dft.Matrix{}
			report = RouteBA2BFullSecondSTCReport{}
		}
	}()

	encoder = ckks.NewEncoder(params, rbdftGeneratorPrecision)
	consumer, err = newRouteBRBDFTFactorConsumer(params, encoder, plan.effectiveLiteral, plan.profile)
	if err != nil {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, fmt.Errorf("secureeval: create Route-B full A2B second-STC factor consumer: %w", err)
	}
	before := dft.SnapshotMatrixConstructionCounters()
	var trace dft.ObservedStreamingTrace
	matrix, trace, err = dft.NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, dft.ObservedSlotsToCoeffs, plan.effectiveLiteral,
		encoder, rbdftGeneratorPrecision, consumer,
	)
	if err != nil {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, fmt.Errorf("secureeval: build observed Route-B full A2B second STC: %w", err)
	}
	delta, err := dft.SnapshotMatrixConstructionCounters().Delta(before)
	if err != nil {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, fmt.Errorf("secureeval: Route-B full A2B second-STC construction counters: %w", err)
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 ||
		delta.ObservedStreaming() != 1 {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, lineagef(
			"Route-B full A2B second-STC construction delta is %d/%d/%d/%d, want 0/0/0/1",
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(),
		)
	}
	evidence, err := consumer.promote(matrix, trace)
	if err != nil {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, fmt.Errorf("secureeval: promote Route-B full A2B second-STC evidence: %w", err)
	}
	consumer.dropEncoderReference()
	encoder = nil
	if err = matrix.ValidateAgainst(params, plan.effectiveLiteral); err != nil ||
		matrix.LevelQ != routeBA2BFullSecondSTCLevelQ || matrix.LevelQ-matrix.Depth(true) != 1 ||
		len(matrix.Matrices) != 2 {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B second STC is not an authenticated L3-to-L1 matrix: %v", err)
	}
	for index, factor := range matrix.Matrices {
		pointer := reflect.ValueOf(factor.Vec).Pointer()
		if pointer == 0 {
			return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B second-STC factor %d is empty", index)
		}
		if _, aliases := residentPointers[pointer]; aliases {
			return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B second STC aliases the installed STC")
		}
	}
	report, err = newRouteBA2BFullSecondSTCReport(plan, evidence, trace, delta)
	if err != nil {
		return dft.Matrix{}, RouteBA2BFullSecondSTCReport{}, err
	}
	return matrix, report, nil
}

func newRouteBA2BFullSecondSTCReport(
	plan routeBA2BFullSecondSTCPlan,
	evidence rbdftPromotedFactorEvidence,
	trace dft.ObservedStreamingTrace,
	delta dft.MatrixConstructionCounters,
) (RouteBA2BFullSecondSTCReport, error) {
	if evidence.role != dft.ObservedSlotsToCoeffs || evidence.count != 2 {
		return RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B second-STC promoted evidence role or count changed")
	}
	if err := trace.Validate(); err != nil || trace.Status() != dft.ObservedStreamingSuccess ||
		trace.Role() != dft.ObservedSlotsToCoeffs || trace.FactorCount() != 2 {
		return RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B second-STC trace changed: %v", err)
	}
	factors := make([]RouteBA2BFullSecondSTCFactorReport, 2)
	for index := range factors {
		factor := evidence.factors[index]
		if factor.index != uint32(index) {
			return RouteBA2BFullSecondSTCReport{}, lineagef("Route-B full A2B second-STC promoted factor order changed")
		}
		factors[index] = RouteBA2BFullSecondSTCFactorReport{
			Index: uint32(index), DiagonalCount: plan.profile.diagonalCounts[index],
			NumericDigest: hex.EncodeToString(factor.numeric.digest[:]), NumericBytes: factor.numeric.bytes,
			EncodedDigest: hex.EncodeToString(factor.encoded.digest[:]), EncodedBytes: factor.encoded.bytes,
		}
	}
	traceDigest := trace.Digest()
	report := RouteBA2BFullSecondSTCReport{
		SchemaVersion: routeBA2BFullSecondSTCReportSchema, Claim: routeBA2BFullSecondSTCClaim,
		SourceLevelQ: plan.sourceEffectiveLiteral.LevelQ,
		InputLevel:   routeBA2BFullSecondSTCLevelQ, OutputLevel: 1,
		LevelP: plan.effectiveLiteral.LevelP, LogSlots: plan.effectiveLiteral.LogSlots,
		Levels:        append([]int(nil), plan.effectiveLiteral.Levels...),
		TransformType: int(plan.effectiveLiteral.Type), Format: int(plan.effectiveLiteral.Format),
		GeneratorPrecisionBits: rbdftGeneratorPrecision, EncoderPrecisionBits: rbdftGeneratorPrecision,
		RawLiteralDigest:       hex.EncodeToString(plan.rawLiteralDigest[:]),
		RawScalingDigest:       hex.EncodeToString(plan.rawScalingDigest[:]),
		EffectiveLiteralDigest: hex.EncodeToString(plan.effectiveLiteralDigest[:]),
		EffectiveScalingDigest: hex.EncodeToString(plan.effectiveScalingDigest[:]),
		GaloisElements:         append([]uint64(nil), plan.galoisElements...),
		FactorCount:            uint32(plan.profile.factorCount),
		FactorDiagonalCounts:   []uint32{plan.profile.diagonalCounts[0], plan.profile.diagonalCounts[1]},
		VectorLength:           plan.profile.vectorLength, ExpectedPolyBytes: plan.profile.expectedPolyBytes,
		TraceStatus: "success", TraceDigest: hex.EncodeToString(traceDigest[:]),
		TraceCompletedEvents: trace.CompletedEventCount(), TraceCleanupEvents: uint32(len(trace.CleanupEvents())),
		DefaultWholeCounterDelta: delta.DefaultWhole(), ExplicitWholeCounterDelta: delta.ExplicitWhole(),
		RawNumericCounterDelta: delta.RawNumeric(), ObservedStreamingCounterDelta: delta.ObservedStreaming(),
		Factors: factors,
	}
	var err error
	report.Digest, err = digestRouteBA2BFullSecondSTCReport(report)
	if err != nil {
		return RouteBA2BFullSecondSTCReport{}, err
	}
	if err = report.Validate(); err != nil {
		return RouteBA2BFullSecondSTCReport{}, err
	}
	return report, nil
}

// RouteBA2BFullResult owns the two LSB-first Boolean half ciphertexts.
type RouteBA2BFullResult struct {
	lowMSB  *rlwe.Ciphertext
	highMSB *rlwe.Ciphertext
}

func (result RouteBA2BFullResult) LowMSB() *rlwe.Ciphertext {
	if result.lowMSB == nil {
		return nil
	}
	return result.lowMSB.CopyNew()
}

func (result RouteBA2BFullResult) HighMSB() *rlwe.Ciphertext {
	if result.highMSB == nil {
		return nil
	}
	return result.highMSB.CopyNew()
}

type routeBA2BFullCircuit struct {
	first           *routeBA2BFirstRoundCircuit
	secondSTC       dft.Matrix
	secondSTCReport RouteBA2BFullSecondSTCReport
	iter1Mask       *rlwe.Plaintext
	idScale         *rlwe.Plaintext
	iter1MaskDigest string
	idScaleDigest   string
}

// routeBA2BFullPreparedEvaluator owns the immutable circuit material and the
// two key-bound Gao kernels used by every sequential evaluation.
type routeBA2BFullPreparedEvaluator struct {
	source  *bootstrapping.Evaluator
	circuit *routeBA2BFullCircuit
	kernel0 *homchain.GaoA2BKernelN16L11Evaluator
	kernel1 *homchain.GaoA2BKernelN16L11Evaluator
}

func newRouteBA2BFullCircuit(evaluator *bootstrapping.Evaluator) (*routeBA2BFullCircuit, error) {
	first, err := newRouteBA2BFirstRoundCircuit(evaluator)
	if err != nil {
		return nil, err
	}
	secondSTC, secondSTCReport, err := buildRouteBA2BFullSecondSTC(evaluator)
	if err != nil {
		return nil, err
	}
	iter1Mask, idScale, iter1MaskDigest, idScaleDigest, err := newRouteBA2BFullOperands(evaluator.BootstrappingParameters)
	if err != nil {
		return nil, err
	}
	if iter1Mask.Level() != 4 || idScale.Level() != 5 ||
		!iter1Mask.Scale.Equal(rlwe.NewScale(evaluator.BootstrappingParameters.Q()[4])) ||
		!idScale.Scale.Equal(rlwe.NewScale(evaluator.BootstrappingParameters.Q()[5])) {
		return nil, lineagef("Route-B full A2B serial plaintext state changed")
	}
	return &routeBA2BFullCircuit{
		first: first, secondSTC: secondSTC, secondSTCReport: secondSTCReport,
		iter1Mask: iter1Mask, idScale: idScale,
		iter1MaskDigest: iter1MaskDigest, idScaleDigest: idScaleDigest,
	}, nil
}

func newRouteBA2BFullPreparedEvaluator(
	evaluator *bootstrapping.Evaluator,
) (*routeBA2BFullPreparedEvaluator, error) {
	if evaluator == nil || evaluator.Evaluator == nil || evaluator.DFTEvaluator == nil {
		return nil, lineagef("Route-B full A2B evaluator is nil")
	}
	circuit, err := newRouteBA2BFullCircuit(evaluator)
	if err != nil {
		return nil, err
	}
	kernel0, err := bindRouteBA2BFirstRoundKernel(circuit.first.kernel, evaluator)
	if err != nil {
		return nil, fmt.Errorf("secureeval: bind Route-B full A2B iter0 kernel: %w", err)
	}
	kernel1, err := bindRouteBA2BFirstRoundKernel(circuit.first.kernel, evaluator)
	if err != nil {
		return nil, fmt.Errorf("secureeval: bind Route-B full A2B iter1 kernel: %w", err)
	}
	if kernel0 == kernel1 {
		return nil, lineagef("Route-B full A2B kernel evaluator instances are aliased")
	}
	return &routeBA2BFullPreparedEvaluator{
		source: evaluator, circuit: circuit, kernel0: kernel0, kernel1: kernel1,
	}, nil
}

// RunFirstSparseA2BFull executes the one authorized complete two-round 8-bit
// conversion. Capacity admission and installed-resident validation occur
// before supplemental construction or HE dispatch.
func (installed *RouteBInstalledEvaluator) RunFirstSparseA2BFull(
	input *rlwe.Ciphertext,
) (
	result RouteBA2BFullResult,
	firstOperation RouteBFirstOperationReport,
	fullReport RouteBA2BFullReport,
	err error,
) {
	var capturedHigh *rlwe.Ciphertext
	runner := func(
		evaluator *bootstrapping.Evaluator,
		ciphertext *rlwe.Ciphertext,
	) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		preparationStarted := time.Now()
		prepared, prepareErr := newRouteBA2BFullPreparedEvaluator(evaluator)
		if prepareErr != nil {
			return nil, routeBFirstOperationObservation{}, prepareErr
		}
		preparationWall := uint64(time.Since(preparationStarted).Nanoseconds())
		if preparationWall == 0 {
			preparationWall = 1
		}
		low, high, firstObservation, report, runErr := prepared.evaluateNew(ciphertext)
		if runErr != nil {
			return nil, routeBFirstOperationObservation{}, runErr
		}
		installed.cell.preparedA2BFull = prepared
		installed.cell.preparedA2BFullWallNanos = preparationWall
		capturedHigh = high
		fullReport = report
		return low, firstObservation, nil
	}
	low, firstOperation, err := installed.runFirstOperationWithHooks(
		input, routeBCapacityGateA2BFull, routeBRuntimeOperationA2BFull,
		validateCanonicalRouteBInstalledResident,
		validateCanonicalRouteBInstalledEvaluator,
		runner,
	)
	if err != nil {
		return RouteBA2BFullResult{}, RouteBFirstOperationReport{}, RouteBA2BFullReport{}, err
	}
	if low == nil || capturedHigh == nil || fullReport.Digest == "" {
		return RouteBA2BFullResult{}, RouteBFirstOperationReport{}, RouteBA2BFullReport{}, lineagef("Route-B full A2B returned an incomplete result")
	}
	return RouteBA2BFullResult{lowMSB: low, highMSB: capturedHigh}, firstOperation, fullReport, nil
}

// RunSparseA2BFull executes another complete conversion with the circuit
// prepared by RunFirstSparseA2BFull. Calls on copies of the same installed
// evaluator are serialized by the shared cell.
func (installed *RouteBInstalledEvaluator) RunSparseA2BFull(
	input *rlwe.Ciphertext,
) (
	result RouteBA2BFullResult,
	operation RouteBFirstOperationReport,
	fullReport RouteBA2BFullReport,
	err error,
) {
	var capturedHigh *rlwe.Ciphertext
	runner := func(
		evaluator *bootstrapping.Evaluator,
		ciphertext *rlwe.Ciphertext,
	) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		if installed == nil || installed.cell == nil || installed.cell.preparedA2BFull == nil ||
			installed.cell.preparedA2BFull.source != evaluator {
			return nil, routeBFirstOperationObservation{}, lineagef("Route-B full A2B evaluator is not prepared")
		}
		low, high, observation, report, runErr := installed.cell.preparedA2BFull.evaluateNew(ciphertext)
		if runErr != nil {
			return nil, routeBFirstOperationObservation{}, runErr
		}
		capturedHigh = high
		fullReport = report
		return low, observation, nil
	}
	low, operation, err := installed.runOperationalA2BFullWithHooks(
		input,
		runner,
	)
	if err != nil {
		return RouteBA2BFullResult{}, RouteBFirstOperationReport{}, RouteBA2BFullReport{}, err
	}
	if low == nil || capturedHigh == nil || fullReport.Digest == "" {
		return RouteBA2BFullResult{}, RouteBFirstOperationReport{}, RouteBA2BFullReport{}, lineagef("Route-B prepared full A2B returned an incomplete result")
	}
	return RouteBA2BFullResult{lowMSB: low, highMSB: capturedHigh}, operation, fullReport, nil
}

func runCanonicalRouteBFirstSparseA2BFull(
	evaluator *bootstrapping.Evaluator,
	input *rlwe.Ciphertext,
) (
	lowMSB *rlwe.Ciphertext,
	highMSB *rlwe.Ciphertext,
	firstObservation routeBFirstOperationObservation,
	report RouteBA2BFullReport,
	err error,
) {
	prepared, err := newRouteBA2BFullPreparedEvaluator(evaluator)
	if err != nil {
		return nil, nil, firstObservation, report, err
	}
	return prepared.evaluateNew(input)
}

func (prepared *routeBA2BFullPreparedEvaluator) evaluateNew(
	input *rlwe.Ciphertext,
) (
	lowMSB *rlwe.Ciphertext,
	highMSB *rlwe.Ciphertext,
	firstObservation routeBFirstOperationObservation,
	report RouteBA2BFullReport,
	err error,
) {
	started := time.Now()
	if prepared == nil || prepared.source == nil || prepared.circuit == nil ||
		prepared.kernel0 == nil || prepared.kernel1 == nil || input == nil {
		return nil, nil, firstObservation, report, lineagef("Route-B prepared full A2B evaluator or input is nil")
	}
	evaluator := prepared.source
	circuit := prepared.circuit
	kernel0Evaluator := prepared.kernel0
	kernel1Evaluator := prepared.kernel1
	if evaluator.Evaluator == nil || evaluator.DFTEvaluator == nil {
		return nil, nil, firstObservation, report, lineagef("Route-B prepared full A2B source evaluator is incomplete")
	}
	params := evaluator.BootstrappingParameters
	defaultScale := params.DefaultScale()
	if input.Level() != 20 || input.Degree() != 1 || input.LogN() != 16 ||
		input.LogDimensions != (ring.Dimensions{Rows: 0, Cols: 11}) || !input.Scale.Equal(defaultScale) {
		return nil, nil, firstObservation, report, lineagef("Route-B full A2B arithmetic input state changed")
	}
	inputBefore := input.CopyNew()
	states := make([]RouteBA2BFullState, 0, 32)
	appendState := func(stage string, ciphertext *rlwe.Ciphertext, target rlwe.Scale) error {
		state, stateErr := snapshotRouteBA2BFullState(stage, ciphertext, target)
		if stateErr == nil {
			states = append(states, state)
		}
		return stateErr
	}
	appendKernelStates := func(iteration int, provenance homchain.GaoA2BKernelProvenance) error {
		kernelStates := provenance.States()
		if len(kernelStates) != 8 {
			return lineagef("Route-B full A2B iter%d kernel state count changed", iteration)
		}
		for _, state := range kernelStates {
			states = append(states, RouteBA2BFullState{
				Stage: fmt.Sprintf("iter%d-kernel-%s", iteration, state.Stage),
				Level: state.Level, Degree: state.Degree, LogRows: 0, LogColumns: 11,
				ScaleHex: state.Scale.ValueHex(), ScaleExact: state.ScaleExact,
			})
		}
		return nil
	}
	if err = appendState("arithmetic-input", input, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	counts := homchain.A2BFullOperationCounts{}

	halves, err := circuit.first.triangle.ZToCNew(input.CopyNew(), circuit.first.specialB0)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B special-b0 Z-To-C: %w", err)
	}
	counts.SpecialB0Transforms++
	if len(halves) != 2 || requireRouteBA2BFullState("special low", halves[0], 19, defaultScale) != nil ||
		requireRouteBA2BFullState("special high", halves[1], 19, defaultScale) != nil {
		return nil, nil, firstObservation, report, lineagef("Route-B full A2B special-b0 output state changed")
	}
	specialLow, specialHigh := halves[0].CopyNew(), halves[1].CopyNew()
	if err = appendState("special-b0-low", halves[0], defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("special-b0-high", halves[1], defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}

	iter0Masked, err := evaluator.Evaluator.MulNew(halves[0], circuit.first.lowMask)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B iter0 mask multiply: %w", err)
	}
	if err = evaluator.Evaluator.Rescale(iter0Masked, iter0Masked); err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B iter0 mask rescale: %w", err)
	}
	counts.MaskMulRescales++
	if err = requireRouteBA2BFullState("iter0 mask", iter0Masked, 18, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("iter0-low-mask", iter0Masked, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}

	iter0STC, err := evaluator.SlotsToCoeffs(iter0Masked, nil)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B iter0 STC: %w", err)
	}
	if err = requireRouteBA2BFullState("iter0 STC", iter0STC, 16, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("iter0-stc", iter0STC, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	iter0Refreshed, firstObservation, err := runCanonicalRouteBFirstSparseMR0(evaluator, iter0STC)
	if err != nil {
		return nil, nil, routeBFirstOperationObservation{}, report, fmt.Errorf("secureeval: Route-B full A2B iter0 MR0: %w", err)
	}
	counts.RefreshInvocations++
	counts.SharedCTSUses++
	if err = appendState("iter0-mr0-output", iter0Refreshed, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	normalization0, err := normalizeRouteBA2BFirstRoundKernelScale(iter0Refreshed, defaultScale)
	if err != nil {
		return nil, nil, firstObservation, report, err
	}
	iter0Kernel, err := kernel0Evaluator.EvaluateNew(iter0Refreshed)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B iter0 Gao kernel: %w", err)
	}
	counts.KernelInvocations++
	iter0Provenance := iter0Kernel.Provenance()
	if err = appendKernelStates(0, iter0Provenance); err != nil {
		return nil, nil, firstObservation, report, err
	}
	id0, msb0 := iter0Kernel.IDCiphertext(), iter0Kernel.MSBCiphertext()
	if err = requireRouteBA2BFullState("iter0 ID", id0, 5, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = requireRouteBA2BFullState("iter0 MSB", msb0, 5, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	id0Saved := id0.CopyNew()

	id0Over16, err := evaluator.Evaluator.MulNew(id0, circuit.idScale)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B ID0/16 multiply: %w", err)
	}
	if err = evaluator.Evaluator.Rescale(id0Over16, id0Over16); err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B ID0/16 rescale: %w", err)
	}
	counts.IDScaleMulRescales++
	if err = requireRouteBA2BFullState("ID0/16", id0Over16, 4, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("id0-over-16", id0Over16, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}

	highAligned := specialHigh.CopyNew()
	evaluator.Evaluator.DropLevel(highAligned, highAligned.Level()-4)
	counts.AlignmentDrops++
	if err = requireRouteBA2BFullState("high core aligned", highAligned, 4, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("high-core-aligned", highAligned, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	highUpdated, err := evaluator.Evaluator.SubNew(highAligned, id0Over16)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B high update: %w", err)
	}
	counts.Subtractions++
	if err = requireRouteBA2BFullState("high core updated", highUpdated, 4, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	highUpdatedSaved := highUpdated.CopyNew()
	if err = appendState("high-core-minus-id0-over-16", highUpdated, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}

	lowAligned := specialLow.CopyNew()
	evaluator.Evaluator.DropLevel(lowAligned, lowAligned.Level()-5)
	counts.AlignmentDrops++
	if err = requireRouteBA2BFullState("low core aligned", lowAligned, 5, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("low-core-aligned", lowAligned, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	lowSelfRemoved, err := evaluator.Evaluator.SubNew(lowAligned, id0)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B low self-removal: %w", err)
	}
	counts.Subtractions++
	if err = requireRouteBA2BFullState("low core self-removed", lowSelfRemoved, 5, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("low-core-minus-id0", lowSelfRemoved, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}

	iter1Masked, err := evaluator.Evaluator.MulNew(highUpdated, circuit.iter1Mask)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B iter1 mask multiply: %w", err)
	}
	if err = evaluator.Evaluator.Rescale(iter1Masked, iter1Masked); err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B iter1 mask rescale: %w", err)
	}
	counts.MaskMulRescales++
	if err = requireRouteBA2BFullState("iter1 mask", iter1Masked, 3, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	iter1MaskedSaved := iter1Masked.CopyNew()
	if err = appendState("iter1-high-mask", iter1Masked, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}

	iter1STC, err := evaluator.DFTEvaluator.SlotsToCoeffsNew(iter1Masked, nil, circuit.secondSTC)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B iter1 STC: %w", err)
	}
	if err = requireRouteBA2BFullState("iter1 STC", iter1STC, 1, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("iter1-stc", iter1STC, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	iter1Refreshed, secondObservation, err := runCanonicalRouteBFirstSparseMR0(evaluator, iter1STC)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B iter1 MR0: %w", err)
	}
	counts.RefreshInvocations++
	counts.SharedCTSUses++
	if err = appendState("iter1-mr0-output", iter1Refreshed, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	normalization1, err := normalizeRouteBA2BFirstRoundKernelScale(iter1Refreshed, defaultScale)
	if err != nil {
		return nil, nil, firstObservation, report, err
	}
	iter1Kernel, err := kernel1Evaluator.EvaluateNew(iter1Refreshed)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B iter1 Gao kernel: %w", err)
	}
	counts.KernelInvocations++
	iter1Provenance := iter1Kernel.Provenance()
	if err = appendKernelStates(1, iter1Provenance); err != nil {
		return nil, nil, firstObservation, report, err
	}
	id1, msb1 := iter1Kernel.IDCiphertext(), iter1Kernel.MSBCiphertext()
	if err = requireRouteBA2BFullState("iter1 ID", id1, 5, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = requireRouteBA2BFullState("iter1 MSB", msb1, 5, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	id1Saved := id1.CopyNew()
	id1Aligned := id1.CopyNew()
	evaluator.Evaluator.DropLevel(id1Aligned, id1Aligned.Level()-4)
	counts.AlignmentDrops++
	if err = requireRouteBA2BFullState("ID1 aligned", id1Aligned, 4, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("id1-aligned", id1Aligned, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	highSelfRemoved, err := evaluator.Evaluator.SubNew(highUpdated, id1Aligned)
	if err != nil {
		return nil, nil, firstObservation, report, fmt.Errorf("secureeval: Route-B full A2B high self-removal: %w", err)
	}
	counts.Subtractions++
	if err = requireRouteBA2BFullState("high core self-removed", highSelfRemoved, 4, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}
	if err = appendState("high-core-minus-id0-over-16-minus-id1", highSelfRemoved, defaultScale); err != nil {
		return nil, nil, firstObservation, report, err
	}

	if !input.Equal(inputBefore) || !halves[0].Equal(specialLow) || !halves[1].Equal(specialHigh) ||
		!id0.Equal(id0Saved) || !highUpdated.Equal(highUpdatedSaved) ||
		!iter1Masked.Equal(iter1MaskedSaved) || !id1.Equal(id1Saved) {
		return nil, nil, firstObservation, report, lineagef("Route-B full A2B mutated an input or retained serial core")
	}
	secondMR0, err := newRouteBA2BFullMR0Report(secondObservation)
	if err != nil {
		return nil, nil, firstObservation, report, err
	}
	capacity, err := canonicalRouteBCapacityPlan(routeBCapacityGateA2BFull)
	if err != nil {
		return nil, nil, firstObservation, report, err
	}
	wall := uint64(time.Since(started).Nanoseconds())
	if wall == 0 {
		wall = 1
	}
	profile := circuit.first.kernel.Profile()
	report = RouteBA2BFullReport{
		SchemaVersion: routeBA2BFullReportSchema, Claim: routeBA2BFullClaim,
		CapacityPlanDigest: capacity.Digest(), KernelProfileDigest: profile.Digest(),
		ExponentialArtifactDigest: profile.ExponentialArtifactDigest(), LUTTableDigest: profile.LUTTableDigest(),
		TransformSourceDigest: circuit.first.transformSourceDigest,
		Iter0MaskSourceDigest: circuit.first.maskSourceDigest,
		Iter1MaskSourceDigest: circuit.iter1MaskDigest, IDScaleSourceDigest: circuit.idScaleDigest,
		TransformRotationIndexes:  append([]int(nil), circuit.first.rotationIndexes...),
		TransformGaloisElements:   append([]uint64(nil), circuit.first.galoisElements...),
		LogBabyStepGiantStepRatio: routeBA2BFirstRoundBSGSRatio,
		LowN1:                     circuit.first.specialB0.Low.N1, HighN1: circuit.first.specialB0.High.N1,
		SecondSTC: circuit.secondSTCReport, SecondMR0: secondMR0,
		ScaleNormalizations: []RouteBA2BFullScaleNormalizationReport{
			newRouteBA2BFullScaleNormalizationReport(0, normalization0),
			newRouteBA2BFullScaleNormalizationReport(1, normalization1),
		},
		States: states,
		KernelOperationCounts: [2]homchain.GaoA2BKernelOperationCounts{
			iter0Provenance.OperationCounts(), iter1Provenance.OperationCounts(),
		},
		OperationCounts: counts, WallNanoseconds: wall,
	}
	report.Digest, err = digestRouteBA2BFullReport(report)
	if err != nil {
		return nil, nil, firstObservation, RouteBA2BFullReport{}, err
	}
	if err = report.Validate(); err != nil {
		return nil, nil, firstObservation, RouteBA2BFullReport{}, err
	}
	return msb0, msb1, firstObservation, report, nil
}

func requireRouteBA2BFullState(name string, ciphertext *rlwe.Ciphertext, level int, scale rlwe.Scale) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level || ciphertext.Degree() != 1 ||
		ciphertext.LogDimensions != (ring.Dimensions{Rows: 0, Cols: 11}) || !ciphertext.Scale.Equal(scale) {
		return lineagef("Route-B full A2B %s is not L%d/degree1/L11/exact-default-scale", name, level)
	}
	return nil
}

func snapshotRouteBA2BFullState(stage string, ciphertext *rlwe.Ciphertext, target rlwe.Scale) (RouteBA2BFullState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return RouteBA2BFullState{}, lineagef("cannot snapshot nil Route-B full A2B %s state", stage)
	}
	scale, err := homchain.NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return RouteBA2BFullState{}, err
	}
	targetScale, err := homchain.NewExactScaleSnapshot(target)
	if err != nil {
		return RouteBA2BFullState{}, err
	}
	return RouteBA2BFullState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogRows: ciphertext.LogDimensions.Rows, LogColumns: ciphertext.LogDimensions.Cols,
		ScaleHex: scale.ValueHex(), ScaleExact: scale.Equal(targetScale),
	}, nil
}

func newRouteBA2BFullScaleNormalizationReport(
	iteration int,
	evidence routeBA2BFirstRoundScaleNormalizationEvidence,
) RouteBA2BFullScaleNormalizationReport {
	return RouteBA2BFullScaleNormalizationReport{
		Iteration: iteration, SourceScaleHex: evidence.SourceScaleHex,
		TargetScaleHex: evidence.TargetScaleHex, AbsLog2Drift: evidence.AbsLog2Drift,
		Bound: routeBA2BFirstRoundMaxScaleLog2Drift, MetadataOnly: evidence.MetadataOnly,
	}
}

func newRouteBA2BFullMR0Report(observation routeBFirstOperationObservation) (RouteBA2BFullMR0Report, error) {
	report := RouteBA2BFullMR0Report{
		TraceGap: observation.traceGap, TraceRotationExponents: observation.traceRotationExponents,
		TraceGaloisElements:     observation.traceGaloisElements,
		TraceDigest:             hex.EncodeToString(observation.traceDigest[:]),
		ModUpInputOutputAliased: observation.modUpInputOutputAliased, CTImagNil: observation.ctImagNil,
		RaisedLevel: observation.raisedLevel, OutputLevel: observation.outputLevel,
		WallNanoseconds: observation.wallNanoseconds,
	}
	if err := report.validate(); err != nil {
		return RouteBA2BFullMR0Report{}, err
	}
	return report, nil
}

// routeBA2BFullSecondSTCPlan is a detached construction contract. The
// installed L18->L16 STC is kept as an immutable source anchor; only deep
// copies with LevelQ=3 may be used to construct the serial-round L3->L1 STC.
type routeBA2BFullSecondSTCPlan struct {
	sourceRawLiteral, sourceEffectiveLiteral dft.MatrixLiteral
	rawLiteral, effectiveLiteral             dft.MatrixLiteral
	profile                                  rbdftFactorProfile
	rawLiteralDigest, rawScalingDigest       RBAUTHDigest
	effectiveLiteralDigest                   RBAUTHDigest
	effectiveScalingDigest                   RBAUTHDigest
	galoisElements                           []uint64
}

func deriveRouteBA2BFullSecondSTCPlan(params ckks.Parameters) (routeBA2BFullSecondSTCPlan, error) {
	plan, err := newRouteBA2BFullSecondSTCPlan(params)
	if err != nil {
		return routeBA2BFullSecondSTCPlan{}, err
	}
	if err = plan.validate(params); err != nil {
		return routeBA2BFullSecondSTCPlan{}, err
	}
	return plan, nil
}

func newRouteBA2BFullSecondSTCPlan(params ckks.Parameters) (routeBA2BFullSecondSTCPlan, error) {
	prepared, _, err := prepareGaoN16RouteBTransportParameters()
	if err != nil {
		return routeBA2BFullSecondSTCPlan{}, err
	}
	raw := prepared.RawParameters()
	effective := prepared.EffectiveParameters()
	if !params.Equal(&effective.BootstrappingParameters) {
		return routeBA2BFullSecondSTCPlan{}, lineagef("Route-B full A2B second-STC parameters differ from the canonical prepared profile")
	}
	sourceRaw := rbdftCloneLiteral(raw.SlotsToCoeffsParameters)
	sourceEffective := rbdftCloneLiteral(effective.SlotsToCoeffsParameters)
	if sourceRaw.LevelQ != 18 || sourceEffective.LevelQ != 18 ||
		!rbdftEqualLiteralExact(sourceEffective, effective.SlotsToCoeffsParameters) {
		return routeBA2BFullSecondSTCPlan{}, lineagef("Route-B full A2B source STC literal changed")
	}

	rawLiteral := rbdftCloneLiteral(sourceRaw)
	effectiveLiteral := rbdftCloneLiteral(sourceEffective)
	rawLiteral.LevelQ = routeBA2BFullSecondSTCLevelQ
	effectiveLiteral.LevelQ = routeBA2BFullSecondSTCLevelQ
	polyBytes, ok := rbdftExpectedPolyBytes(params.N(), routeBA2BFullSecondSTCLevelQ, params.MaxLevelP())
	if !ok {
		return routeBA2BFullSecondSTCPlan{}, lineagef("Route-B full A2B second-STC polynomial size overflow")
	}
	profile := rbdftFactorProfile{
		role: dft.ObservedSlotsToCoeffs, wireRole: RBDFTRoleSTC, factorCount: 2,
		diagonalCounts: [3]uint32{63, 64}, vectorLength: rbdftL11VectorLength,
		expectedPolyBytes: polyBytes, canonicalL11: false,
	}
	if err = rbdftValidateEffectiveLiteral(params, profile, rawLiteral); err != nil {
		return routeBA2BFullSecondSTCPlan{}, fmt.Errorf("secureeval: validate Route-B full A2B raw second STC: %w", err)
	}
	if err = rbdftValidateEffectiveLiteral(params, profile, effectiveLiteral); err != nil {
		return routeBA2BFullSecondSTCPlan{}, fmt.Errorf("secureeval: validate Route-B full A2B effective second STC: %w", err)
	}
	rawLiteralDigest, rawScalingDigest, err := deriveGaoN16RouteBTransformIdentity(
		RBAUTHRoleSTC, RBAUTHPhaseRaw, rawLiteral,
	)
	if err != nil {
		return routeBA2BFullSecondSTCPlan{}, err
	}
	effectiveLiteralDigest, effectiveScalingDigest, err := deriveGaoN16RouteBTransformIdentity(
		RBAUTHRoleSTC, RBAUTHPhaseEffective, effectiveLiteral,
	)
	if err != nil {
		return routeBA2BFullSecondSTCPlan{}, err
	}
	galois := append([]uint64(nil), effectiveLiteral.GaloisElements(params)...)
	slices.Sort(galois)
	galois = slices.Compact(galois)
	sourceGalois := append([]uint64(nil), sourceEffective.GaloisElements(params)...)
	slices.Sort(sourceGalois)
	sourceGalois = slices.Compact(sourceGalois)
	if !slices.Equal(galois, sourceGalois) {
		return routeBA2BFullSecondSTCPlan{}, lineagef("Route-B full A2B second STC changes the installed STC key union")
	}
	return routeBA2BFullSecondSTCPlan{
		sourceRawLiteral: sourceRaw, sourceEffectiveLiteral: sourceEffective,
		rawLiteral: rawLiteral, effectiveLiteral: effectiveLiteral, profile: profile,
		rawLiteralDigest: rawLiteralDigest, rawScalingDigest: rawScalingDigest,
		effectiveLiteralDigest: effectiveLiteralDigest, effectiveScalingDigest: effectiveScalingDigest,
		galoisElements: append([]uint64(nil), galois...),
	}, nil
}

func (plan routeBA2BFullSecondSTCPlan) validate(params ckks.Parameters) error {
	expected, err := newRouteBA2BFullSecondSTCPlan(params)
	if err != nil {
		return err
	}
	if !rbdftEqualLiteralExact(plan.sourceRawLiteral, expected.sourceRawLiteral) ||
		!rbdftEqualLiteralExact(plan.sourceEffectiveLiteral, expected.sourceEffectiveLiteral) ||
		!rbdftEqualLiteralExact(plan.rawLiteral, expected.rawLiteral) ||
		!rbdftEqualLiteralExact(plan.effectiveLiteral, expected.effectiveLiteral) ||
		plan.profile != expected.profile || plan.rawLiteralDigest != expected.rawLiteralDigest ||
		plan.rawScalingDigest != expected.rawScalingDigest ||
		plan.effectiveLiteralDigest != expected.effectiveLiteralDigest ||
		plan.effectiveScalingDigest != expected.effectiveScalingDigest ||
		!slices.Equal(plan.galoisElements, expected.galoisElements) {
		return lineagef("Route-B full A2B second-STC construction plan drifted")
	}
	return nil
}
