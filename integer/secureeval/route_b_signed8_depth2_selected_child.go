package secureeval

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"slices"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

const (
	routeBSigned8Depth2SelectedChildReportSchema = "lcpdte-route-b-signed8-depth2-selected-child-report-v1"
	routeBSigned8Depth2SelectedChildClaim        = "lattigo_n16_l11_signed8_depth2_encrypted_selected_child_security_unverified"
	routeBSigned8Depth2SelectedChildFidelity     = "source_faithful_binary_tree_with_gao_periodic_selector_reraise"

	routeBSigned8Depth2SelectedChildInputLevel           = 20
	routeBSigned8Depth2SelectedChildRootHighLevel        = 5
	routeBSigned8Depth2SelectedChildPhaseBroadcastLevel  = 4
	routeBSigned8Depth2SelectedChildPhaseLevel           = 3
	routeBSigned8Depth2SelectedChildPhaseSTCLevel        = 1
	routeBSigned8Depth2SelectedChildPeriodicInputLevel   = 17
	routeBSigned8Depth2SelectedChildRootBooleanLevel     = 8
	routeBSigned8Depth2SelectedChildConditionedRootLevel = 7
	routeBSigned8Depth2SelectedChildSelectedChildLevel   = 6
	routeBSigned8Depth2SelectedChildChildHighLevel       = 5
	routeBSigned8Depth2SelectedChildChildBroadcastLevel  = 4
	routeBSigned8Depth2SelectedChildChildBooleanLevel    = 3
	routeBSigned8Depth2SelectedChildTerminalProductLevel = 2
	routeBSigned8Depth2SelectedChildOutputLevel          = 1
)

type routeBSigned8Depth2SelectedChildScalePlan struct {
	rootBooleanLevel, conditionedRootLevel, selectedChildLevel  int
	childBooleanLevel, productLevel, outputLevel                int
	rootBooleanScale, conditionerScale, conditionedRootScale    rlwe.Scale
	selectedChildScale, childBooleanScale, terminalProductScale rlwe.Scale
	alphaOperandScale, betaOperandScale, gammaOperandScale      rlwe.Scale
	terminalOutputScale                                         rlwe.Scale
}

func newRouteBSigned8Depth2SelectedChildScalePlan(params ckks.Parameters) (routeBSigned8Depth2SelectedChildScalePlan, error) {
	if params.LogN() != 16 || params.MaxLevel() != 20 || params.MaxLevelP() != 6 ||
		params.LogDefaultScale() != 43 || params.LevelsConsumedPerRescaling() != 1 {
		return routeBSigned8Depth2SelectedChildScalePlan{}, lineagef("selected-child exact-scale plan requires the canonical N16/L11 Route-B parameters")
	}
	scale := params.DefaultScale()
	square0Scale := scale.Mul(scale).Div(rlwe.NewScale(params.Q()[11]))
	rootBooleanScale := square0Scale.Mul(square0Scale).Div(rlwe.NewScale(params.Q()[10]))
	conditionerScale := rlwe.NewScale(params.Q()[8]).Mul(rlwe.NewScale(params.Q()[7])).Div(rootBooleanScale)
	conditionedRootScale := rootBooleanScale.Mul(conditionerScale).Div(rlwe.NewScale(params.Q()[8]))
	selectedChildScale := conditionedRootScale.Mul(scale).Div(rlwe.NewScale(params.Q()[7]))
	terminalProductScale := conditionedRootScale.Mul(scale)
	terminalOutputScale := routeBSigned8Depth2SelectedChildHighPrecisionIntegerScale(params.Q()[7])
	alphaOperandScale := routeBSigned8Depth2SelectedChildHighPrecisionIntegerScale(params.Q()[3])
	betaOperandScale := routeBSigned8Depth2SelectedChildHighPrecisionRatioScale(
		new(big.Int).Mul(new(big.Int).SetUint64(params.Q()[3]), new(big.Int).SetUint64(params.Q()[7])), scale,
	)
	gammaOperandScale := routeBSigned8Depth2SelectedChildHighPrecisionRatioScale(
		new(big.Int).Mul(new(big.Int).SetUint64(params.Q()[3]), new(big.Int).SetUint64(params.Q()[2])), scale,
	)
	scaleHex := func(value rlwe.Scale) string { return value.Value.Text('x', -1) }
	if !rbdftEqualScaleExact(conditionedRootScale, rlwe.NewScale(params.Q()[7])) ||
		!rbdftEqualScaleExact(selectedChildScale, scale) ||
		!rbdftEqualScaleExact(conditionedRootScale.Mul(alphaOperandScale).Div(rlwe.NewScale(params.Q()[3])), terminalOutputScale) ||
		!rbdftEqualScaleExact(scale.Mul(betaOperandScale).Div(rlwe.NewScale(params.Q()[3])), terminalOutputScale) ||
		!rbdftEqualScaleExact(terminalProductScale.Mul(gammaOperandScale).
			Div(rlwe.NewScale(params.Q()[3])).Div(rlwe.NewScale(params.Q()[2])), terminalOutputScale) {
		return routeBSigned8Depth2SelectedChildScalePlan{}, lineagef(
			"selected-child exact-scale algebra changed: conditioned=%s/q7=%s selected=%s/S=%s alpha=%s beta=%s gamma=%s",
			scaleHex(conditionedRootScale), scaleHex(rlwe.NewScale(params.Q()[7])),
			scaleHex(selectedChildScale), scaleHex(scale),
			scaleHex(conditionedRootScale.Mul(alphaOperandScale).Div(rlwe.NewScale(params.Q()[3]))),
			scaleHex(scale.Mul(betaOperandScale).Div(rlwe.NewScale(params.Q()[3]))),
			scaleHex(terminalProductScale.Mul(gammaOperandScale).Div(rlwe.NewScale(params.Q()[3])).Div(rlwe.NewScale(params.Q()[2]))),
		)
	}
	return routeBSigned8Depth2SelectedChildScalePlan{
		rootBooleanLevel:     routeBSigned8Depth2SelectedChildRootBooleanLevel,
		conditionedRootLevel: routeBSigned8Depth2SelectedChildConditionedRootLevel,
		selectedChildLevel:   routeBSigned8Depth2SelectedChildSelectedChildLevel,
		childBooleanLevel:    routeBSigned8Depth2SelectedChildChildBooleanLevel,
		productLevel:         routeBSigned8Depth2SelectedChildTerminalProductLevel,
		outputLevel:          routeBSigned8Depth2SelectedChildOutputLevel,
		rootBooleanScale:     rootBooleanScale, conditionerScale: conditionerScale,
		conditionedRootScale: conditionedRootScale, selectedChildScale: selectedChildScale,
		childBooleanScale: scale, terminalProductScale: terminalProductScale,
		alphaOperandScale: alphaOperandScale, betaOperandScale: betaOperandScale,
		gammaOperandScale: gammaOperandScale, terminalOutputScale: terminalOutputScale,
	}, nil
}

func routeBSigned8Depth2SelectedChildHighPrecisionIntegerScale(value uint64) rlwe.Scale {
	float := new(big.Float).SetPrec(routeBSigned8RootTreeEncoderPrecision).SetMode(big.ToNearestEven).SetUint64(value)
	return rlwe.Scale{Value: *float}
}

func routeBSigned8Depth2SelectedChildHighPrecisionRatioScale(numerator *big.Int, denominator rlwe.Scale) rlwe.Scale {
	value := new(big.Float).SetPrec(routeBSigned8RootTreeEncoderPrecision).SetMode(big.ToNearestEven).SetInt(numerator)
	divisor := new(big.Float).SetPrec(routeBSigned8RootTreeEncoderPrecision).SetMode(big.ToNearestEven)
	divisor.Set(&denominator.Value)
	value.Quo(value, divisor)
	return rlwe.Scale{Value: *value}
}

type RouteBSigned8Depth2SelectedChildScaleReport struct {
	RootBooleanScaleHex     string `json:"root_boolean_scale_hex"`
	ConditionerScaleHex     string `json:"conditioner_scale_hex"`
	ConditionedRootScaleHex string `json:"conditioned_root_scale_hex"`
	SelectedChildScaleHex   string `json:"selected_child_scale_hex"`
	ChildBooleanScaleHex    string `json:"child_boolean_scale_hex"`
	TerminalProductScaleHex string `json:"terminal_product_scale_hex"`
	AlphaOperandScaleHex    string `json:"alpha_operand_scale_hex"`
	BetaOperandScaleHex     string `json:"beta_operand_scale_hex"`
	GammaOperandScaleHex    string `json:"gamma_operand_scale_hex"`
	TerminalOutputScaleHex  string `json:"terminal_output_scale_hex"`
}

func newRouteBSigned8Depth2SelectedChildScaleReport(plan routeBSigned8Depth2SelectedChildScalePlan) (RouteBSigned8Depth2SelectedChildScaleReport, error) {
	values := []rlwe.Scale{
		plan.rootBooleanScale, plan.conditionerScale, plan.conditionedRootScale, plan.selectedChildScale,
		plan.childBooleanScale, plan.terminalProductScale, plan.alphaOperandScale, plan.betaOperandScale,
		plan.gammaOperandScale, plan.terminalOutputScale,
	}
	hexValues := make([]string, len(values))
	for index, value := range values {
		snapshot, err := homchain.NewExactScaleSnapshot(value)
		if err != nil {
			return RouteBSigned8Depth2SelectedChildScaleReport{}, err
		}
		hexValues[index] = snapshot.ValueHex()
	}
	return RouteBSigned8Depth2SelectedChildScaleReport{
		RootBooleanScaleHex: hexValues[0], ConditionerScaleHex: hexValues[1],
		ConditionedRootScaleHex: hexValues[2], SelectedChildScaleHex: hexValues[3],
		ChildBooleanScaleHex: hexValues[4], TerminalProductScaleHex: hexValues[5],
		AlphaOperandScaleHex: hexValues[6], BetaOperandScaleHex: hexValues[7],
		GammaOperandScaleHex: hexValues[8], TerminalOutputScaleHex: hexValues[9],
	}, nil
}

type RouteBSigned8Depth2SelectedChildModelReport struct {
	FeatureIDs [3]uint32  `json:"feature_ids"`
	Thresholds [3]int64   `json:"thresholds"`
	Leaves     [4]float64 `json:"leaves"`
	LeafBits   [4]uint64  `json:"leaf_bits"`
	Digest     string     `json:"digest"`
}

type RouteBSigned8Depth2SelectedChildState struct {
	Stage      string `json:"stage"`
	Level      int    `json:"level"`
	Degree     int    `json:"degree"`
	LogRows    int    `json:"log_rows"`
	LogColumns int    `json:"log_columns"`
	ScaleHex   string `json:"scale_hex"`
	ScaleExact bool   `json:"scale_exact"`
	IsBatched  bool   `json:"is_batched"`
	IsNTT      bool   `json:"is_ntt"`
}

type RouteBSigned8Depth2SelectedChildPeriodicState struct {
	Stage      string `json:"stage"`
	Level      int    `json:"level"`
	Degree     int    `json:"degree"`
	LogRows    int    `json:"log_rows"`
	LogColumns int    `json:"log_columns"`
	ScaleHex   string `json:"scale_hex"`
}

type RouteBSigned8Depth2SelectedChildPeriodicReport struct {
	Claim                     string                                           `json:"claim"`
	ProfileDigest             string                                           `json:"profile_digest"`
	ExponentialArtifactDigest string                                           `json:"exponential_artifact_digest"`
	AffineSourceDigest        string                                           `json:"affine_source_digest"`
	MultiplierPayloadDigest   string                                           `json:"multiplier_payload_digest"`
	OffsetPayloadDigest       string                                           `json:"offset_payload_digest"`
	InputPayloadDigest        string                                           `json:"input_payload_digest"`
	OutputPayloadDigest       string                                           `json:"output_payload_digest"`
	ProvenanceDigest          string                                           `json:"provenance_digest"`
	States                    []RouteBSigned8Depth2SelectedChildPeriodicState  `json:"states"`
	OperationCounts           homchain.GaoPeriodicBooleanN16L11OperationCounts `json:"operation_counts"`
	Digest                    string                                           `json:"digest"`
}

func (report RouteBSigned8Depth2SelectedChildPeriodicReport) Validate() error {
	if report.Claim != string(homchain.GaoPeriodicBooleanN16L11SecurityUnverified) ||
		!routeBA2BFullIsSHA256(report.ProfileDigest) || !routeBA2BFullIsSHA256(report.ExponentialArtifactDigest) ||
		!routeBA2BFullIsSHA256(report.AffineSourceDigest) || !routeBA2BFullIsSHA256(report.MultiplierPayloadDigest) ||
		!routeBA2BFullIsSHA256(report.OffsetPayloadDigest) || !routeBA2BFullIsSHA256(report.InputPayloadDigest) ||
		!routeBA2BFullIsSHA256(report.OutputPayloadDigest) || !routeBA2BFullIsSHA256(report.ProvenanceDigest) ||
		len(report.States) != 6 || report.Digest == "" {
		return lineagef("selected-child periodic Boolean report identity or shape changed")
	}
	wantLevels := []int{17, 11, 10, 9, 9, 8}
	wantStages := []string{"input", "exponential", "square-0", "root-of-unity", "affine-raw", "output"}
	for index, state := range report.States {
		if state.Stage != wantStages[index] || state.Level != wantLevels[index] || state.Degree != 1 ||
			state.LogRows != 0 || state.LogColumns != 11 || state.ScaleHex == "" {
			return lineagef("selected-child periodic Boolean state %d changed", index)
		}
	}
	wantCounts := homchain.GaoPeriodicBooleanN16L11OperationCounts{
		ExponentialPolynomialEvaluations: 1, CiphertextCiphertextProducts: 2,
		Relinearizations: 2, ExplicitRescales: 3,
		CiphertextPlaintextProducts: 1, PlaintextVectorAdditions: 1,
	}
	if report.OperationCounts != wantCounts || report.Digest != digestRouteBSigned8Depth2SelectedChildPeriodicReport(report) {
		return lineagef("selected-child periodic Boolean count or digest changed")
	}
	return nil
}

type RouteBSigned8Depth2SelectedChildOperationCounts struct {
	PublicThresholdSubtractions       int `json:"public_threshold_subtractions"`
	CompleteRootA2BInvocations        int `json:"complete_root_a2b_invocations"`
	RootPhaseBroadcasts               int `json:"root_phase_broadcasts"`
	SupplementalSlotsToCoeffs         int `json:"supplemental_slots_to_coeffs"`
	AdditionalMR0Invocations          int `json:"additional_mr0_invocations"`
	PeriodicBooleanInvocations        int `json:"periodic_boolean_invocations"`
	SelectorConditionProducts         int `json:"selector_condition_products"`
	RootSignNegations                 int `json:"root_sign_negations"`
	RootSignPlaintextAdditions        int `json:"root_sign_plaintext_additions"`
	EncryptedFeatureSelectionProducts int `json:"encrypted_feature_selection_products"`
	PublicThresholdSelectionProducts  int `json:"public_threshold_selection_products"`
	SignOnlyA2BInvocations            int `json:"sign_only_a2b_invocations"`
	ChildSignBroadcasts               int `json:"child_sign_broadcasts"`
	TerminalCiphertextProducts        int `json:"terminal_ciphertext_products"`
	TerminalPlaintextProducts         int `json:"terminal_plaintext_products"`
	OnlineRescales                    int `json:"online_rescales"`
	AdditionalRelinearizations        int `json:"additional_relinearizations"`
	DecryptionOracles                 int `json:"decryption_oracles"`
	PlaintextBranchDecisions          int `json:"plaintext_branch_decisions"`
	LogicalPeakLiveWrapperCiphertexts int `json:"logical_peak_live_wrapper_ciphertexts"`
}

type RouteBSigned8Depth2SelectedChildReport struct {
	SchemaVersion string `json:"schema_version"`
	Claim         string `json:"claim"`
	Fidelity      string `json:"fidelity"`

	CapacityPlanDigest    string                                      `json:"capacity_plan_digest"`
	ParameterDigest       string                                      `json:"parameter_digest"`
	FeatureBindingDigest  string                                      `json:"feature_binding_digest"`
	FeaturePayloadDigests [3]string                                   `json:"feature_payload_digests"`
	Ranges                [3]RouteBSigned8RootTreeRangeReport         `json:"ranges"`
	Model                 RouteBSigned8Depth2SelectedChildModelReport `json:"model"`
	ScalePlan             RouteBSigned8Depth2SelectedChildScaleReport `json:"scale_plan"`

	RootThresholdDigest           string    `json:"root_threshold_digest"`
	PhaseBroadcastSourceDigest    string    `json:"phase_broadcast_source_digest"`
	PhaseBroadcastCompiledDigest  string    `json:"phase_broadcast_compiled_digest"`
	PhaseBroadcastEncodedBytes    uint64    `json:"phase_broadcast_encoded_bytes"`
	PhaseBroadcastRotationIndexes []int     `json:"phase_broadcast_rotation_indexes"`
	PhaseBroadcastGaloisElements  []uint64  `json:"phase_broadcast_galois_elements"`
	ConditionerDigest             string    `json:"conditioner_digest"`
	RootOneDigest                 string    `json:"root_one_digest"`
	ThresholdDeltaDigest          string    `json:"threshold_delta_digest"`
	LeftThresholdDigest           string    `json:"left_threshold_digest"`
	ChildBroadcastSourceDigest    string    `json:"child_broadcast_source_digest"`
	ChildBroadcastCompiledDigest  string    `json:"child_broadcast_compiled_digest"`
	ChildBroadcastEncodedBytes    uint64    `json:"child_broadcast_encoded_bytes"`
	ChildOneDigest                string    `json:"child_one_digest"`
	TerminalOperandDigests        [4]string `json:"terminal_operand_digests"`

	RootFullA2B           RouteBA2BFullReport                             `json:"root_full_a2b"`
	SupplementalSecondSTC RouteBA2BFullSecondSTCReport                    `json:"supplemental_second_stc"`
	PhaseMR0              RouteBA2BFullMR0Report                          `json:"phase_mr0"`
	RootPeriodic          RouteBSigned8Depth2SelectedChildPeriodicReport  `json:"root_periodic"`
	ChildA2Sign           RouteBSigned8Depth2SelectedChildA2SignReport    `json:"child_a2sign"`
	States                []RouteBSigned8Depth2SelectedChildState         `json:"states"`
	OperationCounts       RouteBSigned8Depth2SelectedChildOperationCounts `json:"operation_counts"`
	OutputPayloadDigest   string                                          `json:"output_payload_digest"`
	WallNanoseconds       uint64                                          `json:"wall_nanoseconds"`
	Digest                string                                          `json:"digest"`
}

func (report RouteBSigned8Depth2SelectedChildReport) Validate() error {
	if report.SchemaVersion != routeBSigned8Depth2SelectedChildReportSchema ||
		report.Claim != routeBSigned8Depth2SelectedChildClaim || report.Fidelity != routeBSigned8Depth2SelectedChildFidelity ||
		report.WallNanoseconds == 0 || report.Digest == "" || len(report.States) < 18 ||
		!routeBA2BFullIsSHA256(report.ParameterDigest) || !routeBA2BFullIsSHA256(report.FeatureBindingDigest) ||
		!routeBA2BFullIsSHA256(report.OutputPayloadDigest) {
		return lineagef("selected-child report identity or shape changed")
	}
	capacity, err := canonicalRouteBCapacityPlan(routeBCapacityGateSigned8Depth2SelectedChild)
	if err != nil || report.CapacityPlanDigest != capacity.Digest() {
		return lineagef("selected-child capacity plan identity changed")
	}
	for _, digest := range append(append([]string(nil), report.FeaturePayloadDigests[:]...),
		report.RootThresholdDigest, report.PhaseBroadcastSourceDigest, report.PhaseBroadcastCompiledDigest,
		report.ConditionerDigest, report.RootOneDigest, report.ThresholdDeltaDigest, report.LeftThresholdDigest,
		report.ChildBroadcastSourceDigest, report.ChildBroadcastCompiledDigest, report.ChildOneDigest,
		report.TerminalOperandDigests[0], report.TerminalOperandDigests[1],
		report.TerminalOperandDigests[2], report.TerminalOperandDigests[3]) {
		if !routeBA2BFullIsSHA256(digest) {
			return lineagef("selected-child artifact digest is empty or malformed")
		}
	}
	if report.PhaseBroadcastEncodedBytes == 0 || report.ChildBroadcastEncodedBytes != routeBSigned8RootTreeBroadcastEncodedBytes ||
		!slices.Equal(report.PhaseBroadcastRotationIndexes, routeBSigned8RootTreeExpectedBroadcastRotations()) ||
		!slices.Equal(report.PhaseBroadcastGaloisElements, routeBSigned8RootTreeExpectedBroadcastGalois()) {
		return lineagef("selected-child broadcast topology changed")
	}
	model, err := reconstructRouteBSigned8Depth2SelectedChildModelReport(report.Model)
	if err != nil {
		return err
	}
	var ranges [3]homchain.Signed8NoOverflowRange
	for index, rangeReport := range report.Ranges {
		ranges[index], err = homchain.NewSigned8NoOverflowRange(
			rangeReport.XMinimum, rangeReport.XMaximum, rangeReport.ThresholdMinimum, rangeReport.ThresholdMaximum,
		)
		if err != nil || ranges[index].Digest() != rangeReport.Digest ||
			ranges[index].DifferenceMinimum() != rangeReport.DifferenceMinimum ||
			ranges[index].DifferenceMaximum() != rangeReport.DifferenceMaximum {
			return lineagef("selected-child range report %d changed", index)
		}
	}
	if err = validateRouteBSigned8Depth2SelectedChildRanges(ranges, model); err != nil {
		return err
	}
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return err
	}
	plan, err := newRouteBSigned8Depth2SelectedChildScalePlan(params)
	if err != nil {
		return err
	}
	wantScaleReport, err := newRouteBSigned8Depth2SelectedChildScaleReport(plan)
	if err != nil || report.ScalePlan != wantScaleReport {
		return lineagef("selected-child exact-scale report changed")
	}
	if err = report.RootFullA2B.Validate(); err != nil {
		return err
	}
	if err = report.SupplementalSecondSTC.Validate(); err != nil {
		return err
	}
	if err = report.PhaseMR0.validate(); err != nil {
		return err
	}
	if err = report.RootPeriodic.Validate(); err != nil {
		return err
	}
	if err = report.ChildA2Sign.Validate(); err != nil {
		return err
	}
	wantCounts := routeBSigned8Depth2SelectedChildExpectedCounts()
	if report.OperationCounts != wantCounts || report.OperationCounts.DecryptionOracles != 0 ||
		report.OperationCounts.PlaintextBranchDecisions != 0 {
		return lineagef("selected-child operation ledger changed")
	}
	for index, state := range report.States {
		if state.Stage == "" || state.Level < 0 || state.Degree != 1 || state.LogRows != 0 || state.LogColumns != 11 ||
			state.ScaleHex == "" || !state.ScaleExact || !state.IsBatched || !state.IsNTT {
			return lineagef("selected-child state %d changed", index)
		}
	}
	if report.Digest != digestRouteBSigned8Depth2SelectedChildReport(report) {
		return lineagef("selected-child report digest changed")
	}
	return nil
}

type RouteBSigned8Depth2SelectedChildResult struct {
	ciphertext *rlwe.Ciphertext
	digest     string
}

func (result RouteBSigned8Depth2SelectedChildResult) Ciphertext() *rlwe.Ciphertext {
	if result.ciphertext == nil {
		return nil
	}
	return result.ciphertext.CopyNew()
}

func (result RouteBSigned8Depth2SelectedChildResult) ReportDigest() string { return result.digest }

func (installed *RouteBInstalledEvaluator) RunSigned8Depth2SelectedChildPublic(
	input RouteBSigned8Depth2SelectedChildFeatures,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Depth2SelectedChildModel,
) (result RouteBSigned8Depth2SelectedChildResult, firstOperation RouteBFirstOperationReport, report RouteBSigned8Depth2SelectedChildReport, err error) {
	if err = validateRouteBSigned8Depth2SelectedChildRanges(ranges, model); err != nil {
		return
	}
	if err = validateRouteBSigned8Depth2SelectedChildFeatures(model, input); err != nil {
		return
	}
	rootInput := input.features[0].CopyNew()
	runner := func(evaluator *bootstrapping.Evaluator, root *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		bound := input
		bound.features[0] = root
		if validationErr := validateRouteBSigned8Depth2SelectedChildFeatures(model, bound); validationErr != nil {
			return nil, routeBFirstOperationObservation{}, validationErr
		}
		output, observation, runReport, runErr := runCanonicalRouteBSigned8Depth2SelectedChild(evaluator, bound, ranges, model)
		if runErr == nil {
			report = runReport
		}
		return output, observation, runErr
	}
	output, firstOperation, err := installed.runFirstOperationWithHooks(
		rootInput, routeBCapacityGateSigned8Depth2SelectedChild, routeBRuntimeOperationSigned8Depth2SelectedChild,
		validateCanonicalRouteBInstalledResident, validateCanonicalRouteBInstalledEvaluator, runner,
	)
	if err != nil {
		return RouteBSigned8Depth2SelectedChildResult{}, RouteBFirstOperationReport{}, RouteBSigned8Depth2SelectedChildReport{}, err
	}
	if output == nil || report.Digest == "" {
		return RouteBSigned8Depth2SelectedChildResult{}, RouteBFirstOperationReport{}, RouteBSigned8Depth2SelectedChildReport{}, lineagef("selected-child evaluation returned an incomplete result")
	}
	if err = report.Validate(); err != nil {
		return RouteBSigned8Depth2SelectedChildResult{}, RouteBFirstOperationReport{}, RouteBSigned8Depth2SelectedChildReport{}, err
	}
	return RouteBSigned8Depth2SelectedChildResult{ciphertext: output, digest: report.Digest}, firstOperation, report, nil
}

func snapshotRouteBSigned8Depth2SelectedChildState(stage string, value *rlwe.Ciphertext, level int, scale rlwe.Scale) (RouteBSigned8Depth2SelectedChildState, error) {
	scaleEqual := false
	if value != nil && value.MetaData != nil {
		actualSnapshot, actualErr := homchain.NewExactScaleSnapshot(value.Scale)
		wantSnapshot, wantErr := homchain.NewExactScaleSnapshot(scale)
		scaleEqual = actualErr == nil && wantErr == nil && actualSnapshot.Equal(wantSnapshot)
	}
	if value == nil || value.MetaData == nil || value.Level() != level || value.Degree() != 1 ||
		value.LogDimensions != (ring.Dimensions{Rows: 0, Cols: 11}) || !value.IsBatched || !value.IsNTT || !scaleEqual {
		actualScale := "nil"
		actualLevel, actualDegree := -1, -1
		if value != nil && value.MetaData != nil {
			actualScale = value.Scale.Value.Text('x', -1)
			actualLevel, actualDegree = value.Level(), value.Degree()
		}
		return RouteBSigned8Depth2SelectedChildState{}, lineagef(
			"selected-child state %s is not canonical L%d/degree1/L11/exact-scale: got L%d/degree%d/scale=%s want-scale=%s",
			stage, level, actualLevel, actualDegree, actualScale, scale.Value.Text('x', -1),
		)
	}
	snapshot, err := homchain.NewExactScaleSnapshot(value.Scale)
	if err != nil {
		return RouteBSigned8Depth2SelectedChildState{}, err
	}
	return RouteBSigned8Depth2SelectedChildState{
		Stage: stage, Level: value.Level(), Degree: value.Degree(),
		LogRows: value.LogDimensions.Rows, LogColumns: value.LogDimensions.Cols,
		ScaleHex: snapshot.ValueHex(), ScaleExact: true, IsBatched: value.IsBatched, IsNTT: value.IsNTT,
	}, nil
}

func newRouteBSigned8Depth2SelectedChildModelReport(model RouteBSigned8Depth2SelectedChildModel) RouteBSigned8Depth2SelectedChildModelReport {
	report := RouteBSigned8Depth2SelectedChildModelReport{
		FeatureIDs: model.featureIDs, Thresholds: model.thresholds, Leaves: model.leaves, Digest: model.digest,
	}
	for index, leaf := range model.leaves {
		report.LeafBits[index] = math.Float64bits(leaf)
	}
	return report
}

func reconstructRouteBSigned8Depth2SelectedChildModelReport(report RouteBSigned8Depth2SelectedChildModelReport) (RouteBSigned8Depth2SelectedChildModel, error) {
	for index, leaf := range report.Leaves {
		if math.Float64bits(leaf) != report.LeafBits[index] {
			return RouteBSigned8Depth2SelectedChildModel{}, lineagef("selected-child model leaf bit snapshot changed")
		}
	}
	model, err := NewRouteBSigned8Depth2SelectedChildModel(report.FeatureIDs, report.Thresholds, report.Leaves)
	if err != nil {
		return RouteBSigned8Depth2SelectedChildModel{}, err
	}
	if model.digest != report.Digest {
		return RouteBSigned8Depth2SelectedChildModel{}, lineagef("selected-child model report digest changed")
	}
	return model, nil
}

func routeBSigned8Depth2SelectedChildExpectedCounts() RouteBSigned8Depth2SelectedChildOperationCounts {
	return RouteBSigned8Depth2SelectedChildOperationCounts{
		PublicThresholdSubtractions: 2, CompleteRootA2BInvocations: 1,
		RootPhaseBroadcasts: 1, SupplementalSlotsToCoeffs: 3, AdditionalMR0Invocations: 3,
		PeriodicBooleanInvocations: 1, SelectorConditionProducts: 1,
		RootSignNegations: 1, RootSignPlaintextAdditions: 1,
		EncryptedFeatureSelectionProducts: 1, PublicThresholdSelectionProducts: 1,
		SignOnlyA2BInvocations: 1, ChildSignBroadcasts: 1,
		TerminalCiphertextProducts: 1, TerminalPlaintextProducts: 3,
		OnlineRescales: 9, AdditionalRelinearizations: 2,
		DecryptionOracles: 0, PlaintextBranchDecisions: 0, LogicalPeakLiveWrapperCiphertexts: 20,
	}
}

func digestRouteBSigned8Depth2SelectedChildPeriodicReport(report RouteBSigned8Depth2SelectedChildPeriodicReport) string {
	copyReport := report
	copyReport.Digest = ""
	payload, _ := json.Marshal(copyReport)
	return routeBSigned8DigestBytes(payload)
}

func digestRouteBSigned8Depth2SelectedChildReport(report RouteBSigned8Depth2SelectedChildReport) string {
	copyReport := report
	copyReport.Digest = ""
	payload, _ := json.Marshal(copyReport)
	return routeBSigned8DigestBytes(payload)
}

func selectedChildNonzeroWall(started time.Time) uint64 {
	value := uint64(time.Since(started).Nanoseconds())
	if value == 0 {
		return 1
	}
	return value
}

func ensureSelectedChildNoUnexpectedError(err error, context string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("secureeval: selected-child %s: %w", context, err)
}
