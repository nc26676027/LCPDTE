package secureeval

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

const (
	routeBSigned8Depth2SelectedChildA2SignReportSchema = "lcpdte-route-b-signed8-depth2-selected-child-a2sign-report-v1"
	routeBSigned8Depth2SelectedChildA2SignClaim        = "gao_two_round_8bit_sign_only_low_ingress_security_unverified"
)

type RouteBSigned8Depth2SelectedChildA2SignState struct {
	Stage      string `json:"stage"`
	Level      int    `json:"level"`
	Degree     int    `json:"degree"`
	LogRows    int    `json:"log_rows"`
	LogColumns int    `json:"log_columns"`
	ScaleHex   string `json:"scale_hex"`
	ScaleExact bool   `json:"scale_exact"`
}

type RouteBSigned8Depth2SelectedChildKernelState struct {
	Stage      string `json:"stage"`
	Level      int    `json:"level"`
	Degree     int    `json:"degree"`
	ScaleHex   string `json:"scale_hex"`
	TargetHex  string `json:"target_hex"`
	ScaleExact bool   `json:"scale_exact"`
}

type RouteBSigned8Depth2SelectedChildKernelReport struct {
	ProfileDigest               string                                        `json:"profile_digest"`
	ParameterDigest             string                                        `json:"parameter_digest"`
	OperandGraphDigest          string                                        `json:"operand_graph_digest"`
	KeyProfileDigest            string                                        `json:"key_profile_digest"`
	OperationalEncoderPrecision uint                                          `json:"operational_encoder_precision"`
	InputNormalization          string                                        `json:"input_normalization"`
	RuntimePath                 string                                        `json:"runtime_path"`
	States                      []RouteBSigned8Depth2SelectedChildKernelState `json:"states"`
	OperationCounts             homchain.GaoA2BKernelOperationCounts          `json:"operation_counts"`
	Digest                      string                                        `json:"digest"`
}

func (report RouteBSigned8Depth2SelectedChildKernelReport) Validate() error {
	if report.ProfileDigest != routeBA2BFirstRoundKernelDigest || !routeBA2BFullIsSHA256(report.ParameterDigest) ||
		!routeBA2BFullIsSHA256(report.OperandGraphDigest) || !routeBA2BFullIsSHA256(report.KeyProfileDigest) ||
		report.OperationalEncoderPrecision != 256 || report.InputNormalization == "" || report.RuntimePath == "" ||
		len(report.States) != 8 || report.Digest == "" {
		return lineagef("selected-child A2Sign Gao kernel report identity changed")
	}
	wantLevels := []int{17, 11, 10, 9, 5, 5, 5, 5}
	for index, state := range report.States {
		if state.Stage == "" || state.Level != wantLevels[index] || state.Degree != 1 ||
			state.ScaleHex == "" || state.TargetHex == "" || !state.ScaleExact {
			return lineagef("selected-child A2Sign Gao kernel state %d changed", index)
		}
	}
	wantCounts := homchain.GaoA2BKernelOperationCounts{
		ExpPolynomialEvaluations: 1, ComplexSquarings: 2,
		MultiPolynomialEvaluations: 1, SharedPowerBases: 1,
		GenericLUTEvaluations: 0, Conjugations: 2, RealRecoveries: 2,
	}
	if report.OperationCounts != wantCounts || report.Digest != digestRouteBSigned8Depth2SelectedChildKernelReport(report) {
		return lineagef("selected-child A2Sign Gao kernel count or digest changed")
	}
	return nil
}

type RouteBSigned8Depth2SelectedChildA2SignOperationCounts struct {
	InputAlignmentDrops         int `json:"input_alignment_drops"`
	SpecialB0Transforms         int `json:"special_b0_transforms"`
	SpecialB0OutputRescales     int `json:"special_b0_output_rescales"`
	MaskProducts                int `json:"mask_products"`
	MaskRescales                int `json:"mask_rescales"`
	SlotsToCoeffs               int `json:"slots_to_coeffs"`
	MR0Invocations              int `json:"mr0_invocations"`
	KernelInvocations           int `json:"kernel_invocations"`
	IDScaleProducts             int `json:"id_scale_products"`
	IDScaleRescales             int `json:"id_scale_rescales"`
	HighCoreSubtractions        int `json:"high_core_subtractions"`
	OmittedLowSelfRemoval       int `json:"omitted_low_self_removal"`
	OmittedHighSelfRemoval      int `json:"omitted_high_self_removal"`
	ReturnedIdentityCiphertexts int `json:"returned_identity_ciphertexts"`
	ReturnedBooleanCiphertexts  int `json:"returned_boolean_ciphertexts"`
}

type RouteBSigned8Depth2SelectedChildA2SignReport struct {
	SchemaVersion            string                                                `json:"schema_version"`
	Claim                    string                                                `json:"claim"`
	TransformSourceDigest    string                                                `json:"transform_source_digest"`
	TransformCompiledDigest  string                                                `json:"transform_compiled_digest"`
	TransformEncodedBytes    uint64                                                `json:"transform_encoded_bytes"`
	TransformRotationIndexes []int                                                 `json:"transform_rotation_indexes"`
	TransformGaloisElements  []uint64                                              `json:"transform_galois_elements"`
	LowN1                    int                                                   `json:"low_n1"`
	HighN1                   int                                                   `json:"high_n1"`
	Iter1MaskDigest          string                                                `json:"iter1_mask_digest"`
	IDScaleDigest            string                                                `json:"id_scale_digest"`
	SecondSTCDigest          string                                                `json:"second_stc_digest"`
	MR0                      [2]RouteBA2BFullMR0Report                             `json:"mr0"`
	ScaleNormalizations      [2]RouteBA2BFullScaleNormalizationReport              `json:"scale_normalizations"`
	Kernels                  [2]RouteBSigned8Depth2SelectedChildKernelReport       `json:"kernels"`
	States                   []RouteBSigned8Depth2SelectedChildA2SignState         `json:"states"`
	OperationCounts          RouteBSigned8Depth2SelectedChildA2SignOperationCounts `json:"operation_counts"`
	InputPayloadDigest       string                                                `json:"input_payload_digest"`
	OutputPayloadDigest      string                                                `json:"output_payload_digest"`
	WallNanoseconds          uint64                                                `json:"wall_nanoseconds"`
	Digest                   string                                                `json:"digest"`
}

func (report RouteBSigned8Depth2SelectedChildA2SignReport) Validate() error {
	if report.SchemaVersion != routeBSigned8Depth2SelectedChildA2SignReportSchema ||
		report.Claim != routeBSigned8Depth2SelectedChildA2SignClaim || report.WallNanoseconds == 0 || report.Digest == "" ||
		!routeBA2BFullIsSHA256(report.TransformSourceDigest) || !routeBA2BFullIsSHA256(report.TransformCompiledDigest) ||
		report.TransformEncodedBytes == 0 || !routeBA2BFullIsSHA256(report.Iter1MaskDigest) ||
		!routeBA2BFullIsSHA256(report.IDScaleDigest) || report.SecondSTCDigest != routeBA2BFullSecondSTCReportDigest ||
		!routeBA2BFullIsSHA256(report.InputPayloadDigest) || !routeBA2BFullIsSHA256(report.OutputPayloadDigest) ||
		report.LowN1 != 4 || report.HighN1 != 4 || len(report.States) != 16 {
		return lineagef("selected-child A2Sign report identity or shape changed")
	}
	if !slices.Equal(report.TransformRotationIndexes, []int{1, 2, 3, 2044}) ||
		!slices.Equal(report.TransformGaloisElements, []uint64{5, 25, 125, 89745, 131071}) {
		return lineagef("selected-child A2Sign transform key subset changed")
	}
	for index := range report.MR0 {
		if err := report.MR0[index].validate(); err != nil {
			return err
		}
		if err := report.Kernels[index].Validate(); err != nil {
			return err
		}
		normalization := report.ScaleNormalizations[index]
		if normalization.Iteration != index || normalization.SourceScaleHex != routeBA2BFirstRoundObservedScaleHex ||
			normalization.TargetScaleHex != routeBA2BFirstRoundScaleHex || !normalization.MetadataOnly {
			return lineagef("selected-child A2Sign normalization %d changed", index)
		}
	}
	wantCounts := RouteBSigned8Depth2SelectedChildA2SignOperationCounts{
		InputAlignmentDrops: 1, SpecialB0Transforms: 1, SpecialB0OutputRescales: 2,
		MaskProducts: 2, MaskRescales: 2, SlotsToCoeffs: 2, MR0Invocations: 2,
		KernelInvocations: 2, IDScaleProducts: 1, IDScaleRescales: 1,
		HighCoreSubtractions: 1, OmittedLowSelfRemoval: 1, OmittedHighSelfRemoval: 1,
		ReturnedIdentityCiphertexts: 0, ReturnedBooleanCiphertexts: 1,
	}
	if report.OperationCounts != wantCounts {
		return lineagef("selected-child A2Sign operation ledger changed")
	}
	for index, state := range report.States {
		if state.Stage == "" || state.Level < 0 || state.Degree != 1 || state.LogRows != 0 ||
			state.LogColumns != 11 || state.ScaleHex == "" || !state.ScaleExact {
			return lineagef("selected-child A2Sign state %d changed", index)
		}
	}
	if report.Digest != digestRouteBSigned8Depth2SelectedChildA2SignReport(report) {
		return lineagef("selected-child A2Sign report digest changed")
	}
	return nil
}

func runRouteBSigned8Depth2SelectedChildA2Sign(
	evaluator *bootstrapping.Evaluator,
	circuit *routeBSigned8Depth2SelectedChildA2SignCircuit,
	input *rlwe.Ciphertext,
) (*rlwe.Ciphertext, RouteBSigned8Depth2SelectedChildA2SignReport, error) {
	started := time.Now()
	if evaluator == nil || evaluator.Evaluator == nil || evaluator.DFTEvaluator == nil || circuit == nil || input == nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, lineagef("selected-child A2Sign evaluator, circuit, or input is nil")
	}
	params := evaluator.BootstrappingParameters
	defaultScale := params.DefaultScale()
	if err := requireRouteBSigned8RootTreeState("selected-child A2Sign input", input, 6, defaultScale, params); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	inputBefore := input.CopyNew()
	inputDigest, err := routeBSigned8RootTreeCiphertextDigest(input)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	states := make([]RouteBSigned8Depth2SelectedChildA2SignState, 0, 16)
	appendState := func(stage string, value *rlwe.Ciphertext, level int, scale rlwe.Scale) error {
		if err := requireRouteBSigned8RootTreeState(stage, value, level, scale, params); err != nil {
			return err
		}
		snapshot, err := homchain.NewExactScaleSnapshot(value.Scale)
		if err != nil {
			return err
		}
		states = append(states, RouteBSigned8Depth2SelectedChildA2SignState{
			Stage: stage, Level: value.Level(), Degree: value.Degree(), LogRows: value.LogDimensions.Rows,
			LogColumns: value.LogDimensions.Cols, ScaleHex: snapshot.ValueHex(), ScaleExact: true,
		})
		return nil
	}
	if err = appendState("selected-child-difference", input, 6, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	aligned := input.CopyNew()
	evaluator.Evaluator.DropLevel(aligned, 1)
	if err = appendState("low-ingress-aligned", aligned, 5, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	halves, err := circuit.triangle.ZToCNew(aligned, circuit.specialB0)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, fmt.Errorf("secureeval: selected-child A2Sign special-b0: %w", err)
	}
	if err = appendState("special-b0-low", halves[0], 4, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = appendState("special-b0-high", halves[1], 4, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	lowSeal, highSeal := halves[0].CopyNew(), halves[1].CopyNew()
	iter0Masked, err := evaluator.Evaluator.MulNew(halves[0], circuit.iter1Mask)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, fmt.Errorf("secureeval: selected-child A2Sign iter0 mask: %w", err)
	}
	if err = evaluator.Evaluator.Rescale(iter0Masked, iter0Masked); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = appendState("iter0-mask", iter0Masked, 3, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	iter0STC, err := evaluator.DFTEvaluator.SlotsToCoeffsNew(iter0Masked, nil, circuit.secondSTC)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, fmt.Errorf("secureeval: selected-child A2Sign iter0 STC: %w", err)
	}
	if err = appendState("iter0-stc", iter0STC, 1, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	iter0Refreshed, observation0, err := runCanonicalRouteBFirstSparseMR0(evaluator, iter0STC)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, fmt.Errorf("secureeval: selected-child A2Sign iter0 MR0: %w", err)
	}
	normalization0, err := normalizeRouteBA2BFirstRoundKernelScale(iter0Refreshed, defaultScale)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = appendState("iter0-mr0-normalized", iter0Refreshed, 17, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	kernel0, err := bindRouteBA2BFirstRoundKernel(circuit.kernel, evaluator)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	result0, err := kernel0.EvaluateNew(iter0Refreshed)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, fmt.Errorf("secureeval: selected-child A2Sign iter0 Gao kernel: %w", err)
	}
	id0, msb0 := result0.IDCiphertext(), result0.MSBCiphertext()
	if err = appendState("iter0-id", id0, 5, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = appendState("iter0-msb", msb0, 5, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	id0Seal := id0.CopyNew()
	id0Over16, err := evaluator.Evaluator.MulNew(id0, circuit.idScale)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = evaluator.Evaluator.Rescale(id0Over16, id0Over16); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = appendState("id0-over-16", id0Over16, 4, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	highUpdated, err := evaluator.Evaluator.SubNew(halves[1], id0Over16)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = appendState("high-core-minus-id0-over-16", highUpdated, 4, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	iter1Masked, err := evaluator.Evaluator.MulNew(highUpdated, circuit.iter1Mask)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = evaluator.Evaluator.Rescale(iter1Masked, iter1Masked); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = appendState("iter1-mask", iter1Masked, 3, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	iter1STC, err := evaluator.DFTEvaluator.SlotsToCoeffsNew(iter1Masked, nil, circuit.secondSTC)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, fmt.Errorf("secureeval: selected-child A2Sign iter1 STC: %w", err)
	}
	if err = appendState("iter1-stc", iter1STC, 1, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	iter1Refreshed, observation1, err := runCanonicalRouteBFirstSparseMR0(evaluator, iter1STC)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, fmt.Errorf("secureeval: selected-child A2Sign iter1 MR0: %w", err)
	}
	normalization1, err := normalizeRouteBA2BFirstRoundKernelScale(iter1Refreshed, defaultScale)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = appendState("iter1-mr0-normalized", iter1Refreshed, 17, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	kernel1, err := bindRouteBA2BFirstRoundKernel(circuit.kernel, evaluator)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if kernel0 == kernel1 {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, lineagef("selected-child A2Sign kernel evaluators are aliased")
	}
	result1, err := kernel1.EvaluateNew(iter1Refreshed)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, fmt.Errorf("secureeval: selected-child A2Sign iter1 Gao kernel: %w", err)
	}
	id1, output := result1.IDCiphertext(), result1.MSBCiphertext()
	if err = appendState("iter1-id", id1, 5, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if err = appendState("iter1-msb", output, 5, defaultScale); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	if !input.Equal(inputBefore) || !halves[0].Equal(lowSeal) || !halves[1].Equal(highSeal) || !id0.Equal(id0Seal) {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, lineagef("selected-child A2Sign mutated an input or retained serial operand")
	}
	outputDigest, err := routeBSigned8RootTreeCiphertextDigest(output)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	mr0_0, err := newRouteBA2BFullMR0Report(observation0)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	mr0_1, err := newRouteBA2BFullMR0Report(observation1)
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	kernelReport0, err := newRouteBSigned8Depth2SelectedChildKernelReport(result0.Provenance())
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	kernelReport1, err := newRouteBSigned8Depth2SelectedChildKernelReport(result1.Provenance())
	if err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	report := RouteBSigned8Depth2SelectedChildA2SignReport{
		SchemaVersion:         routeBSigned8Depth2SelectedChildA2SignReportSchema,
		Claim:                 routeBSigned8Depth2SelectedChildA2SignClaim,
		TransformSourceDigest: circuit.transformSourceDigest, TransformCompiledDigest: circuit.transformCompiledDigest,
		TransformEncodedBytes:    circuit.transformEncodedBytes,
		TransformRotationIndexes: append([]int(nil), circuit.rotationIndexes...),
		TransformGaloisElements:  append([]uint64(nil), circuit.galoisElements...),
		LowN1:                    circuit.specialB0.Low.N1, HighN1: circuit.specialB0.High.N1,
		Iter1MaskDigest: circuit.iter1MaskDigest, IDScaleDigest: circuit.idScaleDigest,
		SecondSTCDigest: circuit.secondSTCReport.Digest,
		MR0:             [2]RouteBA2BFullMR0Report{mr0_0, mr0_1},
		ScaleNormalizations: [2]RouteBA2BFullScaleNormalizationReport{
			newRouteBA2BFullScaleNormalizationReport(0, normalization0),
			newRouteBA2BFullScaleNormalizationReport(1, normalization1),
		},
		Kernels: [2]RouteBSigned8Depth2SelectedChildKernelReport{kernelReport0, kernelReport1},
		States:  states,
		OperationCounts: RouteBSigned8Depth2SelectedChildA2SignOperationCounts{
			InputAlignmentDrops: 1, SpecialB0Transforms: 1, SpecialB0OutputRescales: 2,
			MaskProducts: 2, MaskRescales: 2, SlotsToCoeffs: 2, MR0Invocations: 2,
			KernelInvocations: 2, IDScaleProducts: 1, IDScaleRescales: 1,
			HighCoreSubtractions: 1, OmittedLowSelfRemoval: 1, OmittedHighSelfRemoval: 1,
			ReturnedIdentityCiphertexts: 0, ReturnedBooleanCiphertexts: 1,
		},
		InputPayloadDigest: inputDigest, OutputPayloadDigest: outputDigest,
		WallNanoseconds: selectedChildNonzeroWall(started),
	}
	report.Digest = digestRouteBSigned8Depth2SelectedChildA2SignReport(report)
	if err = report.Validate(); err != nil {
		return nil, RouteBSigned8Depth2SelectedChildA2SignReport{}, err
	}
	return output, report, nil
}

func newRouteBSigned8Depth2SelectedChildKernelReport(
	provenance homchain.GaoA2BKernelProvenance,
) (RouteBSigned8Depth2SelectedChildKernelReport, error) {
	states := make([]RouteBSigned8Depth2SelectedChildKernelState, 0, 8)
	for _, state := range provenance.States() {
		states = append(states, RouteBSigned8Depth2SelectedChildKernelState{
			Stage: string(state.Stage), Level: state.Level, Degree: state.Degree,
			ScaleHex: state.Scale.ValueHex(), TargetHex: state.TargetScale.ValueHex(), ScaleExact: state.ScaleExact,
		})
	}
	report := RouteBSigned8Depth2SelectedChildKernelReport{
		ProfileDigest: provenance.ProfileDigest(), ParameterDigest: provenance.ParameterDigest(),
		OperandGraphDigest: provenance.OperandGraphDigest(), KeyProfileDigest: provenance.KeyProfileDigest(),
		OperationalEncoderPrecision: provenance.OperationalEncoderPrecision(),
		InputNormalization:          provenance.InputNormalization(), RuntimePath: provenance.RuntimePath(),
		States: states, OperationCounts: provenance.OperationCounts(),
	}
	report.Digest = digestRouteBSigned8Depth2SelectedChildKernelReport(report)
	if err := report.Validate(); err != nil {
		return RouteBSigned8Depth2SelectedChildKernelReport{}, err
	}
	return report, nil
}

func digestRouteBSigned8Depth2SelectedChildKernelReport(report RouteBSigned8Depth2SelectedChildKernelReport) string {
	copyReport := report
	copyReport.Digest = ""
	payload, _ := json.Marshal(copyReport)
	return routeBSigned8DigestBytes(payload)
}

func digestRouteBSigned8Depth2SelectedChildA2SignReport(report RouteBSigned8Depth2SelectedChildA2SignReport) string {
	copyReport := report
	copyReport.Digest = ""
	payload, _ := json.Marshal(copyReport)
	return routeBSigned8DigestBytes(payload)
}

func bindRouteBGaoPeriodicBooleanN16L11(
	circuit *homchain.GaoPeriodicBooleanN16L11Circuit,
	evaluator *bootstrapping.Evaluator,
) (*homchain.GaoPeriodicBooleanN16L11Evaluator, error) {
	if circuit == nil || evaluator == nil || evaluator.Evaluator == nil || evaluator.MemEvaluationKeySet == nil {
		return nil, lineagef("selected-child periodic Boolean circuit or evaluator graph is incomplete")
	}
	view := evaluator.Evaluator.WithKey(evaluator.MemEvaluationKeySet)
	if view == nil || view.EvaluationKeySet != evaluator.MemEvaluationKeySet {
		return nil, lineagef("selected-child periodic Boolean memory-key binding changed")
	}
	return circuit.BindEvaluator(view)
}

func newRouteBSigned8Depth2SelectedChildPeriodicReport(
	circuit *homchain.GaoPeriodicBooleanN16L11Circuit,
	result homchain.GaoPeriodicBooleanN16L11Result,
) (RouteBSigned8Depth2SelectedChildPeriodicReport, error) {
	if circuit == nil || result.Ciphertext() == nil {
		return RouteBSigned8Depth2SelectedChildPeriodicReport{}, lineagef("selected-child periodic Boolean result is incomplete")
	}
	profile := circuit.Profile()
	provenance := result.Provenance()
	states := make([]RouteBSigned8Depth2SelectedChildPeriodicState, 0, len(provenance.States()))
	for _, state := range provenance.States() {
		states = append(states, RouteBSigned8Depth2SelectedChildPeriodicState{
			Stage: state.Stage, Level: state.Level, Degree: state.Degree,
			LogRows: state.LogDimensions.Rows, LogColumns: state.LogDimensions.Cols,
			ScaleHex: state.Scale.ValueHex(),
		})
	}
	report := RouteBSigned8Depth2SelectedChildPeriodicReport{
		Claim: string(profile.Claim()), ProfileDigest: profile.Digest(),
		ExponentialArtifactDigest: profile.ExponentialArtifactDigest(), AffineSourceDigest: profile.AffineSourceDigest(),
		MultiplierPayloadDigest: profile.MultiplierPayloadDigest(), OffsetPayloadDigest: profile.OffsetPayloadDigest(),
		InputPayloadDigest: provenance.InputPayloadDigest(), OutputPayloadDigest: provenance.OutputPayloadDigest(),
		ProvenanceDigest: provenance.Digest(), States: states, OperationCounts: provenance.OperationCounts(),
	}
	report.Digest = digestRouteBSigned8Depth2SelectedChildPeriodicReport(report)
	if err := report.Validate(); err != nil {
		return RouteBSigned8Depth2SelectedChildPeriodicReport{}, err
	}
	return report, nil
}
