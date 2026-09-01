package secureeval

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"time"

	"dt_go/integer/homchain"
	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	routeBSigned8Radix4ReportSchema = "lcpdte-route-b-signed8-radix4-report-v1"
	routeBSigned8Radix4Claim        = "lattigo_n16_l11_signed8_same_feature_radix4_one_a2b_conditional_security"
	routeBSigned8Radix4Fidelity     = "exact_r0_same_feature_depth2_compilation_and_r1_interval_node"
	routeBSigned8Radix4Formula      = "l0+(l1-l0)*b0+(l2-l1)*b1+(l3-l2)*b2"

	routeBSigned8Radix4EncoderPrecision = 256
	routeBSigned8Radix4InputLevel       = 20
	routeBSigned8Radix4HighLevel        = 5
	routeBSigned8Radix4BroadcastLevel   = 4
	routeBSigned8Radix4SelectorLevel    = 3
	routeBSigned8Radix4AlignedLevel     = 2
	routeBSigned8Radix4OutputLevel      = 1
)

type routeBSigned8Radix4Artifacts struct {
	params ckks.Parameters

	threshold, globalOne *rlwe.Plaintext
	roleMasks            [3]*rlwe.Plaintext
	leafDeltas           [3]*rlwe.Plaintext
	baseLeaf             *rlwe.Plaintext
	broadcast            lintrans.LinearTransformation

	parameterDigest, thresholdDigest, globalOneDigest string
	roleMaskDigests                                   [3]string
	leafDeltaDigests                                  [3]string
	baseLeafDigest                                    string

	broadcastSourceDigest    string
	broadcastCompiledDigest  string
	broadcastEncodedBytes    uint64
	broadcastRotationIndexes []int
	broadcastGaloisElements  []uint64
	alignmentRotationIndexes []int
	alignmentGaloisElements  []uint64
}

func newRouteBSigned8Radix4Artifacts(params ckks.Parameters, model RouteBSigned8Radix4Model) (routeBSigned8Radix4Artifacts, error) {
	canonical, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return routeBSigned8Radix4Artifacts{}, err
	}
	if !params.Equal(&canonical) || params.LogN() != 16 || params.LogDefaultScale() != 43 ||
		params.MaxLevel() != routeBSigned8Radix4InputLevel || params.MaxLevelP() != 6 || params.LevelsConsumedPerRescaling() != 1 {
		return routeBSigned8Radix4Artifacts{}, lineagef("signed8 radix-4 parameters differ from the canonical N16/L11 Route-B chain")
	}
	if err = validateRouteBSigned8Radix4Model(model); err != nil {
		return routeBSigned8Radix4Artifacts{}, err
	}
	encoder := ckks.NewEncoder(params, routeBSigned8Radix4EncoderPrecision)
	thresholdSlots, err := routeBSigned8Radix4ThresholdSlots(model)
	if err != nil {
		return routeBSigned8Radix4Artifacts{}, err
	}
	threshold, err := encodeRouteBSigned8Plaintext(params, encoder, thresholdSlots, routeBSigned8Radix4InputLevel, params.DefaultScale())
	if err != nil {
		return routeBSigned8Radix4Artifacts{}, fmt.Errorf("secureeval: encode signed8 radix-4 threshold batch: %w", err)
	}
	globalOne, err := encodeRouteBSigned8Plaintext(
		params, encoder, routeBSigned8ConstantSlots(1), routeBSigned8Radix4SelectorLevel, params.DefaultScale(),
	)
	if err != nil {
		return routeBSigned8Radix4Artifacts{}, fmt.Errorf("secureeval: encode signed8 radix-4 global one: %w", err)
	}
	var roleMasks [3]*rlwe.Plaintext
	for role := range roleMasks {
		roleMasks[role], err = encodeRouteBSigned8Plaintext(
			params, encoder, routeBSigned8Depth2NodeBatchRoleSlots(role, 1),
			routeBSigned8Radix4SelectorLevel, rlwe.NewScale(params.Q()[routeBSigned8Radix4SelectorLevel]),
		)
		if err != nil {
			return routeBSigned8Radix4Artifacts{}, fmt.Errorf("secureeval: encode signed8 radix-4 role mask %d: %w", role, err)
		}
	}
	leaves := model.leaves
	deltas := [3]float64{leaves[1] - leaves[0], leaves[2] - leaves[1], leaves[3] - leaves[2]}
	var leafDeltas [3]*rlwe.Plaintext
	for index, delta := range deltas {
		leafDeltas[index], err = encodeRouteBSigned8Plaintext(
			params, encoder, routeBSigned8ConstantSlots(delta), routeBSigned8Radix4AlignedLevel,
			rlwe.NewScale(params.Q()[routeBSigned8Radix4AlignedLevel]),
		)
		if err != nil {
			return routeBSigned8Radix4Artifacts{}, fmt.Errorf("secureeval: encode signed8 radix-4 leaf delta %d: %w", index, err)
		}
	}
	baseLeaf, err := encodeRouteBSigned8Plaintext(
		params, encoder, routeBSigned8Depth2NodeBatchRoleSlots(0, leaves[0]),
		routeBSigned8Radix4OutputLevel, params.DefaultScale(),
	)
	if err != nil {
		return routeBSigned8Radix4Artifacts{}, fmt.Errorf("secureeval: encode signed8 radix-4 base leaf: %w", err)
	}
	broadcast, sourceDigest, compiledDigest, encodedBytes, broadcastRotations, broadcastGalois, err := newRouteBSigned8Broadcast(params, encoder)
	if err != nil {
		return routeBSigned8Radix4Artifacts{}, err
	}
	parameterPayload, err := params.MarshalBinary()
	if err != nil {
		return routeBSigned8Radix4Artifacts{}, err
	}
	artifacts := routeBSigned8Radix4Artifacts{
		params: params, threshold: threshold, globalOne: globalOne, roleMasks: roleMasks,
		leafDeltas: leafDeltas, baseLeaf: baseLeaf, broadcast: broadcast,
		parameterDigest:       routeBSigned8DigestBytes(parameterPayload),
		broadcastSourceDigest: sourceDigest, broadcastCompiledDigest: compiledDigest,
		broadcastEncodedBytes: encodedBytes, broadcastRotationIndexes: broadcastRotations,
		broadcastGaloisElements:  broadcastGalois,
		alignmentRotationIndexes: []int{4, 8},
		alignmentGaloisElements: []uint64{
			params.GaloisElementForRotation(4), params.GaloisElementForRotation(8),
		},
	}
	slices.Sort(artifacts.alignmentGaloisElements)
	if artifacts.thresholdDigest, err = routeBSigned8RootTreePlaintextDigest(threshold); err != nil {
		return routeBSigned8Radix4Artifacts{}, err
	}
	if artifacts.globalOneDigest, err = routeBSigned8RootTreePlaintextDigest(globalOne); err != nil {
		return routeBSigned8Radix4Artifacts{}, err
	}
	for index := range roleMasks {
		if artifacts.roleMaskDigests[index], err = routeBSigned8RootTreePlaintextDigest(roleMasks[index]); err != nil {
			return routeBSigned8Radix4Artifacts{}, err
		}
		if artifacts.leafDeltaDigests[index], err = routeBSigned8RootTreePlaintextDigest(leafDeltas[index]); err != nil {
			return routeBSigned8Radix4Artifacts{}, err
		}
	}
	if artifacts.baseLeafDigest, err = routeBSigned8RootTreePlaintextDigest(baseLeaf); err != nil {
		return routeBSigned8Radix4Artifacts{}, err
	}
	return artifacts, nil
}

func routeBSigned8Radix4ThresholdSlots(model RouteBSigned8Radix4Model) ([]*bignum.Complex, error) {
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8Radix4EncoderPrecision)
	if err != nil {
		return nil, err
	}
	values := make([]*bignum.Complex, 0, routeBSigned8Radix4Slots)
	for word := 0; word < routeBSigned8Radix4Words; word++ {
		threshold := int64(0)
		if word < routeBSigned8Radix4Queries*routeBSigned8Radix4WordsPerQuery {
			threshold = model.thresholds[word%routeBSigned8Radix4WordsPerQuery]
		}
		block, blockErr := ringZ.ToRootSlots(ringZ.ArithmeticEncode(uint64(uint8(threshold))))
		if blockErr != nil {
			return nil, fmt.Errorf("secureeval: encode signed8 radix-4 threshold word %d: %w", word, blockErr)
		}
		values = append(values, block...)
	}
	if len(values) != routeBSigned8Radix4Slots {
		return nil, lineagef("signed8 radix-4 threshold slot count changed")
	}
	return values, nil
}

type RouteBSigned8Radix4ModelReport struct {
	Thresholds [3]int64   `json:"thresholds"`
	Leaves     [4]float64 `json:"leaves"`
	LeafBits   [4]uint64  `json:"leaf_bits"`
	Digest     string     `json:"digest"`
}

type RouteBSigned8Radix4Stage string

const (
	RouteBSigned8Radix4StageInput        RouteBSigned8Radix4Stage = "encrypted-repeated-feature-batch"
	RouteBSigned8Radix4StageDifference   RouteBSigned8Radix4Stage = "features-minus-ordered-thresholds"
	RouteBSigned8Radix4StageHighBoolean  RouteBSigned8Radix4Stage = "complete-a2b-high-boolean-half"
	RouteBSigned8Radix4StageBroadcastRaw RouteBSigned8Radix4Stage = "word-sign-broadcast-before-rescale"
	RouteBSigned8Radix4StageSign         RouteBSigned8Radix4Stage = "word-repeated-sign"
	RouteBSigned8Radix4StageGE           RouteBSigned8Radix4Stage = "word-repeated-ge"
	RouteBSigned8Radix4StageT0MaskRaw    RouteBSigned8Radix4Stage = "t0-role-mask-before-rescale"
	RouteBSigned8Radix4StageT0Aligned    RouteBSigned8Radix4Stage = "t0-selector-aligned"
	RouteBSigned8Radix4StageT1MaskRaw    RouteBSigned8Radix4Stage = "t1-role-mask-before-rescale"
	RouteBSigned8Radix4StageT1Masked     RouteBSigned8Radix4Stage = "t1-role-masked"
	RouteBSigned8Radix4StageT1Aligned    RouteBSigned8Radix4Stage = "t1-selector-aligned"
	RouteBSigned8Radix4StageT2MaskRaw    RouteBSigned8Radix4Stage = "t2-role-mask-before-rescale"
	RouteBSigned8Radix4StageT2Masked     RouteBSigned8Radix4Stage = "t2-role-masked"
	RouteBSigned8Radix4StageT2Aligned    RouteBSigned8Radix4Stage = "t2-selector-aligned"
	RouteBSigned8Radix4StageTerm0Raw     RouteBSigned8Radix4Stage = "b0-delta0-before-rescale"
	RouteBSigned8Radix4StageTerm0        RouteBSigned8Radix4Stage = "b0-delta0"
	RouteBSigned8Radix4StageTerm1Raw     RouteBSigned8Radix4Stage = "b1-delta1-before-rescale"
	RouteBSigned8Radix4StageTerm1        RouteBSigned8Radix4Stage = "b1-delta1"
	RouteBSigned8Radix4StageTerm2Raw     RouteBSigned8Radix4Stage = "b2-delta2-before-rescale"
	RouteBSigned8Radix4StageTerm2        RouteBSigned8Radix4Stage = "b2-delta2"
	RouteBSigned8Radix4StageOutput       RouteBSigned8Radix4Stage = "selected-real-leaf-root-words"
)

type RouteBSigned8Radix4State struct {
	Stage      RouteBSigned8Radix4Stage `json:"stage"`
	Level      int                      `json:"level"`
	Degree     int                      `json:"degree"`
	LogRows    int                      `json:"log_rows"`
	LogColumns int                      `json:"log_columns"`
	ScaleHex   string                   `json:"scale_hex"`
	ScaleExact bool                     `json:"scale_exact"`
	IsBatched  bool                     `json:"is_batched"`
	IsNTT      bool                     `json:"is_ntt"`
}

type RouteBSigned8Radix4OperationCounts struct {
	PublicThresholdSubtractions        int `json:"public_threshold_subtractions"`
	CompleteA2BInvocations             int `json:"complete_a2b_invocations"`
	BroadcastLinearTransformations     int `json:"broadcast_linear_transformations"`
	BroadcastDiagonalPlaintextProducts int `json:"broadcast_diagonal_plaintext_products"`
	BroadcastCiphertextAdditions       int `json:"broadcast_ciphertext_additions"`
	BroadcastRotations                 int `json:"broadcast_rotations"`
	BroadcastKeySwitches               int `json:"broadcast_key_switches"`
	BroadcastRescales                  int `json:"broadcast_rescales"`
	GENegations                        int `json:"ge_negations"`
	GEPlaintextAdditions               int `json:"ge_plaintext_additions"`
	RoleMaskPlaintextProducts          int `json:"role_mask_plaintext_products"`
	RoleMaskRescales                   int `json:"role_mask_rescales"`
	AlignmentRotations                 int `json:"alignment_rotations"`
	AlignmentKeySwitches               int `json:"alignment_key_switches"`
	SelectorComplements                int `json:"selector_complements"`
	PathCiphertextProducts             int `json:"path_ciphertext_products"`
	PathRelinearizations               int `json:"path_relinearizations"`
	PathRescales                       int `json:"path_rescales"`
	LeafPlaintextProducts              int `json:"leaf_plaintext_products"`
	LeafRescales                       int `json:"leaf_rescales"`
	LeafCiphertextAdditions            int `json:"leaf_ciphertext_additions"`
	BaseLeafPlaintextAdditions         int `json:"base_leaf_plaintext_additions"`
	LogicalPeakLiveWrapperCiphertexts  int `json:"logical_peak_live_wrapper_ciphertexts"`
}

type RouteBSigned8Radix4AblationLedger struct {
	EquivalentBinaryModelDigest      string `json:"equivalent_binary_model_digest"`
	ExhaustiveEquivalenceProofDigest string `json:"exhaustive_equivalence_proof_digest"`
	DomainMinimum                    int64  `json:"domain_minimum"`
	DomainMaximum                    int64  `json:"domain_maximum"`
	BinaryPathCiphertextProducts     int    `json:"binary_path_ciphertext_products"`
	RadixPathCiphertextProducts      int    `json:"radix_path_ciphertext_products"`
	RemovedCiphertextProducts        int    `json:"removed_ciphertext_products"`
	BinaryPathRelinearizations       int    `json:"binary_path_relinearizations"`
	RadixPathRelinearizations        int    `json:"radix_path_relinearizations"`
	RemovedRelinearizations          int    `json:"removed_relinearizations"`
	BinaryPathRescales               int    `json:"binary_path_rescales"`
	RadixPathRescales                int    `json:"radix_path_rescales"`
	RemovedPathRescales              int    `json:"removed_path_rescales"`
	BinaryOutputLevel                int    `json:"binary_output_level"`
	RadixOutputLevel                 int    `json:"radix_output_level"`
	OutputLevelsSaved                int    `json:"output_levels_saved"`
}

type RouteBSigned8Radix4Report struct {
	SchemaVersion string `json:"schema_version"`
	Claim         string `json:"claim"`
	Fidelity      string `json:"fidelity"`
	Formula       string `json:"selector_formula"`

	CapacityPlanDigest          string                              `json:"capacity_plan_digest"`
	ParameterDigest             string                              `json:"parameter_digest"`
	Ranges                      [3]RouteBSigned8RootTreeRangeReport `json:"ranges"`
	Model                       RouteBSigned8Radix4ModelReport      `json:"model"`
	InputPayloadDigest          string                              `json:"input_payload_digest"`
	OutputPayloadDigest         string                              `json:"output_payload_digest"`
	ThresholdDigest             string                              `json:"threshold_payload_digest"`
	GlobalOneDigest             string                              `json:"global_one_payload_digest"`
	RoleMaskDigests             [3]string                           `json:"role_mask_payload_digests"`
	LeafDeltaDigests            [3]string                           `json:"leaf_delta_payload_digests"`
	BaseLeafDigest              string                              `json:"base_leaf_payload_digest"`
	BroadcastSourceDigest       string                              `json:"broadcast_source_digest"`
	BroadcastCompiledDigest     string                              `json:"broadcast_compiled_digest"`
	BroadcastEncodedBytes       uint64                              `json:"broadcast_encoded_bytes"`
	BroadcastRotationIndexes    []int                               `json:"broadcast_rotation_indexes"`
	BroadcastGaloisElements     []uint64                            `json:"broadcast_galois_elements"`
	AlignmentRotationIndexes    []int                               `json:"alignment_rotation_indexes"`
	AlignmentGaloisElements     []uint64                            `json:"alignment_galois_elements"`
	FullA2B                     RouteBA2BFullReport                 `json:"full_a2b"`
	States                      []RouteBSigned8Radix4State          `json:"states"`
	OperationCounts             RouteBSigned8Radix4OperationCounts  `json:"operation_counts"`
	Ablation                    RouteBSigned8Radix4AblationLedger   `json:"ablation"`
	CommonPrefixWallNanoseconds uint64                              `json:"common_prefix_wall_nanoseconds"`
	TerminalWallNanoseconds     uint64                              `json:"terminal_wall_nanoseconds"`
	WallNanoseconds             uint64                              `json:"wall_nanoseconds"`
	Digest                      string                              `json:"digest"`
}

type RouteBSigned8Radix4Result struct {
	ciphertext *rlwe.Ciphertext
	digest     string
}

func (result RouteBSigned8Radix4Result) Ciphertext() *rlwe.Ciphertext {
	if result.ciphertext == nil {
		return nil
	}
	return result.ciphertext.CopyNew()
}

func (result RouteBSigned8Radix4Result) ReportDigest() string { return result.digest }

func (report RouteBSigned8Radix4Report) Validate() error {
	if report.SchemaVersion != routeBSigned8Radix4ReportSchema || report.Claim != routeBSigned8Radix4Claim ||
		report.Fidelity != routeBSigned8Radix4Fidelity || report.Formula != routeBSigned8Radix4Formula ||
		report.WallNanoseconds == 0 || report.CommonPrefixWallNanoseconds == 0 || report.TerminalWallNanoseconds == 0 ||
		report.WallNanoseconds < report.CommonPrefixWallNanoseconds+report.TerminalWallNanoseconds || report.Digest == "" {
		return lineagef("signed8 radix-4 report identity, timing, or digest changed")
	}
	ranges, model, err := reconstructRouteBSigned8Radix4Inputs(report.Ranges, report.Model)
	if err != nil {
		return err
	}
	if err = validateRouteBSigned8Radix4Inputs(ranges, model); err != nil {
		return err
	}
	plan, err := canonicalRouteBCapacityPlan(routeBCapacityGateSigned8Radix4Node)
	if err != nil {
		return err
	}
	if report.CapacityPlanDigest != plan.Digest() {
		return lineagef("signed8 radix-4 capacity plan changed")
	}
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return err
	}
	artifacts, err := newRouteBSigned8Radix4Artifacts(params, model)
	if err != nil {
		return err
	}
	if report.ParameterDigest != artifacts.parameterDigest || report.ThresholdDigest != artifacts.thresholdDigest ||
		report.GlobalOneDigest != artifacts.globalOneDigest || report.RoleMaskDigests != artifacts.roleMaskDigests ||
		report.LeafDeltaDigests != artifacts.leafDeltaDigests || report.BaseLeafDigest != artifacts.baseLeafDigest ||
		report.BroadcastSourceDigest != artifacts.broadcastSourceDigest || report.BroadcastCompiledDigest != artifacts.broadcastCompiledDigest ||
		report.BroadcastEncodedBytes != artifacts.broadcastEncodedBytes ||
		!slices.Equal(report.BroadcastRotationIndexes, artifacts.broadcastRotationIndexes) ||
		!slices.Equal(report.BroadcastGaloisElements, artifacts.broadcastGaloisElements) ||
		!slices.Equal(report.AlignmentRotationIndexes, artifacts.alignmentRotationIndexes) ||
		!slices.Equal(report.AlignmentGaloisElements, artifacts.alignmentGaloisElements) {
		return lineagef("signed8 radix-4 parameter, plaintext, transform, or key identity changed")
	}
	if !routeBA2BFullIsSHA256(report.InputPayloadDigest) || !routeBA2BFullIsSHA256(report.OutputPayloadDigest) {
		return lineagef("signed8 radix-4 input or output payload digest is malformed")
	}
	if err = report.FullA2B.Validate(); err != nil {
		return fmt.Errorf("secureeval: validate nested signed8 radix-4 complete A2B: %w", err)
	}
	expectedStates, err := routeBSigned8Radix4ExpectedStates(params)
	if err != nil {
		return err
	}
	if !slices.Equal(report.States, expectedStates) || report.OperationCounts != routeBSigned8Radix4ExpectedCounts(artifacts) {
		return lineagef("signed8 radix-4 exact state or operation ledger changed")
	}
	ablation, err := routeBSigned8Radix4ExpectedAblation(model)
	if err != nil {
		return err
	}
	if report.Ablation != ablation {
		return lineagef("signed8 radix-4 binary-equivalence ablation changed")
	}
	digest, err := digestRouteBSigned8Radix4Report(report)
	if err != nil || digest != report.Digest {
		return lineagef("signed8 radix-4 report digest changed")
	}
	return nil
}

func (installed *RouteBInstalledEvaluator) RunSigned8Radix4Public(
	input *rlwe.Ciphertext,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Radix4Model,
) (result RouteBSigned8Radix4Result, firstOperation RouteBFirstOperationReport, report RouteBSigned8Radix4Report, err error) {
	if err = validateRouteBSigned8Radix4Inputs(ranges, model); err != nil {
		return result, firstOperation, report, err
	}
	runner := func(evaluator *bootstrapping.Evaluator, ciphertext *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		output, observation, runReport, runErr := runCanonicalRouteBSigned8Radix4(evaluator, ciphertext, ranges, model)
		if runErr == nil {
			report = runReport
		}
		return output, observation, runErr
	}
	output, firstOperation, err := installed.runFirstOperationWithHooks(
		input, routeBCapacityGateSigned8Radix4Node, routeBRuntimeOperationSigned8Radix4Node,
		validateCanonicalRouteBInstalledResident, validateCanonicalRouteBInstalledEvaluator, runner,
	)
	if err != nil {
		return RouteBSigned8Radix4Result{}, RouteBFirstOperationReport{}, RouteBSigned8Radix4Report{}, err
	}
	if output == nil || report.Digest == "" {
		return RouteBSigned8Radix4Result{}, RouteBFirstOperationReport{}, RouteBSigned8Radix4Report{}, lineagef("signed8 radix-4 returned an incomplete result")
	}
	if err = report.Validate(); err != nil {
		return RouteBSigned8Radix4Result{}, RouteBFirstOperationReport{}, RouteBSigned8Radix4Report{}, err
	}
	return RouteBSigned8Radix4Result{ciphertext: output, digest: report.Digest}, firstOperation, report, nil
}

func runCanonicalRouteBSigned8Radix4(
	evaluator *bootstrapping.Evaluator,
	input *rlwe.Ciphertext,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Radix4Model,
) (output *rlwe.Ciphertext, observation routeBFirstOperationObservation, report RouteBSigned8Radix4Report, err error) {
	started := time.Now()
	if evaluator == nil || evaluator.Evaluator == nil || input == nil {
		return nil, observation, report, lineagef("signed8 radix-4 evaluator or input is nil")
	}
	if err = validateRouteBSigned8Radix4Inputs(ranges, model); err != nil {
		return nil, observation, report, err
	}
	params := evaluator.BootstrappingParameters
	if err = requireRouteBSigned8Radix4State("input", input, routeBSigned8Radix4InputLevel, params.DefaultScale(), params); err != nil {
		return nil, observation, report, err
	}
	inputDigest, err := routeBSigned8RootTreeCiphertextDigest(input)
	if err != nil {
		return nil, observation, report, err
	}
	inputBefore := input.CopyNew()
	artifacts, err := newRouteBSigned8Radix4Artifacts(params, model)
	if err != nil {
		return nil, observation, report, err
	}
	if err = preflightRouteBSigned8Radix4Keys(evaluator.Evaluator, artifacts); err != nil {
		return nil, observation, report, err
	}
	states := make([]RouteBSigned8Radix4State, 0, 21)
	appendState := func(stage RouteBSigned8Radix4Stage, ciphertext *rlwe.Ciphertext, expected rlwe.Scale) error {
		state, stateErr := snapshotRouteBSigned8Radix4State(stage, ciphertext, expected)
		if stateErr == nil {
			states = append(states, state)
		}
		return stateErr
	}
	if err = appendState(RouteBSigned8Radix4StageInput, input, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	difference, err := evaluator.Evaluator.SubNew(input, artifacts.threshold)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 radix-4 threshold subtraction: %w", err)
	}
	if err = appendState(RouteBSigned8Radix4StageDifference, difference, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	_, high, observation, fullReport, err := runCanonicalRouteBFirstSparseA2BFull(evaluator, difference)
	if err != nil {
		return nil, routeBFirstOperationObservation{}, report, fmt.Errorf("secureeval: signed8 radix-4 complete A2B: %w", err)
	}
	if err = appendState(RouteBSigned8Radix4StageHighBoolean, high, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	linear := lintrans.NewEvaluator(evaluator.Evaluator)
	broadcastRaw, err := linear.EvaluateNew(high, artifacts.broadcast)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 radix-4 word sign broadcast: %w", err)
	}
	broadcastRawScale := params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Radix4BroadcastLevel]))
	if err = appendState(RouteBSigned8Radix4StageBroadcastRaw, broadcastRaw, broadcastRawScale); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(broadcastRaw, broadcastRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 radix-4 rescale word sign broadcast: %w", err)
	}
	sign := broadcastRaw
	if err = appendState(RouteBSigned8Radix4StageSign, sign, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	ge := sign.CopyNew()
	ringQ := params.RingQ().AtLevel(ge.Level())
	for index := range ge.Value {
		ringQ.Neg(ge.Value[index], ge.Value[index])
	}
	if err = evaluator.Evaluator.Add(ge, artifacts.globalOne, ge); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 radix-4 complement word signs: %w", err)
	}
	if err = appendState(RouteBSigned8Radix4StageGE, ge, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	maskRawScale := params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Radix4SelectorLevel]))
	maskStages := [3][2]RouteBSigned8Radix4Stage{
		{RouteBSigned8Radix4StageT0MaskRaw, RouteBSigned8Radix4StageT0Aligned},
		{RouteBSigned8Radix4StageT1MaskRaw, RouteBSigned8Radix4StageT1Masked},
		{RouteBSigned8Radix4StageT2MaskRaw, RouteBSigned8Radix4StageT2Masked},
	}
	var selectors [3]*rlwe.Ciphertext
	for role := range selectors {
		masked, maskErr := evaluator.Evaluator.MulNew(ge, artifacts.roleMasks[role])
		if maskErr != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 radix-4 role %d mask: %w", role, maskErr)
		}
		if err = appendState(maskStages[role][0], masked, maskRawScale); err != nil {
			return nil, observation, report, err
		}
		if err = evaluator.Evaluator.Rescale(masked, masked); err != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 radix-4 role %d mask rescale: %w", role, err)
		}
		if err = appendState(maskStages[role][1], masked, params.DefaultScale()); err != nil {
			return nil, observation, report, err
		}
		selectors[role] = masked
	}
	if selectors[1], err = evaluator.Evaluator.RotateNew(selectors[1], 4); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: align signed8 radix-4 t1 selector: %w", err)
	}
	if err = appendState(RouteBSigned8Radix4StageT1Aligned, selectors[1], params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	if selectors[2], err = evaluator.Evaluator.RotateNew(selectors[2], 8); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: align signed8 radix-4 t2 selector: %w", err)
	}
	if err = appendState(RouteBSigned8Radix4StageT2Aligned, selectors[2], params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	commonPrefixWall := uint64(time.Since(started).Nanoseconds())
	if commonPrefixWall == 0 {
		commonPrefixWall = 1
	}

	terminalStarted := time.Now()
	leafRawScale := params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Radix4AlignedLevel]))
	leafStages := [3][2]RouteBSigned8Radix4Stage{
		{RouteBSigned8Radix4StageTerm0Raw, RouteBSigned8Radix4StageTerm0},
		{RouteBSigned8Radix4StageTerm1Raw, RouteBSigned8Radix4StageTerm1},
		{RouteBSigned8Radix4StageTerm2Raw, RouteBSigned8Radix4StageTerm2},
	}
	var terms [3]*rlwe.Ciphertext
	for index, selector := range selectors {
		term, termErr := evaluator.Evaluator.MulNew(selector, artifacts.leafDeltas[index])
		if termErr != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 radix-4 leaf term %d: %w", index, termErr)
		}
		if err = appendState(leafStages[index][0], term, leafRawScale); err != nil {
			return nil, observation, report, err
		}
		if err = evaluator.Evaluator.Rescale(term, term); err != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 radix-4 leaf rescale %d: %w", index, err)
		}
		if err = appendState(leafStages[index][1], term, params.DefaultScale()); err != nil {
			return nil, observation, report, err
		}
		terms[index] = term
	}
	output, err = evaluator.Evaluator.AddNew(terms[0], terms[1])
	if err == nil {
		err = evaluator.Evaluator.Add(output, terms[2], output)
	}
	if err == nil {
		err = evaluator.Evaluator.Add(output, artifacts.baseLeaf, output)
	}
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 radix-4 combine leaf terms: %w", err)
	}
	if err = appendState(RouteBSigned8Radix4StageOutput, output, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	terminalWall := uint64(time.Since(terminalStarted).Nanoseconds())
	if terminalWall == 0 {
		terminalWall = 1
	}
	if !input.Equal(inputBefore) {
		return nil, observation, report, lineagef("signed8 radix-4 mutated its encrypted input")
	}
	outputDigest, err := routeBSigned8RootTreeCiphertextDigest(output)
	if err != nil {
		return nil, observation, report, err
	}
	capacity, err := canonicalRouteBCapacityPlan(routeBCapacityGateSigned8Radix4Node)
	if err != nil {
		return nil, observation, report, err
	}
	ablation, err := routeBSigned8Radix4ExpectedAblation(model)
	if err != nil {
		return nil, observation, report, err
	}
	wall := uint64(time.Since(started).Nanoseconds())
	if wall < commonPrefixWall+terminalWall {
		wall = commonPrefixWall + terminalWall
	}
	report = RouteBSigned8Radix4Report{
		SchemaVersion: routeBSigned8Radix4ReportSchema, Claim: routeBSigned8Radix4Claim,
		Fidelity: routeBSigned8Radix4Fidelity, Formula: routeBSigned8Radix4Formula,
		CapacityPlanDigest: capacity.Digest(), ParameterDigest: artifacts.parameterDigest,
		Ranges: newRouteBSigned8Radix4RangeReports(ranges), Model: newRouteBSigned8Radix4ModelReport(model),
		InputPayloadDigest: inputDigest, OutputPayloadDigest: outputDigest,
		ThresholdDigest: artifacts.thresholdDigest, GlobalOneDigest: artifacts.globalOneDigest,
		RoleMaskDigests: artifacts.roleMaskDigests, LeafDeltaDigests: artifacts.leafDeltaDigests,
		BaseLeafDigest: artifacts.baseLeafDigest, BroadcastSourceDigest: artifacts.broadcastSourceDigest,
		BroadcastCompiledDigest: artifacts.broadcastCompiledDigest, BroadcastEncodedBytes: artifacts.broadcastEncodedBytes,
		BroadcastRotationIndexes: append([]int(nil), artifacts.broadcastRotationIndexes...),
		BroadcastGaloisElements:  append([]uint64(nil), artifacts.broadcastGaloisElements...),
		AlignmentRotationIndexes: append([]int(nil), artifacts.alignmentRotationIndexes...),
		AlignmentGaloisElements:  append([]uint64(nil), artifacts.alignmentGaloisElements...),
		FullA2B:                  fullReport, States: states, OperationCounts: routeBSigned8Radix4ExpectedCounts(artifacts),
		Ablation: ablation, CommonPrefixWallNanoseconds: commonPrefixWall,
		TerminalWallNanoseconds: terminalWall, WallNanoseconds: wall,
	}
	report.Digest, err = digestRouteBSigned8Radix4Report(report)
	if err != nil {
		return nil, observation, RouteBSigned8Radix4Report{}, err
	}
	return output, observation, report, nil
}

func preflightRouteBSigned8Radix4Keys(evaluator *ckks.Evaluator, artifacts routeBSigned8Radix4Artifacts) error {
	if evaluator == nil || evaluator.EvaluationKeySet == nil {
		return lineagef("signed8 radix-4 evaluator key set is nil")
	}
	required := append(append([]uint64(nil), artifacts.broadcastGaloisElements...), artifacts.alignmentGaloisElements...)
	slices.Sort(required)
	required = slices.Compact(required)
	installed := evaluator.EvaluationKeySet.GetGaloisKeysList()
	slices.Sort(installed)
	for _, element := range required {
		if _, present := slices.BinarySearch(installed, element); !present {
			return lineagef("signed8 radix-4 Galois element %d is outside the installed key union", element)
		}
		key, err := evaluator.EvaluationKeySet.GetGaloisKey(element)
		if err != nil || key == nil || key.GaloisElement != element || key.LevelQ() < routeBSigned8Radix4BroadcastLevel || key.LevelP() < 6 {
			return lineagef("signed8 radix-4 Galois key %d is absent or has insufficient levels", element)
		}
	}
	return nil
}

func requireRouteBSigned8Radix4State(name string, ciphertext *rlwe.Ciphertext, level int, scale rlwe.Scale, params ckks.Parameters) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level || ciphertext.Degree() != 1 ||
		ciphertext.LogN() != 16 || ciphertext.LogDimensions != (ring.Dimensions{Rows: 0, Cols: 11}) ||
		!ciphertext.IsBatched || !ciphertext.IsNTT || !rbdftEqualScaleExact(ciphertext.Scale, scale) ||
		ciphertext.Value[0].N() != params.N() || ciphertext.Value[1].N() != params.N() {
		return lineagef("signed8 radix-4 %s is not canonical L%d/degree1/L11/exact-scale", name, level)
	}
	return nil
}

func snapshotRouteBSigned8Radix4State(stage RouteBSigned8Radix4Stage, ciphertext *rlwe.Ciphertext, expected rlwe.Scale) (RouteBSigned8Radix4State, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return RouteBSigned8Radix4State{}, lineagef("cannot snapshot nil signed8 radix-4 stage %s", stage)
	}
	scale, err := homchain.NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return RouteBSigned8Radix4State{}, err
	}
	return RouteBSigned8Radix4State{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogRows: ciphertext.LogDimensions.Rows, LogColumns: ciphertext.LogDimensions.Cols,
		ScaleHex: scale.ValueHex(), ScaleExact: rbdftEqualScaleExact(ciphertext.Scale, expected),
		IsBatched: ciphertext.IsBatched, IsNTT: ciphertext.IsNTT,
	}, nil
}

func routeBSigned8Radix4ExpectedStates(params ckks.Parameters) ([]RouteBSigned8Radix4State, error) {
	snapshot := func(scale rlwe.Scale) (string, error) {
		value, err := homchain.NewExactScaleSnapshot(scale)
		if err != nil {
			return "", err
		}
		return value.ValueHex(), nil
	}
	defaultHex, err := snapshot(params.DefaultScale())
	if err != nil {
		return nil, err
	}
	broadcastHex, err := snapshot(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Radix4BroadcastLevel])))
	if err != nil {
		return nil, err
	}
	maskRawHex, err := snapshot(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Radix4SelectorLevel])))
	if err != nil {
		return nil, err
	}
	leafRawHex, err := snapshot(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Radix4AlignedLevel])))
	if err != nil {
		return nil, err
	}
	state := func(stage RouteBSigned8Radix4Stage, level int, scale string) RouteBSigned8Radix4State {
		return RouteBSigned8Radix4State{Stage: stage, Level: level, Degree: 1, LogRows: 0, LogColumns: 11, ScaleHex: scale, ScaleExact: true, IsBatched: true, IsNTT: true}
	}
	return []RouteBSigned8Radix4State{
		state(RouteBSigned8Radix4StageInput, 20, defaultHex), state(RouteBSigned8Radix4StageDifference, 20, defaultHex),
		state(RouteBSigned8Radix4StageHighBoolean, 5, defaultHex), state(RouteBSigned8Radix4StageBroadcastRaw, 4, broadcastHex),
		state(RouteBSigned8Radix4StageSign, 3, defaultHex), state(RouteBSigned8Radix4StageGE, 3, defaultHex),
		state(RouteBSigned8Radix4StageT0MaskRaw, 3, maskRawHex), state(RouteBSigned8Radix4StageT0Aligned, 2, defaultHex),
		state(RouteBSigned8Radix4StageT1MaskRaw, 3, maskRawHex), state(RouteBSigned8Radix4StageT1Masked, 2, defaultHex),
		state(RouteBSigned8Radix4StageT2MaskRaw, 3, maskRawHex), state(RouteBSigned8Radix4StageT2Masked, 2, defaultHex),
		state(RouteBSigned8Radix4StageT1Aligned, 2, defaultHex), state(RouteBSigned8Radix4StageT2Aligned, 2, defaultHex),
		state(RouteBSigned8Radix4StageTerm0Raw, 2, leafRawHex), state(RouteBSigned8Radix4StageTerm0, 1, defaultHex),
		state(RouteBSigned8Radix4StageTerm1Raw, 2, leafRawHex), state(RouteBSigned8Radix4StageTerm1, 1, defaultHex),
		state(RouteBSigned8Radix4StageTerm2Raw, 2, leafRawHex), state(RouteBSigned8Radix4StageTerm2, 1, defaultHex),
		state(RouteBSigned8Radix4StageOutput, 1, defaultHex),
	}, nil
}

func routeBSigned8Radix4ExpectedCounts(artifacts routeBSigned8Radix4Artifacts) RouteBSigned8Radix4OperationCounts {
	return RouteBSigned8Radix4OperationCounts{
		PublicThresholdSubtractions: 1, CompleteA2BInvocations: 1,
		BroadcastLinearTransformations: 1, BroadcastDiagonalPlaintextProducts: len(artifacts.broadcast.Vec),
		BroadcastCiphertextAdditions: max(len(artifacts.broadcast.Vec)-1, 0),
		BroadcastRotations:           len(artifacts.broadcastRotationIndexes), BroadcastKeySwitches: len(artifacts.broadcastRotationIndexes),
		BroadcastRescales: 1, GENegations: 1, GEPlaintextAdditions: 1,
		RoleMaskPlaintextProducts: 3, RoleMaskRescales: 3,
		AlignmentRotations: len(artifacts.alignmentRotationIndexes), AlignmentKeySwitches: len(artifacts.alignmentRotationIndexes),
		SelectorComplements: 0, PathCiphertextProducts: 0, PathRelinearizations: 0, PathRescales: 0,
		LeafPlaintextProducts: 3, LeafRescales: 3, LeafCiphertextAdditions: 2, BaseLeafPlaintextAdditions: 1,
		LogicalPeakLiveWrapperCiphertexts: 10,
	}
}

func routeBSigned8Radix4ExpectedAblation(model RouteBSigned8Radix4Model) (RouteBSigned8Radix4AblationLedger, error) {
	canonical, _, binaryModel, _, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		return RouteBSigned8Radix4AblationLedger{}, err
	}
	if err = validateRouteBSigned8Radix4Model(model); err != nil {
		return RouteBSigned8Radix4AblationLedger{}, err
	}
	if model.digest != canonical.digest || model.digest != routeBSigned8Radix4ExpectedModelDigest {
		return RouteBSigned8Radix4AblationLedger{}, lineagef("signed8 radix-4 ablation is requested for a foreign model")
	}
	proof, err := routeBSigned8Radix4EquivalenceProofDigest(model)
	if err != nil {
		return RouteBSigned8Radix4AblationLedger{}, err
	}
	if proof != routeBSigned8Radix4ExpectedProofDigest {
		return RouteBSigned8Radix4AblationLedger{}, lineagef("signed8 radix-4 equivalence proof digest changed")
	}
	return RouteBSigned8Radix4AblationLedger{
		EquivalentBinaryModelDigest: binaryModel.Digest(), ExhaustiveEquivalenceProofDigest: proof,
		DomainMinimum: -96, DomainMaximum: 95,
		BinaryPathCiphertextProducts: 3, RadixPathCiphertextProducts: 0, RemovedCiphertextProducts: 3,
		BinaryPathRelinearizations: 3, RadixPathRelinearizations: 0, RemovedRelinearizations: 3,
		BinaryPathRescales: 3, RadixPathRescales: 0, RemovedPathRescales: 3,
		BinaryOutputLevel: 0, RadixOutputLevel: 1, OutputLevelsSaved: 1,
	}, nil
}

func routeBSigned8Radix4EquivalenceProofDigest(model RouteBSigned8Radix4Model) (string, error) {
	canonical, ranges, binaryModel, binaryRanges, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		return "", err
	}
	if model.digest != canonical.digest {
		return "", lineagef("signed8 radix-4 equivalence proof is requested for a foreign model")
	}
	record := struct {
		Schema, RadixDigest, BinaryDigest string
		Minimum, Maximum                  int64
		Rows                              [][7]uint64
	}{Schema: "lcpdte-route-b-signed8-radix4-equivalence-proof-v1", RadixDigest: model.digest, BinaryDigest: binaryModel.digest, Minimum: -96, Maximum: 95}
	for value := int64(-96); value <= 95; value++ {
		leaf, path, predicates, oracleErr := routeBSigned8Radix4Oracle(value, ranges, model)
		if oracleErr != nil {
			return "", oracleErr
		}
		binaryLeaf, binaryPath, branches, binaryErr := routeBSigned8Depth2NodeBatchOracle([3]int64{value, value, value}, binaryRanges, binaryModel)
		if binaryErr != nil {
			return "", binaryErr
		}
		if path != binaryPath || math.Float64bits(leaf) != math.Float64bits(binaryLeaf) {
			return "", lineagef("signed8 radix-4 and binary oracles differ at %d", value)
		}
		record.Rows = append(record.Rows, [7]uint64{
			uint64(value), uint64(path), math.Float64bits(leaf),
			uint64(predicates[0]), uint64(predicates[1]), uint64(predicates[2]),
			uint64(4*branches[0] + 2*branches[1] + branches[2]),
		})
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	return routeBSigned8DigestBytes(payload), nil
}

func newRouteBSigned8Radix4RangeReports(ranges [3]homchain.Signed8NoOverflowRange) (result [3]RouteBSigned8RootTreeRangeReport) {
	for index := range ranges {
		result[index] = newRouteBSigned8RootTreeRangeReport(ranges[index])
	}
	return result
}

func newRouteBSigned8Radix4ModelReport(model RouteBSigned8Radix4Model) RouteBSigned8Radix4ModelReport {
	report := RouteBSigned8Radix4ModelReport{Thresholds: model.thresholds, Leaves: model.leaves, Digest: model.digest}
	for index, leaf := range model.leaves {
		report.LeafBits[index] = math.Float64bits(leaf)
	}
	return report
}

func reconstructRouteBSigned8Radix4Inputs(
	rangeReports [3]RouteBSigned8RootTreeRangeReport,
	modelReport RouteBSigned8Radix4ModelReport,
) (ranges [3]homchain.Signed8NoOverflowRange, model RouteBSigned8Radix4Model, err error) {
	for index, report := range rangeReports {
		ranges[index], err = homchain.NewSigned8NoOverflowRange(report.XMinimum, report.XMaximum, report.ThresholdMinimum, report.ThresholdMaximum)
		if err != nil {
			return ranges, model, err
		}
		if ranges[index].DifferenceMinimum() != report.DifferenceMinimum || ranges[index].DifferenceMaximum() != report.DifferenceMaximum || ranges[index].Digest() != report.Digest {
			return ranges, model, lineagef("signed8 radix-4 range report %d changed", index)
		}
	}
	for index, leaf := range modelReport.Leaves {
		if math.Float64bits(leaf) != modelReport.LeafBits[index] {
			return ranges, model, lineagef("signed8 radix-4 leaf bit snapshot %d changed", index)
		}
	}
	model, err = NewRouteBSigned8Radix4Model(modelReport.Thresholds, modelReport.Leaves)
	if err != nil {
		return ranges, model, err
	}
	if model.digest != modelReport.Digest {
		return ranges, model, lineagef("signed8 radix-4 model report changed")
	}
	return ranges, model, nil
}

func digestRouteBSigned8Radix4Report(report RouteBSigned8Radix4Report) (string, error) {
	copyReport := report
	copyReport.Digest = ""
	payload, err := json.Marshal(copyReport)
	if err != nil {
		return "", err
	}
	return routeBSigned8DigestBytes(payload), nil
}
