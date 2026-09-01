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
	routeBSigned8Depth2NodeBatchReportSchema = "lcpdte-route-b-signed8-depth2-node-batch-report-v1"
	routeBSigned8Depth2NodeBatchClaim        = "lattigo_n16_l11_signed8_public_depth2_all_nodes_one_a2b_security_unverified"
	routeBSigned8Depth2NodeBatchFidelity     = "lattigo_packing_adaptation_r1_public_model_node_batched"

	routeBSigned8Depth2NodeBatchEncoderPrecision = 256
	routeBSigned8Depth2NodeBatchInputLevel       = 20
	routeBSigned8Depth2NodeBatchHighLevel        = 5
	routeBSigned8Depth2NodeBatchBroadcastLevel   = 4
	routeBSigned8Depth2NodeBatchSelectorLevel    = 3
	routeBSigned8Depth2NodeBatchAlignedLevel     = 2
	routeBSigned8Depth2NodeBatchPathLevel        = 1
	routeBSigned8Depth2NodeBatchOutputLevel      = 0
)

type routeBSigned8Depth2NodeBatchArtifacts struct {
	params ckks.Parameters

	threshold, globalOne, rootOne *rlwe.Plaintext
	roleMasks                     [3]*rlwe.Plaintext
	leafDeltas                    [3]*rlwe.Plaintext
	baseLeaf                      *rlwe.Plaintext
	broadcast                     lintrans.LinearTransformation

	pathScale, leafOperandScale rlwe.Scale

	parameterDigest, thresholdDigest, globalOneDigest, rootOneDigest string
	roleMaskDigests                                                  [3]string
	leafDeltaDigests                                                 [3]string
	baseLeafDigest                                                   string

	broadcastSourceDigest    string
	broadcastCompiledDigest  string
	broadcastEncodedBytes    uint64
	broadcastRotationIndexes []int
	broadcastGaloisElements  []uint64
	alignmentRotationIndexes []int
	alignmentGaloisElements  []uint64
}

func newRouteBSigned8Depth2NodeBatchArtifacts(
	params ckks.Parameters,
	model RouteBSigned8Depth2NodeBatchModel,
) (routeBSigned8Depth2NodeBatchArtifacts, error) {
	canonical, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, err
	}
	if !params.Equal(&canonical) || params.LogN() != 16 || params.LogDefaultScale() != 43 ||
		params.MaxLevel() != routeBSigned8Depth2NodeBatchInputLevel || params.MaxLevelP() != 6 ||
		params.LevelsConsumedPerRescaling() != 1 {
		return routeBSigned8Depth2NodeBatchArtifacts{}, lineagef("signed8 depth-2 node-batch parameters differ from the canonical N16/L11 Route-B chain")
	}
	if err = validateRouteBSigned8Depth2NodeBatchModel(model); err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, err
	}
	encoder := ckks.NewEncoder(params, routeBSigned8Depth2NodeBatchEncoderPrecision)
	thresholdSlots, err := routeBSigned8Depth2NodeBatchThresholdSlots(model)
	if err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, err
	}
	threshold, err := encodeRouteBSigned8Plaintext(params, encoder, thresholdSlots, routeBSigned8Depth2NodeBatchInputLevel, params.DefaultScale())
	if err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, fmt.Errorf("secureeval: encode signed8 depth-2 threshold batch: %w", err)
	}
	globalOne, err := encodeRouteBSigned8Plaintext(params, encoder, routeBSigned8ConstantSlots(1), routeBSigned8Depth2NodeBatchSelectorLevel, params.DefaultScale())
	if err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, fmt.Errorf("secureeval: encode signed8 depth-2 global one: %w", err)
	}
	rootOneSlots := routeBSigned8Depth2NodeBatchRoleSlots(0, 1)
	rootOne, err := encodeRouteBSigned8Plaintext(params, encoder, rootOneSlots, routeBSigned8Depth2NodeBatchAlignedLevel, params.DefaultScale())
	if err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, fmt.Errorf("secureeval: encode signed8 depth-2 root-output one: %w", err)
	}
	var roleMasks [3]*rlwe.Plaintext
	for role := range roleMasks {
		roleMasks[role], err = encodeRouteBSigned8Plaintext(
			params, encoder, routeBSigned8Depth2NodeBatchRoleSlots(role, 1),
			routeBSigned8Depth2NodeBatchSelectorLevel, rlwe.NewScale(params.Q()[routeBSigned8Depth2NodeBatchSelectorLevel]),
		)
		if err != nil {
			return routeBSigned8Depth2NodeBatchArtifacts{}, fmt.Errorf("secureeval: encode signed8 depth-2 role mask %d: %w", role, err)
		}
	}
	pathScale := params.DefaultScale().Mul(params.DefaultScale()).Div(rlwe.NewScale(params.Q()[routeBSigned8Depth2NodeBatchAlignedLevel]))
	leafOperandScale := rlwe.NewScale(params.Q()[routeBSigned8Depth2NodeBatchPathLevel]).Mul(params.DefaultScale()).Div(pathScale)
	leaves := model.leaves
	deltas := [3]float64{leaves[1] - leaves[0], leaves[2] - leaves[0], leaves[3] - leaves[2]}
	var leafDeltas [3]*rlwe.Plaintext
	for index, delta := range deltas {
		leafDeltas[index], err = encodeRouteBSigned8Plaintext(
			params, encoder, routeBSigned8ConstantSlots(delta),
			routeBSigned8Depth2NodeBatchPathLevel, leafOperandScale,
		)
		if err != nil {
			return routeBSigned8Depth2NodeBatchArtifacts{}, fmt.Errorf("secureeval: encode signed8 depth-2 leaf delta %d: %w", index, err)
		}
	}
	baseLeaf, err := encodeRouteBSigned8Plaintext(
		params, encoder, routeBSigned8Depth2NodeBatchRoleSlots(0, leaves[0]),
		routeBSigned8Depth2NodeBatchOutputLevel, params.DefaultScale(),
	)
	if err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, fmt.Errorf("secureeval: encode signed8 depth-2 base leaf: %w", err)
	}
	broadcast, sourceDigest, compiledDigest, encodedBytes, broadcastRotations, broadcastGalois, err := newRouteBSigned8Broadcast(params, encoder)
	if err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, err
	}
	parameterPayload, err := params.MarshalBinary()
	if err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, err
	}
	artifacts := routeBSigned8Depth2NodeBatchArtifacts{
		params: params, threshold: threshold, globalOne: globalOne, rootOne: rootOne,
		roleMasks: roleMasks, leafDeltas: leafDeltas, baseLeaf: baseLeaf,
		broadcast: broadcast, pathScale: pathScale, leafOperandScale: leafOperandScale,
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
		return routeBSigned8Depth2NodeBatchArtifacts{}, err
	}
	if artifacts.globalOneDigest, err = routeBSigned8RootTreePlaintextDigest(globalOne); err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, err
	}
	if artifacts.rootOneDigest, err = routeBSigned8RootTreePlaintextDigest(rootOne); err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, err
	}
	for index := range roleMasks {
		if artifacts.roleMaskDigests[index], err = routeBSigned8RootTreePlaintextDigest(roleMasks[index]); err != nil {
			return routeBSigned8Depth2NodeBatchArtifacts{}, err
		}
		if artifacts.leafDeltaDigests[index], err = routeBSigned8RootTreePlaintextDigest(leafDeltas[index]); err != nil {
			return routeBSigned8Depth2NodeBatchArtifacts{}, err
		}
	}
	if artifacts.baseLeafDigest, err = routeBSigned8RootTreePlaintextDigest(baseLeaf); err != nil {
		return routeBSigned8Depth2NodeBatchArtifacts{}, err
	}
	return artifacts, nil
}

func routeBSigned8Depth2NodeBatchThresholdSlots(model RouteBSigned8Depth2NodeBatchModel) ([]*bignum.Complex, error) {
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8Depth2NodeBatchEncoderPrecision)
	if err != nil {
		return nil, err
	}
	values := make([]*bignum.Complex, 0, routeBSigned8Depth2NodeBatchSlots)
	for word := 0; word < routeBSigned8Depth2NodeBatchWords; word++ {
		threshold := int64(0)
		if word < routeBSigned8Depth2NodeBatchQueries*routeBSigned8Depth2NodeBatchWordsPerQuery {
			threshold = model.thresholds[word%routeBSigned8Depth2NodeBatchWordsPerQuery]
		}
		block, blockErr := ringZ.ToRootSlots(ringZ.ArithmeticEncode(uint64(uint8(threshold))))
		if blockErr != nil {
			return nil, fmt.Errorf("secureeval: encode signed8 depth-2 threshold word %d: %w", word, blockErr)
		}
		values = append(values, block...)
	}
	if len(values) != routeBSigned8Depth2NodeBatchSlots {
		return nil, lineagef("signed8 depth-2 threshold slot count changed")
	}
	return values, nil
}

func routeBSigned8Depth2NodeBatchRoleSlots(role int, value float64) []*bignum.Complex {
	values := make([]*bignum.Complex, routeBSigned8Depth2NodeBatchSlots)
	for index := range values {
		values[index] = bignum.NewComplex().SetPrec(routeBSigned8Depth2NodeBatchEncoderPrecision)
	}
	if role < 0 || role >= routeBSigned8Depth2NodeBatchWordsPerQuery {
		return values
	}
	for query := 0; query < routeBSigned8Depth2NodeBatchQueries; query++ {
		word := routeBSigned8Depth2NodeBatchWordsPerQuery*query + role
		for slot := 0; slot < 4; slot++ {
			values[4*word+slot].Real().SetFloat64(value)
		}
	}
	return values
}

type RouteBSigned8Depth2NodeBatchModelReport struct {
	Thresholds [3]int64   `json:"thresholds"`
	Leaves     [4]float64 `json:"leaves"`
	LeafBits   [4]uint64  `json:"leaf_bits"`
	Digest     string     `json:"digest"`
}

type RouteBSigned8Depth2NodeBatchStage string

const (
	RouteBSigned8Depth2StageInput        RouteBSigned8Depth2NodeBatchStage = "encrypted-node-feature-batch"
	RouteBSigned8Depth2StageDifference   RouteBSigned8Depth2NodeBatchStage = "node-features-minus-public-thresholds"
	RouteBSigned8Depth2StageHighBoolean  RouteBSigned8Depth2NodeBatchStage = "complete-a2b-high-boolean-half"
	RouteBSigned8Depth2StageBroadcastRaw RouteBSigned8Depth2NodeBatchStage = "word-sign-broadcast-before-rescale"
	RouteBSigned8Depth2StageSign         RouteBSigned8Depth2NodeBatchStage = "word-repeated-sign"
	RouteBSigned8Depth2StageGE           RouteBSigned8Depth2NodeBatchStage = "word-repeated-ge"
	RouteBSigned8Depth2StageRootMaskRaw  RouteBSigned8Depth2NodeBatchStage = "root-role-mask-before-rescale"
	RouteBSigned8Depth2StageRootAligned  RouteBSigned8Depth2NodeBatchStage = "root-selector-aligned"
	RouteBSigned8Depth2StageLeftMaskRaw  RouteBSigned8Depth2NodeBatchStage = "left-role-mask-before-rescale"
	RouteBSigned8Depth2StageLeftMasked   RouteBSigned8Depth2NodeBatchStage = "left-role-masked"
	RouteBSigned8Depth2StageLeftAligned  RouteBSigned8Depth2NodeBatchStage = "left-selector-aligned"
	RouteBSigned8Depth2StageRightMaskRaw RouteBSigned8Depth2NodeBatchStage = "right-role-mask-before-rescale"
	RouteBSigned8Depth2StageRightMasked  RouteBSigned8Depth2NodeBatchStage = "right-role-masked"
	RouteBSigned8Depth2StageRightAligned RouteBSigned8Depth2NodeBatchStage = "right-selector-aligned"
	RouteBSigned8Depth2StageNotRoot      RouteBSigned8Depth2NodeBatchStage = "one-minus-root-selector"
	RouteBSigned8Depth2StageNotRight     RouteBSigned8Depth2NodeBatchStage = "one-minus-right-selector"
	RouteBSigned8Depth2StageP01Raw       RouteBSigned8Depth2NodeBatchStage = "p01-before-rescale"
	RouteBSigned8Depth2StageP01          RouteBSigned8Depth2NodeBatchStage = "p01"
	RouteBSigned8Depth2StageP10Raw       RouteBSigned8Depth2NodeBatchStage = "p10-before-rescale"
	RouteBSigned8Depth2StageP10          RouteBSigned8Depth2NodeBatchStage = "p10"
	RouteBSigned8Depth2StageP11Raw       RouteBSigned8Depth2NodeBatchStage = "p11-before-rescale"
	RouteBSigned8Depth2StageP11          RouteBSigned8Depth2NodeBatchStage = "p11"
	RouteBSigned8Depth2StageRootRight    RouteBSigned8Depth2NodeBatchStage = "p10-plus-p11"
	RouteBSigned8Depth2StageTerm01Raw    RouteBSigned8Depth2NodeBatchStage = "p01-dl-before-rescale"
	RouteBSigned8Depth2StageTerm01       RouteBSigned8Depth2NodeBatchStage = "p01-dl"
	RouteBSigned8Depth2StageTermXRaw     RouteBSigned8Depth2NodeBatchStage = "root-right-dx-before-rescale"
	RouteBSigned8Depth2StageTermX        RouteBSigned8Depth2NodeBatchStage = "root-right-dx"
	RouteBSigned8Depth2StageTerm11Raw    RouteBSigned8Depth2NodeBatchStage = "p11-dr-before-rescale"
	RouteBSigned8Depth2StageTerm11       RouteBSigned8Depth2NodeBatchStage = "p11-dr"
	RouteBSigned8Depth2StageOutput       RouteBSigned8Depth2NodeBatchStage = "selected-real-leaf-root-words"
)

type RouteBSigned8Depth2NodeBatchState struct {
	Stage      RouteBSigned8Depth2NodeBatchStage `json:"stage"`
	Level      int                               `json:"level"`
	Degree     int                               `json:"degree"`
	LogRows    int                               `json:"log_rows"`
	LogColumns int                               `json:"log_columns"`
	ScaleHex   string                            `json:"scale_hex"`
	ScaleExact bool                              `json:"scale_exact"`
	IsBatched  bool                              `json:"is_batched"`
	IsNTT      bool                              `json:"is_ntt"`
}

type RouteBSigned8Depth2NodeBatchOperationCounts struct {
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
	PathComplementNegations            int `json:"path_complement_negations"`
	PathComplementPlaintextAdditions   int `json:"path_complement_plaintext_additions"`
	PathCiphertextProducts             int `json:"path_ciphertext_products"`
	PathRelinearizations               int `json:"path_relinearizations"`
	PathRescales                       int `json:"path_rescales"`
	PathCiphertextAdditions            int `json:"path_ciphertext_additions"`
	LeafPlaintextProducts              int `json:"leaf_plaintext_products"`
	LeafRescales                       int `json:"leaf_rescales"`
	LeafCiphertextAdditions            int `json:"leaf_ciphertext_additions"`
	BaseLeafPlaintextAdditions         int `json:"base_leaf_plaintext_additions"`
	LogicalPeakLiveWrapperCiphertexts  int `json:"logical_peak_live_wrapper_ciphertexts"`
}

type RouteBSigned8Depth2NodeBatchReport struct {
	SchemaVersion string `json:"schema_version"`
	Claim         string `json:"claim"`
	Fidelity      string `json:"fidelity"`

	CapacityPlanDigest       string                                      `json:"capacity_plan_digest"`
	ParameterDigest          string                                      `json:"parameter_digest"`
	Ranges                   [3]RouteBSigned8RootTreeRangeReport         `json:"ranges"`
	Model                    RouteBSigned8Depth2NodeBatchModelReport     `json:"model"`
	InputPayloadDigest       string                                      `json:"input_payload_digest"`
	OutputPayloadDigest      string                                      `json:"output_payload_digest"`
	ThresholdDigest          string                                      `json:"threshold_payload_digest"`
	GlobalOneDigest          string                                      `json:"global_one_payload_digest"`
	RootOneDigest            string                                      `json:"root_one_payload_digest"`
	RoleMaskDigests          [3]string                                   `json:"role_mask_payload_digests"`
	LeafDeltaDigests         [3]string                                   `json:"leaf_delta_payload_digests"`
	BaseLeafDigest           string                                      `json:"base_leaf_payload_digest"`
	BroadcastSourceDigest    string                                      `json:"broadcast_source_digest"`
	BroadcastCompiledDigest  string                                      `json:"broadcast_compiled_digest"`
	BroadcastEncodedBytes    uint64                                      `json:"broadcast_encoded_bytes"`
	BroadcastRotationIndexes []int                                       `json:"broadcast_rotation_indexes"`
	BroadcastGaloisElements  []uint64                                    `json:"broadcast_galois_elements"`
	AlignmentRotationIndexes []int                                       `json:"alignment_rotation_indexes"`
	AlignmentGaloisElements  []uint64                                    `json:"alignment_galois_elements"`
	PathScaleHex             string                                      `json:"path_scale_hex"`
	LeafOperandScaleHex      string                                      `json:"leaf_operand_scale_hex"`
	FullA2B                  RouteBA2BFullReport                         `json:"full_a2b"`
	States                   []RouteBSigned8Depth2NodeBatchState         `json:"states"`
	OperationCounts          RouteBSigned8Depth2NodeBatchOperationCounts `json:"operation_counts"`
	WallNanoseconds          uint64                                      `json:"wall_nanoseconds"`
	Digest                   string                                      `json:"digest"`
}

type RouteBSigned8Depth2NodeBatchResult struct {
	ciphertext *rlwe.Ciphertext
	digest     string
}

func (result RouteBSigned8Depth2NodeBatchResult) Ciphertext() *rlwe.Ciphertext {
	if result.ciphertext == nil {
		return nil
	}
	return result.ciphertext.CopyNew()
}

func (result RouteBSigned8Depth2NodeBatchResult) ReportDigest() string { return result.digest }

func (report RouteBSigned8Depth2NodeBatchReport) Validate() error {
	if report.SchemaVersion != routeBSigned8Depth2NodeBatchReportSchema ||
		report.Claim != routeBSigned8Depth2NodeBatchClaim || report.Fidelity != routeBSigned8Depth2NodeBatchFidelity ||
		report.WallNanoseconds == 0 || report.Digest == "" {
		return lineagef("signed8 depth-2 node-batch report identity, wall time, or digest changed")
	}
	ranges, model, err := reconstructRouteBSigned8Depth2NodeBatchInputs(report.Ranges, report.Model)
	if err != nil {
		return err
	}
	if err = validateRouteBSigned8Depth2NodeBatchInputs(ranges, model); err != nil {
		return err
	}
	plan, err := canonicalRouteBCapacityPlan(routeBCapacityGateSigned8Depth2NodeBatch)
	if err != nil {
		return err
	}
	if report.CapacityPlanDigest != plan.Digest() {
		return lineagef("signed8 depth-2 node-batch capacity plan changed")
	}
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return err
	}
	artifacts, err := newRouteBSigned8Depth2NodeBatchArtifacts(params, model)
	if err != nil {
		return err
	}
	pathScale, err := homchain.NewExactScaleSnapshot(artifacts.pathScale)
	if err != nil {
		return err
	}
	leafScale, err := homchain.NewExactScaleSnapshot(artifacts.leafOperandScale)
	if err != nil {
		return err
	}
	if report.ParameterDigest != artifacts.parameterDigest || report.ThresholdDigest != artifacts.thresholdDigest ||
		report.GlobalOneDigest != artifacts.globalOneDigest || report.RootOneDigest != artifacts.rootOneDigest ||
		report.RoleMaskDigests != artifacts.roleMaskDigests || report.LeafDeltaDigests != artifacts.leafDeltaDigests ||
		report.BaseLeafDigest != artifacts.baseLeafDigest || report.BroadcastSourceDigest != artifacts.broadcastSourceDigest ||
		report.BroadcastCompiledDigest != artifacts.broadcastCompiledDigest || report.BroadcastEncodedBytes != artifacts.broadcastEncodedBytes ||
		!slices.Equal(report.BroadcastRotationIndexes, artifacts.broadcastRotationIndexes) ||
		!slices.Equal(report.BroadcastGaloisElements, artifacts.broadcastGaloisElements) ||
		!slices.Equal(report.AlignmentRotationIndexes, artifacts.alignmentRotationIndexes) ||
		!slices.Equal(report.AlignmentGaloisElements, artifacts.alignmentGaloisElements) ||
		report.PathScaleHex != pathScale.ValueHex() || report.LeafOperandScaleHex != leafScale.ValueHex() {
		return lineagef("signed8 depth-2 node-batch parameter, plaintext, scale, transform, or key identity changed")
	}
	if !routeBA2BFullIsSHA256(report.InputPayloadDigest) || !routeBA2BFullIsSHA256(report.OutputPayloadDigest) {
		return lineagef("signed8 depth-2 node-batch input or output payload digest is malformed")
	}
	if err = report.FullA2B.Validate(); err != nil {
		return fmt.Errorf("secureeval: validate nested signed8 depth-2 complete A2B: %w", err)
	}
	expectedStates, err := routeBSigned8Depth2NodeBatchExpectedStates(params, artifacts)
	if err != nil {
		return err
	}
	if !slices.Equal(report.States, expectedStates) {
		return lineagef("signed8 depth-2 node-batch exact state ledger changed: got=%+v want=%+v", report.States, expectedStates)
	}
	if report.OperationCounts != routeBSigned8Depth2NodeBatchExpectedCounts(artifacts) {
		return lineagef("signed8 depth-2 node-batch operation ledger changed")
	}
	digest, err := digestRouteBSigned8Depth2NodeBatchReport(report)
	if err != nil || digest != report.Digest {
		return lineagef("signed8 depth-2 node-batch report digest changed")
	}
	return nil
}

func (installed *RouteBInstalledEvaluator) RunSigned8Depth2NodeBatchPublic(
	input *rlwe.Ciphertext,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Depth2NodeBatchModel,
) (result RouteBSigned8Depth2NodeBatchResult, firstOperation RouteBFirstOperationReport, report RouteBSigned8Depth2NodeBatchReport, err error) {
	if err = validateRouteBSigned8Depth2NodeBatchInputs(ranges, model); err != nil {
		return result, firstOperation, report, err
	}
	runner := func(evaluator *bootstrapping.Evaluator, ciphertext *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		output, observation, runReport, runErr := runCanonicalRouteBSigned8Depth2NodeBatch(evaluator, ciphertext, ranges, model)
		if runErr == nil {
			report = runReport
		}
		return output, observation, runErr
	}
	output, firstOperation, err := installed.runFirstOperationWithHooks(
		input, routeBCapacityGateSigned8Depth2NodeBatch, routeBRuntimeOperationSigned8Depth2NodeBatch,
		validateCanonicalRouteBInstalledResident, validateCanonicalRouteBInstalledEvaluator, runner,
	)
	if err != nil {
		return RouteBSigned8Depth2NodeBatchResult{}, RouteBFirstOperationReport{}, RouteBSigned8Depth2NodeBatchReport{}, err
	}
	if output == nil || report.Digest == "" {
		return RouteBSigned8Depth2NodeBatchResult{}, RouteBFirstOperationReport{}, RouteBSigned8Depth2NodeBatchReport{}, lineagef("signed8 depth-2 node-batch returned an incomplete result")
	}
	if err = report.Validate(); err != nil {
		return RouteBSigned8Depth2NodeBatchResult{}, RouteBFirstOperationReport{}, RouteBSigned8Depth2NodeBatchReport{}, err
	}
	return RouteBSigned8Depth2NodeBatchResult{ciphertext: output, digest: report.Digest}, firstOperation, report, nil
}

func runCanonicalRouteBSigned8Depth2NodeBatch(
	evaluator *bootstrapping.Evaluator,
	input *rlwe.Ciphertext,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Depth2NodeBatchModel,
) (output *rlwe.Ciphertext, observation routeBFirstOperationObservation, report RouteBSigned8Depth2NodeBatchReport, err error) {
	started := time.Now()
	if evaluator == nil || evaluator.Evaluator == nil || input == nil {
		return nil, observation, report, lineagef("signed8 depth-2 node-batch evaluator or input is nil")
	}
	if err = validateRouteBSigned8Depth2NodeBatchInputs(ranges, model); err != nil {
		return nil, observation, report, err
	}
	params := evaluator.BootstrappingParameters
	if err = requireRouteBSigned8Depth2NodeBatchState("input", input, routeBSigned8Depth2NodeBatchInputLevel, params.DefaultScale(), params); err != nil {
		return nil, observation, report, err
	}
	inputDigest, err := routeBSigned8RootTreeCiphertextDigest(input)
	if err != nil {
		return nil, observation, report, err
	}
	inputBefore := input.CopyNew()
	artifacts, err := newRouteBSigned8Depth2NodeBatchArtifacts(params, model)
	if err != nil {
		return nil, observation, report, err
	}
	if err = preflightRouteBSigned8Depth2NodeBatchKeys(evaluator.Evaluator, artifacts); err != nil {
		return nil, observation, report, err
	}
	states := make([]RouteBSigned8Depth2NodeBatchState, 0, 30)
	appendState := func(stage RouteBSigned8Depth2NodeBatchStage, ciphertext *rlwe.Ciphertext, expected rlwe.Scale) error {
		state, stateErr := snapshotRouteBSigned8Depth2NodeBatchState(stage, ciphertext, expected)
		if stateErr == nil {
			states = append(states, state)
		}
		return stateErr
	}
	if err = appendState(RouteBSigned8Depth2StageInput, input, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	difference, err := evaluator.Evaluator.SubNew(input, artifacts.threshold)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 threshold subtraction: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageDifference, difference, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	_, high, observation, fullReport, err := runCanonicalRouteBFirstSparseA2BFull(evaluator, difference)
	if err != nil {
		return nil, routeBFirstOperationObservation{}, report, fmt.Errorf("secureeval: signed8 depth-2 complete A2B: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageHighBoolean, high, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	linear := lintrans.NewEvaluator(evaluator.Evaluator)
	broadcastRaw, err := linear.EvaluateNew(high, artifacts.broadcast)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 word sign broadcast: %w", err)
	}
	broadcastRawScale := params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Depth2NodeBatchBroadcastLevel]))
	if err = appendState(RouteBSigned8Depth2StageBroadcastRaw, broadcastRaw, broadcastRawScale); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(broadcastRaw, broadcastRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 rescale word sign broadcast: %w", err)
	}
	sign := broadcastRaw
	if err = appendState(RouteBSigned8Depth2StageSign, sign, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	ge := sign.CopyNew()
	params.RingQ().AtLevel(ge.Level()).Neg(ge.Value[0], ge.Value[0])
	params.RingQ().AtLevel(ge.Level()).Neg(ge.Value[1], ge.Value[1])
	if err = evaluator.Evaluator.Add(ge, artifacts.globalOne, ge); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 complement word signs: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageGE, ge, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	maskRawScale := params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Depth2NodeBatchSelectorLevel]))
	maskStages := [3][2]RouteBSigned8Depth2NodeBatchStage{
		{RouteBSigned8Depth2StageRootMaskRaw, RouteBSigned8Depth2StageRootAligned},
		{RouteBSigned8Depth2StageLeftMaskRaw, RouteBSigned8Depth2StageLeftMasked},
		{RouteBSigned8Depth2StageRightMaskRaw, RouteBSigned8Depth2StageRightMasked},
	}
	var selectors [3]*rlwe.Ciphertext
	for role := range selectors {
		masked, maskErr := evaluator.Evaluator.MulNew(ge, artifacts.roleMasks[role])
		if maskErr != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 role %d mask: %w", role, maskErr)
		}
		if err = appendState(maskStages[role][0], masked, maskRawScale); err != nil {
			return nil, observation, report, err
		}
		if err = evaluator.Evaluator.Rescale(masked, masked); err != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 role %d mask rescale: %w", role, err)
		}
		if err = appendState(maskStages[role][1], masked, params.DefaultScale()); err != nil {
			return nil, observation, report, err
		}
		selectors[role] = masked
	}
	if selectors[1], err = evaluator.Evaluator.RotateNew(selectors[1], 4); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: align signed8 depth-2 left selector: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageLeftAligned, selectors[1], params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	if selectors[2], err = evaluator.Evaluator.RotateNew(selectors[2], 8); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: align signed8 depth-2 right selector: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageRightAligned, selectors[2], params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	b0, bL, bR := selectors[0], selectors[1], selectors[2]
	notRoot, err := complementRouteBSigned8Depth2Selector(params, evaluator.Evaluator, b0, artifacts.rootOne)
	if err != nil {
		return nil, observation, report, err
	}
	if err = appendState(RouteBSigned8Depth2StageNotRoot, notRoot, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	notRight, err := complementRouteBSigned8Depth2Selector(params, evaluator.Evaluator, bR, artifacts.rootOne)
	if err != nil {
		return nil, observation, report, err
	}
	if err = appendState(RouteBSigned8Depth2StageNotRight, notRight, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	pathRawScale := params.DefaultScale().Mul(params.DefaultScale())
	pathPairs := [3][2]*rlwe.Ciphertext{{notRoot, bL}, {b0, notRight}, {b0, bR}}
	pathStages := [3][2]RouteBSigned8Depth2NodeBatchStage{
		{RouteBSigned8Depth2StageP01Raw, RouteBSigned8Depth2StageP01},
		{RouteBSigned8Depth2StageP10Raw, RouteBSigned8Depth2StageP10},
		{RouteBSigned8Depth2StageP11Raw, RouteBSigned8Depth2StageP11},
	}
	var paths [3]*rlwe.Ciphertext
	for index, pair := range pathPairs {
		path, pathErr := evaluator.Evaluator.MulRelinNew(pair[0], pair[1])
		if pathErr != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 path product %d: %w", index, pathErr)
		}
		if err = appendState(pathStages[index][0], path, pathRawScale); err != nil {
			return nil, observation, report, err
		}
		if err = evaluator.Evaluator.Rescale(path, path); err != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 path rescale %d: %w", index, err)
		}
		if err = appendState(pathStages[index][1], path, artifacts.pathScale); err != nil {
			return nil, observation, report, err
		}
		paths[index] = path
	}
	rootRight, err := evaluator.Evaluator.AddNew(paths[1], paths[2])
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 add right-subtree paths: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageRootRight, rootRight, artifacts.pathScale); err != nil {
		return nil, observation, report, err
	}
	leafInputs := [3]*rlwe.Ciphertext{paths[0], rootRight, paths[2]}
	leafStages := [3][2]RouteBSigned8Depth2NodeBatchStage{
		{RouteBSigned8Depth2StageTerm01Raw, RouteBSigned8Depth2StageTerm01},
		{RouteBSigned8Depth2StageTermXRaw, RouteBSigned8Depth2StageTermX},
		{RouteBSigned8Depth2StageTerm11Raw, RouteBSigned8Depth2StageTerm11},
	}
	leafRawScale := artifacts.pathScale.Mul(artifacts.leafOperandScale)
	var terms [3]*rlwe.Ciphertext
	for index, selector := range leafInputs {
		term, termErr := evaluator.Evaluator.MulNew(selector, artifacts.leafDeltas[index])
		if termErr != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 leaf term %d: %w", index, termErr)
		}
		if err = appendState(leafStages[index][0], term, leafRawScale); err != nil {
			return nil, observation, report, err
		}
		if err = evaluator.Evaluator.Rescale(term, term); err != nil {
			return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 leaf rescale %d: %w", index, err)
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
		return nil, observation, report, fmt.Errorf("secureeval: signed8 depth-2 combine leaf terms: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageOutput, output, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	if !input.Equal(inputBefore) {
		return nil, observation, report, lineagef("signed8 depth-2 node-batch mutated its encrypted input")
	}
	outputDigest, err := routeBSigned8RootTreeCiphertextDigest(output)
	if err != nil {
		return nil, observation, report, err
	}
	capacity, err := canonicalRouteBCapacityPlan(routeBCapacityGateSigned8Depth2NodeBatch)
	if err != nil {
		return nil, observation, report, err
	}
	pathScaleSnapshot, err := homchain.NewExactScaleSnapshot(artifacts.pathScale)
	if err != nil {
		return nil, observation, report, err
	}
	leafScaleSnapshot, err := homchain.NewExactScaleSnapshot(artifacts.leafOperandScale)
	if err != nil {
		return nil, observation, report, err
	}
	wall := uint64(time.Since(started).Nanoseconds())
	if wall == 0 {
		wall = 1
	}
	report = RouteBSigned8Depth2NodeBatchReport{
		SchemaVersion: routeBSigned8Depth2NodeBatchReportSchema, Claim: routeBSigned8Depth2NodeBatchClaim,
		Fidelity: routeBSigned8Depth2NodeBatchFidelity, CapacityPlanDigest: capacity.Digest(),
		ParameterDigest: artifacts.parameterDigest, Ranges: newRouteBSigned8Depth2NodeBatchRangeReports(ranges),
		Model: newRouteBSigned8Depth2NodeBatchModelReport(model), InputPayloadDigest: inputDigest,
		OutputPayloadDigest: outputDigest, ThresholdDigest: artifacts.thresholdDigest,
		GlobalOneDigest: artifacts.globalOneDigest, RootOneDigest: artifacts.rootOneDigest,
		RoleMaskDigests: artifacts.roleMaskDigests, LeafDeltaDigests: artifacts.leafDeltaDigests,
		BaseLeafDigest: artifacts.baseLeafDigest, BroadcastSourceDigest: artifacts.broadcastSourceDigest,
		BroadcastCompiledDigest: artifacts.broadcastCompiledDigest, BroadcastEncodedBytes: artifacts.broadcastEncodedBytes,
		BroadcastRotationIndexes: append([]int(nil), artifacts.broadcastRotationIndexes...),
		BroadcastGaloisElements:  append([]uint64(nil), artifacts.broadcastGaloisElements...),
		AlignmentRotationIndexes: append([]int(nil), artifacts.alignmentRotationIndexes...),
		AlignmentGaloisElements:  append([]uint64(nil), artifacts.alignmentGaloisElements...),
		PathScaleHex:             pathScaleSnapshot.ValueHex(), LeafOperandScaleHex: leafScaleSnapshot.ValueHex(),
		FullA2B: fullReport, States: states, OperationCounts: routeBSigned8Depth2NodeBatchExpectedCounts(artifacts),
		WallNanoseconds: wall,
	}
	report.Digest, err = digestRouteBSigned8Depth2NodeBatchReport(report)
	if err != nil {
		return nil, observation, RouteBSigned8Depth2NodeBatchReport{}, err
	}
	return output, observation, report, nil
}

func complementRouteBSigned8Depth2Selector(params ckks.Parameters, evaluator *ckks.Evaluator, selector *rlwe.Ciphertext, one *rlwe.Plaintext) (*rlwe.Ciphertext, error) {
	if evaluator == nil || selector == nil || one == nil {
		return nil, lineagef("signed8 depth-2 selector complement input is nil")
	}
	result := selector.CopyNew()
	ringQ := params.RingQ().AtLevel(result.Level())
	for index := range result.Value {
		ringQ.Neg(result.Value[index], result.Value[index])
	}
	if err := evaluator.Add(result, one, result); err != nil {
		return nil, fmt.Errorf("secureeval: signed8 depth-2 selector complement: %w", err)
	}
	return result, nil
}

func preflightRouteBSigned8Depth2NodeBatchKeys(evaluator *ckks.Evaluator, artifacts routeBSigned8Depth2NodeBatchArtifacts) error {
	if evaluator == nil || evaluator.EvaluationKeySet == nil {
		return lineagef("signed8 depth-2 node-batch evaluator key set is nil")
	}
	required := append(append([]uint64(nil), artifacts.broadcastGaloisElements...), artifacts.alignmentGaloisElements...)
	slices.Sort(required)
	required = slices.Compact(required)
	installed := evaluator.EvaluationKeySet.GetGaloisKeysList()
	slices.Sort(installed)
	for _, element := range required {
		if _, present := slices.BinarySearch(installed, element); !present {
			return lineagef("signed8 depth-2 Galois element %d is outside the installed key union", element)
		}
		key, err := evaluator.EvaluationKeySet.GetGaloisKey(element)
		if err != nil || key == nil || key.GaloisElement != element || key.LevelQ() < routeBSigned8Depth2NodeBatchBroadcastLevel || key.LevelP() < 6 {
			return lineagef("signed8 depth-2 Galois key %d is absent or has insufficient levels", element)
		}
	}
	relin, err := evaluator.EvaluationKeySet.GetRelinearizationKey()
	if err != nil || relin == nil || relin.LevelQ() < routeBSigned8Depth2NodeBatchAlignedLevel || relin.LevelP() < 6 {
		return lineagef("signed8 depth-2 relinearization key is absent or has insufficient levels")
	}
	return nil
}

func requireRouteBSigned8Depth2NodeBatchState(name string, ciphertext *rlwe.Ciphertext, level int, scale rlwe.Scale, params ckks.Parameters) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level || ciphertext.Degree() != 1 ||
		ciphertext.LogN() != 16 || ciphertext.LogDimensions != (ring.Dimensions{Rows: 0, Cols: 11}) ||
		!ciphertext.IsBatched || !ciphertext.IsNTT || !rbdftEqualScaleExact(ciphertext.Scale, scale) ||
		ciphertext.Value[0].N() != params.N() || ciphertext.Value[1].N() != params.N() {
		return lineagef("signed8 depth-2 node-batch %s is not canonical L%d/degree1/L11/exact-scale", name, level)
	}
	return nil
}

func snapshotRouteBSigned8Depth2NodeBatchState(stage RouteBSigned8Depth2NodeBatchStage, ciphertext *rlwe.Ciphertext, expected rlwe.Scale) (RouteBSigned8Depth2NodeBatchState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return RouteBSigned8Depth2NodeBatchState{}, lineagef("cannot snapshot nil signed8 depth-2 stage %s", stage)
	}
	scale, err := homchain.NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return RouteBSigned8Depth2NodeBatchState{}, err
	}
	return RouteBSigned8Depth2NodeBatchState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogRows: ciphertext.LogDimensions.Rows, LogColumns: ciphertext.LogDimensions.Cols,
		ScaleHex: scale.ValueHex(), ScaleExact: rbdftEqualScaleExact(ciphertext.Scale, expected),
		IsBatched: ciphertext.IsBatched, IsNTT: ciphertext.IsNTT,
	}, nil
}

func routeBSigned8Depth2NodeBatchExpectedStates(params ckks.Parameters, artifacts routeBSigned8Depth2NodeBatchArtifacts) ([]RouteBSigned8Depth2NodeBatchState, error) {
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
	broadcastHex, err := snapshot(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Depth2NodeBatchBroadcastLevel])))
	if err != nil {
		return nil, err
	}
	maskRawHex, err := snapshot(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Depth2NodeBatchSelectorLevel])))
	if err != nil {
		return nil, err
	}
	pathRawHex, err := snapshot(params.DefaultScale().Mul(params.DefaultScale()))
	if err != nil {
		return nil, err
	}
	pathHex, err := snapshot(artifacts.pathScale)
	if err != nil {
		return nil, err
	}
	leafRawHex, err := snapshot(artifacts.pathScale.Mul(artifacts.leafOperandScale))
	if err != nil {
		return nil, err
	}
	state := func(stage RouteBSigned8Depth2NodeBatchStage, level int, scale string) RouteBSigned8Depth2NodeBatchState {
		return RouteBSigned8Depth2NodeBatchState{Stage: stage, Level: level, Degree: 1, LogRows: 0, LogColumns: 11, ScaleHex: scale, ScaleExact: true, IsBatched: true, IsNTT: true}
	}
	return []RouteBSigned8Depth2NodeBatchState{
		state(RouteBSigned8Depth2StageInput, 20, defaultHex), state(RouteBSigned8Depth2StageDifference, 20, defaultHex),
		state(RouteBSigned8Depth2StageHighBoolean, 5, defaultHex), state(RouteBSigned8Depth2StageBroadcastRaw, 4, broadcastHex),
		state(RouteBSigned8Depth2StageSign, 3, defaultHex), state(RouteBSigned8Depth2StageGE, 3, defaultHex),
		state(RouteBSigned8Depth2StageRootMaskRaw, 3, maskRawHex), state(RouteBSigned8Depth2StageRootAligned, 2, defaultHex),
		state(RouteBSigned8Depth2StageLeftMaskRaw, 3, maskRawHex), state(RouteBSigned8Depth2StageLeftMasked, 2, defaultHex),
		state(RouteBSigned8Depth2StageRightMaskRaw, 3, maskRawHex), state(RouteBSigned8Depth2StageRightMasked, 2, defaultHex),
		state(RouteBSigned8Depth2StageLeftAligned, 2, defaultHex), state(RouteBSigned8Depth2StageRightAligned, 2, defaultHex),
		state(RouteBSigned8Depth2StageNotRoot, 2, defaultHex), state(RouteBSigned8Depth2StageNotRight, 2, defaultHex),
		state(RouteBSigned8Depth2StageP01Raw, 2, pathRawHex), state(RouteBSigned8Depth2StageP01, 1, pathHex),
		state(RouteBSigned8Depth2StageP10Raw, 2, pathRawHex), state(RouteBSigned8Depth2StageP10, 1, pathHex),
		state(RouteBSigned8Depth2StageP11Raw, 2, pathRawHex), state(RouteBSigned8Depth2StageP11, 1, pathHex),
		state(RouteBSigned8Depth2StageRootRight, 1, pathHex),
		state(RouteBSigned8Depth2StageTerm01Raw, 1, leafRawHex), state(RouteBSigned8Depth2StageTerm01, 0, defaultHex),
		state(RouteBSigned8Depth2StageTermXRaw, 1, leafRawHex), state(RouteBSigned8Depth2StageTermX, 0, defaultHex),
		state(RouteBSigned8Depth2StageTerm11Raw, 1, leafRawHex), state(RouteBSigned8Depth2StageTerm11, 0, defaultHex),
		state(RouteBSigned8Depth2StageOutput, 0, defaultHex),
	}, nil
}

func routeBSigned8Depth2NodeBatchExpectedCounts(artifacts routeBSigned8Depth2NodeBatchArtifacts) RouteBSigned8Depth2NodeBatchOperationCounts {
	return RouteBSigned8Depth2NodeBatchOperationCounts{
		PublicThresholdSubtractions: 1, CompleteA2BInvocations: 1,
		BroadcastLinearTransformations: 1, BroadcastDiagonalPlaintextProducts: len(artifacts.broadcast.Vec),
		BroadcastCiphertextAdditions: max(len(artifacts.broadcast.Vec)-1, 0),
		BroadcastRotations:           len(artifacts.broadcastRotationIndexes), BroadcastKeySwitches: len(artifacts.broadcastRotationIndexes),
		BroadcastRescales: 1, GENegations: 1, GEPlaintextAdditions: 1,
		RoleMaskPlaintextProducts: 3, RoleMaskRescales: 3,
		AlignmentRotations: len(artifacts.alignmentRotationIndexes), AlignmentKeySwitches: len(artifacts.alignmentRotationIndexes),
		PathComplementNegations: 2, PathComplementPlaintextAdditions: 2,
		PathCiphertextProducts: 3, PathRelinearizations: 3, PathRescales: 3, PathCiphertextAdditions: 1,
		LeafPlaintextProducts: 3, LeafRescales: 3, LeafCiphertextAdditions: 2, BaseLeafPlaintextAdditions: 1,
		LogicalPeakLiveWrapperCiphertexts: 16,
	}
}

func newRouteBSigned8Depth2NodeBatchRangeReports(ranges [3]homchain.Signed8NoOverflowRange) (result [3]RouteBSigned8RootTreeRangeReport) {
	for index := range ranges {
		result[index] = newRouteBSigned8RootTreeRangeReport(ranges[index])
	}
	return result
}

func newRouteBSigned8Depth2NodeBatchModelReport(model RouteBSigned8Depth2NodeBatchModel) RouteBSigned8Depth2NodeBatchModelReport {
	report := RouteBSigned8Depth2NodeBatchModelReport{Thresholds: model.thresholds, Leaves: model.leaves, Digest: model.digest}
	for index, leaf := range model.leaves {
		report.LeafBits[index] = math.Float64bits(leaf)
	}
	return report
}

func reconstructRouteBSigned8Depth2NodeBatchInputs(
	rangeReports [3]RouteBSigned8RootTreeRangeReport,
	modelReport RouteBSigned8Depth2NodeBatchModelReport,
) (ranges [3]homchain.Signed8NoOverflowRange, model RouteBSigned8Depth2NodeBatchModel, err error) {
	for index, report := range rangeReports {
		ranges[index], err = homchain.NewSigned8NoOverflowRange(report.XMinimum, report.XMaximum, report.ThresholdMinimum, report.ThresholdMaximum)
		if err != nil {
			return ranges, model, err
		}
		if ranges[index].DifferenceMinimum() != report.DifferenceMinimum || ranges[index].DifferenceMaximum() != report.DifferenceMaximum || ranges[index].Digest() != report.Digest {
			return ranges, model, lineagef("signed8 depth-2 range report %d changed", index)
		}
	}
	for index, leaf := range modelReport.Leaves {
		if math.Float64bits(leaf) != modelReport.LeafBits[index] {
			return ranges, model, lineagef("signed8 depth-2 leaf bit snapshot %d changed", index)
		}
	}
	model, err = NewRouteBSigned8Depth2NodeBatchModel(modelReport.Thresholds, modelReport.Leaves)
	if err != nil {
		return ranges, model, err
	}
	if model.digest != modelReport.Digest {
		return ranges, model, lineagef("signed8 depth-2 model report changed")
	}
	return ranges, model, nil
}

func digestRouteBSigned8Depth2NodeBatchReport(report RouteBSigned8Depth2NodeBatchReport) (string, error) {
	copyReport := report
	copyReport.Digest = ""
	payload, err := json.Marshal(copyReport)
	if err != nil {
		return "", err
	}
	return routeBSigned8DigestBytes(payload), nil
}
