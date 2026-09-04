package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	commonlintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/common/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const (
	routeBSigned8RootTreeReportSchema = "lcpdte-route-b-signed8-root-tree-report-v1"
	routeBSigned8RootTreeClaim        = "lattigo_n16_l11_signed8_public_root_real_leaf_security_unverified"
	routeBSigned8RootTreeFidelity     = "functional_security_unverified"

	routeBSigned8RootTreeWords            = 512
	routeBSigned8RootTreeSlots            = 2048
	routeBSigned8RootTreeEncoderPrecision = 256
	routeBSigned8RootTreeInputLevel       = 20
	routeBSigned8RootTreeA2BHighLevel     = 5
	routeBSigned8RootTreeBooleanLevel     = 4
	routeBSigned8RootTreeSelectorLevel    = 3
	routeBSigned8RootTreeOutputLevel      = 2
	routeBSigned8RootTreeBroadcastColumn  = 3
	routeBSigned8RootTreeBroadcastLevelP  = 6
	routeBSigned8RootTreeBroadcastBSGS    = 0

	routeBSigned8RootTreeBroadcastSourceDigest   = "078fa95a6f35955ff4a8f8bbe9a10ba065e0f07ed318eb04185d09631b1bd5a2"
	routeBSigned8RootTreeBroadcastCompiledDigest = "f5ce60cc821470595ee12a6c99155bcbed29c698da29b030638f973a452e0063"
	routeBSigned8RootTreeBroadcastEncodedBytes   = uint64(25_166_272)
)

func routeBSigned8RootTreeExpectedBroadcastRotations() []int { return []int{1, 2} }
func routeBSigned8RootTreeExpectedBroadcastGalois() []uint64 { return []uint64{5, 25} }

type RouteBSigned8RootTreeRangeReport struct {
	XMinimum          int64  `json:"x_minimum"`
	XMaximum          int64  `json:"x_maximum"`
	ThresholdMinimum  int64  `json:"threshold_minimum"`
	ThresholdMaximum  int64  `json:"threshold_maximum"`
	DifferenceMinimum int64  `json:"difference_minimum"`
	DifferenceMaximum int64  `json:"difference_maximum"`
	Digest            string `json:"digest"`
}

type RouteBSigned8RootTreeModelReport struct {
	Threshold     int64   `json:"threshold"`
	LeftLeaf      float64 `json:"left_leaf"`
	RightLeaf     float64 `json:"right_leaf"`
	LeftLeafBits  uint64  `json:"left_leaf_bits"`
	RightLeafBits uint64  `json:"right_leaf_bits"`
	Digest        string  `json:"digest"`
}

type RouteBSigned8RootTreeStage string

const (
	RouteBSigned8RootTreeStageInput        RouteBSigned8RootTreeStage = "encrypted-feature"
	RouteBSigned8RootTreeStageDifference   RouteBSigned8RootTreeStage = "feature-minus-public-threshold"
	RouteBSigned8RootTreeStageHighBoolean  RouteBSigned8RootTreeStage = "complete-a2b-high-boolean-half"
	RouteBSigned8RootTreeStageBroadcastRaw RouteBSigned8RootTreeStage = "sign-column-broadcast-before-rescale"
	RouteBSigned8RootTreeStageSign         RouteBSigned8RootTreeStage = "repeated-sign"
	RouteBSigned8RootTreeStageGE           RouteBSigned8RootTreeStage = "repeated-ge-selector"
	RouteBSigned8RootTreeStageLeafRaw      RouteBSigned8RootTreeStage = "leaf-delta-product-before-rescale"
	RouteBSigned8RootTreeStageOutput       RouteBSigned8RootTreeStage = "selected-real-leaf"
)

type RouteBSigned8RootTreeState struct {
	Stage      RouteBSigned8RootTreeStage `json:"stage"`
	Level      int                        `json:"level"`
	Degree     int                        `json:"degree"`
	LogRows    int                        `json:"log_rows"`
	LogColumns int                        `json:"log_columns"`
	ScaleHex   string                     `json:"scale_hex"`
	ScaleExact bool                       `json:"scale_exact"`
	IsBatched  bool                       `json:"is_batched"`
	IsNTT      bool                       `json:"is_ntt"`
}

type RouteBSigned8RootTreeOperationCounts struct {
	PublicThresholdSubtractions        int `json:"public_threshold_subtractions"`
	CompleteA2BInvocations             int `json:"complete_a2b_invocations"`
	BroadcastLinearTransformations     int `json:"broadcast_linear_transformations"`
	BroadcastDiagonalPlaintextProducts int `json:"broadcast_diagonal_plaintext_products"`
	BroadcastCiphertextAdditions       int `json:"broadcast_ciphertext_additions"`
	BroadcastRotations                 int `json:"broadcast_rotations"`
	BroadcastKeySwitches               int `json:"broadcast_key_switches"`
	BroadcastRescales                  int `json:"broadcast_rescales"`
	CiphertextNegations                int `json:"ciphertext_negations"`
	SelectorPlaintextAdditions         int `json:"selector_plaintext_additions"`
	LeafCiphertextPlaintextProducts    int `json:"leaf_ciphertext_plaintext_products"`
	LeafRescales                       int `json:"leaf_rescales"`
	LeafPlaintextAdditions             int `json:"leaf_plaintext_additions"`
	AdditionalRelinearizations         int `json:"additional_relinearizations"`
	LogicalPeakLiveWrapperCiphertexts  int `json:"logical_peak_live_wrapper_ciphertexts"`
}

type RouteBSigned8RootTreeReport struct {
	SchemaVersion string `json:"schema_version"`
	Claim         string `json:"claim"`
	Fidelity      string `json:"fidelity"`

	CapacityPlanDigest string                           `json:"capacity_plan_digest"`
	ParameterDigest    string                           `json:"parameter_digest"`
	Range              RouteBSigned8RootTreeRangeReport `json:"range"`
	Model              RouteBSigned8RootTreeModelReport `json:"model"`

	InputPayloadDigest       string   `json:"input_payload_digest"`
	ThresholdPayloadDigest   string   `json:"threshold_payload_digest"`
	BroadcastSourceDigest    string   `json:"broadcast_source_digest"`
	BroadcastCompiledDigest  string   `json:"broadcast_compiled_digest"`
	BroadcastEncodedBytes    uint64   `json:"broadcast_encoded_bytes"`
	BroadcastRotationIndexes []int    `json:"broadcast_rotation_indexes"`
	BroadcastGaloisElements  []uint64 `json:"broadcast_galois_elements"`
	ScalarOnePayloadDigest   string   `json:"scalar_one_payload_digest"`
	LeafDeltaPayloadDigest   string   `json:"leaf_delta_payload_digest"`
	LeftLeafPayloadDigest    string   `json:"left_leaf_payload_digest"`
	OutputPayloadDigest      string   `json:"output_payload_digest"`

	FullA2B         RouteBA2BFullReport                  `json:"full_a2b"`
	States          []RouteBSigned8RootTreeState         `json:"states"`
	OperationCounts RouteBSigned8RootTreeOperationCounts `json:"operation_counts"`
	WallNanoseconds uint64                               `json:"wall_nanoseconds"`
	Digest          string                               `json:"digest"`
}

type RouteBSigned8RootTreeResult struct {
	ciphertext *rlwe.Ciphertext
	digest     string
}

func (result RouteBSigned8RootTreeResult) Ciphertext() *rlwe.Ciphertext {
	if result.ciphertext == nil {
		return nil
	}
	return result.ciphertext.CopyNew()
}

func (result RouteBSigned8RootTreeResult) ReportDigest() string { return result.digest }

type routeBSigned8RootTreeArtifacts struct {
	params                   ckks.Parameters
	threshold, scalarOne     *rlwe.Plaintext
	leafDelta, leftLeaf      *rlwe.Plaintext
	broadcast                ckkslintrans.LinearTransformation
	parameterDigest          string
	thresholdDigest          string
	scalarOneDigest          string
	leafDeltaDigest          string
	leftLeafDigest           string
	broadcastSourceDigest    string
	broadcastCompiledDigest  string
	broadcastEncodedBytes    uint64
	broadcastRotationIndexes []int
	broadcastGaloisElements  []uint64
}

func (report RouteBSigned8RootTreeReport) Validate() error {
	if report.SchemaVersion != routeBSigned8RootTreeReportSchema || report.Claim != routeBSigned8RootTreeClaim ||
		report.Fidelity != routeBSigned8RootTreeFidelity || report.WallNanoseconds == 0 || report.Digest == "" {
		return lineagef("signed8 root-tree report identity, wall time, or digest changed")
	}
	ranges, model, err := reconstructRouteBSigned8RootTreeInputs(report.Range, report.Model)
	if err != nil {
		return err
	}
	if err = validateRouteBSigned8RootTreeInputs(ranges, model); err != nil {
		return err
	}
	plan, err := canonicalRouteBCapacityPlan(routeBCapacityGateSigned8RootTree)
	if err != nil {
		return err
	}
	if report.CapacityPlanDigest != plan.Digest() {
		return lineagef("signed8 root-tree capacity plan changed")
	}
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return err
	}
	artifacts, err := newRouteBSigned8RootTreeArtifacts(params, model)
	if err != nil {
		return err
	}
	if report.ParameterDigest != artifacts.parameterDigest ||
		report.ThresholdPayloadDigest != artifacts.thresholdDigest ||
		report.BroadcastSourceDigest != artifacts.broadcastSourceDigest ||
		report.BroadcastCompiledDigest != artifacts.broadcastCompiledDigest ||
		report.BroadcastEncodedBytes != artifacts.broadcastEncodedBytes ||
		!slices.Equal(report.BroadcastRotationIndexes, artifacts.broadcastRotationIndexes) ||
		!slices.Equal(report.BroadcastGaloisElements, artifacts.broadcastGaloisElements) ||
		report.ScalarOnePayloadDigest != artifacts.scalarOneDigest ||
		report.LeafDeltaPayloadDigest != artifacts.leafDeltaDigest ||
		report.LeftLeafPayloadDigest != artifacts.leftLeafDigest {
		return lineagef("signed8 root-tree parameter, transform, key, or plaintext identity changed")
	}
	for _, value := range []string{report.InputPayloadDigest, report.OutputPayloadDigest} {
		if !routeBA2BFullIsSHA256(value) {
			return lineagef("signed8 root-tree input or output payload digest is malformed")
		}
	}
	if err = report.FullA2B.Validate(); err != nil {
		return fmt.Errorf("secureeval: validate nested signed8 root complete A2B: %w", err)
	}
	expectedStates, err := routeBSigned8RootTreeExpectedStates(params)
	if err != nil {
		return err
	}
	if !slices.Equal(report.States, expectedStates) {
		return lineagef("signed8 root-tree exact state ledger changed: got=%+v want=%+v", report.States, expectedStates)
	}
	expectedCounts := routeBSigned8RootTreeExpectedCounts(artifacts)
	if report.OperationCounts != expectedCounts {
		return lineagef("signed8 root-tree operation ledger changed")
	}
	wantDigest, err := digestRouteBSigned8RootTreeReport(report)
	if err != nil || wantDigest != report.Digest {
		return lineagef("signed8 root-tree report digest changed")
	}
	return nil
}

func (installed *RouteBInstalledEvaluator) RunSigned8RootTreePublic(
	input *rlwe.Ciphertext,
	ranges homchain.Signed8NoOverflowRange,
	model RouteBSigned8RootTreeModel,
) (
	result RouteBSigned8RootTreeResult,
	firstOperation RouteBFirstOperationReport,
	report RouteBSigned8RootTreeReport,
	err error,
) {
	if err = validateRouteBSigned8RootTreeInputs(ranges, model); err != nil {
		return result, firstOperation, report, err
	}
	runner := func(
		evaluator *bootstrapping.Evaluator,
		ciphertext *rlwe.Ciphertext,
	) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		output, observation, runReport, runErr := runCanonicalRouteBSigned8RootTree(evaluator, ciphertext, ranges, model)
		if runErr != nil {
			return nil, routeBFirstOperationObservation{}, runErr
		}
		report = runReport
		return output, observation, nil
	}
	output, firstOperation, err := installed.runFirstOperationWithHooks(
		input, routeBCapacityGateSigned8RootTree, routeBRuntimeOperationSigned8RootTree,
		validateCanonicalRouteBInstalledResident,
		validateCanonicalRouteBInstalledEvaluator,
		runner,
	)
	if err != nil {
		return RouteBSigned8RootTreeResult{}, RouteBFirstOperationReport{}, RouteBSigned8RootTreeReport{}, err
	}
	if output == nil || report.Digest == "" {
		return RouteBSigned8RootTreeResult{}, RouteBFirstOperationReport{}, RouteBSigned8RootTreeReport{}, lineagef("signed8 root-tree returned an incomplete result")
	}
	if err = report.Validate(); err != nil {
		return RouteBSigned8RootTreeResult{}, RouteBFirstOperationReport{}, RouteBSigned8RootTreeReport{}, err
	}
	return RouteBSigned8RootTreeResult{ciphertext: output, digest: report.Digest}, firstOperation, report, nil
}

func runCanonicalRouteBSigned8RootTree(
	evaluator *bootstrapping.Evaluator,
	input *rlwe.Ciphertext,
	ranges homchain.Signed8NoOverflowRange,
	model RouteBSigned8RootTreeModel,
) (
	output *rlwe.Ciphertext,
	firstObservation routeBFirstOperationObservation,
	report RouteBSigned8RootTreeReport,
	err error,
) {
	started := time.Now()
	if evaluator == nil || evaluator.Evaluator == nil || input == nil {
		return nil, firstObservation, report, lineagef("signed8 root-tree evaluator or input is nil")
	}
	if err = validateRouteBSigned8RootTreeInputs(ranges, model); err != nil {
		return nil, firstObservation, report, err
	}
	params := evaluator.BootstrappingParameters
	if err = requireRouteBSigned8RootTreeState("input", input, routeBSigned8RootTreeInputLevel, params.DefaultScale(), params); err != nil {
		return nil, firstObservation, report, err
	}
	inputDigest, err := routeBSigned8RootTreeCiphertextDigest(input)
	if err != nil {
		return nil, firstObservation, report, err
	}
	inputBefore := input.CopyNew()
	artifacts, err := newRouteBSigned8RootTreeArtifacts(params, model)
	if err != nil {
		return nil, firstObservation, report, err
	}
	if err = preflightRouteBSigned8RootTreeBroadcastKeys(evaluator.Evaluator, artifacts); err != nil {
		return nil, firstObservation, report, err
	}
	states := make([]RouteBSigned8RootTreeState, 0, 8)
	appendState := func(stage RouteBSigned8RootTreeStage, ciphertext *rlwe.Ciphertext, scale rlwe.Scale) error {
		state, stateErr := snapshotRouteBSigned8RootTreeState(stage, ciphertext, scale)
		if stateErr == nil {
			states = append(states, state)
		}
		return stateErr
	}
	if err = appendState(RouteBSigned8RootTreeStageInput, input, params.DefaultScale()); err != nil {
		return nil, firstObservation, report, err
	}
	difference, err := evaluator.Evaluator.SubNew(input, artifacts.threshold)
	if err != nil {
		return nil, firstObservation, report, fmt.Errorf("secureeval: signed8 root public-threshold subtraction: %w", err)
	}
	if err = appendState(RouteBSigned8RootTreeStageDifference, difference, params.DefaultScale()); err != nil {
		return nil, firstObservation, report, err
	}
	_, high, firstObservation, fullReport, err := runCanonicalRouteBFirstSparseA2BFull(evaluator, difference)
	if err != nil {
		return nil, routeBFirstOperationObservation{}, report, fmt.Errorf("secureeval: signed8 root complete A2B: %w", err)
	}
	if err = appendState(RouteBSigned8RootTreeStageHighBoolean, high, params.DefaultScale()); err != nil {
		return nil, firstObservation, report, err
	}
	linear := ckkslintrans.NewEvaluator(evaluator.Evaluator)
	broadcastRaw, err := linear.EvaluateNew(high, artifacts.broadcast)
	if err != nil {
		return nil, firstObservation, report, fmt.Errorf("secureeval: signed8 root broadcast sign column: %w", err)
	}
	broadcastRawScale := params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8RootTreeBooleanLevel]))
	if err = appendState(RouteBSigned8RootTreeStageBroadcastRaw, broadcastRaw, broadcastRawScale); err != nil {
		return nil, firstObservation, report, err
	}
	if err = evaluator.Evaluator.Rescale(broadcastRaw, broadcastRaw); err != nil {
		return nil, firstObservation, report, fmt.Errorf("secureeval: signed8 root rescale sign broadcast: %w", err)
	}
	sign := broadcastRaw
	if err = appendState(RouteBSigned8RootTreeStageSign, sign, params.DefaultScale()); err != nil {
		return nil, firstObservation, report, err
	}
	ge := sign.CopyNew()
	ringQ := params.RingQ().AtLevel(ge.Level())
	for index := range ge.Value {
		ringQ.Neg(ge.Value[index], ge.Value[index])
	}
	if err = evaluator.Evaluator.Add(ge, artifacts.scalarOne, ge); err != nil {
		return nil, firstObservation, report, fmt.Errorf("secureeval: signed8 root complement repeated sign: %w", err)
	}
	if err = appendState(RouteBSigned8RootTreeStageGE, ge, params.DefaultScale()); err != nil {
		return nil, firstObservation, report, err
	}
	leafRaw, err := evaluator.Evaluator.MulNew(ge, artifacts.leafDelta)
	if err != nil {
		return nil, firstObservation, report, fmt.Errorf("secureeval: signed8 root multiply leaf delta: %w", err)
	}
	leafRawScale := params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8RootTreeSelectorLevel]))
	if err = appendState(RouteBSigned8RootTreeStageLeafRaw, leafRaw, leafRawScale); err != nil {
		return nil, firstObservation, report, err
	}
	if err = evaluator.Evaluator.Rescale(leafRaw, leafRaw); err != nil {
		return nil, firstObservation, report, fmt.Errorf("secureeval: signed8 root rescale leaf product: %w", err)
	}
	if err = evaluator.Evaluator.Add(leafRaw, artifacts.leftLeaf, leafRaw); err != nil {
		return nil, firstObservation, report, fmt.Errorf("secureeval: signed8 root add left leaf: %w", err)
	}
	output = leafRaw
	if err = appendState(RouteBSigned8RootTreeStageOutput, output, params.DefaultScale()); err != nil {
		return nil, firstObservation, report, err
	}
	if !input.Equal(inputBefore) {
		return nil, firstObservation, report, lineagef("signed8 root-tree mutated its encrypted feature input")
	}
	outputDigest, err := routeBSigned8RootTreeCiphertextDigest(output)
	if err != nil {
		return nil, firstObservation, report, err
	}
	capacity, err := canonicalRouteBCapacityPlan(routeBCapacityGateSigned8RootTree)
	if err != nil {
		return nil, firstObservation, report, err
	}
	wall := uint64(time.Since(started).Nanoseconds())
	if wall == 0 {
		wall = 1
	}
	report = RouteBSigned8RootTreeReport{
		SchemaVersion: routeBSigned8RootTreeReportSchema,
		Claim:         routeBSigned8RootTreeClaim, Fidelity: routeBSigned8RootTreeFidelity,
		CapacityPlanDigest: capacity.Digest(), ParameterDigest: artifacts.parameterDigest,
		Range: newRouteBSigned8RootTreeRangeReport(ranges), Model: newRouteBSigned8RootTreeModelReport(model),
		InputPayloadDigest: inputDigest, ThresholdPayloadDigest: artifacts.thresholdDigest,
		BroadcastSourceDigest:    artifacts.broadcastSourceDigest,
		BroadcastCompiledDigest:  artifacts.broadcastCompiledDigest,
		BroadcastEncodedBytes:    artifacts.broadcastEncodedBytes,
		BroadcastRotationIndexes: append([]int(nil), artifacts.broadcastRotationIndexes...),
		BroadcastGaloisElements:  append([]uint64(nil), artifacts.broadcastGaloisElements...),
		ScalarOnePayloadDigest:   artifacts.scalarOneDigest,
		LeafDeltaPayloadDigest:   artifacts.leafDeltaDigest,
		LeftLeafPayloadDigest:    artifacts.leftLeafDigest,
		OutputPayloadDigest:      outputDigest,
		FullA2B:                  fullReport, States: states,
		OperationCounts: routeBSigned8RootTreeExpectedCounts(artifacts), WallNanoseconds: wall,
	}
	report.Digest, err = digestRouteBSigned8RootTreeReport(report)
	if err != nil {
		return nil, firstObservation, RouteBSigned8RootTreeReport{}, err
	}
	return output, firstObservation, report, nil
}

func canonicalRouteBSigned8RootTreeParameters() (ckks.Parameters, error) {
	prepared, _, err := prepareGaoN16RouteBTransportParameters()
	if err != nil {
		return ckks.Parameters{}, err
	}
	params := prepared.EffectiveParameters().BootstrappingParameters
	if err = validateGaoN16RouteBPreparedIdentity(prepared); err != nil {
		return ckks.Parameters{}, err
	}
	return params, nil
}

func newRouteBSigned8RootTreeArtifacts(params ckks.Parameters, model RouteBSigned8RootTreeModel) (routeBSigned8RootTreeArtifacts, error) {
	canonical, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, err
	}
	if !params.Equal(&canonical) || params.LogN() != 16 || params.LogDefaultScale() != 43 ||
		params.MaxLevel() != 20 || params.MaxLevelP() != routeBSigned8RootTreeBroadcastLevelP ||
		params.LevelsConsumedPerRescaling() != 1 {
		return routeBSigned8RootTreeArtifacts{}, lineagef("signed8 root-tree parameters differ from the canonical N16/L11 Route-B chain")
	}
	if err = validateRouteBSigned8RootTreeModel(model); err != nil {
		return routeBSigned8RootTreeArtifacts{}, err
	}
	encoder := ckks.NewEncoder(params, routeBSigned8RootTreeEncoderPrecision)
	thresholdValues, err := routeBSigned8ThresholdSlots(model.threshold)
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, err
	}
	threshold, err := encodeRouteBSigned8Plaintext(params, encoder, thresholdValues, routeBSigned8RootTreeInputLevel, params.DefaultScale())
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, fmt.Errorf("secureeval: encode signed8 root threshold: %w", err)
	}
	scalarOne, err := encodeRouteBSigned8Plaintext(params, encoder, routeBSigned8ConstantSlots(1), routeBSigned8RootTreeSelectorLevel, params.DefaultScale())
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, fmt.Errorf("secureeval: encode signed8 root scalar one: %w", err)
	}
	leafDelta, err := encodeRouteBSigned8Plaintext(params, encoder, routeBSigned8ConstantSlots(model.rightLeaf-model.leftLeaf), routeBSigned8RootTreeSelectorLevel, rlwe.NewScale(params.Q()[routeBSigned8RootTreeSelectorLevel]))
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, fmt.Errorf("secureeval: encode signed8 root leaf delta: %w", err)
	}
	leftLeaf, err := encodeRouteBSigned8Plaintext(params, encoder, routeBSigned8ConstantSlots(model.leftLeaf), routeBSigned8RootTreeOutputLevel, params.DefaultScale())
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, fmt.Errorf("secureeval: encode signed8 root left leaf: %w", err)
	}
	broadcast, sourceDigest, compiledDigest, encodedBytes, rotations, galois, err := newRouteBSigned8Broadcast(params, encoder)
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, err
	}
	parameterPayload, err := params.MarshalBinary()
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, err
	}
	thresholdDigest, err := routeBSigned8RootTreePlaintextDigest(threshold)
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, err
	}
	scalarOneDigest, err := routeBSigned8RootTreePlaintextDigest(scalarOne)
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, err
	}
	leafDeltaDigest, err := routeBSigned8RootTreePlaintextDigest(leafDelta)
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, err
	}
	leftLeafDigest, err := routeBSigned8RootTreePlaintextDigest(leftLeaf)
	if err != nil {
		return routeBSigned8RootTreeArtifacts{}, err
	}
	return routeBSigned8RootTreeArtifacts{
		params: params, threshold: threshold, scalarOne: scalarOne, leafDelta: leafDelta, leftLeaf: leftLeaf,
		broadcast: broadcast, parameterDigest: routeBSigned8DigestBytes(parameterPayload),
		thresholdDigest: thresholdDigest, scalarOneDigest: scalarOneDigest,
		leafDeltaDigest: leafDeltaDigest, leftLeafDigest: leftLeafDigest,
		broadcastSourceDigest: sourceDigest, broadcastCompiledDigest: compiledDigest,
		broadcastEncodedBytes:    encodedBytes,
		broadcastRotationIndexes: rotations, broadcastGaloisElements: galois,
	}, nil
}

func newRouteBSigned8Broadcast(
	params ckks.Parameters,
	encoder *ckks.Encoder,
) (
	transformation ckkslintrans.LinearTransformation,
	sourceDigest, compiledDigest string,
	encodedBytes uint64,
	rotations []int,
	galois []uint64,
	err error,
) {
	diagonals := make(ckkslintrans.Diagonals[*bignum.Complex], 4)
	for offset := 0; offset < 4; offset++ {
		values := make([]*bignum.Complex, routeBSigned8RootTreeSlots)
		for index := range values {
			values[index] = bignum.NewComplex().SetPrec(routeBSigned8RootTreeEncoderPrecision)
		}
		outputColumn := routeBSigned8RootTreeBroadcastColumn - offset
		for word := 0; word < routeBSigned8RootTreeWords; word++ {
			values[4*word+outputColumn].Real().SetInt64(1)
		}
		diagonals[offset] = values
	}
	parameters := ckkslintrans.Parameters{
		DiagonalsIndexList: []int{0, 1, 2, 3},
		LevelQ:             routeBSigned8RootTreeBooleanLevel, LevelP: routeBSigned8RootTreeBroadcastLevelP,
		Scale:                     rlwe.NewScale(params.Q()[routeBSigned8RootTreeBooleanLevel]),
		LogDimensions:             ring.Dimensions{Rows: 0, Cols: 11},
		LogBabyStepGiantStepRatio: routeBSigned8RootTreeBroadcastBSGS,
	}
	transformation = ckkslintrans.NewTransformation(params, parameters)
	if err = ckkslintrans.Encode(encoder, diagonals, transformation); err != nil {
		return transformation, "", "", 0, nil, nil, fmt.Errorf("secureeval: encode signed8 root broadcast transform: %w", err)
	}
	sourceDigest = routeBSigned8BroadcastSourceDigest()
	compiledDigest, encodedBytes, err = routeBSigned8BroadcastCompiledDigest(transformation)
	if err != nil {
		return transformation, "", "", 0, nil, nil, err
	}
	rotations = routeBSigned8BroadcastRotations(transformation)
	galois = transformation.GaloisElements(params)
	slices.Sort(galois)
	galois = slices.Compact(galois)
	galois = slices.DeleteFunc(galois, func(element uint64) bool { return element == 1 })
	if len(transformation.Vec) != 4 || len(rotations) == 0 || len(galois) != len(rotations) {
		return transformation, "", "", 0, nil, nil, lineagef(
			"signed8 root broadcast transform topology changed: vec=%d rotations=%v galois=%v N1=%d",
			len(transformation.Vec), rotations, galois, transformation.N1,
		)
	}
	if sourceDigest != routeBSigned8RootTreeBroadcastSourceDigest ||
		compiledDigest != routeBSigned8RootTreeBroadcastCompiledDigest ||
		encodedBytes != routeBSigned8RootTreeBroadcastEncodedBytes ||
		!slices.Equal(rotations, routeBSigned8RootTreeExpectedBroadcastRotations()) ||
		!slices.Equal(galois, routeBSigned8RootTreeExpectedBroadcastGalois()) {
		return transformation, "", "", 0, nil, nil, lineagef("signed8 root broadcast frozen source, compiled payload, bytes, rotations, or key subset changed")
	}
	return transformation, sourceDigest, compiledDigest, encodedBytes, rotations, galois, nil
}

func routeBSigned8BroadcastSourceDigest() string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("lcpdte-route-b-signed8-broadcast-source-v1\x00"))
	var record [20]byte
	binary.LittleEndian.PutUint32(record[0:4], routeBSigned8RootTreeWords)
	binary.LittleEndian.PutUint32(record[4:8], routeBSigned8RootTreeSlots)
	binary.LittleEndian.PutUint32(record[8:12], 4)
	binary.LittleEndian.PutUint32(record[12:16], routeBSigned8RootTreeBroadcastColumn)
	binary.LittleEndian.PutUint32(record[16:20], routeBSigned8RootTreeEncoderPrecision)
	_, _ = hasher.Write(record[:])
	for offset := uint32(0); offset < 4; offset++ {
		for word := uint32(0); word < routeBSigned8RootTreeWords; word++ {
			var entry [12]byte
			binary.LittleEndian.PutUint32(entry[0:4], offset)
			binary.LittleEndian.PutUint32(entry[4:8], 4*word+routeBSigned8RootTreeBroadcastColumn-offset)
			binary.LittleEndian.PutUint32(entry[8:12], 1)
			_, _ = hasher.Write(entry[:])
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func routeBSigned8BroadcastCompiledDigest(transformation ckkslintrans.LinearTransformation) (string, uint64, error) {
	if transformation.MetaData == nil || transformation.Vec == nil {
		return "", 0, lineagef("signed8 root broadcast compiled transform is nil")
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("lcpdte-route-b-signed8-broadcast-compiled-v1\x00"))
	scale, err := homchain.NewExactScaleSnapshot(transformation.Scale)
	if err != nil {
		return "", 0, err
	}
	_, _ = fmt.Fprintf(hasher, "Q%d/P%d/N1=%d/bsgs=%d/dims=%d,%d/scale=%s/batched=%t/ntt=%t/montgomery=%t|",
		transformation.LevelQ, transformation.LevelP, transformation.N1,
		transformation.LogBabyStepGiantStepRatio, transformation.LogDimensions.Rows,
		transformation.LogDimensions.Cols, scale.ValueHex(), transformation.IsBatched,
		transformation.IsNTT, transformation.IsMontgomery)
	keys := make([]int, 0, len(transformation.Vec))
	for key := range transformation.Vec {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	var encodedBytes uint64
	for _, key := range keys {
		var keyRecord [8]byte
		binary.LittleEndian.PutUint64(keyRecord[:], uint64(key))
		_, _ = hasher.Write(keyRecord[:])
		poly := transformation.Vec[key]
		written, writeErr := poly.WriteTo(hasher)
		if writeErr != nil || written <= 0 || written != int64(poly.BinarySize()) {
			return "", 0, lineagef("signed8 root broadcast polynomial serialization changed")
		}
		encodedBytes += uint64(written)
	}
	return hex.EncodeToString(hasher.Sum(nil)), encodedBytes, nil
}

func routeBSigned8BroadcastRotations(transformation ckkslintrans.LinearTransformation) []int {
	rotations := make([]int, 0, len(transformation.Vec))
	if transformation.N1 == 0 {
		for index := range transformation.Vec {
			if index != 0 {
				rotations = append(rotations, index)
			}
		}
	} else {
		_, babySteps, giantSteps := commonlintrans.LinearTransformation(transformation).BSGSIndex()
		rotations = append(rotations, babySteps...)
		rotations = append(rotations, giantSteps...)
	}
	sort.Ints(rotations)
	result := rotations[:0]
	for _, rotation := range rotations {
		if rotation != 0 && (len(result) == 0 || result[len(result)-1] != rotation) {
			result = append(result, rotation)
		}
	}
	return result
}

func preflightRouteBSigned8RootTreeBroadcastKeys(evaluator *ckks.Evaluator, artifacts routeBSigned8RootTreeArtifacts) error {
	if evaluator == nil || evaluator.EvaluationKeySet == nil {
		return lineagef("signed8 root broadcast evaluator is nil")
	}
	keySet := evaluator.EvaluationKeySet
	installed := keySet.GetGaloisKeysList()
	slices.Sort(installed)
	for _, element := range artifacts.broadcastGaloisElements {
		if _, present := slices.BinarySearch(installed, element); !present {
			return lineagef("signed8 root broadcast Galois element %d is outside the installed key union", element)
		}
		key, err := keySet.GetGaloisKey(element)
		if err != nil || key == nil || key.GaloisElement != element ||
			key.LevelQ() < routeBSigned8RootTreeBooleanLevel || key.LevelP() < routeBSigned8RootTreeBroadcastLevelP {
			return lineagef("signed8 root broadcast Galois key %d is absent or has insufficient levels", element)
		}
	}
	return nil
}

func routeBSigned8ThresholdSlots(threshold int64) ([]*bignum.Complex, error) {
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8RootTreeEncoderPrecision)
	if err != nil {
		return nil, err
	}
	block, err := ringZ.ToRootSlots(ringZ.ArithmeticEncode(uint64(uint8(threshold))))
	if err != nil {
		return nil, err
	}
	values := make([]*bignum.Complex, 0, routeBSigned8RootTreeSlots)
	for word := 0; word < routeBSigned8RootTreeWords; word++ {
		for _, value := range block {
			values = append(values, value.Clone())
		}
	}
	return values, nil
}

func routeBSigned8ConstantSlots(value float64) []*bignum.Complex {
	values := make([]*bignum.Complex, routeBSigned8RootTreeSlots)
	for index := range values {
		values[index] = bignum.NewComplex().SetPrec(routeBSigned8RootTreeEncoderPrecision)
		values[index].Real().SetFloat64(value)
	}
	return values
}

func encodeRouteBSigned8Plaintext(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	values []*bignum.Complex,
	level int,
	scale rlwe.Scale,
) (*rlwe.Plaintext, error) {
	if len(values) != routeBSigned8RootTreeSlots {
		return nil, lineagef("signed8 root plaintext vector has %d slots, want %d", len(values), routeBSigned8RootTreeSlots)
	}
	plaintext := ckks.NewPlaintext(params, level)
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	plaintext.Scale = scale
	if err := encoder.Encode(values, plaintext); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func requireRouteBSigned8RootTreeState(name string, ciphertext *rlwe.Ciphertext, level int, scale rlwe.Scale, params ckks.Parameters) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level || ciphertext.Degree() != 1 ||
		ciphertext.LogN() != 16 || ciphertext.LogDimensions != (ring.Dimensions{Rows: 0, Cols: 11}) ||
		!ciphertext.IsBatched || !ciphertext.IsNTT || !rbdftEqualScaleExact(ciphertext.Scale, scale) ||
		ciphertext.Value[0].N() != params.N() || ciphertext.Value[1].N() != params.N() {
		return lineagef("signed8 root-tree %s is not canonical L%d/degree1/L11/exact-scale", name, level)
	}
	return nil
}

func snapshotRouteBSigned8RootTreeState(stage RouteBSigned8RootTreeStage, ciphertext *rlwe.Ciphertext, expectedScale rlwe.Scale) (RouteBSigned8RootTreeState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return RouteBSigned8RootTreeState{}, lineagef("cannot snapshot nil signed8 root-tree %s", stage)
	}
	scale, err := homchain.NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return RouteBSigned8RootTreeState{}, err
	}
	return RouteBSigned8RootTreeState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogRows: ciphertext.LogDimensions.Rows, LogColumns: ciphertext.LogDimensions.Cols,
		ScaleHex: scale.ValueHex(), ScaleExact: rbdftEqualScaleExact(ciphertext.Scale, expectedScale),
		IsBatched: ciphertext.IsBatched, IsNTT: ciphertext.IsNTT,
	}, nil
}

func routeBSigned8RootTreeExpectedStates(params ckks.Parameters) ([]RouteBSigned8RootTreeState, error) {
	defaultScale, err := homchain.NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil, err
	}
	broadcastScale, err := homchain.NewExactScaleSnapshot(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8RootTreeBooleanLevel])))
	if err != nil {
		return nil, err
	}
	leafScale, err := homchain.NewExactScaleSnapshot(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8RootTreeSelectorLevel])))
	if err != nil {
		return nil, err
	}
	state := func(stage RouteBSigned8RootTreeStage, level int, scale string) RouteBSigned8RootTreeState {
		return RouteBSigned8RootTreeState{Stage: stage, Level: level, Degree: 1, LogRows: 0, LogColumns: 11, ScaleHex: scale, ScaleExact: true, IsBatched: true, IsNTT: true}
	}
	return []RouteBSigned8RootTreeState{
		state(RouteBSigned8RootTreeStageInput, 20, defaultScale.ValueHex()),
		state(RouteBSigned8RootTreeStageDifference, 20, defaultScale.ValueHex()),
		state(RouteBSigned8RootTreeStageHighBoolean, routeBSigned8RootTreeA2BHighLevel, defaultScale.ValueHex()),
		state(RouteBSigned8RootTreeStageBroadcastRaw, 4, broadcastScale.ValueHex()),
		state(RouteBSigned8RootTreeStageSign, 3, defaultScale.ValueHex()),
		state(RouteBSigned8RootTreeStageGE, 3, defaultScale.ValueHex()),
		state(RouteBSigned8RootTreeStageLeafRaw, 3, leafScale.ValueHex()),
		state(RouteBSigned8RootTreeStageOutput, 2, defaultScale.ValueHex()),
	}, nil
}

func routeBSigned8RootTreeExpectedCounts(artifacts routeBSigned8RootTreeArtifacts) RouteBSigned8RootTreeOperationCounts {
	return RouteBSigned8RootTreeOperationCounts{
		PublicThresholdSubtractions: 1, CompleteA2BInvocations: 1,
		BroadcastLinearTransformations:     1,
		BroadcastDiagonalPlaintextProducts: len(artifacts.broadcast.Vec),
		BroadcastCiphertextAdditions:       max(len(artifacts.broadcast.Vec)-1, 0),
		BroadcastRotations:                 len(artifacts.broadcastRotationIndexes),
		BroadcastKeySwitches:               len(artifacts.broadcastRotationIndexes), BroadcastRescales: 1,
		CiphertextNegations: 1, SelectorPlaintextAdditions: 1,
		LeafCiphertextPlaintextProducts: 1, LeafRescales: 1, LeafPlaintextAdditions: 1,
		AdditionalRelinearizations: 0, LogicalPeakLiveWrapperCiphertexts: 5,
	}
}

func newRouteBSigned8RootTreeRangeReport(ranges homchain.Signed8NoOverflowRange) RouteBSigned8RootTreeRangeReport {
	return RouteBSigned8RootTreeRangeReport{
		XMinimum: ranges.XMinimum(), XMaximum: ranges.XMaximum(),
		ThresholdMinimum: ranges.ThresholdMinimum(), ThresholdMaximum: ranges.ThresholdMaximum(),
		DifferenceMinimum: ranges.DifferenceMinimum(), DifferenceMaximum: ranges.DifferenceMaximum(),
		Digest: ranges.Digest(),
	}
}

func newRouteBSigned8RootTreeModelReport(model RouteBSigned8RootTreeModel) RouteBSigned8RootTreeModelReport {
	return RouteBSigned8RootTreeModelReport{
		Threshold: model.threshold, LeftLeaf: model.leftLeaf, RightLeaf: model.rightLeaf,
		LeftLeafBits: math.Float64bits(model.leftLeaf), RightLeafBits: math.Float64bits(model.rightLeaf),
		Digest: model.digest,
	}
}

func reconstructRouteBSigned8RootTreeInputs(
	rangeReport RouteBSigned8RootTreeRangeReport,
	modelReport RouteBSigned8RootTreeModelReport,
) (homchain.Signed8NoOverflowRange, RouteBSigned8RootTreeModel, error) {
	ranges, err := homchain.NewSigned8NoOverflowRange(
		rangeReport.XMinimum, rangeReport.XMaximum, rangeReport.ThresholdMinimum, rangeReport.ThresholdMaximum,
	)
	if err != nil {
		return homchain.Signed8NoOverflowRange{}, RouteBSigned8RootTreeModel{}, err
	}
	if ranges.DifferenceMinimum() != rangeReport.DifferenceMinimum || ranges.DifferenceMaximum() != rangeReport.DifferenceMaximum ||
		ranges.Digest() != rangeReport.Digest {
		return homchain.Signed8NoOverflowRange{}, RouteBSigned8RootTreeModel{}, lineagef("signed8 root-tree range report changed")
	}
	if math.Float64bits(modelReport.LeftLeaf) != modelReport.LeftLeafBits ||
		math.Float64bits(modelReport.RightLeaf) != modelReport.RightLeafBits {
		return homchain.Signed8NoOverflowRange{}, RouteBSigned8RootTreeModel{}, lineagef("signed8 root-tree model bit snapshot changed")
	}
	model, err := NewRouteBSigned8RootTreeModel(modelReport.Threshold, modelReport.LeftLeaf, modelReport.RightLeaf)
	if err != nil {
		return homchain.Signed8NoOverflowRange{}, RouteBSigned8RootTreeModel{}, err
	}
	if model.Digest() != modelReport.Digest {
		return homchain.Signed8NoOverflowRange{}, RouteBSigned8RootTreeModel{}, lineagef("signed8 root-tree model report changed")
	}
	return ranges, model, nil
}

func routeBSigned8RootTreePlaintextDigest(plaintext *rlwe.Plaintext) (string, error) {
	if plaintext == nil {
		return "", lineagef("cannot digest nil signed8 root plaintext")
	}
	payload, err := plaintext.MarshalBinary()
	if err != nil {
		return "", err
	}
	return routeBSigned8DigestBytes(payload), nil
}

func routeBSigned8RootTreeCiphertextDigest(ciphertext *rlwe.Ciphertext) (string, error) {
	if ciphertext == nil {
		return "", lineagef("cannot digest nil signed8 root ciphertext")
	}
	payload, err := ciphertext.MarshalBinary()
	if err != nil {
		return "", err
	}
	return routeBSigned8DigestBytes(payload), nil
}

func digestRouteBSigned8RootTreeReport(report RouteBSigned8RootTreeReport) (string, error) {
	copyReport := report
	copyReport.Digest = ""
	payload, err := json.Marshal(copyReport)
	if err != nil {
		return "", err
	}
	return routeBSigned8DigestBytes(payload), nil
}

func routeBSigned8DigestBytes(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
