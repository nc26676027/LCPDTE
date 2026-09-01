package secureeval

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

const routeBSigned8SameFeatureBinaryReportSchema = "lcpdte-route-b-signed8-same-feature-binary-control-report-v1"

type RouteBSigned8SameFeatureBinaryReport struct {
	SchemaVersion               string                             `json:"schema_version"`
	Base                        RouteBSigned8Depth2NodeBatchReport `json:"base_depth2_report"`
	CommonPrefixWallNanoseconds uint64                             `json:"common_prefix_wall_nanoseconds"`
	TerminalWallNanoseconds     uint64                             `json:"terminal_wall_nanoseconds"`
	WallNanoseconds             uint64                             `json:"wall_nanoseconds"`
	Digest                      string                             `json:"digest"`
}

type RouteBSigned8SameFeatureBinaryResult struct {
	ciphertext *rlwe.Ciphertext
	digest     string
}

func (result RouteBSigned8SameFeatureBinaryResult) Ciphertext() *rlwe.Ciphertext {
	if result.ciphertext == nil {
		return nil
	}
	return result.ciphertext.CopyNew()
}

func (result RouteBSigned8SameFeatureBinaryResult) ReportDigest() string { return result.digest }

func (report RouteBSigned8SameFeatureBinaryReport) Validate() error {
	if report.SchemaVersion != routeBSigned8SameFeatureBinaryReportSchema || report.Digest == "" ||
		report.CommonPrefixWallNanoseconds == 0 || report.TerminalWallNanoseconds == 0 || report.WallNanoseconds == 0 ||
		report.WallNanoseconds < report.CommonPrefixWallNanoseconds+report.TerminalWallNanoseconds {
		return lineagef("same-feature binary-control report identity or timing changed")
	}
	if err := report.Base.Validate(); err != nil {
		return err
	}
	_, _, binaryModel, binaryRanges, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		return err
	}
	ranges, model, err := reconstructRouteBSigned8Depth2NodeBatchInputs(report.Base.Ranges, report.Base.Model)
	if err != nil {
		return err
	}
	if model.Digest() != binaryModel.Digest() {
		return lineagef("same-feature binary-control model differs from the radix-equivalent binary tree")
	}
	for index := range ranges {
		if ranges[index].Digest() != binaryRanges[index].Digest() {
			return lineagef("same-feature binary-control range %d changed", index)
		}
	}
	digest, err := digestRouteBSigned8SameFeatureBinaryReport(report)
	if err != nil || digest != report.Digest {
		return lineagef("same-feature binary-control report digest changed")
	}
	return nil
}

func (installed *RouteBInstalledEvaluator) RunSigned8SameFeatureBinaryControl(
	input *rlwe.Ciphertext,
) (result RouteBSigned8SameFeatureBinaryResult, firstOperation RouteBFirstOperationReport, report RouteBSigned8SameFeatureBinaryReport, err error) {
	_, _, model, ranges, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		return result, firstOperation, report, err
	}
	runner := func(evaluator *bootstrapping.Evaluator, ciphertext *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		output, observation, runReport, runErr := runCanonicalRouteBSigned8SameFeatureBinary(evaluator, ciphertext, ranges, model)
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
		return RouteBSigned8SameFeatureBinaryResult{}, RouteBFirstOperationReport{}, RouteBSigned8SameFeatureBinaryReport{}, err
	}
	if output == nil || report.Digest == "" {
		return RouteBSigned8SameFeatureBinaryResult{}, RouteBFirstOperationReport{}, RouteBSigned8SameFeatureBinaryReport{}, lineagef("same-feature binary control returned an incomplete result")
	}
	if err = report.Validate(); err != nil {
		return RouteBSigned8SameFeatureBinaryResult{}, RouteBFirstOperationReport{}, RouteBSigned8SameFeatureBinaryReport{}, err
	}
	return RouteBSigned8SameFeatureBinaryResult{ciphertext: output, digest: report.Digest}, firstOperation, report, nil
}

func runCanonicalRouteBSigned8SameFeatureBinary(
	evaluator *bootstrapping.Evaluator,
	input *rlwe.Ciphertext,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Depth2NodeBatchModel,
) (output *rlwe.Ciphertext, observation routeBFirstOperationObservation, report RouteBSigned8SameFeatureBinaryReport, err error) {
	started := time.Now()
	if evaluator == nil || evaluator.Evaluator == nil || input == nil {
		return nil, observation, report, lineagef("same-feature binary-control evaluator or input is nil")
	}
	_, _, expectedModel, expectedRanges, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		return nil, observation, report, err
	}
	if model.Digest() != expectedModel.Digest() {
		return nil, observation, report, lineagef("same-feature binary-control model changed")
	}
	for index := range ranges {
		if ranges[index].Digest() != expectedRanges[index].Digest() {
			return nil, observation, report, lineagef("same-feature binary-control range %d changed", index)
		}
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
		return nil, observation, report, fmt.Errorf("secureeval: same-feature binary threshold subtraction: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageDifference, difference, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	_, high, observation, fullReport, err := runCanonicalRouteBFirstSparseA2BFull(evaluator, difference)
	if err != nil {
		return nil, routeBFirstOperationObservation{}, report, fmt.Errorf("secureeval: same-feature binary complete A2B: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageHighBoolean, high, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	linear := lintrans.NewEvaluator(evaluator.Evaluator)
	broadcastRaw, err := linear.EvaluateNew(high, artifacts.broadcast)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: same-feature binary word sign broadcast: %w", err)
	}
	broadcastRawScale := params.DefaultScale().Mul(rlwe.NewScale(params.Q()[routeBSigned8Depth2NodeBatchBroadcastLevel]))
	if err = appendState(RouteBSigned8Depth2StageBroadcastRaw, broadcastRaw, broadcastRawScale); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(broadcastRaw, broadcastRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: same-feature binary broadcast rescale: %w", err)
	}
	sign := broadcastRaw
	if err = appendState(RouteBSigned8Depth2StageSign, sign, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	ge := sign.CopyNew()
	ringQ := params.RingQ().AtLevel(ge.Level())
	for index := range ge.Value {
		ringQ.Neg(ge.Value[index], ge.Value[index])
	}
	if err = evaluator.Evaluator.Add(ge, artifacts.globalOne, ge); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: same-feature binary complement word signs: %w", err)
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
			return nil, observation, report, fmt.Errorf("secureeval: same-feature binary role %d mask: %w", role, maskErr)
		}
		if err = appendState(maskStages[role][0], masked, maskRawScale); err != nil {
			return nil, observation, report, err
		}
		if err = evaluator.Evaluator.Rescale(masked, masked); err != nil {
			return nil, observation, report, fmt.Errorf("secureeval: same-feature binary role %d mask rescale: %w", role, err)
		}
		if err = appendState(maskStages[role][1], masked, params.DefaultScale()); err != nil {
			return nil, observation, report, err
		}
		selectors[role] = masked
	}
	if selectors[1], err = evaluator.Evaluator.RotateNew(selectors[1], 4); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: align same-feature binary left selector: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageLeftAligned, selectors[1], params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	if selectors[2], err = evaluator.Evaluator.RotateNew(selectors[2], 8); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: align same-feature binary right selector: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageRightAligned, selectors[2], params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	commonPrefixWall := uint64(time.Since(started).Nanoseconds())
	if commonPrefixWall == 0 {
		commonPrefixWall = 1
	}

	terminalStarted := time.Now()
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
			return nil, observation, report, fmt.Errorf("secureeval: same-feature binary path product %d: %w", index, pathErr)
		}
		if err = appendState(pathStages[index][0], path, pathRawScale); err != nil {
			return nil, observation, report, err
		}
		if err = evaluator.Evaluator.Rescale(path, path); err != nil {
			return nil, observation, report, fmt.Errorf("secureeval: same-feature binary path rescale %d: %w", index, err)
		}
		if err = appendState(pathStages[index][1], path, artifacts.pathScale); err != nil {
			return nil, observation, report, err
		}
		paths[index] = path
	}
	rootRight, err := evaluator.Evaluator.AddNew(paths[1], paths[2])
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: same-feature binary add right paths: %w", err)
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
			return nil, observation, report, fmt.Errorf("secureeval: same-feature binary leaf term %d: %w", index, termErr)
		}
		if err = appendState(leafStages[index][0], term, leafRawScale); err != nil {
			return nil, observation, report, err
		}
		if err = evaluator.Evaluator.Rescale(term, term); err != nil {
			return nil, observation, report, fmt.Errorf("secureeval: same-feature binary leaf rescale %d: %w", index, err)
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
		return nil, observation, report, fmt.Errorf("secureeval: same-feature binary combine leaf terms: %w", err)
	}
	if err = appendState(RouteBSigned8Depth2StageOutput, output, params.DefaultScale()); err != nil {
		return nil, observation, report, err
	}
	terminalWall := uint64(time.Since(terminalStarted).Nanoseconds())
	if terminalWall == 0 {
		terminalWall = 1
	}
	if !input.Equal(inputBefore) {
		return nil, observation, report, lineagef("same-feature binary control mutated its encrypted input")
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
	if wall < commonPrefixWall+terminalWall {
		wall = commonPrefixWall + terminalWall
	}
	base := RouteBSigned8Depth2NodeBatchReport{
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
	base.Digest, err = digestRouteBSigned8Depth2NodeBatchReport(base)
	if err != nil {
		return nil, observation, report, err
	}
	report = RouteBSigned8SameFeatureBinaryReport{
		SchemaVersion: routeBSigned8SameFeatureBinaryReportSchema, Base: base,
		CommonPrefixWallNanoseconds: commonPrefixWall, TerminalWallNanoseconds: terminalWall, WallNanoseconds: wall,
	}
	report.Digest, err = digestRouteBSigned8SameFeatureBinaryReport(report)
	if err != nil {
		return nil, observation, RouteBSigned8SameFeatureBinaryReport{}, err
	}
	return output, observation, report, nil
}

func digestRouteBSigned8SameFeatureBinaryReport(report RouteBSigned8SameFeatureBinaryReport) (string, error) {
	copyReport := report
	copyReport.Digest = ""
	payload, err := json.Marshal(copyReport)
	if err != nil {
		return "", err
	}
	return routeBSigned8DigestBytes(payload), nil
}

func validateRouteBSigned8SameFeatureBinaryKeys(report RouteBSigned8SameFeatureBinaryReport) error {
	if !slices.Equal(report.Base.AlignmentRotationIndexes, []int{4, 8}) {
		return lineagef("same-feature binary alignment schedule changed")
	}
	return nil
}
