package secureeval

import (
	"fmt"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func runCanonicalRouteBSigned8Depth2SelectedChild(
	evaluator *bootstrapping.Evaluator,
	input RouteBSigned8Depth2SelectedChildFeatures,
	ranges [3]homchain.Signed8NoOverflowRange,
	model RouteBSigned8Depth2SelectedChildModel,
) (
	output *rlwe.Ciphertext,
	observation routeBFirstOperationObservation,
	report RouteBSigned8Depth2SelectedChildReport,
	err error,
) {
	started := time.Now()
	if evaluator == nil || evaluator.Evaluator == nil || evaluator.DFTEvaluator == nil {
		return nil, observation, report, lineagef("selected-child evaluator graph is incomplete")
	}
	if err = validateRouteBSigned8Depth2SelectedChildRanges(ranges, model); err != nil {
		return nil, observation, report, err
	}
	if err = validateRouteBSigned8Depth2SelectedChildFeatures(model, input); err != nil {
		return nil, observation, report, err
	}
	params := evaluator.BootstrappingParameters
	defaultScale := params.DefaultScale()
	inputBefore := [3]*rlwe.Ciphertext{
		input.features[0].CopyNew(), input.features[1].CopyNew(), input.features[2].CopyNew(),
	}
	states := make([]RouteBSigned8Depth2SelectedChildState, 0, 32)
	appendState := func(stage string, value *rlwe.Ciphertext, level int, scale rlwe.Scale) error {
		state, stateErr := snapshotRouteBSigned8Depth2SelectedChildState(stage, value, level, scale)
		if stateErr == nil {
			states = append(states, state)
		}
		return stateErr
	}
	for role, name := range []string{"root-feature", "left-feature", "right-feature"} {
		if err = appendState(name, input.features[role], 20, defaultScale); err != nil {
			return nil, observation, report, err
		}
	}
	rootArtifacts, err := newRouteBSigned8Depth2SelectedChildRootArtifacts(params, model)
	if err != nil {
		return nil, observation, report, err
	}
	rootDifference, err := evaluator.Evaluator.SubNew(input.features[0], rootArtifacts.threshold)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child root threshold subtraction: %w", err)
	}
	if err = appendState("root-feature-minus-threshold", rootDifference, 20, defaultScale); err != nil {
		return nil, observation, report, err
	}
	_, rootHigh, observation, rootFullA2B, err := runCanonicalRouteBFirstSparseA2BFull(evaluator, rootDifference)
	if err != nil {
		return nil, routeBFirstOperationObservation{}, report, fmt.Errorf("secureeval: selected-child root complete A2B: %w", err)
	}
	if err = appendState("root-high-msb", rootHigh, 5, defaultScale); err != nil {
		return nil, observation, report, err
	}
	// The complete root converter's large supplemental circuit is now dead;
	// reclaim it before constructing the independently authenticated shared
	// L3->L1 STC used by the phase decoder and low-ingress A2Sign.
	releaseRouteBTransientHeap()
	artifacts, err := newRouteBSigned8Depth2SelectedChildArtifacts(evaluator, model)
	if err != nil {
		return nil, observation, report, err
	}
	linear := lintrans.NewEvaluator(evaluator.Evaluator)
	phaseRaw, err := linear.EvaluateNew(rootHigh, artifacts.phaseBroadcast)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child phase-weighted root broadcast: %w", err)
	}
	phaseRawScale := defaultScale.Mul(rlwe.NewScale(params.Q()[4]))
	if err = appendState("root-phase-broadcast-raw", phaseRaw, 4, phaseRawScale); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(phaseRaw, phaseRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child root phase broadcast rescale: %w", err)
	}
	phase := phaseRaw
	if err = appendState("root-phase", phase, 3, defaultScale); err != nil {
		return nil, observation, report, err
	}
	phaseSTC, err := evaluator.DFTEvaluator.SlotsToCoeffsNew(phase, nil, artifacts.a2sign.secondSTC)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child root phase STC: %w", err)
	}
	if err = appendState("root-phase-stc", phaseSTC, 1, defaultScale); err != nil {
		return nil, observation, report, err
	}
	phaseRefreshed, phaseObservation, err := runCanonicalRouteBFirstSparseMR0(evaluator, phaseSTC)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child root phase MR0: %w", err)
	}
	if _, err = normalizeRouteBA2BFirstRoundKernelScale(phaseRefreshed, defaultScale); err != nil {
		return nil, observation, report, err
	}
	if err = appendState("root-phase-mr0-normalized", phaseRefreshed, 17, defaultScale); err != nil {
		return nil, observation, report, err
	}
	periodicEvaluator, err := bindRouteBGaoPeriodicBooleanN16L11(artifacts.periodic, evaluator)
	if err != nil {
		return nil, observation, report, err
	}
	periodicResult, err := periodicEvaluator.EvaluateNew(phaseRefreshed)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child periodic root selector: %w", err)
	}
	rootSign := periodicResult.Ciphertext()
	if err = appendState("root-periodic-sign", rootSign, 8, artifacts.scalePlan.rootBooleanScale); err != nil {
		return nil, observation, report, err
	}
	periodicReport, err := newRouteBSigned8Depth2SelectedChildPeriodicReport(artifacts.periodic, periodicResult)
	if err != nil {
		return nil, observation, report, err
	}
	conditionedRaw, err := evaluator.Evaluator.MulNew(rootSign, artifacts.conditioner)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child root selector conditioner: %w", err)
	}
	conditionedRawScale := artifacts.scalePlan.rootBooleanScale.Mul(artifacts.scalePlan.conditionerScale)
	if err = appendState("root-selector-conditioned-raw", conditionedRaw, 8, conditionedRawScale); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(conditionedRaw, conditionedRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child root selector conditioner rescale: %w", err)
	}
	conditionedSign := conditionedRaw
	if err = appendState("root-sign-conditioned", conditionedSign, 7, artifacts.scalePlan.conditionedRootScale); err != nil {
		return nil, observation, report, err
	}
	conditionedRoot := conditionedSign.CopyNew()
	params.RingQ().AtLevel(conditionedRoot.Level()).Neg(conditionedRoot.Value[0], conditionedRoot.Value[0])
	params.RingQ().AtLevel(conditionedRoot.Level()).Neg(conditionedRoot.Value[1], conditionedRoot.Value[1])
	if err = evaluator.Evaluator.Add(conditionedRoot, artifacts.rootOne, conditionedRoot); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child root sign complement: %w", err)
	}
	if err = appendState("root-ge-selector", conditionedRoot, 7, artifacts.scalePlan.conditionedRootScale); err != nil {
		return nil, observation, report, err
	}
	leftFeature := input.features[1].CopyNew()
	rightFeature := input.features[2].CopyNew()
	evaluator.Evaluator.DropLevel(leftFeature, leftFeature.Level()-7)
	evaluator.Evaluator.DropLevel(rightFeature, rightFeature.Level()-7)
	featureDelta, err := evaluator.Evaluator.SubNew(rightFeature, leftFeature)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child encrypted feature delta: %w", err)
	}
	if err = appendState("right-minus-left-feature", featureDelta, 7, defaultScale); err != nil {
		return nil, observation, report, err
	}
	selectedFeatureRaw, err := evaluator.Evaluator.MulRelinNew(conditionedRoot, featureDelta)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child encrypted feature selection: %w", err)
	}
	selectedRawScale := artifacts.scalePlan.conditionedRootScale.Mul(defaultScale)
	if err = appendState("selected-feature-raw", selectedFeatureRaw, 7, selectedRawScale); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(selectedFeatureRaw, selectedFeatureRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child encrypted feature selection rescale: %w", err)
	}
	evaluator.Evaluator.DropLevel(leftFeature, 1)
	if err = evaluator.Evaluator.Add(selectedFeatureRaw, leftFeature, selectedFeatureRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child encrypted feature base add: %w", err)
	}
	selectedFeature := selectedFeatureRaw
	if err = appendState("selected-child-feature", selectedFeature, 6, defaultScale); err != nil {
		return nil, observation, report, err
	}
	selectedThresholdRaw, err := evaluator.Evaluator.MulNew(conditionedRoot, artifacts.thresholdDelta)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child public threshold selection: %w", err)
	}
	if err = appendState("selected-threshold-raw", selectedThresholdRaw, 7, selectedRawScale); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(selectedThresholdRaw, selectedThresholdRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child public threshold selection rescale: %w", err)
	}
	if err = evaluator.Evaluator.Add(selectedThresholdRaw, artifacts.leftThreshold, selectedThresholdRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child public threshold base add: %w", err)
	}
	selectedThreshold := selectedThresholdRaw
	if err = appendState("selected-child-threshold", selectedThreshold, 6, defaultScale); err != nil {
		return nil, observation, report, err
	}
	childDifference, err := evaluator.Evaluator.SubNew(selectedFeature, selectedThreshold)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child comparator subtraction: %w", err)
	}
	if err = appendState("selected-child-difference", childDifference, 6, defaultScale); err != nil {
		return nil, observation, report, err
	}
	childHigh, childA2SignReport, err := runRouteBSigned8Depth2SelectedChildA2Sign(evaluator, artifacts.a2sign, childDifference)
	if err != nil {
		return nil, observation, report, err
	}
	if err = appendState("selected-child-high-msb", childHigh, 5, defaultScale); err != nil {
		return nil, observation, report, err
	}
	childSignRaw, err := linear.EvaluateNew(childHigh, artifacts.childBroadcast)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child sign broadcast: %w", err)
	}
	childSignRawScale := defaultScale.Mul(rlwe.NewScale(params.Q()[4]))
	if err = appendState("selected-child-sign-broadcast-raw", childSignRaw, 4, childSignRawScale); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(childSignRaw, childSignRaw); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child sign broadcast rescale: %w", err)
	}
	childGE := childSignRaw.CopyNew()
	params.RingQ().AtLevel(childGE.Level()).Neg(childGE.Value[0], childGE.Value[0])
	params.RingQ().AtLevel(childGE.Level()).Neg(childGE.Value[1], childGE.Value[1])
	if err = evaluator.Evaluator.Add(childGE, artifacts.childOne, childGE); err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child sign complement: %w", err)
	}
	if err = appendState("selected-child-ge", childGE, 3, defaultScale); err != nil {
		return nil, observation, report, err
	}
	rootTerminal := conditionedRoot.CopyNew()
	evaluator.Evaluator.DropLevel(rootTerminal, rootTerminal.Level()-3)
	if err = appendState("root-terminal-selector", rootTerminal, 3, artifacts.scalePlan.conditionedRootScale); err != nil {
		return nil, observation, report, err
	}
	productRaw, err := evaluator.Evaluator.MulRelinNew(rootTerminal, childGE)
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child terminal root-child product: %w", err)
	}
	if err = appendState("terminal-root-child-raw", productRaw, 3, artifacts.scalePlan.terminalProductScale); err != nil {
		return nil, observation, report, err
	}
	alphaRaw, err := evaluator.Evaluator.MulNew(rootTerminal, artifacts.alphaLeaf)
	if err != nil {
		return nil, observation, report, err
	}
	if err = appendState("terminal-alpha-raw", alphaRaw, 3, artifacts.scalePlan.conditionedRootScale.Mul(artifacts.scalePlan.alphaOperandScale)); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(alphaRaw, alphaRaw); err != nil {
		return nil, observation, report, err
	}
	if err = appendState("terminal-alpha", alphaRaw, 2, artifacts.scalePlan.terminalOutputScale); err != nil {
		return nil, observation, report, err
	}
	betaRaw, err := evaluator.Evaluator.MulNew(childGE, artifacts.betaLeaf)
	if err != nil {
		return nil, observation, report, err
	}
	if err = appendState("terminal-beta-raw", betaRaw, 3, defaultScale.Mul(artifacts.scalePlan.betaOperandScale)); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(betaRaw, betaRaw); err != nil {
		return nil, observation, report, err
	}
	if err = appendState("terminal-beta", betaRaw, 2, artifacts.scalePlan.terminalOutputScale); err != nil {
		return nil, observation, report, err
	}
	gammaRaw, err := evaluator.Evaluator.MulNew(productRaw, artifacts.gammaLeaf)
	if err != nil {
		return nil, observation, report, err
	}
	if err = appendState("terminal-gamma-raw", gammaRaw, 3, artifacts.scalePlan.terminalProductScale.Mul(artifacts.scalePlan.gammaOperandScale)); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(gammaRaw, gammaRaw); err != nil {
		return nil, observation, report, err
	}
	if err = appendState("terminal-gamma-after-q3", gammaRaw, 2, artifacts.scalePlan.terminalOutputScale.Mul(rlwe.NewScale(params.Q()[2]))); err != nil {
		return nil, observation, report, err
	}
	if err = evaluator.Evaluator.Rescale(gammaRaw, gammaRaw); err != nil {
		return nil, observation, report, err
	}
	if err = appendState("terminal-gamma", gammaRaw, 1, artifacts.scalePlan.terminalOutputScale); err != nil {
		return nil, observation, report, err
	}
	evaluator.Evaluator.DropLevel(alphaRaw, 1)
	evaluator.Evaluator.DropLevel(betaRaw, 1)
	output, err = evaluator.Evaluator.AddNew(alphaRaw, betaRaw)
	if err == nil {
		err = evaluator.Evaluator.Add(output, gammaRaw, output)
	}
	if err == nil {
		err = evaluator.Evaluator.Add(output, artifacts.baseLeaf, output)
	}
	if err != nil {
		return nil, observation, report, fmt.Errorf("secureeval: selected-child terminal leaf combination: %w", err)
	}
	if err = appendState("selected-leaf-output", output, 1, artifacts.scalePlan.terminalOutputScale); err != nil {
		return nil, observation, report, err
	}
	for index := range input.features {
		if !input.features[index].Equal(inputBefore[index]) {
			return nil, observation, report, lineagef("selected-child evaluation mutated encrypted feature %d", index)
		}
	}
	outputDigest, err := routeBSigned8RootTreeCiphertextDigest(output)
	if err != nil {
		return nil, observation, report, err
	}
	phaseMR0, err := newRouteBA2BFullMR0Report(phaseObservation)
	if err != nil {
		return nil, observation, report, err
	}
	capacity, err := canonicalRouteBCapacityPlan(routeBCapacityGateSigned8Depth2SelectedChild)
	if err != nil {
		return nil, observation, report, err
	}
	scaleReport, err := newRouteBSigned8Depth2SelectedChildScaleReport(artifacts.scalePlan)
	if err != nil {
		return nil, observation, report, err
	}
	report = RouteBSigned8Depth2SelectedChildReport{
		SchemaVersion: routeBSigned8Depth2SelectedChildReportSchema,
		Claim:         routeBSigned8Depth2SelectedChildClaim, Fidelity: routeBSigned8Depth2SelectedChildFidelity,
		CapacityPlanDigest: capacity.Digest(), ParameterDigest: rootArtifacts.parameterDigest,
		FeatureBindingDigest: input.digest, FeaturePayloadDigests: input.payloadDigests,
		Ranges: [3]RouteBSigned8RootTreeRangeReport{
			newRouteBSigned8RootTreeRangeReport(ranges[0]), newRouteBSigned8RootTreeRangeReport(ranges[1]),
			newRouteBSigned8RootTreeRangeReport(ranges[2]),
		},
		Model: newRouteBSigned8Depth2SelectedChildModelReport(model), ScalePlan: scaleReport,
		RootThresholdDigest:           rootArtifacts.thresholdDigest,
		PhaseBroadcastSourceDigest:    artifacts.phaseBroadcastSourceDigest,
		PhaseBroadcastCompiledDigest:  artifacts.phaseBroadcastCompiledDigest,
		PhaseBroadcastEncodedBytes:    artifacts.phaseBroadcastEncodedBytes,
		PhaseBroadcastRotationIndexes: append([]int(nil), artifacts.phaseBroadcastRotationIndexes...),
		PhaseBroadcastGaloisElements:  append([]uint64(nil), artifacts.phaseBroadcastGaloisElements...),
		ConditionerDigest:             artifacts.conditionerDigest, RootOneDigest: artifacts.rootOneDigest,
		ThresholdDeltaDigest:         artifacts.thresholdDeltaDigest,
		LeftThresholdDigest:          artifacts.leftThresholdDigest,
		ChildBroadcastSourceDigest:   artifacts.childBroadcastSourceDigest,
		ChildBroadcastCompiledDigest: artifacts.childBroadcastCompiledDigest,
		ChildBroadcastEncodedBytes:   artifacts.childBroadcastEncodedBytes,
		ChildOneDigest:               artifacts.childOneDigest, TerminalOperandDigests: artifacts.terminalOperandDigests,
		RootFullA2B: rootFullA2B, SupplementalSecondSTC: artifacts.a2sign.secondSTCReport,
		PhaseMR0: phaseMR0, RootPeriodic: periodicReport, ChildA2Sign: childA2SignReport,
		States: states, OperationCounts: routeBSigned8Depth2SelectedChildExpectedCounts(),
		OutputPayloadDigest: outputDigest, WallNanoseconds: selectedChildNonzeroWall(started),
	}
	report.Digest = digestRouteBSigned8Depth2SelectedChildReport(report)
	if err = report.Validate(); err != nil {
		return nil, observation, RouteBSigned8Depth2SelectedChildReport{}, err
	}
	return output, observation, report, nil
}
