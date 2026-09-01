package secureeval

import (
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/secureprofile"
	"github.com/nc26676027/LCPDTE/integer/securityparams"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
)

func TestRouteBA2BFullRejectsNilInstalledEvaluatorBeforeDispatch(t *testing.T) {
	var installed *RouteBInstalledEvaluator
	result, firstOperation, report, err := installed.RunFirstSparseA2BFull(nil)
	if !errors.Is(err, ErrRBAUTHLineage) || result.LowMSB() != nil || result.HighMSB() != nil ||
		firstOperation.RuntimeCapacity.Operation != "" || report.Digest != "" {
		t.Fatalf("nil full A2B returned result/first/report/error=%+v/%+v/%+v/%v",
			result, firstOperation, report, err)
	}
}

func TestRouteBA2BFullOracleReturnsBothLSBFirstNibblesForEveryByte(t *testing.T) {
	for word := uint64(0); word < 256; word++ {
		low, high, err := routeBA2BFullOracle(word)
		if err != nil {
			t.Fatal(err)
		}
		for bit := 0; bit < 4; bit++ {
			wantLow := float64((word >> uint(bit)) & 1)
			wantHigh := float64((word >> uint(bit+4)) & 1)
			if low[bit] != wantLow || high[bit] != wantHigh {
				t.Fatalf("word=%d bit=%d low/high=%v/%v, want %v/%v", word, bit, low[bit], high[bit], wantLow, wantHigh)
			}
		}
	}
}

func TestRouteBA2BFullSecondSTCPlanIsIndependentL3ToL1AndUsesFrozenKeys(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := deriveRouteBA2BFullSecondSTCPlan(params)
	if err != nil {
		t.Fatal(err)
	}
	if err = plan.validate(params); err != nil {
		t.Fatal(err)
	}
	if plan.rawLiteral.LevelQ != 3 || plan.effectiveLiteral.LevelQ != 3 ||
		plan.rawLiteral.LevelP != 6 || plan.effectiveLiteral.LevelP != 6 ||
		!slices.Equal(plan.rawLiteral.Levels, []int{1, 1}) ||
		!slices.Equal(plan.effectiveLiteral.Levels, []int{1, 1}) ||
		plan.rawLiteral.LevelQ-plan.rawLiteral.Depth(true) != 1 ||
		plan.effectiveLiteral.LevelQ-plan.effectiveLiteral.Depth(true) != 1 {
		t.Fatalf("second STC literal schedule changed: raw=%+v effective=%+v", plan.rawLiteral, plan.effectiveLiteral)
	}
	if plan.profile.factorCount != 2 || plan.profile.diagonalCounts != [3]uint32{63, 64} ||
		plan.profile.vectorLength != 2048 || plan.profile.expectedPolyBytes != 5_767_272 ||
		plan.profile.canonicalL11 {
		t.Fatalf("second STC factor profile changed: %+v", plan.profile)
	}
	wantGalois := secureprofile.DefaultGaoN16PackingL11CapacityShape().STCGaloisElements()
	if !slices.Equal(plan.galoisElements, wantGalois) {
		t.Fatalf("second STC key union=%v, want frozen STC union=%v", plan.galoisElements, wantGalois)
	}
	if isZeroDigest(plan.rawLiteralDigest) || isZeroDigest(plan.rawScalingDigest) ||
		isZeroDigest(plan.effectiveLiteralDigest) || isZeroDigest(plan.effectiveScalingDigest) {
		t.Fatal("second STC source identities are empty")
	}

	mutated := plan
	mutated.effectiveLiteral = rbdftCloneLiteral(plan.effectiveLiteral)
	mutated.effectiveLiteral.LevelQ++
	if err = mutated.validate(params); err == nil {
		t.Fatal("tampered second STC plan validated")
	}
	mutated = plan
	mutated.galoisElements = append([]uint64(nil), plan.galoisElements...)
	mutated.galoisElements[0]++
	if err = mutated.validate(params); err == nil {
		t.Fatal("second STC plan with a foreign key union validated")
	}

	plan.rawLiteral.Levels[0] = 99
	plan.rawLiteral.Scaling.SetInt64(99)
	fresh, err := deriveRouteBA2BFullSecondSTCPlan(params)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.rawLiteral.Levels[0] != 1 || fresh.rawLiteral.Scaling.Cmp(plan.rawLiteral.Scaling) == 0 {
		t.Fatal("second STC plan exposes aliased source literal metadata")
	}
}

func TestRouteBA2BFullReportBindsTwoRoundSerialGraph(t *testing.T) {
	report := canonicalTestRouteBA2BFullReport(t)
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	tampered := report
	tampered.States = append([]RouteBA2BFullState(nil), report.States...)
	tampered.States[20].Level++
	if err := tampered.Validate(); err == nil {
		t.Fatal("full A2B report with a retagged second STC validated")
	}
	tampered = report
	tampered.OperationCounts.Subtractions--
	if err := tampered.Validate(); err == nil {
		t.Fatal("full A2B report with a truncated serial recurrence validated")
	}
	tampered = report
	tampered.ScaleNormalizations = append([]RouteBA2BFullScaleNormalizationReport(nil), report.ScaleNormalizations...)
	tampered.ScaleNormalizations[1].MetadataOnly = false
	if err := tampered.Validate(); err == nil {
		t.Fatal("full A2B report with an unauthenticated second normalization validated")
	}
}

func canonicalTestRouteBA2BFullReport(t *testing.T) RouteBA2BFullReport {
	t.Helper()
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := deriveRouteBA2BFullSecondSTCPlan(params)
	if err != nil {
		t.Fatal(err)
	}
	secondSTC := canonicalTestRouteBA2BFullSecondSTCReport(t, plan)
	firstRound := canonicalTestRouteBA2BFirstRoundReport(t)
	_, _, iter1MaskDigest, idScaleDigest, err := newRouteBA2BFullOperands(params)
	if err != nil {
		t.Fatal(err)
	}
	stages, levels, scales, exact, err := routeBA2BFullExpectedStateLedger()
	if err != nil {
		t.Fatal(err)
	}
	states := make([]RouteBA2BFullState, len(stages))
	for index := range states {
		states[index] = RouteBA2BFullState{
			Stage: stages[index], Level: levels[index], Degree: 1,
			LogRows: 0, LogColumns: 11, ScaleHex: scales[index], ScaleExact: exact[index],
		}
	}
	drift, err := routeBA2BFirstRoundExpectedScaleLog2Drift()
	if err != nil {
		t.Fatal(err)
	}
	normalizations := make([]RouteBA2BFullScaleNormalizationReport, 2)
	for index := range normalizations {
		normalizations[index] = RouteBA2BFullScaleNormalizationReport{
			Iteration: index, SourceScaleHex: routeBA2BFirstRoundObservedScaleHex,
			TargetScaleHex: routeBA2BFirstRoundScaleHex, AbsLog2Drift: drift,
			Bound: routeBA2BFirstRoundMaxScaleLog2Drift, MetadataOnly: true,
		}
	}
	capacity, err := canonicalRouteBCapacityPlan(routeBCapacityGateA2BFull)
	if err != nil {
		t.Fatal(err)
	}
	traceDigest := make([]byte, 32)
	for index := range traceDigest {
		traceDigest[index] = byte(index + 33)
	}
	report := RouteBA2BFullReport{
		SchemaVersion: routeBA2BFullReportSchema, Claim: routeBA2BFullClaim,
		CapacityPlanDigest: capacity.Digest(), KernelProfileDigest: firstRound.KernelProfileDigest,
		ExponentialArtifactDigest: firstRound.ExponentialArtifactDigest,
		LUTTableDigest:            firstRound.LUTTableDigest,
		TransformSourceDigest:     firstRound.TransformSourceDigest,
		Iter0MaskSourceDigest:     firstRound.MaskSourceDigest,
		Iter1MaskSourceDigest:     iter1MaskDigest, IDScaleSourceDigest: idScaleDigest,
		TransformRotationIndexes:  append([]int(nil), firstRound.TransformRotationIndexes...),
		TransformGaloisElements:   append([]uint64(nil), firstRound.TransformGaloisElements...),
		LogBabyStepGiantStepRatio: firstRound.LogBabyStepGiantStepRatio,
		LowN1:                     firstRound.LowN1, HighN1: firstRound.HighN1,
		SecondSTC: secondSTC,
		SecondMR0: RouteBA2BFullMR0Report{
			TraceGap: 16, TraceRotationExponents: routeBExpectedTraceRotationExponents,
			TraceGaloisElements: routeBExpectedTraceGaloisElements,
			TraceDigest:         hex.EncodeToString(traceDigest), ModUpInputOutputAliased: true,
			CTImagNil: true, RaisedLevel: 20, OutputLevel: 17, WallNanoseconds: 1,
		},
		ScaleNormalizations: normalizations, States: states,
		KernelOperationCounts: [2]homchain.GaoA2BKernelOperationCounts{firstRound.OperationCounts, firstRound.OperationCounts},
		OperationCounts: homchain.A2BFullOperationCounts{
			SpecialB0Transforms: 1, MaskMulRescales: 2, RefreshInvocations: 2,
			KernelInvocations: 2, IDScaleMulRescales: 1, AlignmentDrops: 3,
			Subtractions: 3, ResidualRotations: 0, SharedCTSUses: 2,
		},
		WallNanoseconds: 1,
	}
	report.Digest, err = digestRouteBA2BFullReport(report)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestRouteBA2BFullSecondSTCBuilderRejectsNilBeforeConstruction(t *testing.T) {
	before := dft.SnapshotMatrixConstructionCounters()
	matrix, report, err := buildRouteBA2BFullSecondSTC(nil)
	if err == nil || len(matrix.Matrices) != 0 || report.Digest != "" || len(report.Factors) != 0 {
		t.Fatalf("nil second-STC build returned matrix/report/error=%+v/%+v/%v", matrix, report, err)
	}
	delta, err := dft.SnapshotMatrixConstructionCounters().Delta(before)
	if err != nil {
		t.Fatal(err)
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 ||
		delta.RawNumeric() != 0 || delta.ObservedStreaming() != 0 {
		t.Fatalf("nil second-STC build dispatched a constructor: %d/%d/%d/%d",
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming())
	}
}

func TestRouteBA2BFullSecondSTCReportBindsPlanFactorsAndStreamingTrace(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := deriveRouteBA2BFullSecondSTCPlan(params)
	if err != nil {
		t.Fatal(err)
	}
	report := canonicalTestRouteBA2BFullSecondSTCReport(t, plan)
	if err = report.Validate(); err != nil {
		t.Fatal(err)
	}

	tampered := report
	tampered.EffectiveLiteralDigest = report.RawLiteralDigest
	if err = tampered.Validate(); err == nil {
		t.Fatal("second STC report with a replaced effective literal identity validated")
	}
	tampered = report
	tampered.Factors = append([]RouteBA2BFullSecondSTCFactorReport(nil), report.Factors...)
	tampered.Factors[0].EncodedDigest = report.TraceDigest
	tampered.Digest, err = digestRouteBA2BFullSecondSTCReport(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err = tampered.Validate(); err == nil {
		t.Fatal("self-consistent second STC report with a foreign encoded factor validated")
	}
	tampered = report
	tampered.TraceCompletedEvents--
	if err = tampered.Validate(); err == nil {
		t.Fatal("second STC report with a truncated trace validated")
	}
}

func canonicalTestRouteBA2BFullSecondSTCReport(
	t *testing.T,
	plan routeBA2BFullSecondSTCPlan,
) RouteBA2BFullSecondSTCReport {
	t.Helper()
	factors := make([]RouteBA2BFullSecondSTCFactorReport, 2)
	for index := range factors {
		factors[index] = routeBA2BFullSecondSTCFrozenFactors[index]
	}
	report := RouteBA2BFullSecondSTCReport{
		SchemaVersion: routeBA2BFullSecondSTCReportSchema,
		Claim:         routeBA2BFullSecondSTCClaim,
		SourceLevelQ:  18, InputLevel: 3, OutputLevel: 1, LevelP: 6, LogSlots: 11,
		Levels: []int{1, 1}, TransformType: int(plan.effectiveLiteral.Type),
		Format: int(plan.effectiveLiteral.Format), GeneratorPrecisionBits: 256, EncoderPrecisionBits: 256,
		RawLiteralDigest:       hex.EncodeToString(plan.rawLiteralDigest[:]),
		RawScalingDigest:       hex.EncodeToString(plan.rawScalingDigest[:]),
		EffectiveLiteralDigest: hex.EncodeToString(plan.effectiveLiteralDigest[:]),
		EffectiveScalingDigest: hex.EncodeToString(plan.effectiveScalingDigest[:]),
		GaloisElements:         append([]uint64(nil), plan.galoisElements...),
		FactorCount:            2, FactorDiagonalCounts: []uint32{63, 64}, VectorLength: 2048,
		ExpectedPolyBytes: plan.profile.expectedPolyBytes,
		TraceStatus:       "success", TraceDigest: routeBA2BFullSecondSTCTraceDigest, TraceCompletedEvents: 13,
		TraceCleanupEvents: 0, DefaultWholeCounterDelta: 0, ExplicitWholeCounterDelta: 0,
		RawNumericCounterDelta: 0, ObservedStreamingCounterDelta: 1,
		Factors: factors,
	}
	digest, digestErr := digestRouteBA2BFullSecondSTCReport(report)
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	report.Digest = digest
	return report
}
