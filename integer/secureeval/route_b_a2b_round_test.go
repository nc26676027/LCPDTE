package secureeval

import (
	"math/big"
	"slices"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/secureprofile"
	"github.com/nc26676027/LCPDTE/integer/securityparams"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestRouteBA2BFirstRoundTransformPlanFitsFrozenKeyInventory(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := deriveRouteBA2BFirstRoundTransformPlan(params)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.rotationIndexes, []int{1, 2, 3, 2044}) ||
		!slices.Equal(plan.galoisElements, []uint64{5, 25, 125, 89745, 131071}) ||
		plan.lowN1 != 4 || plan.highN1 != 4 {
		t.Fatalf("derived plan rotations=%v galois=%v n1=%d/%d", plan.rotationIndexes, plan.galoisElements, plan.lowN1, plan.highN1)
	}
	frozen := secureprofile.DefaultGaoN16PackingL11CapacityShape().EvaluationGaloisElements()
	for _, element := range plan.galoisElements {
		if _, present := slices.BinarySearch(frozen, element); !present {
			t.Fatalf("special-b0 key %d is outside the frozen 38-key inventory %v", element, frozen)
		}
	}
}

func TestRouteBA2BFirstRoundNormalizesOnlyCertifiedScaleMetadataDrift(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := big.ParseFloat(routeBA2BFirstRoundObservedScaleHex, 0, 256, big.ToNearestEven)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := ckks.NewCiphertext(params, 1, 17)
	ciphertext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	ciphertext.Scale = rlwe.NewScale(source)
	before := ciphertext.CopyNew()
	evidence, err := normalizeRouteBA2BFirstRoundKernelScale(ciphertext, params.DefaultScale())
	if err != nil {
		t.Fatal(err)
	}
	if evidence.SourceScaleHex != routeBA2BFirstRoundObservedScaleHex ||
		evidence.TargetScaleHex != routeBA2BFirstRoundScaleHex ||
		evidence.AbsLog2Drift <= 0 || evidence.AbsLog2Drift > routeBA2BFirstRoundMaxScaleLog2Drift ||
		!evidence.MetadataOnly || !ciphertext.Scale.Equal(params.DefaultScale()) {
		t.Fatalf("scale-normalization evidence changed: %+v", evidence)
	}
	before.Scale = params.DefaultScale()
	if !ciphertext.MetaData.Equal(before.MetaData) {
		t.Fatal("scale normalization changed non-scale metadata")
	}
	for index := range ciphertext.Value {
		if !ciphertext.Value[index].Equal(&before.Value[index]) {
			t.Fatalf("scale normalization changed ciphertext component %d", index)
		}
	}

	outside := before.CopyNew()
	outside.Scale = params.DefaultScale().Mul(rlwe.NewScale(1.001))
	outsideBefore := outside.CopyNew()
	if _, err = normalizeRouteBA2BFirstRoundKernelScale(outside, params.DefaultScale()); err == nil {
		t.Fatal("scale normalization accepted drift outside the registered bound")
	}
	if !outside.Equal(outsideBefore) {
		t.Fatal("rejected scale normalization mutated its ciphertext")
	}
	nearby := before.CopyNew()
	nearby.Scale = params.DefaultScale().Mul(rlwe.NewScale(1 + 1e-14))
	nearbyBefore := nearby.CopyNew()
	if _, err = normalizeRouteBA2BFirstRoundKernelScale(nearby, params.DefaultScale()); err == nil {
		t.Fatal("scale normalization accepted an unregistered source inside the numeric bound")
	}
	if !nearby.Equal(nearbyBefore) {
		t.Fatal("rejected unregistered scale normalization mutated its ciphertext")
	}
}

func TestRouteBA2BFirstRoundRebindsOnlyTheInstalledMemKeyView(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := rlwe.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	mem := rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeyNew(params.GaloisElementForComplexConjugation(), secretKey),
	)
	keys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: mem}
	inner := ckks.NewEvaluator(params, keys)
	boot := &bootstrapping.Evaluator{Evaluator: inner, EvaluationKeys: keys}
	circuit, err := homchain.NewGaoA2BKernelN16L11Circuit(params, ckks.NewEncoder(params, 256))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := bindRouteBA2BFirstRoundKernel(circuit, boot)
	if err != nil {
		t.Fatal(err)
	}
	if bound == nil || bound.OperationalEncoderPrecision() != 256 ||
		inner.EvaluationKeySet != keys || keys.MemEvaluationKeySet != mem {
		t.Fatal("Route-B kernel rebind changed the installed key graph")
	}
	foreign := &bootstrapping.Evaluator{
		Evaluator: ckks.NewEvaluator(params, mem), EvaluationKeys: keys,
	}
	if _, err = bindRouteBA2BFirstRoundKernel(circuit, foreign); err == nil {
		t.Fatal("Route-B kernel rebind accepted an inner keyset outside the installed wrapper")
	}
}

func TestRouteBA2BFirstRoundReportBindsCanonicalPlanAndEveryBoundary(t *testing.T) {
	report := canonicalTestRouteBA2BFirstRoundReport(t)
	report.States[13].Level++
	if err := report.Validate(); err == nil {
		t.Fatal("tampered MSB output boundary validated")
	}
	report = canonicalTestRouteBA2BFirstRoundReport(t)
	if report.States[8].ScaleHex == routeBA2BFirstRoundScaleHex ||
		report.States[9].ScaleHex == routeBA2BFirstRoundScaleHex {
		t.Fatal("squaring stages unexpectedly use the default scale")
	}
	report.States[8].ScaleHex = routeBA2BFirstRoundScaleHex
	if err := report.Validate(); err == nil {
		t.Fatal("tampered square0 scale boundary validated")
	}
}

func canonicalTestRouteBA2BFirstRoundReport(t *testing.T) RouteBA2BFirstRoundReport {
	t.Helper()
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := homchain.NewGaoA2BKernelN16L11Circuit(params, ckks.NewEncoder(params, 256))
	if err != nil {
		t.Fatal(err)
	}
	profile := kernel.Profile()
	transform, err := deriveRouteBA2BFirstRoundTransformPlan(params)
	if err != nil {
		t.Fatal(err)
	}
	transformDigest, err := digestRouteBA2BTransformSource(
		transform.source, transform.options, transform.rotationIndexes, transform.galoisElements,
	)
	if err != nil {
		t.Fatal(err)
	}
	maskDigest, err := digestRouteBA2BFirstRoundMask(params)
	if err != nil {
		t.Fatal(err)
	}
	capacity, err := canonicalRouteBCapacityPlan(routeBCapacityGateA2BFirstRound)
	if err != nil {
		t.Fatal(err)
	}
	stages := []string{
		"arithmetic-input", "special-b0-low", "special-b0-high", "iter0-low-mask", "iter0-stc", "iter0-mr0-output",
		string(homchain.GaoA2BKernelStageInput), string(homchain.GaoA2BKernelStageExponential),
		string(homchain.GaoA2BKernelStageSquare0), string(homchain.GaoA2BKernelStageRootOfUnity),
		string(homchain.GaoA2BKernelStageIdentityLUT), string(homchain.GaoA2BKernelStageMSBLUT),
		string(homchain.GaoA2BKernelStageIdentityOutput), string(homchain.GaoA2BKernelStageMSBOutput),
	}
	levels := []int{20, 19, 19, 18, 16, 17, 17, 11, 10, 9, 5, 5, 5, 5}
	stateScales, err := routeBA2BFirstRoundExpectedStateScales()
	if err != nil {
		t.Fatal(err)
	}
	states := make([]RouteBA2BFirstRoundState, len(stages))
	for index := range states {
		states[index] = RouteBA2BFirstRoundState{
			Stage: stages[index], Level: levels[index], Degree: 1, LogColumns: 11,
			ScaleHex: stateScales[index], ScaleExact: true,
		}
	}
	states[5].ScaleExact = false
	scaleDrift, err := routeBA2BFirstRoundExpectedScaleLog2Drift()
	if err != nil {
		t.Fatal(err)
	}
	report := RouteBA2BFirstRoundReport{
		SchemaVersion: routeBA2BFirstRoundReportSchema,
		Claim:         string(profile.Claim()), KernelProfileDigest: profile.Digest(),
		ExponentialArtifactDigest: profile.ExponentialArtifactDigest(), LUTTableDigest: profile.LUTTableDigest(),
		CapacityPlanDigest: capacity.Digest(), TransformSourceDigest: transformDigest, MaskSourceDigest: maskDigest,
		TransformRotationIndexes:  append([]int(nil), transform.rotationIndexes...),
		TransformGaloisElements:   append([]uint64(nil), transform.galoisElements...),
		LogBabyStepGiantStepRatio: routeBA2BFirstRoundBSGSRatio,
		LowN1:                     transform.lowN1, HighN1: transform.highN1, States: states,
		ScaleNormalizationSource:       routeBA2BFirstRoundObservedScaleHex,
		ScaleNormalizationTarget:       routeBA2BFirstRoundScaleHex,
		ScaleNormalizationAbsLog2:      scaleDrift,
		ScaleNormalizationBound:        routeBA2BFirstRoundMaxScaleLog2Drift,
		ScaleNormalizationMetadataOnly: true,
		OperationCounts: homchain.GaoA2BKernelOperationCounts{
			ExpPolynomialEvaluations: 1, ComplexSquarings: 2, MultiPolynomialEvaluations: 1,
			SharedPowerBases: 1, Conjugations: 2, RealRecoveries: 2,
		},
		WallNanoseconds: 1,
	}
	report.Digest, err = digestRouteBA2BFirstRoundReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if err = report.Validate(); err != nil {
		t.Fatal(err)
	}
	return report
}
