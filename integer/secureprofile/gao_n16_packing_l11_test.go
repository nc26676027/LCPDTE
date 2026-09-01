package secureprofile

import (
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestGaoN16PackingL11CapacityDerivesExactCombinedPlan(t *testing.T) {
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	if profile.Maturity() != ArtifactCapacityOnlyUnverified ||
		profile.AdaptationLabel() != "lattigo_packing_adaptation_r1" ||
		profile.EvidenceScope() != "capacity_only" || profile.IsSourceFaithful() || profile.IsFullPacked() {
		t.Fatalf("reduced-packing claim boundary changed: %+v", profile)
	}
	if profile.LogN() != 16 || profile.LogSlots() != 11 || profile.Slots() != 2048 ||
		profile.WordBits() != 8 || profile.WordCapacity() != 512 || profile.SparseDenseGap() != 16 ||
		!reflect.DeepEqual(profile.TraceRotations(), []uint64{2048, 4096, 8192, 16384}) {
		t.Fatalf("wrong L11 packing profile: %+v", profile)
	}
	if !reflect.DeepEqual(profile.TraceGaloisElements(), []uint64{65537, 98305, 114689, 122881}) {
		t.Fatalf("wrong Lattigo Trace Galois elements: %v", profile.TraceGaloisElements())
	}
	if profile.ParameterDigest() != gaoN16ExpectedParameterDigest ||
		profile.BaseProfileDigest() != gaoN16ExpectedProfileDigest || profile.Digest() == "" {
		t.Fatalf("profile identity is incomplete: %+v", profile)
	}

	shape := DefaultGaoN16PackingL11CapacityShape()
	plan, err := NewGaoN16PackingL11CapacityPlan(profile, shape, DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if shape.LogN() != 16 || shape.LogSlots() != 11 || shape.RingDegree() != 65536 ||
		shape.Slots() != 2048 || shape.WordCapacity() != 512 || shape.SparseDenseGap() != 16 ||
		shape.TraceRotationCount() != 4 ||
		!reflect.DeepEqual(shape.STCFactorDiagonalCounts(), []uint64{63, 64}) ||
		!reflect.DeepEqual(shape.CTSFactorDiagonalCounts(), []uint64{16, 31, 15}) {
		t.Fatalf("wrong reduced-packing capacity shape: %+v", shape)
	}
	if shape.DFTFormat() != "split_real_and_imag" || shape.STCType() != "homomorphic_decode" ||
		shape.CTSType() != "homomorphic_encode" || !reflect.DeepEqual(shape.STCLevels(), []uint64{1, 1}) ||
		!reflect.DeepEqual(shape.CTSLevels(), []uint64{1, 1, 1}) || shape.LogBSGSRatio() != 0 {
		t.Fatalf("wrong exact no-artifact DFT literal: %+v", shape)
	}
	wantRotationExponents := []int64{-1, 1, 2, 3, 4, 5, 6, 7, 8, 16, 24, 32, 64, 96, 128, 160, 192, 224, 256, 384, 512, 768, 1024, 1280, 1536, 1792, 1920, 1952, 1984, 2016, 2024, 2032, 2040, 2044, 2048, 4096, 8192, 16384}
	wantGaloisUnion := []uint64{5, 25, 125, 625, 3125, 5729, 7937, 15625, 27649, 28609, 31745, 37249, 41473, 49409, 59393, 60833, 60961, 61313, 63489, 65537, 77185, 77953, 78125, 81409, 89345, 89745, 91137, 95233, 98305, 98369, 102017, 113153, 114689, 117889, 122881, 126977, 128481, 131071}
	wantSTC := []uint64{5, 25, 125, 625, 3125, 5729, 7937, 15625, 27649, 28609, 31745, 59393, 60833, 60961, 61313, 63489, 77185, 77953, 78125, 81409, 89345, 91137, 95233, 98369, 102017, 117889, 126977, 128481}
	wantCTS := []uint64{5, 25, 125, 625, 7937, 28609, 31745, 37249, 41473, 49409, 59393, 60833, 60961, 61313, 63489, 77953, 81409, 89745, 102017, 113153, 126977, 128481}
	if !reflect.DeepEqual(plan.EvaluationRotationExponents(), wantRotationExponents) ||
		!reflect.DeepEqual(plan.EvaluationGaloisElements(), wantGaloisUnion) ||
		!reflect.DeepEqual(plan.STCGaloisElements(), wantSTC) ||
		!reflect.DeepEqual(plan.CTSGaloisElements(), wantCTS) ||
		!reflect.DeepEqual(plan.TraceGaloisElements(), profile.TraceGaloisElements()) ||
		plan.ConjugationGaloisElement() != 131071 {
		t.Fatalf("wrong deduplicated L11 key union: rotations=%v galois=%v trace=%v conjugation=%d",
			plan.EvaluationRotationExponents(), plan.EvaluationGaloisElements(), plan.TraceGaloisElements(), plan.ConjugationGaloisElement())
	}
	if plan.Maturity() != ArtifactCapacityOnlyUnverified ||
		plan.AdaptationLabel() != profile.AdaptationLabel() || plan.EvidenceScope() != profile.EvidenceScope() ||
		plan.IsSourceFaithful() || plan.IsFullPacked() ||
		plan.ParameterDigest() != profile.ParameterDigest() || plan.ProfileDigest() != profile.Digest() ||
		plan.ShapeDigest() == "" || plan.PolicyDigest() != DefaultArtifactCapacityPolicy().Digest() || plan.Digest() == "" {
		t.Fatalf("combined plan identity is incomplete: %+v", plan)
	}

	want := map[string]uint64{
		"transform_specifications_bound":                    18874368,
		"compiled_transform_pair_bound":                     205520896,
		"encoded_stc_qp_exact":                              1731198976,
		"encoded_cts_qp_exact":                              910163968,
		"q_only_masks_bound":                                20971520,
		"polynomial_operands_bound":                         69376,
		"full_artifact_construction_peak":                   2968063744,
		"dft_trace_conjugation_evaluation_keys_bound":       3347054592,
		"fixed_evaluation_keys_bound":                       264241152,
		"evaluator_fixed_buffers_bound":                     440926208,
		"max_factor_baby_step_prerotated_ciphertexts_bound": 109051904,
		"n_coefficient_scratch_bound":                       524288,
	}
	for _, estimate := range plan.Estimates() {
		bytes, ok := want[estimate.Name()]
		if !ok || estimate.Bytes() != bytes || estimate.Formula() == "" {
			t.Fatalf("combined estimate changed: name=%q bytes=%d formula=%q", estimate.Name(), estimate.Bytes(), estimate.Formula())
		}
		delete(want, estimate.Name())
	}
	if len(want) != 0 {
		t.Fatalf("missing combined estimates: %v", want)
	}
	if plan.MaxEncodedFactorBytes() != 872415232 || plan.FullArtifactPeakBytes() != 2968063744 ||
		plan.DFTRotationTraceConjugationKeyCount() != 38 || plan.FixedEvaluationKeyCount() != 3 ||
		plan.TotalEvaluationKeyCount() != 41 || plan.EvaluationKeyBytes() != 3611295744 ||
		plan.ProjectedIncrementalPeakBytes() != 7129861888 {
		t.Fatalf("combined plan bounds changed: %+v", plan)
	}

	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "l11-audit-fixture-2026-08-30",
		TotalPhysicalBytes:     33617782768,
		AvailablePhysicalBytes: 17151951897,
	}
	report, permit, err := plan.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Decision() != Admitted || report.Maturity() != ArtifactCapacityOnlyUnverified ||
		report.CurrentSystemUsedBytes() != 16465830871 || report.CapacityLimitBytes() != 26894226214 ||
		report.ProjectedIncrementalPeakBytes() != 7129861888 || report.GuardBytes() != 712986188 ||
		report.GuardedRequirementBytes() != 7842848076 || report.ProjectedSystemUsedBytes() != 24308678947 ||
		report.RemainingBelowLimitBytes() != 2585547267 || report.Digest() == "" {
		t.Fatalf("unexpected L11 audit report: %+v", report)
	}
	if permit.IsZero() || permit.Decision() != Admitted || permit.Maturity() != ArtifactCapacityOnlyUnverified ||
		permit.ProfileDigest() != profile.Digest() || permit.Digest() == "" {
		t.Fatalf("admitted L11 report did not mint its unique permit: %+v", permit)
	}
	t.Logf("L11 digests profile=%s shape=%s policy=%s plan=%s probe=%s report=%s permit=%s",
		profile.Digest(), shape.Digest(), plan.PolicyDigest(), plan.Digest(), report.ProbeDigest(), report.Digest(), permit.Digest())
	if profile.Digest() != "ea9e91c94a7ab29fcce5f8450baa23922b2302ec5b57b921bbc1e0579a5e0f85" ||
		shape.Digest() != "61169b61530bbbdf180b2984cfa684aed637d68b907ae721412f24ce173a8eb4" ||
		plan.PolicyDigest() != "ce12041a2762beb61b799a34d7f918ba2b01ff983716a31fabe246a3f2ec61a9" ||
		plan.Digest() != "9c73127d0a0427a2eb7123cdeb6ad3e2f607470c9e4826635d3fefd7c1bd06b6" ||
		report.ProbeDigest() != "b92e8002d519bd90d42d72e1eec870c51d8116773cb2da549b8d0483a419ee2a" ||
		report.Digest() != "7193fa00a80ffba4affe284c659888e7f471c26baf11ee0ab7f58b66768c4d16" ||
		permit.Digest() != "c6367c8caaf89c0b530d9ad19e0f924c9f1be7e2921c1df765c94d6e35509305" {
		t.Fatal("versioned L11 digest snapshot drifted")
	}
	if err = plan.ValidateReport(snapshot, report); err != nil {
		t.Fatalf("sealed report did not revalidate: %v", err)
	}
	if err = plan.ValidatePermit(snapshot, permit); err != nil {
		t.Fatalf("sealed permit did not revalidate: %v", err)
	}
}

func TestGaoN16PackingL11CapacityPublishesVersionedClaimBoundary(t *testing.T) {
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	shape := DefaultGaoN16PackingL11CapacityShape()
	plan, err := NewGaoN16PackingL11CapacityPlan(profile, shape, DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "l11-versioned-identity",
		TotalPhysicalBytes:     33617782768,
		AvailablePhysicalBytes: 17151951897,
	}
	report, permit, err := plan.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if profile.SchemaVersion() != gaoN16PackingL11ProfileSchema ||
		shape.SchemaVersion() != gaoN16PackingL11ShapeSchema ||
		plan.SchemaVersion() != gaoN16PackingL11PlanSchema ||
		report.SchemaVersion() != gaoN16PackingL11ReportSchema ||
		permit.SchemaVersion() != gaoN16PackingL11PermitSchema {
		t.Fatalf("L11 evidence objects lost their versioned schema boundary: profile=%q shape=%q plan=%q report=%q permit=%q",
			profile.SchemaVersion(), shape.SchemaVersion(), plan.SchemaVersion(), report.SchemaVersion(), permit.SchemaVersion())
	}
	if report.ParameterDigest() != profile.ParameterDigest() || permit.ParameterDigest() != profile.ParameterDigest() ||
		permit.PlanDigest() != plan.Digest() || permit.ShapeDigest() != shape.Digest() ||
		permit.PolicyDigest() != DefaultArtifactCapacityPolicy().Digest() || permit.ReportDigest() != report.Digest() {
		t.Fatalf("versioned report/permit identities are incomplete: report=%+v permit=%+v", report, permit)
	}
}

func TestGaoN16PackingL11CapacityRejectsResealedProfileShapePolicyAndPlanDrift(t *testing.T) {
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	shape := DefaultGaoN16PackingL11CapacityShape()
	policy := DefaultArtifactCapacityPolicy()
	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "l11-drift-fixture",
		TotalPhysicalBytes:     33617782768,
		AvailablePhysicalBytes: 17151951897,
	}
	plan, err := NewGaoN16PackingL11CapacityPlan(profile, shape, policy)
	if err != nil {
		t.Fatal(err)
	}
	_, permit, err := plan.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	constructorCalls := 0
	constructAfterPlanPermit := func(candidate GaoN16PackingL11CapacityPlan, candidatePermit GaoN16PackingL11CapacityPermit) error {
		if validateErr := candidate.ValidatePermit(snapshot, candidatePermit); validateErr != nil {
			return validateErr
		}
		constructorCalls++
		return nil
	}

	profileMutations := []struct {
		name   string
		mutate func(*GaoN16PackingL11Profile)
	}{
		{name: "adaptation label", mutate: func(value *GaoN16PackingL11Profile) { value.adaptationLabel = "gao_source_faithful" }},
		{name: "evidence scope", mutate: func(value *GaoN16PackingL11Profile) { value.evidenceScope = "secure_circuit" }},
		{name: "source faithful promotion", mutate: func(value *GaoN16PackingL11Profile) { value.sourceFaithful = true }},
		{name: "full packed promotion", mutate: func(value *GaoN16PackingL11Profile) { value.fullPacked = true }},
		{name: "log slots", mutate: func(value *GaoN16PackingL11Profile) { value.logSlots = 15 }},
		{name: "word capacity", mutate: func(value *GaoN16PackingL11Profile) { value.wordCapacity = 8192 }},
		{name: "trace rotation", mutate: func(value *GaoN16PackingL11Profile) { value.traceRotations[0] = 16 }},
		{name: "normalized trace offsets", mutate: func(value *GaoN16PackingL11Profile) { value.traceRotations = []uint64{1, 2, 4, 8} }},
		{name: "trace Galois element", mutate: func(value *GaoN16PackingL11Profile) { value.traceGaloisElements[0] = 5 }},
		{name: "parameter digest", mutate: func(value *GaoN16PackingL11Profile) { value.parameterDigest = gaoN16ExpectedProfileDigest }},
	}
	for _, test := range profileMutations {
		t.Run("profile "+test.name, func(t *testing.T) {
			changed := profile
			changed.traceRotations = profile.TraceRotations()
			changed.traceGaloisElements = profile.TraceGaloisElements()
			test.mutate(&changed)
			changed.digest, err = digestGaoN16PackingL11Profile(changed)
			if err != nil {
				t.Fatal(err)
			}
			candidate, candidateErr := NewGaoN16PackingL11CapacityPlan(changed, shape, policy)
			assertL11Blocked(t, candidateErr)
			if candidate.Digest() != "" {
				t.Fatalf("drifted profile emitted plan digest %q", candidate.Digest())
			}
		})
	}

	shapeMutations := []struct {
		name   string
		mutate func(*GaoN16PackingL11CapacityShape)
	}{
		{name: "adaptation label", mutate: func(value *GaoN16PackingL11CapacityShape) { value.adaptationLabel = "gao_full_packed" }},
		{name: "source faithful promotion", mutate: func(value *GaoN16PackingL11CapacityShape) { value.sourceFaithful = true }},
		{name: "full packed promotion", mutate: func(value *GaoN16PackingL11CapacityShape) { value.fullPacked = true }},
		{name: "slots", mutate: func(value *GaoN16PackingL11CapacityShape) { value.slots = 32768 }},
		{name: "word capacity", mutate: func(value *GaoN16PackingL11CapacityShape) { value.wordCapacity = 8192 }},
		{name: "sparse dense gap", mutate: func(value *GaoN16PackingL11CapacityShape) { value.sparseDenseGap = 1 }},
		{name: "STC diagonal", mutate: func(value *GaoN16PackingL11CapacityShape) { value.stcFactorDiagonalCounts[1] = 256 }},
		{name: "CTS diagonal", mutate: func(value *GaoN16PackingL11CapacityShape) { value.ctsFactorDiagonalCounts[1] = 63 }},
		{name: "rotation key count", mutate: func(value *GaoN16PackingL11CapacityShape) { value.dftTraceConjugationKeyCount = 37 }},
		{name: "fixed key policy", mutate: func(value *GaoN16PackingL11CapacityShape) { value.fixedEvaluationKeys[2] = "conjugation" }},
		{name: "key bytes", mutate: func(value *GaoN16PackingL11CapacityShape) { value.keyBytesPerKey-- }},
		{name: "evaluator buffers", mutate: func(value *GaoN16PackingL11CapacityShape) { value.evaluatorFixedBufferBytes-- }},
		{name: "baby step count", mutate: func(value *GaoN16PackingL11CapacityShape) { value.babyStepCiphertextCount-- }},
		{name: "normalized trace offsets", mutate: func(value *GaoN16PackingL11CapacityShape) { value.traceRotations = []uint64{1, 2, 4, 8} }},
		{name: "repack format", mutate: func(value *GaoN16PackingL11CapacityShape) { value.dftFormat = "repack_imag_as_real" }},
		{name: "BSGS ratio", mutate: func(value *GaoN16PackingL11CapacityShape) { value.logBSGSRatio = 1 }},
		{name: "Galois union", mutate: func(value *GaoN16PackingL11CapacityShape) { value.evaluationGaloisElements[0] = 1 }},
	}
	for _, test := range shapeMutations {
		t.Run("shape "+test.name, func(t *testing.T) {
			changed := cloneGaoN16PackingL11CapacityShape(shape)
			test.mutate(&changed)
			changed.digest, err = digestGaoN16PackingL11Shape(changed)
			if err != nil {
				t.Fatal(err)
			}
			candidate, candidateErr := NewGaoN16PackingL11CapacityPlan(profile, changed, policy)
			assertL11Blocked(t, candidateErr)
			if candidate.Digest() != "" {
				t.Fatalf("drifted shape emitted plan digest %q", candidate.Digest())
			}
		})
	}

	overflowShape := cloneGaoN16PackingL11CapacityShape(shape)
	overflowShape.coefficientBytes = math.MaxUint64
	overflowShape.digest, err = digestGaoN16PackingL11Shape(overflowShape)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewGaoN16PackingL11CapacityPlan(profile, overflowShape, policy)
	assertL11Blocked(t, err)

	driftedPolicy := policy
	driftedPolicy.minimumGuardBytes--
	driftedPolicy.digest = digestCapacityPolicy(driftedPolicy)
	_, err = NewGaoN16PackingL11CapacityPlan(profile, shape, driftedPolicy)
	assertL11Blocked(t, err)

	planMutations := []struct {
		name   string
		mutate func(*GaoN16PackingL11CapacityPlan)
	}{
		{name: "adaptation label", mutate: func(value *GaoN16PackingL11CapacityPlan) { value.adaptationLabel = "gao_source_faithful" }},
		{name: "source faithful promotion", mutate: func(value *GaoN16PackingL11CapacityPlan) { value.sourceFaithful = true }},
		{name: "full packed promotion", mutate: func(value *GaoN16PackingL11CapacityPlan) { value.fullPacked = true }},
		{name: "profile digest", mutate: func(value *GaoN16PackingL11CapacityPlan) { value.profileDigest = profile.BaseProfileDigest() }},
		{name: "max factor", mutate: func(value *GaoN16PackingL11CapacityPlan) { value.maxEncodedFactorBytes++ }},
		{name: "artifact peak", mutate: func(value *GaoN16PackingL11CapacityPlan) { value.fullArtifactPeakBytes++ }},
		{name: "key bytes", mutate: func(value *GaoN16PackingL11CapacityPlan) { value.evaluationKeyBytes++ }},
		{name: "combined peak", mutate: func(value *GaoN16PackingL11CapacityPlan) { value.projectedIncrementalPeakBytes++ }},
		{name: "named estimate", mutate: func(value *GaoN16PackingL11CapacityPlan) { value.estimates[0].bytes++ }},
	}
	for _, test := range planMutations {
		t.Run("plan "+test.name, func(t *testing.T) {
			changed := plan
			changed.estimates = plan.Estimates()
			test.mutate(&changed)
			changed.digest, err = digestGaoN16PackingL11Plan(changed)
			if err != nil {
				t.Fatal(err)
			}
			assertL11Blocked(t, constructAfterPlanPermit(changed, permit))
		})
	}
	if constructorCalls != 0 {
		t.Fatalf("drifted/resealed inputs invoked artifact constructor %d times", constructorCalls)
	}
}

func TestGaoN16PackingL11CapacityRejectsStaleForeignAndResealedEvidenceBeforeConstruction(t *testing.T) {
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGaoN16PackingL11CapacityPlan(profile, DefaultGaoN16PackingL11CapacityShape(), DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "l11-unique-admitted-permit",
		TotalPhysicalBytes:     33617782768,
		AvailablePhysicalBytes: 17151951897,
	}
	report, permit, err := plan.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	secondReport, secondPermit, err := plan.Evaluate(snapshot)
	if err != nil || report != secondReport || permit != secondPermit {
		t.Fatalf("same plan/snapshot did not reproduce the unique evidence: report=%+v/%+v permit=%+v/%+v err=%v",
			report, secondReport, permit, secondPermit, err)
	}

	constructorCalls := 0
	constructOnlyAfterPermit := func(candidateSnapshot PhysicalMemorySnapshot, candidate GaoN16PackingL11CapacityPermit) error {
		if validateErr := plan.ValidatePermit(candidateSnapshot, candidate); validateErr != nil {
			return validateErr
		}
		constructorCalls++
		return nil
	}
	if err = constructOnlyAfterPermit(snapshot, permit); err != nil {
		t.Fatalf("unique admitted permit did not reach caller constructor: %v", err)
	}
	if constructorCalls != 1 {
		t.Fatalf("unique admitted permit constructor count=%d, want 1", constructorCalls)
	}

	staleSnapshots := []PhysicalMemorySnapshot{
		{SnapshotID: "foreign-host", TotalPhysicalBytes: snapshot.TotalPhysicalBytes, AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes},
		{SnapshotID: snapshot.SnapshotID, TotalPhysicalBytes: snapshot.TotalPhysicalBytes, AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes + 1},
		{SnapshotID: snapshot.SnapshotID, TotalPhysicalBytes: snapshot.TotalPhysicalBytes + 1, AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes},
		{SnapshotID: "overflow", TotalPhysicalBytes: math.MaxUint64, AvailablePhysicalBytes: math.MaxUint64},
	}
	for index, stale := range staleSnapshots {
		t.Run("stale snapshot "+string(rune('A'+index)), func(t *testing.T) {
			assertL11Blocked(t, constructOnlyAfterPermit(stale, permit))
		})
	}

	permitMutations := []struct {
		name   string
		mutate func(*GaoN16PackingL11CapacityPermit)
	}{
		{name: "schema", mutate: func(value *GaoN16PackingL11CapacityPermit) { value.schema = "foreign" }},
		{name: "adaptation label", mutate: func(value *GaoN16PackingL11CapacityPermit) { value.adaptationLabel = "gao_source_faithful" }},
		{name: "evidence scope", mutate: func(value *GaoN16PackingL11CapacityPermit) { value.evidenceScope = "secure_circuit" }},
		{name: "source faithful promotion", mutate: func(value *GaoN16PackingL11CapacityPermit) { value.sourceFaithful = true }},
		{name: "full packed promotion", mutate: func(value *GaoN16PackingL11CapacityPermit) { value.fullPacked = true }},
		{name: "plan", mutate: func(value *GaoN16PackingL11CapacityPermit) { value.planDigest = profile.Digest() }},
		{name: "profile", mutate: func(value *GaoN16PackingL11CapacityPermit) { value.profileDigest = profile.BaseProfileDigest() }},
		{name: "probe", mutate: func(value *GaoN16PackingL11CapacityPermit) { value.probeDigest = report.Digest() }},
		{name: "report", mutate: func(value *GaoN16PackingL11CapacityPermit) { value.reportDigest = plan.Digest() }},
	}
	for _, test := range permitMutations {
		t.Run("permit "+test.name, func(t *testing.T) {
			changed := permit
			test.mutate(&changed)
			changed.sealDigest, err = digestGaoN16PackingL11Permit(changed)
			if err != nil {
				t.Fatal(err)
			}
			assertL11Blocked(t, constructOnlyAfterPermit(snapshot, changed))
		})
	}

	resealedReport := report
	resealedReport.fullPacked = true
	resealedReport.digest, err = digestGaoN16PackingL11Report(resealedReport)
	if err != nil {
		t.Fatal(err)
	}
	assertL11Blocked(t, plan.ValidateReport(snapshot, resealedReport))

	blockedSnapshot := PhysicalMemorySnapshot{
		SnapshotID:             "l11-strict-boundary-equality",
		TotalPhysicalBytes:     68719476736,
		AvailablePhysicalBytes: 21586743424,
	}
	blockedReport, blockedPermit, blockedErr := plan.Evaluate(blockedSnapshot)
	assertL11Blocked(t, blockedErr)
	if blockedReport.Decision() != ResourceBlocked || !blockedPermit.IsZero() ||
		blockedReport.ProjectedSystemUsedBytes() != blockedReport.CapacityLimitBytes() {
		t.Fatalf("strict boundary did not block equality: report=%+v permit=%+v", blockedReport, blockedPermit)
	}
	if err = plan.ValidateReport(blockedSnapshot, blockedReport); err != nil {
		t.Fatalf("sealed blocked report did not revalidate: %v", err)
	}
	forgedBlocked := permit
	forgedBlocked.probeDigest = blockedReport.ProbeDigest()
	forgedBlocked.reportDigest = blockedReport.Digest()
	forgedBlocked.sealDigest, err = digestGaoN16PackingL11Permit(forgedBlocked)
	if err != nil {
		t.Fatal(err)
	}
	assertL11Blocked(t, constructOnlyAfterPermit(blockedSnapshot, forgedBlocked))

	if constructorCalls != 1 {
		t.Fatalf("stale/foreign/resealed evidence invoked caller constructor; count=%d, want 1", constructorCalls)
	}
}

func TestGaoN16PackingL11CapacityReturnsDefensiveCopies(t *testing.T) {
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	shape := DefaultGaoN16PackingL11CapacityShape()
	plan, err := NewGaoN16PackingL11CapacityPlan(profile, shape, DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "l11-defensive-copy",
		TotalPhysicalBytes:     33617782768,
		AvailablePhysicalBytes: 17151951897,
	}
	_, permit, err := plan.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	rotations := profile.TraceRotations()
	rotations[0] = 16
	stc := shape.STCFactorDiagonalCounts()
	stc[0] = 255
	cts := shape.CTSFactorDiagonalCounts()
	cts[0] = 32
	fixed := shape.FixedEvaluationKeys()
	fixed[0] = "foreign"
	detachedShape := plan.Shape()
	detachedShape.stcFactorDiagonalCounts[0] = 255
	estimates := plan.Estimates()
	estimates[0].bytes++
	union := plan.EvaluationGaloisElements()
	union[0] = 1
	stcKeys := plan.STCGaloisElements()
	stcKeys[0] = 1
	ctsKeys := plan.CTSGaloisElements()
	ctsKeys[0] = 1

	if !reflect.DeepEqual(profile.TraceRotations(), []uint64{2048, 4096, 8192, 16384}) ||
		!reflect.DeepEqual(shape.STCFactorDiagonalCounts(), []uint64{63, 64}) ||
		!reflect.DeepEqual(shape.CTSFactorDiagonalCounts(), []uint64{16, 31, 15}) ||
		!reflect.DeepEqual(shape.FixedEvaluationKeys(), []string{"relinearization", "dense_to_sparse", "sparse_to_dense"}) ||
		!reflect.DeepEqual(plan.Shape().STCFactorDiagonalCounts(), []uint64{63, 64}) ||
		plan.Estimates()[0].Bytes() != 18874368 || plan.EvaluationGaloisElements()[0] != 5 ||
		plan.STCGaloisElements()[0] != 5 || plan.CTSGaloisElements()[0] != 5 ||
		plan.ValidatePermit(snapshot, permit) != nil {
		t.Fatal("detached accessor changed sealed L11 capacity evidence")
	}
}

func TestGaoN16PackingL11CapacityZeroNilAndInvalidSnapshotMatrixFailsBeforeConstruction(t *testing.T) {
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	shape := DefaultGaoN16PackingL11CapacityShape()
	policy := DefaultArtifactCapacityPolicy()
	plan, err := NewGaoN16PackingL11CapacityPlan(profile, shape, policy)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "l11-zero-nil-matrix-valid",
		TotalPhysicalBytes:     33617782768,
		AvailablePhysicalBytes: 17151951897,
	}
	report, permit, err := plan.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	constructorCalls := 0
	constructAfterPermit := func(candidatePlan GaoN16PackingL11CapacityPlan, candidateSnapshot PhysicalMemorySnapshot, candidatePermit GaoN16PackingL11CapacityPermit) error {
		if validateErr := candidatePlan.ValidatePermit(candidateSnapshot, candidatePermit); validateErr != nil {
			return validateErr
		}
		constructorCalls++
		return nil
	}
	constructAfterReportAndPermit := func(candidatePlan GaoN16PackingL11CapacityPlan, candidateSnapshot PhysicalMemorySnapshot, candidateReport GaoN16PackingL11CapacityReport, candidatePermit GaoN16PackingL11CapacityPermit) error {
		if validateErr := candidatePlan.ValidateReport(candidateSnapshot, candidateReport); validateErr != nil {
			return validateErr
		}
		return constructAfterPermit(candidatePlan, candidateSnapshot, candidatePermit)
	}
	assertZeroPlan := func(t *testing.T, candidate GaoN16PackingL11CapacityPlan, candidateErr error) {
		t.Helper()
		assertL11Blocked(t, candidateErr)
		if candidate.Digest() != "" {
			t.Fatalf("rejected constructor input emitted plan digest %q", candidate.Digest())
		}
	}
	assertZeroEvaluation := func(t *testing.T, candidateReport GaoN16PackingL11CapacityReport, candidatePermit GaoN16PackingL11CapacityPermit, candidateErr error) {
		t.Helper()
		assertL11Blocked(t, candidateErr)
		if candidateReport != (GaoN16PackingL11CapacityReport{}) || !candidatePermit.IsZero() {
			t.Fatalf("fail-closed evaluation returned non-zero evidence: report=%+v permit=%+v", candidateReport, candidatePermit)
		}
	}

	t.Run("zero profile", func(t *testing.T) {
		candidate, candidateErr := NewGaoN16PackingL11CapacityPlan(GaoN16PackingL11Profile{}, shape, policy)
		assertZeroPlan(t, candidate, candidateErr)
	})
	profileNilMutations := []struct {
		name   string
		mutate func(*GaoN16PackingL11Profile)
	}{
		{name: "trace rotations", mutate: func(value *GaoN16PackingL11Profile) { value.traceRotations = nil }},
		{name: "trace Galois elements", mutate: func(value *GaoN16PackingL11Profile) { value.traceGaloisElements = nil }},
	}
	for _, test := range profileNilMutations {
		t.Run("nil profile "+test.name, func(t *testing.T) {
			changed := profile
			changed.traceRotations = profile.TraceRotations()
			changed.traceGaloisElements = profile.TraceGaloisElements()
			test.mutate(&changed)
			changed.digest, err = digestGaoN16PackingL11Profile(changed)
			if err != nil {
				t.Fatal(err)
			}
			candidate, candidateErr := NewGaoN16PackingL11CapacityPlan(changed, shape, policy)
			assertZeroPlan(t, candidate, candidateErr)
		})
	}

	t.Run("zero shape", func(t *testing.T) {
		candidate, candidateErr := NewGaoN16PackingL11CapacityPlan(profile, GaoN16PackingL11CapacityShape{}, policy)
		assertZeroPlan(t, candidate, candidateErr)
	})
	shapeNilMutations := []struct {
		name   string
		mutate func(*GaoN16PackingL11CapacityShape)
	}{
		{name: "trace rotations", mutate: func(value *GaoN16PackingL11CapacityShape) { value.traceRotations = nil }},
		{name: "trace Galois elements", mutate: func(value *GaoN16PackingL11CapacityShape) { value.traceGaloisElements = nil }},
		{name: "STC rotations", mutate: func(value *GaoN16PackingL11CapacityShape) { value.stcRotationInputs = nil }},
		{name: "CTS rotations", mutate: func(value *GaoN16PackingL11CapacityShape) { value.ctsRotationInputs = nil }},
		{name: "STC Galois elements", mutate: func(value *GaoN16PackingL11CapacityShape) { value.stcGaloisElements = nil }},
		{name: "CTS Galois elements", mutate: func(value *GaoN16PackingL11CapacityShape) { value.ctsGaloisElements = nil }},
		{name: "STC levels", mutate: func(value *GaoN16PackingL11CapacityShape) { value.stcLevels = nil }},
		{name: "CTS levels", mutate: func(value *GaoN16PackingL11CapacityShape) { value.ctsLevels = nil }},
		{name: "STC factor diagonals", mutate: func(value *GaoN16PackingL11CapacityShape) { value.stcFactorDiagonalCounts = nil }},
		{name: "CTS factor diagonals", mutate: func(value *GaoN16PackingL11CapacityShape) { value.ctsFactorDiagonalCounts = nil }},
		{name: "evaluation rotation exponents", mutate: func(value *GaoN16PackingL11CapacityShape) { value.evaluationRotationExponents = nil }},
		{name: "evaluation Galois elements", mutate: func(value *GaoN16PackingL11CapacityShape) { value.evaluationGaloisElements = nil }},
		{name: "fixed evaluation keys", mutate: func(value *GaoN16PackingL11CapacityShape) { value.fixedEvaluationKeys = nil }},
	}
	for _, test := range shapeNilMutations {
		t.Run("nil shape "+test.name, func(t *testing.T) {
			changed := cloneGaoN16PackingL11CapacityShape(shape)
			test.mutate(&changed)
			changed.digest, err = digestGaoN16PackingL11Shape(changed)
			if err != nil {
				t.Fatal(err)
			}
			candidate, candidateErr := NewGaoN16PackingL11CapacityPlan(profile, changed, policy)
			assertZeroPlan(t, candidate, candidateErr)
		})
	}

	t.Run("zero policy", func(t *testing.T) {
		candidate, candidateErr := NewGaoN16PackingL11CapacityPlan(profile, shape, CapacityPolicy{})
		assertZeroPlan(t, candidate, candidateErr)
	})

	t.Run("zero plan", func(t *testing.T) {
		zero := GaoN16PackingL11CapacityPlan{}
		candidateReport, candidatePermit, candidateErr := zero.Evaluate(snapshot)
		assertZeroEvaluation(t, candidateReport, candidatePermit, candidateErr)
		assertL11Blocked(t, zero.ValidateReport(snapshot, GaoN16PackingL11CapacityReport{}))
		assertL11Blocked(t, zero.ValidatePermit(snapshot, GaoN16PackingL11CapacityPermit{}))
		assertL11Blocked(t, constructAfterPermit(zero, snapshot, permit))
	})

	t.Run("nil plan estimates", func(t *testing.T) {
		changed := plan
		changed.estimates = nil
		changed.digest, err = digestGaoN16PackingL11Plan(changed)
		if err != nil {
			t.Fatal(err)
		}
		candidateReport, candidatePermit, candidateErr := changed.Evaluate(snapshot)
		assertZeroEvaluation(t, candidateReport, candidatePermit, candidateErr)
		assertL11Blocked(t, changed.ValidateReport(snapshot, report))
		assertL11Blocked(t, changed.ValidatePermit(snapshot, permit))
		assertL11Blocked(t, constructAfterPermit(changed, snapshot, permit))
	})

	t.Run("zero report", func(t *testing.T) {
		assertL11Blocked(t, plan.ValidateReport(snapshot, GaoN16PackingL11CapacityReport{}))
		assertL11Blocked(t, constructAfterReportAndPermit(plan, snapshot, GaoN16PackingL11CapacityReport{}, permit))
	})
	t.Run("zero permit", func(t *testing.T) {
		assertL11Blocked(t, plan.ValidatePermit(snapshot, GaoN16PackingL11CapacityPermit{}))
		assertL11Blocked(t, constructAfterPermit(plan, snapshot, GaoN16PackingL11CapacityPermit{}))
	})

	invalidSnapshots := []struct {
		name     string
		snapshot PhysicalMemorySnapshot
	}{
		{name: "blank ID", snapshot: PhysicalMemorySnapshot{SnapshotID: "  ", TotalPhysicalBytes: snapshot.TotalPhysicalBytes, AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes}},
		{name: "zero total", snapshot: PhysicalMemorySnapshot{SnapshotID: "l11-zero-total"}},
		{name: "available exceeds total", snapshot: PhysicalMemorySnapshot{SnapshotID: "l11-invalid-available", TotalPhysicalBytes: 1024, AvailablePhysicalBytes: 1025}},
	}
	for _, test := range invalidSnapshots {
		t.Run("invalid snapshot "+test.name, func(t *testing.T) {
			candidateReport, candidatePermit, candidateErr := plan.Evaluate(test.snapshot)
			assertZeroEvaluation(t, candidateReport, candidatePermit, candidateErr)
			assertL11Blocked(t, plan.ValidateReport(test.snapshot, report))
			assertL11Blocked(t, plan.ValidatePermit(test.snapshot, permit))
			assertL11Blocked(t, constructAfterReportAndPermit(plan, test.snapshot, report, permit))
		})
	}

	if constructorCalls != 0 {
		t.Fatalf("zero/nil/invalid evidence invoked caller artifact constructor %d times", constructorCalls)
	}
}

func assertL11Blocked(t *testing.T, err error) {
	t.Helper()
	var blocked *ErrArtifactCapacityBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("error=%v, want typed ErrArtifactCapacityBlocked", err)
	}
}
