package secureprofile

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"dt_go/integer/securityparams"
)

func TestGaoN16ArtifactCapacityPlanDerivesExactConservativeBounds(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := NewGaoN16ArtifactCapacityPlan(
		profile,
		DefaultGaoN16ArtifactShape(),
		DefaultArtifactCapacityPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}

	shape := plan.Shape()
	if shape.LogN() != 16 || shape.RingDegree() != 65536 || shape.Slots() != 32768 ||
		shape.WordCapacity() != 8192 || shape.QCount() != 21 || shape.PCount() != 7 {
		t.Fatalf("wrong exact capacity shape: %+v", shape)
	}
	if !reflect.DeepEqual(shape.STCFactorDiagonalCounts(), []uint64{255, 256}) ||
		!reflect.DeepEqual(shape.CTSFactorDiagonalCounts(), []uint64{32, 63, 63}) ||
		shape.STCLevelQ() != 18 || shape.STCLevelP() != 6 ||
		shape.CTSLevelQ() != 20 || shape.CTSLevelP() != 6 || shape.MaskLevelQ() != 19 {
		t.Fatalf("wrong exact DFT/mask shape: %+v", shape)
	}
	if plan.Maturity() != ArtifactCapacityOnlyUnverified || plan.ProfileDigest() != profile.Digest() ||
		plan.ParameterDigest() != profile.ParameterDigest() ||
		plan.ShapeDigest() == "" || plan.PolicyDigest() == "" || plan.Digest() == "" {
		t.Fatalf("capacity plan identity is incomplete: maturity=%q profile=%q shape=%q policy=%q plan=%q",
			plan.Maturity(), plan.ProfileDigest(), plan.ShapeDigest(), plan.PolicyDigest(), plan.Digest())
	}
	policy := plan.Policy()
	if policy.LimitNumerator() != 4 || policy.LimitDenominator() != 5 ||
		policy.MinimumGuardBytes() != 536870912 || policy.RelativeGuardNumerator() != 1 ||
		policy.RelativeGuardDenominator() != 10 || policy.Digest() != plan.PolicyDigest() {
		t.Fatalf("capacity policy changed: %+v", policy)
	}

	wantArtifacts := map[string]struct {
		resident  uint64
		transient uint64
	}{
		"transform_specifications_bound": {resident: 301989888},
		"compiled_transform_pair_bound":  {resident: 205520896},
		"encoded_stc_qp_exact":           {resident: 6965690368},
		"encoded_cts_qp_exact":           {resident: 2319450112},
		"q_only_masks_bound":             {resident: 20971520},
		"polynomial_operands_bound":      {resident: 806656, transient: 806656},
		"stc_high_precision_bound":       {transient: 4286578688},
		"cts_high_precision_bound":       {transient: 1325400064},
		"stc_text_digest_bound":          {transient: 6429868032},
		"cts_text_digest_bound":          {transient: 1988100096},
	}
	artifacts := plan.ArtifactEstimates()
	if len(artifacts) != len(wantArtifacts) {
		t.Fatalf("artifact estimate count=%d, want %d", len(artifacts), len(wantArtifacts))
	}
	for _, artifact := range artifacts {
		want, ok := wantArtifacts[artifact.Name()]
		if !ok || artifact.ResidentBytes() != want.resident || artifact.ConstructionTransientBytes() != want.transient {
			t.Fatalf("artifact estimate changed: name=%q resident=%d transient=%d",
				artifact.Name(), artifact.ResidentBytes(), artifact.ConstructionTransientBytes())
		}
		delete(wantArtifacts, artifact.Name())
	}
	if len(wantArtifacts) != 0 {
		t.Fatalf("missing artifact estimates: %v", wantArtifacts)
	}

	wantStages := map[string]uint64{
		"stc_non_streaming_digest_bound": 18211426048,
		"cts_non_streaming_digest_bound": 13127929600,
		"polynomial_clone_bound":         9815236096,
	}
	stages := plan.StageEstimates()
	if len(stages) != len(wantStages) {
		t.Fatalf("stage estimate count=%d, want %d", len(stages), len(wantStages))
	}
	for _, stage := range stages {
		if want, ok := wantStages[stage.Name()]; !ok || stage.ProjectedIncrementalBytes() != want {
			t.Fatalf("stage estimate changed: name=%q bytes=%d", stage.Name(), stage.ProjectedIncrementalBytes())
		}
		delete(wantStages, stage.Name())
	}
	if plan.ResidentArtifactBytes() != 9814429440 || plan.ProjectedIncrementalPeakBytes() != 18211426048 {
		t.Fatalf("resident/peak bounds changed: resident=%d peak=%d",
			plan.ResidentArtifactBytes(), plan.ProjectedIncrementalPeakBytes())
	}
}

func TestGaoN16ArtifactCapacityRejectsInvalidSnapshotsAndCheckedOverflow(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGaoN16ArtifactCapacityPlan(profile, DefaultGaoN16ArtifactShape(), DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		snapshot PhysicalMemorySnapshot
	}{
		{name: "zero total", snapshot: PhysicalMemorySnapshot{SnapshotID: "zero", AvailablePhysicalBytes: 0}},
		{name: "available exceeds total", snapshot: PhysicalMemorySnapshot{SnapshotID: "over", TotalPhysicalBytes: 1024, AvailablePhysicalBytes: 1025}},
		{name: "blank identity", snapshot: PhysicalMemorySnapshot{SnapshotID: "  ", TotalPhysicalBytes: 1024, AvailablePhysicalBytes: 512}},
		{name: "capacity limit multiplication overflow", snapshot: PhysicalMemorySnapshot{SnapshotID: "overflow", TotalPhysicalBytes: math.MaxUint64, AvailablePhysicalBytes: math.MaxUint64}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, permit, evalErr := plan.Evaluate(test.snapshot)
			var blocked *ErrArtifactCapacityBlocked
			if !errors.As(evalErr, &blocked) || report.Digest() != "" || !permit.IsZero() {
				t.Fatalf("invalid snapshot was not fail-closed: report=%+v permit=%+v err=%v", report, permit, evalErr)
			}
		})
	}

	overflowShape := DefaultGaoN16ArtifactShape()
	overflowShape.stcFactorDiagonalCounts = []uint64{math.MaxUint64, 1}
	if got, planErr := NewGaoN16ArtifactCapacityPlan(profile, overflowShape, DefaultArtifactCapacityPolicy()); !errors.As(planErr, new(*ErrArtifactCapacityBlocked)) || got.Digest() != "" {
		t.Fatalf("overflowing artifact shape was not fail-closed: plan=%+v err=%v", got, planErr)
	}
}

func TestGaoN16ArtifactCapacityRejectsProfileShapePolicyAndPlanDrift(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}
	shape := DefaultGaoN16ArtifactShape()
	policy := DefaultArtifactCapacityPolicy()

	profileMutations := []struct {
		name   string
		mutate func(*Profile)
	}{
		{name: "digest", mutate: func(value *Profile) { value.digest = "foreign" }},
		{name: "maturity", mutate: func(value *Profile) { value.maturity = ArtifactCapacityOnlyUnverified }},
		{name: "logN", mutate: func(value *Profile) { value.logN = 15 }},
		{name: "slots", mutate: func(value *Profile) { value.slots = 16384 }},
		{name: "words", mutate: func(value *Profile) { value.wordCapacity = 4096 }},
		{name: "Q count", mutate: func(value *Profile) { value.qCount = 20 }},
		{name: "P count", mutate: func(value *Profile) { value.pCount = 6 }},
	}
	for _, test := range profileMutations {
		t.Run("profile "+test.name, func(t *testing.T) {
			changed := profile
			test.mutate(&changed)
			assertCapacityPlanBlocked(t, changed, shape, policy)
		})
	}

	shapeMutations := []struct {
		name   string
		mutate func(*GaoN16ArtifactShape)
	}{
		{name: "formula schema", mutate: func(value *GaoN16ArtifactShape) { value.formulaVersion = "foreign" }},
		{name: "ring degree", mutate: func(value *GaoN16ArtifactShape) { value.ringDegree-- }},
		{name: "slots", mutate: func(value *GaoN16ArtifactShape) { value.slots-- }},
		{name: "STC factor 255", mutate: func(value *GaoN16ArtifactShape) { value.stcFactorDiagonalCounts[0] = 254 }},
		{name: "STC factor 256", mutate: func(value *GaoN16ArtifactShape) { value.stcFactorDiagonalCounts[1] = 255 }},
		{name: "CTS factor 32", mutate: func(value *GaoN16ArtifactShape) { value.ctsFactorDiagonalCounts[0] = 31 }},
		{name: "CTS factor 63 first", mutate: func(value *GaoN16ArtifactShape) { value.ctsFactorDiagonalCounts[1] = 62 }},
		{name: "CTS factor 63 second", mutate: func(value *GaoN16ArtifactShape) { value.ctsFactorDiagonalCounts[2] = 62 }},
		{name: "STC Q level", mutate: func(value *GaoN16ArtifactShape) { value.stcLevelQ = 17 }},
		{name: "STC P level", mutate: func(value *GaoN16ArtifactShape) { value.stcLevelP = 5 }},
		{name: "CTS Q level", mutate: func(value *GaoN16ArtifactShape) { value.ctsLevelQ = 19 }},
		{name: "CTS P level", mutate: func(value *GaoN16ArtifactShape) { value.ctsLevelP = 5 }},
		{name: "mask level", mutate: func(value *GaoN16ArtifactShape) { value.maskLevelQ = 18 }},
		{name: "complex bound", mutate: func(value *GaoN16ArtifactShape) { value.complexEntryBoundBytes = 255 }},
		{name: "text bound", mutate: func(value *GaoN16ArtifactShape) { value.textComplexBoundBytes = 191 }},
		{name: "text copies", mutate: func(value *GaoN16ArtifactShape) { value.textCopies = 1 }},
	}
	for _, test := range shapeMutations {
		t.Run("shape "+test.name, func(t *testing.T) {
			changed := cloneGaoN16ArtifactShape(shape)
			test.mutate(&changed)
			assertCapacityPlanBlocked(t, profile, changed, policy)
		})
	}

	policyMutations := []struct {
		name   string
		mutate func(*CapacityPolicy)
	}{
		{name: "schema", mutate: func(value *CapacityPolicy) { value.schema = "foreign" }},
		{name: "80 percent numerator", mutate: func(value *CapacityPolicy) { value.limitNumerator = 3 }},
		{name: "80 percent denominator", mutate: func(value *CapacityPolicy) { value.limitDenominator = 4 }},
		{name: "minimum guard", mutate: func(value *CapacityPolicy) { value.minimumGuardBytes-- }},
		{name: "relative numerator", mutate: func(value *CapacityPolicy) { value.relativeGuardNumerator = 2 }},
		{name: "relative denominator", mutate: func(value *CapacityPolicy) { value.relativeGuardDenominator = 11 }},
		{name: "digest", mutate: func(value *CapacityPolicy) { value.digest = "foreign" }},
	}
	for _, test := range policyMutations {
		t.Run("policy "+test.name, func(t *testing.T) {
			changed := policy
			test.mutate(&changed)
			assertCapacityPlanBlocked(t, profile, shape, changed)
		})
	}

	plan, err := NewGaoN16ArtifactCapacityPlan(profile, shape, policy)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := PhysicalMemorySnapshot{SnapshotID: "plan-tamper", TotalPhysicalBytes: 68719476736, AvailablePhysicalBytes: 33776464001}
	planMutations := []struct {
		name   string
		mutate func(*CapacityPlan)
	}{
		{name: "schema-bound maturity", mutate: func(value *CapacityPlan) { value.maturity = ParameterCandidateUnverified }},
		{name: "parameter", mutate: func(value *CapacityPlan) { value.parameterDigest = "foreign" }},
		{name: "profile", mutate: func(value *CapacityPlan) { value.profileDigest = "foreign" }},
		{name: "shape", mutate: func(value *CapacityPlan) { value.shapeDigest = "foreign" }},
		{name: "policy", mutate: func(value *CapacityPlan) { value.policyDigest = "foreign" }},
		{name: "resident", mutate: func(value *CapacityPlan) { value.residentArtifactBytes++ }},
		{name: "peak", mutate: func(value *CapacityPlan) { value.projectedIncrementalPeakBytes++ }},
		{name: "artifact", mutate: func(value *CapacityPlan) { value.artifactEstimates[0].residentBytes++ }},
		{name: "stage", mutate: func(value *CapacityPlan) { value.stageEstimates[0].projectedIncrementalBytes++ }},
		{name: "seal", mutate: func(value *CapacityPlan) { value.digest = "foreign" }},
	}
	for _, test := range planMutations {
		t.Run("plan "+test.name, func(t *testing.T) {
			changed := plan
			changed.artifactEstimates = plan.ArtifactEstimates()
			changed.stageEstimates = plan.StageEstimates()
			test.mutate(&changed)
			report, permit, evalErr := changed.Evaluate(snapshot)
			var blocked *ErrArtifactCapacityBlocked
			if !errors.As(evalErr, &blocked) || report.Digest() != "" || !permit.IsZero() {
				t.Fatalf("tampered plan was not fail-closed: report=%+v permit=%+v err=%v", report, permit, evalErr)
			}
		})
	}
}

func assertCapacityPlanBlocked(t *testing.T, profile Profile, shape GaoN16ArtifactShape, policy CapacityPolicy) {
	t.Helper()
	plan, err := NewGaoN16ArtifactCapacityPlan(profile, shape, policy)
	var blocked *ErrArtifactCapacityBlocked
	if !errors.As(err, &blocked) || plan.Digest() != "" {
		t.Fatalf("drifted capacity input was admitted: plan=%+v err=%v", plan, err)
	}
}

func TestGaoN16ArtifactCapacityBlocksAuditHostBeforeAnyArtifactConstructor(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGaoN16ArtifactCapacityPlan(profile, DefaultGaoN16ArtifactShape(), DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}

	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "read-only-audit-fixture-2026-08-30",
		TotalPhysicalBytes:     33617782768,
		AvailablePhysicalBytes: 17151951897,
	}
	report, permit, err := plan.Evaluate(snapshot)
	var blocked *ErrArtifactCapacityBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("audit-host capacity decision error=%v, want typed ErrArtifactCapacityBlocked", err)
	}
	if report.Decision() != ResourceBlocked || report.Maturity() != ArtifactCapacityOnlyUnverified ||
		report.ParameterDigest() != profile.ParameterDigest() ||
		report.CurrentSystemUsedBytes() != 16465830871 || report.CapacityLimitBytes() != 26894226214 ||
		report.ResidentArtifactBytes() != 9814429440 || report.ProjectedIncrementalPeakBytes() != 18211426048 ||
		report.GuardBytes() != 1821142604 || report.ProjectedSystemUsedBytes() != 36498399523 ||
		report.ShapeDigest() != plan.ShapeDigest() || report.ProbeDigest() == "" || report.Digest() == "" {
		t.Fatalf("unexpected audit-host capacity report: %+v", report)
	}
	if plan.ShapeDigest() != "3185bd05c9c5812d49f711e3f9fb91091e969583fc14b2bd4eb907eca15c7bf6" ||
		plan.PolicyDigest() != "ce12041a2762beb61b799a34d7f918ba2b01ff983716a31fabe246a3f2ec61a9" ||
		plan.Digest() != "2f7f099db9be4584a8d6a06baba4f7dc465a53be88124a4649e52e835fecd791" ||
		report.ProbeDigest() != "7bc07703748f7878268fb7beac51ffc2588de5185abda7a46a8387b1c7ba9011" ||
		report.Digest() != "38b38f3d38aa5252c96044ab0b0b5e398119202e4f6e4a63fd37fa0d879f2779" {
		t.Fatalf("capacity digest snapshot drifted: shape=%s policy=%s plan=%s probe=%s report=%s",
			plan.ShapeDigest(), plan.PolicyDigest(), plan.Digest(), report.ProbeDigest(), report.Digest())
	}
	t.Logf("capacity digests shape=%s policy=%s plan=%s probe=%s report=%s",
		plan.ShapeDigest(), plan.PolicyDigest(), plan.Digest(), report.ProbeDigest(), report.Digest())
	if !permit.IsZero() {
		t.Fatalf("blocked capacity decision emitted a permit: %+v", permit)
	}
	if err = plan.ValidateReport(snapshot, report); err != nil {
		t.Fatalf("sealed blocked report did not revalidate: %v", err)
	}

	constructorCalls := 0
	constructOnlyAfterPermit := func(candidate CapacityPermit) error {
		if validateErr := plan.ValidatePermit(snapshot, candidate); validateErr != nil {
			return validateErr
		}
		constructorCalls++
		return nil
	}
	if err = constructOnlyAfterPermit(permit); !errors.As(err, &blocked) {
		t.Fatalf("zero blocked permit error=%v, want typed ErrArtifactCapacityBlocked", err)
	}
	if constructorCalls != 0 {
		t.Fatalf("blocked path invoked artifact constructor %d times", constructorCalls)
	}

	otherSnapshot := snapshot
	otherSnapshot.SnapshotID = "same-shape-other-host-fixture"
	otherSnapshot.AvailablePhysicalBytes++
	otherReport, _, _ := plan.Evaluate(otherSnapshot)
	if otherReport.ShapeDigest() != report.ShapeDigest() || otherReport.ProbeDigest() == report.ProbeDigest() {
		t.Fatalf("shape/probe digest separation failed: first=%q/%q other=%q/%q",
			report.ShapeDigest(), report.ProbeDigest(), otherReport.ShapeDigest(), otherReport.ProbeDigest())
	}
}

func TestGaoN16ArtifactCapacityRejectsResealedPermitForNonAdmittedReport(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGaoN16ArtifactCapacityPlan(profile, DefaultGaoN16ArtifactShape(), DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}

	admittedSnapshot := PhysicalMemorySnapshot{
		SnapshotID:         "reseal-admitted",
		TotalPhysicalBytes: 68719476736, AvailablePhysicalBytes: 33776464001,
	}
	admittedReport, admittedPermit, err := plan.Evaluate(admittedSnapshot)
	if err != nil || admittedReport.Decision() != Admitted || admittedPermit.IsZero() {
		t.Fatalf("admitted fixture failed: report=%+v permit=%+v err=%v", admittedReport, admittedPermit, err)
	}

	blockedSnapshot := PhysicalMemorySnapshot{
		SnapshotID:         "reseal-blocked",
		TotalPhysicalBytes: 68719476736, AvailablePhysicalBytes: 33776464000,
	}
	blockedReport, _, blockedErr := plan.Evaluate(blockedSnapshot)
	var blocked *ErrArtifactCapacityBlocked
	if !errors.As(blockedErr, &blocked) || blockedReport.Decision() != ResourceBlocked {
		t.Fatalf("blocked fixture failed: report=%+v err=%v", blockedReport, blockedErr)
	}

	overflowSnapshot := PhysicalMemorySnapshot{
		SnapshotID:         "reseal-overflow",
		TotalPhysicalBytes: math.MaxUint64, AvailablePhysicalBytes: math.MaxUint64,
	}
	overflowProbe, err := digestArtifactCapacityProbe(plan.PolicyDigest(), overflowSnapshot)
	if err != nil {
		t.Fatal(err)
	}

	forgeries := []struct {
		name       string
		snapshot   PhysicalMemorySnapshot
		probe      string
		reportSeal string
	}{
		{name: "real blocked report", snapshot: blockedSnapshot, probe: blockedReport.ProbeDigest(), reportSeal: blockedReport.Digest()},
		{name: "overflow snapshot", snapshot: overflowSnapshot, probe: overflowProbe, reportSeal: admittedReport.Digest()},
		{name: "arbitrary digest", snapshot: admittedSnapshot, probe: admittedReport.ProbeDigest(), reportSeal: plan.Digest()},
	}
	constructorCalls := 0
	constructOnlyAfterPermit := func(snapshot PhysicalMemorySnapshot, permit CapacityPermit) error {
		if validateErr := plan.ValidatePermit(snapshot, permit); validateErr != nil {
			return validateErr
		}
		constructorCalls++
		return nil
	}
	for _, test := range forgeries {
		t.Run(test.name, func(t *testing.T) {
			forged := admittedPermit
			forged.probeDigest = test.probe
			forged.reportDigest = test.reportSeal
			forged.sealDigest, err = digestCapacityPermit(forged)
			if err != nil {
				t.Fatal(err)
			}
			if validateErr := constructOnlyAfterPermit(test.snapshot, forged); !errors.As(validateErr, &blocked) {
				t.Fatalf("re-sealed non-admitted permit error=%v, want typed ErrArtifactCapacityBlocked", validateErr)
			}
		})
	}
	if constructorCalls != 0 {
		t.Fatalf("re-sealed non-admitted permits invoked artifact constructor %d times", constructorCalls)
	}
}

func TestGaoN16ArtifactCapacityUsesStrictEightyPercentBoundary(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGaoN16ArtifactCapacityPlan(profile, DefaultGaoN16ArtifactShape(), DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		available uint64
		decision  CapacityDecision
		projected uint64
		wantError bool
	}{
		{name: "one byte below", available: 33776464001, decision: Admitted, projected: 54975581387},
		{name: "equal", available: 33776464000, decision: ResourceBlocked, projected: 54975581388, wantError: true},
		{name: "one byte above", available: 33776463999, decision: ResourceBlocked, projected: 54975581389, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := PhysicalMemorySnapshot{
				SnapshotID:             "strict-boundary-" + test.name,
				TotalPhysicalBytes:     68719476736,
				AvailablePhysicalBytes: test.available,
			}
			report, permit, evalErr := plan.Evaluate(snapshot)
			var blocked *ErrArtifactCapacityBlocked
			if test.wantError != errors.As(evalErr, &blocked) {
				t.Fatalf("Evaluate error=%v, typed-blocked=%t, want %t", evalErr, errors.As(evalErr, &blocked), test.wantError)
			}
			if report.CapacityLimitBytes() != 54975581388 || report.ProjectedSystemUsedBytes() != test.projected ||
				report.Decision() != test.decision {
				t.Fatalf("boundary report changed: %+v", report)
			}
			if test.decision == Admitted {
				if permit.IsZero() || permit.Decision() != Admitted || permit.Maturity() != ArtifactCapacityOnlyUnverified ||
					plan.ValidatePermit(snapshot, permit) != nil {
					t.Fatalf("admitted boundary did not issue a valid permit: %+v", permit)
				}
			} else if !permit.IsZero() {
				t.Fatalf("blocked boundary issued a permit: %+v", permit)
			}
		})
	}
}

func TestGaoN16ArtifactCapacityIncludesConstructionTransientAndGuard(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGaoN16ArtifactCapacityPlan(profile, DefaultGaoN16ArtifactShape(), DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		available    uint64
		residentOnly bool
		projected    uint64
	}{
		{
			name:      "resident fits but non-streaming transient does not",
			available: 23558324789, residentOnly: true,
			projected: 65193720599,
		},
		{
			name:      "peak fits by one byte but guard does not",
			available: 31955321397,
			projected: 56796723991,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := PhysicalMemorySnapshot{
				SnapshotID:             "component-bound-" + test.name,
				TotalPhysicalBytes:     68719476736,
				AvailablePhysicalBytes: test.available,
			}
			report, permit, evalErr := plan.Evaluate(snapshot)
			var blocked *ErrArtifactCapacityBlocked
			withoutRequiredComponent := report.CurrentSystemUsedBytes() + report.ProjectedIncrementalPeakBytes()
			if test.residentOnly {
				withoutRequiredComponent = report.CurrentSystemUsedBytes() + report.ResidentArtifactBytes()
			}
			if !errors.As(evalErr, &blocked) || report.Decision() != ResourceBlocked || !permit.IsZero() ||
				report.CapacityLimitBytes() != 54975581388 ||
				withoutRequiredComponent != report.CapacityLimitBytes()-1 ||
				report.ProjectedSystemUsedBytes() != test.projected {
				t.Fatalf("transient/guard capacity component was omitted: report=%+v err=%v", report, evalErr)
			}
		})
	}
}

func TestGaoN16ArtifactCapacitySealsReportPermitAndDefensiveCopies(t *testing.T) {
	params, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewGaoN16(params)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGaoN16ArtifactCapacityPlan(profile, DefaultGaoN16ArtifactShape(), DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "admitted-permit-fixture",
		TotalPhysicalBytes:     68719476736,
		AvailablePhysicalBytes: 33776464001,
	}
	report, permit, err := plan.Evaluate(snapshot)
	if err != nil || report.Decision() != Admitted || permit.IsZero() ||
		permit.ParameterDigest() != profile.ParameterDigest() {
		t.Fatalf("admitted fixture failed: report=%+v permit=%+v err=%v", report, permit, err)
	}
	if err = plan.ValidateReport(snapshot, report); err != nil {
		t.Fatalf("original report failed validation: %v", err)
	}
	if err = plan.ValidatePermit(snapshot, permit); err != nil {
		t.Fatalf("original permit failed validation: %v", err)
	}

	reportMutations := []struct {
		name   string
		mutate func(*CapacityReport)
	}{
		{name: "zero", mutate: func(value *CapacityReport) { *value = CapacityReport{} }},
		{name: "maturity", mutate: func(value *CapacityReport) { value.maturity = ParameterCandidateUnverified }},
		{name: "decision", mutate: func(value *CapacityReport) { value.decision = ResourceBlocked }},
		{name: "plan", mutate: func(value *CapacityReport) { value.planDigest = "foreign" }},
		{name: "parameter", mutate: func(value *CapacityReport) { value.parameterDigest = "foreign" }},
		{name: "profile", mutate: func(value *CapacityReport) { value.profileDigest = "foreign" }},
		{name: "shape", mutate: func(value *CapacityReport) { value.shapeDigest = "foreign" }},
		{name: "policy", mutate: func(value *CapacityReport) { value.policyDigest = "foreign" }},
		{name: "probe", mutate: func(value *CapacityReport) { value.probeDigest = "foreign" }},
		{name: "snapshot", mutate: func(value *CapacityReport) { value.snapshot.SnapshotID = "foreign" }},
		{name: "current use", mutate: func(value *CapacityReport) { value.currentSystemUsedBytes++ }},
		{name: "limit", mutate: func(value *CapacityReport) { value.capacityLimitBytes++ }},
		{name: "resident", mutate: func(value *CapacityReport) { value.residentArtifactBytes++ }},
		{name: "peak", mutate: func(value *CapacityReport) { value.projectedIncrementalPeakBytes++ }},
		{name: "guard", mutate: func(value *CapacityReport) { value.guardBytes++ }},
		{name: "projected", mutate: func(value *CapacityReport) { value.projectedSystemUsedBytes++ }},
		{name: "remaining", mutate: func(value *CapacityReport) { value.remainingBytes++ }},
		{name: "seal", mutate: func(value *CapacityReport) { value.digest = "foreign" }},
	}
	for _, test := range reportMutations {
		t.Run("report "+test.name, func(t *testing.T) {
			changed := report
			test.mutate(&changed)
			var blocked *ErrArtifactCapacityBlocked
			if validateErr := plan.ValidateReport(snapshot, changed); !errors.As(validateErr, &blocked) {
				t.Fatalf("tampered report error=%v, want typed ErrArtifactCapacityBlocked", validateErr)
			}
		})
	}

	permitMutations := []struct {
		name   string
		mutate func(*CapacityPermit)
	}{
		{name: "zero", mutate: func(value *CapacityPermit) { *value = CapacityPermit{} }},
		{name: "schema", mutate: func(value *CapacityPermit) { value.schema = "foreign" }},
		{name: "maturity", mutate: func(value *CapacityPermit) { value.maturity = ParameterCandidateUnverified }},
		{name: "decision", mutate: func(value *CapacityPermit) { value.decision = ResourceBlocked }},
		{name: "plan", mutate: func(value *CapacityPermit) { value.planDigest = "foreign" }},
		{name: "parameter", mutate: func(value *CapacityPermit) { value.parameterDigest = "foreign" }},
		{name: "profile", mutate: func(value *CapacityPermit) { value.profileDigest = "foreign" }},
		{name: "shape", mutate: func(value *CapacityPermit) { value.shapeDigest = "foreign" }},
		{name: "policy", mutate: func(value *CapacityPermit) { value.policyDigest = "foreign" }},
		{name: "probe", mutate: func(value *CapacityPermit) { value.probeDigest = "foreign" }},
		{name: "report", mutate: func(value *CapacityPermit) { value.reportDigest = "foreign" }},
		{name: "seal", mutate: func(value *CapacityPermit) { value.sealDigest = "foreign" }},
	}
	for _, test := range permitMutations {
		t.Run("permit "+test.name, func(t *testing.T) {
			changed := permit
			test.mutate(&changed)
			var blocked *ErrArtifactCapacityBlocked
			if validateErr := plan.ValidatePermit(snapshot, changed); !errors.As(validateErr, &blocked) {
				t.Fatalf("tampered permit error=%v, want typed ErrArtifactCapacityBlocked", validateErr)
			}
		})
	}

	staleSnapshots := []PhysicalMemorySnapshot{
		{SnapshotID: "newer-snapshot", TotalPhysicalBytes: snapshot.TotalPhysicalBytes, AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes},
		{SnapshotID: snapshot.SnapshotID, TotalPhysicalBytes: snapshot.TotalPhysicalBytes, AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes + 1},
		{SnapshotID: snapshot.SnapshotID, TotalPhysicalBytes: snapshot.TotalPhysicalBytes + 1, AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes},
	}
	for index, stale := range staleSnapshots {
		t.Run("stale snapshot "+string(rune('A'+index)), func(t *testing.T) {
			var blocked *ErrArtifactCapacityBlocked
			if validateErr := plan.ValidatePermit(stale, permit); !errors.As(validateErr, &blocked) {
				t.Fatalf("stale permit error=%v, want typed ErrArtifactCapacityBlocked", validateErr)
			}
		})
	}

	shapeCopy := plan.Shape()
	shapeCopy.stcFactorDiagonalCounts[0] = 1
	shapeCopy.ctsFactorDiagonalCounts[0] = 1
	if !reflect.DeepEqual(plan.Shape().STCFactorDiagonalCounts(), []uint64{255, 256}) ||
		!reflect.DeepEqual(plan.Shape().CTSFactorDiagonalCounts(), []uint64{32, 63, 63}) {
		t.Fatal("Shape accessor exposed mutable factor slices")
	}
	artifactsCopy := plan.ArtifactEstimates()
	artifactsCopy[0].residentBytes++
	for index := range artifactsCopy {
		counts := artifactsCopy[index].FactorDiagonalCounts()
		if len(counts) != 0 {
			counts[0]++
		}
	}
	stagesCopy := plan.StageEstimates()
	stagesCopy[0].projectedIncrementalBytes++
	if plan.ArtifactEstimates()[0].ResidentBytes() != 301989888 ||
		plan.StageEstimates()[0].ProjectedIncrementalBytes() != 18211426048 ||
		plan.ValidateReport(snapshot, report) != nil || plan.ValidatePermit(snapshot, permit) != nil {
		t.Fatal("detached estimate accessors changed sealed plan/report/permit state")
	}
}
