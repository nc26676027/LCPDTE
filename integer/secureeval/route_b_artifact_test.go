package secureeval

import (
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/ring/ringqp"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestRouteBArtifactBuilderSmallProfileProducesLinkedPrivateProduct(t *testing.T) {
	params := rbdftTestParameters(t)
	stcLiteral, stcProfile := rbdftSmallObservedContract(t, params, dft.ObservedSlotsToCoeffs)
	ctsLiteral, ctsProfile := rbdftSmallObservedContract(t, params, dft.ObservedCoeffsToSlots)
	buildPermitIdentity := RBAUTHDigest(sha256.Sum256([]byte("small-build-permit")))
	preparedIdentity := RBAUTHDigest(sha256.Sum256([]byte("small-prepared-parameters")))

	product, err := buildRouteBArtifactFromPlan(routeBArtifactBuildPlan{
		params: params, stcLiteral: stcLiteral, ctsLiteral: ctsLiteral,
		stcProfile: stcProfile, ctsProfile: ctsProfile,
		buildPermitIdentity: buildPermitIdentity, preparedParameterIdentity: preparedIdentity,
		peakRSS: func() (uint64, error) { return 12_345_678, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateRBDFTBuildRecordLinks(product.records, buildPermitIdentity, preparedIdentity); err != nil {
		t.Fatalf("validate linked build records: %v", err)
	}
	parsedReceipt, err := ParseRBDFTBuildReceipt(product.records.BuildReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if parsedReceipt != product.receipt || parsedReceipt.Payload != product.payload ||
		parsedReceipt.BuildPeakRSSBytes != 12_345_678 || parsedReceipt.BuildWallNanoseconds == 0 ||
		parsedReceipt.DefaultCounterDelta != 0 || parsedReceipt.ExplicitWholeCounterDelta != 0 ||
		parsedReceipt.RawNumericCounterDelta != 0 || parsedReceipt.ObservedStreamingCounterDelta != 2 {
		t.Fatalf("small receipt changed: %+v", parsedReceipt)
	}
	if err = product.stc.ValidateAgainst(params, stcLiteral); err != nil {
		t.Fatalf("validate private STC matrix: %v", err)
	}
	if err = product.cts.ValidateAgainst(params, ctsLiteral); err != nil {
		t.Fatalf("validate private CTS matrix: %v", err)
	}
	residentPlan := routeBResidentArtifactPlan{
		params: params, stcLiteral: stcLiteral, ctsLiteral: ctsLiteral,
		stcProfile: stcProfile, ctsProfile: ctsProfile,
	}
	beforeRehash := dft.SnapshotMatrixConstructionCounters()
	residentPayload, residentPair, err := validateRouteBResidentArtifactWithPlan(
		product.stc, product.cts, product.records, product.receipt, residentPlan,
	)
	if err != nil || residentPayload != product.payload || residentPair != product.receipt.ArtifactManifestDigest {
		t.Fatalf("resident rehash payload/pair/error=%+v/%x/%v", residentPayload, residentPair, err)
	}
	afterRehash := dft.SnapshotMatrixConstructionCounters()
	rehashDelta, err := afterRehash.Delta(beforeRehash)
	if err != nil || rehashDelta.DefaultWhole() != 0 || rehashDelta.ExplicitWhole() != 0 ||
		rehashDelta.RawNumeric() != 0 || rehashDelta.ObservedStreaming() != 0 {
		t.Fatalf("resident rehash constructed DFT state=%d/%d/%d/%d err=%v",
			rehashDelta.DefaultWhole(), rehashDelta.ExplicitWhole(), rehashDelta.RawNumeric(),
			rehashDelta.ObservedStreaming(), err)
	}
	mutated := product.stc.Matrices[0]
	rbdftMutateFirstTestPoly(&mutated, func(poly *ringqp.Poly) { poly.Q.Coeffs[0][0] ^= 1 })
	product.stc.Matrices[0] = mutated
	if _, _, err = validateRouteBResidentArtifactWithPlan(
		product.stc, product.cts, product.records, product.receipt, residentPlan,
	); err == nil {
		t.Fatal("one-coefficient resident mutation passed rehash")
	}
	assertRouteBArtifactRecordSetIsDetached(t, product)
}

func assertRouteBArtifactRecordSetIsDetached(t *testing.T, product routeBArtifactBuildProduct) {
	t.Helper()
	copyOfRecords := cloneRBDFTBuildRecordSet(product.records)
	copyOfRecords.STCNumericAggregate[0] ^= 1
	copyOfRecords.BuildReceipt[0] ^= 1
	if product.records.STCNumericAggregate[0] == copyOfRecords.STCNumericAggregate[0] ||
		product.records.BuildReceipt[0] == copyOfRecords.BuildReceipt[0] {
		t.Fatal("record-set clone aliases the private build product")
	}
}

func TestRouteBArtifactBuildPlanRejectsInvalidInputsBeforeConstruction(t *testing.T) {
	params := rbdftTestParameters(t)
	stcLiteral, stcProfile := rbdftSmallObservedContract(t, params, dft.ObservedSlotsToCoeffs)
	ctsLiteral, ctsProfile := rbdftSmallObservedContract(t, params, dft.ObservedCoeffsToSlots)
	valid := routeBArtifactBuildPlan{
		params: params, stcLiteral: stcLiteral, ctsLiteral: ctsLiteral,
		stcProfile: stcProfile, ctsProfile: ctsProfile,
		buildPermitIdentity:       RBAUTHDigest(sha256.Sum256([]byte("small-build-permit"))),
		preparedParameterIdentity: RBAUTHDigest(sha256.Sum256([]byte("small-prepared-parameters"))),
		peakRSS:                   func() (uint64, error) { return 1, nil },
	}
	tests := []struct {
		name   string
		mutate func(*routeBArtifactBuildPlan)
	}{
		{name: "zero parameters", mutate: func(value *routeBArtifactBuildPlan) { value.params = ckks.Parameters{} }},
		{name: "zero build identity", mutate: func(value *routeBArtifactBuildPlan) { value.buildPermitIdentity = RBAUTHDigest{} }},
		{name: "zero prepared identity", mutate: func(value *routeBArtifactBuildPlan) { value.preparedParameterIdentity = RBAUTHDigest{} }},
		{name: "nil RSS sampler", mutate: func(value *routeBArtifactBuildPlan) { value.peakRSS = nil }},
		{name: "swapped STC role", mutate: func(value *routeBArtifactBuildPlan) { value.stcProfile = ctsProfile }},
		{name: "swapped CTS role", mutate: func(value *routeBArtifactBuildPlan) { value.ctsProfile = stcProfile }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := valid
			test.mutate(&plan)
			before := dft.SnapshotMatrixConstructionCounters()
			product, err := buildRouteBArtifactFromPlan(plan)
			if err == nil || !product.isZero() {
				t.Fatalf("invalid plan returned product/error=%+v/%v", product, err)
			}
			after := dft.SnapshotMatrixConstructionCounters()
			delta, deltaErr := after.Delta(before)
			if deltaErr != nil || delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 ||
				delta.RawNumeric() != 0 || delta.ObservedStreaming() != 0 {
				t.Fatalf("invalid plan construction delta=%d/%d/%d/%d err=%v",
					delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(), deltaErr)
			}
		})
	}
}

func TestRouteBAuthorityBeginBuildCapacityBlockPrecedesConstruction(t *testing.T) {
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 1}},
	}}
	authority, err := newRouteBAuthorityWithSampler(sampler)
	if err != nil {
		t.Fatal(err)
	}
	_, permit, err := authority.AuthorizeBuild()
	if err != nil {
		t.Fatal(err)
	}
	receipt, artifact, err := authority.BeginBuild(permit)
	if !errors.Is(err, ErrRBAUTHBlocked) || !receipt.IsZero() || !artifact.IsZero() {
		t.Fatalf("blocked BeginBuild returned receipt/artifact/error=%+v/%+v/%v", receipt, artifact, err)
	}
	if permit.lineage.state.Load() != uint32(routeBLineageAuthorized) || authority.cell.generation != 2 ||
		authority.cell.sampleCalls.Load() != 2 || authority.cell.capacityEvaluationCalls.Load() != 2 ||
		authority.cell.prepareCalls.Load() != 1 {
		t.Fatalf("blocked BeginBuild state/generation/sample/capacity/prepare=%d/%d/%d/%d/%d",
			permit.lineage.state.Load(), authority.cell.generation, authority.cell.sampleCalls.Load(),
			authority.cell.capacityEvaluationCalls.Load(), authority.cell.prepareCalls.Load())
	}
}

func TestRouteBAuthorityBeginBuildSmallPrivateSuccessIsOneShot(t *testing.T) {
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
		{totals: physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}},
	}}
	authority, err := newRouteBAuthorityWithSampler(sampler)
	if err != nil {
		t.Fatal(err)
	}
	_, permit, err := authority.AuthorizeBuild()
	if err != nil {
		t.Fatal(err)
	}
	permitCopy := permit

	params := rbdftTestParameters(t)
	stcLiteral, stcProfile := rbdftSmallObservedContract(t, params, dft.ObservedSlotsToCoeffs)
	ctsLiteral, ctsProfile := rbdftSmallObservedContract(t, params, dft.ObservedCoeffsToSlots)
	buildCalls := 0
	builder := func(prepared bootstrapping.PreparedParameters, buildPermitIdentity RBAUTHDigest) (routeBArtifactBuildProduct, error) {
		buildCalls++
		return buildRouteBArtifactFromPlan(routeBArtifactBuildPlan{
			params: params, stcLiteral: stcLiteral, ctsLiteral: ctsLiteral,
			stcProfile: stcProfile, ctsProfile: ctsProfile,
			buildPermitIdentity:       buildPermitIdentity,
			preparedParameterIdentity: RBAUTHDigest(prepared.Digest()),
			peakRSS:                   func() (uint64, error) { return 22_222_222, nil },
		})
	}
	validator := func(product routeBArtifactBuildProduct, _ bootstrapping.PreparedParameters) error {
		if err := product.stc.ValidateAgainst(params, stcLiteral); err != nil {
			return err
		}
		return product.cts.ValidateAgainst(params, ctsLiteral)
	}
	receipt, artifact, err := authority.beginBuildWithBuilder(permit, builder, validator)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.IsZero() || artifact.IsZero() || buildCalls != 1 ||
		receipt.lineage != permit.lineage || artifact.cell.lineage != permit.lineage ||
		permit.lineage.state.Load() != uint32(routeBLineagePrivateUninstalled) ||
		permit.lineage.lastConsumedGeneration.Load() != 2 {
		t.Fatalf("successful BeginBuild live state changed: receipt=%v artifact=%v calls=%d state=%d generation=%d",
			receipt.IsZero(), artifact.IsZero(), buildCalls, permit.lineage.state.Load(),
			permit.lineage.lastConsumedGeneration.Load())
	}
	if receipt.Report().BuildPeakRSSBytes != 22_222_222 ||
		receipt.Report().ArtifactManifestDigest != permit.lineage.artifactPairManifestIdentity ||
		permit.lineage.buildReceiptIdentity == (RBAUTHDigest{}) ||
		permit.lineage.actualPayload != receipt.Report().Payload {
		t.Fatal("successful BeginBuild receipt anchors changed")
	}
	runtimeEvidence := receipt.RuntimeCapacityEvidence()
	if err = runtimeEvidence.Validate(); err != nil || runtimeEvidence.Operation != routeBRuntimeOperationBeginBuild ||
		runtimeEvidence.Generation != 2 || runtimeEvidence.Digest != permit.lineage.buildUseCapacityEvidenceIdentity {
		t.Fatalf("build runtime-capacity evidence changed: %+v/%v", runtimeEvidence, err)
	}
	records := receipt.Records()
	if err = ValidateRBDFTBuildRecordLinks(
		records, permit.lineage.buildPermitIdentity, permit.Report().Spec.PreparedParameterDigest,
	); err != nil {
		t.Fatal(err)
	}
	marshaled, err := receipt.MarshalBinary()
	if err != nil || !reflect.DeepEqual(marshaled, records.BuildReceipt) {
		t.Fatalf("live receipt marshal mismatch: %v", err)
	}
	records.BuildReceipt[0] ^= 1
	if fresh := receipt.Records(); fresh.BuildReceipt[0] == records.BuildReceipt[0] {
		t.Fatal("live receipt exposes mutable record backing")
	}

	secondReceipt, secondArtifact, secondErr := authority.beginBuildWithBuilder(permitCopy, builder, validator)
	if !errors.Is(secondErr, ErrRBAUTHLineage) || !secondReceipt.IsZero() || !secondArtifact.IsZero() || buildCalls != 1 {
		t.Fatalf("copied permit reuse returned receipt/artifact/calls/error=%v/%v/%d/%v",
			secondReceipt.IsZero(), secondArtifact.IsZero(), buildCalls, secondErr)
	}
}

func TestRouteBAuthorityBeginBuildRejectsTamperedAndForeignPermitsBeforeSampling(t *testing.T) {
	firstSampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}}}
	first, err := newRouteBAuthorityWithSampler(firstSampler)
	if err != nil {
		t.Fatal(err)
	}
	_, permit, err := first.AuthorizeBuild()
	if err != nil {
		t.Fatal(err)
	}
	mutated := permit
	mutated.report.Spec.BuilderID = "tampered-builder"
	called := false
	builder := func(bootstrapping.PreparedParameters, RBAUTHDigest) (routeBArtifactBuildProduct, error) {
		called = true
		return routeBArtifactBuildProduct{}, errors.New("must not run")
	}
	validator := func(routeBArtifactBuildProduct, bootstrapping.PreparedParameters) error {
		called = true
		return errors.New("must not run")
	}
	if receipt, artifact, buildErr := first.beginBuildWithBuilder(mutated, builder, validator); buildErr == nil || !receipt.IsZero() || !artifact.IsZero() || called {
		t.Fatalf("tampered permit reached build side effects: receipt/artifact/called/error=%v/%v/%v/%v",
			receipt.IsZero(), artifact.IsZero(), called, buildErr)
	}
	if firstSampler.calls != 1 || first.cell.prepareCalls.Load() != 1 ||
		permit.lineage.state.Load() != uint32(routeBLineageAuthorized) {
		t.Fatalf("tampered permit changed sampler/prepare/state=%d/%d/%d",
			firstSampler.calls, first.cell.prepareCalls.Load(), permit.lineage.state.Load())
	}

	foreignSampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}}}
	foreign, err := newRouteBAuthorityWithSampler(foreignSampler)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, artifact, buildErr := foreign.beginBuildWithBuilder(permit, builder, validator); !errors.Is(buildErr, ErrRBAUTHLineage) || !receipt.IsZero() || !artifact.IsZero() || called {
		t.Fatalf("foreign permit returned receipt/artifact/called/error=%v/%v/%v/%v",
			receipt.IsZero(), artifact.IsZero(), called, buildErr)
	}
	if foreignSampler.calls != 0 || foreign.cell.prepareCalls.Load() != 0 {
		t.Fatalf("foreign permit sampled or prepared=%d/%d", foreignSampler.calls, foreign.cell.prepareCalls.Load())
	}
}

func TestRouteBAuthorityBeginBuildFailureAndPanicAreTerminal(t *testing.T) {
	for _, test := range []struct {
		name    string
		builder func(error) routeBArtifactBuilder
	}{
		{name: "error", builder: func(sentinel error) routeBArtifactBuilder {
			return func(bootstrapping.PreparedParameters, RBAUTHDigest) (routeBArtifactBuildProduct, error) {
				return routeBArtifactBuildProduct{}, sentinel
			}
		}},
		{name: "panic", builder: func(error) routeBArtifactBuilder {
			return func(bootstrapping.PreparedParameters, RBAUTHDigest) (routeBArtifactBuildProduct, error) {
				panic("builder panic sentinel")
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
				{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
				{totals: physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}},
			}}
			authority, err := newRouteBAuthorityWithSampler(sampler)
			if err != nil {
				t.Fatal(err)
			}
			_, permit, err := authority.AuthorizeBuild()
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("builder error sentinel")
			validatorCalled := false
			receipt, artifact, buildErr := authority.beginBuildWithBuilder(
				permit, test.builder(sentinel),
				func(routeBArtifactBuildProduct, bootstrapping.PreparedParameters) error {
					validatorCalled = true
					return nil
				},
			)
			if buildErr == nil || !receipt.IsZero() || !artifact.IsZero() || validatorCalled ||
				permit.lineage.state.Load() != uint32(routeBLineageFailed) ||
				permit.lineage.lastConsumedGeneration.Load() != 2 ||
				permit.lineage.buildUseCapacityEvidenceIdentity == (RBAUTHDigest{}) ||
				permit.lineage.buildReceiptIdentity != (RBAUTHDigest{}) {
				t.Fatalf("terminal failure receipt/artifact/validator/state/generation/error=%v/%v/%v/%d/%d/%v",
					receipt.IsZero(), artifact.IsZero(), validatorCalled, permit.lineage.state.Load(),
					permit.lineage.lastConsumedGeneration.Load(), buildErr)
			}
			if test.name == "error" && !errors.Is(buildErr, sentinel) {
				t.Fatalf("builder sentinel was not preserved: %v", buildErr)
			}
			if secondReceipt, secondArtifact, secondErr := authority.beginBuildWithBuilder(
				permit, test.builder(sentinel), func(routeBArtifactBuildProduct, bootstrapping.PreparedParameters) error { return nil },
			); !errors.Is(secondErr, ErrRBAUTHLineage) || !secondReceipt.IsZero() || !secondArtifact.IsZero() {
				t.Fatalf("failed lineage was reusable: %v/%v/%v", secondReceipt.IsZero(), secondArtifact.IsZero(), secondErr)
			}
		})
	}
}

func TestRouteBAuthorityConcurrentBeginBuildCopiesHaveOneBuilder(t *testing.T) {
	const attempts = 2
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
		{totals: physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}},
		{totals: physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}},
	}}
	authority, err := newRouteBAuthorityWithSampler(sampler)
	if err != nil {
		t.Fatal(err)
	}
	_, permit, err := authority.AuthorizeBuild()
	if err != nil {
		t.Fatal(err)
	}
	params := rbdftTestParameters(t)
	stcLiteral, stcProfile := rbdftSmallObservedContract(t, params, dft.ObservedSlotsToCoeffs)
	ctsLiteral, ctsProfile := rbdftSmallObservedContract(t, params, dft.ObservedCoeffsToSlots)
	var buildCalls atomic.Uint32
	builder := func(prepared bootstrapping.PreparedParameters, buildPermitIdentity RBAUTHDigest) (routeBArtifactBuildProduct, error) {
		buildCalls.Add(1)
		return buildRouteBArtifactFromPlan(routeBArtifactBuildPlan{
			params: params, stcLiteral: stcLiteral, ctsLiteral: ctsLiteral,
			stcProfile: stcProfile, ctsProfile: ctsProfile,
			buildPermitIdentity:       buildPermitIdentity,
			preparedParameterIdentity: RBAUTHDigest(prepared.Digest()),
			peakRSS:                   func() (uint64, error) { return 33_333_333, nil },
		})
	}
	validator := func(product routeBArtifactBuildProduct, _ bootstrapping.PreparedParameters) error {
		if err := product.stc.ValidateAgainst(params, stcLiteral); err != nil {
			return err
		}
		return product.cts.ValidateAgainst(params, ctsLiteral)
	}
	type outcome struct {
		receipt  ArtifactBuildReceipt
		artifact RouteBArtifact
		err      error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, attempts)
	var wait sync.WaitGroup
	for index := 0; index < attempts; index++ {
		wait.Add(1)
		permitCopy := permit
		go func() {
			defer wait.Done()
			<-start
			receipt, artifact, buildErr := authority.beginBuildWithBuilder(permitCopy, builder, validator)
			outcomes <- outcome{receipt: receipt, artifact: artifact, err: buildErr}
		}()
	}
	close(start)
	wait.Wait()
	close(outcomes)

	successes, lineageFailures := 0, 0
	for outcome := range outcomes {
		switch {
		case outcome.err == nil && !outcome.receipt.IsZero() && !outcome.artifact.IsZero():
			successes++
		case errors.Is(outcome.err, ErrRBAUTHLineage) && outcome.receipt.IsZero() && outcome.artifact.IsZero():
			lineageFailures++
		default:
			t.Fatalf("unexpected concurrent BeginBuild outcome: %+v", outcome)
		}
	}
	if successes != 1 || lineageFailures != 1 || buildCalls.Load() != 1 ||
		permit.lineage.state.Load() != uint32(routeBLineagePrivateUninstalled) {
		t.Fatalf("concurrent BeginBuild successes/lineage/build/state=%d/%d/%d/%d",
			successes, lineageFailures, buildCalls.Load(), permit.lineage.state.Load())
	}
}

func TestRouteBAuthorityBeginBuildPublicSurfaceAndGateOrder(t *testing.T) {
	authorityType := reflect.TypeOf((*RouteBAuthority)(nil))
	method, ok := authorityType.MethodByName("BeginBuild")
	if !ok || method.Type.NumIn() != 2 || method.Type.In(1) != reflect.TypeOf(ArtifactBuildPermit{}) ||
		method.Type.NumOut() != 3 || method.Type.Out(0) != reflect.TypeOf(ArtifactBuildReceipt{}) ||
		method.Type.Out(1) != reflect.TypeOf(RouteBArtifact{}) {
		t.Fatalf("BeginBuild public surface changed: present=%v type=%v", ok, method.Type)
	}
	for _, value := range []reflect.Type{reflect.TypeOf(ArtifactBuildReceipt{}), reflect.TypeOf(RouteBArtifact{})} {
		for index := 0; index < value.NumField(); index++ {
			if value.Field(index).IsExported() {
				t.Fatalf("%s exposes field %s", value, value.Field(index).Name)
			}
		}
	}
	for methodIndex := 0; methodIndex < authorityType.NumMethod(); methodIndex++ {
		method := authorityType.Method(methodIndex)
		for input := 1; input < method.Type.NumIn(); input++ {
			if method.Type.In(input) == reflect.TypeOf(RuntimeCapacityEvidenceReport{}) ||
				method.Type.In(input) == reflect.TypeOf(RBAUTHCapacityBinding{}) ||
				method.Type.In(input) == reflect.TypeOf(physicalMemoryTotals{}) {
				t.Fatalf("Authority method %s accepts capacity evidence input %s", method.Name, method.Type.In(input))
			}
		}
	}

	parsed, err := parser.ParseFile(token.NewFileSet(), "route_b_live_artifact.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if isFunction && function.Recv != nil && function.Name.Name == "beginBuildWithBuilder" {
			target = function
			break
		}
	}
	if target == nil {
		t.Fatal("beginBuildWithBuilder declaration is missing")
	}
	var calls []string
	ast.Inspect(target.Body, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.Ident:
			calls = append(calls, function.Name)
		case *ast.SelectorExpr:
			calls = append(calls, function.Sel.Name)
		}
		return true
	})
	indexOf := func(name string) int {
		for index, call := range calls {
			if call == name {
				return index
			}
		}
		return -1
	}
	sample := indexOf("sampleAndEvaluateCapacity")
	prepare := indexOf("prepareStoredParametersValue")
	transition := indexOf("CompareAndSwap")
	build := indexOf("builder")
	if sample < 0 || prepare <= sample || transition <= prepare || build <= transition {
		t.Fatalf("BeginBuild gate order changed: calls=%v", calls)
	}
	for _, forbidden := range []string{"NewEncoder", "NewEvaluator", "NewKeyGenerator", "GenEvaluationKeys", "NewMatrixFromLiteralWithGeneratorPrecisionObserved"} {
		if indexOf(forbidden) >= 0 {
			t.Fatalf("BeginBuild directly calls forbidden constructor %q: %v", forbidden, calls)
		}
	}
}
