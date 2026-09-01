package secureeval

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sync"
	"testing"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/ring/ringqp"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type smallRouteBLiveFixture struct {
	authority              *RouteBAuthority
	permit                 ArtifactBuildPermit
	receipt                ArtifactBuildReceipt
	artifact               RouteBArtifact
	params                 ckks.Parameters
	stcLiteral, ctsLiteral dft.MatrixLiteral
	stcProfile, ctsProfile rbdftFactorProfile
}

func newSmallRouteBLiveFixture(
	t *testing.T,
	sampler *scriptedPhysicalMemorySampler,
) smallRouteBLiveFixture {
	t.Helper()
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
	builder := func(prepared bootstrapping.PreparedParameters, buildPermitIdentity RBAUTHDigest) (routeBArtifactBuildProduct, error) {
		return buildRouteBArtifactFromPlan(routeBArtifactBuildPlan{
			params: params, stcLiteral: stcLiteral, ctsLiteral: ctsLiteral,
			stcProfile: stcProfile, ctsProfile: ctsProfile,
			buildPermitIdentity:       buildPermitIdentity,
			preparedParameterIdentity: RBAUTHDigest(prepared.Digest()),
			peakRSS:                   func() (uint64, error) { return 44_444_444, nil },
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
	return smallRouteBLiveFixture{
		authority: authority, permit: permit, receipt: receipt, artifact: artifact,
		params: params, stcLiteral: stcLiteral, ctsLiteral: ctsLiteral,
		stcProfile: stcProfile, ctsProfile: ctsProfile,
	}
}

func (fixture smallRouteBLiveFixture) residentValidator(calls *int) routeBResidentArtifactValidator {
	return func(
		cell *routeBArtifactCell,
		receipt ArtifactBuildReceipt,
		_ bootstrapping.PreparedParameters,
	) (RBAUTHActualPayload, RBAUTHDigest, error) {
		*calls++
		return validateRouteBResidentArtifactWithPlan(
			cell.stc, cell.cts, cell.records, receipt.report,
			routeBResidentArtifactPlan{
				params: fixture.params, stcLiteral: fixture.stcLiteral, ctsLiteral: fixture.ctsLiteral,
				stcProfile: fixture.stcProfile, ctsProfile: fixture.ctsProfile,
			},
		)
	}
}

func TestRouteBAuthorityAuthorizeReadyRehashesResidentArtifactAfterCAS(t *testing.T) {
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
		{totals: physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}},
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
	}}
	fixture := newSmallRouteBLiveFixture(t, sampler)
	receiptCopy, artifactCopy := fixture.receipt, fixture.artifact
	residentCalls := 0
	spec, readyPermit, err := fixture.authority.authorizeReadyWithValidator(
		fixture.permit, fixture.receipt, fixture.artifact, fixture.residentValidator(&residentCalls),
	)
	if err != nil {
		t.Fatal(err)
	}
	if readyPermit.IsZero() || spec != readyPermit.Report().Spec || residentCalls != 1 ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageReady) ||
		fixture.permit.lineage.lastConsumedGeneration.Load() != 3 || fixture.artifact.IsZero() {
		t.Fatalf("ready state/permit/calls/generation/artifact=%d/%v/%d/%d/%v",
			fixture.permit.lineage.state.Load(), readyPermit.IsZero(), residentCalls,
			fixture.permit.lineage.lastConsumedGeneration.Load(), fixture.artifact.IsZero())
	}
	if spec.ActualPayload != fixture.receipt.Report().Payload ||
		spec.BuildReceiptDigest != fixture.permit.lineage.buildReceiptIdentity ||
		spec.ArtifactPairManifestDigest != fixture.permit.lineage.artifactPairManifestIdentity ||
		fixture.permit.lineage.readySpecIdentity == (RBAUTHDigest{}) ||
		fixture.permit.lineage.readyPermitIdentity == (RBAUTHDigest{}) {
		t.Fatal("ready specification or private anchors changed")
	}
	runtimeEvidence := readyPermit.RuntimeCapacityEvidence()
	if err = runtimeEvidence.Validate(); err != nil || runtimeEvidence.Operation != routeBRuntimeOperationAuthorizeReady ||
		runtimeEvidence.Generation != 3 || runtimeEvidence.Digest != fixture.permit.lineage.readyUseCapacityEvidenceIdentity {
		t.Fatalf("ready runtime-capacity evidence changed: %+v/%v", runtimeEvidence, err)
	}
	readyRecord, err := readyPermit.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReadyPermit(readyRecord)
	if err != nil || parsed != readyPermit.Report() {
		t.Fatalf("ready permit inert round trip=%+v/%v", parsed, err)
	}
	if secondSpec, secondPermit, secondErr := fixture.authority.authorizeReadyWithValidator(
		fixture.permit, receiptCopy, artifactCopy, fixture.residentValidator(&residentCalls),
	); !errors.Is(secondErr, ErrRBAUTHLineage) || secondSpec != (ReadySpec{}) || !secondPermit.IsZero() || residentCalls != 1 {
		t.Fatalf("Ready reuse returned spec/permit/calls/error=%+v/%v/%d/%v",
			secondSpec, secondPermit.IsZero(), residentCalls, secondErr)
	}
}

func TestRouteBAuthorityAuthorizeReadyCapacityBlockPrecedesResidentRead(t *testing.T) {
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
		{totals: physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}},
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 1}},
	}}
	fixture := newSmallRouteBLiveFixture(t, sampler)
	residentCalls := 0
	spec, readyPermit, err := fixture.authority.authorizeReadyWithValidator(
		fixture.permit, fixture.receipt, fixture.artifact, fixture.residentValidator(&residentCalls),
	)
	if !errors.Is(err, ErrRBAUTHBlocked) || spec != (ReadySpec{}) || !readyPermit.IsZero() || residentCalls != 0 {
		t.Fatalf("blocked Ready returned spec/permit/read/error=%+v/%v/%d/%v", spec, readyPermit.IsZero(), residentCalls, err)
	}
	if fixture.permit.lineage.state.Load() != uint32(routeBLineagePrivateUninstalled) ||
		fixture.permit.lineage.lastConsumedGeneration.Load() != 2 || fixture.artifact.IsZero() ||
		fixture.authority.cell.prepareCalls.Load() != 2 {
		t.Fatalf("blocked Ready state/generation/artifact/prepare=%d/%d/%v/%d",
			fixture.permit.lineage.state.Load(), fixture.permit.lineage.lastConsumedGeneration.Load(),
			fixture.artifact.IsZero(), fixture.authority.cell.prepareCalls.Load())
	}
}

func TestRouteBAuthorityAuthorizeReadyResidentMutationIsTerminal(t *testing.T) {
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
		{totals: physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}},
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
	}}
	fixture := newSmallRouteBLiveFixture(t, sampler)
	transformation := fixture.artifact.cell.stc.Matrices[0]
	rbdftMutateFirstTestPoly(&transformation, func(poly *ringqp.Poly) { poly.Q.Coeffs[0][0] ^= 1 })
	fixture.artifact.cell.stc.Matrices[0] = transformation
	residentCalls := 0
	spec, readyPermit, err := fixture.authority.authorizeReadyWithValidator(
		fixture.permit, fixture.receipt, fixture.artifact, fixture.residentValidator(&residentCalls),
	)
	if err == nil || spec != (ReadySpec{}) || !readyPermit.IsZero() || residentCalls != 1 ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageFailed) {
		t.Fatalf("mutated resident Ready spec/permit/read/state/error=%+v/%v/%d/%d/%v",
			spec, readyPermit.IsZero(), residentCalls, fixture.permit.lineage.state.Load(), err)
	}
}

func TestRouteBAuthorityAuthorizeReadyConcurrentCopiesHaveOneResidentReader(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBLiveFixture(t, sampler)
	residentCalls := 0
	validator := fixture.residentValidator(&residentCalls)
	type result struct {
		spec   ReadySpec
		permit ReadyPermit
		err    error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	for range 2 {
		go func() {
			defer workers.Done()
			<-start
			spec, permit, err := fixture.authority.authorizeReadyWithValidator(
				fixture.permit, fixture.receipt, fixture.artifact, validator,
			)
			results <- result{spec: spec, permit: permit, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	successes, lineageFailures := 0, 0
	for value := range results {
		switch {
		case value.err == nil && value.spec != (ReadySpec{}) && !value.permit.IsZero():
			successes++
		case errors.Is(value.err, ErrRBAUTHLineage) && value.spec == (ReadySpec{}) && value.permit.IsZero():
			lineageFailures++
		default:
			t.Fatalf("unexpected concurrent Ready result: spec=%+v permit-zero=%v err=%v", value.spec, value.permit.IsZero(), value.err)
		}
	}
	if successes != 1 || lineageFailures != 1 || residentCalls != 1 ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageReady) {
		t.Fatalf("concurrent Ready success/lineage/read/state=%d/%d/%d/%d",
			successes, lineageFailures, residentCalls, fixture.permit.lineage.state.Load())
	}
}

func TestRouteBAuthorityAuthorizeReadyRejectsForeignLiveInputsBeforeSampling(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	leftSampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{admitted, admitted}}
	rightSampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{admitted, admitted}}
	left := newSmallRouteBLiveFixture(t, leftSampler)
	right := newSmallRouteBLiveFixture(t, rightSampler)
	leftCallsBefore := leftSampler.calls
	residentCalls := 0
	spec, permit, err := left.authority.authorizeReadyWithValidator(
		left.permit, right.receipt, right.artifact, left.residentValidator(&residentCalls),
	)
	if !errors.Is(err, ErrRBAUTHLineage) || spec != (ReadySpec{}) || !permit.IsZero() ||
		residentCalls != 0 || leftSampler.calls != leftCallsBefore ||
		left.authority.cell.prepareCalls.Load() != 2 {
		t.Fatalf("foreign Ready spec/permit/read/sample/prepare/error=%+v/%v/%d/%d/%d/%v",
			spec, permit.IsZero(), residentCalls, leftSampler.calls, left.authority.cell.prepareCalls.Load(), err)
	}
}

func TestRouteBAuthorityAuthorizeReadyPublicSurfaceAndGateOrder(t *testing.T) {
	authorityType := reflect.TypeOf((*RouteBAuthority)(nil))
	method, ok := authorityType.MethodByName("AuthorizeReady")
	if !ok || method.Type.NumIn() != 4 || method.Type.In(1) != reflect.TypeOf(ArtifactBuildPermit{}) ||
		method.Type.In(2) != reflect.TypeOf(ArtifactBuildReceipt{}) ||
		method.Type.In(3) != reflect.TypeOf(RouteBArtifact{}) || method.Type.NumOut() != 3 ||
		method.Type.Out(0) != reflect.TypeOf(ReadySpec{}) || method.Type.Out(1) != reflect.TypeOf(ReadyPermit{}) {
		t.Fatalf("AuthorizeReady public surface changed: present=%v type=%v", ok, method.Type)
	}
	for index := 0; index < reflect.TypeOf(ReadyPermit{}).NumField(); index++ {
		if reflect.TypeOf(ReadyPermit{}).Field(index).IsExported() {
			t.Fatalf("ReadyPermit exposes field %s", reflect.TypeOf(ReadyPermit{}).Field(index).Name)
		}
	}

	parsed, err := parser.ParseFile(token.NewFileSet(), "route_b_ready.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if isFunction && function.Recv != nil && function.Name.Name == "authorizeReadyWithValidator" {
			target = function
			break
		}
	}
	if target == nil {
		t.Fatal("authorizeReadyWithValidator declaration is missing")
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
	sample, prepare := indexOf("sampleAndEvaluateCapacity"), indexOf("prepareStoredParametersValue")
	transition, residentRead := indexOf("CompareAndSwap"), indexOf("validator")
	if sample < 0 || prepare <= sample || transition <= prepare || residentRead <= transition {
		t.Fatalf("AuthorizeReady gate order changed: calls=%v", calls)
	}
}
