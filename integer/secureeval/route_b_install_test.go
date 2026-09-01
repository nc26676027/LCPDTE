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
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring/ringqp"
)

type smallRouteBReadyFixture struct {
	smallRouteBLiveFixture
	readyPermit ReadyPermit
}

func newSmallRouteBReadyFixture(t *testing.T, sampler *scriptedPhysicalMemorySampler) smallRouteBReadyFixture {
	t.Helper()
	fixture := newSmallRouteBLiveFixture(t, sampler)
	residentCalls := 0
	_, readyPermit, err := fixture.authority.authorizeReadyWithValidator(
		fixture.permit, fixture.receipt, fixture.artifact, fixture.residentValidator(&residentCalls),
	)
	if err != nil || residentCalls != 1 {
		t.Fatalf("authorize small Ready fixture: reads=%d err=%v", residentCalls, err)
	}
	return smallRouteBReadyFixture{smallRouteBLiveFixture: fixture, readyPermit: readyPermit}
}

func (fixture smallRouteBReadyFixture) installHooks(
	residentCalls, keygenCalls, assemblerCalls, installedValidationCalls *int,
) (
	routeBResidentArtifactValidator,
	routeBEvaluationKeyGenerator,
	routeBPrebuiltEvaluatorAssembler,
	routeBInstalledEvaluatorValidator,
) {
	resident := fixture.residentValidator(residentCalls)
	keygen := func(_ bootstrapping.PreparedParameters, secretKey *rlwe.SecretKey) (*bootstrapping.EvaluationKeys, error) {
		*keygenCalls++
		if secretKey == nil {
			return nil, errors.New("nil test secret key")
		}
		return &bootstrapping.EvaluationKeys{}, nil
	}
	assembler := func(
		_ bootstrapping.PreparedParameters,
		cell *routeBArtifactCell,
		donor **bootstrapping.EvaluationKeys,
	) (*bootstrapping.Evaluator, error) {
		*assemblerCalls++
		if cell == nil || len(cell.stc.Matrices) == 0 || len(cell.cts.Matrices) == 0 ||
			donor == nil || *donor == nil {
			return nil, errors.New("test assembler input is empty")
		}
		evaluator := &bootstrapping.Evaluator{S2CDFTMatrix: cell.stc, C2SDFTMatrix: cell.cts}
		cell.stc, cell.cts = dft.Matrix{}, dft.Matrix{}
		*donor = nil
		return evaluator, nil
	}
	installedValidator := func(evaluator *bootstrapping.Evaluator, _ bootstrapping.PreparedParameters) error {
		*installedValidationCalls++
		if evaluator == nil {
			return errors.New("nil installed test evaluator")
		}
		if err := evaluator.S2CDFTMatrix.ValidateAgainst(fixture.params, fixture.stcLiteral); err != nil {
			return err
		}
		return evaluator.C2SDFTMatrix.ValidateAgainst(fixture.params, fixture.ctsLiteral)
	}
	return resident, keygen, assembler, installedValidator
}

func TestRouteBAuthorityInstallMovesReadyArtifactAfterExclusiveGate(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBReadyFixture(t, sampler)
	residentCalls, keygenCalls, assemblerCalls, installedValidationCalls := 0, 0, 0, 0
	resident, keygen, assembler, installedValidator := fixture.installHooks(
		&residentCalls, &keygenCalls, &assemblerCalls, &installedValidationCalls,
	)
	before := dft.SnapshotMatrixConstructionCounters()
	installed, err := fixture.authority.installWithHooks(
		fixture.readyPermit, fixture.receipt, fixture.artifact, new(rlwe.SecretKey),
		resident, keygen, assembler, installedValidator,
	)
	if err != nil {
		t.Fatal(err)
	}
	if installed == nil || installed.IsZero() || !fixture.artifact.IsZero() ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageInstalledUnverified) ||
		fixture.permit.lineage.lastConsumedGeneration.Load() != 4 ||
		residentCalls != 1 || keygenCalls != 1 || assemblerCalls != 1 || installedValidationCalls != 1 {
		t.Fatalf("install ownership/state/generation/calls=%v/%v/%d/%d/%d/%d/%d/%d",
			installed == nil, fixture.artifact.IsZero(), fixture.permit.lineage.state.Load(),
			fixture.permit.lineage.lastConsumedGeneration.Load(), residentCalls, keygenCalls,
			assemblerCalls, installedValidationCalls)
	}
	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil || delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 ||
		delta.RawNumeric() != 0 || delta.ObservedStreaming() != 0 {
		t.Fatalf("install constructor delta=%+v err=%v", delta, err)
	}
	runtimeEvidence := installed.InstallRuntimeCapacityEvidence()
	if err = runtimeEvidence.Validate(); err != nil || runtimeEvidence.Operation != routeBRuntimeOperationInstall ||
		runtimeEvidence.Generation != 4 || runtimeEvidence.Digest != fixture.permit.lineage.installCapacityEvidenceIdentity {
		t.Fatalf("install runtime-capacity evidence=%+v err=%v", runtimeEvidence, err)
	}
	second, secondErr := fixture.authority.installWithHooks(
		fixture.readyPermit, fixture.receipt, fixture.artifact, new(rlwe.SecretKey),
		resident, keygen, assembler, installedValidator,
	)
	if !errors.Is(secondErr, ErrRBAUTHLineage) || second != nil || residentCalls != 1 || keygenCalls != 1 || assemblerCalls != 1 {
		t.Fatalf("reused Install result/read/keygen/assemble/error=%v/%d/%d/%d/%v",
			second, residentCalls, keygenCalls, assemblerCalls, secondErr)
	}
}

func TestRouteBAuthorityInstallCapacityBlockPrecedesResidentReadAndKeygen(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted,
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 1}},
	}}
	fixture := newSmallRouteBReadyFixture(t, sampler)
	residentCalls, keygenCalls, assemblerCalls, installedValidationCalls := 0, 0, 0, 0
	resident, keygen, assembler, installedValidator := fixture.installHooks(
		&residentCalls, &keygenCalls, &assemblerCalls, &installedValidationCalls,
	)
	installed, err := fixture.authority.installWithHooks(
		fixture.readyPermit, fixture.receipt, fixture.artifact, new(rlwe.SecretKey),
		resident, keygen, assembler, installedValidator,
	)
	if !errors.Is(err, ErrRBAUTHBlocked) || installed != nil || residentCalls != 0 || keygenCalls != 0 ||
		assemblerCalls != 0 || installedValidationCalls != 0 || fixture.artifact.IsZero() ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageReady) ||
		fixture.permit.lineage.lastConsumedGeneration.Load() != 3 {
		t.Fatalf("blocked Install result/read/keygen/assemble/validate/artifact/state/generation/error=%v/%d/%d/%d/%d/%v/%d/%d/%v",
			installed, residentCalls, keygenCalls, assemblerCalls, installedValidationCalls,
			fixture.artifact.IsZero(), fixture.permit.lineage.state.Load(),
			fixture.permit.lineage.lastConsumedGeneration.Load(), err)
	}
}

func TestRouteBAuthorityInstallResidentMutationIsTerminalBeforeKeygen(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBReadyFixture(t, sampler)
	transformation := fixture.artifact.cell.cts.Matrices[0]
	rbdftMutateFirstTestPoly(&transformation, func(poly *ringqp.Poly) { poly.Q.Coeffs[0][0] ^= 1 })
	fixture.artifact.cell.cts.Matrices[0] = transformation
	residentCalls, keygenCalls, assemblerCalls, installedValidationCalls := 0, 0, 0, 0
	resident, keygen, assembler, installedValidator := fixture.installHooks(
		&residentCalls, &keygenCalls, &assemblerCalls, &installedValidationCalls,
	)
	installed, err := fixture.authority.installWithHooks(
		fixture.readyPermit, fixture.receipt, fixture.artifact, new(rlwe.SecretKey),
		resident, keygen, assembler, installedValidator,
	)
	if err == nil || installed != nil || residentCalls != 1 || keygenCalls != 0 || assemblerCalls != 0 ||
		installedValidationCalls != 0 || !fixture.artifact.IsZero() ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageFailed) {
		t.Fatalf("mutated Install result/read/keygen/assemble/validate/artifact/state/error=%v/%d/%d/%d/%d/%v/%d/%v",
			installed, residentCalls, keygenCalls, assemblerCalls, installedValidationCalls,
			fixture.artifact.IsZero(), fixture.permit.lineage.state.Load(), err)
	}
}

func TestRouteBAuthorityInstallKeygenFailureIsTerminal(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBReadyFixture(t, sampler)
	residentCalls, keygenCalls, assemblerCalls := 0, 0, 0
	resident := fixture.residentValidator(&residentCalls)
	keygen := func(bootstrapping.PreparedParameters, *rlwe.SecretKey) (*bootstrapping.EvaluationKeys, error) {
		keygenCalls++
		return nil, errors.New("test keygen failure")
	}
	assembler := func(bootstrapping.PreparedParameters, *routeBArtifactCell, **bootstrapping.EvaluationKeys) (*bootstrapping.Evaluator, error) {
		assemblerCalls++
		return nil, nil
	}
	installed, err := fixture.authority.installWithHooks(
		fixture.readyPermit, fixture.receipt, fixture.artifact, new(rlwe.SecretKey), resident,
		keygen, assembler, func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error { return nil },
	)
	if err == nil || installed != nil || residentCalls != 1 || keygenCalls != 1 || assemblerCalls != 0 ||
		!fixture.artifact.IsZero() || fixture.permit.lineage.state.Load() != uint32(routeBLineageFailed) {
		t.Fatalf("keygen failure result/read/keygen/assemble/artifact/state/error=%v/%d/%d/%d/%v/%d/%v",
			installed, residentCalls, keygenCalls, assemblerCalls, fixture.artifact.IsZero(),
			fixture.permit.lineage.state.Load(), err)
	}
}

func TestRouteBAuthorityInstallAssemblerPanicClearsDonorsAndIsTerminal(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBReadyFixture(t, sampler)
	residentCalls, keygenCalls, assemblerCalls := 0, 0, 0
	resident := fixture.residentValidator(&residentCalls)
	keygen := func(bootstrapping.PreparedParameters, *rlwe.SecretKey) (*bootstrapping.EvaluationKeys, error) {
		keygenCalls++
		return &bootstrapping.EvaluationKeys{}, nil
	}
	var capturedDonor **bootstrapping.EvaluationKeys
	assembler := func(_ bootstrapping.PreparedParameters, _ *routeBArtifactCell, donor **bootstrapping.EvaluationKeys) (*bootstrapping.Evaluator, error) {
		assemblerCalls++
		capturedDonor = donor
		panic("test assembler panic")
	}
	installed, err := fixture.authority.installWithHooks(
		fixture.readyPermit, fixture.receipt, fixture.artifact, new(rlwe.SecretKey), resident,
		keygen, assembler, func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error { return nil },
	)
	if err == nil || installed != nil || residentCalls != 1 || keygenCalls != 1 || assemblerCalls != 1 ||
		capturedDonor == nil || *capturedDonor != nil || !fixture.artifact.IsZero() ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageFailed) {
		t.Fatalf("assembler panic result/read/keygen/assemble/donor/artifact/state/error=%v/%d/%d/%d/%v/%v/%d/%v",
			installed, residentCalls, keygenCalls, assemblerCalls,
			capturedDonor == nil || *capturedDonor != nil, fixture.artifact.IsZero(),
			fixture.permit.lineage.state.Load(), err)
	}
}

func TestRouteBAuthorityInstallConcurrentCopiesHaveOneSideEffectWinner(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBReadyFixture(t, sampler)
	residentCalls, keygenCalls, assemblerCalls, installedValidationCalls := 0, 0, 0, 0
	resident, keygen, assembler, installedValidator := fixture.installHooks(
		&residentCalls, &keygenCalls, &assemblerCalls, &installedValidationCalls,
	)
	type result struct {
		installed *RouteBInstalledEvaluator
		err       error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	for range 2 {
		go func() {
			defer workers.Done()
			<-start
			installed, err := fixture.authority.installWithHooks(
				fixture.readyPermit, fixture.receipt, fixture.artifact, new(rlwe.SecretKey),
				resident, keygen, assembler, installedValidator,
			)
			results <- result{installed: installed, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes, lineageFailures := 0, 0
	for value := range results {
		switch {
		case value.err == nil && value.installed != nil && !value.installed.IsZero():
			successes++
		case errors.Is(value.err, ErrRBAUTHLineage) && value.installed == nil:
			lineageFailures++
		default:
			t.Fatalf("unexpected concurrent Install result: installed=%v err=%v", value.installed, value.err)
		}
	}
	if successes != 1 || lineageFailures != 1 || residentCalls != 1 || keygenCalls != 1 ||
		assemblerCalls != 1 || installedValidationCalls != 1 ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageInstalledUnverified) {
		t.Fatalf("concurrent Install success/lineage/read/keygen/assemble/validate/state=%d/%d/%d/%d/%d/%d/%d",
			successes, lineageFailures, residentCalls, keygenCalls, assemblerCalls,
			installedValidationCalls, fixture.permit.lineage.state.Load())
	}
}

func TestRouteBAuthorityInstallPublicSurfaceAndGateOrder(t *testing.T) {
	authorityType := reflect.TypeOf((*RouteBAuthority)(nil))
	method, ok := authorityType.MethodByName("Install")
	if !ok || method.Type.NumIn() != 5 || method.Type.In(1) != reflect.TypeOf(ReadyPermit{}) ||
		method.Type.In(2) != reflect.TypeOf(ArtifactBuildReceipt{}) ||
		method.Type.In(3) != reflect.TypeOf(RouteBArtifact{}) ||
		method.Type.In(4) != reflect.TypeOf((*rlwe.SecretKey)(nil)) || method.Type.NumOut() != 2 ||
		method.Type.Out(0) != reflect.TypeOf((*RouteBInstalledEvaluator)(nil)) {
		t.Fatalf("Install public surface changed: present=%v type=%v", ok, method.Type)
	}
	for index := 0; index < reflect.TypeOf(RouteBInstalledEvaluator{}).NumField(); index++ {
		if reflect.TypeOf(RouteBInstalledEvaluator{}).Field(index).IsExported() {
			t.Fatalf("RouteBInstalledEvaluator exposes field %s", reflect.TypeOf(RouteBInstalledEvaluator{}).Field(index).Name)
		}
	}

	parsed, err := parser.ParseFile(token.NewFileSet(), "route_b_install.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if isFunction && function.Recv != nil && function.Name.Name == "installWithHooks" {
			target = function
			break
		}
	}
	if target == nil {
		t.Fatal("installWithHooks declaration is missing")
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
	transition, residentRead := indexOf("CompareAndSwap"), indexOf("residentValidator")
	keygen, assemble := indexOf("keyGenerator"), indexOf("assembler")
	if sample < 0 || prepare <= sample || transition <= prepare || residentRead <= transition ||
		keygen <= residentRead || assemble <= keygen {
		t.Fatalf("Install gate order changed: calls=%v", calls)
	}
}
