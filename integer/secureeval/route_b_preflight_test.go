package secureeval

import (
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"reflect"
	"sync"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring/ringqp"
)

func TestRouteBExpectedTracePairsUseDispatchOrderNotSortedKeyOrder(t *testing.T) {
	modulus := big.NewInt(2 * 65_536)
	for index, exponent := range routeBExpectedTraceRotationExponents {
		want := new(big.Int).Exp(big.NewInt(5), new(big.Int).SetUint64(exponent), modulus).Uint64()
		if routeBExpectedTraceGaloisElements[index] != want {
			t.Fatalf("Trace pair %d is rotation=%d/galois=%d, want galois=%d",
				index, exponent, routeBExpectedTraceGaloisElements[index], want)
		}
	}
	if routeBExpectedTraceGaloisElements != ([routeBTraceDispatchCount]uint64{122881, 114689, 98305, 65537}) {
		t.Fatalf("Trace dispatch Galois order changed: %v", routeBExpectedTraceGaloisElements)
	}
}

type smallRouteBInstalledFixture struct {
	smallRouteBReadyFixture
	installed *RouteBInstalledEvaluator
}

func newSmallRouteBInstalledFixture(t *testing.T, sampler *scriptedPhysicalMemorySampler) smallRouteBInstalledFixture {
	t.Helper()
	fixture := newSmallRouteBReadyFixture(t, sampler)
	residentCalls, keygenCalls, assemblerCalls, installedValidationCalls := 0, 0, 0, 0
	resident, keygen, assembler, installedValidator := fixture.installHooks(
		&residentCalls, &keygenCalls, &assemblerCalls, &installedValidationCalls,
	)
	installed, err := fixture.authority.installWithHooks(
		fixture.readyPermit, fixture.receipt, fixture.artifact, new(rlwe.SecretKey),
		resident, keygen, assembler, installedValidator,
	)
	if err != nil || installed == nil || residentCalls != 1 || keygenCalls != 1 ||
		assemblerCalls != 1 || installedValidationCalls != 1 {
		t.Fatalf("install small preflight fixture: installed=%v calls=%d/%d/%d/%d err=%v",
			installed, residentCalls, keygenCalls, assemblerCalls, installedValidationCalls, err)
	}
	return smallRouteBInstalledFixture{smallRouteBReadyFixture: fixture, installed: installed}
}

func (fixture smallRouteBInstalledFixture) installedResidentValidator(calls *int) routeBInstalledResidentValidator {
	return func(
		cell *routeBInstalledEvaluatorCell,
		_ bootstrapping.PreparedParameters,
	) (RBAUTHActualPayload, RBAUTHDigest, error) {
		*calls++
		return validateRouteBResidentArtifactWithPlan(
			cell.evaluator.S2CDFTMatrix, cell.evaluator.C2SDFTMatrix,
			cell.records, cell.receipt,
			routeBResidentArtifactPlan{
				params: fixture.params, stcLiteral: fixture.stcLiteral, ctsLiteral: fixture.ctsLiteral,
				stcProfile: fixture.stcProfile, ctsProfile: fixture.ctsProfile,
			},
		)
	}
}

func canonicalTestRouteBFirstOperationObservation() routeBFirstOperationObservation {
	keyInventory := [routeBEvaluationGaloisKeyCount]uint64{
		5, 25, 125, 625, 3125, 5729, 7937, 15625, 27649, 28609, 31745, 37249,
		41473, 49409, 59393, 60833, 60961, 61313, 63489, 65537, 77185, 77953,
		78125, 81409, 89345, 89745, 91137, 95233, 98305, 98369, 102017, 113153,
		114689, 117889, 122881, 126977, 128481, 131071,
	}
	layout, _, _ := deriveRouteBPackingLayoutIdentity()
	return routeBFirstOperationObservation{
		logN: 16, logSlots: 11, traceGap: 16,
		traceRotationExponents:  [routeBTraceDispatchCount]uint64{2048, 4096, 8192, 16384},
		traceGaloisElements:     [routeBTraceDispatchCount]uint64{122881, 114689, 98305, 65537},
		traceDigest:             RBAUTHDigest(sha256.Sum256([]byte("test-route-b-trace"))),
		modUpInputOutputAliased: true,
		ctImagNil:               true,
		packingLayoutDigest:     layout,
		evaluationGaloisKeys:    keyInventory,
		raisedLevel:             20,
		outputLevel:             17,
		wallNanoseconds:         1234,
	}
}

func TestRouteBInstalledEvaluatorFirstSparseMR0PreflightsBeforeHE(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls, installedValidationCalls, runnerCalls := 0, 0, 0
	resident := fixture.installedResidentValidator(&residentCalls)
	installedValidator := func(evaluator *bootstrapping.Evaluator, _ bootstrapping.PreparedParameters) error {
		installedValidationCalls++
		if evaluator != fixture.installed.cell.evaluator {
			return errors.New("installed evaluator pointer changed")
		}
		return nil
	}
	runner := func(evaluator *bootstrapping.Evaluator, input *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		runnerCalls++
		if evaluator != fixture.installed.cell.evaluator || input == nil {
			return nil, routeBFirstOperationObservation{}, errors.New("test runner input changed")
		}
		return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
	}
	output, report, err := fixture.installed.runFirstSparseMR0WithHooks(
		new(rlwe.Ciphertext), resident, installedValidator, runner,
	)
	if err != nil {
		t.Fatal(err)
	}
	reportErr := report.Validate()
	if output == nil || reportErr != nil || residentCalls != 1 ||
		installedValidationCalls != 1 || runnerCalls != 1 || fixture.installed.IsZero() ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageOperational) ||
		fixture.permit.lineage.lastConsumedGeneration.Load() != 5 {
		t.Fatalf("first MR0 output/report/read/validate/run/installed/state/generation=%v/%v/%d/%d/%d/%v/%d/%d",
			output, reportErr, residentCalls, installedValidationCalls, runnerCalls, fixture.installed.IsZero(),
			fixture.permit.lineage.state.Load(), fixture.permit.lineage.lastConsumedGeneration.Load())
	}
	if report.RuntimeCapacity.Operation != routeBRuntimeOperationPreflight ||
		report.RuntimeCapacity.Generation != 5 ||
		report.RuntimeCapacity.Digest != fixture.permit.lineage.preflightCapacityEvidenceIdentity ||
		report.ObservedTraceGap != 16 || !report.ObservedCTImagNil ||
		report.ObservedPackingLayoutDigest != report.ExpectedPackingLayoutDigest {
		t.Fatalf("first MR0 evidence changed: %+v", report)
	}
	secondOutput, secondReport, secondErr := fixture.installed.runFirstSparseMR0WithHooks(
		new(rlwe.Ciphertext), resident, installedValidator, runner,
	)
	if !errors.Is(secondErr, ErrRBAUTHLineage) || secondOutput != nil || secondReport != (RouteBFirstOperationReport{}) ||
		residentCalls != 1 || runnerCalls != 1 {
		t.Fatalf("reused first MR0 output/report/read/run/error=%v/%+v/%d/%d/%v",
			secondOutput, secondReport, residentCalls, runnerCalls, secondErr)
	}
}

func TestRouteBInstalledEvaluatorA2BFirstRoundUsesExpandedGateBeforeHE(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls, installedValidationCalls, runnerCalls := 0, 0, 0
	output, report, err := fixture.installed.runFirstOperationWithHooks(
		new(rlwe.Ciphertext), routeBCapacityGateA2BFirstRound, routeBRuntimeOperationA2BFirstRound,
		fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error {
			installedValidationCalls++
			return nil
		},
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			runnerCalls++
			return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if output == nil || report.Validate() != nil || report.RuntimeCapacity.Operation != routeBRuntimeOperationA2BFirstRound ||
		report.RuntimeCapacity.Peak.PreGuardIncrementalPeakBytes != 1_227_427_584 ||
		report.RuntimeCapacity.Peak.GuardedRequirementBytes != 1_764_298_496 ||
		residentCalls != 1 || installedValidationCalls != 1 || runnerCalls != 1 ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageOperational) {
		t.Fatalf("A2B first-round gate/output/report/calls/state changed: output=%v report=%+v calls=%d/%d/%d state=%d",
			output, report, residentCalls, installedValidationCalls, runnerCalls, fixture.permit.lineage.state.Load())
	}
}

func TestRouteBInstalledEvaluatorA2BFullUsesExpandedGateBeforeHE(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls, installedValidationCalls, runnerCalls := 0, 0, 0
	output, report, err := fixture.installed.runFirstOperationWithHooks(
		new(rlwe.Ciphertext), routeBCapacityGateA2BFull, routeBRuntimeOperationA2BFull,
		fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error {
			installedValidationCalls++
			return nil
		},
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			runnerCalls++
			return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if output == nil || report.Validate() != nil || report.RuntimeCapacity.Operation != routeBRuntimeOperationA2BFull ||
		report.RuntimeCapacity.Peak.PreGuardIncrementalPeakBytes != 2_381_123_328 ||
		report.RuntimeCapacity.Peak.GuardedRequirementBytes != 2_917_994_240 ||
		residentCalls != 1 || installedValidationCalls != 1 || runnerCalls != 1 ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageOperational) {
		t.Fatalf("A2B-full gate/output/report/calls/state changed: output=%v report=%+v calls=%d/%d/%d state=%d",
			output, report, residentCalls, installedValidationCalls, runnerCalls, fixture.permit.lineage.state.Load())
	}
}

func TestRouteBInstalledEvaluatorPreparedA2BRepeatUsesSealedResidentState(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	firstOutput, _, err := fixture.installed.runFirstOperationWithHooks(
		new(rlwe.Ciphertext), routeBCapacityGateA2BFull, routeBRuntimeOperationA2BFull,
		fixture.installedResidentValidator(new(int)),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error { return nil },
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
		},
	)
	if err != nil || firstOutput == nil {
		t.Fatalf("prepare operational A2B fixture: output=%v err=%v", firstOutput, err)
	}
	fixture.installed.cell.preparedA2BFull = &routeBA2BFullPreparedEvaluator{
		source: fixture.installed.cell.evaluator,
	}

	runnerCalls := 0
	output, report, err := fixture.installed.runOperationalA2BFullWithHooks(
		new(rlwe.Ciphertext),
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			runnerCalls++
			return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if output == nil || report.Validate() != nil || runnerCalls != 1 ||
		report.RuntimeCapacity.Operation != routeBRuntimeOperationA2BFull ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageOperational) ||
		fixture.permit.lineage.lastConsumedGeneration.Load() != 5 || sampler.calls != 5 {
		t.Fatalf("prepared repeat output/report/run/state/generation=%v/%+v/%d/%d/%d",
			output, report, runnerCalls, fixture.permit.lineage.state.Load(),
			fixture.permit.lineage.lastConsumedGeneration.Load())
	}
}

func TestRouteBInstalledEvaluatorSigned8RootTreeUsesExpandedGateBeforeHE(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls, installedValidationCalls, runnerCalls := 0, 0, 0
	output, report, err := fixture.installed.runFirstOperationWithHooks(
		new(rlwe.Ciphertext), routeBCapacityGateSigned8RootTree, routeBRuntimeOperationSigned8RootTree,
		fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error {
			installedValidationCalls++
			return nil
		},
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			runnerCalls++
			return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if output == nil || report.Validate() != nil || report.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8RootTree ||
		report.RuntimeCapacity.Peak.PreGuardIncrementalPeakBytes != 2_451_902_208 ||
		report.RuntimeCapacity.Peak.GuardedRequirementBytes != 2_988_773_120 ||
		residentCalls != 1 || installedValidationCalls != 1 || runnerCalls != 1 ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageOperational) {
		t.Fatalf("signed8-root-tree gate/output/report/calls/state changed: output=%v report=%+v calls=%d/%d/%d state=%d",
			output, report, residentCalls, installedValidationCalls, runnerCalls, fixture.permit.lineage.state.Load())
	}
}

func TestRouteBInstalledEvaluatorSigned8Depth2NodeBatchUsesExpandedGateBeforeHE(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls, installedValidationCalls, runnerCalls := 0, 0, 0
	output, report, err := fixture.installed.runFirstOperationWithHooks(
		new(rlwe.Ciphertext), routeBCapacityGateSigned8Depth2NodeBatch, routeBRuntimeOperationSigned8Depth2NodeBatch,
		fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error {
			installedValidationCalls++
			return nil
		},
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			runnerCalls++
			return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if output == nil || report.Validate() != nil || report.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8Depth2NodeBatch ||
		report.RuntimeCapacity.Peak.PreGuardIncrementalPeakBytes != 2_517_438_208 ||
		report.RuntimeCapacity.Peak.GuardedRequirementBytes != 3_054_309_120 ||
		residentCalls != 1 || installedValidationCalls != 1 || runnerCalls != 1 ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageOperational) {
		t.Fatalf("signed8-depth2-node-batch gate/output/report/calls/state changed: output=%v report=%+v calls=%d/%d/%d state=%d",
			output, report, residentCalls, installedValidationCalls, runnerCalls, fixture.permit.lineage.state.Load())
	}
}

func TestRouteBInstalledEvaluatorSigned8Depth2SelectedChildUsesExpandedGateBeforeHE(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls, installedValidationCalls, runnerCalls := 0, 0, 0
	output, report, err := fixture.installed.runFirstOperationWithHooks(
		new(rlwe.Ciphertext), routeBCapacityGateSigned8Depth2SelectedChild, routeBRuntimeOperationSigned8Depth2SelectedChild,
		fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error {
			installedValidationCalls++
			return nil
		},
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			runnerCalls++
			return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if output == nil || report.Validate() != nil || report.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8Depth2SelectedChild ||
		report.RuntimeCapacity.Peak.PreGuardIncrementalPeakBytes != 2_765_426_432 ||
		report.RuntimeCapacity.Peak.GuardedRequirementBytes != 3_302_297_344 ||
		residentCalls != 1 || installedValidationCalls != 1 || runnerCalls != 1 ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageOperational) {
		t.Fatalf("signed8-depth2-selected-child gate/output/report/calls/state changed: output=%v report=%+v calls=%d/%d/%d state=%d",
			output, report, residentCalls, installedValidationCalls, runnerCalls, fixture.permit.lineage.state.Load())
	}
}

func TestRouteBInstalledEvaluatorFirstSparseMR0CapacityBlockPrecedesResidentRead(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted,
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 1}},
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls, installedValidationCalls, runnerCalls := 0, 0, 0
	output, report, err := fixture.installed.runFirstSparseMR0WithHooks(
		new(rlwe.Ciphertext), fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error {
			installedValidationCalls++
			return nil
		},
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			runnerCalls++
			return nil, routeBFirstOperationObservation{}, nil
		},
	)
	if !errors.Is(err, ErrRBAUTHBlocked) || output != nil || report != (RouteBFirstOperationReport{}) ||
		residentCalls != 0 || installedValidationCalls != 0 || runnerCalls != 0 || fixture.installed.IsZero() ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageInstalledUnverified) ||
		fixture.permit.lineage.lastConsumedGeneration.Load() != 4 {
		t.Fatalf("blocked first MR0 output/report/read/validate/run/installed/state/generation/error=%v/%+v/%d/%d/%d/%v/%d/%d/%v",
			output, report, residentCalls, installedValidationCalls, runnerCalls, fixture.installed.IsZero(),
			fixture.permit.lineage.state.Load(), fixture.permit.lineage.lastConsumedGeneration.Load(), err)
	}
}

func TestRouteBInstalledEvaluatorFirstSparseMR0ResidentMutationIsTerminalBeforeHE(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	transformation := fixture.installed.cell.evaluator.S2CDFTMatrix.Matrices[0]
	rbdftMutateFirstTestPoly(&transformation, func(poly *ringqp.Poly) { poly.Q.Coeffs[0][0] ^= 1 })
	fixture.installed.cell.evaluator.S2CDFTMatrix.Matrices[0] = transformation
	residentCalls, runnerCalls := 0, 0
	output, report, err := fixture.installed.runFirstSparseMR0WithHooks(
		new(rlwe.Ciphertext), fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error { return nil },
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			runnerCalls++
			return nil, routeBFirstOperationObservation{}, nil
		},
	)
	if err == nil || output != nil || report != (RouteBFirstOperationReport{}) || residentCalls != 1 ||
		runnerCalls != 0 || !fixture.installed.IsZero() ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageFailed) {
		t.Fatalf("mutated first MR0 output/report/read/run/installed/state/error=%v/%+v/%d/%d/%v/%d/%v",
			output, report, residentCalls, runnerCalls, fixture.installed.IsZero(),
			fixture.permit.lineage.state.Load(), err)
	}
}

func TestRouteBInstalledEvaluatorFirstSparseMR0RunnerFailureIsTerminal(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls, runnerCalls := 0, 0
	output, report, err := fixture.installed.runFirstSparseMR0WithHooks(
		new(rlwe.Ciphertext), fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error { return nil },
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			runnerCalls++
			return nil, routeBFirstOperationObservation{}, errors.New("test MR0 failure")
		},
	)
	if err == nil || output != nil || report != (RouteBFirstOperationReport{}) || residentCalls != 1 ||
		runnerCalls != 1 || !fixture.installed.IsZero() ||
		fixture.permit.lineage.state.Load() != uint32(routeBLineageFailed) {
		t.Fatalf("failed first MR0 output/report/read/run/installed/state/error=%v/%+v/%d/%d/%v/%d/%v",
			output, report, residentCalls, runnerCalls, fixture.installed.IsZero(),
			fixture.permit.lineage.state.Load(), err)
	}
}

func TestRouteBInstalledEvaluatorFirstSparseMR0ConcurrentCopiesHaveOneHERunner(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls, installedValidationCalls, runnerCalls := 0, 0, 0
	resident := fixture.installedResidentValidator(&residentCalls)
	installedValidator := func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error {
		installedValidationCalls++
		return nil
	}
	runner := func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
		runnerCalls++
		return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
	}
	type result struct {
		output *rlwe.Ciphertext
		report RouteBFirstOperationReport
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
			output, report, err := fixture.installed.runFirstSparseMR0WithHooks(
				new(rlwe.Ciphertext), resident, installedValidator, runner,
			)
			results <- result{output: output, report: report, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes, lineageFailures := 0, 0
	for value := range results {
		switch {
		case value.err == nil && value.output != nil && value.report != (RouteBFirstOperationReport{}):
			successes++
		case errors.Is(value.err, ErrRBAUTHLineage) && value.output == nil && value.report == (RouteBFirstOperationReport{}):
			lineageFailures++
		default:
			t.Fatalf("unexpected concurrent first MR0 result: output=%v report=%+v err=%v", value.output, value.report, value.err)
		}
	}
	if successes != 1 || lineageFailures != 1 || residentCalls != 1 || installedValidationCalls != 1 ||
		runnerCalls != 1 || fixture.permit.lineage.state.Load() != uint32(routeBLineageOperational) {
		t.Fatalf("concurrent first MR0 success/lineage/read/validate/run/state=%d/%d/%d/%d/%d/%d",
			successes, lineageFailures, residentCalls, installedValidationCalls, runnerCalls,
			fixture.permit.lineage.state.Load())
	}
}

func TestRouteBInstalledEvaluatorFirstSparseMR0PublicSurfaceAndGateOrder(t *testing.T) {
	typeOfInstalled := reflect.TypeOf((*RouteBInstalledEvaluator)(nil))
	method, ok := typeOfInstalled.MethodByName("RunFirstSparseMR0")
	if !ok || method.Type.NumIn() != 2 || method.Type.In(1) != reflect.TypeOf((*rlwe.Ciphertext)(nil)) ||
		method.Type.NumOut() != 3 || method.Type.Out(0) != reflect.TypeOf((*rlwe.Ciphertext)(nil)) ||
		method.Type.Out(1) != reflect.TypeOf(RouteBFirstOperationReport{}) {
		t.Fatalf("RunFirstSparseMR0 public surface changed: present=%v type=%v", ok, method.Type)
	}

	parsed, err := parser.ParseFile(token.NewFileSet(), "route_b_preflight.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if isFunction && function.Recv != nil && function.Name.Name == "runFirstOperationWithHooks" {
			target = function
			break
		}
	}
	if target == nil {
		t.Fatal("runFirstOperationWithHooks declaration is missing")
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
	run := indexOf("runner")
	if sample < 0 || prepare <= sample || transition <= prepare || residentRead <= transition || run <= residentRead {
		t.Fatalf("first sparse MR0 gate order changed: calls=%v", calls)
	}
}

func TestRouteBCanonicalL11MR0ResultValidationBindsLifecycleEvidence(t *testing.T) {
	admitted := scriptedPhysicalMemoryResult{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		admitted, admitted, admitted, admitted, admitted,
	}}
	fixture := newSmallRouteBInstalledFixture(t, sampler)
	residentCalls := 0
	_, firstOperation, err := fixture.installed.runFirstSparseMR0WithHooks(
		new(rlwe.Ciphertext), fixture.installedResidentValidator(&residentCalls),
		func(*bootstrapping.Evaluator, bootstrapping.PreparedParameters) error { return nil },
		func(*bootstrapping.Evaluator, *rlwe.Ciphertext) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
			return new(rlwe.Ciphertext), canonicalTestRouteBFirstOperationObservation(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	result := RouteBCanonicalL11MR0Result{
		BuildSpec: fixture.permit.report.Spec, BuildReceipt: fixture.receipt.report,
		ReadySpec: fixture.readyPermit.report.Spec, FirstOperation: firstOperation,
		BuildRuntime: fixture.receipt.runtime, ReadyRuntime: fixture.readyPermit.runtime,
		InstallRuntime:           fixture.installed.cell.install,
		OverallConstructionDelta: [4]uint64{0, 0, 0, 2},
		PostInstallPeakRSSBytes:  1, PostMR0PeakRSSBytes: 1, TotalWallNanoseconds: 1,
	}
	if err = result.Validate(); err != nil {
		t.Fatal(err)
	}
	result.OverallConstructionDelta[0] = 1
	if err = result.Validate(); !errors.Is(err, ErrRBAUTHLineage) {
		t.Fatalf("drifted canonical result error=%v", err)
	}
}
