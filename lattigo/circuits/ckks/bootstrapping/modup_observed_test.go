package bootstrapping

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/mod1"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestModUpObservedSuccessMatchesStock(t *testing.T) {
	fixture := newModUpObservedTestFixture(t)
	stockEvaluator := fixture.newEvaluator(fixture.keySet, false)
	observedEvaluator := fixture.newEvaluator(fixture.keySet, false)
	stockInput := fixture.ciphertext.CopyNew()
	observedInput := fixture.ciphertext.CopyNew()

	stockOutput, err := stockEvaluator.ModUp(stockInput)
	if err != nil {
		t.Fatalf("stock ModUp failed: %v", err)
	}
	observedOutput, report, err := observedEvaluator.ModUpObserved(observedInput)
	if err != nil {
		t.Fatalf("observed ModUp failed: %v", err)
	}
	if stockOutput != stockInput || observedOutput != observedInput {
		t.Fatal("successful ModUp did not preserve the in-place output pointer")
	}
	stockBytes, err := stockOutput.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	observedBytes, err := observedOutput.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stockBytes, observedBytes) {
		t.Fatal("stock and observed ModUp ciphertext bytes differ")
	}
	if stockOutput.Level() != observedOutput.Level() || !stockOutput.Scale.Equal(observedOutput.Scale) || !reflect.DeepEqual(stockOutput.MetaData, observedOutput.MetaData) {
		t.Fatal("stock and observed ModUp metadata, level or scale differ")
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("success report rejected: %v", err)
	}
	if report.Status() != ModUpTraceSuccess || report.FailureKind() != ModUpTraceFailureNone || report.FailureStage() != ModUpTraceStageNone {
		t.Fatalf("unexpected success disposition: status=%d kind=%d stage=%d", report.Status(), report.FailureKind(), report.FailureStage())
	}
	if !report.TraceStarted() {
		t.Fatal("successful ModUp did not record its Trace invocation")
	}
	nested := report.TraceReport()
	if err := nested.Validate(); err != nil {
		t.Fatalf("nested Trace report rejected: %v", err)
	}
	if nested.Status() != rlwe.TraceDispatchSuccess || !nested.InputOutputAliased() {
		t.Fatal("nested Trace report does not describe the successful in-place Trace")
	}
	if got, want := len(nested.Events()), len(rlwe.GaloisElementsForTrace(fixture.params, modUpObservedTestLogSlots)); got != want {
		t.Fatalf("nested Trace events=%d, want %d", got, want)
	}
}

func TestModUpObservedUsesOneTraceAndPreservesRuntimeIdentity(t *testing.T) {
	fixture := newModUpObservedTestFixture(t)
	keys := &modUpObservedCountingKeySet{delegate: fixture.keySet}
	evaluator := fixture.newEvaluator(keys, false)
	before, err := evaluator.Evaluator.Evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}

	output, report, err := evaluator.ModUpObserved(fixture.ciphertext.CopyNew())
	if err != nil || output == nil {
		t.Fatalf("observed ModUp failed: output=%v err=%v", output, err)
	}
	after, err := evaluator.Evaluator.Evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equal(after) {
		t.Fatal("observation changed the RLWE evaluator/key/buffer topology")
	}
	wantCalls := rlwe.GaloisElementsForTrace(fixture.params, modUpObservedTestLogSlots)
	if !slices.Equal(keys.calls, wantCalls) {
		t.Fatalf("Galois-key lookups=%v, want exactly one Trace in source order %v", keys.calls, wantCalls)
	}
	nested := report.TraceReport()
	if nested.AttemptedDispatches() != uint32(len(wantCalls)) || nested.CompletedDispatches() != uint32(len(wantCalls)) {
		t.Fatalf("nested Trace dispatch ledger=%d/%d, want %d/%d", nested.AttemptedDispatches(), nested.CompletedDispatches(), len(wantCalls), len(wantCalls))
	}
	events := nested.Events()
	if len(events) == 0 {
		t.Fatal("nested Trace event list is empty")
	}
	events[0] = rlwe.TraceDispatchEvent{}
	if report.TraceReport().Events()[0].GaloisElement() == 0 {
		t.Fatal("nested Trace accessor exposed mutable event backing")
	}
}

func TestModUpObservedTraceErrorPreservesStockPointerAndPrefix(t *testing.T) {
	fixture := newModUpObservedTestFixture(t)
	stockKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet, failAt: 2}
	observedKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet, failAt: 2}
	stockEvaluator := fixture.newEvaluator(stockKeys, false)
	observedEvaluator := fixture.newEvaluator(observedKeys, false)
	stockInput := fixture.ciphertext.CopyNew()
	observedInput := fixture.ciphertext.CopyNew()

	stockOutput, stockErr := stockEvaluator.ModUp(stockInput)
	if stockErr == nil || stockOutput != stockInput {
		t.Fatalf("stock Trace error semantics changed: output=%p input=%p err=%v", stockOutput, stockInput, stockErr)
	}
	observedOutput, report, observedErr := observedEvaluator.ModUpObserved(observedInput)
	if observedErr == nil || observedOutput != observedInput {
		t.Fatalf("observed ordinary Trace error semantics changed: output=%p input=%p err=%v", observedOutput, observedInput, observedErr)
	}
	if stockErr.Error() != observedErr.Error() {
		t.Fatalf("stock/observed Trace errors differ: stock=%q observed=%q", stockErr, observedErr)
	}
	stockBytes, err := stockOutput.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	observedBytes, err := observedOutput.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stockBytes, observedBytes) {
		t.Fatal("stock and observed ordinary Trace-error prefixes differ")
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("Trace-error report rejected: %v", err)
	}
	if report.Status() != ModUpTraceFailure || report.FailureKind() != ModUpTraceFailureError || report.FailureStage() != ModUpTraceStageTrace || !report.TraceStarted() {
		t.Fatalf("unexpected Trace-error disposition: status=%d kind=%d stage=%d started=%v", report.Status(), report.FailureKind(), report.FailureStage(), report.TraceStarted())
	}
	nested := report.TraceReport()
	if nested.Status() != rlwe.TraceDispatchFailure || nested.FailureKind() != rlwe.TraceDispatchFailureError || nested.AttemptedDispatches() != 2 || nested.CompletedDispatches() != 1 {
		t.Fatalf("unexpected nested Trace prefix: status=%d kind=%d attempted=%d completed=%d", nested.Status(), nested.FailureKind(), nested.AttemptedDispatches(), nested.CompletedDispatches())
	}
	events := nested.Events()
	if len(events) != 2 || !events[0].Completed() || events[1].Completed() {
		t.Fatalf("nested Trace error prefix completion flags changed: %+v", events)
	}
	if len(stockKeys.calls) != 2 || len(observedKeys.calls) != 2 {
		t.Fatalf("stock/observed Trace lookup counts=%d/%d, want 2/2", len(stockKeys.calls), len(observedKeys.calls))
	}
}

func TestModUpObservedNestedTracePanicReturnsNilAndStockStillPanics(t *testing.T) {
	fixture := newModUpObservedTestFixture(t)
	observedKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet, panicAt: 2}
	observedEvaluator := fixture.newEvaluator(observedKeys, false)

	output, report, err := observedEvaluator.ModUpObserved(fixture.ciphertext.CopyNew())
	if err == nil || output != nil {
		t.Fatalf("nested Trace panic was not normalized to nil output and error: output=%p err=%v", output, err)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("nested-panic ModUp report rejected: %v", err)
	}
	if report.Status() != ModUpTraceFailure || report.FailureKind() != ModUpTraceFailurePanic || report.FailureStage() != ModUpTraceStageTrace || !report.TraceStarted() {
		t.Fatalf("unexpected nested-panic disposition: status=%d kind=%d stage=%d started=%v", report.Status(), report.FailureKind(), report.FailureStage(), report.TraceStarted())
	}
	nested := report.TraceReport()
	if nested.FailureKind() != rlwe.TraceDispatchFailurePanic || nested.AttemptedDispatches() != 2 || nested.CompletedDispatches() != 1 {
		t.Fatalf("unexpected nested panic prefix: kind=%d attempted=%d completed=%d", nested.FailureKind(), nested.AttemptedDispatches(), nested.CompletedDispatches())
	}
	events := nested.Events()
	if len(events) != 2 || !events[0].Completed() || events[1].Completed() {
		t.Fatalf("nested Trace panic completion flags changed: %+v", events)
	}

	stockKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet, panicAt: 2}
	stockEvaluator := fixture.newEvaluator(stockKeys, false)
	if recovered, ok := captureModUpObservedTestPanic(func() {
		_, _ = stockEvaluator.ModUp(fixture.ciphertext.CopyNew())
	}); !ok || recovered == nil {
		t.Fatal("stock ModUp recovered the injected Trace panic")
	}
	if len(observedKeys.calls) != 2 || len(stockKeys.calls) != 2 {
		t.Fatalf("observed/stock panic lookup counts=%d/%d, want 2/2", len(observedKeys.calls), len(stockKeys.calls))
	}
}

func TestModUpObservedPreTraceErrorAndPanicReturnNil(t *testing.T) {
	fixture := newModUpObservedTestFixture(t)

	t.Run("ordinary dense-to-sparse error", func(t *testing.T) {
		stockKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet}
		observedKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet}
		stockEvaluator := fixture.newEvaluator(stockKeys, true)
		observedEvaluator := fixture.newEvaluator(observedKeys, true)
		stockInput := ckks.NewCiphertext(fixture.params, 2, 0)
		observedInput := stockInput.CopyNew()

		stockOutput, stockErr := stockEvaluator.ModUp(stockInput)
		observedOutput, report, observedErr := observedEvaluator.ModUpObserved(observedInput)
		if stockErr == nil || observedErr == nil || stockOutput != nil || observedOutput != nil {
			t.Fatalf("pre-Trace ordinary error semantics changed: stock=(%p,%v) observed=(%p,%v)", stockOutput, stockErr, observedOutput, observedErr)
		}
		if stockErr.Error() != observedErr.Error() {
			t.Fatalf("stock/observed pre-Trace errors differ: stock=%q observed=%q", stockErr, observedErr)
		}
		if err := report.Validate(); err != nil {
			t.Fatalf("pre-Trace error report rejected: %v", err)
		}
		if report.Status() != ModUpTraceFailure || report.FailureKind() != ModUpTraceFailureError || report.FailureStage() != ModUpTraceStageDenseToSparse || report.TraceStarted() || !report.TraceReport().IsZero() {
			t.Fatalf("unexpected pre-Trace error disposition: status=%d kind=%d stage=%d started=%v nestedZero=%v", report.Status(), report.FailureKind(), report.FailureStage(), report.TraceStarted(), report.TraceReport().IsZero())
		}
		if len(stockKeys.calls) != 0 || len(observedKeys.calls) != 0 {
			t.Fatal("pre-Trace error unexpectedly looked up a Trace key")
		}
	})

	t.Run("dense-to-sparse panic", func(t *testing.T) {
		observedKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet}
		observedEvaluator := fixture.newEvaluator(observedKeys, true)
		output, report, err := observedEvaluator.ModUpObserved(nil)
		if err == nil || output != nil {
			t.Fatalf("pre-Trace panic was not normalized to nil output and error: output=%p err=%v", output, err)
		}
		if err := report.Validate(); err != nil {
			t.Fatalf("pre-Trace panic report rejected: %v", err)
		}
		if report.Status() != ModUpTraceFailure || report.FailureKind() != ModUpTraceFailurePanic || report.FailureStage() != ModUpTraceStageDenseToSparse || report.TraceStarted() || !report.TraceReport().IsZero() {
			t.Fatalf("unexpected pre-Trace panic disposition: status=%d kind=%d stage=%d started=%v nestedZero=%v", report.Status(), report.FailureKind(), report.FailureStage(), report.TraceStarted(), report.TraceReport().IsZero())
		}

		stockEvaluator := fixture.newEvaluator(&modUpObservedCountingKeySet{delegate: fixture.keySet}, true)
		if recovered, ok := captureModUpObservedTestPanic(func() {
			_, _ = stockEvaluator.ModUp(nil)
		}); !ok || recovered == nil {
			t.Fatal("stock ModUp recovered a pre-Trace panic")
		}
		if len(observedKeys.calls) != 0 {
			t.Fatal("pre-Trace panic unexpectedly looked up a Trace key")
		}
	})

	t.Run("coefficient-lift panic", func(t *testing.T) {
		observedKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet}
		observedEvaluator := fixture.newEvaluator(observedKeys, false)
		output, report, err := observedEvaluator.ModUpObserved(nil)
		if err == nil || output != nil {
			t.Fatalf("coefficient-lift panic was not normalized to nil output and error: output=%p err=%v", output, err)
		}
		if err := report.Validate(); err != nil {
			t.Fatalf("coefficient-lift panic report rejected: %v", err)
		}
		if report.FailureKind() != ModUpTraceFailurePanic || report.FailureStage() != ModUpTraceStageCoefficientLift || report.TraceStarted() {
			t.Fatalf("unexpected coefficient-lift panic disposition: kind=%d stage=%d started=%v", report.FailureKind(), report.FailureStage(), report.TraceStarted())
		}

		stockEvaluator := fixture.newEvaluator(&modUpObservedCountingKeySet{delegate: fixture.keySet}, false)
		if recovered, ok := captureModUpObservedTestPanic(func() {
			_, _ = stockEvaluator.ModUp(nil)
		}); !ok || recovered == nil {
			t.Fatal("stock ModUp recovered a coefficient-lift panic")
		}
	})
}

func TestModUpTraceReportRejectsZeroAndFieldMutation(t *testing.T) {
	var zero ModUpTraceReport
	if !zero.IsZero() || zero.Validate() == nil {
		t.Fatal("zero ModUp Trace report was accepted")
	}

	fixture := newModUpObservedTestFixture(t)
	_, original, err := fixture.newEvaluator(fixture.keySet, false).ModUpObserved(fixture.ciphertext.CopyNew())
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Validate(); err != nil || original.Digest() == ([32]byte{}) {
		t.Fatalf("fixture report is not a sealed success: err=%v", err)
	}

	resealed := func(report ModUpTraceReport) ModUpTraceReport {
		report.digest = digestModUpTraceReport(report)
		return report
	}
	tests := map[string]func(ModUpTraceReport) ModUpTraceReport{
		"version": func(report ModUpTraceReport) ModUpTraceReport {
			report.version++
			return resealed(report)
		},
		"status": func(report ModUpTraceReport) ModUpTraceReport {
			report.status = ModUpTraceStatusUnset
			return resealed(report)
		},
		"success failure kind": func(report ModUpTraceReport) ModUpTraceReport {
			report.failureKind = ModUpTraceFailureError
			return resealed(report)
		},
		"success failure stage": func(report ModUpTraceReport) ModUpTraceReport {
			report.failureStage = ModUpTraceStageTrace
			return resealed(report)
		},
		"missing nested report": func(report ModUpTraceReport) ModUpTraceReport {
			report.traceReport = rlwe.TraceDispatchReport{}
			return resealed(report)
		},
		"nested report without start": func(report ModUpTraceReport) ModUpTraceReport {
			report.traceStarted = false
			return resealed(report)
		},
		"digest": func(report ModUpTraceReport) ModUpTraceReport {
			report.digest[0] ^= 1
			return report
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := mutate(original).Validate(); err == nil {
				t.Fatal("mutated ModUp Trace report was accepted")
			}
		})
	}
}

func TestModUpObservedOuterTraceEntryPanicSealsWithoutNestedEvidence(t *testing.T) {
	fixture := newModUpObservedTestFixture(t)
	observedEvaluator := fixture.newEvaluator(fixture.keySet, false)
	observedEvaluator.Evaluator = nil

	output, report, err := observedEvaluator.ModUpObserved(fixture.ciphertext.CopyNew())
	if err == nil || output != nil {
		t.Fatalf("outer Trace-entry panic was not normalized to nil output and error: output=%p err=%v", output, err)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("outer Trace-entry panic report rejected: %v", err)
	}
	if report.FailureKind() != ModUpTraceFailurePanic || report.FailureStage() != ModUpTraceStageTrace || report.TraceStarted() || !report.TraceReport().IsZero() {
		t.Fatalf("unexpected Trace-entry panic disposition: kind=%d stage=%d started=%v nestedZero=%v", report.FailureKind(), report.FailureStage(), report.TraceStarted(), report.TraceReport().IsZero())
	}

	stockEvaluator := fixture.newEvaluator(fixture.keySet, false)
	stockEvaluator.Evaluator = nil
	if recovered, ok := captureModUpObservedTestPanic(func() {
		_, _ = stockEvaluator.ModUp(fixture.ciphertext.CopyNew())
	}); !ok || recovered == nil {
		t.Fatal("stock ModUp recovered an outer Trace-entry panic")
	}
}

func TestCanonicalN16L11ModUpObservedSuccess(t *testing.T) {
	fixture := newCanonicalN16L11ModUpObservedTestFixture(t)
	stockKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet}
	observedKeys := &modUpObservedCountingKeySet{delegate: fixture.keySet}
	stockEvaluator := fixture.newEvaluatorForLogSlots(stockKeys, false, 11)
	observedEvaluator := fixture.newEvaluatorForLogSlots(observedKeys, false, 11)
	if stockEvaluator.EvkDenseToSparse != nil || stockEvaluator.EvkSparseToDense != nil ||
		observedEvaluator.EvkDenseToSparse != nil || observedEvaluator.EvkSparseToDense != nil {
		t.Fatal("minimal N16 fixture unexpectedly installed dense/sparse switching keys")
	}

	stockInput := fixture.ciphertext.CopyNew()
	observedInput := fixture.ciphertext.CopyNew()
	stockOutput, err := stockEvaluator.ModUp(stockInput)
	if err != nil {
		t.Fatalf("stock N16/L11 ModUp failed: %v", err)
	}
	observedOutput, report, err := observedEvaluator.ModUpObserved(observedInput)
	if err != nil {
		t.Fatalf("observed N16/L11 ModUp failed: %v", err)
	}
	if stockOutput != stockInput || observedOutput != observedInput {
		t.Fatal("N16/L11 ModUp did not preserve the in-place output pointer")
	}
	stockBytes, err := stockOutput.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	observedBytes, err := observedOutput.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stockBytes, observedBytes) {
		t.Fatal("stock and observed N16/L11 ciphertext bytes differ")
	}
	if stockOutput.Level() != observedOutput.Level() || !stockOutput.Scale.Equal(observedOutput.Scale) ||
		!reflect.DeepEqual(stockOutput.MetaData, observedOutput.MetaData) {
		t.Fatal("stock and observed N16/L11 metadata, level or scale differ")
	}

	if err := report.Validate(); err != nil {
		t.Fatalf("N16/L11 ModUp report rejected: %v", err)
	}
	if report.Status() != ModUpTraceSuccess || !report.TraceStarted() {
		t.Fatalf("unexpected N16/L11 ModUp disposition: status=%d traceStarted=%v", report.Status(), report.TraceStarted())
	}
	nested := report.TraceReport()
	if err := nested.Validate(); err != nil {
		t.Fatalf("N16/L11 nested Trace report rejected: %v", err)
	}
	if nested.Status() != rlwe.TraceDispatchSuccess || nested.RingLogN() != 16 ||
		nested.RingType() != ring.Standard || nested.RequestedLogN() != 11 || !nested.InputOutputAliased() ||
		nested.AttemptedDispatches() != 4 || nested.CompletedDispatches() != 4 {
		t.Fatalf("unexpected N16/L11 nested header: status=%d ringLogN=%d ringType=%d requested=%d alias=%v dispatches=%d/%d",
			nested.Status(), nested.RingLogN(), nested.RingType(), nested.RequestedLogN(), nested.InputOutputAliased(), nested.AttemptedDispatches(), nested.CompletedDispatches())
	}

	wantExponents := []uint64{2048, 4096, 8192, 16384}
	wantGaloisElements := []uint64{122881, 114689, 98305, 65537}
	if derived := rlwe.GaloisElementsForTrace(fixture.params, 11); !slices.Equal(derived, wantGaloisElements) {
		t.Fatalf("N16/L11 parameter-derived source order=%v, want %v", derived, wantGaloisElements)
	}
	if !slices.Equal(stockKeys.calls, wantGaloisElements) || !slices.Equal(observedKeys.calls, wantGaloisElements) {
		t.Fatalf("N16/L11 stock/observed lookup orders=%v/%v, want %v", stockKeys.calls, observedKeys.calls, wantGaloisElements)
	}
	events := nested.Events()
	if len(events) != 4 {
		t.Fatalf("N16/L11 nested event count=%d, want 4", len(events))
	}
	for i, event := range events {
		if event.Sequence() != uint32(i) || event.Kind() != rlwe.TraceDispatchAutomorphism ||
			!event.HasOrdinaryExponent() || event.OrdinaryExponent() != wantExponents[i] ||
			event.GaloisElement() != wantGaloisElements[i] || !event.Completed() {
			t.Fatalf("N16/L11 event %d changed: sequence=%d kind=%d hasExponent=%v exponent=%d galEl=%d completed=%v",
				i, event.Sequence(), event.Kind(), event.HasOrdinaryExponent(), event.OrdinaryExponent(), event.GaloisElement(), event.Completed())
		}
	}
}

const modUpObservedTestLogSlots = 1

type modUpObservedTestFixture struct {
	params     ckks.Parameters
	mod1       mod1.Parameters
	keySet     *rlwe.MemEvaluationKeySet
	ciphertext *rlwe.Ciphertext
}

type modUpObservedCountingKeySet struct {
	delegate rlwe.EvaluationKeySet
	calls    []uint64
	failAt   int
	panicAt  int
}

func (keySet *modUpObservedCountingKeySet) GetGaloisKey(galEl uint64) (*rlwe.GaloisKey, error) {
	keySet.calls = append(keySet.calls, galEl)
	call := len(keySet.calls)
	if call == keySet.panicAt {
		panic(fmt.Sprintf("injected Galois-key panic at call %d", call))
	}
	if call == keySet.failAt {
		return nil, fmt.Errorf("injected Galois-key error at call %d", call)
	}
	return keySet.delegate.GetGaloisKey(galEl)
}

func (keySet *modUpObservedCountingKeySet) GetGaloisKeysList() []uint64 {
	return keySet.delegate.GetGaloisKeysList()
}

func (keySet *modUpObservedCountingKeySet) GetRelinearizationKey() (*rlwe.RelinearizationKey, error) {
	return keySet.delegate.GetRelinearizationKey()
}

func (keySet *modUpObservedCountingKeySet) ShallowCopy() rlwe.EvaluationKeySet {
	return keySet
}

func captureModUpObservedTestPanic(operation func()) (recovered any, panicked bool) {
	defer func() {
		if recovered = recover(); recovered != nil {
			panicked = true
		}
	}()
	operation()
	return nil, false
}

func newModUpObservedTestFixture(t *testing.T) modUpObservedTestFixture {
	t.Helper()
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{30, 29},
		LogP:            []int{30},
		LogDefaultScale: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	mod1Parameters, err := mod1.NewParametersFromLiteral(params, mod1.ParametersLiteral{
		LevelQ:          0,
		LogScale:        params.LogDefaultScale(),
		Mod1Type:        mod1.SinContinuous,
		Scaling:         1,
		LogMessageRatio: 4,
		K:               1,
		Mod1Degree:      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := rlwe.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisElements := rlwe.GaloisElementsForTrace(params, modUpObservedTestLogSlots)
	galoisKeys := make([]*rlwe.GaloisKey, len(galoisElements))
	for i, galEl := range galoisElements {
		galoisKeys[i] = keyGenerator.GenGaloisKeyNew(galEl, secretKey)
	}
	keySet := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)

	plaintext := ckks.NewPlaintext(params, 0)
	if err = ckks.NewEncoder(params).Encode([]complex128{0.125, -0.25, 0.375, -0.5}, plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	return modUpObservedTestFixture{
		params: params, mod1: mod1Parameters, keySet: keySet, ciphertext: ciphertext,
	}
}

func newCanonicalN16L11ModUpObservedTestFixture(t *testing.T) modUpObservedTestFixture {
	t.Helper()
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            16,
		LogQ:            []int{30, 29},
		LogP:            []int{30},
		LogDefaultScale: 20,
		Xs:              ring.Ternary{H: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	if params.RingType() != ring.Standard || params.LogN() != 16 {
		t.Fatalf("invalid canonical test ring: type=%d logN=%d", params.RingType(), params.LogN())
	}
	mod1Parameters, err := mod1.NewParametersFromLiteral(params, mod1.ParametersLiteral{
		LevelQ:          0,
		LogScale:        params.LogDefaultScale(),
		Mod1Type:        mod1.SinContinuous,
		Scaling:         1,
		LogMessageRatio: 4,
		K:               1,
		Mod1Degree:      1,
	})
	if err != nil {
		t.Fatal(err)
	}

	wantGaloisElements := []uint64{122881, 114689, 98305, 65537}
	keyGenerator := rlwe.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisKeys := make([]*rlwe.GaloisKey, len(wantGaloisElements))
	for i, galEl := range wantGaloisElements {
		galoisKeys[i] = keyGenerator.GenGaloisKeyNew(galEl, secretKey)
	}
	keySet := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	if got := keySet.GetGaloisKeysList(); len(got) != 4 {
		t.Fatalf("minimal N16 fixture installed %d Trace keys, want 4", len(got))
	}

	ciphertext := ckks.NewCiphertext(params, 1, 0)
	q := params.Q()[0]
	for j := range ciphertext.Value[0].Coeffs[0] {
		ciphertext.Value[0].Coeffs[0][j] = (uint64(j)*17 + 3) % q
		ciphertext.Value[1].Coeffs[0][j] = (uint64(j)*29 + 5) % q
	}
	ringQ := params.RingQ().AtLevel(0)
	ringQ.NTT(ciphertext.Value[0], ciphertext.Value[0])
	ringQ.NTT(ciphertext.Value[1], ciphertext.Value[1])
	ciphertext.IsNTT = true

	return modUpObservedTestFixture{
		params: params, mod1: mod1Parameters, keySet: keySet, ciphertext: ciphertext,
	}
}

func (fixture modUpObservedTestFixture) newEvaluator(keySet rlwe.EvaluationKeySet, withDenseToSparse bool) Evaluator {
	return fixture.newEvaluatorForLogSlots(keySet, withDenseToSparse, modUpObservedTestLogSlots)
}

func (fixture modUpObservedTestFixture) newEvaluatorForLogSlots(keySet rlwe.EvaluationKeySet, withDenseToSparse bool, logSlots int) Evaluator {
	evaluationKeys := &EvaluationKeys{MemEvaluationKeySet: fixture.keySet}
	if withDenseToSparse {
		evaluationKeys.EvkDenseToSparse = rlwe.NewEvaluationKey(fixture.params)
	}
	return Evaluator{
		Parameters: Parameters{
			ResidualParameters:      fixture.params,
			BootstrappingParameters: fixture.params,
			CoeffsToSlotsParameters: dft.MatrixLiteral{LogSlots: logSlots},
		},
		Evaluator:      ckks.NewEvaluator(fixture.params, keySet),
		EvaluationKeys: evaluationKeys,
		Mod1Parameters: fixture.mod1,
	}
}
