// Modified by the LCPDTE project for local module integration and, where applicable,
// runtime instrumentation. See lattigo/NOTICE for attribution and modification details.

package rlwe

import (
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/utils/sampling"
)

type traceObservedTestKeySet struct {
	base    EvaluationKeySet
	mu      sync.Mutex
	calls   []uint64
	failAt  int
	panicAt int
}

func (keySet *traceObservedTestKeySet) GetGaloisKey(galEl uint64) (*GaloisKey, error) {
	keySet.mu.Lock()
	keySet.calls = append(keySet.calls, galEl)
	call := len(keySet.calls)
	failAt := keySet.failAt
	panicAt := keySet.panicAt
	keySet.mu.Unlock()

	if call == panicAt {
		panic(fmt.Sprintf("injected Trace dispatch panic %d", call))
	}
	if call == failAt {
		return nil, fmt.Errorf("injected Trace dispatch error %d", call)
	}
	return keySet.base.GetGaloisKey(galEl)
}

func (keySet *traceObservedTestKeySet) GetGaloisKeysList() []uint64 {
	return keySet.base.GetGaloisKeysList()
}

func (keySet *traceObservedTestKeySet) GetRelinearizationKey() (*RelinearizationKey, error) {
	return keySet.base.GetRelinearizationKey()
}

func (keySet *traceObservedTestKeySet) ShallowCopy() EvaluationKeySet { return keySet }

func (keySet *traceObservedTestKeySet) Calls() []uint64 {
	keySet.mu.Lock()
	defer keySet.mu.Unlock()
	return append([]uint64(nil), keySet.calls...)
}

func traceObservedTestParameters(t *testing.T) Parameters {
	t.Helper()
	params, err := NewParametersFromLiteral(ParametersLiteral{
		LogN:    4,
		LogQ:    []int{30, 30, 30},
		LogP:    []int{30, 30},
		NTTFlag: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func traceObservedTestParametersForRing(t *testing.T, ringType ring.Type) Parameters {
	t.Helper()
	params, err := NewParametersFromLiteral(ParametersLiteral{
		LogN:     4,
		LogQ:     []int{30, 30, 30},
		LogP:     []int{30, 30},
		RingType: ringType,
		NTTFlag:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func traceObservedTestBaseKeySet(t *testing.T, params Parameters, galEls []uint64) EvaluationKeySet {
	t.Helper()
	keyGenerator := NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	return NewMemEvaluationKeySet(nil, keyGenerator.GenGaloisKeysNew(galEls, secretKey)...)
}

func traceObservedTestCiphertext(t *testing.T, params Parameters, isNTT bool) *Ciphertext {
	t.Helper()
	prng, err := sampling.NewKeyedPRNG([]byte("trace-observed-test-input"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := NewCiphertextRandom(prng, params, 1, params.MaxLevel())
	ciphertext.Scale = NewScale(1 << 20)
	if !isNTT {
		ringQ := params.RingQ().AtLevel(ciphertext.Level())
		ringQ.INTT(ciphertext.Value[0], ciphertext.Value[0])
		ringQ.INTT(ciphertext.Value[1], ciphertext.Value[1])
		ciphertext.IsNTT = false
	}
	return ciphertext
}

func TestTraceObservedMatchesStockAndRecordsSourceOrder(t *testing.T) {
	params := traceObservedTestParameters(t)
	const logN = 1
	wantGalois := []uint64{25, 17}
	base := traceObservedTestBaseKeySet(t, params, wantGalois)
	stockKeySet := &traceObservedTestKeySet{base: base}
	observedKeySet := &traceObservedTestKeySet{base: base}
	stockEvaluator := NewEvaluator(params, stockKeySet)
	observedEvaluator := NewEvaluator(params, observedKeySet)

	input := NewCiphertext(params, 1, params.MaxLevel())
	stockOutput := NewCiphertext(params, 1, params.MaxLevel())
	observedOutput := NewCiphertext(params, 1, params.MaxLevel())

	if err := stockEvaluator.Trace(input.CopyNew(), logN, stockOutput); err != nil {
		t.Fatal(err)
	}
	report, err := observedEvaluator.TraceObserved(input.CopyNew(), logN, observedOutput)
	if err != nil {
		t.Fatal(err)
	}
	if !stockOutput.Equal(observedOutput) {
		t.Fatal("observed Trace output differs from stock Trace")
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("invalid observed report: %v", err)
	}
	if report.Status() != TraceDispatchSuccess || report.FailureKind() != TraceDispatchFailureNone ||
		report.FailureStage() != TraceDispatchStageNone {
		t.Fatalf("unexpected success ledger: status=%d kind=%d stage=%d", report.Status(), report.FailureKind(), report.FailureStage())
	}

	events := report.Events()
	if len(events) != len(wantGalois) {
		t.Fatalf("event count=%d, want %d", len(events), len(wantGalois))
	}
	gotGalois := make([]uint64, len(events))
	for i, event := range events {
		if event.Sequence() != uint32(i) || event.Kind() != TraceDispatchAutomorphism ||
			!event.HasOrdinaryExponent() || event.OrdinaryExponent() != uint64(1<<(logN+i)) || !event.Completed() {
			t.Fatalf("event %d has unexpected shape", i)
		}
		gotGalois[i] = event.GaloisElement()
	}
	if !reflect.DeepEqual(gotGalois, wantGalois) {
		t.Fatalf("source-order dispatches=%v, want %v", gotGalois, wantGalois)
	}
	stockCalls := stockKeySet.Calls()
	observedCalls := observedKeySet.Calls()
	if !reflect.DeepEqual(stockCalls, wantGalois) || !reflect.DeepEqual(observedCalls, wantGalois) ||
		!reflect.DeepEqual(stockCalls, observedCalls) {
		t.Fatalf("stock lookups=%v observed lookups=%v, want independent literal %v", stockCalls, observedCalls, wantGalois)
	}
}

func TestTraceObservedDispatchErrorAndPanicPrefixes(t *testing.T) {
	params := traceObservedTestParameters(t)
	const logN = 0
	wantGalois := GaloisElementsForTrace(params, logN)
	base := traceObservedTestBaseKeySet(t, params, wantGalois)

	for dispatch := 1; dispatch <= len(wantGalois); dispatch++ {
		t.Run(fmt.Sprintf("error-%d", dispatch), func(t *testing.T) {
			keySet := &traceObservedTestKeySet{base: base, failAt: dispatch}
			evaluator := NewEvaluator(params, keySet)
			ciphertext := NewCiphertext(params, 1, params.MaxLevel())
			report, err := evaluator.TraceObserved(ciphertext, logN, ciphertext)
			if err == nil {
				t.Fatal("injected dispatch error was not returned")
			}
			assertTraceObservedFailurePrefix(t, report, TraceDispatchFailureError, dispatch, wantGalois)
			if calls := keySet.Calls(); !reflect.DeepEqual(calls, wantGalois[:dispatch]) {
				t.Fatalf("key lookups=%v, want %v", calls, wantGalois[:dispatch])
			}
		})

		t.Run(fmt.Sprintf("panic-%d", dispatch), func(t *testing.T) {
			keySet := &traceObservedTestKeySet{base: base, panicAt: dispatch}
			evaluator := NewEvaluator(params, keySet)
			ciphertext := NewCiphertext(params, 1, params.MaxLevel())
			report, err := evaluator.TraceObserved(ciphertext, logN, ciphertext)
			if err == nil {
				t.Fatal("injected dispatch panic was not returned as an error")
			}
			assertTraceObservedFailurePrefix(t, report, TraceDispatchFailurePanic, dispatch, wantGalois)
			if calls := keySet.Calls(); !reflect.DeepEqual(calls, wantGalois[:dispatch]) {
				t.Fatalf("key lookups=%v, want %v", calls, wantGalois[:dispatch])
			}
		})
	}
}

func TestTraceObservedPreservesStockAliasNTTMetadataAndRuntimeIdentity(t *testing.T) {
	params := traceObservedTestParameters(t)
	const logN = 1
	wantGalois := GaloisElementsForTrace(params, logN)
	base := traceObservedTestBaseKeySet(t, params, wantGalois)

	for _, isNTT := range []bool{true, false} {
		for _, aliased := range []bool{true, false} {
			name := fmt.Sprintf("ntt-%t-aliased-%t", isNTT, aliased)
			t.Run(name, func(t *testing.T) {
				input := traceObservedTestCiphertext(t, params, isNTT)
				stockInput := input.CopyNew()
				observedInput := input.CopyNew()
				var stockOutput, observedOutput *Ciphertext
				if aliased {
					stockOutput = stockInput
					observedOutput = observedInput
				} else {
					stockOutput = NewCiphertext(params, 1, params.MaxLevel()-1)
					observedOutput = NewCiphertext(params, 1, params.MaxLevel()-1)
				}

				stockEvaluator := NewEvaluator(params, base)
				observedKeySet := &traceObservedTestKeySet{base: base}
				observedEvaluator := NewEvaluator(params, observedKeySet)
				identityBefore, err := observedEvaluator.RuntimeIdentitySnapshot()
				if err != nil {
					t.Fatal(err)
				}
				if err = stockEvaluator.Trace(stockInput, logN, stockOutput); err != nil {
					t.Fatal(err)
				}
				report, err := observedEvaluator.TraceObserved(observedInput, logN, observedOutput)
				if err != nil {
					t.Fatal(err)
				}
				identityAfter, err := observedEvaluator.RuntimeIdentitySnapshot()
				if err != nil {
					t.Fatal(err)
				}

				if !stockOutput.Equal(observedOutput) || !stockOutput.MetaData.Equal(observedOutput.MetaData) ||
					stockOutput.Level() != observedOutput.Level() || !stockOutput.Scale.Equal(observedOutput.Scale) ||
					stockOutput.IsNTT != observedOutput.IsNTT {
					t.Fatal("observed Trace changed stock ciphertext bytes, metadata, level, scale or NTT state")
				}
				if !identityBefore.Equal(identityAfter) {
					t.Fatal("Trace observation changed evaluator runtime identity")
				}
				if err := report.Validate(); err != nil {
					t.Fatal(err)
				}
				if report.InputOutputAliased() != aliased {
					t.Fatalf("alias flag=%t, want %t", report.InputOutputAliased(), aliased)
				}
				if calls := observedKeySet.Calls(); !reflect.DeepEqual(calls, wantGalois) {
					t.Fatalf("key lookups=%v, want %v", calls, wantGalois)
				}
			})
		}
	}
}

func TestTraceObservedPreservesStockErrorAndStockPanic(t *testing.T) {
	params := traceObservedTestParameters(t)
	const logN = 0
	wantGalois := GaloisElementsForTrace(params, logN)
	base := traceObservedTestBaseKeySet(t, params, wantGalois)

	for _, aliased := range []bool{true, false} {
		t.Run(fmt.Sprintf("error-aliased-%t", aliased), func(t *testing.T) {
			stockErrorKeySet := &traceObservedTestKeySet{base: base, failAt: 2}
			observedErrorKeySet := &traceObservedTestKeySet{base: base, failAt: 2}
			stockErrorEvaluator := NewEvaluator(params, stockErrorKeySet)
			observedErrorEvaluator := NewEvaluator(params, observedErrorKeySet)
			stockInput := traceObservedTestCiphertext(t, params, true)
			observedInput := stockInput.CopyNew()
			var stockOutput, observedOutput *Ciphertext
			if aliased {
				stockOutput = stockInput
				observedOutput = observedInput
			} else {
				stockOutput = NewCiphertext(params, 1, params.MaxLevel())
				observedOutput = NewCiphertext(params, 1, params.MaxLevel())
			}
			stockErr := stockErrorEvaluator.Trace(stockInput, logN, stockOutput)
			report, observedErr := observedErrorEvaluator.TraceObserved(observedInput, logN, observedOutput)
			if stockErr == nil || observedErr == nil || stockErr.Error() != observedErr.Error() {
				t.Fatalf("stock error=%v observed error=%v", stockErr, observedErr)
			}
			if !stockInput.Equal(observedInput) || !stockOutput.Equal(observedOutput) {
				t.Fatal("observed ordinary error changed the stock input or partial output")
			}
			if report.InputOutputAliased() != aliased {
				t.Fatalf("error alias flag=%t, want %t", report.InputOutputAliased(), aliased)
			}
			assertTraceObservedFailurePrefix(t, report, TraceDispatchFailureError, 2, wantGalois)
		})
	}

	stockPanicKeySet := &traceObservedTestKeySet{base: base, panicAt: 2}
	stockPanicEvaluator := NewEvaluator(params, stockPanicKeySet)
	stockPanic := captureTraceObservedTestPanic(func() {
		ciphertext := traceObservedTestCiphertext(t, params, true)
		_ = stockPanicEvaluator.Trace(ciphertext, logN, ciphertext)
	})
	if stockPanic == nil {
		t.Fatal("stock Trace unexpectedly recovered the injected panic")
	}
}

func TestTraceObservedValidationFailureMatchesStockWithZeroDispatch(t *testing.T) {
	params := traceObservedTestParameters(t)
	stockEvaluator := NewEvaluator(params, nil)
	observedEvaluator := NewEvaluator(params, nil)
	stockInput := NewCiphertext(params, 2, params.MaxLevel())
	observedInput := stockInput.CopyNew()
	stockOutput := NewCiphertext(params, 1, params.MaxLevel())
	observedOutput := stockOutput.CopyNew()
	stockErr := stockEvaluator.Trace(stockInput, 1, stockOutput)
	report, observedErr := observedEvaluator.TraceObserved(observedInput, 1, observedOutput)
	if stockErr == nil || observedErr == nil || stockErr.Error() != observedErr.Error() {
		t.Fatalf("stock error=%v observed error=%v", stockErr, observedErr)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.Status() != TraceDispatchFailure || report.FailureKind() != TraceDispatchFailureError ||
		report.FailureStage() != TraceDispatchStageValidation || report.AttemptedDispatches() != 0 ||
		report.CompletedDispatches() != 0 || len(report.Events()) != 0 {
		t.Fatalf("unexpected validation failure report: %+v", report)
	}
}

func captureTraceObservedTestPanic(f func()) (recovered any) {
	defer func() { recovered = recover() }()
	f()
	return nil
}

func TestTraceObservedGapAtMostOneCopiesWithoutDispatch(t *testing.T) {
	params := traceObservedTestParameters(t)
	input := traceObservedTestCiphertext(t, params, false)
	output := NewCiphertext(params, 1, params.MaxLevel()-1)
	evaluator := NewEvaluator(params, nil)
	report, err := evaluator.TraceObserved(input, params.LogN()-1, output)
	if err != nil {
		t.Fatal(err)
	}
	if !output.Equal(input) {
		t.Fatal("gap<=1 distinct-output Trace did not preserve the stock copy behavior")
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.Status() != TraceDispatchSuccess || report.AttemptedDispatches() != 0 ||
		report.CompletedDispatches() != 0 || len(report.Events()) != 0 || report.InputOutputAliased() {
		t.Fatalf("unexpected zero-dispatch report: %+v", report)
	}
}

func TestTraceObservedLogNZeroRingTypeShapesAndCrossWireRejection(t *testing.T) {
	standardParams := traceObservedTestParametersForRing(t, ring.Standard)
	standardGalois := GaloisElementsForTrace(standardParams, 0)
	standardBase := traceObservedTestBaseKeySet(t, standardParams, standardGalois)
	standardEvaluator := NewEvaluator(standardParams, standardBase)
	standardCiphertext := traceObservedTestCiphertext(t, standardParams, true)
	standardReport, err := standardEvaluator.TraceObserved(standardCiphertext, 0, standardCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if err := standardReport.Validate(); err != nil {
		t.Fatal(err)
	}
	standardEvents := standardReport.Events()
	if len(standardEvents) != standardParams.LogN() || standardReport.RingType() != ring.Standard {
		t.Fatalf("unexpected standard-ring event shape: %d events", len(standardEvents))
	}
	last := standardEvents[len(standardEvents)-1]
	if last.Kind() != TraceDispatchOrderTwoAutomorphism || last.HasOrdinaryExponent() ||
		last.OrdinaryExponent() != 0 || last.GaloisElement() != standardParams.RingQ().NthRoot()-1 || !last.Completed() {
		t.Fatal("standard-ring final event is not the tagged order-two automorphism")
	}

	conjugateParams := traceObservedTestParametersForRing(t, ring.ConjugateInvariant)
	conjugateGalois := traceObservedOrdinaryGaloisElements(conjugateParams, 0)
	conjugateBase := traceObservedTestBaseKeySet(t, conjugateParams, conjugateGalois)
	conjugateEvaluator := NewEvaluator(conjugateParams, conjugateBase)
	conjugateCiphertext := traceObservedTestCiphertext(t, conjugateParams, true)
	conjugateReport, err := conjugateEvaluator.TraceObserved(conjugateCiphertext, 0, conjugateCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if err := conjugateReport.Validate(); err != nil {
		t.Fatal(err)
	}
	conjugateEvents := conjugateReport.Events()
	if len(conjugateEvents) != conjugateParams.LogN()-1 || conjugateReport.RingType() != ring.ConjugateInvariant {
		t.Fatalf("unexpected conjugate-invariant event shape: %d events", len(conjugateEvents))
	}
	for index, event := range conjugateEvents {
		if event.Kind() != TraceDispatchAutomorphism || !event.HasOrdinaryExponent() ||
			event.GaloisElement() != conjugateGalois[index] {
			t.Fatalf("conjugate-invariant event %d has an invalid tag", index)
		}
	}

	standardAsConjugate := cloneTraceDispatchReportForTest(standardReport)
	standardAsConjugate.ringType = ring.ConjugateInvariant
	standardAsConjugate.digest = digestTraceDispatchReport(standardAsConjugate)
	if err := standardAsConjugate.Validate(); err == nil {
		t.Fatal("standard order-two report validated as conjugate-invariant")
	}
	conjugateAsStandard := cloneTraceDispatchReportForTest(conjugateReport)
	conjugateAsStandard.ringType = ring.Standard
	conjugateAsStandard.digest = digestTraceDispatchReport(conjugateAsStandard)
	if err := conjugateAsStandard.Validate(); err == nil {
		t.Fatal("conjugate-invariant report validated as standard")
	}
}

func traceObservedOrdinaryGaloisElements(params Parameters, logN int) []uint64 {
	result := make([]uint64, 0, params.LogN()-logN-1)
	for i := logN; i < params.LogN()-1; i++ {
		result = append(result, params.GaloisElement(1<<i))
	}
	return result
}

func cloneTraceDispatchReportForTest(report TraceDispatchReport) TraceDispatchReport {
	report.events = append([]TraceDispatchEvent(nil), report.events...)
	return report
}

func TestRealN16TraceObservedL11SourceOrder(t *testing.T) {
	// This is deliberately the smallest self-contained standard-ring fixture
	// that can execute the four real L11 Trace automorphisms: one Q prime, one
	// P prime, and exactly the four required Galois keys.
	runtime.GC()
	var memoryBefore runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	fixtureStarted := time.Now()

	params, err := NewParametersFromLiteral(ParametersLiteral{
		LogN:     16,
		LogQ:     []int{30},
		LogP:     []int{30},
		RingType: ring.Standard,
		NTTFlag:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantGalois := []uint64{122881, 114689, 98305, 65537}
	base := traceObservedTestBaseKeySet(t, params, wantGalois)
	countingKeys := &traceObservedTestKeySet{base: base}
	evaluator := NewEvaluator(params, countingKeys)
	ciphertext := NewCiphertext(params, 1, params.MaxLevel())

	traceStarted := time.Now()
	report, err := evaluator.TraceObserved(ciphertext, 11, ciphertext)
	traceElapsed := time.Since(traceStarted)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.RingLogN() != 16 || report.RingType() != ring.Standard || report.RequestedLogN() != 11 ||
		!report.InputOutputAliased() || report.AttemptedDispatches() != 4 || report.CompletedDispatches() != 4 {
		t.Fatalf("unexpected real N16/L11 ledger: %+v", report)
	}
	events := report.Events()
	if len(events) != len(wantGalois) {
		t.Fatalf("real N16/L11 event count=%d, want %d", len(events), len(wantGalois))
	}
	for index, event := range events {
		wantExponent := uint64(1) << (11 + index)
		if event.Sequence() != uint32(index) || event.Kind() != TraceDispatchAutomorphism ||
			!event.HasOrdinaryExponent() || event.OrdinaryExponent() != wantExponent ||
			event.GaloisElement() != wantGalois[index] || !event.Completed() {
			t.Fatalf("real N16/L11 event %d has unexpected source-order evidence", index)
		}
	}
	if calls := countingKeys.Calls(); !reflect.DeepEqual(calls, wantGalois) {
		t.Fatalf("real N16/L11 key lookups=%v, want independent literal %v", calls, wantGalois)
	}

	var memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryAfter)
	t.Logf("real N16/L11 fixture elapsed=%s TraceObserved elapsed=%s total-allocated=%.1f MiB heap-live-delta=%.1f MiB",
		time.Since(fixtureStarted), traceElapsed,
		float64(memoryAfter.TotalAlloc-memoryBefore.TotalAlloc)/(1<<20),
		float64(int64(memoryAfter.HeapAlloc)-int64(memoryBefore.HeapAlloc))/(1<<20))
}

func TestTraceDispatchReportDefensiveCopiesDigestCoverageAndSemanticValidation(t *testing.T) {
	params := traceObservedTestParameters(t)
	base := traceObservedTestBaseKeySet(t, params, GaloisElementsForTrace(params, 0))
	evaluator := NewEvaluator(params, base)
	ciphertext := traceObservedTestCiphertext(t, params, true)
	report, err := evaluator.TraceObserved(ciphertext, 0, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}

	firstCopy := report.Events()
	firstCopy[0].galoisElement = 0
	secondCopy := report.Events()
	if secondCopy[0].galoisElement == 0 || &firstCopy[0] == &secondCopy[0] {
		t.Fatal("Events did not return a defensive copy")
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("caller mutation changed the report: %v", err)
	}

	var zero TraceDispatchReport
	if !zero.IsZero() || zero.Digest() != ([32]byte{}) || zero.Validate() == nil {
		t.Fatal("zero Trace report was not rejected as absent")
	}
	if report.IsZero() || report.Digest() == ([32]byte{}) {
		t.Fatal("sealed Trace report was mistaken for zero")
	}

	digestMutations := []struct {
		name   string
		mutate func(*TraceDispatchReport)
	}{
		{"version", func(value *TraceDispatchReport) { value.version++ }},
		{"status", func(value *TraceDispatchReport) { value.status = TraceDispatchFailure }},
		{"failure-kind", func(value *TraceDispatchReport) { value.failureKind = TraceDispatchFailureError }},
		{"failure-stage", func(value *TraceDispatchReport) { value.failureStage = TraceDispatchStageDispatch }},
		{"ring-logN", func(value *TraceDispatchReport) { value.ringLogN++ }},
		{"ring-type", func(value *TraceDispatchReport) { value.ringType = ring.ConjugateInvariant }},
		{"requested-logN", func(value *TraceDispatchReport) { value.requestedLogN++ }},
		{"alias", func(value *TraceDispatchReport) { value.inputOutputAliased = !value.inputOutputAliased }},
		{"attempted", func(value *TraceDispatchReport) { value.attemptedDispatches++ }},
		{"completed", func(value *TraceDispatchReport) { value.completedDispatches-- }},
		{"event-sequence", func(value *TraceDispatchReport) { value.events[0].sequence++ }},
		{"event-kind", func(value *TraceDispatchReport) { value.events[0].kind = TraceDispatchOrderTwoAutomorphism }},
		{"event-has-exponent", func(value *TraceDispatchReport) { value.events[0].hasOrdinaryExponent = false }},
		{"event-exponent", func(value *TraceDispatchReport) { value.events[0].ordinaryExponent++ }},
		{"event-galois", func(value *TraceDispatchReport) { value.events[0].galoisElement++ }},
		{"event-completed", func(value *TraceDispatchReport) { value.events[0].completed = false }},
		{"digest", func(value *TraceDispatchReport) { value.digest[0] ^= 1 }},
	}
	for _, mutation := range digestMutations {
		t.Run("digest-"+mutation.name, func(t *testing.T) {
			mutated := cloneTraceDispatchReportForTest(report)
			mutation.mutate(&mutated)
			if err := mutated.Validate(); err == nil {
				t.Fatal("field mutation was not covered by the sealed digest")
			}
		})
	}

	semanticMutations := []struct {
		name   string
		mutate func(*TraceDispatchReport)
	}{
		{"ordinary-missing-exponent", func(value *TraceDispatchReport) { value.events[0].hasOrdinaryExponent = false }},
		{"ordinary-zero-exponent", func(value *TraceDispatchReport) { value.events[0].ordinaryExponent = 0 }},
		{"ordinary-wrong-galois", func(value *TraceDispatchReport) { value.events[0].galoisElement = 1 }},
		{"order-two-has-exponent", func(value *TraceDispatchReport) {
			last := len(value.events) - 1
			value.events[last].hasOrdinaryExponent = true
			value.events[last].ordinaryExponent = 1
		}},
		{"incomplete-not-last", func(value *TraceDispatchReport) {
			value.events[0].completed = false
			value.completedDispatches--
		}},
	}
	for _, mutation := range semanticMutations {
		t.Run("semantic-"+mutation.name, func(t *testing.T) {
			mutated := cloneTraceDispatchReportForTest(report)
			mutation.mutate(&mutated)
			mutated.digest = digestTraceDispatchReport(mutated)
			if err := mutated.Validate(); err == nil {
				t.Fatal("structurally invalid resealed report was accepted")
			}
		})
	}
}

func TestTraceDispatchReportRejectsResealedCompletedDispatchFailures(t *testing.T) {
	params := traceObservedTestParameters(t)
	wantGalois := []uint64{5, 25, 17, 31}
	base := traceObservedTestBaseKeySet(t, params, wantGalois)

	for _, failure := range []struct {
		name    string
		failAt  int
		panicAt int
	}{
		{name: "ordinary-error", failAt: 2},
		{name: "recovered-panic", panicAt: 2},
	} {
		t.Run(failure.name, func(t *testing.T) {
			keySet := &traceObservedTestKeySet{base: base, failAt: failure.failAt, panicAt: failure.panicAt}
			evaluator := NewEvaluator(params, keySet)
			ciphertext := NewCiphertext(params, 1, params.MaxLevel())
			report, err := evaluator.TraceObserved(ciphertext, 0, ciphertext)
			if err == nil || report.Validate() != nil {
				t.Fatalf("failed to obtain a valid dispatch-failure report: err=%v validate=%v", err, report.Validate())
			}

			impossible := cloneTraceDispatchReportForTest(report)
			last := len(impossible.events) - 1
			impossible.events[last].completed = true
			impossible.completedDispatches = impossible.attemptedDispatches
			impossible.digest = digestTraceDispatchReport(impossible)
			if err := impossible.Validate(); err == nil {
				t.Fatal("resealed dispatch failure with k completed out of k attempted was accepted")
			}
		})
	}
}

func TestTraceObservedRecoversValidationPanicButStockStillPanics(t *testing.T) {
	params := traceObservedTestParameters(t)
	stockEvaluator := NewEvaluator(params, nil)
	if recovered := captureTraceObservedTestPanic(func() {
		_ = stockEvaluator.Trace(nil, 1, NewCiphertext(params, 1, params.MaxLevel()))
	}); recovered == nil {
		t.Fatal("stock Trace unexpectedly recovered nil-input panic")
	}

	observedEvaluator := NewEvaluator(params, nil)
	report, err := observedEvaluator.TraceObserved(nil, 1, NewCiphertext(params, 1, params.MaxLevel()))
	if err == nil {
		t.Fatal("TraceObserved did not return the recovered nil-input panic")
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("invalid recovered validation-panic report: %v", err)
	}
	if report.Status() != TraceDispatchFailure || report.FailureKind() != TraceDispatchFailurePanic ||
		report.FailureStage() != TraceDispatchStageValidation || report.AttemptedDispatches() != 0 {
		t.Fatalf("unexpected validation-panic ledger: %+v", report)
	}
}

func TestTraceObservedConcurrentIndependentEvaluators(t *testing.T) {
	params := traceObservedTestParameters(t)
	const logN = 1
	wantGalois := GaloisElementsForTrace(params, logN)
	base := traceObservedTestBaseKeySet(t, params, wantGalois)

	const workers = 8
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			evaluator := NewEvaluator(params, base)
			ciphertext := NewCiphertext(params, 1, params.MaxLevel())
			report, err := evaluator.TraceObserved(ciphertext, logN, ciphertext)
			if err != nil {
				errors <- err
				return
			}
			if err := report.Validate(); err != nil {
				errors <- err
				return
			}
			got := report.Events()
			if len(got) != len(wantGalois) {
				errors <- fmt.Errorf("got %d dispatches, want %d", len(got), len(wantGalois))
				return
			}
			for index := range got {
				if got[index].GaloisElement() != wantGalois[index] {
					errors <- fmt.Errorf("dispatch %d=%d, want %d", index, got[index].GaloisElement(), wantGalois[index])
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
}

func assertTraceObservedFailurePrefix(t *testing.T, report TraceDispatchReport, kind TraceDispatchFailureKind, dispatch int, wantGalois []uint64) {
	t.Helper()
	if err := report.Validate(); err != nil {
		t.Fatalf("invalid failure report: %v", err)
	}
	if report.Status() != TraceDispatchFailure || report.FailureKind() != kind ||
		report.FailureStage() != TraceDispatchStageDispatch || report.AttemptedDispatches() != uint32(dispatch) ||
		report.CompletedDispatches() != uint32(dispatch-1) {
		t.Fatalf("unexpected failure ledger: status=%d kind=%d stage=%d attempted=%d completed=%d",
			report.Status(), report.FailureKind(), report.FailureStage(), report.AttemptedDispatches(), report.CompletedDispatches())
	}
	events := report.Events()
	if len(events) != dispatch {
		t.Fatalf("events=%d, want %d", len(events), dispatch)
	}
	for index, event := range events {
		if event.Sequence() != uint32(index) || event.GaloisElement() != wantGalois[index] ||
			event.Completed() != (index < dispatch-1) {
			t.Fatalf("failure event %d has unexpected prefix shape", index)
		}
	}
}
