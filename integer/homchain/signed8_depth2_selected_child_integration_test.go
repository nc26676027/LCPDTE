package homchain

import (
	"math"
	"math/cmplx"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
)

func TestSigned8Depth2SelectedChildEncryptedFourPathsPublic(t *testing.T) {
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		t.Fatal(err)
	}
	base := newSigned8ComparatorFixture(t, ranges)
	tree := signed8Depth2TestTree()
	circuit, err := NewSigned8Depth2SelectedChildCircuit(base.circuit, tree)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}

	rootWords := [4]int64{-1, -1, 1, 1}
	leftWords := [4]int64{-5, -4, 0, 0}
	rightWords := [4]int64{0, 0, 2, 3}
	ciphertexts := []*rlwe.Ciphertext{
		base.encryptSigned(t, rootWords),
		base.encryptSigned(t, leftWords),
		base.encryptSigned(t, rightWords),
	}
	input, err := circuit.BindCiphertexts(ciphertexts, base.params)
	if err != nil {
		t.Fatal(err)
	}
	inputBefore := cloneSigned8Depth2SelectedChildInput(input)
	result, trace, err := evaluator.EvaluatePublicNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSigned8Depth2SelectedChildInputs(input, inputBefore) {
		t.Fatal("complete selected-child evaluation mutated its admitted input")
	}
	if err = circuit.validateResult(result); err != nil {
		t.Fatalf("selected-child result did not validate: %v", err)
	}
	if err = circuit.validateTrace(input, result, trace); err != nil {
		t.Fatalf("selected-child trace did not validate: %v", err)
	}
	if err = evaluator.preflight(); err != nil {
		t.Fatalf("selected-child evaluator changed after accepted scratch use: %v", err)
	}

	got := decodeSigned8Depth2Child(t, base.integerEncoder, base.decryptor, result.Ciphertext())
	tolerance := circuit.terminal.Profile().MagnitudeCertificate().OutputToleranceFloat64Up()
	maxRealError, maxImagError := 0.0, 0.0
	for word := 0; word < signed8Words; word++ {
		want, oracleErr := tree.Evaluate([]int8{int8(rootWords[word]), int8(leftWords[word]), int8(rightWords[word])})
		if oracleErr != nil {
			t.Fatal(oracleErr)
		}
		for slot := 4 * word; slot < 4*(word+1); slot++ {
			realError := math.Abs(real(got[slot]) - want)
			imagError := math.Abs(imag(got[slot]))
			maxRealError = math.Max(maxRealError, realError)
			maxImagError = math.Max(maxImagError, imagError)
			if realError > tolerance || imagError > tolerance {
				t.Fatalf("selected-child word=%d slot=%d got=%v want=%g errors=%g/%g tolerance=%g",
					word, slot, got[slot], want, realError, imagError, tolerance)
			}
		}
	}

	rootCounts := trace.RootComparatorTrace().WrapperOperationCounts()
	childCounts := trace.ChildComparatorTrace().OperationCounts()
	if rootCounts.CiphertextPlaintextSubtractions != 1 || rootCounts.CiphertextCiphertextSubtractions != 0 ||
		childCounts.CiphertextCiphertextSubtractions != 1 ||
		trace.RootComparatorTrace().OperandMode() != Signed8PublicThresholdCTPT ||
		result.TerminalResult().OperandMode() != Signed8PublicThresholdCTPT ||
		trace.TerminalTrace().DecoderResult().OperandMode() != Signed8PublicThresholdCTPT {
		t.Fatalf("selected-child operand schedule changed: root=%+v child=%+v mode=%s",
			rootCounts, childCounts, result.TerminalResult().OperandMode())
	}
	bytes := trace.ByteLedger()
	durations := trace.StageDurations()
	if bytes.ModuleReportedSum() <= 0 || bytes.TerminalComposedUnique != 106662 ||
		durations.Sum() <= 0 || durations.Sum() > trace.WallTime() || trace.Digest() == "" ||
		trace.Linkage().Digest() == "" || trace.Linkage().Digest() != result.LinkageDigest() {
		t.Fatalf("selected-child evidence ledger changed: bytes=%+v durations=%+v wall=%s", bytes, durations, trace.WallTime())
	}

	outputCopy := result.Ciphertext()
	outputCopy.Value[0].Coeffs[0][0]++
	if result.Ciphertext().Equal(outputCopy) {
		t.Fatal("selected-child result leaked its owned output ciphertext")
	}

	// Recompute every outer digest after changing a linkage field. Validation
	// must still reject because the linkage no longer matches the typed root
	// selector input retained by the trace.
	mutatedTrace := trace
	mutatedTrace.linkage.RootComparatorOutputPayloadDigest = digestString("foreign-root-output")
	mutatedTrace.linkage.digest = digestSigned8Depth2SelectedChildLinkage(mutatedTrace.linkage)
	mutatedTrace.linkageDigest = mutatedTrace.linkage.digest
	mutatedResult := result
	mutatedResult.linkageDigest = mutatedTrace.linkageDigest
	mutatedResult.provenanceDigest = digestSigned8Depth2SelectedChildResult(mutatedResult)
	mutatedTrace.resultProvenanceDigest = mutatedResult.provenanceDigest
	mutatedTrace.traceDigest = digestSigned8Depth2SelectedChildTrace(mutatedTrace)
	if err = circuit.validateTrace(input, mutatedResult, mutatedTrace); err == nil {
		t.Fatal("self-consistently resealed foreign root linkage was admitted")
	}

	mutatedNested := trace
	mutatedNested.rootComparator.wrapperCounts.CiphertextPlaintextSubtractions++
	mutatedNested.traceDigest = digestSigned8Depth2SelectedChildTrace(mutatedNested)
	if err = circuit.validateTrace(input, result, mutatedNested); err == nil {
		t.Fatal("self-consistently resealed root operation overcount was admitted")
	}

	// The chosen words deliberately cover all four paths, including equality
	// at the left threshold (-4) and right threshold (3), both of which route GE.
	wantPaths := [4]int{0, 1, 2, 3}
	for word := range wantPaths {
		path, routeErr := tree.Route([]int8{int8(rootWords[word]), int8(leftWords[word]), int8(rightWords[word])})
		if routeErr != nil || path != wantPaths[word] {
			t.Fatalf("word %d path=%d err=%v, want %d", word, path, routeErr, wantPaths[word])
		}
	}
	if cmplx.Abs(got[4]-complex(tree.Leaves[1], 0)) > tolerance ||
		cmplx.Abs(got[12]-complex(tree.Leaves[3], 0)) > tolerance {
		t.Fatal("equality did not route to the GE/right child")
	}

	t.Logf("selected-child depth2: profile=%s result=%s trace=%s linkage=%s wall=%s stages=%+v bytes=%+v module-sum=%d real-max=%g imag-max=%g tolerance=%g",
		circuit.Profile().Digest(), result.ProvenanceDigest(), trace.Digest(), trace.Linkage().Digest(),
		trace.WallTime(), durations, bytes, bytes.ModuleReportedSum(), maxRealError, maxImagError, tolerance)
}
