package homchain_test

import (
	"math"
	"math/cmplx"
	"reflect"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestA2BFullIngress6A5ExecutesTheMeasuredFirstSTCAndAcceptedSuffix(t *testing.T) {
	base := newA2BFullFixture(t)
	ranges := homchain.NewA2BFullIngress6FullRingRangeCertificate()
	circuit, err := homchain.NewA2BFullIngress6Circuit(
		base.params,
		ckks.NewEncoder(base.params, a2bRefreshTestPrecision),
		ckks.NewEncoder(base.params, 256),
		homchain.A2BFullIngress6StandaloneTestFixtureV1,
		ranges,
	)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := base.encrypt(t, [4]uint64{0xa5, 0xa5, 0xa5, 0xa5})
	base.source.Evaluator.DropLevel(ciphertext, ciphertext.Level()-6)
	input, err := circuit.BindInput(ciphertext, base.params)
	if err != nil {
		t.Fatal(err)
	}
	result, trace, err := evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	assertRepeatedA2BRefreshBlock(t, base.kernelEncoder, base.decryptor, result.LowMSB(), []float64{1, 0, 1, 0}, 3e-3)
	assertRepeatedA2BRefreshBlock(t, base.kernelEncoder, base.decryptor, result.HighMSB(), []float64{0, 1, 0, 1}, 3e-3)
	factor0, ok0 := trace.State(homchain.A2BFullIngress6StageIter0STCFactor0)
	factor1, ok1 := trace.State(homchain.A2BFullIngress6StageIter0STCFactor1)
	if !ok0 || !ok1 || factor0.Level != 3 || factor1.Level != 2 ||
		!factor0.Scale.EqualScale(base.params.DefaultScale()) || !factor1.Scale.EqualScale(base.params.DefaultScale()) {
		t.Fatalf("first STC factor trace changed: factor0=%+v/%t factor1=%+v/%t", factor0, ok0, factor1, ok1)
	}
	if trace.ProfileDigest() != circuit.Profile().Digest() || trace.RangeDigest() != ranges.Digest() ||
		trace.AdmissionDigest() != circuit.Profile().AdmissionDigest() || trace.InputBindingDigest() != input.BindingDigest() {
		t.Fatalf("ingress6 trace lost admission provenance: %+v", trace)
	}
	if got, want := trace.States(), circuit.Profile().ExpectedStates(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ingress6 runtime states differ from sealed order:\n got=%+v\nwant=%+v", got, want)
	}
	if got, want := trace.OperationCounts(), circuit.Profile().OperationCounts(); got != want {
		t.Fatalf("ingress6 runtime operation counts=%+v, want %+v", got, want)
	}
	if got, want := trace.RuntimeGaloisElements(), circuit.RequiredKeyProfile().All(); !reflect.DeepEqual(got, want) || !trace.RelinearizationKeyMatched() {
		t.Fatalf("ingress6 runtime key graph=%v/relin=%t, want %v/true", got, trace.RelinearizationKeyMatched(), want)
	}
	if got, want := trace.SerializedBytes(), circuit.Profile().ExpectedSerializedBytes(); !reflect.DeepEqual(got, want) || !got.Complete() {
		t.Fatalf("ingress6 runtime serialized bytes=%+v, want %+v", got, want)
	}
	wantBytes := []int{
		3998, 3470, 3470, 2942, 2414, 1886, 830, 11390, 9806, 3470, 3470, 2942, 2942,
		2942, 3470, 3470, 2414, 1358, 830, 11390, 9806, 3470, 3470, 2942, 2942,
	}
	serialized := trace.SerializedBytes()
	boundaries := serialized.RetainedBoundaries()
	if serialized.OnlineInputBytes() != 3998 || serialized.OnlineLowOutputBytes() != 3470 ||
		serialized.OnlineHighOutputBytes() != 3470 || serialized.OnlineTotal() != 10938 ||
		serialized.RetainedTraceTotal() != 101534 || len(boundaries) != len(wantBytes) {
		t.Fatalf("ingress6 exact serialized totals changed: online=%d/%d/%d total=%d retained=%d boundaries=%d",
			serialized.OnlineInputBytes(), serialized.OnlineLowOutputBytes(), serialized.OnlineHighOutputBytes(),
			serialized.OnlineTotal(), serialized.RetainedTraceTotal(), len(boundaries))
	}
	for index, state := range trace.States() {
		retained, ok := trace.RetainedCiphertext(state.Stage)
		if !ok || retained == nil {
			t.Fatalf("ingress6 stage %d/%q has no real retained runtime ciphertext", index, state.Stage)
		}
		payload, marshalErr := retained.MarshalBinary()
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if boundaries[index].Stage != state.Stage || boundaries[index].Bytes != wantBytes[index] ||
			state.SerializedBytes != wantBytes[index] || len(payload) != wantBytes[index] {
			t.Fatalf("ingress6 stage %d/%q serialized bytes boundary/state/runtime=%d/%d/%d, want %d",
				index, state.Stage, boundaries[index].Bytes, state.SerializedBytes, len(payload), wantBytes[index])
		}
		retained.Resize(retained.Degree(), 0)
		fresh, freshOK := trace.RetainedCiphertext(state.Stage)
		if !freshOK || fresh.Level() != state.Level {
			t.Fatalf("ingress6 retained runtime ciphertext %q accessor aliases trace storage", state.Stage)
		}
	}
}

func TestA2BFullIngress6PostBindKeyTamperFailsBeforeAnyCiphertextOperation(t *testing.T) {
	base := newA2BFullFixture(t)
	circuit, err := homchain.NewA2BFullIngress6Circuit(
		base.params,
		ckks.NewEncoder(base.params, a2bRefreshTestPrecision),
		ckks.NewEncoder(base.params, 256),
		homchain.A2BFullIngress6StandaloneTestFixtureV1,
		homchain.NewA2BFullIngress6FullRingRangeCertificate(),
	)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := base.encrypt(t, [4]uint64{0xa5, 0x5a, 0xff, 0})
	base.source.Evaluator.DropLevel(ciphertext, ciphertext.Level()-6)
	input, err := circuit.BindInput(ciphertext, base.params)
	if err != nil {
		t.Fatal(err)
	}
	elements := circuit.RequiredKeyProfile().All()
	if len(elements) == 0 {
		t.Fatal("ingress6 has no runtime Galois key to tamper")
	}
	keySet := base.source.MemEvaluationKeySet
	element := elements[0]
	saved := keySet.GaloisKeys[element]
	delete(keySet.GaloisKeys, element)
	result, trace, err := evaluator.EvaluateNew(input)
	keySet.GaloisKeys[element] = saved
	if err == nil || trace.FailureStage() != homchain.A2BFullIngress6StageKeyPreflight ||
		trace.OperationCounts() != (homchain.A2BFullIngress6OperationCounts{}) || len(trace.States()) != 0 ||
		len(trace.RuntimeGaloisElements()) != 0 || trace.SerializedBytes().OnlineTotal() != 0 ||
		result.LowMSB() != nil || result.HighMSB() != nil {
		t.Fatalf("post-bind key tamper was not fail-closed: stage=%q counts=%+v states=%d runtime-keys=%v bytes=%+v err=%v",
			trace.FailureStage(), trace.OperationCounts(), len(trace.States()), trace.RuntimeGaloisElements(), trace.SerializedBytes(), err)
	}
	if _, _, err = evaluator.EvaluateNew(input); err != nil {
		t.Fatalf("restored ingress6 key graph did not recover: %v", err)
	}
}

func TestA2BFullIngress6All256MatchesIndependentOracleAndAcceptedL20(t *testing.T) {
	base := newA2BFullFixture(t)
	circuit, err := homchain.NewA2BFullIngress6Circuit(
		base.params,
		ckks.NewEncoder(base.params, a2bRefreshTestPrecision),
		ckks.NewEncoder(base.params, 256),
		homchain.A2BFullIngress6StandaloneTestFixtureV1,
		homchain.NewA2BFullIngress6FullRingRangeCertificate(),
	)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := circuit.BindEvaluator(base.source)
	if err != nil {
		t.Fatal(err)
	}
	var maxOracleError, maxDifferentialError float64
	for batch := 0; batch < 64; batch++ {
		words := [4]uint64{uint64(4 * batch), uint64(4*batch + 1), uint64(4*batch + 2), uint64(4*batch + 3)}
		arithmeticRoot := base.encrypt(t, words)
		accepted, _, err := base.evaluator.EvaluateNew(arithmeticRoot.CopyNew())
		if err != nil {
			t.Fatalf("accepted L20 batch %d words=%v: %v", batch, words, err)
		}
		ingressCiphertext := arithmeticRoot.CopyNew()
		base.source.Evaluator.DropLevel(ingressCiphertext, ingressCiphertext.Level()-6)
		input, err := circuit.BindInput(ingressCiphertext, base.params)
		if err != nil {
			t.Fatalf("bind L6 batch %d words=%v: %v", batch, words, err)
		}
		ingress, _, err := evaluator.EvaluateNew(input)
		if err != nil {
			t.Fatalf("ingress6 batch %d words=%v: %v", batch, words, err)
		}
		ingressValues := [4][]complex128{
			decodeA2BRefresh(t, base.kernelEncoder, base.decryptor, ingress.LowMSB()),
			decodeA2BRefresh(t, base.kernelEncoder, base.decryptor, ingress.HighMSB()),
			decodeA2BRefresh(t, base.refreshEncoder, base.decryptor, ingress.LowSelfRemoved()),
			decodeA2BRefresh(t, base.refreshEncoder, base.decryptor, ingress.HighSelfRemoved()),
		}
		acceptedValues := [4][]complex128{
			decodeA2BRefresh(t, base.kernelEncoder, base.decryptor, accepted.LowMSB()),
			decodeA2BRefresh(t, base.kernelEncoder, base.decryptor, accepted.HighMSB()),
			decodeA2BRefresh(t, base.refreshEncoder, base.decryptor, accepted.LowSelfRemoved()),
			decodeA2BRefresh(t, base.refreshEncoder, base.decryptor, accepted.HighSelfRemoved()),
		}
		for wordIndex, word := range words {
			bits, oracleErr := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
			if oracleErr != nil {
				t.Fatal(oracleErr)
			}
			rawLow, _ := a2bRefreshSpecialB0Block(t, base.ringZ, word)
			wantID0 := a2bRefreshLowOracleBlock(t, word)
			highResidual := a2bFullSourceScheduledHighResidualOracleBlock(t, base.ringZ, word)
			for slot := 0; slot < 4; slot++ {
				index := 4*wordIndex + slot
				wantID1 := highResidual[slot] - math.Ceil(highResidual[slot])
				if math.Abs(highResidual[slot]-math.Round(highResidual[slot])) < 1e-5 {
					wantID1 = 0
				}
				want := [4]complex128{
					complex(float64(bits.Low[slot]), 0), complex(float64(bits.High[slot]), 0),
					complex(rawLow[slot]-wantID0[slot], 0), complex(highResidual[slot]-wantID1, 0),
				}
				for output := range want {
					oracleDistance := cmplx.Abs(ingressValues[output][index] - want[output])
					differentialDistance := cmplx.Abs(ingressValues[output][index] - acceptedValues[output][index])
					maxOracleError = math.Max(maxOracleError, oracleDistance)
					maxDifferentialError = math.Max(maxDifferentialError, differentialDistance)
					if oracleDistance > 3e-3 || differentialDistance > 3e-3 {
						t.Fatalf("word=%#02x slot=%d output=%d ingress=%v accepted=%v oracle=%v distances=%.3g/%.3g",
							word, slot, output, ingressValues[output][index], acceptedValues[output][index], want[output], oracleDistance, differentialDistance)
					}
				}
			}
		}
	}
	t.Logf("ingress6 all256 final bits/residue max oracle error=%.3g, accepted-L20 differential=%.3g", maxOracleError, maxDifferentialError)
}
