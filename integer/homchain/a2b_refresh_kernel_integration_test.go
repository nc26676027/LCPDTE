package homchain_test

import (
	"math"
	"math/cmplx"
	"testing"

	"dt_go/integer/homchain"
	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestA2BRefreshOutputFeedsGaoKernelAtExactScale(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	refreshEncoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	refreshCircuit, err := homchain.NewA2BRefreshCircuit(params, refreshEncoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	bootstrapEvaluator := a2bRefreshBootstrapEvaluator(t, refreshCircuit, params, keyGenerator, secretKey)
	refreshEvaluator, err := refreshCircuit.BindEvaluator(bootstrapEvaluator)
	if err != nil {
		t.Fatal(err)
	}

	ringZ, err := z2n.NewWithPrecision(z2n.Word8, a2bRefreshTestPrecision)
	if err != nil {
		t.Fatal(err)
	}
	input := encryptA2BRefreshWords(
		t, refreshCircuit, params, ringZ, refreshEncoder, ckks.NewEncryptor(params, secretKey),
		[4]uint64{0xa5, 0x5a, 0xff, 0},
	)
	refreshResult, refreshTrace, err := refreshEvaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	refreshedLow := refreshResult.RefreshedLow()
	refreshedBefore := refreshedLow.CopyNew()

	kernelCircuit, err := homchain.NewGaoA2BKernelCircuit(params, ckks.NewEncoder(params, 256))
	if err != nil {
		t.Fatal(err)
	}
	sharedKeySet := bootstrapEvaluator.MemEvaluationKeySet
	sharedRelinearization, err := sharedKeySet.GetRelinearizationKey()
	if err != nil {
		t.Fatal(err)
	}
	sharedConjugation, err := sharedKeySet.GetGaloisKey(params.GaloisElementForComplexConjugation())
	if err != nil {
		t.Fatal(err)
	}
	kernelSource := ckks.NewEvaluator(params, sharedKeySet)
	if kernelSource.EvaluationKeySet != sharedKeySet {
		t.Fatal("kernel source did not retain the refresh MemEvaluationKeySet pointer")
	}
	kernelRelinearization, err := kernelSource.EvaluationKeySet.GetRelinearizationKey()
	if err != nil || kernelRelinearization != sharedRelinearization {
		t.Fatal("kernel source did not retain the refresh relinearization-key pointer")
	}
	kernelConjugation, err := kernelSource.EvaluationKeySet.GetGaloisKey(params.GaloisElementForComplexConjugation())
	if err != nil || kernelConjugation != sharedConjugation {
		t.Fatal("kernel source did not retain the refresh conjugation-key pointer")
	}
	kernelEvaluator, err := kernelCircuit.BindEvaluator(kernelSource)
	if err != nil {
		t.Fatal(err)
	}
	kernelResult, err := kernelEvaluator.EvaluateNew(refreshedLow)
	if err != nil {
		t.Fatalf("refresh output did not satisfy the Gao kernel exact ingress: %v", err)
	}
	if !refreshedLow.Equal(refreshedBefore) {
		t.Fatal("composed Gao kernel mutated the refresh output")
	}
	if after, getErr := sharedKeySet.GetRelinearizationKey(); getErr != nil || after != sharedRelinearization {
		t.Fatal("direct composition replaced the shared relinearization-key pointer")
	}
	if after, getErr := sharedKeySet.GetGaloisKey(params.GaloisElementForComplexConjugation()); getErr != nil || after != sharedConjugation {
		t.Fatal("direct composition replaced the shared conjugation-key pointer")
	}
	ctsState, ok := refreshTrace.State(homchain.A2BRefreshLowHalf, homchain.A2BRefreshStageCoeffsToSlots)
	if !ok {
		t.Fatal("missing refresh CTS trace")
	}
	t.Logf(
		"direct composition: refresh CTS L%d scale=%s; kernel ID/MSB L%d/L%d",
		ctsState.Level, ctsState.Scale.ValueHex(), kernelResult.IDCiphertext().Level(), kernelResult.MSBCiphertext().Level(),
	)
}

func TestA2BRefreshLowComposesThroughGaoKernelForAll256Words(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	refreshEncoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	refreshCircuit, err := homchain.NewA2BRefreshCircuit(params, refreshEncoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	bootstrapEvaluator := a2bRefreshBootstrapEvaluator(t, refreshCircuit, params, keyGenerator, secretKey)
	refreshEvaluator, err := refreshCircuit.BindEvaluator(bootstrapEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	kernelEncoder := ckks.NewEncoder(params, 256)
	kernelCircuit, err := homchain.NewGaoA2BKernelCircuit(params, kernelEncoder)
	if err != nil {
		t.Fatal(err)
	}
	kernelEvaluator, err := kernelCircuit.BindEvaluator(ckks.NewEvaluator(params, bootstrapEvaluator.MemEvaluationKeySet))
	if err != nil {
		t.Fatal(err)
	}

	ringZ, err := z2n.NewWithPrecision(z2n.Word8, a2bRefreshTestPrecision)
	if err != nil {
		t.Fatal(err)
	}
	encryptor := ckks.NewEncryptor(params, secretKey)
	decryptor := ckks.NewDecryptor(params, secretKey)
	var maxLiftDistance, maxAbsLift, maxRefreshRootError float64
	var maxKernelRootError, maxIdentityError, maxMSBError float64
	for batch := 0; batch < 64; batch++ {
		words := [4]uint64{
			uint64(4 * batch), uint64(4*batch + 1), uint64(4*batch + 2), uint64(4*batch + 3),
		}
		input := encryptA2BRefreshWords(t, refreshCircuit, params, ringZ, refreshEncoder, encryptor, words)
		refreshResult, refreshTrace, err := refreshEvaluator.EvaluateNew(input)
		if err != nil {
			t.Fatalf("refresh batch %d words=%v: %v", batch, words, err)
		}
		refreshed := refreshResult.RefreshedLow()
		if refreshed.Level() != kernelCircuit.Profile().InputLevel() ||
			!kernelCircuit.Profile().InputScale().EqualScale(refreshed.Scale) {
			t.Fatalf("batch %d refresh output is not exact kernel ingress: level=%d scale=%v", batch, refreshed.Level(), refreshed.Scale)
		}
		if state, ok := refreshTrace.State(homchain.A2BRefreshLowHalf, homchain.A2BRefreshStageCoeffsToSlots); !ok || state.Level != 17 || !state.Scale.EqualScale(params.DefaultScale()) {
			t.Fatalf("batch %d missing exact L17/S35 refresh trace: ok=%t state=%+v", batch, ok, state)
		}
		refreshedBefore := refreshed.CopyNew()
		kernelResult, err := kernelEvaluator.EvaluateNew(refreshed)
		if err != nil {
			t.Fatalf("kernel batch %d words=%v: %v", batch, words, err)
		}
		if !refreshed.Equal(refreshedBefore) {
			t.Fatalf("kernel batch %d mutated the refresh output", batch)
		}
		states := kernelResult.Provenance().States()
		if len(states) == 0 || states[0].Level != 17 || !states[0].ScaleExact ||
			!states[0].Scale.EqualScale(params.DefaultScale()) {
			t.Fatalf("kernel batch %d did not admit exact L17/S35: %+v", batch, states)
		}

		refreshValues := decodeA2BRefresh(t, refreshEncoder, decryptor, refreshed)
		rootValues := decodeA2BRefresh(t, kernelEncoder, decryptor, kernelResult.RootOfUnityCiphertext())
		identityValues := decodeA2BRefresh(t, kernelEncoder, decryptor, kernelResult.IDCiphertext())
		msbValues := decodeA2BRefresh(t, kernelEncoder, decryptor, kernelResult.MSBCiphertext())
		for wordIndex, word := range words {
			rawLow, _ := a2bRefreshSpecialB0Block(t, ringZ, word)
			wantIdentity := a2bRefreshLowOracleBlock(t, word)
			bits, oracleErr := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
			if oracleErr != nil {
				t.Fatal(oracleErr)
			}
			for slot := 0; slot < 4; slot++ {
				index := 4*wordIndex + slot
				liftDistance, absLift, refreshRootError := a2bRefreshLatticeMetrics(refreshValues[index], rawLow[slot])
				kernelRootWant := cmplx.Exp(complex(0, 2*math.Pi*rawLow[slot]))
				kernelRootError := cmplx.Abs(rootValues[index] - kernelRootWant)
				identityError := math.Abs(real(identityValues[index]) - wantIdentity[slot])
				msbError := math.Abs(real(msbValues[index]) - float64(bits.Low[slot]))
				maxLiftDistance = math.Max(maxLiftDistance, liftDistance)
				maxAbsLift = math.Max(maxAbsLift, absLift)
				maxRefreshRootError = math.Max(maxRefreshRootError, refreshRootError)
				maxKernelRootError = math.Max(maxKernelRootError, kernelRootError)
				maxIdentityError = math.Max(maxIdentityError, identityError)
				maxMSBError = math.Max(maxMSBError, msbError)
				if math.Abs(imag(refreshValues[index])) > 5e-4 || liftDistance > 3e-3 || absLift >= 16 ||
					refreshRootError > 0.02 || kernelRootError > 0.02 || identityError > 3e-3 || msbError > 3e-3 {
					t.Fatalf(
						"word %#02x slot %d: y=%v lift-distance=%.3g |I|=%.3g refresh-root=%.3g kernel-root=%.3g ID-error=%.3g MSB-error=%.3g",
						word, slot, refreshValues[index], liftDistance, absLift, refreshRootError,
						kernelRootError, identityError, msbError,
					)
				}
			}
		}
	}
	t.Logf(
		"all256 refresh->kernel maxima: lift-distance=%.12g |I|=%.0f refresh-root=%.12g kernel-root=%.12g ID=%.12g MSB=%.12g",
		maxLiftDistance, maxAbsLift, maxRefreshRootError, maxKernelRootError, maxIdentityError, maxMSBError,
	)
}
