package homchain

import (
	"math"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

func TestSignFusionAll256MatchesOracleAndGenericB2A(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := NewSignFusionCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if profile.Claim() != SignFusionDirectRankOneMSBToArithmeticOnly ||
		profile.Fidelity() != SignFusionLattigoTreeFusion || profile.Maturity() != SignFusionFunctionalNotSecure ||
		profile.WordBits() != z2n.Word8 || profile.Words() != 4 || profile.Slots() != 16 || profile.EncoderPrecision() != 256 ||
		profile.InputHalfRole() != SignFusionHighBooleanHalf || profile.InputBitOrder() != SignFusionLSBFirst ||
		profile.OutputEncoding() != SignFusionArithmeticRootSlots || profile.OutputMinimum() != 0 || profile.OutputMaximum() != 1 ||
		profile.TransformName() != signFusionTransformName || profile.SourceBasis() != U0FusedTInv ||
		profile.SourceColumn() != 0 || profile.InputColumn() != 3 {
		t.Fatalf("unexpected direct sign-fusion contract: %+v", profile)
	}
	if profile.InputLevel() != 5 || profile.OutputLevel() != 4 ||
		!profile.InputScale().EqualScale(params.DefaultScale()) ||
		!profile.OutputScale().EqualScale(params.DefaultScale()) {
		t.Fatalf("unexpected direct sign-fusion state contract: input=L%d/%s output=L%d/%s",
			profile.InputLevel(), profile.InputScale().ValueHex(), profile.OutputLevel(), profile.OutputScale().ValueHex())
	}
	for label, pair := range map[string][2]string{
		"parameter": {profile.ParameterDigest(), "085e0a9b826d469ac5514d3db988672f41ab0a4f1bb2fe82705842226a8eacc2"},
		"source":    {profile.SourceDigest(), "c5bda437c079d1b60671cf2909460a3f2a0f29d0bef81bacb4fa8d2dd147849f"},
		"compiled":  {profile.CompiledDigest(), "da9827044a8ee1f07769b47fff01213e23f6ea5e7d644f6dd03fd133d8031b0b"},
		"profile":   {profile.Digest(), "68b3bcc5edd24e7e2aeefbf184534b750a3d94506cbf10afb1839ebed474a4ae"},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("frozen sign-fusion %s digest: got %s, want %s", label, pair[0], pair[1])
		}
	}
	t.Logf("sign-fusion digests: params=%s source=%s compiled=%s profile=%s ops=%+v",
		profile.ParameterDigest(), profile.SourceDigest(), profile.CompiledDigest(), profile.Digest(), profile.OperationCounts())

	b2a, err := NewB2AFullAtLevelCircuit(params, encoder, 5)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	keyElements := signFusionUniqueElements(append(profile.RequiredGaloisElements(), b2a.Profile().RequiredGaloisElements()...))
	galoisKeys := keyGenerator.GenGaloisKeysNew(keyElements, secretKey)
	keySet := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	sourceEvaluator := ckks.NewEvaluator(params, keySet)
	bound, err := circuit.BindEvaluator(sourceEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	boundB2A, err := b2a.BindEvaluator(sourceEvaluator)
	if err != nil {
		t.Fatal(err)
	}

	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	encryptor := ckks.NewEncryptor(params, secretKey)
	decryptor := ckks.NewDecryptor(params, secretKey)
	maxOracleError, maxControlError := 0.0, 0.0
	for batch := 0; batch < 64; batch++ {
		words := [4]uint64{uint64(4 * batch), uint64(4*batch + 1), uint64(4*batch + 2), uint64(4*batch + 3)}
		highValues := make([]complex128, params.MaxSlots())
		controlLowValues := make([]complex128, params.MaxSlots())
		for wordIndex, word := range words {
			halves, oracleErr := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
			if oracleErr != nil {
				t.Fatal(oracleErr)
			}
			for bit := 0; bit < 4; bit++ {
				highValues[4*wordIndex+bit] = complex(float64(halves.High[bit]), 0)
			}
			controlLowValues[4*wordIndex] = complex(float64((word>>7)&1), 0)
		}
		highCiphertext := signFusionEncryptAtLevel(t, params, encoder, encryptor, 5, highValues)
		highBefore := highCiphertext.CopyNew()
		input, bindErr := circuit.BindBooleanHalf(highCiphertext, SignFusionHighBooleanHalf, SignFusionLSBFirst)
		if bindErr != nil {
			t.Fatalf("batch %d bind high half: %v", batch, bindErr)
		}
		result, evaluationErr := bound.EvaluateNew(input)
		if evaluationErr != nil {
			t.Fatalf("batch %d evaluate fusion: %v", batch, evaluationErr)
		}
		if !highCiphertext.Equal(highBefore) {
			t.Fatalf("batch %d fusion mutated the high Boolean half", batch)
		}
		output := result.Ciphertext()
		if output.Level() != 4 || output.Degree() != 1 || output.LogDimensions != params.LogMaxDimensions() ||
			!output.IsBatched || !output.IsNTT || output.Slots() != params.MaxSlots() ||
			!profile.OutputScale().EqualScale(output.Scale) {
			t.Fatalf("batch %d output state: level=%d degree=%d dimensions=%+v scale=%v",
				batch, output.Level(), output.Degree(), output.LogDimensions, output.Scale)
		}

		controlLow := signFusionEncryptAtLevel(t, params, encoder, encryptor, 5, controlLowValues)
		controlHigh := signFusionEncryptAtLevel(t, params, encoder, encryptor, 5, make([]complex128, params.MaxSlots()))
		controlLowHandle, bindErr := b2a.BindLow(controlLow)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		controlHighHandle, bindErr := b2a.BindHigh(controlHigh)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		controlInput, bindErr := b2a.BindInput(controlLowHandle, controlHighHandle)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		controlResult, controlErr := boundB2A.EvaluateNew(controlInput)
		if controlErr != nil {
			t.Fatal(controlErr)
		}

		decoded := signFusionDecrypt(t, params, encoder, decryptor, output)
		controlDecoded := signFusionDecrypt(t, params, encoder, decryptor, controlResult.Ciphertext())
		for wordIndex, word := range words {
			sign := (word >> 7) & 1
			wantSlots := ringZ.ArithmeticRootSlots(sign)
			for slot := 0; slot < 4; slot++ {
				index := 4*wordIndex + slot
				oracleDistance := signFusionComplexDistance(decoded[index], wantSlots[slot].Complex128())
				controlDistance := signFusionComplexDistance(decoded[index], controlDecoded[index])
				maxOracleError = math.Max(maxOracleError, oracleDistance)
				maxControlError = math.Max(maxControlError, controlDistance)
				if oracleDistance > 5e-4 || controlDistance > 5e-4 {
					t.Fatalf("word %#02x slot %d: fused=%v oracle=%v control=%v errors=(%.3g,%.3g)",
						word, slot, decoded[index], wantSlots[slot].Complex128(), controlDecoded[index], oracleDistance, controlDistance)
				}
			}
			if got := signFusionRecoverWord(t, ringZ, decoded[4*wordIndex:4*(wordIndex+1)]); got != sign {
				t.Fatalf("word %#02x fused sign residue=%d, want %d", word, got, sign)
			}
		}
	}
	t.Logf("direct rank-one sign fusion all256: max-oracle-error=%.12g max-generic-B2A-error=%.12g", maxOracleError, maxControlError)
}

func TestSignFusionSealedMatrixTraceAndRealKernelHighComposition(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := NewSignFusionCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if profile.DigestSchema() != signFusionProfileDigestSchema || profile.ParameterDigest() == "" ||
		profile.SourceDigest() == "" || profile.CompiledDigest() == "" || profile.Digest() == "" {
		t.Fatalf("incomplete sealed sign-fusion profile: %+v", profile)
	}
	if got, want := profile.RequiredRotationIndexes(), []int{1, 2}; !slices.Equal(got, want) {
		t.Fatalf("rank-one rotation schedule: got %v, want %v", got, want)
	}
	if got, want := profile.RequiredGaloisElements(), []uint64{5, 25}; !slices.Equal(got, want) {
		t.Fatalf("rank-one Galois schedule: got %v, want %v", got, want)
	}
	if profile.RequiresRelinearization() || profile.RequiresConjugation() ||
		!profile.MatrixScale().EqualScale(rlwe.NewScale(params.Q()[5])) ||
		profile.LogBabyStepGiantStepRatio() != 0 || profile.BabyStepSize() != 2 {
		t.Fatalf("unexpected sign-fusion key/scale contract: relin=%t conjugation=%t matrix=%s",
			profile.RequiresRelinearization(), profile.RequiresConjugation(), profile.MatrixScale().ValueHex())
	}
	wantCounts := SignFusionOperationCounts{
		LinearTransformations: 1, Rotations: 2, CiphertextPlaintextMultiplications: 4,
		Additions: 3, Rescales: 1, KeySwitches: 2, LogicalPeakLiveCiphertexts: 2,
	}
	if got := profile.OperationCounts(); got != wantCounts {
		t.Fatalf("rank-one operation counts: got %+v, want %+v", got, wantCounts)
	}

	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specifications, err := NewSpecificationsFromRing(ringZ, signFusionWords)
	if err != nil {
		t.Fatal(err)
	}
	wantBasis := specifications.UFusedTInvPair().Low.Matrix()
	gotMatrix := circuit.source.Matrix()
	if len(gotMatrix) != 4 {
		t.Fatalf("M_sign rows=%d, want 4", len(gotMatrix))
	}
	for row := 0; row < 4; row++ {
		if len(gotMatrix[row]) != 4 {
			t.Fatalf("M_sign row %d columns=%d, want 4", row, len(gotMatrix[row]))
		}
		for column := 0; column < 4; column++ {
			if column == signFusionInputColumn {
				if !signFusionBigComplexEqual(gotMatrix[row][column], wantBasis[row][signFusionSourceColumn]) {
					t.Fatalf("M_sign[%d,%d] is not U0_tInv[%d,0]", row, column, row)
				}
			} else if !isZero(gotMatrix[row][column]) {
				t.Fatalf("M_sign[%d,%d] is nonzero outside rank-one input column", row, column)
			}
		}
	}
	if circuit.source.precision != z2n.DefaultPrecision || circuit.transform.N1 != 2 ||
		circuit.transform.LevelQ != signFusionInputLevel || circuit.transform.LevelP != params.MaxLevelP() ||
		len(circuit.transform.Vec) != 4 {
		t.Fatalf("unexpected compiled rank-one payload: precision=%d N1=%d Q=%d P=%d diagonals=%d",
			circuit.source.precision, circuit.transform.N1, circuit.transform.LevelQ, circuit.transform.LevelP, len(circuit.transform.Vec))
	}

	rotationCopy := profile.RequiredRotationIndexes()
	galoisCopy := profile.RequiredGaloisElements()
	rotationCopy[0], galoisCopy[0] = 99, 99
	if !slices.Equal(circuit.Profile().RequiredRotationIndexes(), []int{1, 2}) ||
		!slices.Equal(circuit.Profile().RequiredGaloisElements(), []uint64{5, 25}) {
		t.Fatal("sign-fusion profile key accessors alias private storage")
	}

	kernel, err := NewGaoA2BKernelCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	relinearizationKey := keyGenerator.GenRelinearizationKeyNew(secretKey)
	keyElements := signFusionUniqueElements(append(profile.RequiredGaloisElements(), kernel.Profile().KeyProfile().ConjugationGaloisElement()))
	galoisKeys := keyGenerator.GenGaloisKeysNew(keyElements, secretKey)
	keySet := rlwe.NewMemEvaluationKeySet(relinearizationKey, galoisKeys...)
	sourceEvaluator := ckks.NewEvaluator(params, keySet)
	boundKernel, err := kernel.BindEvaluator(sourceEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	boundFusion, err := circuit.BindEvaluator(sourceEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	if boundFusion.keySet != keySet || boundFusion.ckks != sourceEvaluator {
		t.Fatal("sign-fusion evaluator did not retain the admitted evaluator/key-set identities")
	}
	for _, element := range profile.RequiredGaloisElements() {
		key, keyErr := keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil || boundFusion.galoisKeys[element] != key {
			t.Fatalf("sign-fusion did not retain Galois key %d pointer", element)
		}
	}
	blockDecryptor := ckks.NewDecryptor(params, secretKey)
	for activeBlock := 0; activeBlock < signFusionWords; activeBlock++ {
		values := make([]complex128, params.MaxSlots())
		values[4*activeBlock+signFusionInputColumn] = 1
		ciphertext := signFusionEncryptAtLevel(t, params, encoder, ckks.NewEncryptor(params, secretKey), signFusionInputLevel, values)
		handle, bindErr := circuit.BindBooleanHalf(ciphertext, SignFusionHighBooleanHalf, SignFusionLSBFirst)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		isolated, evaluationErr := boundFusion.EvaluateNew(handle)
		if evaluationErr != nil {
			t.Fatal(evaluationErr)
		}
		decoded := signFusionDecrypt(t, params, encoder, blockDecryptor, isolated.Ciphertext())
		for block := 0; block < signFusionWords; block++ {
			wantSign := uint64(0)
			if block == activeBlock {
				wantSign = 1
			}
			want := ringZ.ArithmeticRootSlots(wantSign)
			for slot := 0; slot < 4; slot++ {
				if distance := signFusionComplexDistance(decoded[4*block+slot], want[slot].Complex128()); distance > 5e-4 {
					t.Fatalf("active block %d leaked into block %d slot %d: error %.3g", activeBlock, block, slot, distance)
				}
			}
		}
	}

	words := [4]uint64{0x00, 0x7f, 0x80, 0xa5}
	kernelInput := signFusionEncryptKernelHighCodes(t, params, encoder, secretKey, words)
	kernelInputBefore := kernelInput.CopyNew()
	kernelResult, err := boundKernel.EvaluateNew(kernelInput)
	if err != nil {
		t.Fatal(err)
	}
	if !kernelInput.Equal(kernelInputBefore) {
		t.Fatal("real Gao kernel mutated its normalized high-half input")
	}
	high := kernelResult.MSBCiphertext()
	if high.Level() != profile.InputLevel() || !profile.InputScale().EqualScale(high.Scale) {
		t.Fatalf("real kernel high output is not exact sign-fusion ingress: L%d/%v", high.Level(), high.Scale)
	}
	highBefore := high.CopyNew()
	handle, err := circuit.BindBooleanHalf(high, SignFusionHighBooleanHalf, SignFusionLSBFirst)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	result, err := boundFusion.EvaluateNew(handle)
	wall := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if !high.Equal(highBefore) {
		t.Fatal("sign fusion mutated the real kernel high output")
	}

	provenance := result.Provenance()
	if provenance.ProfileDigest() != profile.Digest() || provenance.SourceDigest() != profile.SourceDigest() ||
		provenance.CompiledDigest() != profile.CompiledDigest() || provenance.OperationCounts() != wantCounts {
		t.Fatalf("sign-fusion provenance drifted: %+v", provenance)
	}
	states := provenance.States()
	wantStages := []SignFusionStage{SignFusionStageHighBooleanInput, SignFusionStageRankOneLinear, SignFusionStageArithmeticSign}
	wantLevels := []int{5, 5, 4}
	if len(states) != len(wantStages) {
		t.Fatalf("sign-fusion states=%d, want %d", len(states), len(wantStages))
	}
	inputScale, err := profile.InputScale().Scale()
	if err != nil {
		t.Fatal(err)
	}
	matrixScale, err := profile.MatrixScale().Scale()
	if err != nil {
		t.Fatal(err)
	}
	wantLinearScale, err := NewExactScaleSnapshot(inputScale.Mul(matrixScale))
	if err != nil {
		t.Fatal(err)
	}
	for index := range states {
		if states[index].Stage != wantStages[index] || states[index].Level != wantLevels[index] ||
			states[index].Degree != 1 || states[index].LogDimensions != params.LogMaxDimensions() {
			t.Fatalf("sign-fusion state %d: %+v", index, states[index])
		}
	}
	if !states[0].Scale.Equal(profile.InputScale()) || !states[1].Scale.Equal(wantLinearScale) ||
		!states[2].Scale.Equal(profile.OutputScale()) {
		t.Fatalf("sign-fusion exact scale trace: input=%s LT=%s output=%s want=%s/%s/%s",
			states[0].Scale.ValueHex(), states[1].Scale.ValueHex(), states[2].Scale.ValueHex(),
			profile.InputScale().ValueHex(), wantLinearScale.ValueHex(), profile.OutputScale().ValueHex())
	}
	if got, want := []string{states[0].Scale.ValueHex(), states[1].Scale.ValueHex(), states[2].Scale.ValueHex()},
		[]string{"0x1p+35", "0x1.fffffe904p+69", "0x1p+35"}; !slices.Equal(got, want) {
		t.Fatalf("frozen exact-scale trace: got %v, want %v", got, want)
	}
	states[0].Level = -1
	if provenance.States()[0].Level != 5 {
		t.Fatal("sign-fusion provenance state accessor aliases private storage")
	}

	output := result.Ciphertext()
	output.Scale = rlwe.NewScale(3)
	if !profile.OutputScale().EqualScale(result.Ciphertext().Scale) {
		t.Fatal("sign-fusion output accessor aliases private ciphertext metadata")
	}
	decoded := signFusionDecrypt(t, params, encoder, ckks.NewDecryptor(params, secretKey), result.Ciphertext())
	maxError := 0.0
	for wordIndex, word := range words {
		sign := (word >> 7) & 1
		want := ringZ.ArithmeticRootSlots(sign)
		for slot := 0; slot < 4; slot++ {
			errorValue := signFusionComplexDistance(decoded[4*wordIndex+slot], want[slot].Complex128())
			maxError = math.Max(maxError, errorValue)
			if errorValue > 5e-4 {
				t.Fatalf("real kernel->fusion word %#02x slot %d error %.3g", word, slot, errorValue)
			}
		}
		if got := signFusionRecoverWord(t, ringZ, decoded[4*wordIndex:4*(wordIndex+1)]); got != sign {
			t.Fatalf("real kernel->fusion word %#02x residue=%d, want sign=%d", word, got, sign)
		}
	}
	keyBytes := signFusionSerializedGaloisKeyBytes(t, keySet, profile.RequiredGaloisElements())
	t.Logf("real Gao-high -> rank-one fusion: L5/%s -> LT L5/%s -> L4/%s, max-error=%.12g, Galois-bytes=%d, wall=%s",
		states[0].Scale.ValueHex(), states[1].Scale.ValueHex(), states[2].Scale.ValueHex(), maxError, keyBytes, wall)
}

func TestSignFusionRejectsInvalidConstructionIngressKeysGraphAndAlternatives(t *testing.T) {
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	if _, err = NewSignFusionCircuit(params, nil); err == nil {
		t.Fatal("sign-fusion constructor accepted a nil encoder")
	}
	if _, err = NewSignFusionCircuit(params, ckks.NewEncoder(params)); err == nil {
		t.Fatal("sign-fusion constructor accepted a default <=53-bit encoder")
	}

	reorderedQ := append([]uint64(nil), params.Q()...)
	reorderedQ[1], reorderedQ[2] = reorderedQ[2], reorderedQ[1]
	reorderedParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, Q: reorderedQ, P: append([]uint64(nil), params.P()...), LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	if params.Equal(&reorderedParams) {
		t.Fatal("same-bit reordered-Q negative unexpectedly equals canonical Gao parameters")
	}
	if _, err = NewSignFusionCircuit(reorderedParams, ckks.NewEncoder(reorderedParams, z2n.DefaultPrecision)); err == nil {
		t.Fatal("sign fusion accepted a same-bit reordered Q chain")
	}

	canonicalModuli := make(map[uint64]bool, len(params.Q())+len(params.P()))
	for _, modulus := range append(append([]uint64(nil), params.Q()...), params.P()...) {
		canonicalModuli[modulus] = true
	}
	primeGenerator := ring.NewNTTFriendlyPrimesGenerator(35, uint64(params.NthRoot()))
	var alternatePrime uint64
	for alternatePrime == 0 {
		candidate, generationErr := primeGenerator.NextAlternatingPrime()
		if generationErr != nil {
			t.Fatal(generationErr)
		}
		if !canonicalModuli[candidate] && int(math.Round(math.Log2(float64(candidate)))) == 35 {
			alternatePrime = candidate
		}
	}
	alternateQ := append([]uint64(nil), params.Q()...)
	alternateQ[1] = alternatePrime
	alternateParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, Q: alternateQ, P: append([]uint64(nil), params.P()...), LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	if params.Equal(&alternateParams) {
		t.Fatal("same-bit alternate-Q negative unexpectedly equals canonical Gao parameters")
	}
	if _, err = NewSignFusionCircuit(alternateParams, ckks.NewEncoder(alternateParams, z2n.DefaultPrecision)); err == nil {
		t.Fatal("sign fusion accepted a same-bit alternate Q prime")
	}
	if _, err = NewSignFusionCircuit(params, ckks.NewEncoder(reorderedParams, z2n.DefaultPrecision)); err == nil {
		t.Fatal("sign fusion accepted an encoder from a different modulus chain")
	}

	circuit, err := NewSignFusionCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	validCiphertext := signFusionEncryptAtLevel(t, params, encoder, ckks.NewEncryptor(params, secretKey), profile.InputLevel(), make([]complex128, params.MaxSlots()))
	if _, err = circuit.BindBooleanHalf(nil, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted a nil Boolean half")
	}
	if _, err = circuit.BindBooleanHalf(validCiphertext, SignFusionLowBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted the low Boolean half role")
	}
	if _, err = circuit.BindBooleanHalf(validCiphertext, SignFusionHighBooleanHalf, SignFusionMSBFirst); err == nil {
		t.Fatal("sign fusion accepted MSB-first Boolean layout")
	}
	wrongLevel := signFusionEncryptAtLevel(t, params, encoder, ckks.NewEncryptor(params, secretKey), profile.InputLevel()+1, make([]complex128, params.MaxSlots()))
	if _, err = circuit.BindBooleanHalf(wrongLevel, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted the wrong physical ingress level")
	}
	badScale := validCiphertext.CopyNew()
	badScale.Scale = badScale.Scale.Mul(rlwe.NewScale(2))
	if _, err = circuit.BindBooleanHalf(badScale, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted a non-profile exact scale")
	}
	modularScale := validCiphertext.CopyNew()
	modularScale.Scale.Mod = big.NewInt(257)
	if _, err = circuit.BindBooleanHalf(modularScale, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted modular scale metadata")
	}
	precisionMismatch := validCiphertext.CopyNew()
	precisionMismatch.Scale.Value = *new(big.Float).
		SetPrec(precisionMismatch.Scale.Value.Prec() + 1).
		Set(&precisionMismatch.Scale.Value)
	if _, err = circuit.BindBooleanHalf(precisionMismatch, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted same-value scale with different precision metadata")
	}
	roundingMismatch := validCiphertext.CopyNew()
	roundingMismatch.Scale.Value.SetMode(big.ToZero)
	if _, err = circuit.BindBooleanHalf(roundingMismatch, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted same-value scale with different rounding metadata")
	}
	badDimensions := validCiphertext.CopyNew()
	badDimensions.LogDimensions.Cols--
	if _, err = circuit.BindBooleanHalf(badDimensions, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted partial slot dimensions")
	}
	badDegree := validCiphertext.CopyNew()
	badDegree.Resize(2, badDegree.Level())
	if _, err = circuit.BindBooleanHalf(badDegree, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted a degree-two Boolean half")
	}
	badBatching := validCiphertext.CopyNew()
	badBatching.IsBatched = false
	if _, err = circuit.BindBooleanHalf(badBatching, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted a non-batched Boolean half")
	}
	badNTT := validCiphertext.CopyNew()
	badNTT.IsNTT = false
	if _, err = circuit.BindBooleanHalf(badNTT, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted a non-NTT Boolean half")
	}
	badMetadata := validCiphertext.CopyNew()
	badMetadata.MetaData = nil
	if _, err = circuit.BindBooleanHalf(badMetadata, SignFusionHighBooleanHalf, SignFusionLSBFirst); err == nil {
		t.Fatal("sign fusion accepted nil ciphertext metadata")
	}

	if _, err = circuit.BindEvaluator(nil); err == nil {
		t.Fatal("sign fusion accepted a nil evaluator")
	}
	if _, err = circuit.BindEvaluator(ckks.NewEvaluator(params, nil)); err == nil {
		t.Fatal("sign fusion accepted a nil evaluation-key set")
	}
	required := profile.RequiredGaloisElements()
	for missingIndex, missing := range required {
		present := append([]uint64(nil), required[:missingIndex]...)
		present = append(present, required[missingIndex+1:]...)
		presentKeys := keyGenerator.GenGaloisKeysNew(present, secretKey)
		if _, err = circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, presentKeys...))); err == nil {
			t.Fatalf("sign fusion accepted a set missing Galois key %d", missing)
		}
	}
	wrongEvaluatorKeys := keyGenerator.GenGaloisKeysNew(required, secretKey)
	if _, err = circuit.BindEvaluator(ckks.NewEvaluator(reorderedParams, rlwe.NewMemEvaluationKeySet(nil, wrongEvaluatorKeys...))); err == nil {
		t.Fatal("sign fusion accepted an evaluator from a different modulus chain")
	}

	galoisKeys := keyGenerator.GenGaloisKeysNew(required, secretKey)
	keySet := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	keySet.GaloisKeys[required[0]], keySet.GaloisKeys[required[1]] = keySet.GaloisKeys[required[1]], keySet.GaloisKeys[required[0]]
	if _, err = circuit.BindEvaluator(ckks.NewEvaluator(params, keySet)); err == nil {
		t.Fatal("sign fusion accepted swapped Galois-element payloads")
	}
	keySet.GaloisKeys[required[0]], keySet.GaloisKeys[required[1]] = keySet.GaloisKeys[required[1]], keySet.GaloisKeys[required[0]]
	sourceEvaluator := ckks.NewEvaluator(params, keySet)
	bound, err := circuit.BindEvaluator(sourceEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := circuit.BindBooleanHalf(validCiphertext, SignFusionHighBooleanHalf, SignFusionLSBFirst)
	if err != nil {
		t.Fatal(err)
	}
	assertRejectedBeforeInputMutation := func(name string) {
		t.Helper()
		before := validCiphertext.CopyNew()
		if _, evaluationErr := bound.EvaluateNew(handle); evaluationErr == nil {
			t.Fatalf("%s was accepted after binding", name)
		}
		if !validCiphertext.Equal(before) {
			t.Fatalf("%s failure mutated the Boolean input", name)
		}
	}

	for _, element := range required {
		original := keySet.GaloisKeys[element]
		keySet.GaloisKeys[element] = nil
		assertRejectedBeforeInputMutation("deleted Galois key")
		keySet.GaloisKeys[element] = original
	}
	for _, element := range required {
		original := keySet.GaloisKeys[element]
		keySet.GaloisKeys[element] = keyGenerator.GenGaloisKeyNew(element, secretKey)
		assertRejectedBeforeInputMutation("same-secret Galois-key pointer swap")
		keySet.GaloisKeys[element] = original
	}
	originalKeySet := sourceEvaluator.EvaluationKeySet
	sourceEvaluator.EvaluationKeySet = rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	assertRejectedBeforeInputMutation("source evaluator key-set replacement")
	sourceEvaluator.EvaluationKeySet = originalKeySet
	originalBoundKeySet := bound.keySet
	bound.keySet = rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	assertRejectedBeforeInputMutation("bound key-set identity replacement")
	bound.keySet = originalBoundKeySet
	originalExpectedKey := bound.galoisKeys[required[0]]
	bound.galoisKeys[required[0]] = keyGenerator.GenGaloisKeyNew(required[0], secretKey)
	assertRejectedBeforeInputMutation("captured Galois-key identity replacement")
	bound.galoisKeys[required[0]] = originalExpectedKey
	originalLinear := bound.linear
	bound.linear = ckkslintrans.NewEvaluator(ckks.NewEvaluator(params, keySet))
	assertRejectedBeforeInputMutation("linear evaluator graph replacement")
	bound.linear = originalLinear
	originalCKKS := bound.ckks
	bound.ckks = ckks.NewEvaluator(params, keySet)
	assertRejectedBeforeInputMutation("bound CKKS evaluator replacement")
	bound.ckks = originalCKKS
	originalProfileDigest := circuit.profile.digest
	circuit.profile.digest = signFusionDigestText("tampered-sign-fusion-profile")
	assertRejectedBeforeInputMutation("profile digest mutation")
	circuit.profile.digest = originalProfileDigest
	originalHandleDigest := handle.digest
	handle.digest = signFusionDigestText("foreign-sign-fusion-handle")
	assertRejectedBeforeInputMutation("foreign profile input handle")
	handle.digest = originalHandleDigest

	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	specifications, err := NewSpecificationsFromRing(ringZ, signFusionWords)
	if err != nil {
		t.Fatal(err)
	}
	maskMatrix := makeMatrix(4, 4, z2n.DefaultPrecision)
	maskMatrix[3][3] = realComplex(1, z2n.DefaultPrecision)
	naiveMask, err := newTransformSpec(TransformName("naive-global-slot3-mask-without-block-broadcast"), maskMatrix, signFusionWords)
	if err != nil {
		t.Fatal(err)
	}
	alternatives := []struct {
		name   string
		source TransformSpec
	}{
		{name: "normal U1", source: specifications.UPair().High},
		{name: "full fused U1", source: specifications.UFusedTInvPair().High},
		{name: "slot3 mask without block correction", source: naiveMask},
	}
	originalSource := circuit.source
	originalTransform := circuit.transform
	for _, alternative := range alternatives {
		alternativeTransform := signFusionCompileAlternative(t, params, encoder, alternative.source)
		circuit.source, circuit.transform = alternative.source, alternativeTransform
		assertRejectedBeforeInputMutation(alternative.name + " source/compiled replacement")
		circuit.source, circuit.transform = originalSource, alternativeTransform
		assertRejectedBeforeInputMutation(alternative.name + " compiled numeric payload replacement")
		circuit.source, circuit.transform = originalSource, originalTransform
	}

	signFusionAssertMislabelledLayoutDiffers(t, circuit, bound, params, encoder, secretKey, ringZ, "low/high swap", func(word uint64, slot int) uint64 {
		return word >> uint(slot) & 1
	})
	signFusionAssertMislabelledLayoutDiffers(t, circuit, bound, params, encoder, secretKey, ringZ, "MSB-first high half", func(word uint64, slot int) uint64 {
		return word >> uint(7-slot) & 1
	})

	if _, err = bound.EvaluateNew(handle); err != nil {
		t.Fatalf("restored sign-fusion graph did not recover: %v", err)
	}
}

func signFusionEncryptAtLevel(t *testing.T, params ckks.Parameters, encoder *ckks.Encoder, encryptor *rlwe.Encryptor, level int, values []complex128) *rlwe.Ciphertext {
	t.Helper()
	plaintext := ckks.NewPlaintext(params, level)
	plaintext.LogDimensions = params.LogMaxDimensions()
	plaintext.Scale = params.DefaultScale()
	if err := encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func signFusionEncryptKernelHighCodes(
	t *testing.T,
	params ckks.Parameters,
	encoder *ckks.Encoder,
	secretKey *rlwe.SecretKey,
	words [4]uint64,
) *rlwe.Ciphertext {
	t.Helper()
	values := make([]complex128, params.MaxSlots())
	for wordIndex, word := range words {
		for slot := 0; slot < 4; slot++ {
			var prefix uint64
			for term := 0; term <= slot; term++ {
				bit := word >> uint(4+slot-term) & 1
				prefix += bit << uint(3-term)
			}
			code := (16 - prefix) & 15
			values[4*wordIndex+slot] = complex(float64(code)/256, 0)
		}
	}
	return signFusionEncryptAtLevel(t, params, encoder, ckks.NewEncryptor(params, secretKey), 17, values)
}

func signFusionSerializedGaloisKeyBytes(t *testing.T, keySet *rlwe.MemEvaluationKeySet, elements []uint64) int {
	t.Helper()
	total := 0
	for _, element := range elements {
		key, err := keySet.GetGaloisKey(element)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := key.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		total += len(payload)
	}
	return total
}

func signFusionBigComplexEqual(left, right *bignum.Complex) bool {
	return left != nil && right != nil && left.Real() != nil && left.Imag() != nil &&
		right.Real() != nil && right.Imag() != nil &&
		left.Real().Cmp(right.Real()) == 0 && left.Imag().Cmp(right.Imag()) == 0 &&
		left.Prec() == right.Prec()
}

func signFusionCompileAlternative(t *testing.T, params ckks.Parameters, encoder *ckks.Encoder, source TransformSpec) ckkslintrans.LinearTransformation {
	t.Helper()
	transformation, err := Compile(params, encoder, source, CompileOptions{
		LevelQ: signFusionInputLevel, LevelP: params.MaxLevelP(),
		Scale: rlwe.NewScale(params.Q()[signFusionInputLevel]), LogBabyStepGiantStepRatio: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return transformation
}

func signFusionAssertMislabelledLayoutDiffers(
	t *testing.T,
	circuit *SignFusionCircuit,
	bound *SignFusionEvaluator,
	params ckks.Parameters,
	encoder *ckks.Encoder,
	secretKey *rlwe.SecretKey,
	ringZ *z2n.Ring,
	name string,
	bitAtSlot func(word uint64, slot int) uint64,
) {
	t.Helper()
	words := [4]uint64{0x08, 0x10, 0x80, 0xa5}
	values := make([]complex128, params.MaxSlots())
	for wordIndex, word := range words {
		for slot := 0; slot < 4; slot++ {
			values[4*wordIndex+slot] = complex(float64(bitAtSlot(word, slot)), 0)
		}
	}
	ciphertext := signFusionEncryptAtLevel(t, params, encoder, ckks.NewEncryptor(params, secretKey), signFusionInputLevel, values)
	before := ciphertext.CopyNew()
	// This deliberately lies to the typed admission seam. Encrypted payloads
	// carry no self-authenticating half-role/order tag, so the numerical
	// sentinel must remain distinguishable from the admitted layout.
	handle, err := circuit.BindBooleanHalf(ciphertext, SignFusionHighBooleanHalf, SignFusionLSBFirst)
	if err != nil {
		t.Fatal(err)
	}
	result, err := bound.EvaluateNew(handle)
	if err != nil {
		t.Fatal(err)
	}
	if !ciphertext.Equal(before) {
		t.Fatalf("%s sentinel mutated its input", name)
	}
	decoded := signFusionDecrypt(t, params, encoder, ckks.NewDecryptor(params, secretKey), result.Ciphertext())
	maxOracleDifference := 0.0
	for wordIndex, word := range words {
		want := ringZ.ArithmeticRootSlots((word >> 7) & 1)
		for slot := 0; slot < 4; slot++ {
			maxOracleDifference = math.Max(maxOracleDifference,
				signFusionComplexDistance(decoded[4*wordIndex+slot], want[slot].Complex128()))
		}
	}
	if maxOracleDifference < 0.1 {
		t.Fatalf("%s was not numerically distinguished from high/LSB-first sign semantics: max difference %.3g", name, maxOracleDifference)
	}
}

func signFusionDecrypt(t *testing.T, params ckks.Parameters, encoder *ckks.Encoder, decryptor *rlwe.Decryptor, ciphertext *rlwe.Ciphertext) []complex128 {
	t.Helper()
	values := make([]complex128, ciphertext.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), values); err != nil {
		t.Fatal(err)
	}
	return values
}

func signFusionRecoverWord(t *testing.T, ringZ *z2n.Ring, slots []complex128) uint64 {
	t.Helper()
	highPrecision := make([]*bignum.Complex, len(slots))
	for index, value := range slots {
		highPrecision[index] = bignum.ToComplex(value, z2n.DefaultPrecision)
	}
	word, err := ringZ.RecoverWord(highPrecision)
	if err != nil {
		t.Fatal(err)
	}
	return word
}

func signFusionComplexDistance(left, right complex128) float64 {
	return math.Abs(real(left-right)) + math.Abs(imag(left-right))
}

func signFusionUniqueElements(elements []uint64) []uint64 {
	seen := make(map[uint64]bool, len(elements))
	result := make([]uint64, 0, len(elements))
	for _, element := range elements {
		if !seen[element] {
			seen[element] = true
			result = append(result, element)
		}
	}
	return result
}
