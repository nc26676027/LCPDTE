package homchain_test

import (
	"math"
	"slices"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestB2AFullAtLevelConnectsToTheA2BParameterChain(t *testing.T) {
	params := b2aChainFunctionalParameters(t)
	canonical, err := homchain.GaoA2BKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	if !params.Equal(&canonical) {
		t.Fatal("B2A test fixture drifted from GaoA2BKernelFunctionalParameters")
	}
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	const inputLevel = 5
	circuit, err := homchain.NewB2AFullAtLevelCircuit(params, encoder, inputLevel)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if got, want := profile.DigestSchema(), "b2a-full-chain-v1"; got != want {
		t.Fatalf("digest schema: got %q, want %q", got, want)
	}
	if got, want := profile.TransformSourceDigest(), "6f812fdda4a80cc7f55fec7fcc76b7db4d17f04ec211e7f44e55a399cf6b6d99"; got != want {
		t.Errorf("transform-source digest: got %s, want %s", got, want)
	}
	if got, want := profile.CompiledPlanDigest(), "1bcf11a721a23b91752bd88b017da88fff233d77b7476fc1c2f7b5754a129227"; got != want {
		t.Errorf("compiled-plan digest: got %s, want %s", got, want)
	}
	if got, want := profile.Digest(), "01d138a6d34431b8d88c4826c0afa9e1445e55b9f4152b61fdd55e3c168588a3"; got != want {
		t.Errorf("profile digest: got %s, want %s", got, want)
	}
	if got, want := profile.RequiredRotationIndexes(), []int{1, 2, 12, 14}; !slices.Equal(got, want) {
		t.Fatalf("rotation indexes: got %v, want %v", got, want)
	}
	if got, want := profile.RequiredGaloisElements(), []uint64{5, 17, 25, 41}; !slices.Equal(got, want) {
		t.Fatalf("Galois elements: got %v, want %v", got, want)
	}
	if got, want := profile.WordBits(), z2n.Word8; got != want {
		t.Fatalf("word bits: got %d, want %d", got, want)
	}
	if got, want := profile.Words(), 4; got != want {
		t.Fatalf("words: got %d, want %d", got, want)
	}
	if got, want := profile.Slots(), 16; got != want {
		t.Fatalf("slots: got %d, want %d", got, want)
	}
	if got, want := profile.LevelQ(), inputLevel; got != want {
		t.Fatalf("input level: got %d, want %d", got, want)
	}
	if got, want := profile.LogDimensions(), params.LogMaxDimensions(); got != want {
		t.Fatalf("dimensions: got %+v, want %+v", got, want)
	}
	if !profile.InputScale().EqualScale(params.DefaultScale()) || profile.InputScale().HasMod() {
		t.Fatal("profile does not bind the exact non-modular A2B-chain scale")
	}
	if profile.RequiresRelinearization() || profile.RequiresConjugation() {
		t.Fatal("B2A-at-level requested a relinearization or conjugation key")
	}

	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisKeys := keyGenerator.GenGaloisKeysNew(profile.RequiredGaloisElements(), secretKey)
	bound, err := circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)))
	if err != nil {
		t.Fatal(err)
	}

	words := []uint64{0x00, 0x10, 0xa5, 0xff}
	lowValues := make([]complex128, params.MaxSlots())
	highValues := make([]complex128, params.MaxSlots())
	for wordIndex, word := range words {
		halves, err := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
		if err != nil {
			t.Fatal(err)
		}
		for bit := 0; bit < 4; bit++ {
			lowValues[wordIndex*4+bit] = complex(float64(halves.Low[bit]), 0)
			highValues[wordIndex*4+bit] = complex(float64(halves.High[bit]), 0)
		}
	}
	lowCiphertext := b2aChainEncryptAtLevel(t, params, encoder, secretKey, inputLevel, lowValues)
	highCiphertext := b2aChainEncryptAtLevel(t, params, encoder, secretKey, inputLevel, highValues)
	lowBefore, highBefore := lowCiphertext.CopyNew(), highCiphertext.CopyNew()
	low, err := circuit.BindLow(lowCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	high, err := circuit.BindHigh(highCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindInput(low, high)
	if err != nil {
		t.Fatal(err)
	}
	result, err := bound.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if !lowCiphertext.Equal(lowBefore) || !highCiphertext.Equal(highBefore) {
		t.Fatal("B2A-at-level mutated a Boolean input half")
	}
	detachedOutput := result.Ciphertext()
	detachedOutput.Scale = detachedOutput.Scale.Mul(rlwe.NewScale(2))
	output := result.Ciphertext()
	if output == nil || output.Scale.Equal(detachedOutput.Scale) {
		t.Fatal("B2A-at-level result accessor aliases internal ciphertext state")
	}
	if got, want := result.Provenance().ProfileDigest(), profile.Digest(); got != want {
		t.Fatalf("result profile digest: got %s, want %s", got, want)
	}
	if got, want := output.Level(), inputLevel-1; got != want {
		t.Fatalf("output level: got %d, want %d", got, want)
	}
	if snapshot, err := homchain.NewExactScaleSnapshot(output.Scale); err != nil || !snapshot.EqualScale(params.DefaultScale()) {
		t.Fatalf("output scale is not the exact A2B-chain default: snapshot=%+v err=%v", snapshot, err)
	}

	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	b2aAssertResidues(t, ringZ, b2aDecrypt(t, params, encoder, secretKey, output), words)
}

func TestB2AFullAtLevelRejectsInvalidIngressState(t *testing.T) {
	params := b2aChainFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	reorderedQ := append([]uint64(nil), params.Q()...)
	reorderedQ[1], reorderedQ[2] = reorderedQ[2], reorderedQ[1]
	reorderedParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, Q: reorderedQ, P: append([]uint64(nil), params.P()...), LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	if params.Equal(&reorderedParams) {
		t.Fatal("reordered-Q negative unexpectedly equals the canonical parameter chain")
	}
	if _, err = homchain.NewB2AFullAtLevelCircuit(reorderedParams, ckks.NewEncoder(reorderedParams, z2n.DefaultPrecision), 5); err == nil {
		t.Fatal("same-bit reordered Q chain was accepted as the canonical A2B parameter chain")
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
		t.Fatal("alternate-Q negative unexpectedly equals the canonical parameter chain")
	}
	if _, err = homchain.NewB2AFullAtLevelCircuit(alternateParams, ckks.NewEncoder(alternateParams, z2n.DefaultPrecision), 5); err == nil {
		t.Fatal("same-bit alternate Q prime was accepted as the canonical A2B parameter chain")
	}
	if _, err := homchain.NewB2AFullAtLevelCircuit(params, nil, 5); err == nil {
		t.Fatal("nil encoder was accepted")
	}
	if _, err := homchain.NewB2AFullAtLevelCircuit(params, ckks.NewEncoder(params, 192), 5); err == nil {
		t.Fatal("non-profile encoder precision was accepted")
	}
	standaloneParams := b2aFunctionalParameters(t)
	if _, err := homchain.NewB2AFullAtLevelCircuit(params, ckks.NewEncoder(standaloneParams, z2n.DefaultPrecision), 5); err == nil {
		t.Fatal("encoder with mismatched parameters was accepted")
	}
	if _, err := homchain.NewB2AFullAtLevelCircuit(params, encoder, 0); err == nil {
		t.Fatal("level-zero B2A ingress was accepted instead of the fixed level 5")
	}
	if _, err := homchain.NewB2AFullAtLevelCircuit(params, encoder, 4); err == nil {
		t.Fatal("level-4 B2A ingress was accepted instead of the fixed level 5")
	}
	if _, err := homchain.NewB2AFullAtLevelCircuit(params, encoder, 6); err == nil {
		t.Fatal("level-6 B2A ingress was accepted instead of the fixed level 5")
	}
	if _, err := homchain.NewB2AFullAtLevelCircuit(params, encoder, params.MaxLevel()+1); err == nil {
		t.Fatal("B2A ingress above MaxLevel was accepted")
	}

	circuit, err := homchain.NewB2AFullAtLevelCircuit(params, encoder, 5)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	wrongLevel := b2aChainEncryptAtLevel(t, params, encoder, secretKey, 6, make([]complex128, params.MaxSlots()))
	if _, err := circuit.BindLow(wrongLevel); err == nil {
		t.Fatal("Boolean half at the wrong physical ingress level was accepted")
	}
	valid := b2aChainEncryptAtLevel(t, params, encoder, secretKey, 5, make([]complex128, params.MaxSlots()))
	badScale := valid.CopyNew()
	badScale.Scale = badScale.Scale.Mul(rlwe.NewScale(2))
	if _, err := circuit.BindHigh(badScale); err == nil {
		t.Fatal("Boolean half at a non-profile exact scale was accepted")
	}
	if _, err := circuit.BindEvaluator(ckks.NewEvaluator(params, nil)); err == nil {
		t.Fatal("nil evaluation-key set was accepted")
	}
	required := circuit.Profile().RequiredGaloisElements()
	for missingIndex, missing := range required {
		present := append([]uint64(nil), required[:missingIndex]...)
		present = append(present, required[missingIndex+1:]...)
		keys := keyGenerator.GenGaloisKeysNew(present, secretKey)
		if _, err := circuit.BindEvaluator(ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil, keys...))); err == nil {
			t.Fatalf("key preflight accepted a set missing Galois element %d", missing)
		}
	}
}

func TestB2AFullAtLevelRejectsPostBindKeyMutationBeforeInputMutation(t *testing.T) {
	params := b2aChainFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	circuit, err := homchain.NewB2AFullAtLevelCircuit(params, encoder, 5)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	required := circuit.Profile().RequiredGaloisElements()
	galoisKeys := keyGenerator.GenGaloisKeysNew(required, secretKey)
	keySet := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	sourceEvaluator := ckks.NewEvaluator(params, keySet)
	bound, err := circuit.BindEvaluator(sourceEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	lowCiphertext := b2aChainEncryptAtLevel(t, params, encoder, secretKey, 5, make([]complex128, params.MaxSlots()))
	highCiphertext := b2aChainEncryptAtLevel(t, params, encoder, secretKey, 5, make([]complex128, params.MaxSlots()))
	low, err := circuit.BindLow(lowCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	high, err := circuit.BindHigh(highCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	input, err := circuit.BindInput(low, high)
	if err != nil {
		t.Fatal(err)
	}
	assertRejectedBeforeInputMutation := func(name string) {
		t.Helper()
		lowBefore, highBefore := lowCiphertext.CopyNew(), highCiphertext.CopyNew()
		if _, evaluationErr := bound.EvaluateNew(input); evaluationErr == nil {
			t.Fatalf("%s was accepted after binding", name)
		}
		if !lowCiphertext.Equal(lowBefore) || !highCiphertext.Equal(highBefore) {
			t.Fatalf("%s failure mutated an input half", name)
		}
	}

	for _, element := range required {
		original := keySet.GaloisKeys[element]
		keySet.GaloisKeys[element] = nil
		assertRejectedBeforeInputMutation("deleted Galois key")
		keySet.GaloisKeys[element] = original
	}

	replacement := keyGenerator.GenGaloisKeyNew(required[0], secretKey)
	original := keySet.GaloisKeys[required[0]]
	keySet.GaloisKeys[required[0]] = replacement
	assertRejectedBeforeInputMutation("same-secret Galois key pointer swap")
	keySet.GaloisKeys[required[0]] = original

	foreignSecret := keyGenerator.GenSecretKeyNew()
	foreignKey := keyGenerator.GenGaloisKeyNew(required[0], foreignSecret)
	keySet.GaloisKeys[required[0]] = foreignKey
	assertRejectedBeforeInputMutation("foreign-secret Galois key swap")
	keySet.GaloisKeys[required[0]] = original

	originalKeySet := sourceEvaluator.EvaluationKeySet
	sourceEvaluator.EvaluationKeySet = rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	assertRejectedBeforeInputMutation("evaluation key-set replacement")
	sourceEvaluator.EvaluationKeySet = originalKeySet

	if _, err = bound.EvaluateNew(input); err != nil {
		t.Fatalf("restored key graph did not recover: %v", err)
	}
}

func TestB2AFullAtLevelProfileAccessorsAreDefensive(t *testing.T) {
	params := b2aChainFunctionalParameters(t)
	circuit, err := homchain.NewB2AFullAtLevelCircuit(params, ckks.NewEncoder(params, z2n.DefaultPrecision), 5)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	rotations := profile.RequiredRotationIndexes()
	galois := profile.RequiredGaloisElements()
	rotations[0] = 99
	galois[0] = 99
	if got, want := circuit.Profile().RequiredRotationIndexes(), []int{1, 2, 12, 14}; !slices.Equal(got, want) {
		t.Fatalf("rotation accessor aliases profile storage: got %v, want %v", got, want)
	}
	if got, want := circuit.Profile().RequiredGaloisElements(), []uint64{5, 17, 25, 41}; !slices.Equal(got, want) {
		t.Fatalf("Galois accessor aliases profile storage: got %v, want %v", got, want)
	}

	standaloneParams := b2aFunctionalParameters(t)
	standalone, err := homchain.NewB2AFullCircuit(standaloneParams, ckks.NewEncoder(standaloneParams, z2n.DefaultPrecision))
	if err != nil {
		t.Fatal(err)
	}
	standaloneProfile := standalone.Profile()
	if got, want := standaloneProfile.DigestSchema(), "b2a-full-v2"; got != want {
		t.Fatalf("standalone digest schema drifted: got %q, want %q", got, want)
	}
	if standaloneProfile.TransformSourceDigest() != "" || standaloneProfile.CompiledPlanDigest() != "" {
		t.Fatal("chain-only digest fields leaked into the standalone v2 profile")
	}
	if got, want := standaloneProfile.Digest(), "783ca9bc757fe908bddea34d35d70791b04668f93cee52d13189dd02c68f8f8b"; got != want {
		t.Fatalf("standalone v2 digest drifted: got %s, want %s", got, want)
	}
}

func b2aChainFunctionalParameters(t *testing.T) ckks.Parameters {
	t.Helper()
	logQ := []int{50}
	for i := 0; i < 20; i++ {
		logQ = append(logQ, 35)
	}
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            5,
		LogQ:            logQ,
		LogP:            []int{50},
		LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func b2aChainEncryptAtLevel(t *testing.T, params ckks.Parameters, encoder *ckks.Encoder, secretKey *rlwe.SecretKey, level int, values []complex128) *rlwe.Ciphertext {
	t.Helper()
	plaintext := ckks.NewPlaintext(params, level)
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: params.LogMaxSlots()}
	plaintext.Scale = params.DefaultScale()
	if err := encoder.Encode(values, plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}
