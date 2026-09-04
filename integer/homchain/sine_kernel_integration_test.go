package homchain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestFunctionalNotSecureGaoSineKernelConsumesNineLevelsAtFullPacking(t *testing.T) {
	params, err := homchain.GaoSineKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := homchain.NewGaoSineKernelProfile()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := params.MaxSlots(), 16; got != want {
		t.Fatalf("functional profile slots: got %d, want %d", got, want)
	}
	if got, want := params.MaxLevel(), profile.LattigoSchedule().TotalLevels(); got != want {
		t.Fatalf("functional profile level: got %d, want %d", got, want)
	}
	if got, want := params.LogDefaultScale(), 35; got != want {
		t.Fatalf("functional profile log scale: got %d, want %d", got, want)
	}
	const qCenter = uint64(1) << 35
	const qTolerance = uint64(1) << 20
	for i, qi := range params.Q() {
		if qi < qCenter-qTolerance || qi > qCenter+qTolerance {
			t.Fatalf("functional profile Q[%d]=%d is not a 35-bit-scale prime", i, qi)
		}
	}
	if p := params.P(); len(p) != 1 || p[0] < uint64(1)<<59 || p[0] >= uint64(1)<<60 {
		t.Fatalf("functional profile P is not one 60-bit auxiliary prime: %v", p)
	}

	encoder := ckks.NewEncoder(params, profile.Precision())
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	relinearizationKey := keyGenerator.GenRelinearizationKeyNew(secretKey)
	evaluator := ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(relinearizationKey))
	if got, want := evaluator.Encoder.Prec(), params.EncodingPrecision(); got != want || got > 53 {
		t.Fatalf("fixture evaluator did not start on the default <=53-bit encoder: got %d, want %d", got, want)
	}
	artifact := "inline-functional-not-secure:gao-sine-input-is-x-equals-u-over-16"
	digest := sha256.Sum256([]byte(artifact))
	certificate, err := homchain.NewGaoSineKernelInputCertificate(
		profile, params.DefaultScale(), artifact, hex.EncodeToString(digest[:]),
	)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.DomainInternallyVerified() || certificate.VerificationStatus() != homchain.GaoSineDomainExternalUnverified {
		t.Fatal("encrypted x=u/16 range claim was promoted to an internal proof")
	}
	kernel, err := homchain.NewGaoSineKernelEvaluator(params, encoder, evaluator, certificate)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := kernel.OperationalEncoderPrecision(), profile.Precision(); got != want {
		t.Fatalf("kernel operational encoder precision: got %d, want %d", got, want)
	}
	if got, want := evaluator.Encoder.Prec(), params.EncodingPrecision(); got != want {
		t.Fatalf("constructor mutated caller evaluator precision: got %d, want %d", got, want)
	}
	encodingPlan := kernel.OperandEncodingPlan()
	if encodingPlan.PolynomialEncoding() != homchain.GaoSinePackedVectorEncoding ||
		encodingPlan.PolynomialMappedSlots() != params.MaxSlots() {
		t.Fatalf("polynomial operand is not a full-slot packed vector: kind=%q slots=%d",
			encodingPlan.PolynomialEncoding(), encodingPlan.PolynomialMappedSlots())
	}
	if got, want := encodingPlan.RecurrenceVectorSlots(), ([3]int{16, 16, 16}); got != want {
		t.Fatalf("recurrence operands are not full-slot packed vectors: got %v, want %v", got, want)
	}
	if got, want := encodingPlan.RecurrenceEncodings(), ([3]homchain.GaoSineOperandEncoding{
		homchain.GaoSinePackedVectorEncoding,
		homchain.GaoSinePackedVectorEncoding,
		homchain.GaoSinePackedVectorEncoding,
	}); got != want {
		t.Fatalf("recurrence operand dispatch kinds: got %v, want %v", got, want)
	}

	// The pinned contract lists fifteen distinct probes. The final +1.25 probe
	// fills the sixteenth physical slot without weakening any listed sentinel.
	uNumerators := []int64{0, 1, -1, 1, -1, 3, -3, 31, -31, 63, -63, 62, -62, 64, -64, 5}
	uDenominators := []int64{1, 8, 8, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4}
	inputs := make([]*big.Float, params.MaxSlots())
	want := make([]*big.Float, params.MaxSlots())
	for i := range inputs {
		u := new(big.Rat).SetFrac(big.NewInt(uNumerators[i]), big.NewInt(uDenominators[i]))
		x := new(big.Rat).Quo(u, big.NewRat(16, 1))
		inputs[i] = new(big.Float).SetPrec(profile.Precision()).SetRat(x)
		oracle, err := homchain.EvaluateGaoSineKernelOracle(profile, inputs[i])
		if err != nil {
			t.Fatalf("oracle slot %d: %v", i, err)
		}
		want[i] = oracle.FixedKernel()
	}
	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	plaintext.LogDimensions = params.LogMaxDimensions()
	plaintext.Scale = params.DefaultScale()
	if err = encoder.Encode(inputs, plaintext); err != nil {
		t.Fatal(err)
	}
	input, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	inputBefore := input.CopyNew()
	result, err := kernel.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if !input.Equal(inputBefore) {
		t.Fatal("Gao sine kernel mutated its input")
	}
	output := result.Ciphertext()
	if output == nil {
		t.Fatal("Gao sine result has nil ciphertext")
	}
	pristineOutput := output.CopyNew()
	if err = evaluator.Add(output, 1, output); err != nil {
		t.Fatal(err)
	}
	if second := result.Ciphertext(); second == nil || !second.Equal(pristineOutput) {
		t.Fatal("mutating a returned ciphertext changed the owned Gao sine result")
	}
	output = pristineOutput
	if output.Level() != 0 || output.Degree() != 1 {
		t.Fatalf("output state: level=%d degree=%d", output.Level(), output.Degree())
	}
	provenance := result.Provenance()
	if provenance.ProfileDigest() != profile.Digest() || provenance.InputCertificateDigest() != certificate.Digest() {
		t.Fatal("Gao sine provenance is not bound to the profile and input certificate")
	}
	if got, want := provenance.OperationalEncoderPrecision(), profile.Precision(); got != want {
		t.Fatalf("provenance operational encoder precision: got %d, want %d", got, want)
	}
	if got := provenance.OperandEncodingTrace(); got != encodingPlan {
		t.Fatalf("runtime operand trace does not match the constructor plan: got %+v, want %+v", got, encodingPlan)
	}
	if provenance.SourceSchedule() != (homchain.GaoSineSchedule{PolynomialLevels: 6, DoubleAngleLevels: 3}) ||
		provenance.LattigoSchedule() != (homchain.GaoSineSchedule{PolynomialLevels: 6, DoubleAngleLevels: 3}) {
		t.Fatal("source and Lattigo depth ledgers were conflated")
	}
	states := provenance.States()
	wantLevels := []int{9, 3, 2, 1, 0}
	if len(states) != len(wantLevels) {
		t.Fatalf("state count: got %d, want %d", len(states), len(wantLevels))
	}
	for i, state := range states {
		if state.Level != wantLevels[i] || state.Degree != 1 || !state.ScaleExact {
			t.Fatalf("state %d: %+v", i, state)
		}
	}
	if provenance.FinalScalePrecisionBits() < 100 {
		t.Fatalf("naturally reached final scale has only %.2f bits relative precision", provenance.FinalScalePrecisionBits())
	}

	decoded := make([]*big.Float, params.MaxSlots())
	decrypted := ckks.NewDecryptor(params, secretKey).DecryptNew(output)
	if err = encoder.Decode(decrypted, decoded); err != nil {
		t.Fatal(err)
	}
	maxError := new(big.Float).SetPrec(profile.Precision())
	for i := range decoded {
		error := absDifference(decoded[i], want[i])
		if error.Cmp(maxError) > 0 {
			maxError.Set(error)
		}
	}
	maxErrorFloat, _ := maxError.Float64()
	precisionBits := math.Inf(1)
	if maxErrorFloat != 0 {
		precisionBits = -math.Log2(maxErrorFloat)
	}
	t.Logf("Gao sine ciphertext-to-fixed-oracle max error=%s (%.2f bits); final-scale precision=%.2f bits; profile=%s",
		maxError.Text('e', 8), precisionBits, provenance.FinalScalePrecisionBits(), profile.Digest())
	if maxError.Cmp(pow2Negative(20, profile.Precision())) >= 0 {
		t.Fatalf("ciphertext-to-fixed-oracle error=%s exceeds functional 2^-20 gate", maxError.Text('e', 8))
	}
}

func TestGaoSinePackedVectorDispatchDistinguishesDefault53BitScalarRounding(t *testing.T) {
	params, err := homchain.GaoSineKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := homchain.NewGaoSineKernelProfile()
	if err != nil {
		t.Fatal(err)
	}
	defaultEvaluator := ckks.NewEvaluator(params, nil)
	if got := defaultEvaluator.Encoder.Prec(); got > 53 {
		t.Fatalf("rounding-trap fixture requires the default scalar precision, got %d", got)
	}
	packedEvaluator := defaultEvaluator.ShallowCopy()
	packedEvaluator.Encoder = ckks.NewEncoder(params, profile.Precision())

	// The exact Gao dyadic has 128 fractional bits. At scale 2^200 the
	// default scalar dispatch's 53-bit conversion is visible, while the packed
	// vector dispatch calls the bound 256-bit Encoder and preserves it.
	exact := profile.RecurrenceValues()[0]
	packed := make([]*big.Float, params.MaxSlots())
	for i := range packed {
		packed[i] = new(big.Float).SetPrec(profile.Precision()).Set(exact)
	}
	highScaleValue := new(big.Float).SetPrec(profile.Precision()).SetInt(
		new(big.Int).Lsh(big.NewInt(1), 200),
	)
	zero := ckks.NewCiphertext(params, 1, params.MaxLevel())
	zero.Scale = rlwe.NewScale(highScaleValue)
	scalarOutput := zero.CopyNew()
	if err = packedEvaluator.Add(scalarOutput, exact, scalarOutput); err != nil {
		t.Fatal(err)
	}
	packedOutput := zero.CopyNew()
	if err = packedEvaluator.Add(packedOutput, packed, packedOutput); err != nil {
		t.Fatal(err)
	}
	if scalarOutput.Equal(packedOutput) {
		t.Fatal("53-bit scalar and 256-bit packed-vector branches were not source-distinguishable")
	}

	scalarDecoded := make([]*big.Float, params.MaxSlots())
	packedDecoded := make([]*big.Float, params.MaxSlots())
	secretKey := ckks.NewKeyGenerator(params).GenSecretKeyNew()
	decryptor := ckks.NewDecryptor(params, secretKey)
	if err = packedEvaluator.Decode(decryptor.DecryptNew(scalarOutput), scalarDecoded); err != nil {
		t.Fatal(err)
	}
	if err = packedEvaluator.Decode(decryptor.DecryptNew(packedOutput), packedDecoded); err != nil {
		t.Fatal(err)
	}
	scalarError := absDifference(scalarDecoded[0], exact)
	packedError := absDifference(packedDecoded[0], exact)
	if packedError.Cmp(pow2Negative(128, profile.Precision())) >= 0 {
		t.Fatalf("256-bit packed-vector rounding trap error=%s, want <2^-128", packedError.Text('e', 8))
	}
	if scalarError.Cmp(pow2Negative(56, profile.Precision())) <= 0 {
		t.Fatalf("default scalar rounding trap error=%s, want >2^-56", scalarError.Text('e', 8))
	}

	// PolynomialVector's non-nil mapping reaches the corresponding vector
	// MulThenAdd branch. Exercise both MulThenAdd sources with the same trap.
	one := ckks.NewCiphertext(params, 1, params.MaxLevel())
	one.Scale = rlwe.NewScale(1)
	if err = packedEvaluator.Add(one, 1, one); err != nil {
		t.Fatal(err)
	}
	scalarMulOutput := ckks.NewCiphertext(params, 1, params.MaxLevel())
	scalarMulOutput.Scale = rlwe.NewScale(highScaleValue)
	if err = packedEvaluator.MulThenAdd(one, exact, scalarMulOutput); err != nil {
		t.Fatal(err)
	}
	packedMulOutput := ckks.NewCiphertext(params, 1, params.MaxLevel())
	packedMulOutput.Scale = rlwe.NewScale(highScaleValue)
	if err = packedEvaluator.MulThenAdd(one, packed, packedMulOutput); err != nil {
		t.Fatal(err)
	}
	if scalarMulOutput.Equal(packedMulOutput) {
		t.Fatal("53-bit scalar and 256-bit packed-vector MulThenAdd branches were not source-distinguishable")
	}
	if err = packedEvaluator.Decode(decryptor.DecryptNew(scalarMulOutput), scalarDecoded); err != nil {
		t.Fatal(err)
	}
	if err = packedEvaluator.Decode(decryptor.DecryptNew(packedMulOutput), packedDecoded); err != nil {
		t.Fatal(err)
	}
	scalarMulError := absDifference(scalarDecoded[0], exact)
	packedMulError := absDifference(packedDecoded[0], exact)
	if packedMulError.Cmp(pow2Negative(128, profile.Precision())) >= 0 ||
		scalarMulError.Cmp(pow2Negative(56, profile.Precision())) <= 0 {
		t.Fatalf("MulThenAdd rounding trap errors: scalar53=%s packed256=%s",
			scalarMulError.Text('e', 8), packedMulError.Text('e', 8))
	}
	t.Logf("Gao sine dispatch rounding traps: Add scalar53=%s packed256=%s; MulThenAdd scalar53=%s packed256=%s",
		scalarError.Text('e', 8), packedError.Text('e', 8), scalarMulError.Text('e', 8), packedMulError.Text('e', 8))
}

func TestGaoSineKernelRejectsMissingKeyAndInvalidInputCertificateState(t *testing.T) {
	params, err := homchain.GaoSineKernelFunctionalParameters()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := homchain.NewGaoSineKernelProfile()
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, profile.Precision())
	artifact := "inline-functional-not-secure:gao-sine-input-is-x-equals-u-over-16"
	digest := sha256.Sum256([]byte(artifact))
	certificate, err := homchain.NewGaoSineKernelInputCertificate(profile, params.DefaultScale(), artifact, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	missingKeyEvaluator := ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(nil))
	if _, err = homchain.NewGaoSineKernelEvaluator(params, encoder, missingKeyEvaluator, certificate); err == nil {
		t.Fatal("constructor accepted a missing relinearization key")
	}
	if _, err = homchain.NewGaoSineKernelInputCertificate(profile, params.DefaultScale(), artifact, "wrong"); err == nil {
		t.Fatal("input certificate accepted a mismatched evidence digest")
	}

	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	mutableKeySet := rlwe.NewMemEvaluationKeySet(keyGenerator.GenRelinearizationKeyNew(secretKey))
	kernel, err := homchain.NewGaoSineKernelEvaluator(
		params, encoder,
		ckks.NewEvaluator(params, mutableKeySet),
		certificate,
	)
	if err != nil {
		t.Fatal(err)
	}
	badLevel := ckks.NewCiphertext(params, 1, params.MaxLevel()-1)
	badLevel.LogDimensions = params.LogMaxDimensions()
	badLevel.Scale = params.DefaultScale()
	if _, err = kernel.EvaluateNew(badLevel); err == nil {
		t.Fatal("evaluator accepted an input at the wrong level")
	}
	badScale := ckks.NewCiphertext(params, 1, params.MaxLevel())
	badScale.LogDimensions = params.LogMaxDimensions()
	badScale.Scale = params.DefaultScale().Mul(rlwe.NewScale(2))
	if _, err = kernel.EvaluateNew(badScale); err == nil {
		t.Fatal("evaluator accepted an input with a mismatched exact scale")
	}

	validInput := ckks.NewCiphertext(params, 1, params.MaxLevel())
	validInput.LogDimensions = params.LogMaxDimensions()
	validInput.Scale = params.DefaultScale()
	validInputBefore := validInput.CopyNew()
	mutableKeySet.RelinearizationKey = nil
	if _, err = kernel.EvaluateNew(validInput); err == nil {
		t.Fatal("evaluator ran after its relinearization key was removed post-construction")
	}
	if !validInput.Equal(validInputBefore) {
		t.Fatal("post-constructor key preflight failure mutated the input")
	}
}
