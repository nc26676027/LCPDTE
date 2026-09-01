package homchain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	ckksdft "github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type sealedA2AIHighPublicEvaluator interface {
	A2AIHighNew(*rlwe.Ciphertext, homchain.A2AIAdmissionCertificate) (*rlwe.Ciphertext, homchain.A2AIHighTrace, error)
}

var _ sealedA2AIHighPublicEvaluator = (*homchain.A2AIHighEvaluator)(nil)

func TestA2AIHighCircuitSealsNormalTransformsBeforeKeyGeneration(t *testing.T) {
	params := a2aiFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	rawDFTConfig := homchain.RawFullSlotDFTConfig{
		SlotsToCoeffsLevelQ: params.MaxLevel() - params.LevelsConsumedPerRescaling(),
		SlotsToCoeffsLevels: []int{1, 1},
		CoeffsToSlotsLevelQ: params.MaxLevel(),
		CoeffsToSlotsLevels: []int{1, 1, 1},
		LevelP:              params.MaxLevelP(),
	}
	rawDFT, err := homchain.NewRawFullSlotDFT(params, encoder, rawDFTConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rawDFT.GeneratorPrecision(), z2n.DefaultPrecision; got != want {
		t.Fatalf("raw DFT generator precision: got %d, want %d", got, want)
	}
	if got, want := rawDFT.MatrixSourceDigest(), "479964f861b0c9bd15f888c4c13dd526cd1192e6534680aca1cd2d839f5fd8aa"; got != want {
		t.Fatalf("raw DFT matrix-source digest: got %q, want %q", got, want)
	}
	defaultPrecisionDFT, err := homchain.NewRawFullSlotDFT(params, ckks.NewEncoder(params), rawDFTConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := defaultPrecisionDFT.GeneratorPrecision(), params.EncodingPrecision(); got != want || got >= z2n.DefaultPrecision {
		t.Fatalf("default raw DFT generator precision: got %d, want %d below %d", got, want, z2n.DefaultPrecision)
	}
	if got, lowerPrecision := rawDFT.MatrixSourceDigest(), defaultPrecisionDFT.MatrixSourceDigest(); got == lowerPrecision {
		t.Fatalf("192-bit and %d-bit DFT matrix sources have the same digest %q", params.EncodingPrecision(), got)
	}
	circuit, err := homchain.NewA2AIHighCircuit(params, encoder, rawDFT, homchain.A2AIHighOptions{
		MaxAbsLog2ScaleDownError: 1e-6,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if got, want := profile.WordBits(), z2n.Word8; got != want {
		t.Fatalf("word bits: got %d, want %d", got, want)
	}
	if got, want := profile.Words(), 4; got != want {
		t.Fatalf("words: got %d, want %d", got, want)
	}
	if got, want := profile.Slots(), params.MaxSlots(); got != want {
		t.Fatalf("slots: got %d, want %d", got, want)
	}
	if got, want := profile.EncoderPrecision(), z2n.DefaultPrecision; got != want {
		t.Fatalf("encoder precision: got %d, want %d", got, want)
	}
	if got, want := profile.MaxAbsLog2ScaleDownError(), 1e-6; got != want {
		t.Fatalf("ScaleDown error bound: got %g, want %g", got, want)
	}
	if got, want := profile.TransformNames(), []homchain.TransformName{homchain.V0Normal, homchain.V1Normal, homchain.U0Normal, homchain.U1Normal}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sealed transform names: got %v, want %v", got, want)
	}
	vCompile, uCompile := profile.VCompile(), profile.UCompile()
	if vCompile.LowName() != homchain.V0Normal || vCompile.HighName() != homchain.V1Normal ||
		uCompile.LowName() != homchain.U0Normal || uCompile.HighName() != homchain.U1Normal {
		t.Fatalf("compile provenance is not normal V/U: V=(%s,%s) U=(%s,%s)", vCompile.LowName(), vCompile.HighName(), uCompile.LowName(), uCompile.HighName())
	}
	if got, want := vCompile.LevelQ(), params.MaxLevel(); got != want {
		t.Fatalf("V compile level: got %d, want %d", got, want)
	}
	if got, want := uCompile.LevelQ(), rawDFT.CoeffsToSlotsOutputLevel(); got != want {
		t.Fatalf("U compile level: got %d, want %d", got, want)
	}
	if !vCompile.Scale().EqualScale(params.DefaultScale()) || !uCompile.Scale().EqualScale(params.DefaultScale()) {
		t.Fatal("normal V/U were not compiled at the exact default scale")
	}
	if profile.TransformSourceDigest() == "" || profile.RawDFTDigest() == "" || profile.ParametersDigest() == "" || profile.CircuitDigest() == "" {
		t.Fatalf("incomplete sealed provenance: %+v", profile)
	}
	if got, want := profile.TransformSourceDigest(), "684e28bcc0471875f6b0de6b8d3f389bf182424673dd7e52b201362671335e01"; got != want {
		t.Fatalf("normal source-matrix digest: got %q, want %q", got, want)
	}
	if got, want := profile.RawDFTDigest(), "a18c6f92e819d0e5d7751232ee3367e7d383f1c70631b8b757e421992581c196"; got != want {
		t.Fatalf("raw DFT digest: got %q, want %q", got, want)
	}
	if got, want := profile.CircuitDigest(), "062f533be7011ea36af41e23da164bb0f6ea42ed2edcc5317381381133f82c64"; got != want {
		t.Fatalf("sealed circuit digest: got %q, want %q", got, want)
	}
	if got, want := profile.ParametersDigest(), "64c09f6594276ab4c43c6e562b9a1e786a4459733bd1b29deb600a1a091617bc"; got != want {
		t.Fatalf("CKKS parameter digest: got %q, want %q", got, want)
	}

	first := circuit.RequiredKeyProfile()
	if first.Digest == "" || len(first.All) == 0 {
		t.Fatal("key profile is unavailable before bootstrap key generation")
	}
	if got, want := first.Digest, "07b0576b23a7e86fd6c76ef428515d4d2ee6f90583f76260dcff2fe9c4c6f721"; got != want {
		t.Fatalf("sealed key-profile digest: got %q, want %q", got, want)
	}
	if got, want := first.ZToC, []uint64{5, 17, 25, 41}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sealed Z-To-C key profile: got %v, want %v", got, want)
	}
	if got, want := first.SlotsToCoeffs, []uint64{5, 17, 25, 33, 41, 49}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sealed Slots-To-Coeffs key profile: got %v, want %v", got, want)
	}
	if len(first.Trace) != 0 {
		t.Fatalf("sealed gap-one Trace unexpectedly needs keys: %v", first.Trace)
	}
	if got, want := first.CoeffsToSlots, []uint64{5, 17, 25, 33, 41, 49}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sealed Coeffs-To-Slots key profile: got %v, want %v", got, want)
	}
	if got, want := first.CToZ, []uint64{5, 17, 25, 41}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sealed C-To-Z key profile: got %v, want %v", got, want)
	}
	if got, want := first.Conjugation, []uint64{63}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sealed conjugation key profile: got %v, want %v", got, want)
	}
	if got, want := first.All, []uint64{5, 17, 25, 33, 41, 49, 63}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sealed union key profile: got %v, want %v", got, want)
	}
	wantFirst := first.All[0]
	first.All[0] ^= 1
	first.ZToC = nil
	second := circuit.RequiredKeyProfile()
	if got := second.All[0]; got != wantFirst || len(second.ZToC) == 0 {
		t.Fatal("RequiredKeyProfile aliases mutable caller-owned slices")
	}
	names := profile.TransformNames()
	names[0] = homchain.V0FusedT
	if got := circuit.Profile().TransformNames()[0]; got != homchain.V0Normal {
		t.Fatal("Profile aliases mutable caller-owned transform names")
	}
	rotations := profile.VCompile().RotationIndexes()
	wantRotation := rotations[0]
	rotations[0]++
	if got := circuit.Profile().VCompile().RotationIndexes()[0]; got != wantRotation {
		t.Fatal("Profile aliases mutable compile-state rotations")
	}

	typeOfCircuit := reflect.TypeOf(*circuit)
	for i := 0; i < typeOfCircuit.NumField(); i++ {
		if typeOfCircuit.Field(i).IsExported() {
			t.Fatalf("A2AIHighCircuit exposes field %q", typeOfCircuit.Field(i).Name)
		}
	}
}

func TestA2AIHighCircuitRejectsUnboundEncoderParametersPrecisionAndRawProfile(t *testing.T) {
	params := a2aiFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	config := homchain.RawFullSlotDFTConfig{
		SlotsToCoeffsLevelQ: params.MaxLevel() - params.LevelsConsumedPerRescaling(),
		SlotsToCoeffsLevels: []int{1, 1},
		CoeffsToSlotsLevelQ: params.MaxLevel(),
		CoeffsToSlotsLevels: []int{1, 1, 1},
		LevelP:              params.MaxLevelP(),
	}
	rawDFT, err := homchain.NewRawFullSlotDFT(params, encoder, config)
	if err != nil {
		t.Fatal(err)
	}
	options := homchain.A2AIHighOptions{MaxAbsLog2ScaleDownError: 1e-6}
	if _, err = homchain.NewA2AIHighCircuit(params, nil, rawDFT, options); err == nil {
		t.Fatal("nil encoder was accepted")
	}
	if _, err = homchain.NewA2AIHighCircuit(params, ckks.NewEncoder(params, 128), rawDFT, options); err == nil {
		t.Fatal("non-default encoder precision was accepted")
	}
	lowPrecisionRawDFT, err := homchain.NewRawFullSlotDFT(params, ckks.NewEncoder(params, 128), config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = homchain.NewA2AIHighCircuit(params, encoder, lowPrecisionRawDFT, options); err == nil {
		t.Fatal("raw DFT encoded at non-default precision was accepted")
	}
	if _, err = homchain.NewA2AIHighCircuit(params, encoder, rawDFT, homchain.A2AIHighOptions{}); err == nil {
		t.Fatal("zero ScaleDown error contract was accepted")
	}

	otherParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            6,
		LogQ:            []int{50, 35, 35, 35, 35, 35, 35, 35, 35},
		LogP:            []int{50},
		LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherEncoder := ckks.NewEncoder(otherParams, z2n.DefaultPrecision)
	if _, err = homchain.NewRawFullSlotDFT(params, otherEncoder, config); err == nil {
		t.Fatal("raw DFT constructor accepted an encoder with different parameters")
	}
	otherRawDFT, err := homchain.NewRawFullSlotDFT(otherParams, otherEncoder, homchain.RawFullSlotDFTConfig{
		SlotsToCoeffsLevelQ: otherParams.MaxLevel() - otherParams.LevelsConsumedPerRescaling(),
		SlotsToCoeffsLevels: []int{1, 1},
		CoeffsToSlotsLevelQ: otherParams.MaxLevel(),
		CoeffsToSlotsLevels: []int{1, 1, 1},
		LevelP:              otherParams.MaxLevelP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = homchain.NewA2AIHighCircuit(params, otherEncoder, rawDFT, options); err == nil {
		t.Fatal("encoder with different parameters was accepted")
	}
	if _, err = homchain.NewA2AIHighCircuit(params, encoder, otherRawDFT, options); err == nil {
		t.Fatal("raw DFT with different parameters was accepted")
	}
	if _, err = homchain.NewA2AIHighCircuit(otherParams, otherEncoder, otherRawDFT, options); err == nil {
		t.Fatal("non-profile LogN/slot parameters were accepted")
	}

	bsgsRawDFT, err := homchain.NewRawFullSlotDFT(params, encoder, homchain.RawFullSlotDFTConfig{
		SlotsToCoeffsLevelQ: params.MaxLevel() - params.LevelsConsumedPerRescaling(),
		SlotsToCoeffsLevels: []int{1, 1},
		CoeffsToSlotsLevelQ: params.MaxLevel(),
		CoeffsToSlotsLevels: []int{1, 1, 1},
		LevelP:              params.MaxLevelP(),
		LogBSGSRatio:        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = homchain.NewA2AIHighCircuit(params, encoder, bsgsRawDFT, options); err == nil {
		t.Fatal("non-profile raw DFT BSGS ratio was accepted")
	}
}

func TestFunctionalNotSecureA2AIHighRemovesIntegerOverflowAtFullPacking(t *testing.T) {
	params := a2aiFunctionalParameters(t)
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}

	const words = 4
	if got, want := params.MaxSlots(), words*len(ringZ.Roots()); got != want {
		t.Fatalf("test is not full-packed: got %d slots, want %d", got, want)
	}

	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)

	rawDFT, err := homchain.NewRawFullSlotDFT(params, encoder, homchain.RawFullSlotDFTConfig{
		SlotsToCoeffsLevelQ: params.MaxLevel() - params.LevelsConsumedPerRescaling(),
		SlotsToCoeffsLevels: []int{1, 1},
		CoeffsToSlotsLevelQ: params.MaxLevel(),
		CoeffsToSlotsLevels: []int{1, 1, 1},
		LevelP:              params.MaxLevelP(),
		LogBSGSRatio:        0,
	})
	if err != nil {
		t.Fatal(err)
	}

	circuit, err := homchain.NewA2AIHighCircuit(params, encoder, rawDFT, homchain.A2AIHighOptions{
		MaxAbsLog2ScaleDownError: 1e-6,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	keyProfile := circuit.RequiredKeyProfile()

	btpParams := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: rawDFT.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: rawDFT.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ:          rawDFT.CoeffsToSlotsOutputLevel(),
			LogScale:        params.LogDefaultScale(),
			Mod1Type:        mod1.SinContinuous,
			LogMessageRatio: 0,
			K:               1,
			Mod1Degree:      3,
		},
		CircuitOrder: bootstrapping.Custom,
	}

	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisElements := keyProfile.All
	evaluationKeys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeysNew(galoisElements, secretKey)...,
	)}
	bootstrapEvaluator, err := bootstrapping.NewEvaluator(btpParams, evaluationKeys)
	if err != nil {
		t.Fatal(err)
	}
	a2ai, err := circuit.BindEvaluator(bootstrapEvaluator)
	if err != nil {
		t.Fatal(err)
	}

	wordValues := []uint64{0x00, 0x10, 0x80, 0xa5}
	overflows := [][]int64{
		{63, -63, 56, -56, 48, -48, 40, -40},
		{-61, 53, -45, 37, -29, 21, -13, 5},
		{59, 0, -57, 0, 55, 0, -53, 0},
		{-51, 49, 0, -47, 45, 0, -43, 41},
	}

	inputSlots := make([]*bignum.Complex, 0, params.MaxSlots())
	wantSlots := make([]*bignum.Complex, 0, params.MaxSlots())
	wantPolynomials := make([]z2n.Polynomial, 0, words)
	maxInputOverflow := 0.0
	for i, word := range wordValues {
		for _, coefficient := range overflows[i] {
			maxInputOverflow = math.Max(maxInputOverflow, math.Abs(float64(coefficient)))
		}
		integerOverflow, err := ringZ.NewPolynomial(a2aiIntegerCoefficients(overflows[i]))
		if err != nil {
			t.Fatal(err)
		}
		noisy, err := ringZ.Add(ringZ.ArithmeticEncode(word), integerOverflow)
		if err != nil {
			t.Fatal(err)
		}
		if decoded, err := ringZ.DecodeArithmetic(noisy); err != nil || decoded != word {
			t.Fatalf("overflow polynomial changed word %d: got %#x, err=%v", i, decoded, err)
		}
		rootSlots, err := ringZ.ToRootSlots(noisy)
		if err != nil {
			t.Fatal(err)
		}
		inputSlots = append(inputSlots, rootSlots...)
		canonical, err := ringZ.CanonicalizeArithmetic(ringZ.ArithmeticEncode(word))
		if err != nil {
			t.Fatal(err)
		}
		wantPolynomials = append(wantPolynomials, canonical)
		canonicalSlots, err := ringZ.ToRootSlots(canonical)
		if err != nil {
			t.Fatal(err)
		}
		wantSlots = append(wantSlots, canonicalSlots...)
	}

	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	plaintext.LogDimensions = profile.VCompile().LogDimensions()
	if err := encoder.Encode(inputSlots, plaintext); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	inputBefore := ciphertext.CopyNew()
	admission := functionalA2AIAdmission(t, ciphertext.Scale, big.NewInt(64))

	got, trace, err := a2ai.A2AIHighNew(ciphertext, admission)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("A2A-I trace: %+v", trace)
	if !ciphertext.Equal(inputBefore) {
		t.Fatal("A2AIHighNew mutated its input ciphertext")
	}
	if got, want := trace.AdaptationLabel, homchain.A2AIGuardedLattigoAdaptation; got != want {
		t.Fatalf("adaptation label: got %q, want %q", got, want)
	}
	if got, want := trace.RawScaleSemantics, homchain.A2AIRawScaleQ0TimesError; got != want {
		t.Fatalf("raw-scale semantics: got %q, want %q", got, want)
	}
	if got, want := trace.CircuitDigest, profile.CircuitDigest(); got != want {
		t.Fatalf("circuit digest: got %q, want %q", got, want)
	}
	if got, want := trace.TransformSourceDigest, profile.TransformSourceDigest(); got != want {
		t.Fatalf("transform-source digest: got %q, want %q", got, want)
	}
	if got, want := trace.Admission.CertificateDigest, admission.Digest(); got != want {
		t.Fatalf("admission digest: got %q, want %q", got, want)
	}
	if trace.Admission.MessageBoundInternallyVerified {
		t.Fatal("functional admission was promoted to an internally verified message bound")
	}
	if !trace.Admission.InlineArtifactIntegrityChecked {
		t.Fatal("inline admission artifact digest was not checked")
	}
	if got, want := trace.Admission.VerificationStatus, homchain.A2AIEvidenceExternalUnverified; got != want {
		t.Fatalf("admission verification: got %q, want %q", got, want)
	}
	if got, want := trace.Admission.MaturityStatus, homchain.A2AIEvidenceFunctionalNotSecure; got != want {
		t.Fatalf("admission maturity: got %q, want %q", got, want)
	}
	if trace.EarlyResize.MessageBoundInternallyVerified {
		t.Fatal("early-Resize topology was reported as an internally verified centered-message proof")
	}
	if !trace.EarlyResize.TopologyConditionInternallyComputed {
		t.Fatal("early-Resize topology condition was not recorded")
	}
	if got, want := trace.EarlyResize.Source, "lattigo-v6.1.1:bootstrapping.ScaleDown/checkMessageRatio"; got != want {
		t.Fatalf("early-Resize source: got %q, want %q", got, want)
	}
	if got, want := trace.EarlyResize.InitialLevel, trace.AfterSlotsToCoeffs.Level; got != want {
		t.Fatalf("early-Resize initial level: got %d, want %d", got, want)
	}
	if got, want := len(trace.EarlyResize.ExpectedSteps), trace.AfterSlotsToCoeffs.Level; got != want {
		t.Fatalf("functional early-Resize steps: got %d, want %d", got, want)
	}
	if trace.EarlyResize.ActualEarlyResizeCountKnown {
		t.Fatal("adapter cannot observe Lattigo's internal early-Resize count")
	}
	if !trace.EarlyResize.ObservedOutputLevelKnown || trace.EarlyResize.ObservedOutputLevel != 0 {
		t.Fatalf("ScaleDown output-level observation is absent or wrong: %+v", trace.EarlyResize)
	}
	if got, want := trace.EarlyResize.TerminalLevelBeforeRescale, 0; got != want {
		t.Fatalf("early-Resize terminal level: got %d, want %d", got, want)
	}
	if trace.EarlyResize.ExpectedFinalRescaleToQ0 {
		t.Fatal("functional topology reaches q0 through early Resize, not a final rescale")
	}
	for level, step := range trace.EarlyResize.ExpectedSteps {
		wantFrom := trace.AfterSlotsToCoeffs.Level - level
		if step.FromLevel != wantFrom || step.ToLevel != wantFrom-1 || step.Condition != "current_message_ratio >= dropped_modulus * MessageRatio" {
			t.Fatalf("early-Resize step %d is inconsistent: %+v", level, step)
		}
	}
	if trace.FailureStage != "" {
		t.Fatalf("successful trace has failure stage %q", trace.FailureStage)
	}
	stages := []struct {
		name  string
		state homchain.CiphertextState
	}{
		{"input", trace.Input},
		{"Z-To-C", trace.AfterZToC},
		{"Slots-To-Coeffs", trace.AfterSlotsToCoeffs},
		{"ScaleDown", trace.AfterScaleDown},
		{"ModUp", trace.AfterModUp},
		{"Coeffs-To-Slots", trace.AfterCoeffsToSlots},
		{"output", trace.Output},
	}
	for _, stage := range stages {
		if stage.state.Status != homchain.A2AIReached {
			t.Fatalf("%s status: got %v, want reached", stage.name, stage.state.Status)
		}
	}
	if got, want := trace.RawDFT.SlotsToCoeffs.Levels, []int{1, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Slots-To-Coeffs levels: got %v, want %v", got, want)
	}
	if got, want := trace.RawDFT.CoeffsToSlots.Levels, []int{1, 1, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Coeffs-To-Slots levels: got %v, want %v", got, want)
	}
	if got, want := trace.RawDFT.SlotsToCoeffs.PhysicalRescaleDepth, 2; got != want {
		t.Fatalf("Slots-To-Coeffs physical depth: got %d, want %d", got, want)
	}
	if got, want := trace.RawDFT.CoeffsToSlots.PhysicalRescaleDepth, 3; got != want {
		t.Fatalf("Coeffs-To-Slots physical depth: got %d, want %d", got, want)
	}
	if trace.RawDFT.SlotsToCoeffs.ReportedModuliDepth != trace.RawDFT.SlotsToCoeffs.PhysicalRescaleDepth ||
		trace.RawDFT.CoeffsToSlots.ReportedModuliDepth != trace.RawDFT.CoeffsToSlots.PhysicalRescaleDepth {
		t.Fatal("all-one DFT factorization has inconsistent reported and physical depth")
	}
	if got, want := trace.RawDFT.Normalization, homchain.A2AIDFTNormalizationLattigoFullSplit; got != want {
		t.Fatalf("raw DFT normalization: got %q, want %q", got, want)
	}
	if got, want := trace.RawDFT.EncoderPrecision, z2n.DefaultPrecision; got != want {
		t.Fatalf("raw DFT encoder precision: got %d, want %d", got, want)
	}
	if got, want := trace.RawDFT.GeneratorPrecision, z2n.DefaultPrecision; got != want {
		t.Fatalf("raw DFT generator precision: got %d, want %d", got, want)
	}
	if got, want := trace.RawDFT.MatrixSourceDigest, rawDFT.MatrixSourceDigest(); got != want || got == "" {
		t.Fatalf("raw DFT matrix-source digest: got %q, want %q", got, want)
	}
	if trace.RawDFT.Digest == "" || trace.RawDFT.SlotsToCoeffs.ScalingHex == "" || trace.RawDFT.CoeffsToSlots.ScalingHex == "" {
		t.Fatal("raw DFT audit profile is incomplete")
	}
	if got, want := trace.KeyProfile.SwitchingMode, homchain.A2AIDenseNoSwitchLattigoAdaptation; got != want {
		t.Fatalf("switching mode: got %q, want %q", got, want)
	}
	if !trace.KeyProfile.RelinearizationRequired || trace.KeyProfile.Digest == "" {
		t.Fatal("key profile omits relinearization or digest")
	}
	if len(trace.KeyProfile.Trace) != 0 {
		t.Fatalf("gap-one Trace unexpectedly requires rotations: %v", trace.KeyProfile.Trace)
	}
	wantGalois := append([]uint64(nil), galoisElements...)
	sort.Slice(wantGalois, func(i, j int) bool { return wantGalois[i] < wantGalois[j] })
	if got := trace.KeyProfile.All; !reflect.DeepEqual(got, wantGalois) {
		t.Fatalf("exact A2A-I Galois profile: got %v, want %v", got, wantGalois)
	}
	if !trace.KeyPreflight.Checked || !trace.KeyPreflight.EvaluatorGraphChecked || !trace.KeyPreflight.EvaluatorGraphMatched ||
		trace.KeyPreflight.EvaluatorGraphMismatch != "" || !trace.KeyPreflight.RelinearizationPresent || !trace.KeyPreflight.RelinearizationLevelMatched ||
		!trace.KeyPreflight.SwitchingModeMatched || len(trace.KeyPreflight.MissingGaloisElements) != 0 {
		t.Fatalf("key preflight did not prove required-key presence: %+v", trace.KeyPreflight)
	}

	if got, want := trace.FullPackingGap, 1; got != want {
		t.Fatalf("full-packing Trace gap: got %d, want %d", got, want)
	}
	if got, want := trace.Input.Level, params.MaxLevel(); got != want {
		t.Fatalf("input level: got %d, want %d", got, want)
	}
	if got, want := trace.AfterZToC.Level, rawDFT.SlotsToCoeffsLiteral().LevelQ; got != want {
		t.Fatalf("Z-To-C level: got %d, want %d", got, want)
	}
	if got, want := trace.AfterSlotsToCoeffs.Level, rawDFT.SlotsToCoeffsOutputLevel(); got != want {
		t.Fatalf("Slots-To-Coeffs level: got %d, want %d", got, want)
	}
	if !trace.AfterSlotsToCoeffs.Scale.Equal(trace.AfterZToC.Scale) {
		t.Fatal("raw Slots-To-Coeffs changed scale")
	}
	if got, want := trace.AfterScaleDown.Level, 0; got != want {
		t.Fatalf("ScaleDown level: got %d, want %d", got, want)
	}
	if got, want := trace.AfterModUp.Level, params.MaxLevel(); got != want {
		t.Fatalf("ModUp level: got %d, want %d", got, want)
	}
	if got, want := trace.AfterCoeffsToSlots.Level, rawDFT.CoeffsToSlotsOutputLevel(); got != want {
		t.Fatalf("Coeffs-To-Slots level: got %d, want %d", got, want)
	}
	if !trace.AfterCoeffsToSlots.Scale.Equal(trace.AfterModUp.Scale) {
		t.Fatal("raw Coeffs-To-Slots changed scale")
	}
	if got, want := trace.Output.Level, profile.UCompile().LevelQ()-params.LevelsConsumedPerRescaling(); got != want {
		t.Fatalf("C-To-Z output level: got %d, want %d", got, want)
	}
	if math.Abs(trace.ScaleDownLog2Error) > trace.MaxAbsLog2ScaleDownError {
		t.Fatalf("ScaleDown error %.4g exceeds bound %.4g", trace.ScaleDownLog2Error, trace.MaxAbsLog2ScaleDownError)
	}
	scaleDownError := scaleFromSnapshot(t, trace.ScaleDownError)
	afterScaleDown := scaleFromSnapshot(t, trace.AfterScaleDown.Scale)
	q0TimesError := rlwe.NewScale(params.Q()[0]).Mul(scaleDownError)
	if precision := afterScaleDown.Log2Delta(q0TimesError); precision < 100 {
		t.Fatalf("ScaleDown raw scale is not q0*errScale: relative precision %.2f bits", precision)
	}
	if !trace.AfterModUp.Scale.Equal(trace.AfterScaleDown.Scale) {
		t.Fatal("ModUp changed the exact raw scale under the no-relabel contract")
	}
	afterCoeffsToSlots := scaleFromSnapshot(t, trace.AfterCoeffsToSlots.Scale)
	uScale := scaleFromSnapshot(t, profile.UCompile().Scale())
	expectedOutputScale := afterCoeffsToSlots.Mul(uScale)
	for i := 0; i < params.LevelsConsumedPerRescaling(); i++ {
		expectedOutputScale = expectedOutputScale.Div(rlwe.NewScale(params.Q()[profile.UCompile().LevelQ()-i]))
	}
	if !trace.Output.Scale.EqualScale(expectedOutputScale) {
		gotScale := scaleFromSnapshot(t, trace.Output.Scale)
		t.Fatalf("C-To-Z output scale: got %s, want %s", gotScale.Value.Text('x', -1), expectedOutputScale.Value.Text('x', -1))
	}
	mutableScale := scaleFromSnapshot(t, trace.Input.Scale)
	mutableScale.Value.SetInt64(1)
	if !trace.Input.Scale.EqualScale(ciphertext.Scale) {
		t.Fatal("mutating a recovered trace scale changed the immutable input snapshot")
	}

	decoded := make([]complex128, params.MaxSlots())
	if err := encoder.Decode(ckks.NewDecryptor(params, secretKey).DecryptNew(got), decoded); err != nil {
		t.Fatal(err)
	}
	// This is an empirical functional diagnostic for this tiny profile, not a
	// certified centered-message or production correctness bound.
	maxEmpiricalFreshIntegralResidual := 0.0
	for wordIndex, word := range wordValues {
		block := make([]*bignum.Complex, len(ringZ.Roots()))
		for slot := range block {
			block[slot] = bignum.ToComplex(decoded[wordIndex*len(block)+slot], z2n.DefaultPrecision)
		}
		polynomial, err := ringZ.FromRootSlots(block)
		if err != nil {
			t.Fatal(err)
		}
		residue, err := ringZ.DecodeArithmetic(polynomial)
		if err != nil {
			t.Fatal(err)
		}
		if residue != word {
			t.Fatalf("word %d residue: got %#x, want %#x", wordIndex, residue, word)
		}
		canonical, err := ringZ.CanonicalizeArithmetic(polynomial)
		if err != nil {
			t.Fatal(err)
		}
		gotCoefficients := canonical.Coefficients()
		wantCoefficients := wantPolynomials[wordIndex].Coefficients()
		rawCoefficients := polynomial.Coefficients()
		for coefficient := range gotCoefficients {
			gotFloat, _ := gotCoefficients[coefficient].Float64()
			wantFloat, _ := wantCoefficients[coefficient].Float64()
			if difference := math.Abs(gotFloat - wantFloat); difference > 2e-5 {
				t.Fatalf(
					"word %d coefficient %d after canonicalization: got %.12g, want %.12g, error %.3g",
					wordIndex, coefficient, gotFloat, wantFloat, difference,
				)
			}
			rawFloat, _ := rawCoefficients[coefficient].Float64()
			maxEmpiricalFreshIntegralResidual = math.Max(maxEmpiricalFreshIntegralResidual, math.Abs(math.Round(rawFloat-gotFloat)))
		}
		canonicalSlots, err := ringZ.ToRootSlots(canonical)
		if err != nil {
			t.Fatal(err)
		}
		for slot := range canonicalSlots {
			assertApproxComplex(
				t, canonicalSlots[slot].Complex128(),
				wantSlots[wordIndex*len(canonicalSlots)+slot].Complex128(), 2e-4,
			)
		}
	}
	if maxInputOverflow < 60 {
		t.Fatalf("test did not inject a high nonzero integer overflow: max %.1f", maxInputOverflow)
	}
	if maxEmpiricalFreshIntegralResidual > 8 {
		t.Fatalf(
			"A2A-I empirical FUNCTIONAL-NOT-SECURE fresh-I diagnostic %.1f exceeds observed threshold 8 (input %.1f); threshold is not a proof bound",
			maxEmpiricalFreshIntegralResidual, maxInputOverflow,
		)
	}

	// One-hot sentinel: only one word block carries a residue and adversarial
	// integral representative. Empty blocks are checked in raw coefficient
	// space, before canonicalization could hide integral cross-talk.
	const sentinelBlock = 2
	sentinelWords := []uint64{0, 0, 0x5a, 0}
	sentinelOverflow := []int64{63, -63, 61, -61, 59, -59, 57, -57}
	sentinelSlots := make([]*bignum.Complex, 0, params.MaxSlots())
	for block, word := range sentinelWords {
		polynomial := ringZ.ArithmeticEncode(word)
		if block == sentinelBlock {
			integerOverflow, err := ringZ.NewPolynomial(a2aiIntegerCoefficients(sentinelOverflow))
			if err != nil {
				t.Fatal(err)
			}
			polynomial, err = ringZ.Add(polynomial, integerOverflow)
			if err != nil {
				t.Fatal(err)
			}
		}
		blockSlots, err := ringZ.ToRootSlots(polynomial)
		if err != nil {
			t.Fatal(err)
		}
		sentinelSlots = append(sentinelSlots, blockSlots...)
	}
	sentinelPlaintext := ckks.NewPlaintext(params, params.MaxLevel())
	sentinelPlaintext.LogDimensions = profile.VCompile().LogDimensions()
	if err := encoder.Encode(sentinelSlots, sentinelPlaintext); err != nil {
		t.Fatal(err)
	}
	sentinelCiphertext, err := ckks.NewEncryptor(params, secretKey).EncryptNew(sentinelPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	sentinelAdmission := functionalA2AIAdmission(t, sentinelCiphertext.Scale, big.NewInt(64))
	sentinelOutput, sentinelTrace, err := a2ai.A2AIHighNew(sentinelCiphertext, sentinelAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sentinelTrace.KeyProfile.Digest, trace.KeyProfile.Digest; got != want {
		t.Fatalf("sentinel key-profile digest: got %q, want %q", got, want)
	}
	sentinelDecoded := make([]complex128, params.MaxSlots())
	if err := encoder.Decode(ckks.NewDecryptor(params, secretKey).DecryptNew(sentinelOutput), sentinelDecoded); err != nil {
		t.Fatal(err)
	}
	// Derive the zero baseline from the same encryption by subtracting the
	// encoded sentinel plaintext. This retains identical encryption noise, so
	// differences in empty blocks cannot be attributed to independent fresh-I
	// randomness from a second encryption.
	zeroCiphertext, err := bootstrapEvaluator.Evaluator.SubNew(sentinelCiphertext, sentinelPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	zeroAdmission := functionalA2AIAdmission(t, zeroCiphertext.Scale, big.NewInt(64))
	zeroOutput, _, err := a2ai.A2AIHighNew(zeroCiphertext, zeroAdmission)
	if err != nil {
		t.Fatal(err)
	}
	zeroDecoded := make([]complex128, params.MaxSlots())
	if err := encoder.Decode(ckks.NewDecryptor(params, secretKey).DecryptNew(zeroOutput), zeroDecoded); err != nil {
		t.Fatal(err)
	}
	for block, word := range sentinelWords {
		rootBlock := make([]*bignum.Complex, len(ringZ.Roots()))
		zeroComparisonBlock := make([]*bignum.Complex, len(ringZ.Roots()))
		for slot := range rootBlock {
			rootBlock[slot] = bignum.ToComplex(sentinelDecoded[block*len(rootBlock)+slot], z2n.DefaultPrecision)
			zeroComparisonBlock[slot] = bignum.ToComplex(zeroDecoded[block*len(rootBlock)+slot], z2n.DefaultPrecision)
		}
		polynomial, err := ringZ.FromRootSlots(rootBlock)
		if err != nil {
			t.Fatal(err)
		}
		residue, err := ringZ.DecodeArithmetic(polynomial)
		if err != nil || residue != word {
			t.Fatalf("sentinel block %d residue: got %#x, want %#x, err=%v", block, residue, word, err)
		}
		if block != sentinelBlock {
			zeroPolynomial, err := ringZ.FromRootSlots(zeroComparisonBlock)
			if err != nil {
				t.Fatal(err)
			}
			for coefficient, value := range polynomial.Coefficients() {
				raw, _ := value.Float64()
				zeroRaw, _ := zeroPolynomial.Coefficients()[coefficient].Float64()
				if math.Abs(raw-zeroRaw) > 5e-4 {
					t.Fatalf("raw one-hot cross-talk into block %d coefficient %d: sentinel %.6g baseline %.6g", block, coefficient, raw, zeroRaw)
				}
			}
		}
	}
}

func TestA2AIHighRejectsUnsafeScaleContracts(t *testing.T) {
	params := a2aiFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	rawDFT, err := homchain.NewRawFullSlotDFT(params, encoder, homchain.RawFullSlotDFTConfig{
		SlotsToCoeffsLevelQ: params.MaxLevel() - params.LevelsConsumedPerRescaling(),
		SlotsToCoeffsLevels: []int{1, 1},
		CoeffsToSlotsLevelQ: params.MaxLevel(),
		CoeffsToSlotsLevels: []int{1, 1, 1},
		LevelP:              params.MaxLevelP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := homchain.NewA2AIHighCircuit(params, encoder, rawDFT, homchain.A2AIHighOptions{
		MaxAbsLog2ScaleDownError: 1e-6,
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		logScale        int
		logMessageRatio int
	}{
		{name: "non-unit-message-ratio", logScale: params.LogDefaultScale(), logMessageRatio: 1},
		{name: "mod-up-scale-relabel", logScale: 51, logMessageRatio: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bootstrapEvaluator := a2aiBootstrapEvaluator(t, params, rawDFT, test.logScale, test.logMessageRatio)
			if _, err := circuit.BindEvaluator(bootstrapEvaluator); err == nil {
				t.Fatal("BindEvaluator accepted an unsafe scale contract")
			}
		})
	}
	t.Run("sparse-switching-keys", func(t *testing.T) {
		bootstrapEvaluator := a2aiBootstrapEvaluator(t, params, rawDFT, params.LogDefaultScale(), 0)
		bootstrapEvaluator.EvkDenseToSparse = &rlwe.EvaluationKey{}
		if _, err := circuit.BindEvaluator(bootstrapEvaluator); err == nil {
			t.Fatal("BindEvaluator accepted sparse switching keys under the dense/no-switch adaptation")
		}
	})
	t.Run("residual-parameter-mismatch", func(t *testing.T) {
		bootstrapEvaluator := a2aiBootstrapEvaluator(t, params, rawDFT, params.LogDefaultScale(), 0)
		mismatched, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            5,
			LogQ:            []int{50, 35, 35, 35, 35, 35, 35, 35, 35},
			LogP:            []int{50},
			LogDefaultScale: 34,
		})
		if err != nil {
			t.Fatal(err)
		}
		bootstrapEvaluator.ResidualParameters = mismatched
		if _, err = circuit.BindEvaluator(bootstrapEvaluator); err == nil {
			t.Fatal("BindEvaluator accepted mismatched residual parameters")
		}
	})
}

func TestA2AIHighEvaluatorGraphReplacementFailsBeforeCiphertextMutation(t *testing.T) {
	params := a2aiFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	rawDFT, err := homchain.NewRawFullSlotDFT(params, encoder, homchain.RawFullSlotDFTConfig{
		SlotsToCoeffsLevelQ: params.MaxLevel() - params.LevelsConsumedPerRescaling(),
		SlotsToCoeffsLevels: []int{1, 1},
		CoeffsToSlotsLevelQ: params.MaxLevel(),
		CoeffsToSlotsLevels: []int{1, 1, 1},
		LevelP:              params.MaxLevelP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := homchain.NewA2AIHighCircuit(params, encoder, rawDFT, homchain.A2AIHighOptions{
		MaxAbsLog2ScaleDownError: 1e-6,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.RequiredKeyProfile()
	alternateKeyGenerator := ckks.NewKeyGenerator(params)
	alternateSecret := alternateKeyGenerator.GenSecretKeyNew()
	alternateKeys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
		alternateKeyGenerator.GenRelinearizationKeyNew(alternateSecret),
		alternateKeyGenerator.GenGaloisKeysNew(profile.All, alternateSecret)...,
	)}
	alternateMain := ckks.NewEvaluator(params, alternateKeys)
	alternateDFT := ckksdft.NewEvaluator(params, alternateMain)

	malformed := a2aiBootstrapEvaluator(t, params, rawDFT, params.LogDefaultScale(), 0)
	malformed.DFTEvaluator = alternateDFT
	if _, err = circuit.BindEvaluator(malformed); err == nil {
		t.Fatal("BindEvaluator accepted a DFT evaluator backed by a different main evaluator/key set")
	}

	source := a2aiBootstrapEvaluator(t, params, rawDFT, params.LogDefaultScale(), 0)
	bound, err := circuit.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	input := ckks.NewCiphertext(params, 1, params.MaxLevel())
	input.LogDimensions = circuit.Profile().VCompile().LogDimensions()
	input.Scale = params.DefaultScale()
	inputBefore := input.CopyNew()
	admission := functionalA2AIAdmission(t, input.Scale, big.NewInt(64))
	assertGraphFailure := func(name string) {
		t.Helper()
		_, trace, err := bound.A2AIHighNew(input, admission)
		if err == nil {
			t.Fatalf("%s replacement passed evaluator-graph preflight", name)
		}
		if trace.FailureStage != homchain.A2AIStageKeyPreflight || !trace.KeyPreflight.Checked ||
			!trace.KeyPreflight.EvaluatorGraphChecked || trace.KeyPreflight.EvaluatorGraphMatched ||
			trace.KeyPreflight.EvaluatorGraphMismatch == "" {
			t.Fatalf("%s replacement lacks typed graph-preflight evidence: trace=%+v err=%v", name, trace, err)
		}
		if trace.AfterZToC.Status != homchain.A2AINotReached {
			t.Fatalf("%s replacement reached Z-To-C before failing: %+v", name, trace.AfterZToC)
		}
		if !input.Equal(inputBefore) {
			t.Fatalf("%s replacement mutated input before failing", name)
		}
	}

	originalDFT := source.DFTEvaluator
	source.DFTEvaluator = alternateDFT
	assertGraphFailure("DFT evaluator")
	source.DFTEvaluator = originalDFT

	originalMain := source.Evaluator
	source.Evaluator = alternateMain
	assertGraphFailure("main evaluator")
	source.Evaluator = originalMain

	originalKeySet := source.Evaluator.EvaluationKeySet
	source.Evaluator.EvaluationKeySet = alternateKeys
	assertGraphFailure("main evaluator key set")
	source.Evaluator.EvaluationKeySet = originalKeySet

	originalEvaluationKeys := source.EvaluationKeys
	source.EvaluationKeys = alternateKeys
	assertGraphFailure("bootstrap evaluation-key object")
	source.EvaluationKeys = originalEvaluationKeys
}

func TestA2AIHighRejectsNonUnitDFTFactorization(t *testing.T) {
	params := a2aiFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	cases := []struct {
		name string
		stc  []int
		cts  []int
	}{
		{name: "Slots-To-Coeffs", stc: []int{2}, cts: []int{1, 1, 1}},
		{name: "Coeffs-To-Slots", stc: []int{1, 1}, cts: []int{1, 2}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rawDFT, err := homchain.NewRawFullSlotDFT(params, encoder, homchain.RawFullSlotDFTConfig{
				SlotsToCoeffsLevelQ: params.MaxLevel() - params.LevelsConsumedPerRescaling(),
				SlotsToCoeffsLevels: testCase.stc,
				CoeffsToSlotsLevelQ: params.MaxLevel(),
				CoeffsToSlotsLevels: testCase.cts,
				LevelP:              params.MaxLevelP(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = homchain.NewA2AIHighCircuit(params, encoder, rawDFT, homchain.A2AIHighOptions{
				MaxAbsLog2ScaleDownError: 1e-6,
			}); err == nil {
				t.Fatalf("expected A2A-I to reject %s non-unit Levels", testCase.name)
			}
		})
	}
}

func TestA2AIHighRejectsZeroAndMismatchedAdmissionWithTypedFailureStage(t *testing.T) {
	params := a2aiFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	rawDFT, err := homchain.NewRawFullSlotDFT(params, encoder, homchain.RawFullSlotDFTConfig{
		SlotsToCoeffsLevelQ: params.MaxLevel() - params.LevelsConsumedPerRescaling(),
		SlotsToCoeffsLevels: []int{1, 1},
		CoeffsToSlotsLevelQ: params.MaxLevel(),
		CoeffsToSlotsLevels: []int{1, 1, 1},
		LevelP:              params.MaxLevelP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := homchain.NewA2AIHighCircuit(params, encoder, rawDFT, homchain.A2AIHighOptions{
		MaxAbsLog2ScaleDownError: 1e-6,
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapEvaluator := a2aiBootstrapEvaluator(
		t, params, rawDFT, params.LogDefaultScale(), 0,
	)
	a2ai, err := circuit.BindEvaluator(bootstrapEvaluator)
	if err != nil {
		t.Fatal(err)
	}

	zeroCertificate := homchain.A2AIAdmissionCertificate{}
	_, trace, err := a2ai.A2AIHighNew(nil, zeroCertificate)
	if err == nil {
		t.Fatal("expected zero A2A-I admission certificate to be rejected")
	}
	if got, want := trace.FailureStage, homchain.A2AIStageAdmission; got != want {
		t.Fatalf("failure stage: got %q, want %q", got, want)
	}
	if got, want := trace.Input.Status, homchain.A2AINotReached; got != want {
		t.Fatalf("input stage status: got %v, want %v", got, want)
	}

	if _, zeroTrace, err := a2ai.A2AIHighNew(nil, zeroCertificate); err == nil || zeroTrace.FailureStage != homchain.A2AIStageAdmission {
		t.Fatalf("zero-value admission was not rejected with a typed admission failure: trace=%+v err=%v", zeroTrace, err)
	}
	input := ckks.NewCiphertext(params, 1, params.MaxLevel())
	input.Scale = params.DefaultScale()
	wrongDelta := input.Scale.Mul(rlwe.NewScale(2))
	mismatchedAdmission := functionalA2AIAdmission(t, wrongDelta, big.NewInt(64))
	if _, mismatchTrace, err := a2ai.A2AIHighNew(input, mismatchedAdmission); err == nil || mismatchTrace.FailureStage != homchain.A2AIStageAdmission {
		t.Fatalf("mismatched Delta was not rejected with a typed admission failure: trace=%+v err=%v", mismatchTrace, err)
	}
}

func TestA2AIHighKeyPreflightRejectsMissingTransformKeysBeforeEvaluation(t *testing.T) {
	params := a2aiFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	rawDFT, err := homchain.NewRawFullSlotDFT(params, encoder, homchain.RawFullSlotDFTConfig{
		SlotsToCoeffsLevelQ: params.MaxLevel() - params.LevelsConsumedPerRescaling(),
		SlotsToCoeffsLevels: []int{1, 1},
		CoeffsToSlotsLevelQ: params.MaxLevel(),
		CoeffsToSlotsLevels: []int{1, 1, 1},
		LevelP:              params.MaxLevelP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := homchain.NewA2AIHighCircuit(params, encoder, rawDFT, homchain.A2AIHighOptions{
		MaxAbsLog2ScaleDownError: 1e-6,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.RequiredKeyProfile()
	if len(profile.All) == 0 {
		t.Fatal("test profile has no Galois keys to omit")
	}
	missingElement := profile.All[len(profile.All)/2]
	btpParams := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: rawDFT.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: rawDFT.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: rawDFT.CoeffsToSlotsOutputLevel(), LogScale: params.LogDefaultScale(),
			Mod1Type: mod1.SinContinuous, LogMessageRatio: 0, K: 1, Mod1Degree: 3,
		},
		CircuitOrder: bootstrapping.Custom,
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	bootstrapEvaluator, err := bootstrapping.NewEvaluator(btpParams, &bootstrapping.EvaluationKeys{
		MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
			keyGenerator.GenRelinearizationKeyNew(secretKey),
			keyGenerator.GenGaloisKeysNew(profile.All, secretKey)...,
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	a2ai, err := circuit.BindEvaluator(bootstrapEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	input := ckks.NewCiphertext(params, 1, params.MaxLevel())
	input.LogDimensions = circuit.Profile().VCompile().LogDimensions()
	input.Scale = params.DefaultScale()
	admission := functionalA2AIAdmission(t, input.Scale, big.NewInt(64))
	savedKey := bootstrapEvaluator.MemEvaluationKeySet.GaloisKeys[missingElement]
	bootstrapEvaluator.MemEvaluationKeySet.GaloisKeys[missingElement] = nil
	_, nilKeyTrace, err := a2ai.A2AIHighNew(input, admission)
	if err == nil || nilKeyTrace.FailureStage != homchain.A2AIStageKeyPreflight ||
		!reflect.DeepEqual(nilKeyTrace.KeyPreflight.MissingGaloisElements, []uint64{missingElement}) {
		t.Fatalf("nil Galois key did not fail closed: trace=%+v err=%v", nilKeyTrace, err)
	}
	bootstrapEvaluator.MemEvaluationKeySet.GaloisKeys[missingElement] = savedKey

	delete(bootstrapEvaluator.MemEvaluationKeySet.GaloisKeys, missingElement)
	_, trace, err := a2ai.A2AIHighNew(input, admission)
	if err == nil {
		t.Fatal("expected key preflight to reject missing V/U keys")
	}
	if got, want := trace.FailureStage, homchain.A2AIStageKeyPreflight; got != want {
		t.Fatalf("failure stage: got %q, want %q", got, want)
	}
	if !trace.KeyPreflight.Checked || len(trace.KeyPreflight.MissingGaloisElements) == 0 {
		t.Fatalf("missing key evidence was not recorded: %+v", trace.KeyPreflight)
	}
	if !reflect.DeepEqual(trace.KeyPreflight.MissingGaloisElements, []uint64{missingElement}) {
		t.Fatalf("missing key evidence: got %v, want [%d]", trace.KeyPreflight.MissingGaloisElements, missingElement)
	}
	if trace.AfterZToC.Status != homchain.A2AINotReached {
		t.Fatalf("Z-To-C ran before key preflight failure: status=%v", trace.AfterZToC.Status)
	}
}

func a2aiBootstrapEvaluator(
	t *testing.T,
	params ckks.Parameters,
	rawDFT homchain.RawFullSlotDFT,
	logScale, logMessageRatio int,
) *bootstrapping.Evaluator {
	t.Helper()
	btpParams := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: rawDFT.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: rawDFT.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: rawDFT.CoeffsToSlotsOutputLevel(), LogScale: logScale,
			Mod1Type: mod1.SinContinuous, LogMessageRatio: logMessageRatio, K: 1, Mod1Degree: 3,
		},
		CircuitOrder: bootstrapping.Custom,
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisElements := uniqueUint64(append(
		btpParams.GaloisElements(params), params.GaloisElementForComplexConjugation(),
	))
	bootstrapEvaluator, err := bootstrapping.NewEvaluator(btpParams, &bootstrapping.EvaluationKeys{
		MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
			keyGenerator.GenRelinearizationKeyNew(secretKey),
			keyGenerator.GenGaloisKeysNew(galoisElements, secretKey)...,
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	return bootstrapEvaluator
}

func a2aiFunctionalParameters(t *testing.T) ckks.Parameters {
	t.Helper()
	// FUNCTIONAL-NOT-SECURE: LogN=5 is intentionally tiny. It makes four
	// n=8 words exactly fill all 16 CKKS slots and tests wiring, not security.
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            5,
		LogQ:            []int{50, 35, 35, 35, 35, 35, 35, 35, 35},
		LogP:            []int{50},
		LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func functionalA2AIAdmission(t *testing.T, delta rlwe.Scale, centeredBound *big.Int) homchain.A2AIAdmissionCertificate {
	t.Helper()
	artifact := "inline-functional-not-secure:a2ai-centered-bound-after-slots-to-coeffs"
	digest := sha256.Sum256([]byte(artifact))
	certificate, err := homchain.NewA2AIAdmissionCertificate(homchain.A2AIAdmissionRequest{
		Delta:                delta,
		DeltaSemantics:       homchain.A2AIDeltaGaoArithmeticInput,
		CenteredMessageBound: centeredBound,
		CenteredBoundUnit:    homchain.A2AICenteredCoefficientInfinityNorm,
		CenteredBoundDomain:  homchain.A2AIBoundBeforeGuardedScaleDown,
		EvidenceArtifact:     artifact,
		EvidenceDigest:       hex.EncodeToString(digest[:]),
		VerificationStatus:   homchain.A2AIEvidenceExternalUnverified,
		MaturityStatus:       homchain.A2AIEvidenceFunctionalNotSecure,
	})
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func scaleFromSnapshot(t *testing.T, snapshot homchain.ExactScaleSnapshot) rlwe.Scale {
	t.Helper()
	scale, err := snapshot.Scale()
	if err != nil {
		t.Fatal(err)
	}
	return scale
}

func a2aiIntegerCoefficients(values []int64) []*big.Float {
	result := make([]*big.Float, len(values))
	for i, value := range values {
		result[i] = new(big.Float).SetPrec(z2n.DefaultPrecision).SetInt64(value)
	}
	return result
}

func uniqueUint64(values []uint64) []uint64 {
	seen := make(map[uint64]struct{}, len(values))
	result := make([]uint64, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
