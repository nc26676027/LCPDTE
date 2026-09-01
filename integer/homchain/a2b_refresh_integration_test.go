package homchain_test

import (
	"fmt"
	"math"
	"math/big"
	"math/cmplx"
	"reflect"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	ckksdft "github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const a2bRefreshTestPrecision uint = 192

func TestA2BRefreshCircuitProfileContract(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	circuit, err := homchain.NewA2BRefreshCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}

	profile := circuit.Profile()
	if got, want := profile.Fidelity(), homchain.A2BRefreshFunctionalLattigoAdaptationNotSecure; got != want {
		t.Fatalf("fidelity: got %q, want %q", got, want)
	}
	if got, want := profile.WordBits(), z2n.Word8; got != want {
		t.Fatalf("word bits: got %d, want %d", got, want)
	}
	if got, want := profile.ChunkWidth(), uint(4); got != want {
		t.Fatalf("chunk width: got %d, want %d", got, want)
	}
	if got, want := profile.Words(), 4; got != want {
		t.Fatalf("words: got %d, want %d", got, want)
	}
	if got, want := profile.Slots(), 16; got != want {
		t.Fatalf("slots: got %d, want %d", got, want)
	}
	if got, want := profile.InputLevel(), 20; got != want {
		t.Fatalf("input level: got %d, want %d", got, want)
	}
	if got, want := profile.Schedule(), homchain.A2BRefreshFirstIterationParallelHalfBackbones; got != want {
		t.Fatalf("schedule: got %q, want %q", got, want)
	}
	if got, want := profile.TransformNames(), []homchain.TransformName{homchain.V0SpecialB0, homchain.V1Normal}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transform family: got %v, want %v", got, want)
	}
	transform := profile.Transform()
	if transform.LowName() != homchain.V0SpecialB0 || transform.HighName() != homchain.V1Normal ||
		transform.LevelQ() != 20 || transform.LevelP() != 0 || !transform.Scale().EqualScale(rlwe.NewScale(params.Q()[20])) {
		t.Fatalf("special-b0 compile profile changed: low/high=%s/%s Q/P=%d/%d", transform.LowName(), transform.HighName(), transform.LevelQ(), transform.LevelP())
	}
	if got, want := profile.LogMessageRatio(), 15; got != want {
		t.Fatalf("refresh LogMessageRatio=%d, want %d", got, want)
	}
	if profile.MaskLevel() != 19 || profile.MaskOutputLevel() != 18 {
		t.Fatalf("mask is not a separately charged L19->L18 source operation: input/output=%d/%d", profile.MaskLevel(), profile.MaskOutputLevel())
	}
	if got, want := profile.EncoderPrecision(), a2bRefreshTestPrecision; got != want {
		t.Fatalf("encoder precision: got %d, want %d", got, want)
	}
	if profile.Digest() == "" || profile.TransformSourceDigest() == "" || profile.MaskSourceDigest() == "" || profile.ParametersDigest() == "" {
		t.Fatalf("incomplete profile provenance: %+v", profile)
	}
	if got, want := profile.Digest(), "d0f67dd6bcfec2bc07e7ef3ef8dff9c335cd5302b0fd0fb74873e72a4e6cfe04"; got != want {
		t.Fatalf("sealed A2B refresh profile digest=%s, want %s", got, want)
	}

	dft := profile.DFT()
	if got, want := dft.GeneratorPrecision(), a2bRefreshTestPrecision; got != want {
		t.Fatalf("DFT generator precision: got %d, want %d", got, want)
	}
	if got, want := dft.EncoderPrecision(), a2bRefreshTestPrecision; got != want {
		t.Fatalf("DFT encoder precision: got %d, want %d", got, want)
	}
	if dft.SlotsToCoeffsRawMatrixDigest() == "" || dft.CoeffsToSlotsRawMatrixDigest() == "" ||
		dft.SlotsToCoeffsExecutionMatrixDigest() == "" || dft.CoeffsToSlotsExecutionMatrixDigest() == "" || dft.Digest() == "" {
		t.Fatal("DFT numeric-payload provenance is incomplete")
	}
	if got, want := dft.SlotsToCoeffsRawMatrixDigest(), "6a9aa34b8e06528eb2da5f5e9825645fa169c58e6ce1838a5ff07410b00da334"; got != want {
		t.Fatalf("raw STC numeric-payload digest=%s, want %s", got, want)
	}
	if got, want := dft.CoeffsToSlotsRawMatrixDigest(), "b9c51a09bdcd940df8fe757d2265b1f471ab417dce2efa4aa48108b8d35c8e2c"; got != want {
		t.Fatalf("raw CTS numeric-payload digest=%s, want %s", got, want)
	}
	if got, want := dft.SlotsToCoeffsExecutionMatrixDigest(), "7acb7e6f84445a97ad8f685de64ef21a241635ea0945b66fb5da2d7a141cac0e"; got != want {
		t.Fatalf("STC numeric-payload digest=%s, want %s", got, want)
	}
	if got, want := dft.CoeffsToSlotsExecutionMatrixDigest(), "3bfb9b2d3cc55d05b70f5b178742dc1220070fa413a8a93ce37d2838e970a996"; got != want {
		t.Fatalf("CTS numeric-payload digest=%s, want %s", got, want)
	}
	if dft.SlotsToCoeffsMatrixDigest() != dft.SlotsToCoeffsExecutionMatrixDigest() ||
		dft.CoeffsToSlotsMatrixDigest() != dft.CoeffsToSlotsExecutionMatrixDigest() {
		t.Fatal("legacy matrix-digest accessors diverged from initialized execution payloads")
	}
	if got, want := dft.Digest(), "25de76d98458c68ac40a3369a780332b043c124403e29dc2241c31b558523277"; got != want {
		t.Fatalf("DFT profile digest=%s, want %s", got, want)
	}
	if profile.NormalizedInputCertified() {
		t.Fatal("stopped refresh promoted a non-deterministic Lattigo lift to certified u/16")
	}
	if got := profile.NormalizedVariable(); got != "exp46-y=(I+a)/16;a=selected-special-b0-raw" {
		t.Fatalf("normalized variable: got %q", got)
	}
	if !strings.Contains(profile.NormalizedInvariant(), "16*y-a-is-integral") ||
		!strings.Contains(profile.NormalizedInvariant(), "low-a-congruent-to--u/16-mod-Z") ||
		!strings.Contains(profile.NormalizedInvariant(), "cancels-integral-lifts") ||
		!strings.Contains(profile.NormalizedInvariant(), "CTS-L17-exact-S35-matches-Gao-kernel-ingress") ||
		strings.Contains(profile.NormalizedInputBlocker(), "scale-bridge-is-not-closed") {
		t.Fatalf("incomplete normalization boundary: invariant=%q blocker=%q", profile.NormalizedInvariant(), profile.NormalizedInputBlocker())
	}
	stc, cts := dft.SlotsToCoeffsLiteral(), dft.CoeffsToSlotsLiteral()
	if stc.Type != ckksdft.HomomorphicDecode || cts.Type != ckksdft.HomomorphicEncode ||
		stc.Format != ckksdft.SplitRealAndImag || cts.Format != ckksdft.SplitRealAndImag ||
		stc.LogSlots != 4 || cts.LogSlots != 4 || stc.LevelP != 0 || cts.LevelP != 0 ||
		stc.LogBSGSRatio != 0 || cts.LogBSGSRatio != 0 || stc.BitReversed || cts.BitReversed {
		t.Fatalf("unexpected raw DFT structure: STC=%+v CTS=%+v", stc, cts)
	}
	if !reflect.DeepEqual(stc.Levels, []int{1, 1}) || stc.LevelQ != 18 {
		t.Fatalf("STC literal: LevelQ=%d Levels=%v", stc.LevelQ, stc.Levels)
	}
	if !reflect.DeepEqual(cts.Levels, []int{1, 1, 1}) || cts.LevelQ != 20 {
		t.Fatalf("CTS literal: LevelQ=%d Levels=%v", cts.LevelQ, cts.Levels)
	}
	if stc.Scaling == nil || stc.Scaling.Cmp(new(big.Float).SetInt64(1)) != 0 {
		t.Fatalf("STC Scaling is not exactly one: %v", stc.Scaling)
	}
	if cts.Scaling == nil || cts.Scaling.Cmp(new(big.Float).SetMantExp(new(big.Float).SetInt64(1), -4)) != 0 {
		t.Fatalf("CTS Scaling is not exactly 1/16: %v", cts.Scaling)
	}
	if stc.Scaling.Prec() != a2bRefreshTestPrecision || cts.Scaling.Prec() != a2bRefreshTestPrecision {
		t.Fatalf("DFT literal precision STC/CTS=%d/%d, want %d", stc.Scaling.Prec(), cts.Scaling.Prec(), a2bRefreshTestPrecision)
	}
	executionSTC, executionCTS := dft.SlotsToCoeffsExecutionLiteral(), dft.CoeffsToSlotsExecutionLiteral()
	if !reflect.DeepEqual(executionSTC.Levels, stc.Levels) || !reflect.DeepEqual(executionCTS.Levels, cts.Levels) ||
		executionSTC.Scaling == nil || executionCTS.Scaling == nil ||
		executionSTC.Scaling.Prec() != a2bRefreshTestPrecision || executionCTS.Scaling.Prec() != a2bRefreshTestPrecision {
		t.Fatalf("incomplete initialized DFT literals: STC=%+v CTS=%+v", executionSTC, executionCTS)
	}
	wantExecutionSTC := new(big.Float).SetPrec(a2bRefreshTestPrecision).SetInt64(1 << 15)
	if executionSTC.Scaling.Cmp(wantExecutionSTC) != 0 {
		t.Fatalf("initialized STC Scaling=%s, want 2^15", executionSTC.Scaling.Text('x', -1))
	}
	mod1Parameters, err := mod1.NewParametersFromLiteral(params, mod1.ParametersLiteral{
		LevelQ: 17, LogScale: 35, Mod1Type: mod1.SinContinuous, LogMessageRatio: 15, K: 1, Mod1Degree: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	qDiv := mod1Parameters.ScalingFactor().Float64() / math.Exp2(math.Round(math.Log2(float64(params.Q()[0]))))
	wantExecutionCTS := new(big.Float).SetPrec(a2bRefreshTestPrecision).Set(cts.Scaling)
	wantExecutionCTS.Mul(wantExecutionCTS, new(big.Float).SetPrec(a2bRefreshTestPrecision).SetFloat64(qDiv/(mod1Parameters.K*mod1Parameters.QDiff)))
	if executionCTS.Scaling.Cmp(wantExecutionCTS) != 0 {
		t.Fatalf("initialized CTS Scaling=%s, want raw 1/16 times qDiv/(K*QDiff)=%s", executionCTS.Scaling.Text('x', -1), wantExecutionCTS.Text('x', -1))
	}
	stc.Levels[0] = 99
	cts.Scaling.SetInt64(1)
	executionSTC.Scaling.SetInt64(1)
	executionCTS.Levels[0] = 99
	if got := circuit.Profile().DFT().SlotsToCoeffsLiteral().Levels; !reflect.DeepEqual(got, []int{1, 1}) {
		t.Fatal("DFT literal levels alias caller-owned data")
	}
	if got := circuit.Profile().DFT().CoeffsToSlotsLiteral().Scaling; got.Cmp(new(big.Float).SetMantExp(new(big.Float).SetInt64(1), -4)) != 0 {
		t.Fatal("DFT literal scaling aliases caller-owned data")
	}
	if got := circuit.Profile().DFT().SlotsToCoeffsExecutionLiteral().Scaling; got.Cmp(wantExecutionSTC) != 0 {
		t.Fatal("initialized STC literal scaling aliases caller-owned data")
	}
	if got := circuit.Profile().DFT().CoeffsToSlotsExecutionLiteral().Levels; !reflect.DeepEqual(got, []int{1, 1, 1}) {
		t.Fatal("initialized CTS literal levels alias caller-owned data")
	}

	keys := circuit.RequiredKeyProfile()
	if !keys.RelinearizationRequired() || len(keys.All()) == 0 || keys.Digest() == "" {
		t.Fatal("key profile omits relinearization, Galois elements, or digest")
	}
	if len(keys.Trace()) != 0 || len(keys.Residual()) != 0 {
		t.Fatalf("fixed full-packed stopped slice has unexpected trace/residual keys: trace=%v residual=%v", keys.Trace(), keys.Residual())
	}
	if got := keys.Conjugation(); len(got) != 1 || got[0] != params.GaloisElementForComplexConjugation() {
		t.Fatalf("conjugation key component=%v", got)
	}
	wantUnion := map[uint64]bool{}
	for _, component := range [][]uint64{keys.SpecialB0(), keys.SlotsToCoeffs(), keys.Trace(), keys.CoeffsToSlots(), keys.Conjugation(), keys.Residual()} {
		for _, element := range component {
			wantUnion[element] = true
		}
	}
	if len(keys.All()) != len(wantUnion) {
		t.Fatalf("key union has %d elements, component union has %d", len(keys.All()), len(wantUnion))
	}
	for _, element := range keys.All() {
		if !wantUnion[element] {
			t.Fatalf("key union contains unclassified element %d", element)
		}
	}
	first := keys.All()
	first[0] ^= 1
	if reflect.DeepEqual(first, circuit.RequiredKeyProfile().All()) {
		t.Fatal("key profile aliases caller-owned slices")
	}
	names := profile.TransformNames()
	names[0] = homchain.V0Normal
	if circuit.Profile().TransformNames()[0] != homchain.V0SpecialB0 {
		t.Fatal("transform names alias caller-owned slices")
	}

	typeOfCircuit := reflect.TypeOf(*circuit)
	for i := 0; i < typeOfCircuit.NumField(); i++ {
		if typeOfCircuit.Field(i).IsExported() {
			t.Fatalf("A2BRefreshCircuit exposes field %q", typeOfCircuit.Field(i).Name)
		}
	}
}

func TestA2BRefreshRejectsWrongPrecisionParametersAndPublicGraphInjection(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	if _, err := homchain.NewA2BRefreshCircuit(params, nil); err == nil {
		t.Fatal("nil encoder was accepted")
	}
	for _, precision := range []uint{128, 256} {
		if _, err := homchain.NewA2BRefreshCircuit(params, ckks.NewEncoder(params, precision)); err == nil || !strings.Contains(err.Error(), "want 192") {
			t.Fatalf("encoder precision %d was accepted: %v", precision, err)
		}
	}
	shortLogQ := []int{50}
	for i := 0; i < 19; i++ {
		shortLogQ = append(shortLogQ, 35)
	}
	shortParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: shortLogQ, LogP: []int{50}, LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := homchain.NewA2BRefreshCircuit(shortParams, ckks.NewEncoder(shortParams, a2bRefreshTestPrecision)); err == nil {
		t.Fatal("lower-level serial-style parameter profile was accepted by the fixed first-iteration constructor")
	}
	canonicalQ := params.Q()
	canonicalP := params.P()
	reorderedQ := append([]uint64(nil), canonicalQ...)
	reorderedQ[1], reorderedQ[2] = reorderedQ[2], reorderedQ[1]
	reorderedParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, Q: reorderedQ, P: append([]uint64(nil), canonicalP...), LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = homchain.NewA2BRefreshCircuit(reorderedParams, ckks.NewEncoder(reorderedParams, a2bRefreshTestPrecision)); err == nil {
		t.Fatal("same-bit reordered Q chain was accepted in place of the canonical Gao parameters")
	}
	canonicalModuli := make(map[uint64]bool, len(canonicalQ)+len(canonicalP))
	for _, modulus := range append(append([]uint64(nil), canonicalQ...), canonicalP...) {
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
	alternateQ := append([]uint64(nil), canonicalQ...)
	alternateQ[1] = alternatePrime
	alternateParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, Q: alternateQ, P: append([]uint64(nil), canonicalP...), LogDefaultScale: 35,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = homchain.NewA2BRefreshCircuit(alternateParams, ckks.NewEncoder(alternateParams, a2bRefreshTestPrecision)); err == nil {
		t.Fatal("same-bit alternate Q prime was accepted in place of the canonical Gao parameters")
	}

	circuit, err := homchain.NewA2BRefreshCircuit(params, ckks.NewEncoder(params, a2bRefreshTestPrecision))
	if err != nil {
		t.Fatal(err)
	}
	gotFields := make([]string, 0)
	typeOfCircuit := reflect.TypeOf(*circuit)
	for i := 0; i < typeOfCircuit.NumField(); i++ {
		field := typeOfCircuit.Field(i)
		gotFields = append(gotFields, field.Name)
		if field.IsExported() {
			t.Fatalf("circuit exposes graph-injection field %q", field.Name)
		}
	}
	wantFields := []string{"params", "specialB0", "lowMask", "highMask", "stc", "cts", "profile", "keyProfile"}
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("sealed circuit graph fields=%v, want %v", gotFields, wantFields)
	}
	circuitMethods := make([]string, reflect.TypeOf(circuit).NumMethod())
	for i := range circuitMethods {
		circuitMethods[i] = reflect.TypeOf(circuit).Method(i).Name
	}
	if want := []string{"BindEvaluator", "Profile", "RequiredKeyProfile"}; !reflect.DeepEqual(circuitMethods, want) {
		t.Fatalf("public circuit seam=%v, want non-injectable seam %v", circuitMethods, want)
	}
	resultType := reflect.TypeOf(homchain.A2BRefreshResult{})
	for i := 0; i < resultType.NumField(); i++ {
		if resultType.Field(i).IsExported() {
			t.Fatalf("result exposes saved-core field %q", resultType.Field(i).Name)
		}
	}
}

func TestA2BRefreshBindRejectsSourceCTSScalingOne(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	circuit, err := homchain.NewA2BRefreshCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	source := a2bRefreshBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey)
	if source.CoeffsToSlotsParameters.Scaling == nil {
		t.Fatal("bootstrap constructor erased initialized CTS scaling")
	}
	// NewEvaluator folds the same initialization factor into the raw literal.
	// Multiplying its initialized 1/16 by 16 therefore models raw Scaling=1.
	wrongScaling := new(big.Float).SetPrec(source.CoeffsToSlotsParameters.Scaling.Prec()).Set(source.CoeffsToSlotsParameters.Scaling)
	wrongScaling.Mul(wrongScaling, new(big.Float).SetPrec(wrongScaling.Prec()).SetInt64(16))
	source.CoeffsToSlotsParameters.Scaling = wrongScaling
	if _, err := circuit.BindEvaluator(source); err == nil || !strings.Contains(err.Error(), "Scaling=1/1/16") {
		t.Fatalf("source CTS Scaling=1 substitution was accepted: %v", err)
	}
}

func TestA2BRefreshBindRejectsWrongMessageRatio(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	circuit, err := homchain.NewA2BRefreshCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	source := a2bRefreshBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey)
	source.Mod1Parameters.LogMessageRatio = 14
	if _, err = circuit.BindEvaluator(source); err == nil || !strings.Contains(err.Error(), "LogMessageRatio=15") {
		t.Fatalf("source LogMessageRatio=14 substitution was accepted: %v", err)
	}
}

func TestA2BRefreshBindRejectsRawPaperDFTAsExecutionMetadata(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	circuit, err := homchain.NewA2BRefreshCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	source := a2bRefreshBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey)
	dft := circuit.Profile().DFT()
	source.SlotsToCoeffsParameters = dft.SlotsToCoeffsLiteral()
	source.CoeffsToSlotsParameters = dft.CoeffsToSlotsLiteral()
	if _, err = circuit.BindEvaluator(source); err == nil || !strings.Contains(err.Error(), "MR15 initialization") {
		t.Fatalf("raw paper DFT literals were accepted as initialized execution metadata: %v", err)
	}
}

func TestA2BRefreshFirstIterationRunsTwoDistinctEncryptedBackbones(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	circuit, err := homchain.NewA2BRefreshCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	bootstrapEvaluator := a2bRefreshBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey)
	executionDFT := circuit.Profile().DFT()
	if bootstrapEvaluator.Mod1Parameters.LogMessageRatio != 15 ||
		bootstrapEvaluator.SlotsToCoeffsParameters.Scaling.Cmp(executionDFT.SlotsToCoeffsExecutionLiteral().Scaling) != 0 ||
		bootstrapEvaluator.CoeffsToSlotsParameters.Scaling.Cmp(executionDFT.CoeffsToSlotsExecutionLiteral().Scaling) != 0 {
		t.Fatal("bootstrap constructor metadata does not match the sealed MR15 initialized DFT literals")
	}
	evaluator, err := circuit.BindEvaluator(bootstrapEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorType := reflect.TypeOf(*evaluator)
	for i := 0; i < evaluatorType.NumField(); i++ {
		if evaluatorType.Field(i).IsExported() {
			t.Fatalf("bound evaluator exposes execution-graph field %q", evaluatorType.Field(i).Name)
		}
	}
	typ := reflect.TypeOf(evaluator)
	evaluatorMethods := make([]string, typ.NumMethod())
	for i := range evaluatorMethods {
		evaluatorMethods[i] = typ.Method(i).Name
	}
	if !reflect.DeepEqual(evaluatorMethods, []string{"EvaluateNew"}) {
		t.Fatalf("bound evaluator exposes a graph-injection seam: methods=%v", evaluatorMethods)
	}

	ringZ, err := z2n.NewWithPrecision(z2n.Word8, a2bRefreshTestPrecision)
	if err != nil {
		t.Fatal(err)
	}
	inputSlots := make([]*bignum.Complex, 0, params.MaxSlots())
	for word := 0; word < 4; word++ {
		block, err := ringZ.ToRootSlots(ringZ.ArithmeticEncode(0xa5))
		if err != nil {
			t.Fatal(err)
		}
		inputSlots = append(inputSlots, block...)
	}
	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	plaintext.LogDimensions = circuit.Profile().Transform().LogDimensions()
	if err = encoder.Encode(inputSlots, plaintext); err != nil {
		t.Fatal(err)
	}
	input, err := ckks.NewEncryptor(params, secretKey).EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	inputBefore := input.CopyNew()
	result, trace, err := evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if !input.Equal(inputBefore) {
		t.Fatal("A2B refresh mutated its arithmetic input")
	}
	if got, want := trace.Fidelity(), homchain.A2BRefreshFunctionalLattigoAdaptationNotSecure; got != want {
		t.Fatalf("trace fidelity: got %q, want %q", got, want)
	}
	if got, want := trace.Schedule(), homchain.A2BRefreshFirstIterationParallelHalfBackbones; got != want {
		t.Fatalf("trace schedule: got %q, want %q", got, want)
	}
	if got, want := trace.ProfileDigest(), circuit.Profile().Digest(); got != want {
		t.Fatalf("trace profile digest: got %q, want %q", got, want)
	}
	if !trace.KeyPreflight().Checked || !trace.KeyPreflight().GraphChecked || !trace.KeyPreflight().GraphMatched ||
		!trace.KeyPreflight().DenseNoSwitchingMatched || len(trace.KeyPreflight().MissingGaloisElements) != 0 ||
		len(trace.KeyPreflight().InvalidGaloisElements) != 0 || len(trace.KeyPreflight().UnexpectedGaloisElements) != 0 ||
		!trace.KeyPreflight().RelinearizationPresent ||
		!trace.KeyPreflight().RelinearizationMatched {
		t.Fatalf("key/graph preflight did not pass: %+v", trace.KeyPreflight())
	}
	wantTraceOrder := [][2]string{
		{string(homchain.A2BRefreshWholeInput), string(homchain.A2BRefreshStageInput)},
		{string(homchain.A2BRefreshLowHalf), string(homchain.A2BRefreshStageSpecialB0)},
		{string(homchain.A2BRefreshHighHalf), string(homchain.A2BRefreshStageSpecialB0)},
		{string(homchain.A2BRefreshLowHalf), string(homchain.A2BRefreshStageMaskRescale)},
		{string(homchain.A2BRefreshHighHalf), string(homchain.A2BRefreshStageMaskRescale)},
		{string(homchain.A2BRefreshLowHalf), string(homchain.A2BRefreshStageSlotsToCoeffs)},
		{string(homchain.A2BRefreshLowHalf), string(homchain.A2BRefreshStageScaleDown)},
		{string(homchain.A2BRefreshLowHalf), string(homchain.A2BRefreshStageModUpTrace)},
		{string(homchain.A2BRefreshLowHalf), string(homchain.A2BRefreshStageCoeffsToSlots)},
		{string(homchain.A2BRefreshHighHalf), string(homchain.A2BRefreshStageSlotsToCoeffs)},
		{string(homchain.A2BRefreshHighHalf), string(homchain.A2BRefreshStageScaleDown)},
		{string(homchain.A2BRefreshHighHalf), string(homchain.A2BRefreshStageModUpTrace)},
		{string(homchain.A2BRefreshHighHalf), string(homchain.A2BRefreshStageCoeffsToSlots)},
	}
	states := trace.States()
	if len(states) != len(wantTraceOrder) {
		t.Fatalf("trace length=%d, want %d", len(states), len(wantTraceOrder))
	}
	for i, state := range states {
		if got := [2]string{string(state.Half), string(state.Stage)}; got != wantTraceOrder[i] {
			t.Fatalf("trace[%d]=%v, want %v", i, got, wantTraceOrder[i])
		}
	}

	expectedLevels := map[homchain.A2BRefreshStage]int{
		homchain.A2BRefreshStageInput:         20,
		homchain.A2BRefreshStageSpecialB0:     19,
		homchain.A2BRefreshStageMaskRescale:   18,
		homchain.A2BRefreshStageSlotsToCoeffs: 16,
		homchain.A2BRefreshStageScaleDown:     0,
		homchain.A2BRefreshStageModUpTrace:    20,
		homchain.A2BRefreshStageCoeffsToSlots: 17,
	}
	inputState, ok := trace.State(homchain.A2BRefreshWholeInput, homchain.A2BRefreshStageInput)
	if !ok || inputState.Level != expectedLevels[homchain.A2BRefreshStageInput] {
		t.Fatalf("input trace state: ok=%t state=%+v", ok, inputState)
	}
	if !inputState.Scale.EqualScale(params.DefaultScale()) {
		t.Fatal("input trace does not preserve the exact default scale")
	}
	for _, half := range []homchain.A2BRefreshHalf{homchain.A2BRefreshLowHalf, homchain.A2BRefreshHighHalf} {
		for _, stage := range []homchain.A2BRefreshStage{
			homchain.A2BRefreshStageSpecialB0,
			homchain.A2BRefreshStageMaskRescale,
			homchain.A2BRefreshStageSlotsToCoeffs,
			homchain.A2BRefreshStageScaleDown,
			homchain.A2BRefreshStageModUpTrace,
			homchain.A2BRefreshStageCoeffsToSlots,
		} {
			state, ok := trace.State(half, stage)
			if !ok || state.Level != expectedLevels[stage] {
				t.Fatalf("%s/%s state: ok=%t got=%+v want level=%d", half, stage, ok, state, expectedLevels[stage])
			}
			if state.Invocation != half {
				t.Fatalf("%s/%s invocation identity: got %q", half, stage, state.Invocation)
			}
			if state.Scale.ValueHex() == "" || state.Scale.Precision() == 0 {
				t.Fatalf("%s/%s has an incomplete exact scale snapshot", half, stage)
			}
		}
		assertA2BRefreshScaleTrace(t, trace, half, params)
	}

	decrypt := ckks.NewDecryptor(params, secretKey)
	rawLow, rawHigh := a2bRefreshSpecialB0Block(t, ringZ, 0xa5)
	oracleLow := a2bRefreshLowOracleBlock(t, 0xa5)
	if !reflect.DeepEqual(rawLow, oracleLow) {
		t.Fatalf("A5 special-b0 low=%v, Boolean-prefix oracle=%v", rawLow, oracleLow)
	}
	if want := []float64{-0.5, -0.25, -0.625, -0.3125}; !reflect.DeepEqual(oracleLow, want) {
		t.Fatalf("A5 u/16 residue=%v, want %v", oracleLow, want)
	}
	freshHighPrefixOracle := a2bRefreshHalfOracleBlock(t, 0xa5, z2n.BooleanHighHalf)
	if reflect.DeepEqual(rawHigh, freshHighPrefixOracle) {
		t.Fatal("parallel untouched high core was misidentified as a freshly re-encoded high-prefix control")
	}
	if want := []float64{0, -0.5, -0.25, -0.625}; !reflect.DeepEqual(freshHighPrefixOracle, want) {
		t.Fatalf("A5 fresh high-prefix re-encode=%v, want %v; this is not the source serial residual", freshHighPrefixOracle, want)
	}
	assertRepeatedA2BRefreshBlock(t, encoder, decrypt, result.SpecialB0Low(), rawLow, 2e-4)
	assertRepeatedA2BRefreshBlock(t, encoder, decrypt, result.SpecialB0High(), rawHigh, 2e-4)
	assertRepeatedA2BRefreshBlock(t, encoder, decrypt, result.MaskedLow(), rawLow, 3e-4)
	assertRepeatedA2BRefreshBlock(t, encoder, decrypt, result.MaskedHigh(), rawHigh, 3e-4)
	lowDistance, lowAbsLift := assertA2BRefreshLatticeBlock(t, encoder, decrypt, result.RefreshedLow(), rawLow)
	highDistance, highAbsLift := assertA2BRefreshLatticeBlock(t, encoder, decrypt, result.RefreshedHigh(), rawHigh)
	if lowDistance > 2e-3 || highDistance > 2e-3 {
		t.Fatalf("A5 lift integer distance low/high=%.3g/%.3g", lowDistance, highDistance)
	}
	if lowAbsLift >= 16 || highAbsLift >= 16 {
		t.Fatalf("A5 observed |I| lacks the K=16 interval margin: low/high=%.3g/%.3g", lowAbsLift, highAbsLift)
	}

	lowFirst, lowSecond := result.RefreshedLow(), result.RefreshedLow()
	high := result.RefreshedHigh()
	if lowFirst == lowSecond || lowFirst == high {
		t.Fatal("result accessors shared ciphertext pointers")
	}
	lowFirst.Resize(lowFirst.Degree(), 0)
	if got := result.RefreshedLow().Level(); got != 17 {
		t.Fatalf("mutating a returned low copy changed saved result level to %d", got)
	}
	specialCopy := result.SpecialB0Low()
	specialCopy.Resize(specialCopy.Degree(), 0)
	maskedCopy := result.MaskedHigh()
	maskedCopy.Resize(maskedCopy.Degree(), 0)
	if result.SpecialB0Low().Level() != 19 || result.MaskedHigh().Level() != 18 {
		t.Fatal("mutating returned evidence changed a saved special-b0 or masked core")
	}
	if result.RefreshedLow().Equal(result.RefreshedHigh()) {
		t.Fatal("the low and high refresh invocations returned one shared ciphertext result")
	}

	serialIngress := input.CopyNew()
	serialIngress.Resize(serialIngress.Degree(), 3)
	serialBefore := serialIngress.CopyNew()
	if _, rejectedTrace, err := evaluator.EvaluateNew(serialIngress); err == nil || !strings.Contains(err.Error(), "want 20/1") {
		t.Fatalf("first-iteration matrices accepted a lower serial-iter1 ingress: trace=%+v err=%v", rejectedTrace, err)
	} else if len(rejectedTrace.States()) != 0 || !serialIngress.Equal(serialBefore) {
		t.Fatal("lower serial-iter1 ingress was operated on before fixed-level rejection")
	}
}

func TestA2BRefreshLowResidueMatchesBooleanOracleForAll256Words(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	circuit, err := homchain.NewA2BRefreshCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	bootstrapEvaluator := a2bRefreshBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey)
	evaluator, err := circuit.BindEvaluator(bootstrapEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, a2bRefreshTestPrecision)
	if err != nil {
		t.Fatal(err)
	}
	decryptor := ckks.NewDecryptor(params, secretKey)
	encryptor := ckks.NewEncryptor(params, secretKey)

	var maxIntegerDistance, maxAbsLift, maxRootError float64
	for batch := 0; batch < 64; batch++ {
		words := [4]uint64{
			uint64(4 * batch), uint64(4*batch + 1), uint64(4*batch + 2), uint64(4*batch + 3),
		}
		input := encryptA2BRefreshWords(t, circuit, params, ringZ, encoder, encryptor, words)
		inputBefore := input.CopyNew()
		result, trace, err := evaluator.EvaluateNew(input)
		if err != nil {
			t.Fatalf("batch %d words=%v: %v", batch, words, err)
		}
		if !input.Equal(inputBefore) {
			t.Fatalf("batch %d mutated its packed arithmetic input", batch)
		}
		if got := len(trace.States()); got != 13 {
			t.Fatalf("batch %d trace states=%d, want 13", batch, got)
		}

		specialLow := decodeA2BRefresh(t, encoder, decryptor, result.SpecialB0Low())
		specialHigh := decodeA2BRefresh(t, encoder, decryptor, result.SpecialB0High())
		maskedLow := decodeA2BRefresh(t, encoder, decryptor, result.MaskedLow())
		maskedHigh := decodeA2BRefresh(t, encoder, decryptor, result.MaskedHigh())
		refreshedLow := decodeA2BRefresh(t, encoder, decryptor, result.RefreshedLow())
		refreshedHigh := decodeA2BRefresh(t, encoder, decryptor, result.RefreshedHigh())

		for wordIndex, word := range words {
			rawLow, rawHigh := a2bRefreshSpecialB0Block(t, ringZ, word)
			oracleLow := a2bRefreshHalfOracleBlock(t, word, z2n.BooleanLowHalf)
			for slot := range rawLow {
				if distance := math.Abs(rawLow[slot] - oracleLow[slot] - math.Round(rawLow[slot]-oracleLow[slot])); distance > 1e-12 {
					t.Fatalf("word %#02x slot %d special-b0 raw=%g is not the Boolean residue %g modulo Z", word, slot, rawLow[slot], oracleLow[slot])
				}
			}
			start := 4 * wordIndex
			for slot := 0; slot < 4; slot++ {
				index := start + slot
				assertA2BRefreshValue(t, fmt.Sprintf("word %#02x special-low[%d]", word, slot), specialLow[index], rawLow[slot], 4e-4)
				assertA2BRefreshValue(t, fmt.Sprintf("word %#02x special-high[%d]", word, slot), specialHigh[index], rawHigh[slot], 4e-4)
				assertA2BRefreshValue(t, fmt.Sprintf("word %#02x masked-low[%d]", word, slot), maskedLow[index], rawLow[slot], 5e-4)
				assertA2BRefreshValue(t, fmt.Sprintf("word %#02x masked-high[%d]", word, slot), maskedHigh[index], rawHigh[slot], 5e-4)

				for _, sample := range []struct {
					name string
					got  complex128
					want float64
				}{
					{name: "low", got: refreshedLow[index], want: rawLow[slot]},
					{name: "high", got: refreshedHigh[index], want: rawHigh[slot]},
				} {
					distance, absLift, rootError := a2bRefreshLatticeMetrics(sample.got, sample.want)
					maxIntegerDistance = math.Max(maxIntegerDistance, distance)
					maxAbsLift = math.Max(maxAbsLift, absLift)
					maxRootError = math.Max(maxRootError, rootError)
					if math.Abs(imag(sample.got)) > 5e-4 || distance > 3e-3 || absLift >= 16 || rootError > 0.02 {
						t.Fatalf(
							"word %#02x %s[%d]: y=%v residue-a=%.12g integer-distance=%.3g |I|=%.3g root-error=%.3g",
							word, sample.name, slot, sample.got, sample.want, distance, absLift, rootError,
						)
					}
				}
			}
		}
	}
	if maxIntegerDistance > 3e-3 || maxAbsLift >= 16 || maxRootError > 0.02 {
		t.Fatalf("exhaustive lift margins failed: integer-distance=%.3g |I|=%.3g root-error=%.3g", maxIntegerDistance, maxAbsLift, maxRootError)
	}
}

func TestA2BRefreshEveryMissingKeyFailsClosedBeforeCiphertextOperation(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	encoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	circuit, err := homchain.NewA2BRefreshCircuit(params, encoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	source := a2bRefreshBootstrapEvaluator(t, circuit, params, keyGenerator, secretKey)
	keySet := source.MemEvaluationKeySet
	if keySet == nil {
		t.Fatal("bootstrap evaluator has no mutable key set for fail-closed test")
	}

	for _, element := range circuit.RequiredKeyProfile().All() {
		key := keySet.GaloisKeys[element]
		if key == nil {
			t.Fatalf("required Galois key %d was absent before the negative", element)
		}
		delete(keySet.GaloisKeys, element)
		if _, err := circuit.BindEvaluator(source); err == nil || !strings.Contains(err.Error(), "missing-galois") {
			t.Fatalf("BindEvaluator accepted missing Galois key %d: %v", element, err)
		}
		keySet.GaloisKeys[element] = key
	}
	relinearization := keySet.RelinearizationKey
	keySet.RelinearizationKey = nil
	if _, err := circuit.BindEvaluator(source); err == nil || !strings.Contains(err.Error(), "relin") {
		t.Fatalf("BindEvaluator accepted a missing relinearization key: %v", err)
	}
	keySet.RelinearizationKey = relinearization
	requiredSet := map[uint64]bool{}
	for _, element := range circuit.RequiredKeyProfile().All() {
		requiredSet[element] = true
	}
	var extraElement uint64
	for rotation := 1; rotation < params.MaxSlots(); rotation++ {
		candidate := params.GaloisElement(rotation)
		if !requiredSet[candidate] {
			extraElement = candidate
			break
		}
	}
	if extraElement == 0 {
		t.Fatal("could not find an unused valid Galois element for the exact-union negative")
	}
	extraKey := keyGenerator.GenGaloisKeysNew([]uint64{extraElement}, secretKey)[0]
	keySet.GaloisKeys[extraElement] = extraKey
	if _, err := circuit.BindEvaluator(source); err == nil || !strings.Contains(err.Error(), "unexpected-galois") {
		t.Fatalf("BindEvaluator accepted extra Galois key %d outside the exact union: %v", extraElement, err)
	}
	delete(keySet.GaloisKeys, extraElement)

	evaluator, err := circuit.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, a2bRefreshTestPrecision)
	if err != nil {
		t.Fatal(err)
	}
	input := encryptA2BRefreshWords(
		t, circuit, params, ringZ, encoder, ckks.NewEncryptor(params, secretKey),
		[4]uint64{0xa5, 0x5a, 0xff, 0},
	)
	for _, element := range circuit.RequiredKeyProfile().All() {
		key := keySet.GaloisKeys[element]
		delete(keySet.GaloisKeys, element)
		inputBefore := input.CopyNew()
		_, trace, err := evaluator.EvaluateNew(input)
		if err == nil || len(trace.KeyPreflight().MissingGaloisElements) != 1 || trace.KeyPreflight().MissingGaloisElements[0] != element {
			t.Fatalf("per-call preflight did not identify missing Galois key %d: trace=%+v err=%v", element, trace.KeyPreflight(), err)
		}
		if len(trace.States()) != 0 || !input.Equal(inputBefore) {
			t.Fatalf("missing Galois key %d reached a ciphertext stage or mutated the input", element)
		}
		keySet.GaloisKeys[element] = key
	}
	keySet.RelinearizationKey = nil
	inputBefore := input.CopyNew()
	_, trace, err := evaluator.EvaluateNew(input)
	if err == nil || trace.KeyPreflight().RelinearizationPresent || trace.KeyPreflight().RelinearizationMatched {
		t.Fatalf("per-call preflight accepted missing relinearization key: trace=%+v err=%v", trace.KeyPreflight(), err)
	}
	if len(trace.States()) != 0 || !input.Equal(inputBefore) {
		t.Fatal("missing relinearization key reached a ciphertext stage or mutated the input")
	}
	keySet.RelinearizationKey = relinearization
	keySet.GaloisKeys[extraElement] = extraKey
	inputBefore = input.CopyNew()
	_, trace, err = evaluator.EvaluateNew(input)
	if err == nil || len(trace.KeyPreflight().UnexpectedGaloisElements) != 1 || trace.KeyPreflight().UnexpectedGaloisElements[0] != extraElement {
		t.Fatalf("per-call preflight accepted extra Galois key %d: trace=%+v err=%v", extraElement, trace.KeyPreflight(), err)
	}
	if len(trace.States()) != 0 || !input.Equal(inputBefore) {
		t.Fatal("extra Galois key reached a ciphertext stage or mutated the input")
	}
	delete(keySet.GaloisKeys, extraElement)

	savedDFT := source.DFTEvaluator
	source.DFTEvaluator = nil
	inputBefore = input.CopyNew()
	_, trace, err = evaluator.EvaluateNew(input)
	if err == nil || trace.KeyPreflight().GraphMismatch == "" || !strings.Contains(err.Error(), "graph preflight") {
		t.Fatalf("per-call preflight accepted a replaced source execution graph: trace=%+v err=%v", trace.KeyPreflight(), err)
	}
	if len(trace.States()) != 0 || !input.Equal(inputBefore) {
		t.Fatal("source graph replacement reached a ciphertext stage or mutated the input")
	}
	source.DFTEvaluator = savedDFT
}

func a2bRefreshFunctionalParameters(t *testing.T) ckks.Parameters {
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

func a2bRefreshBootstrapEvaluator(
	t *testing.T,
	circuit *homchain.A2BRefreshCircuit,
	params ckks.Parameters,
	keyGenerator *rlwe.KeyGenerator,
	secretKey *rlwe.SecretKey,
) *bootstrapping.Evaluator {
	t.Helper()
	keyProfile := circuit.RequiredKeyProfile()
	galoisElements := keyProfile.All()
	dft := circuit.Profile().DFT()
	bootstrapParameters := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: dft.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: dft.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ:          dft.CoeffsToSlotsLiteral().LevelQ - 3,
			LogScale:        params.LogDefaultScale(),
			Mod1Type:        mod1.SinContinuous,
			LogMessageRatio: 15,
			K:               1,
			Mod1Degree:      3,
		},
		CircuitOrder: bootstrapping.Custom,
	}
	evaluationKeys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeysNew(galoisElements, secretKey)...,
	)}
	evaluator, err := bootstrapping.NewEvaluator(bootstrapParameters, evaluationKeys)
	if err != nil {
		t.Fatal(err)
	}
	return evaluator
}

func assertRepeatedA2BRefreshBlock(
	t *testing.T,
	encoder *ckks.Encoder,
	decryptor *rlwe.Decryptor,
	ciphertext *rlwe.Ciphertext,
	want []float64,
	tolerance float64,
) {
	t.Helper()
	if ciphertext == nil {
		t.Fatal("nil ciphertext evidence")
	}
	decoded := make([]complex128, ciphertext.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded)%len(want) != 0 {
		t.Fatalf("decoded slots=%d are not a multiple of block=%d", len(decoded), len(want))
	}
	for i, got := range decoded {
		if errorReal := math.Abs(real(got) - want[i%len(want)]); errorReal > tolerance {
			t.Fatalf("slot %d real: got %.12g, want %.12g, error %.3g > %.3g", i, real(got), want[i%len(want)], errorReal, tolerance)
		}
		if errorImag := math.Abs(imag(got)); errorImag > tolerance {
			t.Fatalf("slot %d imaginary: got %.12g, error %.3g > %.3g", i, imag(got), errorImag, tolerance)
		}
	}
}

func assertA2BRefreshScaleTrace(
	t *testing.T,
	trace homchain.A2BRefreshTrace,
	half homchain.A2BRefreshHalf,
	params ckks.Parameters,
) {
	t.Helper()
	state := func(stage homchain.A2BRefreshStage) homchain.A2BRefreshCiphertextState {
		result, ok := trace.State(half, stage)
		if !ok {
			t.Fatalf("missing %s/%s scale state", half, stage)
		}
		return result
	}
	special := state(homchain.A2BRefreshStageSpecialB0)
	masked := state(homchain.A2BRefreshStageMaskRescale)
	stc := state(homchain.A2BRefreshStageSlotsToCoeffs)
	scaledDown := state(homchain.A2BRefreshStageScaleDown)
	raised := state(homchain.A2BRefreshStageModUpTrace)
	cts := state(homchain.A2BRefreshStageCoeffsToSlots)
	if !special.Scale.Equal(masked.Scale) || !masked.Scale.Equal(stc.Scale) {
		t.Fatalf("%s pre-refresh scale chain changed: special=%s mask=%s STC=%s", half, special.Scale.ValueHex(), masked.Scale.ValueHex(), stc.Scale.ValueHex())
	}
	if !scaledDown.Scale.Equal(raised.Scale) || !raised.Scale.Equal(cts.Scale) {
		t.Fatalf("%s raw refresh scale chain changed: ScaleDown=%s ModUp=%s CTS=%s", half, scaledDown.Scale.ValueHex(), raised.Scale.ValueHex(), cts.Scale.ValueHex())
	}
	for _, item := range []struct {
		stage homchain.A2BRefreshStage
		scale homchain.ExactScaleSnapshot
	}{
		{homchain.A2BRefreshStageSpecialB0, special.Scale},
		{homchain.A2BRefreshStageMaskRescale, masked.Scale},
		{homchain.A2BRefreshStageSlotsToCoeffs, stc.Scale},
		{homchain.A2BRefreshStageScaleDown, scaledDown.Scale},
		{homchain.A2BRefreshStageModUpTrace, raised.Scale},
		{homchain.A2BRefreshStageCoeffsToSlots, cts.Scale},
	} {
		if !item.scale.EqualScale(params.DefaultScale()) {
			t.Fatalf("%s/%s scale=%s, want exact Gao kernel S35", half, item.stage, item.scale.ValueHex())
		}
	}
	errScale, errLog2, ok := trace.ScaleDownError(half)
	if !ok || math.IsNaN(errLog2) || math.IsInf(errLog2, 0) || math.Abs(errLog2) > 1e-6 {
		t.Fatalf("%s ScaleDown error witness: ok=%t log2=%g snapshot=%+v", half, ok, errLog2, errScale)
	}
	gotScale, err := scaledDown.Scale.Scale()
	if err != nil {
		t.Fatal(err)
	}
	wantErrScale, err := errScale.Scale()
	if err != nil {
		t.Fatal(err)
	}
	if got := gotScale.Div(rlwe.NewScale(params.Q()[0]).Div(rlwe.NewScale(math.Exp2(15)))); !got.Equal(wantErrScale) {
		t.Fatalf("%s ScaleDown scale is not exactly (q0/2^15)*errScale", half)
	}
}

func assertA2BRefreshLatticeBlock(
	t *testing.T,
	encoder *ckks.Encoder,
	decryptor *rlwe.Decryptor,
	ciphertext *rlwe.Ciphertext,
	wantResidue []float64,
) (maxIntegerDistance, maxAbsLift float64) {
	t.Helper()
	decoded := decodeA2BRefresh(t, encoder, decryptor, ciphertext)
	if len(decoded)%len(wantResidue) != 0 {
		t.Fatalf("decoded slots=%d are not a multiple of residue block=%d", len(decoded), len(wantResidue))
	}
	for index, got := range decoded {
		want := wantResidue[index%len(wantResidue)]
		distance, absLift, rootError := a2bRefreshLatticeMetrics(got, want)
		maxIntegerDistance = math.Max(maxIntegerDistance, distance)
		maxAbsLift = math.Max(maxAbsLift, absLift)
		if math.Abs(imag(got)) > 5e-4 || distance > 2e-3 || absLift >= 16 || rootError > 0.015 {
			t.Fatalf(
				"slot %d: normalized y=%v residue-a=%.12g integer-distance=%.3g |I|=%.3g root-error=%.3g",
				index, got, want, distance, absLift, rootError,
			)
		}
	}
	return
}

func a2bRefreshLatticeMetrics(got complex128, wantResidue float64) (integerDistance, absLift, rootError float64) {
	lift := math.Round(16*real(got) - wantResidue)
	integerDistance = math.Abs(16*real(got) - wantResidue - lift)
	absLift = math.Abs(lift)
	gotRoot := cmplx.Exp(complex(0, 32*math.Pi) * got)
	wantRoot := cmplx.Exp(complex(0, 2*math.Pi*wantResidue))
	rootError = cmplx.Abs(gotRoot - wantRoot)
	return
}

func assertA2BRefreshValue(t *testing.T, name string, got complex128, want, tolerance float64) {
	t.Helper()
	if errorReal := math.Abs(real(got) - want); errorReal > tolerance {
		t.Fatalf("%s real: got %.12g, want %.12g, error %.3g > %.3g", name, real(got), want, errorReal, tolerance)
	}
	if errorImag := math.Abs(imag(got)); errorImag > tolerance {
		t.Fatalf("%s imaginary: got %.12g, error %.3g > %.3g", name, imag(got), errorImag, tolerance)
	}
}

func encryptA2BRefreshWords(
	t *testing.T,
	circuit *homchain.A2BRefreshCircuit,
	params ckks.Parameters,
	ringZ *z2n.Ring,
	encoder *ckks.Encoder,
	encryptor *rlwe.Encryptor,
	words [4]uint64,
) *rlwe.Ciphertext {
	t.Helper()
	inputSlots := make([]*bignum.Complex, 0, params.MaxSlots())
	for _, word := range words {
		block, err := ringZ.ToRootSlots(ringZ.ArithmeticEncode(word))
		if err != nil {
			t.Fatal(err)
		}
		inputSlots = append(inputSlots, block...)
	}
	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	plaintext.LogDimensions = circuit.Profile().Transform().LogDimensions()
	if err := encoder.Encode(inputSlots, plaintext); err != nil {
		t.Fatal(err)
	}
	input, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func a2bRefreshSpecialB0Block(t *testing.T, ringZ *z2n.Ring, word uint64) (low, high []float64) {
	t.Helper()
	coefficients := ringZ.ArithmeticEncode(word).Coefficients()
	if len(coefficients) != 8 {
		t.Fatalf("arithmetic coefficient count: got %d, want 8", len(coefficients))
	}
	toFloat := func(index int) float64 {
		value, _ := coefficients[index].Float64()
		return value
	}
	return []float64{2 * toFloat(1), toFloat(1), toFloat(2), toFloat(3)},
		[]float64{toFloat(4), toFloat(5), toFloat(6), toFloat(7)}
}

func a2bRefreshLowOracleBlock(t *testing.T, word uint64) []float64 {
	t.Helper()
	return a2bRefreshHalfOracleBlock(t, word, z2n.BooleanLowHalf)
}

func a2bRefreshHalfOracleBlock(t *testing.T, word uint64, half z2n.BooleanHalfKind) []float64 {
	t.Helper()
	bits, err := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
	if err != nil {
		t.Fatal(err)
	}
	selected := bits.Low
	if half == z2n.BooleanHighHalf {
		selected = bits.High
	}
	result := make([]float64, 4)
	for slot := 0; slot < 4; slot++ {
		var prefix uint64
		for j := 0; j <= slot; j++ {
			prefix += uint64(selected[slot-j]) << uint(3-j)
		}
		code := (16 - prefix) & 15
		value, err := z2n.A2BTwoLUTOracle(code, 4)
		if err != nil {
			t.Fatal(err)
		}
		if value.MSB != selected[slot] {
			t.Fatalf("word %#02x %s slot %d: LUT MSB=%d, bit=%d", word, half, slot, value.MSB, selected[slot])
		}
		result[slot], _ = value.ID.Float64()
	}
	return result
}

func decodeA2BRefresh(t *testing.T, encoder *ckks.Encoder, decryptor *rlwe.Decryptor, ciphertext *rlwe.Ciphertext) []complex128 {
	t.Helper()
	decoded := make([]complex128, ciphertext.Slots())
	if err := encoder.Decode(decryptor.DecryptNew(ciphertext), decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}
