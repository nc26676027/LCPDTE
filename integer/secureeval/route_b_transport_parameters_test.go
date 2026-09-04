package secureeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/big"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/mod1"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const gaoN16RouteBCompatibilityPolynomialFingerprintHex = "d40394a8477ac33b29fdc2ddc411124b59aee59314edeb05eb1c6631688f9a16"

func TestGaoN16RouteBTransportParametersCanonicalPreparation(t *testing.T) {
	raw, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	assertGaoN16RouteBTransportRaw(t, raw)

	beforeRaw, err := raw.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	beforeCounters := dft.SnapshotMatrixConstructionCounters()
	directPrepared, err := bootstrapping.PrepareParameters(raw)
	if err != nil {
		t.Fatal(err)
	}
	prepared, transforms, err := prepareGaoN16RouteBTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	preparedAgain, transformsAgain, err := prepareGaoN16RouteBTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	afterCounters := dft.SnapshotMatrixConstructionCounters()
	delta, err := afterCounters.Delta(beforeCounters)
	if err != nil {
		t.Fatal(err)
	}
	if got := [4]uint64{delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming()}; got != [4]uint64{} {
		t.Fatalf("pure canonical preparation constructed DFT data: %v", got)
	}
	if err = prepared.Verify(); err != nil {
		t.Fatal(err)
	}
	if directPrepared.Digest() != prepared.Digest() || preparedAgain.Digest() != prepared.Digest() {
		t.Fatal("direct and repeated canonical preparations produced different seals")
	}
	if transformsAgain != transforms {
		t.Fatal("repeated canonical preparation produced different typed transform identities")
	}
	afterRaw, err := raw.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeRaw, afterRaw) {
		t.Fatal("direct canonical preparation mutated its caller-owned raw value")
	}

	preparedDigest := prepared.Digest()
	if got := hex.EncodeToString(preparedDigest[:]); got != gaoN16RouteBPreparedDigestHex {
		t.Fatalf("prepared digest changed: got %s want %s", got, gaoN16RouteBPreparedDigestHex)
	}
	if got := sha256.Sum256(beforeRaw); hex.EncodeToString(got[:]) != gaoN16RouteBRawDiagnosticDigestHex {
		t.Fatalf("raw diagnostic digest changed: %x", got)
	}
	assertGaoN16RouteBTransformDigests(t, transforms)
	assertGaoN16RouteBEffectiveScalings(t, raw, prepared)
	assertGaoN16RouteBCompatibilityPolynomial(t, prepared)
}

func TestGaoN16RouteBTransportParametersDetachedAndOrderBound(t *testing.T) {
	first, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	if &first.SlotsToCoeffsParameters.Levels[0] == &first.CoeffsToSlotsParameters.Levels[0] ||
		first.SlotsToCoeffsParameters.Scaling == first.CoeffsToSlotsParameters.Scaling {
		t.Fatal("STC and CTS storage alias within one canonical constructor result")
	}
	firstSTCLevels := &first.SlotsToCoeffsParameters.Levels[0]
	firstCTSLevels := &first.CoeffsToSlotsParameters.Levels[0]
	firstSTCScaling := first.SlotsToCoeffsParameters.Scaling
	firstCTSScaling := first.CoeffsToSlotsParameters.Scaling
	first.SlotsToCoeffsParameters.Levels[0] = 99
	first.CoeffsToSlotsParameters.Levels[0] = 99
	first.SlotsToCoeffsParameters.Scaling.SetInt64(99)
	first.CoeffsToSlotsParameters.Scaling.SetInt64(99)

	second, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	if firstSTCLevels == &second.SlotsToCoeffsParameters.Levels[0] ||
		firstCTSLevels == &second.CoeffsToSlotsParameters.Levels[0] ||
		firstSTCScaling == second.SlotsToCoeffsParameters.Scaling ||
		firstCTSScaling == second.CoeffsToSlotsParameters.Scaling {
		t.Fatal("separate canonical constructor results share DFT storage")
	}
	assertGaoN16RouteBTransportRaw(t, second)

	validPrepared, err := bootstrapping.PrepareParameters(second)
	if err != nil {
		t.Fatal(err)
	}
	custom := second
	custom.CircuitOrder = bootstrapping.Custom
	customPrepared, err := bootstrapping.PrepareParameters(custom)
	if err != nil {
		t.Fatalf("Custom is expected to bypass vendor order checks before project identity rejects it: %v", err)
	}
	if customPrepared.Digest() == validPrepared.Digest() {
		t.Fatal("CircuitOrder drift did not change the prepared identity")
	}
	stock := second
	stock.CircuitOrder = bootstrapping.ModUpThenEncode
	if _, err = bootstrapping.PrepareParameters(stock); err == nil {
		t.Fatal("ModUpThenEncode unexpectedly accepted the 15 != 18 level relation")
	}
	nonNilIterations := second
	nonNilIterations.IterationsParameters = &bootstrapping.IterationsParameters{}
	nonNilPrepared, err := bootstrapping.PrepareParameters(nonNilIterations)
	if err != nil {
		t.Fatal(err)
	}
	if nonNilPrepared.Digest() == validPrepared.Digest() {
		t.Fatal("nil and non-nil empty iterations share a prepared identity")
	}
}

func TestGaoN16RouteBTransportParametersPreparedDetachment(t *testing.T) {
	raw, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	callerFingerprint := routeBParametersFingerprint(t, raw)
	prepared, err := bootstrapping.PrepareParameters(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := routeBParametersFingerprint(t, raw); got != callerFingerprint {
		t.Fatal("PrepareParameters mutated the caller-owned canonical raw value")
	}

	rawView := prepared.RawParameters()
	effectiveView := prepared.EffectiveParameters()
	derivedView := prepared.Mod1Parameters()
	if &rawView.SlotsToCoeffsParameters.Levels[0] == &raw.SlotsToCoeffsParameters.Levels[0] ||
		&rawView.CoeffsToSlotsParameters.Levels[0] == &raw.CoeffsToSlotsParameters.Levels[0] ||
		rawView.SlotsToCoeffsParameters.Scaling == raw.SlotsToCoeffsParameters.Scaling ||
		rawView.CoeffsToSlotsParameters.Scaling == raw.CoeffsToSlotsParameters.Scaling {
		t.Fatal("prepared raw accessor aliases caller-owned DFT storage")
	}
	if &effectiveView.SlotsToCoeffsParameters.Levels[0] == &rawView.SlotsToCoeffsParameters.Levels[0] ||
		&effectiveView.CoeffsToSlotsParameters.Levels[0] == &rawView.CoeffsToSlotsParameters.Levels[0] ||
		effectiveView.SlotsToCoeffsParameters.Scaling == rawView.SlotsToCoeffsParameters.Scaling ||
		effectiveView.CoeffsToSlotsParameters.Scaling == rawView.CoeffsToSlotsParameters.Scaling {
		t.Fatal("raw and effective accessors share mutable DFT storage")
	}

	rawFingerprint := routeBParametersFingerprint(t, rawView)
	effectiveFingerprint := routeBParametersFingerprint(t, effectiveView)
	derivedFingerprint := routeBMod1Fingerprint(t, derivedView)
	digest := prepared.Digest()

	raw.SlotsToCoeffsParameters.Levels[0] = 91
	raw.CoeffsToSlotsParameters.Levels[0] = 92
	raw.SlotsToCoeffsParameters.Scaling.SetInt64(93)
	raw.CoeffsToSlotsParameters.Scaling.SetInt64(94)
	raw.Mod1ParametersLiteral.K = 95
	raw.CircuitOrder = bootstrapping.Custom

	rawView.SlotsToCoeffsParameters.Levels[0] = 81
	rawView.CoeffsToSlotsParameters.Levels[0] = 82
	rawView.SlotsToCoeffsParameters.Scaling.SetInt64(83)
	rawView.CoeffsToSlotsParameters.Scaling.SetInt64(84)
	effectiveView.SlotsToCoeffsParameters.Levels[0] = 71
	effectiveView.CoeffsToSlotsParameters.Levels[0] = 72
	effectiveView.SlotsToCoeffsParameters.Scaling.SetInt64(73)
	effectiveView.CoeffsToSlotsParameters.Scaling.SetInt64(74)

	derivedView.Mod1Poly.A.SetInt64(61)
	derivedView.Mod1Poly.B.SetInt64(62)
	mutateFirstRouteBPolynomialScalar(t, &derivedView, 63)

	if got := routeBParametersFingerprint(t, prepared.RawParameters()); got != rawFingerprint {
		t.Fatal("caller or raw-accessor mutation changed prepared raw state")
	}
	if got := routeBParametersFingerprint(t, prepared.EffectiveParameters()); got != effectiveFingerprint {
		t.Fatal("effective-accessor mutation changed prepared effective state")
	}
	if got := routeBMod1Fingerprint(t, prepared.Mod1Parameters()); got != derivedFingerprint {
		t.Fatal("derived-polynomial accessor mutation changed prepared Mod1 state")
	}
	if prepared.Digest() != digest {
		t.Fatal("external alias attacks changed the prepared seal")
	}
	if err = prepared.Verify(); err != nil {
		t.Fatalf("external alias attacks invalidated the prepared seal: %v", err)
	}

	transforms, err := deriveGaoN16RouteBTransformIdentities(prepared)
	if err != nil {
		t.Fatal(err)
	}
	assertGaoN16RouteBTransformDigests(t, transforms)

	iterationInput, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	iterationInput.IterationsParameters = &bootstrapping.IterationsParameters{
		ReservedPrimeBitSize:   43,
		BootstrappingPrecision: []float64{19.25, 23.5},
	}
	iterationCallerFingerprint := routeBParametersFingerprint(t, iterationInput)
	iterationPrepared, err := bootstrapping.PrepareParameters(iterationInput)
	if err != nil {
		t.Fatal(err)
	}
	if got := routeBParametersFingerprint(t, iterationInput); got != iterationCallerFingerprint {
		t.Fatal("PrepareParameters mutated caller-owned iteration storage")
	}
	iterationRaw := iterationPrepared.RawParameters()
	iterationEffective := iterationPrepared.EffectiveParameters()
	if iterationRaw.IterationsParameters == iterationInput.IterationsParameters ||
		iterationEffective.IterationsParameters == iterationInput.IterationsParameters ||
		iterationRaw.IterationsParameters == iterationEffective.IterationsParameters ||
		&iterationRaw.IterationsParameters.BootstrappingPrecision[0] == &iterationInput.IterationsParameters.BootstrappingPrecision[0] ||
		&iterationEffective.IterationsParameters.BootstrappingPrecision[0] == &iterationInput.IterationsParameters.BootstrappingPrecision[0] ||
		&iterationRaw.IterationsParameters.BootstrappingPrecision[0] == &iterationEffective.IterationsParameters.BootstrappingPrecision[0] {
		t.Fatal("prepared iteration pointers or slices alias caller/accessor storage")
	}
	iterationRawFingerprint := routeBParametersFingerprint(t, iterationRaw)
	iterationEffectiveFingerprint := routeBParametersFingerprint(t, iterationEffective)
	iterationDigest := iterationPrepared.Digest()
	iterationInput.IterationsParameters.BootstrappingPrecision[0] = -1
	iterationRaw.IterationsParameters.BootstrappingPrecision[0] = -2
	iterationEffective.IterationsParameters.BootstrappingPrecision[0] = -3
	if got := routeBParametersFingerprint(t, iterationPrepared.RawParameters()); got != iterationRawFingerprint {
		t.Fatal("iteration alias attack changed prepared raw state")
	}
	if got := routeBParametersFingerprint(t, iterationPrepared.EffectiveParameters()); got != iterationEffectiveFingerprint {
		t.Fatal("iteration alias attack changed prepared effective state")
	}
	if iterationPrepared.Digest() != iterationDigest {
		t.Fatal("iteration alias attack changed prepared seal")
	}
	if err = iterationPrepared.Verify(); err != nil {
		t.Fatalf("iteration alias attack invalidated prepared seal: %v", err)
	}
}

func TestGaoN16RouteBTransportParametersMutationMatrix(t *testing.T) {
	canonical, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	canonicalPrepared, err := bootstrapping.PrepareParameters(canonical)
	if err != nil {
		t.Fatal(err)
	}
	canonicalDigest := canonicalPrepared.Digest()

	mutatedCKKSScale := func(source ckks.Parameters) ckks.Parameters {
		t.Helper()
		literal := source.ParametersLiteral()
		literal.LogDefaultScale++
		mutated, err := ckks.NewParametersFromLiteral(literal)
		if err != nil {
			t.Fatalf("construct mutated CKKS parameters: %v", err)
		}
		return mutated
	}
	doubleScaling := func(source *big.Float) *big.Float {
		return new(big.Float).SetPrec(source.Prec()).SetMode(source.Mode()).Mul(source, new(big.Float).SetInt64(2))
	}
	negativeScaling := func(source *big.Float) *big.Float {
		return new(big.Float).SetPrec(source.Prec()).SetMode(source.Mode()).Neg(source)
	}
	zeroScaling := func(source *big.Float) *big.Float {
		return new(big.Float).SetPrec(source.Prec()).SetMode(source.Mode()).SetInt64(0)
	}
	precisionScaling := func(source *big.Float) *big.Float {
		return new(big.Float).Copy(source).SetPrec(128)
	}
	modeScaling := func(source *big.Float) *big.Float {
		return new(big.Float).Copy(source).SetMode(big.ToZero)
	}
	accuracyScaling := func(source *big.Float) *big.Float {
		t.Helper()
		var mantissa big.Float
		exponent := source.MantExp(&mantissa)
		tiny := new(big.Float).SetPrec(512).SetInt64(1)
		tiny.SetMantExp(tiny, exponent-400)
		result := new(big.Float).SetPrec(source.Prec()).SetMode(source.Mode()).Add(source, tiny)
		if result.Cmp(source) != 0 || result.Acc() == big.Exact ||
			result.Prec() != source.Prec() || result.Mode() != source.Mode() ||
			result.Signbit() != source.Signbit() ||
			string(result.Append(nil, 'x', -1)) != string(source.Append(nil, 'x', -1)) {
			t.Fatalf("failed to create same-value accuracy mutation: value=%s accuracy=%s", result.Text('x', -1), result.Acc())
		}
		return result
	}

	tests := []struct {
		name               string
		mutate             func(*bootstrapping.Parameters)
		wantTransformDrift bool
	}{
		{"residual-parameters", func(raw *bootstrapping.Parameters) { raw.ResidualParameters = mutatedCKKSScale(raw.ResidualParameters) }, false},
		{"bootstrap-parameters", func(raw *bootstrapping.Parameters) {
			raw.BootstrappingParameters = mutatedCKKSScale(raw.BootstrappingParameters)
		}, false},
		{"ephemeral-secret-weight", func(raw *bootstrapping.Parameters) { raw.EphemeralSecretWeight++ }, false},
		{"circuit-order-custom", func(raw *bootstrapping.Parameters) { raw.CircuitOrder = bootstrapping.Custom }, false},
		{"circuit-order-stock", func(raw *bootstrapping.Parameters) { raw.CircuitOrder = bootstrapping.ModUpThenEncode }, false},
		{"circuit-order-invalid", func(raw *bootstrapping.Parameters) { raw.CircuitOrder = bootstrapping.CircuitOrder(127) }, false},
		{"iterations-empty", func(raw *bootstrapping.Parameters) { raw.IterationsParameters = &bootstrapping.IterationsParameters{} }, false},
		{"iterations-empty-slice", func(raw *bootstrapping.Parameters) {
			raw.IterationsParameters = &bootstrapping.IterationsParameters{BootstrappingPrecision: []float64{}}
		}, false},
		{"iterations-zero-slice", func(raw *bootstrapping.Parameters) {
			raw.IterationsParameters = &bootstrapping.IterationsParameters{BootstrappingPrecision: []float64{0}}
		}, false},
		{"iterations-populated", func(raw *bootstrapping.Parameters) {
			raw.IterationsParameters = &bootstrapping.IterationsParameters{ReservedPrimeBitSize: 43, BootstrappingPrecision: []float64{20}}
		}, false},

		{"stc-type", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.Type = dft.HomomorphicEncode }, true},
		{"stc-log-slots", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.LogSlots-- }, true},
		{"stc-level-q", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.LevelQ-- }, true},
		{"stc-level-p", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.LevelP-- }, true},
		{"stc-levels", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.Levels[0]++ }, true},
		{"stc-levels-nil", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.Levels = nil }, true},
		{"stc-levels-empty", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.Levels = []int{} }, true},
		{"stc-format", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.Format = dft.Standard }, true},
		{"stc-scaling-nil", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.Scaling = nil }, true},
		{"stc-scaling-zero", func(raw *bootstrapping.Parameters) {
			raw.SlotsToCoeffsParameters.Scaling = zeroScaling(raw.SlotsToCoeffsParameters.Scaling)
		}, true},
		{"stc-scaling-sign", func(raw *bootstrapping.Parameters) {
			raw.SlotsToCoeffsParameters.Scaling = negativeScaling(raw.SlotsToCoeffsParameters.Scaling)
		}, true},
		{"stc-scaling-value", func(raw *bootstrapping.Parameters) {
			raw.SlotsToCoeffsParameters.Scaling = doubleScaling(raw.SlotsToCoeffsParameters.Scaling)
		}, true},
		{"stc-scaling-precision", func(raw *bootstrapping.Parameters) {
			raw.SlotsToCoeffsParameters.Scaling = precisionScaling(raw.SlotsToCoeffsParameters.Scaling)
		}, true},
		{"stc-scaling-mode", func(raw *bootstrapping.Parameters) {
			raw.SlotsToCoeffsParameters.Scaling = modeScaling(raw.SlotsToCoeffsParameters.Scaling)
		}, true},
		{"stc-scaling-accuracy", func(raw *bootstrapping.Parameters) {
			raw.SlotsToCoeffsParameters.Scaling = accuracyScaling(raw.SlotsToCoeffsParameters.Scaling)
		}, true},
		{"stc-bit-reversed", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.BitReversed = true }, true},
		{"stc-log-bsgs-ratio", func(raw *bootstrapping.Parameters) { raw.SlotsToCoeffsParameters.LogBSGSRatio++ }, true},

		{"cts-type", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.Type = dft.HomomorphicDecode }, true},
		{"cts-log-slots", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.LogSlots-- }, true},
		{"cts-level-q", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.LevelQ-- }, true},
		{"cts-level-p", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.LevelP-- }, true},
		{"cts-levels", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.Levels[0]++ }, true},
		{"cts-levels-nil", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.Levels = nil }, true},
		{"cts-levels-empty", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.Levels = []int{} }, true},
		{"cts-format", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.Format = dft.Standard }, true},
		{"cts-scaling-nil", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.Scaling = nil }, true},
		{"cts-scaling-zero", func(raw *bootstrapping.Parameters) {
			raw.CoeffsToSlotsParameters.Scaling = zeroScaling(raw.CoeffsToSlotsParameters.Scaling)
		}, true},
		{"cts-scaling-sign", func(raw *bootstrapping.Parameters) {
			raw.CoeffsToSlotsParameters.Scaling = negativeScaling(raw.CoeffsToSlotsParameters.Scaling)
		}, true},
		{"cts-scaling-value", func(raw *bootstrapping.Parameters) {
			raw.CoeffsToSlotsParameters.Scaling = doubleScaling(raw.CoeffsToSlotsParameters.Scaling)
		}, true},
		{"cts-scaling-precision", func(raw *bootstrapping.Parameters) {
			raw.CoeffsToSlotsParameters.Scaling = precisionScaling(raw.CoeffsToSlotsParameters.Scaling)
		}, true},
		{"cts-scaling-mode", func(raw *bootstrapping.Parameters) {
			raw.CoeffsToSlotsParameters.Scaling = modeScaling(raw.CoeffsToSlotsParameters.Scaling)
		}, true},
		{"cts-scaling-accuracy", func(raw *bootstrapping.Parameters) {
			raw.CoeffsToSlotsParameters.Scaling = accuracyScaling(raw.CoeffsToSlotsParameters.Scaling)
		}, true},
		{"cts-bit-reversed", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.BitReversed = true }, true},
		{"cts-log-bsgs-ratio", func(raw *bootstrapping.Parameters) { raw.CoeffsToSlotsParameters.LogBSGSRatio++ }, true},

		{"mod1-level-q", func(raw *bootstrapping.Parameters) { raw.Mod1ParametersLiteral.LevelQ-- }, false},
		{"mod1-log-scale", func(raw *bootstrapping.Parameters) { raw.Mod1ParametersLiteral.LogScale++ }, false},
		{"mod1-type", func(raw *bootstrapping.Parameters) { raw.Mod1ParametersLiteral.Mod1Type = mod1.CosContinuous }, false},
		{"mod1-scaling", func(raw *bootstrapping.Parameters) { raw.Mod1ParametersLiteral.Scaling = 0.5 }, false},
		{"mod1-log-message-ratio", func(raw *bootstrapping.Parameters) { raw.Mod1ParametersLiteral.LogMessageRatio++ }, false},
		{"mod1-k", func(raw *bootstrapping.Parameters) { raw.Mod1ParametersLiteral.K++ }, false},
		{"mod1-degree", func(raw *bootstrapping.Parameters) { raw.Mod1ParametersLiteral.Mod1Degree++ }, false},
		{"mod1-double-angle", func(raw *bootstrapping.Parameters) { raw.Mod1ParametersLiteral.DoubleAngle++ }, false},
		{"mod1-inverse-degree", func(raw *bootstrapping.Parameters) { raw.Mod1ParametersLiteral.Mod1InvDegree++ }, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := newGaoN16RouteBTransportParameters()
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&raw)
			prepared, err := bootstrapping.PrepareParameters(raw)
			if err != nil {
				return
			}
			if prepared.Digest() == canonicalDigest {
				t.Fatal("mutation retained the canonical prepared identity")
			}
			if err = validateGaoN16RouteBPreparedIdentity(prepared); err == nil {
				t.Fatal("mutation passed the canonical prepared identity gate")
			}
			if !test.wantTransformDrift {
				return
			}
			transforms, err := deriveGaoN16RouteBTransformIdentities(prepared)
			if err != nil {
				return
			}
			if err = validateGaoN16RouteBTransformIdentitySet(transforms); err == nil {
				t.Fatal("DFT mutation passed the typed transform identity gate")
			}
		})
	}
}

func TestGaoN16RouteBTransformIdentityRejectsNarrowing(t *testing.T) {
	raw, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	base := raw.SlotsToCoeffsParameters
	tooLargeInt32 := int(int64(math.MaxInt32) + 1)
	tests := []struct {
		name   string
		mutate func(*dft.MatrixLiteral)
	}{
		{"type", func(value *dft.MatrixLiteral) { value.Type = dft.Type(256) }},
		{"format", func(value *dft.MatrixLiteral) { value.Format = dft.Format(256) }},
		{"log-slots", func(value *dft.MatrixLiteral) { value.LogSlots = tooLargeInt32 }},
		{"level-q", func(value *dft.MatrixLiteral) { value.LevelQ = tooLargeInt32 }},
		{"level-p", func(value *dft.MatrixLiteral) { value.LevelP = tooLargeInt32 }},
		{"factor-level", func(value *dft.MatrixLiteral) { value.Levels[0] = tooLargeInt32 }},
		{"log-bsgs-ratio", func(value *dft.MatrixLiteral) { value.LogBSGSRatio = tooLargeInt32 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			literal := base
			literal.Levels = append([]int(nil), base.Levels...)
			test.mutate(&literal)
			if _, _, err := deriveGaoN16RouteBTransformIdentity(RBAUTHRoleSTC, RBAUTHPhaseRaw, literal); err == nil {
				t.Fatal("narrowing mutation was accepted")
			}
		})
	}
}

func assertGaoN16RouteBTransportRaw(t *testing.T, raw bootstrapping.Parameters) {
	t.Helper()
	if !raw.ResidualParameters.Equal(&raw.BootstrappingParameters) ||
		raw.ResidualParameters.LogN() != 16 || raw.ResidualParameters.MaxLevelQ() != 20 ||
		raw.ResidualParameters.MaxLevelP() != 6 || raw.ResidualParameters.LogDefaultScale() != 43 {
		t.Fatal("canonical Route-B transport CKKS parameters changed")
	}
	if raw.CircuitOrder != bootstrapping.DecodeThenModUp || raw.EphemeralSecretWeight != 32 || raw.IterationsParameters != nil {
		t.Fatalf("canonical remaining fields changed: order=%d h=%d iterations=%v", raw.CircuitOrder, raw.EphemeralSecretWeight, raw.IterationsParameters)
	}
	assertLiteral := func(name string, literal dft.MatrixLiteral, typ dft.Type, levelQ int, levels []int, scaling string) {
		t.Helper()
		actualScaling := "<nil>"
		if literal.Scaling != nil {
			actualScaling = string(literal.Scaling.Append(nil, 'x', -1))
		}
		if literal.Type != typ || literal.LogSlots != 11 || literal.LevelQ != levelQ || literal.LevelP != 6 ||
			literal.Format != dft.SplitRealAndImag || literal.BitReversed || literal.LogBSGSRatio != 0 ||
			!equalRouteBInts(literal.Levels, levels) || literal.Scaling == nil || literal.Scaling.Prec() != 256 ||
			literal.Scaling.Mode() != big.ToNearestEven || literal.Scaling.Acc() != big.Exact || literal.Scaling.Signbit() ||
			actualScaling != scaling {
			t.Fatalf("canonical %s literal changed: %+v scaling=%s want=%s", name, literal, actualScaling, scaling)
		}
	}
	assertLiteral("STC", raw.SlotsToCoeffsParameters, dft.HomomorphicDecode, 18, []int{1, 1}, "0x1p+00")
	assertLiteral("CTS", raw.CoeffsToSlotsParameters, dft.HomomorphicEncode, 20, []int{1, 1, 1}, "0x1p-04")
	wantMod1 := mod1.ParametersLiteral{
		LevelQ: 17, LogScale: 43, Mod1Type: mod1.SinContinuous, Scaling: 0,
		LogMessageRatio: 0, K: 1, Mod1Degree: 3, DoubleAngle: 0, Mod1InvDegree: 0,
	}
	if raw.Mod1ParametersLiteral != wantMod1 {
		t.Fatalf("canonical compatibility literal changed: got %+v want %+v", raw.Mod1ParametersLiteral, wantMod1)
	}
}

func assertGaoN16RouteBEffectiveScalings(t *testing.T, raw bootstrapping.Parameters, prepared bootstrapping.PreparedParameters) {
	t.Helper()
	effective := prepared.EffectiveParameters()
	if effective.SlotsToCoeffsParameters.Scaling == nil || effective.CoeffsToSlotsParameters.Scaling == nil {
		t.Fatal("effective scaling is nil")
	}
	q0 := raw.BootstrappingParameters.Q()[0]
	roundedQ0 := math.Exp2(math.Round(math.Log2(float64(q0))))
	scalingFactor := math.Exp2(float64(raw.Mod1ParametersLiteral.LogScale))
	messageRatio := math.Exp2(float64(raw.Mod1ParametersLiteral.LogMessageRatio))
	qDiff := float64(q0) / roundedQ0
	qDiv := scalingFactor / roundedQ0
	if qDiv > 1 {
		qDiv = 1
	}
	ctsBase := qDiv / (float64(raw.Mod1ParametersLiteral.K) * qDiff)
	stcBase := raw.BootstrappingParameters.DefaultScale().Float64() / (scalingFactor / messageRatio)
	wantSTC := new(big.Float).Mul(raw.SlotsToCoeffsParameters.Scaling, new(big.Float).SetFloat64(stcBase))
	wantCTS := new(big.Float).Mul(raw.CoeffsToSlotsParameters.Scaling, new(big.Float).SetFloat64(ctsBase))
	assertRouteBBigFloatEqual(t, "effective STC scaling", effective.SlotsToCoeffsParameters.Scaling, wantSTC)
	assertRouteBBigFloatEqual(t, "effective CTS scaling", effective.CoeffsToSlotsParameters.Scaling, wantCTS)

	derived := prepared.Mod1Parameters()
	if math.Float64bits(derived.QDiff) != math.Float64bits(qDiff) {
		t.Fatalf("derived qDiff changed: got %.17g want %.17g", derived.QDiff, qDiff)
	}
	inverseQDiff := 1 / qDiff
	if math.Round(inverseQDiff) != 1 || inverseQDiff == 1 {
		t.Fatalf("qDiff fixture no longer distinguishes rounded scalar from metadata correction: 1/qDiff=%.17g", inverseQDiff)
	}
	if effective.CoeffsToSlotsParameters.Scaling.Cmp(raw.CoeffsToSlotsParameters.Scaling) == 0 {
		t.Fatal("effective CTS scaling lost the nontrivial qDiff metadata correction")
	}
}

func assertGaoN16RouteBCompatibilityPolynomial(t *testing.T, prepared bootstrapping.PreparedParameters) {
	t.Helper()
	parameters := prepared.Mod1Parameters()
	if parameters.LevelQ != 17 || parameters.LogDefaultScale != 43 || parameters.Mod1Type != mod1.SinContinuous ||
		parameters.LogMessageRatio != 0 || parameters.DoubleAngle != 0 || parameters.K != 1 ||
		len(parameters.Mod1Poly.Coeffs) != 4 || parameters.Mod1InvPoly != nil {
		t.Fatalf("resident compatibility polynomial changed: %+v", parameters)
	}
	fingerprint := routeBMod1Fingerprint(t, parameters)
	if got := hex.EncodeToString(fingerprint[:]); got != gaoN16RouteBCompatibilityPolynomialFingerprintHex {
		t.Fatalf("resident compatibility polynomial fingerprint changed: got %s want %s", got, gaoN16RouteBCompatibilityPolynomialFingerprintHex)
	}
}

func assertGaoN16RouteBTransformDigests(t *testing.T, value RBAUTHTransformDigests) {
	t.Helper()
	expected := [...]string{
		gaoN16RouteBRawSTCLiteralDigestHex,
		gaoN16RouteBRawSTCScalingDigestHex,
		gaoN16RouteBEffectiveSTCLiteralDigestHex,
		gaoN16RouteBEffectiveSTCScalingDigestHex,
		gaoN16RouteBRawCTSLiteralDigestHex,
		gaoN16RouteBRawCTSScalingDigestHex,
		gaoN16RouteBEffectiveCTSLiteralDigestHex,
		gaoN16RouteBEffectiveCTSScalingDigestHex,
	}
	for index, digest := range transformDigestSlice(value) {
		if got := hex.EncodeToString(digest[:]); got != expected[index] {
			t.Fatalf("transform digest %d changed: got %s want %s", index, got, expected[index])
		}
	}
}

func equalRouteBInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func assertRouteBBigFloatEqual(t *testing.T, name string, got, want *big.Float) {
	t.Helper()
	if got == nil || want == nil {
		t.Fatalf("%s has nil operand", name)
	}
	gotGob, err := got.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	wantGob, err := want.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	if got.Prec() != want.Prec() || got.Mode() != want.Mode() || got.Acc() != want.Acc() ||
		got.Signbit() != want.Signbit() || string(got.Append(nil, 'x', -1)) != string(want.Append(nil, 'x', -1)) ||
		!bytes.Equal(gotGob, wantGob) {
		t.Fatalf("%s changed: got(value=%s prec=%d mode=%s acc=%s sign=%t) want(value=%s prec=%d mode=%s acc=%s sign=%t)",
			name, got.Text('x', -1), got.Prec(), got.Mode(), got.Acc(), got.Signbit(),
			want.Text('x', -1), want.Prec(), want.Mode(), want.Acc(), want.Signbit())
	}
}

func routeBParametersFingerprint(t *testing.T, value bootstrapping.Parameters) [sha256.Size]byte {
	t.Helper()
	var canonical bytes.Buffer
	payload, err := value.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	writeRouteBTestBytes(&canonical, payload)
	for _, scaling := range []*big.Float{
		value.SlotsToCoeffsParameters.Scaling,
		value.CoeffsToSlotsParameters.Scaling,
	} {
		if scaling == nil {
			writeRouteBTestUint64(&canonical, 0)
			continue
		}
		writeRouteBTestUint64(&canonical, 1)
		encoded, err := scaling.GobEncode()
		if err != nil {
			t.Fatal(err)
		}
		writeRouteBTestBytes(&canonical, encoded)
	}
	return sha256.Sum256(canonical.Bytes())
}

func routeBMod1Fingerprint(t *testing.T, value mod1.Parameters) [sha256.Size]byte {
	t.Helper()
	var canonical bytes.Buffer
	for _, field := range []uint64{
		uint64(value.LevelQ), uint64(value.LogDefaultScale), uint64(value.Mod1Type),
		uint64(value.LogMessageRatio), uint64(value.DoubleAngle), math.Float64bits(value.QDiff),
		math.Float64bits(value.Sqrt2Pi), math.Float64bits(value.K),
	} {
		writeRouteBTestUint64(&canonical, field)
	}
	writePolynomial := func(polynomial *bignum.Polynomial) {
		if polynomial == nil {
			writeRouteBTestUint64(&canonical, 0)
			return
		}
		writeRouteBTestUint64(&canonical, 1)
		writeRouteBTestUint64(&canonical, uint64(polynomial.Basis))
		writeRouteBTestUint64(&canonical, uint64(polynomial.Nodes))
		writeRouteBTestBool(&canonical, polynomial.IsOdd)
		writeRouteBTestBool(&canonical, polynomial.IsEven)
		writeRouteBTestFloat(t, &canonical, &polynomial.A)
		writeRouteBTestFloat(t, &canonical, &polynomial.B)
		writeRouteBTestUint64(&canonical, uint64(len(polynomial.Coeffs)))
		for _, coefficient := range polynomial.Coeffs {
			if coefficient == nil {
				writeRouteBTestUint64(&canonical, 0)
				continue
			}
			writeRouteBTestUint64(&canonical, 1)
			writeRouteBTestFloat(t, &canonical, coefficient[0])
			writeRouteBTestFloat(t, &canonical, coefficient[1])
		}
	}
	writePolynomial(&value.Mod1Poly)
	writePolynomial(value.Mod1InvPoly)
	return sha256.Sum256(canonical.Bytes())
}

func mutateFirstRouteBPolynomialScalar(t *testing.T, value *mod1.Parameters, replacement int64) {
	t.Helper()
	for _, coefficient := range value.Mod1Poly.Coeffs {
		if coefficient != nil && coefficient[0] != nil {
			coefficient[0].SetInt64(replacement)
			return
		}
	}
	t.Fatal("resident compatibility polynomial has no mutable real coefficient")
}

func writeRouteBTestFloat(t *testing.T, buffer *bytes.Buffer, value *big.Float) {
	t.Helper()
	if value == nil {
		writeRouteBTestUint64(buffer, 0)
		return
	}
	writeRouteBTestUint64(buffer, 1)
	encoded, err := value.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	writeRouteBTestBytes(buffer, encoded)
}

func writeRouteBTestBool(buffer *bytes.Buffer, value bool) {
	if value {
		writeRouteBTestUint64(buffer, 1)
		return
	}
	writeRouteBTestUint64(buffer, 0)
}

func writeRouteBTestBytes(buffer *bytes.Buffer, value []byte) {
	writeRouteBTestUint64(buffer, uint64(len(value)))
	_, _ = buffer.Write(value)
}

func writeRouteBTestUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	_, _ = buffer.Write(encoded[:])
}
