package bootstrapping

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/mod1"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestPrepareParametersMatchesFrozenLegacyPreparation(t *testing.T) {
	// These exact values were captured from Evaluator.initialize before the
	// preparation seam was wired into the stock constructor. Keeping the oracle
	// as bytes avoids duplicating the production scaling formula in this test.
	wantS2CGob := "010a000000c000000006955555555555555555555555555555555555555555555556"
	wantC2SGob := "0112000000a0fffffff6b6db6db6db4b400000000000000000000000000000000000"
	wantDigest := "b74e38d720ec072710845df22d21b2ed5d2e78e8b2fbe0795ab54a48efd5c5e1"

	prepared, err := PrepareParameters(prepareParametersTestInput(t))
	if err != nil {
		t.Fatal(err)
	}
	effective := prepared.EffectiveParameters()
	for role, test := range map[string]struct {
		scaling *big.Float
		want    string
	}{
		"S2C": {scaling: effective.SlotsToCoeffsParameters.Scaling, want: wantS2CGob},
		"C2S": {scaling: effective.CoeffsToSlotsParameters.Scaling, want: wantC2SGob},
	} {
		got, err := test.scaling.GobEncode()
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != test.want {
			t.Fatalf("%s effective scaling drifted: got %s, want %s", role, hex.EncodeToString(got), test.want)
		}
	}
	digest := prepared.Digest()
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("prepared/Mod1 seal drifted: got %s, want %s", got, wantDigest)
	}
}

func TestPrepareParametersPreservesAndDetachesInput(t *testing.T) {
	input := prepareParametersTestInput(t)
	inputS2CScaling, err := input.SlotsToCoeffsParameters.Scaling.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	inputC2SScaling, err := input.CoeffsToSlotsParameters.Scaling.GobEncode()
	if err != nil {
		t.Fatal(err)
	}

	before := dft.SnapshotMatrixConstructionCounters()
	prepared, err := PrepareParameters(input)
	if err != nil {
		t.Fatal(err)
	}
	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil {
		t.Fatal(err)
	}
	if got := [4]uint64{delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming()}; got != [4]uint64{} {
		t.Fatalf("PrepareParameters constructed DFT data: delta=%v", got)
	}
	if err := prepared.Verify(); err != nil {
		t.Fatalf("prepared seal rejected: %v", err)
	}

	if got, err := input.SlotsToCoeffsParameters.Scaling.GobEncode(); err != nil || !bytes.Equal(got, inputS2CScaling) {
		t.Fatalf("PrepareParameters mutated the input S2C scaling: err=%v", err)
	}
	if got, err := input.CoeffsToSlotsParameters.Scaling.GobEncode(); err != nil || !bytes.Equal(got, inputC2SScaling) {
		t.Fatalf("PrepareParameters mutated the input C2S scaling: err=%v", err)
	}
	if got := input.SlotsToCoeffsParameters.Levels; len(got) != 1 || got[0] != 1 {
		t.Fatalf("PrepareParameters mutated input S2C levels: %v", got)
	}
	if got := input.IterationsParameters.BootstrappingPrecision; len(got) != 2 || got[0] != 19.25 || got[1] != 23.5 {
		t.Fatalf("PrepareParameters mutated input iterations: %v", got)
	}

	raw := prepared.RawParameters()
	assertPreparedTestScaling(t, raw.SlotsToCoeffsParameters.Scaling, inputS2CScaling, 192, big.AwayFromZero)
	assertPreparedTestScaling(t, raw.CoeffsToSlotsParameters.Scaling, inputC2SScaling, 160, big.ToZero)
	if raw.IterationsParameters == input.IterationsParameters || &raw.IterationsParameters.BootstrappingPrecision[0] == &input.IterationsParameters.BootstrappingPrecision[0] {
		t.Fatal("prepared raw iterations alias the caller input")
	}
	if &raw.SlotsToCoeffsParameters.Levels[0] == &input.SlotsToCoeffsParameters.Levels[0] {
		t.Fatal("prepared raw S2C levels alias the caller input")
	}
	if raw.SlotsToCoeffsParameters.Scaling == input.SlotsToCoeffsParameters.Scaling {
		t.Fatal("prepared raw S2C scaling aliases the caller input")
	}

	digest := prepared.Digest()
	input.SlotsToCoeffsParameters.Levels[0] = 99
	input.SlotsToCoeffsParameters.Scaling.SetInt64(99)
	input.CoeffsToSlotsParameters.Scaling.SetInt64(98)
	input.IterationsParameters.BootstrappingPrecision[0] = -1

	raw.SlotsToCoeffsParameters.Levels[0] = 77
	raw.SlotsToCoeffsParameters.Scaling.SetInt64(77)
	raw.CoeffsToSlotsParameters.Scaling.SetInt64(76)
	raw.IterationsParameters.BootstrappingPrecision[0] = -2

	rawAgain := prepared.RawParameters()
	assertPreparedTestScaling(t, rawAgain.SlotsToCoeffsParameters.Scaling, inputS2CScaling, 192, big.AwayFromZero)
	assertPreparedTestScaling(t, rawAgain.CoeffsToSlotsParameters.Scaling, inputC2SScaling, 160, big.ToZero)
	if got := rawAgain.SlotsToCoeffsParameters.Levels; len(got) != 1 || got[0] != 1 {
		t.Fatalf("prepared raw S2C levels were mutated through an alias: %v", got)
	}
	if got := rawAgain.IterationsParameters.BootstrappingPrecision; len(got) != 2 || got[0] != 19.25 || got[1] != 23.5 {
		t.Fatalf("prepared iterations were mutated through an alias: %v", got)
	}
	if prepared.Digest() != digest {
		t.Fatal("prepared digest changed after mutating caller-owned or accessor-owned data")
	}
	if err := prepared.Verify(); err != nil {
		t.Fatalf("prepared seal changed after external mutations: %v", err)
	}

	derived := prepared.Mod1Parameters()
	if len(derived.Mod1Poly.Coeffs) != 2 || derived.Mod1Poly.Coeffs[1] == nil {
		t.Fatalf("unexpected derived Mod1 polynomial: degree=%d", derived.Mod1Poly.Degree())
	}
	originalCoefficient, err := derived.Mod1Poly.Coeffs[1][0].GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	derived.Mod1Poly.Coeffs[1][0].SetInt64(123)
	derivedAgain := prepared.Mod1Parameters()
	if got, err := derivedAgain.Mod1Poly.Coeffs[1][0].GobEncode(); err != nil || !bytes.Equal(got, originalCoefficient) {
		t.Fatalf("derived Mod1 accessor aliases prepared state: err=%v", err)
	}
	if err := prepared.Verify(); err != nil {
		t.Fatalf("derived accessor mutation changed prepared seal: %v", err)
	}
}

func TestPrepareParametersSealIncludesBigFloatMetadataAndCircuitOrder(t *testing.T) {
	base := prepareParametersTestInput(t)
	base.SlotsToCoeffsParameters.Scaling = new(big.Float).
		SetPrec(192).
		SetMode(big.AwayFromZero).
		SetFloat64(0.5)
	basePrepared, err := PrepareParameters(base)
	if err != nil {
		t.Fatal(err)
	}

	precisionVariant := prepareParametersTestInput(t)
	precisionVariant.SlotsToCoeffsParameters.Scaling = new(big.Float).
		SetPrec(256).
		SetMode(big.AwayFromZero).
		SetFloat64(0.5)
	if base.SlotsToCoeffsParameters.Scaling.Cmp(precisionVariant.SlotsToCoeffsParameters.Scaling) != 0 ||
		base.SlotsToCoeffsParameters.Scaling.Mode() != precisionVariant.SlotsToCoeffsParameters.Scaling.Mode() ||
		base.SlotsToCoeffsParameters.Scaling.Acc() != precisionVariant.SlotsToCoeffsParameters.Scaling.Acc() {
		t.Fatal("precision-isolation fixtures differ in value, rounding mode or accuracy")
	}
	precisionPrepared, err := PrepareParameters(precisionVariant)
	if err != nil {
		t.Fatal(err)
	}
	if base.SlotsToCoeffsParameters.Scaling.Prec() == precisionVariant.SlotsToCoeffsParameters.Scaling.Prec() {
		t.Fatal("precision-isolation fixtures use the same precision")
	}
	if basePrepared.Digest() == precisionPrepared.Digest() {
		t.Fatal("prepared seal omitted big.Float precision")
	}

	modeVariant := prepareParametersTestInput(t)
	modeVariant.SlotsToCoeffsParameters.Scaling = new(big.Float).
		SetPrec(192).
		SetMode(big.ToNearestEven).
		SetFloat64(0.5)
	if base.SlotsToCoeffsParameters.Scaling.Cmp(modeVariant.SlotsToCoeffsParameters.Scaling) != 0 ||
		base.SlotsToCoeffsParameters.Scaling.Prec() != modeVariant.SlotsToCoeffsParameters.Scaling.Prec() ||
		base.SlotsToCoeffsParameters.Scaling.Acc() != modeVariant.SlotsToCoeffsParameters.Scaling.Acc() {
		t.Fatal("rounding-mode-isolation fixtures differ in value, precision or accuracy")
	}
	if base.SlotsToCoeffsParameters.Scaling.Mode() == modeVariant.SlotsToCoeffsParameters.Scaling.Mode() {
		t.Fatal("rounding-mode-isolation fixtures use the same rounding mode")
	}
	modePrepared, err := PrepareParameters(modeVariant)
	if err != nil {
		t.Fatal(err)
	}
	if basePrepared.Digest() == modePrepared.Digest() {
		t.Fatal("prepared seal omitted big.Float rounding mode")
	}

	exactAccuracy := new(big.Float).
		SetPrec(2).
		SetMode(big.ToNegativeInf).
		SetFloat64(0.5)
	belowAccuracy := new(big.Float).
		SetPrec(2).
		SetMode(big.ToNegativeInf).
		SetRat(big.NewRat(17, 32))
	if exactAccuracy.Cmp(belowAccuracy) != 0 || exactAccuracy.Prec() != belowAccuracy.Prec() || exactAccuracy.Mode() != belowAccuracy.Mode() {
		t.Fatal("accuracy-isolation fixtures differ in value, precision or rounding mode")
	}
	if exactAccuracy.Acc() != big.Exact || belowAccuracy.Acc() != big.Below {
		t.Fatalf("accuracy-isolation fixture metadata = (%v, %v), want (Exact, Below)", exactAccuracy.Acc(), belowAccuracy.Acc())
	}
	exactAccuracyInput := prepareParametersTestInput(t)
	exactAccuracyInput.SlotsToCoeffsParameters.Scaling = exactAccuracy
	exactAccuracyPrepared, err := PrepareParameters(exactAccuracyInput)
	if err != nil {
		t.Fatal(err)
	}
	belowAccuracyInput := prepareParametersTestInput(t)
	belowAccuracyInput.SlotsToCoeffsParameters.Scaling = belowAccuracy
	belowAccuracyPrepared, err := PrepareParameters(belowAccuracyInput)
	if err != nil {
		t.Fatal(err)
	}
	if exactAccuracyPrepared.Digest() == belowAccuracyPrepared.Digest() {
		t.Fatal("prepared seal omitted big.Float accuracy")
	}

	orderVariant := prepareParametersTestInput(t)
	orderVariant.CircuitOrder = Custom
	orderPrepared, err := PrepareParameters(orderVariant)
	if err != nil {
		t.Fatal(err)
	}
	if basePrepared.Digest() == orderPrepared.Digest() {
		t.Fatal("prepared seal omitted CircuitOrder")
	}
}

func TestPrepareParametersPreservesNonNilEmptySlices(t *testing.T) {
	input := prepareParametersTestInput(t)
	input.CircuitOrder = Custom
	input.SlotsToCoeffsParameters.Levels = []int{}
	input.CoeffsToSlotsParameters.Levels = []int{}
	input.IterationsParameters.BootstrappingPrecision = []float64{}

	prepared, err := PrepareParameters(input)
	if err != nil {
		t.Fatal(err)
	}
	raw := prepared.RawParameters()
	if raw.SlotsToCoeffsParameters.Levels == nil || raw.CoeffsToSlotsParameters.Levels == nil {
		t.Fatal("non-nil empty DFT level topology collapsed to nil")
	}
	if raw.IterationsParameters.BootstrappingPrecision == nil {
		t.Fatal("non-nil empty iteration precision collapsed to nil")
	}
}

func TestPreparedParametersVerifyRejectsInternalDrift(t *testing.T) {
	baseline, err := PrepareParameters(prepareParametersTestInput(t))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*PreparedParameters)
	}{
		{
			name: "raw circuit order",
			mutate: func(prepared *PreparedParameters) {
				prepared.raw.CircuitOrder = Custom
			},
		},
		{
			name: "effective scaling",
			mutate: func(prepared *PreparedParameters) {
				prepared.effective.CoeffsToSlotsParameters.Scaling.SetInt64(123)
			},
		},
		{
			name: "derived coefficient",
			mutate: func(prepared *PreparedParameters) {
				prepared.mod1Parameters.Mod1Poly.Coeffs[1][0].SetInt64(123)
			},
		},
		{
			name: "stored digest",
			mutate: func(prepared *PreparedParameters) {
				prepared.digest[0] ^= 1
			},
		},
		{
			name: "seal version",
			mutate: func(prepared *PreparedParameters) {
				prepared.sealVersion++
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := PreparedParameters{
				sealVersion:    baseline.sealVersion,
				raw:            cloneBootstrappingParameters(baseline.raw),
				effective:      cloneBootstrappingParameters(baseline.effective),
				mod1Parameters: cloneMod1Parameters(baseline.mod1Parameters),
				digest:         baseline.digest,
			}
			test.mutate(&candidate)
			if err := candidate.Verify(); err == nil {
				t.Fatal("internally drifted prepared parameters unexpectedly verified")
			}
		})
	}
}

func TestPrepareParametersConjugateInvariantKeepsRawAndAdjustsOnlyEffective(t *testing.T) {
	conjugateInvariant, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{50, 40, 40},
		LogP:            []int{50},
		LogDefaultScale: 40,
		RingType:        ring.ConjugateInvariant,
	})
	if err != nil {
		t.Fatal(err)
	}
	standard, err := conjugateInvariant.StandardParameters()
	if err != nil {
		t.Fatal(err)
	}

	input := prepareParametersTestInput(t)
	input.ResidualParameters = conjugateInvariant
	input.BootstrappingParameters = standard
	input.SlotsToCoeffsParameters.LogSlots = standard.LogMaxSlots()
	input.CoeffsToSlotsParameters.LogSlots = standard.LogMaxSlots()
	originalScaling, err := input.SlotsToCoeffsParameters.Scaling.GobEncode()
	if err != nil {
		t.Fatal(err)
	}

	prepared, err := PrepareParameters(input)
	if err != nil {
		t.Fatal(err)
	}
	gotRaw, err := prepared.RawParameters().SlotsToCoeffsParameters.Scaling.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRaw, originalScaling) {
		t.Fatal("conjugate-invariant preparation changed the sealed raw S2C scaling")
	}

	// A standard-ring reference with an explicit 0.5 S2C factor is an
	// independent oracle for the legacy CI adjustment before runtime scaling.
	reference := cloneBootstrappingParameters(input)
	reference.ResidualParameters = standard
	reference.SlotsToCoeffsParameters.Scaling = new(big.Float).SetFloat64(0.5)
	referencePrepared, err := PrepareParameters(reference)
	if err != nil {
		t.Fatal(err)
	}
	gotEffective, err := prepared.EffectiveParameters().SlotsToCoeffsParameters.Scaling.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	wantEffective, err := referencePrepared.EffectiveParameters().SlotsToCoeffsParameters.Scaling.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotEffective, wantEffective) {
		t.Fatal("conjugate-invariant effective S2C scaling does not match the legacy 0.5 adjustment")
	}
}

func TestNewEvaluatorConsumesPreparedParametersOnStockPath(t *testing.T) {
	input := prepareParametersTestInput(t)
	prepared, err := PrepareParameters(input)
	if err != nil {
		t.Fatal(err)
	}

	keyGenerator := rlwe.NewKeyGenerator(input.ResidualParameters)
	secretKey := keyGenerator.GenSecretKeyNew()
	evaluationKeys, _, err := input.GenEvaluationKeys(secretKey)
	if err != nil {
		t.Fatal(err)
	}

	before := dft.SnapshotMatrixConstructionCounters()
	evaluator, err := NewEvaluator(input, evaluationKeys)
	if err != nil {
		t.Fatal(err)
	}
	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil {
		t.Fatal(err)
	}
	if got := [4]uint64{delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming()}; got != [4]uint64{2, 0, 0, 0} {
		t.Fatalf("stock constructor DFT delta = %v, want [2 0 0 0]", got)
	}
	if len(evaluator.C2SDFTMatrix.Matrices) != input.CoeffsToSlotsParameters.Depth(false) || len(evaluator.S2CDFTMatrix.Matrices) != input.SlotsToCoeffsParameters.Depth(false) {
		t.Fatalf("stock constructor installed wrong DFT factor counts: C2S=%d S2C=%d", len(evaluator.C2SDFTMatrix.Matrices), len(evaluator.S2CDFTMatrix.Matrices))
	}

	stockDigest, err := digestPreparedParameters(prepared.RawParameters(), evaluator.Parameters, evaluator.Mod1Parameters)
	if err != nil {
		t.Fatal(err)
	}
	if stockDigest != prepared.Digest() {
		t.Fatalf("stock constructor did not consume the prepared effective state: got %X, want %X", stockDigest, prepared.Digest())
	}
}

func TestEvaluatorShallowCopyKeepsBootstrappingParametersForNestedEvaluators(t *testing.T) {
	conjugateInvariant, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{50, 40, 40},
		LogP:            []int{50},
		LogDefaultScale: 40,
		RingType:        ring.ConjugateInvariant,
	})
	if err != nil {
		t.Fatal(err)
	}
	standard, err := conjugateInvariant.StandardParameters()
	if err != nil {
		t.Fatal(err)
	}
	input := prepareParametersTestInput(t)
	input.ResidualParameters = conjugateInvariant
	input.BootstrappingParameters = standard
	input.SlotsToCoeffsParameters.LogSlots = standard.LogMaxSlots()
	input.CoeffsToSlotsParameters.LogSlots = standard.LogMaxSlots()

	secretKey := rlwe.NewKeyGenerator(conjugateInvariant).GenSecretKeyNew()
	evaluationKeys, _, err := input.GenEvaluationKeys(secretKey)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := NewEvaluator(input, evaluationKeys)
	if err != nil {
		t.Fatal(err)
	}
	shallow := evaluator.ShallowCopy()

	identity, err := shallow.DFTEvaluator.RuntimeIdentitySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	parameterPayload, err := standard.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := identity.ParametersDigest(), sha256.Sum256(parameterPayload); got != want {
		t.Fatalf("shallow DFT evaluator parameters digest = %X, want bootstrapping digest %X", got, want)
	}
	if !shallow.Mod1Evaluator.PolynomialEvaluator.Parameters.Equal(&standard) {
		t.Fatal("shallow Mod1 polynomial evaluator uses residual instead of bootstrapping parameters")
	}
}

func TestPrepareParametersRejectsInvalidInputsWithoutDFTConstruction(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Parameters)
	}{
		{
			name: "sin with double angle",
			mutate: func(parameters *Parameters) {
				parameters.Mod1ParametersLiteral.DoubleAngle = 1
			},
		},
		{
			name: "inconsistent C2S level",
			mutate: func(parameters *Parameters) {
				parameters.CoeffsToSlotsParameters.LevelQ++
			},
		},
		{
			name: "invalid circuit order",
			mutate: func(parameters *Parameters) {
				parameters.CircuitOrder = CircuitOrder(127)
			},
		},
		{
			name: "non-positive K",
			mutate: func(parameters *Parameters) {
				parameters.Mod1ParametersLiteral.K = 0
			},
		},
		{
			name: "negative message ratio",
			mutate: func(parameters *Parameters) {
				parameters.Mod1ParametersLiteral.LogMessageRatio = -1
			},
		},
		{
			name: "negative Mod1 degree",
			mutate: func(parameters *Parameters) {
				parameters.CircuitOrder = DecodeThenModUp
				parameters.Mod1ParametersLiteral.Mod1Degree = -2
			},
		},
		{
			name: "negative Mod1 inverse degree",
			mutate: func(parameters *Parameters) {
				parameters.CircuitOrder = Custom
				parameters.Mod1ParametersLiteral.Mod1InvDegree = -1
			},
		},
		{
			name: "negative double angle",
			mutate: func(parameters *Parameters) {
				parameters.CircuitOrder = Custom
				parameters.Mod1ParametersLiteral.DoubleAngle = -1
			},
		},
		{
			name: "NaN Mod1 scaling",
			mutate: func(parameters *Parameters) {
				parameters.CircuitOrder = Custom
				parameters.Mod1ParametersLiteral.Scaling = math.NaN()
			},
		},
		{
			name: "infinite Mod1 scaling",
			mutate: func(parameters *Parameters) {
				parameters.CircuitOrder = Custom
				parameters.Mod1ParametersLiteral.Scaling = math.Inf(1)
			},
		},
		{
			name: "non-real double-angle scaling root",
			mutate: func(parameters *Parameters) {
				parameters.CircuitOrder = Custom
				parameters.Mod1ParametersLiteral.Mod1Type = mod1.CosContinuous
				parameters.Mod1ParametersLiteral.DoubleAngle = 1
				parameters.Mod1ParametersLiteral.Scaling = -1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := prepareParametersTestInput(t)
			test.mutate(&input)
			before := dft.SnapshotMatrixConstructionCounters()
			var prepareErr error
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("invalid PrepareParameters panicked instead of returning an error: %v", recovered)
					}
				}()
				_, prepareErr = PrepareParameters(input)
			}()
			if prepareErr == nil {
				t.Fatal("invalid parameters unexpectedly accepted")
			}
			after := dft.SnapshotMatrixConstructionCounters()
			delta, err := after.Delta(before)
			if err != nil {
				t.Fatal(err)
			}
			if got := [4]uint64{delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming()}; got != [4]uint64{} {
				t.Fatalf("invalid PrepareParameters constructed DFT data: delta=%v", got)
			}
		})
	}

	if err := (PreparedParameters{}).Verify(); err == nil {
		t.Fatal("zero PreparedParameters unexpectedly verified")
	}
}

func prepareParametersTestInput(t *testing.T) Parameters {
	t.Helper()
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{50, 40, 40},
		LogP:            []int{50},
		LogDefaultScale: 40,
	})
	if err != nil {
		t.Fatal(err)
	}

	return Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: dft.MatrixLiteral{
			Type:         dft.HomomorphicDecode,
			LogSlots:     params.LogMaxSlots(),
			LevelQ:       0,
			LevelP:       0,
			Levels:       []int{1},
			Format:       dft.Standard,
			Scaling:      new(big.Float).SetPrec(192).SetMode(big.AwayFromZero).SetRat(big.NewRat(7, 3)),
			LogBSGSRatio: 1,
		},
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ:          1,
			LogScale:        params.LogDefaultScale(),
			Mod1Type:        mod1.SinContinuous,
			Scaling:         1.125,
			LogMessageRatio: 4,
			K:               1,
			Mod1Degree:      1,
		},
		CoeffsToSlotsParameters: dft.MatrixLiteral{
			Type:         dft.HomomorphicEncode,
			LogSlots:     params.LogMaxSlots(),
			LevelQ:       2,
			LevelP:       0,
			Levels:       []int{1},
			Format:       dft.Standard,
			Scaling:      new(big.Float).SetPrec(160).SetMode(big.ToZero).SetRat(big.NewRat(5, 7)),
			LogBSGSRatio: 1,
		},
		IterationsParameters: &IterationsParameters{
			BootstrappingPrecision: []float64{19.25, 23.5},
			ReservedPrimeBitSize:   37,
		},
		EphemeralSecretWeight: 0,
		CircuitOrder:          ModUpThenEncode,
	}
}

func assertPreparedTestScaling(t *testing.T, got *big.Float, wantGob []byte, wantPrecision uint, wantMode big.RoundingMode) {
	t.Helper()
	if got == nil {
		t.Fatal("scaling is nil")
	}
	if got.Prec() != wantPrecision || got.Mode() != wantMode {
		t.Fatalf("scaling metadata = (prec=%d mode=%v), want (prec=%d mode=%v)", got.Prec(), got.Mode(), wantPrecision, wantMode)
	}
	gotGob, err := got.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotGob, wantGob) {
		t.Fatal("scaling value or exact metadata drifted")
	}
}
