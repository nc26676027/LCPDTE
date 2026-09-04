package homchain

import (
	"fmt"

	"github.com/nc26676027/LCPDTE/integer/securityparams"
	ckkspolynomial "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/polynomial"
	commonpolynomial "github.com/nc26676027/LCPDTE/lattigo/circuits/common/polynomial"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const (
	gaoA2BKernelN16L11InputLevel  = 17
	gaoA2BKernelN16L11OutputLevel = 5
	gaoA2BKernelN16L11LogSlots    = 11
	gaoA2BKernelN16L11Slots       = 1 << gaoA2BKernelN16L11LogSlots
)

const (
	// GaoA2BKernelN16L11KernelOnlyUnverified labels the exact-parameter,
	// sparse-packing vertical gate. It is not a complete A2B, refresh,
	// security, tree, or performance claim.
	GaoA2BKernelN16L11KernelOnlyUnverified GaoA2BKernelClaim = "lattigo_n16_l11_sparse_kernel_only_security_unverified_not_full_a2b"
)

// GaoA2BKernelN16L11Profile binds the Gao degree-46/R2 and shared ID/MSB
// graph to the exact local N16 parameter candidate and 2,048 active slots.
type GaoA2BKernelN16L11Profile struct {
	claim                       GaoA2BKernelClaim
	inputLevel                  int
	slots                       int
	logDimensions               ring.Dimensions
	operationalEncoderPrecision uint
	inputScale                  ExactScaleSnapshot
	booleanOutputLevel          int
	booleanOutputScale          ExactScaleSnapshot
	exponentialDegree           int
	squaringRounds              int
	lutDegrees                  [2]int
	exponentialProfileDigest    string
	exponentialArtifactDigest   string
	lutTableDigest              string
	parameterDigest             string
	operandGraphDigest          string
	operandPlan                 GaoA2BKernelOperandPlan
	keyProfile                  GaoA2BKernelKeyProfile
	digest                      string
}

func (p GaoA2BKernelN16L11Profile) Claim() GaoA2BKernelClaim { return p.claim }
func (p GaoA2BKernelN16L11Profile) InputLevel() int          { return p.inputLevel }
func (p GaoA2BKernelN16L11Profile) Slots() int               { return p.slots }
func (p GaoA2BKernelN16L11Profile) LogDimensions() ring.Dimensions {
	return p.logDimensions
}
func (p GaoA2BKernelN16L11Profile) OperationalEncoderPrecision() uint {
	return p.operationalEncoderPrecision
}
func (p GaoA2BKernelN16L11Profile) InputScale() ExactScaleSnapshot { return p.inputScale }
func (p GaoA2BKernelN16L11Profile) BooleanOutputLevel() int        { return p.booleanOutputLevel }
func (p GaoA2BKernelN16L11Profile) BooleanOutputScale() ExactScaleSnapshot {
	return p.booleanOutputScale
}
func (p GaoA2BKernelN16L11Profile) ExponentialDegree() int { return p.exponentialDegree }
func (p GaoA2BKernelN16L11Profile) SquaringRounds() int    { return p.squaringRounds }
func (p GaoA2BKernelN16L11Profile) LUTDegrees() [2]int     { return p.lutDegrees }
func (p GaoA2BKernelN16L11Profile) ExponentialProfileDigest() string {
	return p.exponentialProfileDigest
}
func (p GaoA2BKernelN16L11Profile) ExponentialArtifactDigest() string {
	return p.exponentialArtifactDigest
}
func (p GaoA2BKernelN16L11Profile) LUTTableDigest() string  { return p.lutTableDigest }
func (p GaoA2BKernelN16L11Profile) ParameterDigest() string { return p.parameterDigest }
func (p GaoA2BKernelN16L11Profile) OperandGraphDigest() string {
	return p.operandGraphDigest
}
func (p GaoA2BKernelN16L11Profile) OperandPlan() GaoA2BKernelOperandPlan {
	return p.operandPlan
}
func (p GaoA2BKernelN16L11Profile) KeyProfile() GaoA2BKernelKeyProfile {
	result := p.keyProfile
	result.rotationIndexes = p.keyProfile.RequiredRotationIndexes()
	return result
}
func (p GaoA2BKernelN16L11Profile) InputNormalization() string {
	return "refreshed-normalized-y=(J+p/16)/16;kernel-grid-J=0-gives-y=p/256"
}
func (p GaoA2BKernelN16L11Profile) RuntimePath() string {
	return "n16-l11-sparse-normalized-y;exp46-chebyshev-packed-vector256/evaluate;mulrelin-rescale^2;id-msb-degree15-packed-vectors/evaluate-multi-poly/shared-power-basis/target-S43;conjugate-add^2"
}
func (p GaoA2BKernelN16L11Profile) Digest() string { return p.digest }

// GaoA2BKernelN16L11Circuit is a second adapter. The accepted LogN=5
// functional circuit remains unchanged.
type GaoA2BKernelN16L11Circuit struct {
	params             ckks.Parameters
	encoder            *ckks.Encoder
	profile            GaoA2BKernelN16L11Profile
	exponentialOperand ckkspolynomial.PolynomialVector
	identityOperand    ckkspolynomial.PolynomialVector
	msbOperand         ckkspolynomial.PolynomialVector
}

// NewGaoA2BKernelN16L11Circuit seals the exact Gao polynomials for the local
// N16/L11 kernel-only gate.
func NewGaoA2BKernelN16L11Circuit(params ckks.Parameters, encoder *ckks.Encoder) (*GaoA2BKernelN16L11Circuit, error) {
	expected, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		return nil, fmt.Errorf("homchain: construct canonical N16 Gao parameters: %w", err)
	}
	if !params.Equal(&expected) || params.LogN() != 16 || params.MaxLevel() != 20 ||
		params.MaxLevelP() != 6 || params.LogDefaultScale() != 43 ||
		params.RingType() != ring.Standard || params.LevelsConsumedPerRescaling() != 1 {
		return nil, fmt.Errorf("homchain: N16/L11 Gao kernel requires the exact lattigo-gao-compatible-n16-v1 parameters")
	}
	if encoder == nil {
		return nil, fmt.Errorf("homchain: N16/L11 Gao kernel encoder is nil")
	}
	encoderParameters := encoder.GetParameters()
	if !params.Equal(&encoderParameters) || encoder.Prec() != gaoA2BKernelEncoderPrecision {
		return nil, fmt.Errorf("homchain: N16/L11 Gao kernel requires a parameter-matched 256-bit encoder")
	}

	exponentialProfile, err := NewGaoA2BExpProfile()
	if err != nil {
		return nil, err
	}
	lutProfile, err := NewGaoA2BLUTProfile()
	if err != nil {
		return nil, err
	}
	exponentialOperand, err := newA2BKernelPackedPolynomial(exponentialProfile.LattigoPolynomial(), gaoA2BKernelN16L11Slots)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct N16/L11 Gao exponential operand: %w", err)
	}
	identityPolynomial, err := lutProfile.LattigoPolynomial(GaoA2BLUTIdentity)
	if err != nil {
		return nil, err
	}
	identityOperand, err := newA2BKernelPackedPolynomial(identityPolynomial, gaoA2BKernelN16L11Slots)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct N16/L11 Gao identity operand: %w", err)
	}
	msbPolynomial, err := lutProfile.LattigoPolynomial(GaoA2BLUTMSB)
	if err != nil {
		return nil, err
	}
	msbOperand, err := newA2BKernelPackedPolynomial(msbPolynomial, gaoA2BKernelN16L11Slots)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct N16/L11 Gao MSB operand: %w", err)
	}
	operandPlan, err := inspectA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, gaoA2BKernelN16L11Slots)
	if err != nil {
		return nil, err
	}
	inputScale, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil, err
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal N16/L11 Gao kernel parameters: %w", err)
	}
	keyProfile := GaoA2BKernelKeyProfile{
		requiresRelinearization: true,
		requiresConjugation:     true,
		conjugationElement:      params.GaloisElementForComplexConjugation(),
		rotationIndexes:         []int{},
	}
	keyProfile.digest = a2bKernelDigestText(fmt.Sprintf(
		"n16-l11-kernel-keys-v1;relinearization=true;conjugation=true;conjugation-element=%d;rotations=[];min-level-q=%d;level-p=%d",
		keyProfile.conjugationElement, gaoA2BKernelN16L11InputLevel, params.MaxLevelP(),
	))
	profile := GaoA2BKernelN16L11Profile{
		claim:      GaoA2BKernelN16L11KernelOnlyUnverified,
		inputLevel: gaoA2BKernelN16L11InputLevel, slots: gaoA2BKernelN16L11Slots,
		logDimensions:               ring.Dimensions{Rows: 0, Cols: gaoA2BKernelN16L11LogSlots},
		operationalEncoderPrecision: encoder.Prec(), inputScale: inputScale,
		booleanOutputLevel: gaoA2BKernelN16L11OutputLevel, booleanOutputScale: inputScale,
		exponentialDegree: exponentialProfile.Degree(), squaringRounds: exponentialProfile.SquaringRounds(),
		lutDegrees:                [2]int{lutProfile.Degree(), lutProfile.Degree()},
		exponentialProfileDigest:  exponentialProfile.Digest(),
		exponentialArtifactDigest: exponentialProfile.ArtifactDigest(),
		lutTableDigest:            lutProfile.TableDigest(), parameterDigest: a2bKernelDigestBytes(parameterBytes),
		operandGraphDigest: digestA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, operandPlan),
		operandPlan:        operandPlan, keyProfile: keyProfile,
	}
	profile.digest = digestGaoA2BKernelN16L11Profile(profile)
	circuit := &GaoA2BKernelN16L11Circuit{
		params: params, encoder: encoder.ShallowCopy(), profile: profile,
		exponentialOperand: exponentialOperand, identityOperand: identityOperand, msbOperand: msbOperand,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *GaoA2BKernelN16L11Circuit) Profile() GaoA2BKernelN16L11Profile {
	if c == nil {
		return GaoA2BKernelN16L11Profile{}
	}
	result := c.profile
	result.keyProfile = c.profile.KeyProfile()
	return result
}

type gaoA2BKernelN16L11SparseCoefficientGetter struct {
	values []*bignum.Complex
}

func (g *gaoA2BKernelN16L11SparseCoefficientGetter) GetVectorCoefficient(
	polynomial commonpolynomial.PolynomialVector,
	degree int,
) []*bignum.Complex {
	for index := range g.values {
		g.values[index] = nil
	}
	for polynomialIndex, slots := range polynomial.Mapping {
		for _, slot := range slots {
			g.values[slot] = polynomial.Value[polynomialIndex].Coeffs[degree]
		}
	}
	return g.values
}

func (*gaoA2BKernelN16L11SparseCoefficientGetter) GetSingleCoefficient(
	polynomial commonpolynomial.Polynomial,
	degree int,
) *bignum.Complex {
	return polynomial.Coeffs[degree]
}

// GaoA2BKernelN16L11Evaluator owns the sparse coefficient encoder and a
// private CKKS evaluator copy bound to one key set.
type GaoA2BKernelN16L11Evaluator struct {
	circuit            *GaoA2BKernelN16L11Circuit
	source             *ckks.Evaluator
	ckks               *ckks.Evaluator
	polynomial         *ckkspolynomial.Evaluator
	coefficientGetter  *gaoA2BKernelN16L11SparseCoefficientGetter
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	conjugationKey     *rlwe.GaloisKey
	operationalEncoder *ckks.Encoder
}

func (c *GaoA2BKernelN16L11Circuit) BindEvaluator(evaluator *ckks.Evaluator) (*GaoA2BKernelN16L11Evaluator, error) {
	if c == nil {
		return nil, fmt.Errorf("homchain: nil N16/L11 Gao kernel circuit")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if evaluator == nil || evaluator.GetParameters() == nil || !c.params.Equal(evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: N16/L11 Gao evaluator parameters do not match the circuit")
	}
	keySet, ok := evaluator.EvaluationKeySet.(*rlwe.MemEvaluationKeySet)
	if !ok || keySet == nil {
		return nil, fmt.Errorf("homchain: N16/L11 Gao evaluator requires an in-memory evaluation-key set")
	}
	relinearizationKey, conjugationKey, err := preflightGaoA2BKernelN16L11Keys(c.profile, keySet, nil, nil)
	if err != nil {
		return nil, err
	}
	operational := evaluator.ShallowCopy()
	operationalEncoder := c.encoder.ShallowCopy()
	operational.Encoder = operationalEncoder
	polynomialEvaluator := ckkspolynomial.NewEvaluator(c.params, operational)
	coefficientGetter := &gaoA2BKernelN16L11SparseCoefficientGetter{
		values: make([]*bignum.Complex, c.profile.slots),
	}
	polynomialEvaluator.Evaluator.CoefficientGetter = coefficientGetter
	bound, ok := polynomialEvaluator.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || bound != operational {
		return nil, fmt.Errorf("homchain: N16/L11 Gao polynomial graph is not bound to the private CKKS evaluator")
	}
	return &GaoA2BKernelN16L11Evaluator{
		circuit: c, source: evaluator, ckks: operational, polynomial: polynomialEvaluator,
		coefficientGetter: coefficientGetter, keySet: keySet,
		relinearizationKey: relinearizationKey, conjugationKey: conjugationKey,
		operationalEncoder: operationalEncoder,
	}, nil
}

func (e *GaoA2BKernelN16L11Evaluator) OperationalEncoderPrecision() uint {
	if e == nil || e.operationalEncoder == nil {
		return 0
	}
	return e.operationalEncoder.Prec()
}

func (e *GaoA2BKernelN16L11Evaluator) SparseCoefficientSlots() int {
	if e == nil || e.coefficientGetter == nil {
		return 0
	}
	return len(e.coefficientGetter.values)
}

func (e *GaoA2BKernelN16L11Evaluator) EvaluateNew(input *rlwe.Ciphertext) (GaoA2BKernelResult, error) {
	if e == nil || e.circuit == nil || e.ckks == nil || e.polynomial == nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: nil N16/L11 Gao kernel evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		return GaoA2BKernelResult{}, err
	}
	if err := e.validateInput(input); err != nil {
		return GaoA2BKernelResult{}, err
	}
	if err := e.preflightGraphAndKeys(); err != nil {
		return GaoA2BKernelResult{}, err
	}
	exponentialOperand, err := cloneA2BKernelPolynomialVector(e.circuit.exponentialOperand)
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	identityOperand, err := cloneA2BKernelPolynomialVector(e.circuit.identityOperand)
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	msbOperand, err := cloneA2BKernelPolynomialVector(e.circuit.msbOperand)
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	plan, err := inspectA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, e.circuit.profile.slots)
	if err != nil || plan != e.circuit.profile.operandPlan {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao cloned operand plan changed")
	}
	if digestA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, plan) != e.circuit.profile.operandGraphDigest {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao cloned operand digest changed")
	}

	inputBefore := input.CopyNew()
	states := make([]GaoA2BKernelCiphertextState, 0, 8)
	state, err := snapshotA2BKernelState(GaoA2BKernelStageInput, input, e.circuit.params.DefaultScale())
	if err != nil || !state.ScaleExact {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao input scale state changed: %w", err)
	}
	states = append(states, state)
	counts := GaoA2BKernelOperationCounts{}

	exponential, err := e.polynomial.Evaluate(input, exponentialOperand, e.circuit.params.DefaultScale())
	counts.ExpPolynomialEvaluations++
	if err != nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: evaluate N16/L11 Gao exponential polynomial: %w", err)
	}
	wantExponentialLevel := input.Level() - exponentialOperand.Depth()
	if exponential.Level() != wantExponentialLevel || exponential.Degree() != 1 {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao exponential state changed")
	}
	state, err = snapshotA2BKernelState(GaoA2BKernelStageExponential, exponential, e.circuit.params.DefaultScale())
	if err != nil || !state.ScaleExact {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao exponential scale state changed: %w", err)
	}
	states = append(states, state)
	exponentialBase := exponential.CopyNew()

	root := exponential
	for round, stage := range [...]GaoA2BKernelStage{GaoA2BKernelStageSquare0, GaoA2BKernelStageRootOfUnity} {
		previousScale := root.Scale
		previousLevel := root.Level()
		root, err = e.ckks.MulRelinNew(root, root)
		if err != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao square %d: %w", round, err)
		}
		if err = e.ckks.Rescale(root, root); err != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao square %d rescale: %w", round, err)
		}
		counts.ComplexSquarings++
		expectedScale := previousScale.Mul(previousScale).Div(rlwe.NewScale(e.circuit.params.Q()[previousLevel]))
		if root.Level() != previousLevel-1 || root.Degree() != 1 {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao square %d state changed", round)
		}
		state, err = snapshotA2BKernelState(stage, root, expectedScale)
		if err != nil || !state.ScaleExact {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao square %d scale state changed: %w", round, err)
		}
		states = append(states, state)
	}
	rootOfUnity := root.CopyNew()

	lutOutputs, err := e.polynomial.EvaluateMultiPoly(
		root, []interface{}{identityOperand, msbOperand}, e.circuit.params.DefaultScale(),
	)
	counts.MultiPolynomialEvaluations++
	counts.SharedPowerBases++
	if err != nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: evaluate N16/L11 Gao shared ID/MSB LUT: %w", err)
	}
	if len(lutOutputs) != 2 || lutOutputs[0] == nil || lutOutputs[1] == nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao shared LUT output shape changed")
	}
	wantLUTLevel := root.Level() - identityOperand.Depth()
	for index, output := range lutOutputs {
		if output.Level() != wantLUTLevel || output.Degree() != 1 {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao LUT output %d state changed", index)
		}
	}
	for index, stage := range [...]GaoA2BKernelStage{GaoA2BKernelStageIdentityLUT, GaoA2BKernelStageMSBLUT} {
		state, err = snapshotA2BKernelState(stage, lutOutputs[index], e.circuit.params.DefaultScale())
		if err != nil || !state.ScaleExact {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao LUT output %d scale changed: %w", index, err)
		}
		states = append(states, state)
	}

	for index, stage := range [...]GaoA2BKernelStage{GaoA2BKernelStageIdentityOutput, GaoA2BKernelStageMSBOutput} {
		outputScale := lutOutputs[index].Scale
		conjugate, conjugateErr := e.ckks.ConjugateNew(lutOutputs[index])
		if conjugateErr != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: conjugate N16/L11 Gao LUT %d: %w", index, conjugateErr)
		}
		counts.Conjugations++
		if err = e.ckks.Add(lutOutputs[index], conjugate, lutOutputs[index]); err != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: recover N16/L11 Gao LUT %d real part: %w", index, err)
		}
		counts.RealRecoveries++
		state, err = snapshotA2BKernelState(stage, lutOutputs[index], outputScale)
		if err != nil || !state.ScaleExact {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao real output %d scale changed: %w", index, err)
		}
		states = append(states, state)
	}

	if !input.Equal(inputBefore) {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao kernel mutated its input")
	}
	return GaoA2BKernelResult{
		identity: lutOutputs[0], msb: lutOutputs[1],
		exponentialBase: exponentialBase, rootOfUnity: rootOfUnity,
		provenance: GaoA2BKernelProvenance{
			profileDigest: e.circuit.profile.digest, parameterDigest: e.circuit.profile.parameterDigest,
			operandGraphDigest:     e.circuit.profile.operandGraphDigest,
			keyProfileDigest:       e.circuit.profile.keyProfile.digest,
			operationalEncoderPrec: e.OperationalEncoderPrecision(),
			inputNormalization:     e.circuit.profile.InputNormalization(), operandPlan: plan,
			runtimePath: e.circuit.profile.RuntimePath(), states: states, operationCounts: counts,
		},
	}, nil
}

func (e *GaoA2BKernelN16L11Evaluator) validateInput(input *rlwe.Ciphertext) error {
	if input == nil || input.MetaData == nil {
		return fmt.Errorf("homchain: N16/L11 Gao kernel input is nil or has nil metadata")
	}
	profile := e.circuit.profile
	if input.Level() != profile.inputLevel || input.Degree() != 1 ||
		input.LogN() != e.circuit.params.LogN() || !input.IsBatched || !input.IsNTT ||
		input.LogDimensions != profile.logDimensions || input.Slots() != profile.slots ||
		!profile.inputScale.EqualScale(input.Scale) {
		scale, scaleErr := NewExactScaleSnapshot(input.Scale)
		gotScale := "invalid"
		if scaleErr == nil {
			gotScale = scale.ValueHex()
		}
		return fmt.Errorf(
			"homchain: N16/L11 Gao kernel input got level=%d degree=%d LogN=%d batched=%t NTT=%t dimensions=%d,%d slots=%d scale=%s; want level=%d degree=1 LogN=%d batched=true NTT=true dimensions=%d,%d slots=%d scale=%s",
			input.Level(), input.Degree(), input.LogN(), input.IsBatched, input.IsNTT,
			input.LogDimensions.Rows, input.LogDimensions.Cols, input.Slots(), gotScale,
			profile.inputLevel, e.circuit.params.LogN(), profile.logDimensions.Rows,
			profile.logDimensions.Cols, profile.slots, profile.inputScale.ValueHex(),
		)
	}
	return nil
}

func (e *GaoA2BKernelN16L11Evaluator) preflightGraphAndKeys() error {
	if e.source == nil || e.source.EvaluationKeySet != e.keySet || e.ckks == nil ||
		e.ckks.EvaluationKeySet != e.keySet || e.ckks.Encoder != e.operationalEncoder ||
		e.operationalEncoder == nil || e.operationalEncoder.Prec() != gaoA2BKernelEncoderPrecision ||
		e.coefficientGetter == nil || len(e.coefficientGetter.values) != e.circuit.profile.slots ||
		e.polynomial == nil || e.polynomial.Evaluator.CoefficientGetter != e.coefficientGetter {
		return fmt.Errorf("homchain: N16/L11 Gao evaluator graph changed before evaluation")
	}
	relinearizationKey, conjugationKey, err := preflightGaoA2BKernelN16L11Keys(
		e.circuit.profile, e.keySet, e.relinearizationKey, e.conjugationKey,
	)
	if err != nil || relinearizationKey != e.relinearizationKey || conjugationKey != e.conjugationKey {
		return fmt.Errorf("homchain: N16/L11 Gao key identity changed before evaluation: %w", err)
	}
	return nil
}

func preflightGaoA2BKernelN16L11Keys(
	profile GaoA2BKernelN16L11Profile,
	keySet *rlwe.MemEvaluationKeySet,
	expectedRelinearization *rlwe.RelinearizationKey,
	expectedConjugation *rlwe.GaloisKey,
) (*rlwe.RelinearizationKey, *rlwe.GaloisKey, error) {
	if keySet == nil {
		return nil, nil, fmt.Errorf("homchain: N16/L11 Gao evaluation-key set is nil")
	}
	relinearizationKey, err := keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, nil, fmt.Errorf("homchain: N16/L11 Gao relinearization key is missing: %v", err)
	}
	if expectedRelinearization != nil && relinearizationKey != expectedRelinearization {
		return nil, nil, fmt.Errorf("homchain: N16/L11 Gao relinearization key identity changed")
	}
	conjugationKey, err := keySet.GetGaloisKey(profile.keyProfile.conjugationElement)
	if err != nil || conjugationKey == nil {
		return nil, nil, fmt.Errorf("homchain: N16/L11 Gao conjugation key is missing: %v", err)
	}
	if expectedConjugation != nil && conjugationKey != expectedConjugation {
		return nil, nil, fmt.Errorf("homchain: N16/L11 Gao conjugation key identity changed")
	}
	if relinearizationKey.LevelQ() < profile.inputLevel || relinearizationKey.LevelP() != 6 ||
		conjugationKey.LevelQ() < profile.inputLevel || conjugationKey.LevelP() != 6 ||
		conjugationKey.GaloisElement != profile.keyProfile.conjugationElement {
		return nil, nil, fmt.Errorf("homchain: N16/L11 Gao evaluation keys have insufficient levels or wrong P/conjugation state")
	}
	return relinearizationKey, conjugationKey, nil
}

func (c *GaoA2BKernelN16L11Circuit) validate() error {
	if c == nil || c.encoder == nil {
		return fmt.Errorf("homchain: nil N16/L11 Gao kernel circuit")
	}
	expected, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		return err
	}
	encoderParameters := c.encoder.GetParameters()
	if !c.params.Equal(&expected) || !c.params.Equal(&encoderParameters) ||
		c.encoder.Prec() != gaoA2BKernelEncoderPrecision {
		return fmt.Errorf("homchain: N16/L11 Gao parameters or encoder changed")
	}
	exponentialProfile, err := NewGaoA2BExpProfile()
	if err != nil {
		return err
	}
	lutProfile, err := NewGaoA2BLUTProfile()
	if err != nil {
		return err
	}
	parameterBytes, err := c.params.MarshalBinary()
	if err != nil {
		return err
	}
	plan, err := inspectA2BKernelOperands(
		c.exponentialOperand, c.identityOperand, c.msbOperand, gaoA2BKernelN16L11Slots,
	)
	if err != nil || plan != c.profile.operandPlan ||
		digestA2BKernelOperands(c.exponentialOperand, c.identityOperand, c.msbOperand, plan) != c.profile.operandGraphDigest {
		return fmt.Errorf("homchain: N16/L11 Gao sealed operand graph changed")
	}
	if c.profile.claim != GaoA2BKernelN16L11KernelOnlyUnverified ||
		c.profile.inputLevel != gaoA2BKernelN16L11InputLevel ||
		c.profile.booleanOutputLevel != gaoA2BKernelN16L11OutputLevel ||
		c.profile.slots != gaoA2BKernelN16L11Slots ||
		c.profile.logDimensions != (ring.Dimensions{Rows: 0, Cols: gaoA2BKernelN16L11LogSlots}) ||
		c.profile.operationalEncoderPrecision != gaoA2BKernelEncoderPrecision ||
		!c.profile.inputScale.EqualScale(c.params.DefaultScale()) ||
		!c.profile.booleanOutputScale.EqualScale(c.params.DefaultScale()) ||
		c.profile.exponentialDegree != exponentialProfile.Degree() ||
		c.profile.squaringRounds != exponentialProfile.SquaringRounds() ||
		c.profile.lutDegrees != [2]int{lutProfile.Degree(), lutProfile.Degree()} ||
		c.profile.exponentialProfileDigest != exponentialProfile.Digest() ||
		c.profile.exponentialArtifactDigest != exponentialProfile.ArtifactDigest() ||
		c.profile.lutTableDigest != lutProfile.TableDigest() ||
		c.profile.parameterDigest != a2bKernelDigestBytes(parameterBytes) ||
		!c.profile.keyProfile.requiresRelinearization || !c.profile.keyProfile.requiresConjugation ||
		c.profile.keyProfile.conjugationElement != c.params.GaloisElementForComplexConjugation() ||
		len(c.profile.keyProfile.rotationIndexes) != 0 ||
		c.profile.digest != digestGaoA2BKernelN16L11Profile(c.profile) {
		return fmt.Errorf("homchain: N16/L11 Gao profile or fixed contract changed")
	}
	return nil
}

func digestGaoA2BKernelN16L11Profile(profile GaoA2BKernelN16L11Profile) string {
	return a2bKernelDigestText(fmt.Sprintf(
		"gao-a2b-kernel-n16-l11-v1|claim=%s|input-level=%d|slots=%d|dimensions=%d,%d|encoder-precision=%d|input-scale=%s|boolean-output-level=%d|boolean-output-scale=%s|exp-degree=%d|squares=%d|lut-degrees=%v|input-normalization=%s|exp-profile=%s|exp-artifact=%s|lut-table=%s|params=%s|operand-graph=%s|operand=%s,%d,%v,%v,%v|key=%s|path=%s",
		profile.claim, profile.inputLevel, profile.slots, profile.logDimensions.Rows, profile.logDimensions.Cols,
		profile.operationalEncoderPrecision, profile.inputScale.canonicalString(), profile.booleanOutputLevel,
		profile.booleanOutputScale.canonicalString(), profile.exponentialDegree, profile.squaringRounds,
		profile.lutDegrees, profile.InputNormalization(), profile.exponentialProfileDigest,
		profile.exponentialArtifactDigest, profile.lutTableDigest, profile.parameterDigest,
		profile.operandGraphDigest, profile.operandPlan.exponentialEncoding, profile.operandPlan.exponentialSlots,
		profile.operandPlan.lutEncodings, profile.operandPlan.lutSlots, profile.operandPlan.outputOrder,
		profile.keyProfile.digest, profile.RuntimePath(),
	))
}
