package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	ckkspolynomial "github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	gaoA2BKernelInputLevel       = 17
	gaoA2BKernelOutputLevel      = 5
	gaoA2BKernelEncoderPrecision = uint(256)
)

// GaoA2BKernelClaim is the precise claim carried by this isolated kernel.
// The surrounding Boolean refresh, special-b0 path, and residual composition
// are deliberately outside this slice.
type GaoA2BKernelClaim string

const (
	GaoA2BKernelFunctionalLattigoOptimizedAdaptationNotSecureNotFullA2B GaoA2BKernelClaim = "functional_lattigo_optimized_adaptation_not_secure_not_full_a2b"
)

// GaoA2BKernelOperandEncoding names the actual evaluator dispatch used for
// every coefficient. Packed vectors route through the evaluator's bound
// Encoder.Encode path instead of Parameters.EncodingPrecision scalar rounding.
type GaoA2BKernelOperandEncoding string

const (
	GaoA2BKernelPackedVectorEncoding GaoA2BKernelOperandEncoding = "packed-vector/Encoder.Encode"
)

// GaoA2BKernelOperandPlan is an immutable description of the coefficient
// operands and the fixed output order used by the sealed graph.
type GaoA2BKernelOperandPlan struct {
	exponentialEncoding GaoA2BKernelOperandEncoding
	exponentialSlots    int
	lutEncodings        [2]GaoA2BKernelOperandEncoding
	lutSlots            [2]int
	outputOrder         [2]GaoA2BLUTKind
}

func (p GaoA2BKernelOperandPlan) ExponentialEncoding() GaoA2BKernelOperandEncoding {
	return p.exponentialEncoding
}
func (p GaoA2BKernelOperandPlan) ExponentialMappedSlots() int { return p.exponentialSlots }
func (p GaoA2BKernelOperandPlan) LUTEncodings() [2]GaoA2BKernelOperandEncoding {
	return p.lutEncodings
}
func (p GaoA2BKernelOperandPlan) LUTMappedSlots() [2]int { return p.lutSlots }
func (p GaoA2BKernelOperandPlan) OutputOrder() [2]GaoA2BLUTKind {
	return p.outputOrder
}

// GaoA2BKernelKeyProfile is the minimal fixed key requirement. Complex
// conjugation is one automorphism, not a slot rotation in this profile.
type GaoA2BKernelKeyProfile struct {
	requiresRelinearization bool
	requiresConjugation     bool
	conjugationElement      uint64
	rotationIndexes         []int
	digest                  string
}

func (p GaoA2BKernelKeyProfile) RequiresRelinearization() bool {
	return p.requiresRelinearization
}
func (p GaoA2BKernelKeyProfile) RequiresConjugation() bool { return p.requiresConjugation }
func (p GaoA2BKernelKeyProfile) ConjugationGaloisElement() uint64 {
	return p.conjugationElement
}
func (p GaoA2BKernelKeyProfile) RequiredRotationIndexes() []int {
	return append([]int(nil), p.rotationIndexes...)
}
func (p GaoA2BKernelKeyProfile) Digest() string { return p.digest }

// GaoA2BKernelProfile binds the exact parameters and both frozen coefficient
// profiles to one immutable functional circuit description.
type GaoA2BKernelProfile struct {
	claim                       GaoA2BKernelClaim
	inputLevel                  int
	slots                       int
	logDimensions               ring.Dimensions
	operationalEncoderPrecision uint
	inputScale                  ExactScaleSnapshot
	booleanOutputLevel          int
	booleanOutputScale          ExactScaleSnapshot
	exponentialProfileDigest    string
	exponentialArtifactDigest   string
	lutTableDigest              string
	parameterDigest             string
	operandGraphDigest          string
	operandPlan                 GaoA2BKernelOperandPlan
	keyProfile                  GaoA2BKernelKeyProfile
	digest                      string
}

func (p GaoA2BKernelProfile) Claim() GaoA2BKernelClaim { return p.claim }
func (p GaoA2BKernelProfile) InputLevel() int          { return p.inputLevel }
func (p GaoA2BKernelProfile) Slots() int               { return p.slots }
func (p GaoA2BKernelProfile) LogDimensions() ring.Dimensions {
	return p.logDimensions
}
func (p GaoA2BKernelProfile) OperationalEncoderPrecision() uint {
	return p.operationalEncoderPrecision
}
func (p GaoA2BKernelProfile) InputScale() ExactScaleSnapshot { return p.inputScale }
func (p GaoA2BKernelProfile) BooleanOutputLevel() int        { return p.booleanOutputLevel }
func (p GaoA2BKernelProfile) BooleanOutputScale() ExactScaleSnapshot {
	return p.booleanOutputScale
}
func (p GaoA2BKernelProfile) ExponentialProfileDigest() string {
	return p.exponentialProfileDigest
}
func (p GaoA2BKernelProfile) ExponentialArtifactDigest() string {
	return p.exponentialArtifactDigest
}
func (p GaoA2BKernelProfile) LUTTableDigest() string  { return p.lutTableDigest }
func (p GaoA2BKernelProfile) ParameterDigest() string { return p.parameterDigest }
func (p GaoA2BKernelProfile) OperandGraphDigest() string {
	return p.operandGraphDigest
}
func (p GaoA2BKernelProfile) OperandPlan() GaoA2BKernelOperandPlan {
	return p.operandPlan
}
func (p GaoA2BKernelProfile) KeyProfile() GaoA2BKernelKeyProfile {
	result := p.keyProfile
	result.rotationIndexes = p.keyProfile.RequiredRotationIndexes()
	return result
}
func (p GaoA2BKernelProfile) InputNormalization() string {
	return "refreshed-normalized-y=(J+p/16)/16;kernel-grid-J=0-gives-y=p/256"
}
func (p GaoA2BKernelProfile) RuntimePath() string {
	return "normalized-y-input;exp46-chebyshev-packed-vector/evaluate;mulrelin-rescale^2;id-msb-degree15-packed-vectors/evaluate-multi-poly/shared-power-basis/target-exact-default-S35;conjugate-add^2"
}
func (p GaoA2BKernelProfile) Digest() string { return p.digest }

// GaoA2BKernelFunctionalParameters returns the fixed LogN=5 functional-only
// parameter set. Q0 is 50 bits and Q1..Q20 are 35 bits; the kernel enters at
// level 17 with the exact 2^35 default scale.
func GaoA2BKernelFunctionalParameters() (ckks.Parameters, error) {
	logQ := make([]int, 21)
	logQ[0] = 50
	for i := 1; i < len(logQ); i++ {
		logQ[i] = 35
	}
	return ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            5,
		LogQ:            logQ,
		LogP:            []int{50},
		LogDefaultScale: 35,
	})
}

// GaoA2BKernelCircuit owns all three polynomial vectors. Callers cannot
// substitute coefficients, change output order, or split the shared LUT call.
type GaoA2BKernelCircuit struct {
	params             ckks.Parameters
	encoder            *ckks.Encoder
	profile            GaoA2BKernelProfile
	exponentialOperand ckkspolynomial.PolynomialVector
	identityOperand    ckkspolynomial.PolynomialVector
	msbOperand         ckkspolynomial.PolynomialVector
}

// NewGaoA2BKernelCircuit constructs and authenticates the sealed coefficient
// graph before any evaluator or ciphertext is accepted.
func NewGaoA2BKernelCircuit(params ckks.Parameters, encoder *ckks.Encoder) (*GaoA2BKernelCircuit, error) {
	expected, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		return nil, fmt.Errorf("homchain: construct Gao A2B kernel parameters: %w", err)
	}
	if !params.Equal(&expected) || params.RingType() != ring.Standard || params.LogN() != 5 ||
		params.MaxSlots() != 16 || params.MaxLevel() != 20 || params.MaxLevelP() != 0 ||
		params.LevelsConsumedPerRescaling() != 1 || params.LogDefaultScale() != 35 {
		return nil, fmt.Errorf("homchain: Gao A2B kernel requires exact LogN=5, LogQ=[50,35x20], LogP=[50], S35 parameters")
	}
	if encoder == nil {
		return nil, fmt.Errorf("homchain: Gao A2B kernel encoder is nil")
	}
	encoderParameters := encoder.GetParameters()
	if !params.Equal(&encoderParameters) || encoder.Prec() != gaoA2BKernelEncoderPrecision {
		return nil, fmt.Errorf("homchain: Gao A2B kernel requires a parameter-matched 256-bit encoder")
	}

	exponentialProfile, err := NewGaoA2BExpProfile()
	if err != nil {
		return nil, err
	}
	lutProfile, err := NewGaoA2BLUTProfile()
	if err != nil {
		return nil, err
	}
	exponentialOperand, err := newA2BKernelPackedPolynomial(exponentialProfile.LattigoPolynomial(), params.MaxSlots())
	if err != nil {
		return nil, fmt.Errorf("homchain: construct packed Gao A2B exponential: %w", err)
	}
	identityPolynomial, err := lutProfile.LattigoPolynomial(GaoA2BLUTIdentity)
	if err != nil {
		return nil, err
	}
	identityOperand, err := newA2BKernelPackedPolynomial(identityPolynomial, params.MaxSlots())
	if err != nil {
		return nil, fmt.Errorf("homchain: construct packed Gao A2B identity LUT: %w", err)
	}
	msbPolynomial, err := lutProfile.LattigoPolynomial(GaoA2BLUTMSB)
	if err != nil {
		return nil, err
	}
	msbOperand, err := newA2BKernelPackedPolynomial(msbPolynomial, params.MaxSlots())
	if err != nil {
		return nil, fmt.Errorf("homchain: construct packed Gao A2B MSB LUT: %w", err)
	}
	operandPlan, err := inspectA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, params.MaxSlots())
	if err != nil {
		return nil, err
	}
	operandGraphDigest := digestA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, operandPlan)
	inputScale, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil, fmt.Errorf("homchain: snapshot Gao A2B kernel input scale: %w", err)
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal Gao A2B kernel parameters: %w", err)
	}
	parameterDigest := a2bKernelDigestBytes(parameterBytes)
	keyProfile := GaoA2BKernelKeyProfile{
		requiresRelinearization: true,
		requiresConjugation:     true,
		conjugationElement:      params.GaloisElementForComplexConjugation(),
		rotationIndexes:         []int{},
	}
	keyProfile.digest = a2bKernelDigestText(fmt.Sprintf(
		"relinearization=true;conjugation=true;conjugation-element=%d;rotations=[];min-level-q=%d;level-p=0",
		keyProfile.conjugationElement, gaoA2BKernelInputLevel,
	))
	profile := GaoA2BKernelProfile{
		claim:      GaoA2BKernelFunctionalLattigoOptimizedAdaptationNotSecureNotFullA2B,
		inputLevel: gaoA2BKernelInputLevel, slots: params.MaxSlots(), logDimensions: params.LogMaxDimensions(),
		operationalEncoderPrecision: encoder.Prec(), inputScale: inputScale,
		booleanOutputLevel: gaoA2BKernelOutputLevel, booleanOutputScale: inputScale,
		exponentialProfileDigest:  exponentialProfile.Digest(),
		exponentialArtifactDigest: exponentialProfile.ArtifactDigest(),
		lutTableDigest:            lutProfile.TableDigest(), parameterDigest: parameterDigest,
		operandGraphDigest: operandGraphDigest,
		operandPlan:        operandPlan, keyProfile: keyProfile,
	}
	profile.digest = digestA2BKernelProfile(profile)
	circuit := &GaoA2BKernelCircuit{
		params: params, encoder: encoder.ShallowCopy(), profile: profile,
		exponentialOperand: exponentialOperand, identityOperand: identityOperand, msbOperand: msbOperand,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *GaoA2BKernelCircuit) Profile() GaoA2BKernelProfile {
	if c == nil {
		return GaoA2BKernelProfile{}
	}
	result := c.profile
	result.keyProfile = c.profile.KeyProfile()
	return result
}

// GaoA2BKernelEvaluator is a private, key-bound execution graph. The caller's
// evaluator remains on its original encoder precision.
type GaoA2BKernelEvaluator struct {
	circuit            *GaoA2BKernelCircuit
	source             *ckks.Evaluator
	ckks               *ckks.Evaluator
	polynomial         *ckkspolynomial.Evaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	conjugationKey     *rlwe.GaloisKey
	operationalEncoder *ckks.Encoder
}

// BindEvaluator preflights both required key identities, seals a private
// evaluator copy, and binds the 256-bit circuit encoder to every vector
// coefficient dispatch.
func (c *GaoA2BKernelCircuit) BindEvaluator(evaluator *ckks.Evaluator) (*GaoA2BKernelEvaluator, error) {
	if c == nil {
		return nil, fmt.Errorf("homchain: nil Gao A2B kernel circuit")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if evaluator == nil || evaluator.GetParameters() == nil || !c.params.Equal(evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: Gao A2B evaluator parameters do not match the circuit")
	}
	keySet, ok := evaluator.EvaluationKeySet.(*rlwe.MemEvaluationKeySet)
	if !ok || keySet == nil {
		return nil, fmt.Errorf("homchain: Gao A2B evaluator requires an in-memory evaluation-key set")
	}
	relinearizationKey, conjugationKey, err := preflightA2BKernelKeys(c.profile, keySet, nil, nil)
	if err != nil {
		return nil, err
	}
	operational := evaluator.ShallowCopy()
	operationalEncoder := c.encoder.ShallowCopy()
	operational.Encoder = operationalEncoder
	if operational.Encoder.Prec() != c.profile.operationalEncoderPrecision {
		return nil, fmt.Errorf("homchain: Gao A2B private operational encoder precision drifted")
	}
	polynomialEvaluator := ckkspolynomial.NewEvaluator(c.params, operational)
	bound, ok := polynomialEvaluator.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || bound != operational {
		return nil, fmt.Errorf("homchain: Gao A2B polynomial evaluator graph is not bound to the private CKKS evaluator")
	}
	return &GaoA2BKernelEvaluator{
		circuit: c, source: evaluator, ckks: operational, polynomial: polynomialEvaluator,
		keySet: keySet, relinearizationKey: relinearizationKey, conjugationKey: conjugationKey,
		operationalEncoder: operationalEncoder,
	}, nil
}

func (e *GaoA2BKernelEvaluator) Profile() GaoA2BKernelProfile {
	if e == nil || e.circuit == nil {
		return GaoA2BKernelProfile{}
	}
	return e.circuit.Profile()
}

func (e *GaoA2BKernelEvaluator) OperationalEncoderPrecision() uint {
	if e == nil || e.operationalEncoder == nil {
		return 0
	}
	return e.operationalEncoder.Prec()
}

// GaoA2BKernelStage identifies one measured ciphertext boundary.
type GaoA2BKernelStage string

const (
	GaoA2BKernelStageInput          GaoA2BKernelStage = "normalized-input-y-equals-J-plus-p-over-16-all-over-16"
	GaoA2BKernelStageExponential    GaoA2BKernelStage = "degree-46-chebyshev-exp-i8pi-y"
	GaoA2BKernelStageSquare0        GaoA2BKernelStage = "complex-square-0"
	GaoA2BKernelStageRootOfUnity    GaoA2BKernelStage = "complex-square-1-exp-i2pi-J-plus-p-over-16"
	GaoA2BKernelStageIdentityLUT    GaoA2BKernelStage = "shared-basis-identity-lut"
	GaoA2BKernelStageMSBLUT         GaoA2BKernelStage = "shared-basis-msb-lut"
	GaoA2BKernelStageIdentityOutput GaoA2BKernelStage = "identity-plus-conjugate"
	GaoA2BKernelStageMSBOutput      GaoA2BKernelStage = "msb-plus-conjugate"
)

// GaoA2BKernelCiphertextState records both the actual exact scale and the
// operation-derived target. No level drop or scale metadata retag occurs.
type GaoA2BKernelCiphertextState struct {
	Stage       GaoA2BKernelStage
	Level       int
	Degree      int
	Scale       ExactScaleSnapshot
	TargetScale ExactScaleSnapshot
	ScaleExact  bool
}

// GaoA2BKernelOperationCounts proves the single shared-basis runtime path.
// GenericLUTEvaluations remains zero because neither LUT is evaluated through
// an independent generic Evaluate call.
type GaoA2BKernelOperationCounts struct {
	ExpPolynomialEvaluations   int
	ComplexSquarings           int
	MultiPolynomialEvaluations int
	SharedPowerBases           int
	GenericLUTEvaluations      int
	Conjugations               int
	RealRecoveries             int
}

// GaoA2BKernelProvenance is a detached audit record for one evaluation.
type GaoA2BKernelProvenance struct {
	profileDigest          string
	parameterDigest        string
	operandGraphDigest     string
	keyProfileDigest       string
	operationalEncoderPrec uint
	inputNormalization     string
	operandPlan            GaoA2BKernelOperandPlan
	runtimePath            string
	states                 []GaoA2BKernelCiphertextState
	operationCounts        GaoA2BKernelOperationCounts
}

func (p GaoA2BKernelProvenance) ProfileDigest() string   { return p.profileDigest }
func (p GaoA2BKernelProvenance) ParameterDigest() string { return p.parameterDigest }
func (p GaoA2BKernelProvenance) OperandGraphDigest() string {
	return p.operandGraphDigest
}
func (p GaoA2BKernelProvenance) KeyProfileDigest() string { return p.keyProfileDigest }
func (p GaoA2BKernelProvenance) OperationalEncoderPrecision() uint {
	return p.operationalEncoderPrec
}
func (p GaoA2BKernelProvenance) OperandPlan() GaoA2BKernelOperandPlan { return p.operandPlan }
func (p GaoA2BKernelProvenance) InputNormalization() string           { return p.inputNormalization }
func (p GaoA2BKernelProvenance) RuntimePath() string                  { return p.runtimePath }
func (p GaoA2BKernelProvenance) States() []GaoA2BKernelCiphertextState {
	return append([]GaoA2BKernelCiphertextState(nil), p.states...)
}
func (p GaoA2BKernelProvenance) OperationCounts() GaoA2BKernelOperationCounts {
	return p.operationCounts
}

// GaoA2BKernelResult owns named ID/MSB outputs in source order and detached
// copies of the two exponential checkpoints used by integration tests.
type GaoA2BKernelResult struct {
	identity        *rlwe.Ciphertext
	msb             *rlwe.Ciphertext
	exponentialBase *rlwe.Ciphertext
	rootOfUnity     *rlwe.Ciphertext
	provenance      GaoA2BKernelProvenance
}

func (r GaoA2BKernelResult) IdentityCiphertext() *rlwe.Ciphertext {
	return r.IDCiphertext()
}

// IDCiphertext returns a detached copy of the named periodic ID output.
func (r GaoA2BKernelResult) IDCiphertext() *rlwe.Ciphertext {
	if r.identity == nil {
		return nil
	}
	return r.identity.CopyNew()
}
func (r GaoA2BKernelResult) MSBCiphertext() *rlwe.Ciphertext {
	if r.msb == nil {
		return nil
	}
	return r.msb.CopyNew()
}
func (r GaoA2BKernelResult) ExponentialBaseCiphertext() *rlwe.Ciphertext {
	if r.exponentialBase == nil {
		return nil
	}
	return r.exponentialBase.CopyNew()
}
func (r GaoA2BKernelResult) RootOfUnityCiphertext() *rlwe.Ciphertext {
	if r.rootOfUnity == nil {
		return nil
	}
	return r.rootOfUnity.CopyNew()
}
func (r GaoA2BKernelResult) Provenance() GaoA2BKernelProvenance { return r.provenance }

// EvaluateNew executes the fixed graph. The input is the CTS-normalized
// Chebyshev variable y=(J+p/16)/16; this kernel intentionally performs no
// further division by 16. Key, graph, profile, input level, dimensions, and
// exact scale are all checked before the first homomorphic operation.
func (e *GaoA2BKernelEvaluator) EvaluateNew(input *rlwe.Ciphertext) (GaoA2BKernelResult, error) {
	if e == nil || e.circuit == nil || e.ckks == nil || e.polynomial == nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: nil Gao A2B kernel evaluator")
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
	operandPlan, err := inspectA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, e.circuit.profile.slots)
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	if operandPlan != e.circuit.profile.operandPlan {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B kernel operand plan changed before evaluation")
	}
	if digestA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, operandPlan) != e.circuit.profile.operandGraphDigest {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B kernel cloned operand coefficient digest changed before evaluation")
	}
	inputBefore := input.CopyNew()
	states := make([]GaoA2BKernelCiphertextState, 0, 8)
	state, err := snapshotA2BKernelState(GaoA2BKernelStageInput, input, e.circuit.params.DefaultScale())
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	if err = requireA2BKernelExactScale(state); err != nil {
		return GaoA2BKernelResult{}, err
	}
	states = append(states, state)
	counts := GaoA2BKernelOperationCounts{}
	exponentialTargetScale := e.circuit.params.DefaultScale()
	exponential, err := e.polynomial.Evaluate(input, exponentialOperand, exponentialTargetScale)
	counts.ExpPolynomialEvaluations++
	if err != nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: evaluate Gao A2B exponential polynomial: %w", err)
	}
	wantExponentialLevel := input.Level() - exponentialOperand.Depth()
	if exponential.Level() != wantExponentialLevel || exponential.Degree() != 1 {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B exponential state level=%d degree=%d, want level=%d degree=1", exponential.Level(), exponential.Degree(), wantExponentialLevel)
	}
	state, err = snapshotA2BKernelState(GaoA2BKernelStageExponential, exponential, exponentialTargetScale)
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	if err = requireA2BKernelExactScale(state); err != nil {
		return GaoA2BKernelResult{}, err
	}
	states = append(states, state)
	exponentialBase := exponential.CopyNew()

	root := exponential
	for round, stage := range [...]GaoA2BKernelStage{GaoA2BKernelStageSquare0, GaoA2BKernelStageRootOfUnity} {
		previousScale := root.Scale
		previousLevel := root.Level()
		root, err = e.ckks.MulRelinNew(root, root)
		if err != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B complex square %d MulRelinNew: %w", round, err)
		}
		if err = e.ckks.Rescale(root, root); err != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B complex square %d Rescale: %w", round, err)
		}
		counts.ComplexSquarings++
		expectedScale := previousScale.Mul(previousScale).Div(rlwe.NewScale(e.circuit.params.Q()[previousLevel]))
		if root.Level() != previousLevel-1 || root.Degree() != 1 {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B complex square %d state level=%d degree=%d", round, root.Level(), root.Degree())
		}
		state, err = snapshotA2BKernelState(stage, root, expectedScale)
		if err != nil {
			return GaoA2BKernelResult{}, err
		}
		if err = requireA2BKernelExactScale(state); err != nil {
			return GaoA2BKernelResult{}, err
		}
		states = append(states, state)
	}
	rootOfUnity := root.CopyNew()

	lutTargetScale, err := e.circuit.profile.booleanOutputScale.Scale()
	if err != nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: recover sealed Gao A2B Boolean output scale: %w", err)
	}
	lutOutputs, err := e.polynomial.EvaluateMultiPoly(
		root,
		[]interface{}{identityOperand, msbOperand},
		lutTargetScale,
	)
	counts.MultiPolynomialEvaluations++
	counts.SharedPowerBases++
	if err != nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: evaluate Gao A2B shared-basis ID/MSB LUTs: %w", err)
	}
	if len(lutOutputs) != 2 || lutOutputs[0] == nil || lutOutputs[1] == nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B shared-basis LUT returned %d outputs, want named ID and MSB", len(lutOutputs))
	}
	wantLUTLevel := root.Level() - identityOperand.Depth()
	if identityOperand.Depth() != msbOperand.Depth() {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B LUT depths differ after sealing")
	}
	for index, output := range lutOutputs {
		if output.Level() != wantLUTLevel || output.Degree() != 1 {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B LUT output %d level=%d degree=%d, want level=%d degree=1", index, output.Level(), output.Degree(), wantLUTLevel)
		}
	}
	state, err = snapshotA2BKernelState(GaoA2BKernelStageIdentityLUT, lutOutputs[0], lutTargetScale)
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	if err = requireA2BKernelExactScale(state); err != nil {
		return GaoA2BKernelResult{}, err
	}
	states = append(states, state)
	state, err = snapshotA2BKernelState(GaoA2BKernelStageMSBLUT, lutOutputs[1], lutTargetScale)
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	if err = requireA2BKernelExactScale(state); err != nil {
		return GaoA2BKernelResult{}, err
	}
	states = append(states, state)

	identityLUTScale := lutOutputs[0].Scale
	identityConjugate, err := e.ckks.ConjugateNew(lutOutputs[0])
	if err != nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: conjugate Gao A2B identity LUT: %w", err)
	}
	counts.Conjugations++
	if err = e.ckks.Add(lutOutputs[0], identityConjugate, lutOutputs[0]); err != nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: recover Gao A2B identity real part: %w", err)
	}
	counts.RealRecoveries++
	state, err = snapshotA2BKernelState(GaoA2BKernelStageIdentityOutput, lutOutputs[0], identityLUTScale)
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	if err = requireA2BKernelExactScale(state); err != nil {
		return GaoA2BKernelResult{}, err
	}
	states = append(states, state)

	msbLUTScale := lutOutputs[1].Scale
	msbConjugate, err := e.ckks.ConjugateNew(lutOutputs[1])
	if err != nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: conjugate Gao A2B MSB LUT: %w", err)
	}
	counts.Conjugations++
	if err = e.ckks.Add(lutOutputs[1], msbConjugate, lutOutputs[1]); err != nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: recover Gao A2B MSB real part: %w", err)
	}
	counts.RealRecoveries++
	state, err = snapshotA2BKernelState(GaoA2BKernelStageMSBOutput, lutOutputs[1], msbLUTScale)
	if err != nil {
		return GaoA2BKernelResult{}, err
	}
	if err = requireA2BKernelExactScale(state); err != nil {
		return GaoA2BKernelResult{}, err
	}
	states = append(states, state)

	if !input.Equal(inputBefore) {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: Gao A2B kernel mutated its input")
	}
	return GaoA2BKernelResult{
		identity: lutOutputs[0], msb: lutOutputs[1],
		exponentialBase: exponentialBase, rootOfUnity: rootOfUnity,
		provenance: GaoA2BKernelProvenance{
			profileDigest: e.circuit.profile.digest, parameterDigest: e.circuit.profile.parameterDigest,
			operandGraphDigest:     e.circuit.profile.operandGraphDigest,
			keyProfileDigest:       e.circuit.profile.keyProfile.digest,
			operationalEncoderPrec: e.OperationalEncoderPrecision(),
			inputNormalization:     e.circuit.profile.InputNormalization(),
			operandPlan:            operandPlan,
			runtimePath:            e.circuit.profile.RuntimePath(), states: states, operationCounts: counts,
		},
	}, nil
}

func (e *GaoA2BKernelEvaluator) validateInput(input *rlwe.Ciphertext) error {
	if input == nil || input.MetaData == nil {
		return fmt.Errorf("homchain: Gao A2B kernel input is nil or has nil metadata")
	}
	profile := e.circuit.profile
	if input.Level() != profile.inputLevel || input.Degree() != 1 {
		return fmt.Errorf("homchain: Gao A2B kernel input level=%d degree=%d, want level=%d degree=1", input.Level(), input.Degree(), profile.inputLevel)
	}
	if input.LogN() != e.circuit.params.LogN() || !input.IsBatched || !input.IsNTT ||
		input.LogDimensions != profile.logDimensions || input.Slots() != profile.slots {
		return fmt.Errorf("homchain: Gao A2B kernel input is not a full-packed 16-slot CKKS ciphertext")
	}
	if !profile.inputScale.EqualScale(input.Scale) {
		return fmt.Errorf("homchain: Gao A2B kernel input exact scale does not match the profile")
	}
	return nil
}

func (e *GaoA2BKernelEvaluator) preflightGraphAndKeys() error {
	if e.source == nil || e.source.EvaluationKeySet != e.keySet || e.ckks == nil ||
		e.ckks.EvaluationKeySet != e.keySet || e.ckks.Encoder != e.operationalEncoder ||
		e.operationalEncoder == nil || e.operationalEncoder.Prec() != e.circuit.profile.operationalEncoderPrecision {
		return fmt.Errorf("homchain: Gao A2B evaluator graph or operational encoder was replaced before evaluation")
	}
	bound, ok := e.polynomial.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || bound != e.ckks {
		return fmt.Errorf("homchain: Gao A2B polynomial evaluator graph was replaced before evaluation")
	}
	_, _, err := preflightA2BKernelKeys(e.circuit.profile, e.keySet, e.relinearizationKey, e.conjugationKey)
	return err
}

func preflightA2BKernelKeys(
	profile GaoA2BKernelProfile,
	keySet *rlwe.MemEvaluationKeySet,
	expectedRelinearization *rlwe.RelinearizationKey,
	expectedConjugation *rlwe.GaloisKey,
) (*rlwe.RelinearizationKey, *rlwe.GaloisKey, error) {
	if keySet == nil {
		return nil, nil, fmt.Errorf("homchain: Gao A2B evaluation-key set is nil")
	}
	relinearizationKey, err := keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, nil, fmt.Errorf("homchain: Gao A2B relinearization key is missing: %v", err)
	}
	if expectedRelinearization != nil && relinearizationKey != expectedRelinearization {
		return nil, nil, fmt.Errorf("homchain: Gao A2B relinearization key identity changed before evaluation")
	}
	conjugationKey, err := keySet.GetGaloisKey(profile.keyProfile.conjugationElement)
	if err != nil || conjugationKey == nil {
		return nil, nil, fmt.Errorf("homchain: Gao A2B conjugation key is missing: %v", err)
	}
	if expectedConjugation != nil && conjugationKey != expectedConjugation {
		return nil, nil, fmt.Errorf("homchain: Gao A2B conjugation key identity changed before evaluation")
	}
	if relinearizationKey.LevelQ() < profile.inputLevel || relinearizationKey.LevelP() != 0 ||
		conjugationKey.LevelQ() < profile.inputLevel || conjugationKey.LevelP() != 0 ||
		conjugationKey.GaloisElement != profile.keyProfile.conjugationElement {
		return nil, nil, fmt.Errorf("homchain: Gao A2B evaluation keys have insufficient levels or the wrong conjugation element")
	}
	return relinearizationKey, conjugationKey, nil
}

func (c *GaoA2BKernelCircuit) validate() error {
	if c == nil || c.encoder == nil {
		return fmt.Errorf("homchain: nil or incomplete Gao A2B kernel circuit")
	}
	expected, err := GaoA2BKernelFunctionalParameters()
	encoderParameters := c.encoder.GetParameters()
	if err != nil || !c.params.Equal(&expected) || c.encoder.Prec() != gaoA2BKernelEncoderPrecision ||
		!c.params.Equal(&encoderParameters) {
		return fmt.Errorf("homchain: Gao A2B kernel parameters or private encoder changed")
	}
	exponentialProfile, err := NewGaoA2BExpProfile()
	if err != nil {
		return fmt.Errorf("homchain: rebuild Gao A2B exponential profile: %w", err)
	}
	lutProfile, err := NewGaoA2BLUTProfile()
	if err != nil {
		return fmt.Errorf("homchain: rebuild Gao A2B LUT profile: %w", err)
	}
	parameterBytes, err := c.params.MarshalBinary()
	if err != nil {
		return fmt.Errorf("homchain: remarshal Gao A2B kernel parameters: %w", err)
	}
	expectedKeyProfileDigest := a2bKernelDigestText(fmt.Sprintf(
		"relinearization=true;conjugation=true;conjugation-element=%d;rotations=[];min-level-q=%d;level-p=0",
		c.params.GaloisElementForComplexConjugation(), gaoA2BKernelInputLevel,
	))
	plan, err := inspectA2BKernelOperands(c.exponentialOperand, c.identityOperand, c.msbOperand, c.params.MaxSlots())
	if err != nil || plan != c.profile.operandPlan {
		return fmt.Errorf("homchain: Gao A2B kernel sealed operand graph changed")
	}
	if digestA2BKernelOperands(c.exponentialOperand, c.identityOperand, c.msbOperand, plan) != c.profile.operandGraphDigest {
		return fmt.Errorf("homchain: Gao A2B kernel sealed operand coefficient digest changed")
	}
	if c.profile.claim != GaoA2BKernelFunctionalLattigoOptimizedAdaptationNotSecureNotFullA2B ||
		c.profile.inputLevel != gaoA2BKernelInputLevel || c.profile.slots != 16 ||
		c.profile.logDimensions != c.params.LogMaxDimensions() ||
		c.profile.operationalEncoderPrecision != gaoA2BKernelEncoderPrecision ||
		!c.profile.inputScale.EqualScale(c.params.DefaultScale()) ||
		c.profile.booleanOutputLevel != gaoA2BKernelOutputLevel ||
		!c.profile.booleanOutputScale.EqualScale(c.params.DefaultScale()) ||
		c.profile.exponentialProfileDigest != exponentialProfile.Digest() ||
		c.profile.exponentialArtifactDigest != exponentialProfile.ArtifactDigest() ||
		c.profile.lutTableDigest != lutProfile.TableDigest() ||
		c.profile.parameterDigest != a2bKernelDigestBytes(parameterBytes) ||
		c.profile.keyProfile.digest != expectedKeyProfileDigest ||
		c.profile.keyProfile.conjugationElement != c.params.GaloisElementForComplexConjugation() ||
		!c.profile.keyProfile.requiresRelinearization || !c.profile.keyProfile.requiresConjugation ||
		len(c.profile.keyProfile.rotationIndexes) != 0 || c.profile.digest != digestA2BKernelProfile(c.profile) {
		return fmt.Errorf("homchain: Gao A2B kernel profile digest or fixed contract changed")
	}
	return nil
}

func newA2BKernelPackedPolynomial(polynomial bignum.Polynomial, slots int) (ckkspolynomial.PolynomialVector, error) {
	mapping := map[int][]int{0: make([]int, slots)}
	for i := range mapping[0] {
		mapping[0][i] = i
	}
	return ckkspolynomial.NewPolynomialVector([]bignum.Polynomial{polynomial}, mapping)
}

func inspectA2BKernelOperands(
	exponential, identity, msb ckkspolynomial.PolynomialVector,
	slots int,
) (GaoA2BKernelOperandPlan, error) {
	operands := [...]ckkspolynomial.PolynomialVector{exponential, identity, msb}
	wantDegrees := [...]int{46, 15, 15}
	wantBases := [...]bignum.Basis{bignum.Chebyshev, bignum.Monomial, bignum.Monomial}
	for operandIndex, operand := range operands {
		if len(operand.Value) != 1 || len(operand.Mapping) != 1 || operand.Value[0].Degree() != wantDegrees[operandIndex] ||
			operand.Value[0].Basis != wantBases[operandIndex] {
			return GaoA2BKernelOperandPlan{}, fmt.Errorf("homchain: Gao A2B packed operand %d has the wrong polynomial shape", operandIndex)
		}
		mapping, ok := operand.Mapping[0]
		if !ok || len(mapping) != slots {
			return GaoA2BKernelOperandPlan{}, fmt.Errorf("homchain: Gao A2B packed operand %d maps %d slots, want %d", operandIndex, len(mapping), slots)
		}
		for mappingIndex, slot := range mapping {
			if slot != mappingIndex {
				return GaoA2BKernelOperandPlan{}, fmt.Errorf("homchain: Gao A2B packed operand %d mapping is not the exact full-slot sequence 0..%d", operandIndex, slots-1)
			}
		}
		for _, coefficient := range operand.Value[0].Coeffs {
			if coefficient == nil || coefficient.Real() == nil || coefficient.Imag() == nil ||
				coefficient.Real().Prec() < gaoA2BKernelEncoderPrecision || coefficient.Imag().Prec() < gaoA2BKernelEncoderPrecision {
				return GaoA2BKernelOperandPlan{}, fmt.Errorf("homchain: Gao A2B packed operand %d contains a nil or low-precision coefficient", operandIndex)
			}
		}
	}
	return GaoA2BKernelOperandPlan{
		exponentialEncoding: GaoA2BKernelPackedVectorEncoding,
		exponentialSlots:    slots,
		lutEncodings:        [2]GaoA2BKernelOperandEncoding{GaoA2BKernelPackedVectorEncoding, GaoA2BKernelPackedVectorEncoding},
		lutSlots:            [2]int{slots, slots},
		outputOrder:         [2]GaoA2BLUTKind{GaoA2BLUTIdentity, GaoA2BLUTMSB},
	}, nil
}

func cloneA2BKernelPolynomialVector(value ckkspolynomial.PolynomialVector) (ckkspolynomial.PolynomialVector, error) {
	polynomials := make([]bignum.Polynomial, len(value.Value))
	for i := range value.Value {
		polynomials[i] = value.Value[i].Polynomial.Clone()
		polynomials[i].Interval.A = *new(big.Float).SetPrec(value.Value[i].Interval.A.Prec()).Set(&value.Value[i].Interval.A)
		polynomials[i].Interval.B = *new(big.Float).SetPrec(value.Value[i].Interval.B.Prec()).Set(&value.Value[i].Interval.B)
	}
	mapping := make(map[int][]int, len(value.Mapping))
	for index, slots := range value.Mapping {
		mapping[index] = append([]int(nil), slots...)
	}
	result, err := ckkspolynomial.NewPolynomialVector(polynomials, mapping)
	if err != nil {
		return ckkspolynomial.PolynomialVector{}, fmt.Errorf("homchain: clone Gao A2B packed polynomial: %w", err)
	}
	return result, nil
}

func digestA2BKernelOperands(
	exponential, identity, msb ckkspolynomial.PolynomialVector,
	plan GaoA2BKernelOperandPlan,
) string {
	var canonical strings.Builder
	fmt.Fprintf(&canonical, "gao-a2b-kernel-operands-v1|encoding=%s,%v|slots=%d,%v|output=%v\n",
		plan.exponentialEncoding, plan.lutEncodings, plan.exponentialSlots, plan.lutSlots, plan.outputOrder)
	for operandIndex, operand := range [...]ckkspolynomial.PolynomialVector{exponential, identity, msb} {
		fmt.Fprintf(&canonical, "operand=%d|polynomials=%d|mappings=%d\n", operandIndex, len(operand.Value), len(operand.Mapping))
		for polynomialIndex, polynomial := range operand.Value {
			fmt.Fprintf(&canonical, "polynomial=%d|basis=%d|degree=%d|depth=%d|odd=%t|even=%t|interval=%s,%s\n",
				polynomialIndex, polynomial.Basis, polynomial.Degree(), polynomial.Depth(), polynomial.IsOdd, polynomial.IsEven,
				polynomial.Interval.A.Text('x', -1), polynomial.Interval.B.Text('x', -1))
			for coefficientIndex, coefficient := range polynomial.Coeffs {
				fmt.Fprintf(&canonical, "coefficient=%d|real=%s|imaginary=%s|precision=%d,%d\n",
					coefficientIndex, coefficient.Real().Text('x', -1), coefficient.Imag().Text('x', -1),
					coefficient.Real().Prec(), coefficient.Imag().Prec())
			}
			fmt.Fprintf(&canonical, "mapping=%d:%v\n", polynomialIndex, operand.Mapping[polynomialIndex])
		}
	}
	return a2bKernelDigestText(canonical.String())
}

func snapshotA2BKernelState(stage GaoA2BKernelStage, ciphertext *rlwe.Ciphertext, target rlwe.Scale) (GaoA2BKernelCiphertextState, error) {
	actual, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return GaoA2BKernelCiphertextState{}, fmt.Errorf("homchain: snapshot Gao A2B %s scale: %w", stage, err)
	}
	expected, err := NewExactScaleSnapshot(target)
	if err != nil {
		return GaoA2BKernelCiphertextState{}, fmt.Errorf("homchain: snapshot Gao A2B %s target scale: %w", stage, err)
	}
	return GaoA2BKernelCiphertextState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		Scale: actual, TargetScale: expected, ScaleExact: actual.Equal(expected),
	}, nil
}

func requireA2BKernelExactScale(state GaoA2BKernelCiphertextState) error {
	if !state.ScaleExact {
		return fmt.Errorf(
			"homchain: Gao A2B kernel %s scale=%s differs from operation-derived target=%s",
			state.Stage, state.Scale.canonicalString(), state.TargetScale.canonicalString(),
		)
	}
	return nil
}

func digestA2BKernelProfile(profile GaoA2BKernelProfile) string {
	var canonical strings.Builder
	fmt.Fprintf(&canonical,
		"gao-a2b-kernel-v3|claim=%s|input-level=%d|slots=%d|dimensions=%d,%d|encoder-precision=%d|input-scale=%s|boolean-output-level=%d|boolean-output-scale=%s|input-normalization=%s|exp-profile=%s|exp-artifact=%s|lut-table=%s|params=%s|operand-graph=%s|operand=%s,%d,%v,%v,%v|key=%s|path=%s",
		profile.claim, profile.inputLevel, profile.slots, profile.logDimensions.Rows, profile.logDimensions.Cols,
		profile.operationalEncoderPrecision, profile.inputScale.canonicalString(), profile.booleanOutputLevel,
		profile.booleanOutputScale.canonicalString(), profile.InputNormalization(),
		profile.exponentialProfileDigest, profile.exponentialArtifactDigest, profile.lutTableDigest,
		profile.parameterDigest, profile.operandGraphDigest, profile.operandPlan.exponentialEncoding, profile.operandPlan.exponentialSlots,
		profile.operandPlan.lutEncodings, profile.operandPlan.lutSlots, profile.operandPlan.outputOrder,
		profile.keyProfile.digest, profile.RuntimePath(),
	)
	return a2bKernelDigestText(canonical.String())
}

func a2bKernelDigestText(value string) string { return a2bKernelDigestBytes([]byte(value)) }

func a2bKernelDigestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
