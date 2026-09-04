package homchain

import (
	"fmt"
	"math/big"

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
	gaoA2BKernelN16FullLogSlots   = 15
	gaoA2BKernelN16FullSlots      = 1 << gaoA2BKernelN16FullLogSlots
)

// GaoA2BKernelN16FullPackedSlots is the Gao/OpenFHE-compatible number of
// complex slots at LogN=16.
const GaoA2BKernelN16FullPackedSlots = gaoA2BKernelN16FullSlots

const (
	// GaoA2BKernelN16L11KernelOnlyUnverified labels the exact-parameter,
	// sparse-packing vertical gate. It is not a complete A2B, refresh,
	// security, tree, or performance claim.
	GaoA2BKernelN16L11KernelOnlyUnverified GaoA2BKernelClaim = "lattigo_n16_l11_sparse_kernel_only_security_unverified_not_full_a2b"

	// GaoA2BKernelN16FullPackedKernelOnlyUnverified labels the polynomial
	// kernel at the Gao/OpenFHE-compatible 32,768-slot packing. The surrounding
	// refresh and two-round A2B composition remain outside this claim.
	GaoA2BKernelN16FullPackedKernelOnlyUnverified GaoA2BKernelClaim = "lattigo_n16_l15_full_packed_kernel_only_security_unverified_not_full_a2b"
)

type gaoA2BKernelN16Packing struct {
	claim               GaoA2BKernelClaim
	logSlots            int
	slots               int
	keyDigestSchema     string
	profileDigestSchema string
	runtimePath         string
}

func gaoA2BKernelN16L11Packing() gaoA2BKernelN16Packing {
	return gaoA2BKernelN16Packing{
		claim:               GaoA2BKernelN16L11KernelOnlyUnverified,
		logSlots:            gaoA2BKernelN16L11LogSlots,
		slots:               gaoA2BKernelN16L11Slots,
		keyDigestSchema:     "n16-l11-kernel-keys-v1",
		profileDigestSchema: "gao-a2b-kernel-n16-l11-v1",
		runtimePath:         "n16-l11-sparse-normalized-y;exp46-chebyshev-packed-vector256/evaluate;mulrelin-rescale^2;id-msb-degree15-packed-vectors/evaluate-multi-poly/shared-power-basis/target-S43;conjugate-add^2",
	}
}

func gaoA2BKernelN16FullPacking() gaoA2BKernelN16Packing {
	return gaoA2BKernelN16Packing{
		claim:               GaoA2BKernelN16FullPackedKernelOnlyUnverified,
		logSlots:            gaoA2BKernelN16FullLogSlots,
		slots:               gaoA2BKernelN16FullSlots,
		keyDigestSchema:     "n16-l15-full-packed-kernel-keys-v1",
		profileDigestSchema: "gao-a2b-kernel-n16-l15-full-packed-v1",
		runtimePath:         "n16-l15-full-packed-normalized-y;exp46-chebyshev-scalar/evaluate;mulrelin-rescale^2;root16-real-id-plus-i-msb-degree15-scalar/evaluate-once/target-S43;conjugate-split-real-imag",
	}
}

func gaoA2BKernelN16PackingForProfile(profile GaoA2BKernelN16L11Profile) (gaoA2BKernelN16Packing, error) {
	switch profile.claim {
	case GaoA2BKernelN16L11KernelOnlyUnverified:
		return gaoA2BKernelN16L11Packing(), nil
	case GaoA2BKernelN16FullPackedKernelOnlyUnverified:
		return gaoA2BKernelN16FullPacking(), nil
	default:
		return gaoA2BKernelN16Packing{}, fmt.Errorf("homchain: unsupported N16 Gao kernel claim %q", profile.claim)
	}
}

func gaoA2BKernelN16ParametersForPacking(packing gaoA2BKernelN16Packing) (ckks.Parameters, error) {
	switch packing.claim {
	case GaoA2BKernelN16L11KernelOnlyUnverified:
		return securityparams.GaoCompatibleN16Parameters()
	case GaoA2BKernelN16FullPackedKernelOnlyUnverified:
		return securityparams.GaoOpenFHEFullN16Parameters()
	default:
		return ckks.Parameters{}, fmt.Errorf("homchain: unsupported N16 Gao kernel claim %q", packing.claim)
	}
}

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
	packing, err := gaoA2BKernelN16PackingForProfile(p)
	if err != nil {
		return ""
	}
	return packing.runtimePath
}
func (p GaoA2BKernelN16L11Profile) Digest() string { return p.digest }

// GaoA2BKernelN16FullPackedProfile is the N16 profile returned by the
// full-packed constructor. Its claim, shape, digests, and runtime path are
// distinct from the frozen L11 adaptation.
type GaoA2BKernelN16FullPackedProfile = GaoA2BKernelN16L11Profile

// GaoA2BKernelN16L11Circuit is a second adapter. The accepted LogN=5
// functional circuit remains unchanged.
type GaoA2BKernelN16L11Circuit struct {
	params             ckks.Parameters
	encoder            *ckks.Encoder
	profile            GaoA2BKernelN16L11Profile
	exponentialOperand ckkspolynomial.PolynomialVector
	identityOperand    ckkspolynomial.PolynomialVector
	msbOperand         ckkspolynomial.PolynomialVector
	packedLUTOperand   ckkspolynomial.Polynomial
}

// GaoA2BKernelN16FullPackedCircuit uses the same sealed Gao polynomial graph
// as the L11 circuit with the full 32,768-slot operand mapping.
type GaoA2BKernelN16FullPackedCircuit = GaoA2BKernelN16L11Circuit

// NewGaoA2BKernelN16L11Circuit seals the exact Gao polynomials for the local
// N16/L11 kernel-only gate.
func NewGaoA2BKernelN16L11Circuit(params ckks.Parameters, encoder *ckks.Encoder) (*GaoA2BKernelN16L11Circuit, error) {
	return newGaoA2BKernelN16Circuit(params, encoder, gaoA2BKernelN16L11Packing())
}

// NewGaoA2BKernelN16FullPackedCircuit seals the Gao degree-46/R2 and shared
// ID/MSB polynomial graph over all 32,768 complex slots of the canonical N16
// parameter set.
func NewGaoA2BKernelN16FullPackedCircuit(params ckks.Parameters, encoder *ckks.Encoder) (*GaoA2BKernelN16FullPackedCircuit, error) {
	return newGaoA2BKernelN16Circuit(params, encoder, gaoA2BKernelN16FullPacking())
}

func newGaoA2BKernelN16Circuit(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	packing gaoA2BKernelN16Packing,
) (*GaoA2BKernelN16L11Circuit, error) {
	expected, err := gaoA2BKernelN16ParametersForPacking(packing)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct canonical N16 Gao parameters: %w", err)
	}
	if !params.Equal(&expected) || params.LogN() != 16 || params.MaxLevel() != 20 ||
		params.MaxLevelP() != 6 || params.LogDefaultScale() != 43 ||
		params.RingType() != ring.Standard || params.LevelsConsumedPerRescaling() != 1 {
		return nil, fmt.Errorf("homchain: N16 Gao kernel requires the exact parameters for packing claim %q", packing.claim)
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
	exponentialOperand, err := newA2BKernelPackedPolynomial(exponentialProfile.LattigoPolynomial(), packing.slots)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct N16/L11 Gao exponential operand: %w", err)
	}
	identityPolynomial, err := lutProfile.LattigoPolynomial(GaoA2BLUTIdentity)
	if err != nil {
		return nil, err
	}
	identityOperand, err := newA2BKernelPackedPolynomial(identityPolynomial, packing.slots)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct N16/L11 Gao identity operand: %w", err)
	}
	msbPolynomial, err := lutProfile.LattigoPolynomial(GaoA2BLUTMSB)
	if err != nil {
		return nil, err
	}
	msbOperand, err := newA2BKernelPackedPolynomial(msbPolynomial, packing.slots)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct N16/L11 Gao MSB operand: %w", err)
	}
	var packedLUTOperand ckkspolynomial.Polynomial
	if packing.claim == GaoA2BKernelN16FullPackedKernelOnlyUnverified {
		if packedLUTOperand, err = newGaoA2BKernelN16PackedLUT(identityPolynomial, msbPolynomial); err != nil {
			return nil, err
		}
	}
	operandPlan, err := inspectA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, packing.slots)
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
		"%s;relinearization=true;conjugation=true;conjugation-element=%d;rotations=[];min-level-q=%d;level-p=%d",
		packing.keyDigestSchema,
		keyProfile.conjugationElement, gaoA2BKernelN16L11InputLevel, params.MaxLevelP(),
	))
	profile := GaoA2BKernelN16L11Profile{
		claim:      packing.claim,
		inputLevel: gaoA2BKernelN16L11InputLevel, slots: packing.slots,
		logDimensions:               ring.Dimensions{Rows: 0, Cols: packing.logSlots},
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
	profile.digest = digestGaoA2BKernelN16Profile(profile, packing.profileDigestSchema)
	circuit := &GaoA2BKernelN16L11Circuit{
		params: params, encoder: encoder.ShallowCopy(), profile: profile,
		exponentialOperand: exponentialOperand, identityOperand: identityOperand, msbOperand: msbOperand,
		packedLUTOperand: packedLUTOperand,
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

// polynomialEvaluationOperands selects the coefficient representation used by
// the online evaluator. The full-packed Gao circuit evaluates one polynomial on
// every slot, so scalar coefficients preserve the exact function while avoiding
// a 32,768-entry arbitrary-precision vector encoding for every coefficient. The
// frozen sparse profile retains its explicit slot mapping and vector operands.
func (c *GaoA2BKernelN16L11Circuit) polynomialEvaluationOperands() (exponential interface{}, luts []interface{}) {
	if c == nil {
		return nil, nil
	}
	if c.profile.claim == GaoA2BKernelN16FullPackedKernelOnlyUnverified {
		return ckkspolynomial.Polynomial(c.exponentialOperand.Value[0]), []interface{}{
			c.packedLUTOperand,
		}
	}
	return c.exponentialOperand, []interface{}{c.identityOperand, c.msbOperand}
}

// newGaoA2BKernelN16PackedLUT first replaces each source LUT with its
// Hermitian degree-15 representative on z^16=1. The representatives evaluate
// to the source LUTs' real parts at every sixteenth root, so one complex
// polynomial can carry ID in its real channel and MSB in its imaginary channel.
func newGaoA2BKernelN16PackedLUT(
	identity, msb bignum.Polynomial,
) (ckkspolynomial.Polynomial, error) {
	if identity.Basis != bignum.Monomial || msb.Basis != bignum.Monomial ||
		identity.Degree() != gaoA2BLUTDegree || msb.Degree() != gaoA2BLUTDegree {
		return ckkspolynomial.Polynomial{}, fmt.Errorf("homchain: N16 full-packed Gao LUT operands have incompatible shapes")
	}
	coefficients := make([]*bignum.Complex, gaoA2BLUTDegree+1)
	for index := range coefficients {
		pairedIndex := (-index) & gaoA2BLUTDegree
		identityCoefficient, identityPaired := identity.Coeffs[index], identity.Coeffs[pairedIndex]
		msbCoefficient, msbPaired := msb.Coeffs[index], msb.Coeffs[pairedIndex]
		components := []*bignum.Complex{identityCoefficient, identityPaired, msbCoefficient, msbPaired}
		for _, candidate := range components {
			if candidate == nil || candidate.Real() == nil || candidate.Imag() == nil {
				return ckkspolynomial.Polynomial{}, fmt.Errorf("homchain: N16 full-packed Gao LUT coefficient %d is incomplete", index)
			}
		}
		precision := identityCoefficient.Prec()
		for _, candidate := range components[1:] {
			if candidate.Prec() > precision {
				precision = candidate.Prec()
			}
		}
		two := new(big.Float).SetPrec(precision).SetInt64(2)
		identityReal := new(big.Float).SetPrec(precision).Quo(
			new(big.Float).SetPrec(precision).Add(identityCoefficient.Real(), identityPaired.Real()), two,
		)
		identityImaginary := new(big.Float).SetPrec(precision).Quo(
			new(big.Float).SetPrec(precision).Sub(identityCoefficient.Imag(), identityPaired.Imag()), two,
		)
		msbReal := new(big.Float).SetPrec(precision).Quo(
			new(big.Float).SetPrec(precision).Add(msbCoefficient.Real(), msbPaired.Real()), two,
		)
		msbImaginary := new(big.Float).SetPrec(precision).Quo(
			new(big.Float).SetPrec(precision).Sub(msbCoefficient.Imag(), msbPaired.Imag()), two,
		)
		coefficients[index] = &bignum.Complex{
			new(big.Float).SetPrec(precision).Sub(identityReal, msbImaginary),
			new(big.Float).SetPrec(precision).Add(identityImaginary, msbReal),
		}
	}
	return ckkspolynomial.NewPolynomial(bignum.NewPolynomial(bignum.Monomial, coefficients, nil)), nil
}

func equalGaoA2BKernelN16PackedLUT(left, right ckkspolynomial.Polynomial) bool {
	if left.Basis != right.Basis || left.Degree() != right.Degree() || len(left.Coeffs) != len(right.Coeffs) {
		return false
	}
	for index := range left.Coeffs {
		if left.Coeffs[index] == nil || left.Coeffs[index].Real() == nil || left.Coeffs[index].Imag() == nil ||
			right.Coeffs[index] == nil || right.Coeffs[index].Real() == nil || right.Coeffs[index].Imag() == nil ||
			left.Coeffs[index].Real().Cmp(right.Coeffs[index].Real()) != 0 ||
			left.Coeffs[index].Imag().Cmp(right.Coeffs[index].Imag()) != 0 {
			return false
		}
	}
	return true
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

// GaoA2BKernelN16FullPackedEvaluator is a key-bound evaluator whose
// coefficient vectors cover every canonical N16 complex slot.
type GaoA2BKernelN16FullPackedEvaluator = GaoA2BKernelN16L11Evaluator

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
	return e.CoefficientSlots()
}

// CoefficientSlots reports the number of slots covered by each packed
// polynomial coefficient vector for either supported N16 packing.
func (e *GaoA2BKernelN16L11Evaluator) CoefficientSlots() int {
	if e == nil || e.coefficientGetter == nil {
		return 0
	}
	return len(e.coefficientGetter.values)
}

func (e *GaoA2BKernelN16L11Evaluator) EvaluateNew(input *rlwe.Ciphertext) (GaoA2BKernelResult, error) {
	return e.evaluateNew(input, true)
}

// EvaluatePreparedNew executes the sealed kernel after BindEvaluator has
// authenticated the circuit and key graph. It is intended for a reusable,
// privately owned server session: unlike EvaluateNew it does not re-hash the
// immutable polynomial graph or clone its read-only operands on every call.
func (e *GaoA2BKernelN16L11Evaluator) EvaluatePreparedNew(input *rlwe.Ciphertext) (GaoA2BKernelResult, error) {
	return e.evaluateNew(input, false)
}

// EvaluatePreparedMSBNew evaluates the full-packed kernel when only the MSB
// LUT output is live. It shares the same exp46 and two-square prefix while
// avoiding construction and real recovery of the unused identity output.
func (e *GaoA2BKernelN16L11Evaluator) EvaluatePreparedMSBNew(input *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if e == nil || e.circuit == nil || e.ckks == nil || e.polynomial == nil {
		return nil, fmt.Errorf("homchain: nil N16/L11 Gao MSB kernel evaluator")
	}
	if e.circuit.profile.claim != GaoA2BKernelN16FullPackedKernelOnlyUnverified {
		return nil, fmt.Errorf("homchain: prepared MSB-only entry requires the N16 full-packed Gao kernel")
	}
	if err := e.validateInput(input); err != nil {
		return nil, err
	}
	if len(e.circuit.exponentialOperand.Value) != 1 || len(e.circuit.msbOperand.Value) != 1 {
		return nil, fmt.Errorf("homchain: N16 full-packed Gao MSB operand is unavailable")
	}
	evaluationExponential := ckkspolynomial.Polynomial(e.circuit.exponentialOperand.Value[0])
	evaluationMSB := ckkspolynomial.Polynomial(e.circuit.msbOperand.Value[0])
	exponential, err := e.polynomial.Evaluate(input, evaluationExponential, e.circuit.params.DefaultScale())
	if err != nil {
		return nil, fmt.Errorf("homchain: evaluate N16 full-packed Gao MSB exponential polynomial: %w", err)
	}
	if exponential.Level() != input.Level()-e.circuit.exponentialOperand.Depth() || exponential.Degree() != 1 {
		return nil, fmt.Errorf("homchain: N16 full-packed Gao MSB exponential state changed")
	}
	root := exponential
	for round := 0; round < 2; round++ {
		root, err = e.ckks.MulRelinNew(root, root)
		if err != nil {
			return nil, fmt.Errorf("homchain: N16 full-packed Gao MSB square %d: %w", round, err)
		}
		if err = e.ckks.Rescale(root, root); err != nil {
			return nil, fmt.Errorf("homchain: N16 full-packed Gao MSB square %d rescale: %w", round, err)
		}
	}
	msb, err := e.polynomial.Evaluate(root, evaluationMSB, e.circuit.params.DefaultScale())
	if err != nil {
		return nil, fmt.Errorf("homchain: evaluate N16 full-packed Gao MSB LUT: %w", err)
	}
	if msb == nil || msb.Level() != e.circuit.profile.booleanOutputLevel || msb.Degree() != 1 ||
		!e.circuit.profile.booleanOutputScale.EqualScale(msb.Scale) {
		return nil, fmt.Errorf("homchain: N16 full-packed Gao MSB output state changed")
	}
	conjugate, err := e.ckks.ConjugateNew(msb)
	if err != nil {
		return nil, fmt.Errorf("homchain: conjugate N16 full-packed Gao MSB output: %w", err)
	}
	if err = e.ckks.Add(msb, conjugate, msb); err != nil {
		return nil, fmt.Errorf("homchain: recover N16 full-packed Gao MSB real output: %w", err)
	}
	return msb, nil
}

func (e *GaoA2BKernelN16L11Evaluator) evaluateNew(input *rlwe.Ciphertext, verifySealedGraph bool) (GaoA2BKernelResult, error) {
	if e == nil || e.circuit == nil || e.ckks == nil || e.polynomial == nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: nil N16/L11 Gao kernel evaluator")
	}
	if err := e.validateInput(input); err != nil {
		return GaoA2BKernelResult{}, err
	}

	exponentialOperand := e.circuit.exponentialOperand
	identityOperand := e.circuit.identityOperand
	msbOperand := e.circuit.msbOperand
	plan := e.circuit.profile.operandPlan
	var inputBefore *rlwe.Ciphertext
	if verifySealedGraph {
		if err := e.circuit.validate(); err != nil {
			return GaoA2BKernelResult{}, err
		}
		if err := e.preflightGraphAndKeys(); err != nil {
			return GaoA2BKernelResult{}, err
		}
		var err error
		if exponentialOperand, err = cloneA2BKernelPolynomialVector(exponentialOperand); err != nil {
			return GaoA2BKernelResult{}, err
		}
		if identityOperand, err = cloneA2BKernelPolynomialVector(identityOperand); err != nil {
			return GaoA2BKernelResult{}, err
		}
		if msbOperand, err = cloneA2BKernelPolynomialVector(msbOperand); err != nil {
			return GaoA2BKernelResult{}, err
		}
		if plan, err = inspectA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, e.circuit.profile.slots); err != nil || plan != e.circuit.profile.operandPlan {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao cloned operand plan changed")
		}
		if digestA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, plan) != e.circuit.profile.operandGraphDigest {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao cloned operand digest changed")
		}
		inputBefore = input.CopyNew()
	}

	states := make([]GaoA2BKernelCiphertextState, 0, 8)
	state, err := snapshotA2BKernelState(GaoA2BKernelStageInput, input, e.circuit.params.DefaultScale())
	if err != nil || !state.ScaleExact {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao input scale state changed: %w", err)
	}
	states = append(states, state)
	counts := GaoA2BKernelOperationCounts{}

	evaluationExponential, evaluationLUTs := e.circuit.polynomialEvaluationOperands()
	if verifySealedGraph {
		if e.circuit.profile.claim == GaoA2BKernelN16FullPackedKernelOnlyUnverified {
			packedLUT, packedErr := newGaoA2BKernelN16PackedLUT(
				identityOperand.Value[0].Polynomial, msbOperand.Value[0].Polynomial,
			)
			if packedErr != nil {
				return GaoA2BKernelResult{}, packedErr
			}
			evaluationExponential = ckkspolynomial.Polynomial(exponentialOperand.Value[0])
			evaluationLUTs = []interface{}{
				packedLUT,
			}
		} else {
			evaluationExponential = exponentialOperand
			evaluationLUTs = []interface{}{identityOperand, msbOperand}
		}
	}
	exponential, err := e.polynomial.Evaluate(input, evaluationExponential, e.circuit.params.DefaultScale())
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

	var lutOutputs []*rlwe.Ciphertext
	if e.circuit.profile.claim == GaoA2BKernelN16FullPackedKernelOnlyUnverified {
		if len(evaluationLUTs) != 1 {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16 full-packed Gao complex-packed LUT operand is unavailable")
		}
		packedLUT, evaluationErr := e.polynomial.Evaluate(
			root, evaluationLUTs[0], e.circuit.params.DefaultScale(),
		)
		counts.GenericLUTEvaluations++
		if evaluationErr != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: evaluate N16 full-packed Gao complex-packed ID+i*MSB LUT: %w", evaluationErr)
		}
		lutOutputs = []*rlwe.Ciphertext{packedLUT, packedLUT}
	} else {
		lutOutputs, err = e.polynomial.EvaluateMultiPoly(
			root, evaluationLUTs, e.circuit.params.DefaultScale(),
		)
		counts.MultiPolynomialEvaluations++
		counts.SharedPowerBases++
		if err != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: evaluate N16/L11 Gao shared ID/MSB LUT: %w", err)
		}
	}
	if len(lutOutputs) != 2 || lutOutputs[0] == nil || lutOutputs[1] == nil {
		return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao LUT output shape changed")
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

	if e.circuit.profile.claim == GaoA2BKernelN16FullPackedKernelOnlyUnverified {
		packedLUT := lutOutputs[0]
		conjugate, conjugateErr := e.ckks.ConjugateNew(packedLUT)
		if conjugateErr != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: conjugate N16 full-packed Gao complex-packed LUT: %w", conjugateErr)
		}
		counts.Conjugations++
		identity := packedLUT.CopyNew()
		if err = e.ckks.Add(packedLUT, conjugate, identity); err != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: split N16 full-packed Gao identity channel: %w", err)
		}
		if err = e.ckks.Sub(packedLUT, conjugate, packedLUT); err != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: split N16 full-packed Gao MSB channel: %w", err)
		}
		if err = e.ckks.Mul(packedLUT, -1i, packedLUT); err != nil {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: normalize N16 full-packed Gao MSB channel: %w", err)
		}
		counts.RealRecoveries += 2
		lutOutputs = []*rlwe.Ciphertext{identity, packedLUT}
	} else {
		for index := range lutOutputs {
			conjugate, conjugateErr := e.ckks.ConjugateNew(lutOutputs[index])
			if conjugateErr != nil {
				return GaoA2BKernelResult{}, fmt.Errorf("homchain: conjugate N16/L11 Gao LUT %d: %w", index, conjugateErr)
			}
			counts.Conjugations++
			if err = e.ckks.Add(lutOutputs[index], conjugate, lutOutputs[index]); err != nil {
				return GaoA2BKernelResult{}, fmt.Errorf("homchain: recover N16/L11 Gao LUT %d real part: %w", index, err)
			}
			counts.RealRecoveries++
		}
	}
	for index, stage := range [...]GaoA2BKernelStage{GaoA2BKernelStageIdentityOutput, GaoA2BKernelStageMSBOutput} {
		outputScale := lutOutputs[index].Scale
		state, err = snapshotA2BKernelState(stage, lutOutputs[index], outputScale)
		if err != nil || !state.ScaleExact {
			return GaoA2BKernelResult{}, fmt.Errorf("homchain: N16/L11 Gao real output %d scale changed: %w", index, err)
		}
		states = append(states, state)
	}

	if verifySealedGraph && !input.Equal(inputBefore) {
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
	packing, err := gaoA2BKernelN16PackingForProfile(c.profile)
	if err != nil {
		return err
	}
	expected, err := gaoA2BKernelN16ParametersForPacking(packing)
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
		c.exponentialOperand, c.identityOperand, c.msbOperand, packing.slots,
	)
	if err != nil || plan != c.profile.operandPlan ||
		digestA2BKernelOperands(c.exponentialOperand, c.identityOperand, c.msbOperand, plan) != c.profile.operandGraphDigest {
		return fmt.Errorf("homchain: N16/L11 Gao sealed operand graph changed")
	}
	if c.profile.claim == GaoA2BKernelN16FullPackedKernelOnlyUnverified {
		expectedPackedLUT, packedErr := newGaoA2BKernelN16PackedLUT(
			c.identityOperand.Value[0].Polynomial, c.msbOperand.Value[0].Polynomial,
		)
		if packedErr != nil || !equalGaoA2BKernelN16PackedLUT(c.packedLUTOperand, expectedPackedLUT) {
			return fmt.Errorf("homchain: N16 full-packed Gao derived packed LUT changed")
		}
	} else if len(c.packedLUTOperand.Coeffs) != 0 {
		return fmt.Errorf("homchain: N16/L11 sparse Gao kernel contains a full-packed LUT")
	}
	if c.profile.claim != packing.claim ||
		c.profile.inputLevel != gaoA2BKernelN16L11InputLevel ||
		c.profile.booleanOutputLevel != gaoA2BKernelN16L11OutputLevel ||
		c.profile.slots != packing.slots ||
		c.profile.logDimensions != (ring.Dimensions{Rows: 0, Cols: packing.logSlots}) ||
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
		c.profile.keyProfile.digest != a2bKernelDigestText(fmt.Sprintf(
			"%s;relinearization=true;conjugation=true;conjugation-element=%d;rotations=[];min-level-q=%d;level-p=%d",
			packing.keyDigestSchema, c.profile.keyProfile.conjugationElement,
			gaoA2BKernelN16L11InputLevel, c.params.MaxLevelP(),
		)) ||
		c.profile.RuntimePath() != packing.runtimePath ||
		c.profile.digest != digestGaoA2BKernelN16Profile(c.profile, packing.profileDigestSchema) {
		return fmt.Errorf("homchain: N16/L11 Gao profile or fixed contract changed")
	}
	return nil
}

func digestGaoA2BKernelN16L11Profile(profile GaoA2BKernelN16L11Profile) string {
	return digestGaoA2BKernelN16Profile(profile, gaoA2BKernelN16L11Packing().profileDigestSchema)
}

func digestGaoA2BKernelN16Profile(profile GaoA2BKernelN16L11Profile, schema string) string {
	return a2bKernelDigestText(fmt.Sprintf(
		"%s|claim=%s|input-level=%d|slots=%d|dimensions=%d,%d|encoder-precision=%d|input-scale=%s|boolean-output-level=%d|boolean-output-scale=%s|exp-degree=%d|squares=%d|lut-degrees=%v|input-normalization=%s|exp-profile=%s|exp-artifact=%s|lut-table=%s|params=%s|operand-graph=%s|operand=%s,%d,%v,%v,%v|key=%s|path=%s",
		schema, profile.claim, profile.inputLevel, profile.slots, profile.logDimensions.Rows, profile.logDimensions.Cols,
		profile.operationalEncoderPrecision, profile.inputScale.canonicalString(), profile.booleanOutputLevel,
		profile.booleanOutputScale.canonicalString(), profile.exponentialDegree, profile.squaringRounds,
		profile.lutDegrees, profile.InputNormalization(), profile.exponentialProfileDigest,
		profile.exponentialArtifactDigest, profile.lutTableDigest, profile.parameterDigest,
		profile.operandGraphDigest, profile.operandPlan.exponentialEncoding, profile.operandPlan.exponentialSlots,
		profile.operandPlan.lutEncodings, profile.operandPlan.lutSlots, profile.operandPlan.outputOrder,
		profile.keyProfile.digest, profile.RuntimePath(),
	))
}
