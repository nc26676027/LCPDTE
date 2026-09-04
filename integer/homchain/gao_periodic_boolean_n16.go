package homchain

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const (
	gaoPeriodicBooleanN16L11ProfileSchema = "gao-periodic-boolean-n16-l11-profile-v1"
	gaoPeriodicBooleanN16L11ResultSchema  = "gao-periodic-boolean-n16-l11-result-v1"
	gaoPeriodicBooleanN16L11Words         = 512
	gaoPeriodicBooleanN16L11HalfWidth     = 4
	gaoPeriodicBooleanN16L11Slots         = gaoPeriodicBooleanN16L11Words * gaoPeriodicBooleanN16L11HalfWidth
	gaoPeriodicBooleanN16L11InputLevel    = 17
	gaoPeriodicBooleanN16L11ExpLevel      = 11
	gaoPeriodicBooleanN16L11Square0Level  = 10
	gaoPeriodicBooleanN16L11RootLevel     = 9
	gaoPeriodicBooleanN16L11OutputLevel   = 8
)

// GaoPeriodicBooleanN16L11Claim fixes the bounded status of the periodic
// selector decoder. It is a secure-parameter functional component, not an
// application-security or performance claim.
type GaoPeriodicBooleanN16L11Claim string

const GaoPeriodicBooleanN16L11SecurityUnverified GaoPeriodicBooleanN16L11Claim = "lattigo_n16_l11_gao_periodic_boolean_reraise_security_unverified"

type GaoPeriodicBooleanN16L11OperationCounts struct {
	ExponentialPolynomialEvaluations int
	CiphertextCiphertextProducts     int
	Relinearizations                 int
	ExplicitRescales                 int
	CiphertextPlaintextProducts      int
	PlaintextVectorAdditions         int
}

type GaoPeriodicBooleanN16L11State struct {
	Stage         string
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

type GaoPeriodicBooleanN16L11Profile struct {
	claim                                            GaoPeriodicBooleanN16L11Claim
	inputLevel, exponentialLevel, square0Level       int
	rootLevel, outputLevel, slots                    int
	exponentialDegree, squaringRounds                int
	logDimensions                                    ring.Dimensions
	inputScale, square0Scale, rootScale, outputScale ExactScaleSnapshot
	kernelProfileDigest, exponentialArtifactDigest   string
	affineSourceDigest                               string
	multiplierPayloadDigest, offsetPayloadDigest     string
	operationCounts                                  GaoPeriodicBooleanN16L11OperationCounts
	digest                                           string
}

func (p GaoPeriodicBooleanN16L11Profile) Claim() GaoPeriodicBooleanN16L11Claim { return p.claim }
func (p GaoPeriodicBooleanN16L11Profile) InputLevel() int                      { return p.inputLevel }
func (p GaoPeriodicBooleanN16L11Profile) ExponentialLevel() int                { return p.exponentialLevel }
func (p GaoPeriodicBooleanN16L11Profile) Square0Level() int                    { return p.square0Level }
func (p GaoPeriodicBooleanN16L11Profile) RootLevel() int                       { return p.rootLevel }
func (p GaoPeriodicBooleanN16L11Profile) OutputLevel() int                     { return p.outputLevel }
func (p GaoPeriodicBooleanN16L11Profile) Slots() int                           { return p.slots }
func (p GaoPeriodicBooleanN16L11Profile) ExponentialDegree() int               { return p.exponentialDegree }
func (p GaoPeriodicBooleanN16L11Profile) SquaringRounds() int                  { return p.squaringRounds }
func (p GaoPeriodicBooleanN16L11Profile) LogDimensions() ring.Dimensions       { return p.logDimensions }
func (p GaoPeriodicBooleanN16L11Profile) InputScale() ExactScaleSnapshot       { return p.inputScale }
func (p GaoPeriodicBooleanN16L11Profile) RootScale() ExactScaleSnapshot        { return p.rootScale }
func (p GaoPeriodicBooleanN16L11Profile) OutputScale() ExactScaleSnapshot      { return p.outputScale }
func (p GaoPeriodicBooleanN16L11Profile) KernelProfileDigest() string          { return p.kernelProfileDigest }
func (p GaoPeriodicBooleanN16L11Profile) ExponentialArtifactDigest() string {
	return p.exponentialArtifactDigest
}
func (p GaoPeriodicBooleanN16L11Profile) AffineSourceDigest() string { return p.affineSourceDigest }
func (p GaoPeriodicBooleanN16L11Profile) MultiplierPayloadDigest() string {
	return p.multiplierPayloadDigest
}
func (p GaoPeriodicBooleanN16L11Profile) OffsetPayloadDigest() string { return p.offsetPayloadDigest }
func (p GaoPeriodicBooleanN16L11Profile) OperationCounts() GaoPeriodicBooleanN16L11OperationCounts {
	return p.operationCounts
}
func (p GaoPeriodicBooleanN16L11Profile) Digest() string { return p.digest }

type gaoPeriodicBooleanN16L11AffineSource struct {
	phase, multiplier, offset []*bignum.Complex
	digest                    string
}

type GaoPeriodicBooleanN16L11Circuit struct {
	params               ckks.Parameters
	encoder              *ckks.Encoder
	kernel               *GaoA2BKernelN16L11Circuit
	affineSource         gaoPeriodicBooleanN16L11AffineSource
	affineMultiplier     *rlwe.Plaintext
	affineOffset         *rlwe.Plaintext
	affineMultiplierSeal *rlwe.Plaintext
	affineOffsetSeal     *rlwe.Plaintext
	profile              GaoPeriodicBooleanN16L11Profile
}

func NewGaoPeriodicBooleanN16L11Circuit(
	params ckks.Parameters,
	encoder *ckks.Encoder,
) (*GaoPeriodicBooleanN16L11Circuit, error) {
	kernel, err := NewGaoA2BKernelN16L11Circuit(params, encoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct N16/L11 periodic Boolean kernel: %w", err)
	}
	kernelProfile := kernel.Profile()
	if kernelProfile.InputLevel() != gaoPeriodicBooleanN16L11InputLevel ||
		kernelProfile.ExponentialDegree() != 46 || kernelProfile.SquaringRounds() != 2 {
		return nil, fmt.Errorf("homchain: N16/L11 periodic Boolean kernel schedule changed")
	}
	source, err := newGaoPeriodicBooleanN16L11AffineSource(encoder.Prec())
	if err != nil {
		return nil, err
	}
	defaultScale := params.DefaultScale()
	square0Scale := defaultScale.Mul(defaultScale).Div(rlwe.NewScale(params.Q()[gaoPeriodicBooleanN16L11ExpLevel]))
	rootScale := square0Scale.Mul(square0Scale).Div(rlwe.NewScale(params.Q()[gaoPeriodicBooleanN16L11Square0Level]))
	multiplier, err := newGaoPeriodicBooleanN16L11Plaintext(
		params, encoder, source.multiplier, gaoPeriodicBooleanN16L11RootLevel,
		rlwe.NewScale(params.Q()[gaoPeriodicBooleanN16L11RootLevel]),
	)
	if err != nil {
		return nil, err
	}
	offset, err := newGaoPeriodicBooleanN16L11Plaintext(
		params, encoder, source.offset, gaoPeriodicBooleanN16L11OutputLevel, rootScale,
	)
	if err != nil {
		return nil, err
	}
	multiplierDigest, err := signed8PlaintextDigest(multiplier)
	if err != nil {
		return nil, err
	}
	offsetDigest, err := signed8PlaintextDigest(offset)
	if err != nil {
		return nil, err
	}
	snapshots := make([]ExactScaleSnapshot, 4)
	for index, scale := range []rlwe.Scale{defaultScale, square0Scale, rootScale, rootScale} {
		if snapshots[index], err = NewExactScaleSnapshot(scale); err != nil {
			return nil, err
		}
	}
	profile := GaoPeriodicBooleanN16L11Profile{
		claim:      GaoPeriodicBooleanN16L11SecurityUnverified,
		inputLevel: gaoPeriodicBooleanN16L11InputLevel, exponentialLevel: gaoPeriodicBooleanN16L11ExpLevel,
		square0Level: gaoPeriodicBooleanN16L11Square0Level, rootLevel: gaoPeriodicBooleanN16L11RootLevel,
		outputLevel: gaoPeriodicBooleanN16L11OutputLevel, slots: gaoPeriodicBooleanN16L11Slots,
		exponentialDegree: kernelProfile.ExponentialDegree(), squaringRounds: kernelProfile.SquaringRounds(),
		logDimensions: ring.Dimensions{Rows: 0, Cols: gaoA2BKernelN16L11LogSlots},
		inputScale:    snapshots[0], square0Scale: snapshots[1], rootScale: snapshots[2], outputScale: snapshots[3],
		kernelProfileDigest: kernelProfile.Digest(), exponentialArtifactDigest: kernelProfile.ExponentialArtifactDigest(),
		affineSourceDigest: source.digest, multiplierPayloadDigest: multiplierDigest, offsetPayloadDigest: offsetDigest,
		operationCounts: GaoPeriodicBooleanN16L11OperationCounts{
			ExponentialPolynomialEvaluations: 1, CiphertextCiphertextProducts: 2,
			Relinearizations: 2, ExplicitRescales: 3,
			CiphertextPlaintextProducts: 1, PlaintextVectorAdditions: 1,
		},
	}
	profile.digest = digestGaoPeriodicBooleanN16L11Profile(profile)
	circuit := &GaoPeriodicBooleanN16L11Circuit{
		params: params, encoder: encoder.ShallowCopy(), kernel: kernel, affineSource: source,
		affineMultiplier: multiplier, affineOffset: offset,
		affineMultiplierSeal: multiplier.CopyNew(), affineOffsetSeal: offset.CopyNew(), profile: profile,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *GaoPeriodicBooleanN16L11Circuit) Profile() GaoPeriodicBooleanN16L11Profile {
	if c == nil {
		return GaoPeriodicBooleanN16L11Profile{}
	}
	return c.profile
}

type GaoPeriodicBooleanN16L11Evaluator struct {
	circuit *GaoPeriodicBooleanN16L11Circuit
	kernel  *GaoA2BKernelN16L11Evaluator
}

func (c *GaoPeriodicBooleanN16L11Circuit) BindEvaluator(
	evaluator *ckks.Evaluator,
) (*GaoPeriodicBooleanN16L11Evaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	kernel, err := c.kernel.BindEvaluator(evaluator)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind N16/L11 periodic Boolean evaluator: %w", err)
	}
	return &GaoPeriodicBooleanN16L11Evaluator{circuit: c, kernel: kernel}, nil
}

type GaoPeriodicBooleanN16L11Provenance struct {
	profileDigest, inputPayloadDigest, outputPayloadDigest string
	states                                                 []GaoPeriodicBooleanN16L11State
	operationCounts                                        GaoPeriodicBooleanN16L11OperationCounts
	digest                                                 string
}

func (p GaoPeriodicBooleanN16L11Provenance) ProfileDigest() string      { return p.profileDigest }
func (p GaoPeriodicBooleanN16L11Provenance) InputPayloadDigest() string { return p.inputPayloadDigest }
func (p GaoPeriodicBooleanN16L11Provenance) OutputPayloadDigest() string {
	return p.outputPayloadDigest
}
func (p GaoPeriodicBooleanN16L11Provenance) States() []GaoPeriodicBooleanN16L11State {
	return append([]GaoPeriodicBooleanN16L11State(nil), p.states...)
}
func (p GaoPeriodicBooleanN16L11Provenance) OperationCounts() GaoPeriodicBooleanN16L11OperationCounts {
	return p.operationCounts
}
func (p GaoPeriodicBooleanN16L11Provenance) Digest() string { return p.digest }

type GaoPeriodicBooleanN16L11Result struct {
	output     *rlwe.Ciphertext
	provenance GaoPeriodicBooleanN16L11Provenance
}

func (r GaoPeriodicBooleanN16L11Result) Ciphertext() *rlwe.Ciphertext {
	if r.output == nil {
		return nil
	}
	return r.output.CopyNew()
}
func (r GaoPeriodicBooleanN16L11Result) Provenance() GaoPeriodicBooleanN16L11Provenance {
	result := r.provenance
	result.states = r.provenance.States()
	return result
}

func (e *GaoPeriodicBooleanN16L11Evaluator) EvaluateNew(
	input *rlwe.Ciphertext,
) (GaoPeriodicBooleanN16L11Result, error) {
	if e == nil || e.circuit == nil || e.kernel == nil {
		return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: nil N16/L11 periodic Boolean evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		return GaoPeriodicBooleanN16L11Result{}, err
	}
	if err := e.kernel.validateInput(input); err != nil {
		return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: periodic Boolean input: %w", err)
	}
	if err := e.kernel.preflightGraphAndKeys(); err != nil {
		return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: periodic Boolean preflight: %w", err)
	}
	inputBefore := input.CopyNew()
	inputDigest, err := signed8CiphertextDigest(input)
	if err != nil {
		return GaoPeriodicBooleanN16L11Result{}, err
	}
	states := make([]GaoPeriodicBooleanN16L11State, 0, 6)
	appendState := func(stage string, value *rlwe.Ciphertext, scale rlwe.Scale) error {
		state, stateErr := snapshotGaoPeriodicBooleanN16L11State(stage, value, scale)
		if stateErr == nil {
			states = append(states, state)
		}
		return stateErr
	}
	if err = appendState("input", input, e.circuit.params.DefaultScale()); err != nil {
		return GaoPeriodicBooleanN16L11Result{}, err
	}
	exponentialOperand, err := cloneA2BKernelPolynomialVector(e.circuit.kernel.exponentialOperand)
	if err != nil {
		return GaoPeriodicBooleanN16L11Result{}, err
	}
	exponential, err := e.kernel.polynomial.Evaluate(input, exponentialOperand, e.circuit.params.DefaultScale())
	if err != nil {
		return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: evaluate N16/L11 periodic exponential: %w", err)
	}
	if err = appendState("exponential", exponential, e.circuit.params.DefaultScale()); err != nil {
		return GaoPeriodicBooleanN16L11Result{}, err
	}
	root := exponential
	for round, stateName := range []string{"square-0", "root-of-unity"} {
		root, err = e.kernel.ckks.MulRelinNew(root, root)
		if err != nil {
			return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: periodic Boolean square %d: %w", round, err)
		}
		if err = e.kernel.ckks.Rescale(root, root); err != nil {
			return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: periodic Boolean square %d rescale: %w", round, err)
		}
		wantScale := []ExactScaleSnapshot{e.circuit.profile.square0Scale, e.circuit.profile.rootScale}[round]
		scale, scaleErr := wantScale.Scale()
		if scaleErr != nil {
			return GaoPeriodicBooleanN16L11Result{}, scaleErr
		}
		if err = appendState(stateName, root, scale); err != nil {
			return GaoPeriodicBooleanN16L11Result{}, err
		}
	}
	affineRaw, err := e.kernel.ckks.MulNew(root, e.circuit.affineMultiplier)
	if err != nil {
		return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: periodic Boolean affine multiply: %w", err)
	}
	rootScale, err := e.circuit.profile.rootScale.Scale()
	if err != nil {
		return GaoPeriodicBooleanN16L11Result{}, err
	}
	affineRawScale := rootScale.Mul(rlwe.NewScale(e.circuit.params.Q()[gaoPeriodicBooleanN16L11RootLevel]))
	if err = appendState("affine-raw", affineRaw, affineRawScale); err != nil {
		return GaoPeriodicBooleanN16L11Result{}, err
	}
	output := affineRaw.CopyNew()
	if err = e.kernel.ckks.Rescale(output, output); err != nil {
		return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: periodic Boolean affine rescale: %w", err)
	}
	if err = e.kernel.ckks.Add(output, e.circuit.affineOffset, output); err != nil {
		return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: periodic Boolean affine offset: %w", err)
	}
	if err = appendState("output", output, rootScale); err != nil {
		return GaoPeriodicBooleanN16L11Result{}, err
	}
	if !input.Equal(inputBefore) || !e.circuit.affineMultiplier.Equal(e.circuit.affineMultiplierSeal) ||
		!e.circuit.affineOffset.Equal(e.circuit.affineOffsetSeal) {
		return GaoPeriodicBooleanN16L11Result{}, fmt.Errorf("homchain: periodic Boolean evaluation mutated an input or cached affine operand")
	}
	outputDigest, err := signed8CiphertextDigest(output)
	if err != nil {
		return GaoPeriodicBooleanN16L11Result{}, err
	}
	provenance := GaoPeriodicBooleanN16L11Provenance{
		profileDigest: e.circuit.profile.digest, inputPayloadDigest: inputDigest,
		outputPayloadDigest: outputDigest, states: states, operationCounts: e.circuit.profile.operationCounts,
	}
	provenance.digest = digestGaoPeriodicBooleanN16L11Provenance(provenance)
	return GaoPeriodicBooleanN16L11Result{output: output, provenance: provenance}, nil
}

func (c *GaoPeriodicBooleanN16L11Circuit) validate() error {
	if c == nil || c.encoder == nil || c.kernel == nil || c.affineMultiplier == nil || c.affineOffset == nil ||
		c.affineMultiplierSeal == nil || c.affineOffsetSeal == nil {
		return fmt.Errorf("homchain: nil or incomplete N16/L11 periodic Boolean circuit")
	}
	if err := c.kernel.validate(); err != nil {
		return err
	}
	encoderParams := c.encoder.GetParameters()
	if !c.params.Equal(&encoderParams) || c.encoder.Prec() != gaoA2BKernelEncoderPrecision ||
		!c.affineMultiplier.Equal(c.affineMultiplierSeal) || !c.affineOffset.Equal(c.affineOffsetSeal) {
		return fmt.Errorf("homchain: N16/L11 periodic Boolean parameter or affine graph changed")
	}
	source, err := newGaoPeriodicBooleanN16L11AffineSource(c.encoder.Prec())
	if err != nil || source.digest != c.affineSource.digest {
		return fmt.Errorf("homchain: N16/L11 periodic Boolean affine source changed")
	}
	multiplierDigest, err := signed8PlaintextDigest(c.affineMultiplier)
	if err != nil {
		return err
	}
	offsetDigest, err := signed8PlaintextDigest(c.affineOffset)
	if err != nil {
		return err
	}
	p := c.profile
	if p.claim != GaoPeriodicBooleanN16L11SecurityUnverified || p.inputLevel != 17 ||
		p.exponentialLevel != 11 || p.square0Level != 10 || p.rootLevel != 9 || p.outputLevel != 8 ||
		p.slots != gaoPeriodicBooleanN16L11Slots || p.exponentialDegree != 46 || p.squaringRounds != 2 ||
		p.logDimensions != (ring.Dimensions{Rows: 0, Cols: 11}) ||
		p.kernelProfileDigest != c.kernel.profile.digest ||
		p.exponentialArtifactDigest != c.kernel.profile.exponentialArtifactDigest ||
		p.affineSourceDigest != source.digest || p.multiplierPayloadDigest != multiplierDigest ||
		p.offsetPayloadDigest != offsetDigest || p.digest != digestGaoPeriodicBooleanN16L11Profile(p) {
		return fmt.Errorf("homchain: N16/L11 periodic Boolean profile changed")
	}
	return nil
}

func newGaoPeriodicBooleanN16L11AffineSource(precision uint) (gaoPeriodicBooleanN16L11AffineSource, error) {
	if precision < gaoA2BKernelEncoderPrecision {
		return gaoPeriodicBooleanN16L11AffineSource{}, fmt.Errorf("homchain: periodic Boolean precision=%d, want >=256", precision)
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, precision)
	if err != nil {
		return gaoPeriodicBooleanN16L11AffineSource{}, err
	}
	coefficients := ringZ.TauInverse().Coefficients()
	if len(coefficients) != 2*gaoPeriodicBooleanN16L11HalfWidth {
		return gaoPeriodicBooleanN16L11AffineSource{}, fmt.Errorf("homchain: periodic Boolean tau inverse coefficient count changed")
	}
	result := gaoPeriodicBooleanN16L11AffineSource{
		phase:      make([]*bignum.Complex, gaoPeriodicBooleanN16L11Slots),
		multiplier: make([]*bignum.Complex, gaoPeriodicBooleanN16L11Slots),
		offset:     make([]*bignum.Complex, gaoPeriodicBooleanN16L11Slots),
	}
	var canonical strings.Builder
	fmt.Fprintf(&canonical, "gao-periodic-boolean-n16-l11-affine-v1|precision=%d|words=%d", precision, gaoPeriodicBooleanN16L11Words)
	for word := 0; word < gaoPeriodicBooleanN16L11Words; word++ {
		for slot := 0; slot < gaoPeriodicBooleanN16L11HalfWidth; slot++ {
			index := word*gaoPeriodicBooleanN16L11HalfWidth + slot
			phase := bignum.NewComplex().SetPrec(precision)
			phase.Real().Set(coefficients[slot])
			root := selectorPeriodicRootOfUnity(coefficients[slot], precision)
			denominator := &bignum.Complex{
				new(big.Float).SetPrec(precision).Sub(root.Real(), new(big.Float).SetPrec(precision).SetInt64(1)),
				new(big.Float).SetPrec(precision).Set(root.Imag()),
			}
			multiplier, reciprocalErr := selectorPeriodicComplexReciprocal(denominator, precision)
			if reciprocalErr != nil {
				return gaoPeriodicBooleanN16L11AffineSource{}, reciprocalErr
			}
			offset := &bignum.Complex{
				new(big.Float).SetPrec(precision).Neg(multiplier.Real()),
				new(big.Float).SetPrec(precision).Neg(multiplier.Imag()),
			}
			result.phase[index], result.multiplier[index], result.offset[index] = phase, multiplier, offset
			if word == 0 {
				fmt.Fprintf(&canonical, "|slot=%d/a=%s/m=%s,%s/c=%s,%s", slot,
					coefficients[slot].Text('x', -1), multiplier.Real().Text('x', -1), multiplier.Imag().Text('x', -1),
					offset.Real().Text('x', -1), offset.Imag().Text('x', -1))
			}
		}
	}
	result.digest = digestString(canonical.String())
	return result, nil
}

func evaluateGaoPeriodicBooleanN16L11Oracle(bit uint64, precision uint) ([]*bignum.Complex, error) {
	if bit > 1 {
		return nil, fmt.Errorf("homchain: periodic Boolean oracle bit=%d is not Boolean", bit)
	}
	source, err := newGaoPeriodicBooleanN16L11AffineSource(precision)
	if err != nil {
		return nil, err
	}
	result := make([]*bignum.Complex, len(source.phase))
	for index := range result {
		phase := new(big.Float).SetPrec(precision)
		if bit == 1 {
			phase.Set(source.phase[index].Real())
		}
		root := selectorPeriodicRootOfUnity(phase, precision)
		decoded := selectorPeriodicComplexMul(root, source.multiplier[index], precision)
		decoded.Real().Add(decoded.Real(), source.offset[index].Real())
		decoded.Imag().Add(decoded.Imag(), source.offset[index].Imag())
		result[index] = decoded
	}
	return result, nil
}

func newGaoPeriodicBooleanN16L11Plaintext(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	values []*bignum.Complex,
	level int,
	scale rlwe.Scale,
) (*rlwe.Plaintext, error) {
	if encoder == nil || len(values) != gaoPeriodicBooleanN16L11Slots || level < 0 || level > params.MaxLevel() {
		return nil, fmt.Errorf("homchain: invalid N16/L11 periodic Boolean plaintext source")
	}
	plaintext := ckks.NewPlaintext(params, level)
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: gaoA2BKernelN16L11LogSlots}
	plaintext.Scale = scale
	if err := encoder.Encode(cloneSelectorPeriodicComplexVector(values), plaintext); err != nil {
		return nil, fmt.Errorf("homchain: encode N16/L11 periodic Boolean plaintext: %w", err)
	}
	return plaintext, nil
}

func snapshotGaoPeriodicBooleanN16L11State(
	stage string,
	value *rlwe.Ciphertext,
	wantScale rlwe.Scale,
) (GaoPeriodicBooleanN16L11State, error) {
	if value == nil || value.MetaData == nil || value.Degree() != 1 ||
		value.LogDimensions != (ring.Dimensions{Rows: 0, Cols: gaoA2BKernelN16L11LogSlots}) ||
		!value.IsBatched || !value.IsNTT {
		return GaoPeriodicBooleanN16L11State{}, fmt.Errorf("homchain: invalid periodic Boolean state %s", stage)
	}
	scale, err := NewExactScaleSnapshot(value.Scale)
	if err != nil {
		return GaoPeriodicBooleanN16L11State{}, err
	}
	want, err := NewExactScaleSnapshot(wantScale)
	if err != nil || !scale.Equal(want) {
		return GaoPeriodicBooleanN16L11State{}, fmt.Errorf("homchain: periodic Boolean state %s scale changed", stage)
	}
	return GaoPeriodicBooleanN16L11State{
		Stage: stage, Level: value.Level(), Degree: value.Degree(),
		LogDimensions: value.LogDimensions, Scale: scale,
	}, nil
}

func digestGaoPeriodicBooleanN16L11Profile(profile GaoPeriodicBooleanN16L11Profile) string {
	return digestString(fmt.Sprintf(
		"%s|claim=%s|levels=%d,%d,%d,%d,%d|slots=%d|dimensions=%d,%d|degree=%d|squares=%d|scales=%s,%s,%s,%s|kernel=%s|exp=%s|affine=%s|multiplier=%s|offset=%s|counts=%+v",
		gaoPeriodicBooleanN16L11ProfileSchema, profile.claim, profile.inputLevel, profile.exponentialLevel,
		profile.square0Level, profile.rootLevel, profile.outputLevel, profile.slots,
		profile.logDimensions.Rows, profile.logDimensions.Cols, profile.exponentialDegree, profile.squaringRounds,
		profile.inputScale.canonicalString(), profile.square0Scale.canonicalString(),
		profile.rootScale.canonicalString(), profile.outputScale.canonicalString(),
		profile.kernelProfileDigest, profile.exponentialArtifactDigest, profile.affineSourceDigest,
		profile.multiplierPayloadDigest, profile.offsetPayloadDigest, profile.operationCounts,
	))
}

func digestGaoPeriodicBooleanN16L11Provenance(provenance GaoPeriodicBooleanN16L11Provenance) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s|profile=%s|input=%s|output=%s|counts=%+v",
		gaoPeriodicBooleanN16L11ResultSchema, provenance.profileDigest, provenance.inputPayloadDigest,
		provenance.outputPayloadDigest, provenance.operationCounts)
	for _, state := range provenance.states {
		fmt.Fprintf(&builder, "|state=%s,L%d,D%d,%d,%d,%s", state.Stage, state.Level, state.Degree,
			state.LogDimensions.Rows, state.LogDimensions.Cols, state.Scale.canonicalString())
	}
	return digestString(builder.String())
}
