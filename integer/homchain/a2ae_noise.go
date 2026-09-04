package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	ckksdft "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	ckkspolynomial "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/polynomial"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

// A2AENoiseFidelity is the strongest claim carried by this circuit. The
// dense/no-switch ScaleDown/ModUp bridge is a functional Lattigo adapter; it
// does not reproduce Gao--Zheng's sparse-key ModRaise construction.
type A2AENoiseFidelity string

const (
	A2AENoiseLattigoAdaptation A2AENoiseFidelity = "lattigo_adaptation"
)

// A2AENoiseMaturity prevents the tiny LogN=5 wiring parameters from being
// mistaken for a security-bearing parameter set.
type A2AENoiseMaturity string

const (
	A2AENoiseFunctionalNotSecure A2AENoiseMaturity = "functional_not_secure"
)

// A2AENoiseOptions bounds the deterministic Lattigo ScaleDown scale error.
type A2AENoiseOptions struct {
	MaxAbsLog2ScaleDownError float64
}

// A2AENoiseDFTProfile is a detached projection of the A2A-e-owned DFT
// literals and their high-precision numerical source witnesses.
type A2AENoiseDFTProfile struct {
	stcLiteral         ckksdft.MatrixLiteral
	ctsLiteral         ckksdft.MatrixLiteral
	encoderPrecision   uint
	generatorPrecision uint
	stcMatrixDigest    string
	ctsMatrixDigest    string
	digest             string
}

func (p A2AENoiseDFTProfile) SlotsToCoeffsLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.stcLiteral)
}

func (p A2AENoiseDFTProfile) CoeffsToSlotsLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.ctsLiteral)
}

func (p A2AENoiseDFTProfile) EncoderPrecision() uint            { return p.encoderPrecision }
func (p A2AENoiseDFTProfile) GeneratorPrecision() uint          { return p.generatorPrecision }
func (p A2AENoiseDFTProfile) SlotsToCoeffsMatrixDigest() string { return p.stcMatrixDigest }
func (p A2AENoiseDFTProfile) CoeffsToSlotsMatrixDigest() string { return p.ctsMatrixDigest }
func (p A2AENoiseDFTProfile) Digest() string                    { return p.digest }

// A2AENoiseTransformProfile describes one sealed fused transform pair.
type A2AENoiseTransformProfile struct {
	lowName         TransformName
	highName        TransformName
	levelQ          int
	levelP          int
	matrixScale     ExactScaleSnapshot
	logDimensions   ring.Dimensions
	rotationIndexes []int
	galoisElements  []uint64
}

func (p A2AENoiseTransformProfile) LowName() TransformName          { return p.lowName }
func (p A2AENoiseTransformProfile) HighName() TransformName         { return p.highName }
func (p A2AENoiseTransformProfile) LevelQ() int                     { return p.levelQ }
func (p A2AENoiseTransformProfile) LevelP() int                     { return p.levelP }
func (p A2AENoiseTransformProfile) MatrixScale() ExactScaleSnapshot { return p.matrixScale }
func (p A2AENoiseTransformProfile) LogDimensions() ring.Dimensions  { return p.logDimensions }
func (p A2AENoiseTransformProfile) RotationIndexes() []int {
	return append([]int(nil), p.rotationIndexes...)
}
func (p A2AENoiseTransformProfile) GaloisElements() []uint64 {
	return append([]uint64(nil), p.galoisElements...)
}

func cloneA2AENoiseTransformProfile(p A2AENoiseTransformProfile) A2AENoiseTransformProfile {
	result := p
	result.rotationIndexes = p.RotationIndexes()
	result.galoisElements = p.GaloisElements()
	return result
}

// A2AENoiseKeyProfile is the exact preflight union for the sealed graph.
type A2AENoiseKeyProfile struct {
	fusedT          []uint64
	slotsToCoeffs   []uint64
	trace           []uint64
	coeffsToSlots   []uint64
	fusedTInverse   []uint64
	conjugation     []uint64
	all             []uint64
	relinearization bool
	digest          string
}

func (p A2AENoiseKeyProfile) FusedT() []uint64 { return append([]uint64(nil), p.fusedT...) }
func (p A2AENoiseKeyProfile) SlotsToCoeffs() []uint64 {
	return append([]uint64(nil), p.slotsToCoeffs...)
}
func (p A2AENoiseKeyProfile) Trace() []uint64 { return append([]uint64(nil), p.trace...) }
func (p A2AENoiseKeyProfile) CoeffsToSlots() []uint64 {
	return append([]uint64(nil), p.coeffsToSlots...)
}
func (p A2AENoiseKeyProfile) FusedTInverse() []uint64 {
	return append([]uint64(nil), p.fusedTInverse...)
}
func (p A2AENoiseKeyProfile) Conjugation() []uint64 {
	return append([]uint64(nil), p.conjugation...)
}
func (p A2AENoiseKeyProfile) All() []uint64                 { return append([]uint64(nil), p.all...) }
func (p A2AENoiseKeyProfile) RelinearizationRequired() bool { return p.relinearization }
func (p A2AENoiseKeyProfile) Digest() string                { return p.digest }

func cloneA2AENoiseKeyProfile(p A2AENoiseKeyProfile) A2AENoiseKeyProfile {
	result := p
	result.fusedT = p.FusedT()
	result.slotsToCoeffs = p.SlotsToCoeffs()
	result.trace = p.Trace()
	result.coeffsToSlots = p.CoeffsToSlots()
	result.fusedTInverse = p.FusedTInverse()
	result.conjugation = p.Conjugation()
	result.all = p.All()
	return result
}

// A2AENoiseProfile fixes the only supported functional vertical slice.
type A2AENoiseProfile struct {
	fidelity                 A2AENoiseFidelity
	maturity                 A2AENoiseMaturity
	wordBits                 z2n.WordBits
	words                    int
	slots                    int
	encoderPrecision         uint
	logicalDepth             int
	postModUpPhysicalDepth   int
	transformNames           []TransformName
	fusedT                   A2AENoiseTransformProfile
	fusedTInverse            A2AENoiseTransformProfile
	dft                      A2AENoiseDFTProfile
	sineProfileDigest        string
	sineScaleSchedule        []ExactScaleSnapshot
	transformSourceDigest    string
	parametersDigest         string
	maxAbsLog2ScaleDownError float64
	digest                   string
}

func (p A2AENoiseProfile) Fidelity() A2AENoiseFidelity { return p.fidelity }
func (p A2AENoiseProfile) Maturity() A2AENoiseMaturity { return p.maturity }
func (p A2AENoiseProfile) WordBits() z2n.WordBits      { return p.wordBits }
func (p A2AENoiseProfile) Words() int                  { return p.words }
func (p A2AENoiseProfile) Slots() int                  { return p.slots }
func (p A2AENoiseProfile) EncoderPrecision() uint      { return p.encoderPrecision }
func (p A2AENoiseProfile) LogicalDepth() int           { return p.logicalDepth }
func (p A2AENoiseProfile) PostModUpPhysicalDepth() int { return p.postModUpPhysicalDepth }
func (p A2AENoiseProfile) TransformNames() []TransformName {
	return append([]TransformName(nil), p.transformNames...)
}
func (p A2AENoiseProfile) FusedT() A2AENoiseTransformProfile {
	return cloneA2AENoiseTransformProfile(p.fusedT)
}
func (p A2AENoiseProfile) FusedTInverse() A2AENoiseTransformProfile {
	return cloneA2AENoiseTransformProfile(p.fusedTInverse)
}
func (p A2AENoiseProfile) DFT() A2AENoiseDFTProfile {
	result := p.dft
	result.stcLiteral = p.dft.SlotsToCoeffsLiteral()
	result.ctsLiteral = p.dft.CoeffsToSlotsLiteral()
	return result
}
func (p A2AENoiseProfile) SineProfileDigest() string { return p.sineProfileDigest }
func (p A2AENoiseProfile) SineScaleSchedule() []ExactScaleSnapshot {
	return append([]ExactScaleSnapshot(nil), p.sineScaleSchedule...)
}
func (p A2AENoiseProfile) TransformSourceDigest() string { return p.transformSourceDigest }
func (p A2AENoiseProfile) ParametersDigest() string      { return p.parametersDigest }
func (p A2AENoiseProfile) MaxAbsLog2ScaleDownError() float64 {
	return p.maxAbsLog2ScaleDownError
}
func (p A2AENoiseProfile) Digest() string { return p.digest }

// A2AENoiseCircuit owns every transform, DFT matrix and sine operand used by
// EvalArithToArithNoise. No executable matrix is exposed by an accessor.
type A2AENoiseCircuit struct {
	params               ckks.Parameters
	encoder              *ckks.Encoder
	fusedT               CompiledPair
	fusedTInverse        CompiledPair
	stc                  ckksdft.Matrix
	cts                  ckksdft.Matrix
	sineProfile          GaoSineKernelProfile
	sinePolynomialTarget rlwe.Scale
	sineExpectedScales   []rlwe.Scale
	options              A2AENoiseOptions
	profile              A2AENoiseProfile
	keyProfile           A2AENoiseKeyProfile
}

// A2AENoiseFunctionalParameters returns the fixed wiring-only parameter set.
func A2AENoiseFunctionalParameters() (ckks.Parameters, error) {
	logQ := make([]int, 17)
	for i := range logQ {
		logQ[i] = 35
	}
	return ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: logQ, LogP: []int{60}, LogDefaultScale: 35,
	})
}

// NewA2AENoiseCircuit seals the fixed n=8, four-word, full-packed A2A-e graph.
func NewA2AENoiseCircuit(params ckks.Parameters, encoder *ckks.Encoder, options A2AENoiseOptions) (*A2AENoiseCircuit, error) {
	if encoder == nil {
		return nil, fmt.Errorf("homchain: A2A-e encoder is nil")
	}
	encoderParams := encoder.GetParameters()
	if !params.Equal(&encoderParams) || encoder.Prec() != z2n.DefaultPrecision {
		return nil, fmt.Errorf("homchain: A2A-e encoder parameters or precision do not match the fixed profile")
	}
	if err := validateA2AENoiseParameters(params); err != nil {
		return nil, err
	}
	if options.MaxAbsLog2ScaleDownError <= 0 || math.IsNaN(options.MaxAbsLog2ScaleDownError) || math.IsInf(options.MaxAbsLog2ScaleDownError, 0) {
		return nil, fmt.Errorf("homchain: invalid A2A-e ScaleDown error bound %g", options.MaxAbsLog2ScaleDownError)
	}

	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-e construct Z2^8 ring: %w", err)
	}
	const words = 4
	specifications, err := NewSpecificationsFromRing(ringZ, words)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-e construct fused transform sources: %w", err)
	}
	vSpec, uSpec := specifications.VFusedTPair(), specifications.UFusedTInvPair()
	if vSpec.Low.Name() != V0FusedT || vSpec.High.Name() != V1FusedT ||
		uSpec.Low.Name() != U0FusedTInv || uSpec.High.Name() != U1FusedTInv {
		return nil, fmt.Errorf("homchain: A2A-e transform sources are not fused-t/fused-t-inverse")
	}
	sineProfile, err := NewGaoSineKernelProfile()
	if err != nil {
		return nil, err
	}
	sineTarget, sineScales, err := measureA2AENoiseSineSchedule(params, encoder, sineProfile)
	if err != nil {
		return nil, fmt.Errorf("homchain: measure and seal A2A-e sine scale schedule: %w", err)
	}
	vOptions := CompileOptions{
		LevelQ: params.MaxLevel(), LevelP: params.MaxLevelP(),
		Scale: rlwe.NewScale(params.Q()[params.MaxLevel()]), LogBabyStepGiantStepRatio: 0,
	}
	fusedT, err := CompilePair(params, encoder, vSpec, vOptions)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-e compile fused-t V: %w", err)
	}
	// The three square/rescale rounds reach a scale extremely close to, but
	// not bit-identical with, Delta because their backwards square roots are
	// rounded at rlwe.ScalePrecision. Fold the exact compensating ratio into
	// the final fused U plaintext scale; no ciphertext metadata is retagged.
	uMatrixScale := rlwe.NewScale(params.Q()[4]).Mul(params.DefaultScale()).Div(sineScales[4])
	uOptions := CompileOptions{
		LevelQ: 4, LevelP: params.MaxLevelP(), Scale: uMatrixScale,
		LogBabyStepGiantStepRatio: 0,
	}
	fusedTInverse, err := CompilePair(params, encoder, uSpec, uOptions)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-e compile fused-t-inverse U: %w", err)
	}
	if err = validateCompiledPairAtLevel("A2A-e fused-t V", fusedT, 16); err != nil {
		return nil, err
	}
	if err = validateCompiledPairAtLevel("A2A-e fused-t-inverse U", fusedTInverse, 4); err != nil {
		return nil, err
	}

	stcLiteral, ctsLiteral := a2aeNoiseDFTLiterals(params, encoder.Prec())
	stc, stcDigest, err := newDFTMatrixFromLiteralAtPrecision(params, stcLiteral, encoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-e encode Slots-To-Coeffs: %w", err)
	}
	cts, ctsDigest, err := newDFTMatrixFromLiteralAtPrecision(params, ctsLiteral, encoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-e encode Coeffs-To-Slots: %w", err)
	}
	dftProfile := A2AENoiseDFTProfile{
		stcLiteral: cloneDFTLiteral(stcLiteral), ctsLiteral: cloneDFTLiteral(ctsLiteral),
		encoderPrecision: encoder.Prec(), generatorPrecision: encoder.Prec(),
		stcMatrixDigest: stcDigest, ctsMatrixDigest: ctsDigest,
	}
	dftProfile.digest = digestString(fmt.Sprintf(
		"a2ae-dft-v1|stc=%v|cts=%v|encoder=%d|generator=%d|stc-matrix=%s|cts-matrix=%s|normalization=lattigo-full-split-gap1-cts-1-over-16",
		dftLiteralTrace(stcLiteral), dftLiteralTrace(ctsLiteral), encoder.Prec(), encoder.Prec(), stcDigest, ctsDigest,
	))

	vProfile, err := newA2AENoiseTransformProfile(params, vSpec, fusedT, vOptions)
	if err != nil {
		return nil, err
	}
	uProfile, err := newA2AENoiseTransformProfile(params, uSpec, fusedTInverse, uOptions)
	if err != nil {
		return nil, err
	}
	keyProfile := newA2AENoiseKeyProfile(params, fusedT, fusedTInverse, stcLiteral, ctsLiteral)
	if got, want := keyProfile.All(), []uint64{5, 17, 25, 33, 41, 49, 63}; !equalA2AENoiseUint64s(got, want) {
		return nil, fmt.Errorf("homchain: A2A-e generated Galois union=%v, want exact %v", got, want)
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal A2A-e parameters: %w", err)
	}
	sineScaleSnapshots := make([]ExactScaleSnapshot, len(sineScales))
	for i := range sineScales {
		if sineScaleSnapshots[i], err = NewExactScaleSnapshot(sineScales[i]); err != nil {
			return nil, fmt.Errorf("homchain: snapshot A2A-e sine schedule %d: %w", i, err)
		}
	}
	profile := A2AENoiseProfile{
		fidelity: A2AENoiseLattigoAdaptation, maturity: A2AENoiseFunctionalNotSecure,
		wordBits: z2n.Word8, words: words, slots: params.MaxSlots(), encoderPrecision: encoder.Prec(),
		logicalDepth: 16, postModUpPhysicalDepth: 13,
		transformNames: []TransformName{V0FusedT, V1FusedT, U0FusedTInv, U1FusedTInv},
		fusedT:         vProfile, fusedTInverse: uProfile, dft: dftProfile,
		sineProfileDigest: sineProfile.Digest(), sineScaleSchedule: sineScaleSnapshots,
		transformSourceDigest: digestA2AENoiseTransformSources(vSpec, uSpec),
		parametersDigest:      sha256Hex(parameterBytes), maxAbsLog2ScaleDownError: options.MaxAbsLog2ScaleDownError,
	}
	profile.digest = digestA2AENoiseProfile(profile, keyProfile)
	return &A2AENoiseCircuit{
		params: params, encoder: encoder.ShallowCopy(), fusedT: fusedT, fusedTInverse: fusedTInverse,
		stc: stc, cts: cts, sineProfile: sineProfile, sinePolynomialTarget: sineTarget,
		sineExpectedScales: append([]rlwe.Scale(nil), sineScales...),
		options:            options, profile: profile, keyProfile: keyProfile,
	}, nil
}

func (c *A2AENoiseCircuit) Profile() A2AENoiseProfile {
	if c == nil {
		return A2AENoiseProfile{}
	}
	result := c.profile
	result.transformNames = c.profile.TransformNames()
	result.fusedT = c.profile.FusedT()
	result.fusedTInverse = c.profile.FusedTInverse()
	result.dft = c.profile.DFT()
	result.sineScaleSchedule = c.profile.SineScaleSchedule()
	return result
}

func (c *A2AENoiseCircuit) RequiredKeyProfile() A2AENoiseKeyProfile {
	if c == nil {
		return A2AENoiseKeyProfile{}
	}
	return cloneA2AENoiseKeyProfile(c.keyProfile)
}

func equalA2AENoiseUint64s(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func validateA2AENoiseParameters(params ckks.Parameters) error {
	canonical, err := A2AENoiseFunctionalParameters()
	if err != nil {
		return fmt.Errorf("homchain: construct canonical A2A-e parameters: %w", err)
	}
	if !params.Equal(&canonical) {
		return fmt.Errorf("homchain: A2A-e parameters differ from the exact canonical modulus chain")
	}
	if params.LogN() != 5 || params.RingType() != ring.Standard || params.MaxSlots() != 16 ||
		params.MaxLevel() != 16 || params.MaxLevelP() != 0 || params.LevelsConsumedPerRescaling() != 1 {
		return fmt.Errorf("homchain: A2A-e requires standard LogN=5, 17 Q primes, one P prime, and 16 full slots")
	}
	if params.LogDefaultScale() != 35 || len(params.Q()) != 17 || len(params.P()) != 1 || roundedLog2(params.P()[0]) != 60 {
		return fmt.Errorf("homchain: A2A-e requires LogQ=[35x17], LogP=[60], LogDefaultScale=35")
	}
	for i, qi := range params.Q() {
		if roundedLog2(qi) != 35 {
			return fmt.Errorf("homchain: A2A-e Q[%d] has %d bits, want 35", i, roundedLog2(qi))
		}
	}
	return nil
}

func a2aeNoiseDFTLiterals(params ckks.Parameters, precision uint) (ckksdft.MatrixLiteral, ckksdft.MatrixLiteral) {
	one := new(big.Float).SetPrec(precision).SetInt64(1)
	oneSixteenth := new(big.Float).SetPrec(precision).SetInt64(1)
	oneSixteenth.SetMantExp(oneSixteenth, -4)
	return ckksdft.MatrixLiteral{
			Type: ckksdft.HomomorphicDecode, Format: ckksdft.SplitRealAndImag,
			LogSlots: params.LogMaxSlots(), LevelQ: 15, LevelP: params.MaxLevelP(),
			Levels: []int{1, 1}, Scaling: one, LogBSGSRatio: 0,
		}, ckksdft.MatrixLiteral{
			Type: ckksdft.HomomorphicEncode, Format: ckksdft.SplitRealAndImag,
			LogSlots: params.LogMaxSlots(), LevelQ: 16, LevelP: params.MaxLevelP(),
			Levels: []int{1, 1, 1}, Scaling: oneSixteenth, LogBSGSRatio: 0,
		}
}

func newA2AENoiseTransformProfile(params ckks.Parameters, spec PairSpec, pair CompiledPair, options CompileOptions) (A2AENoiseTransformProfile, error) {
	scale, err := NewExactScaleSnapshot(options.Scale)
	if err != nil {
		return A2AENoiseTransformProfile{}, err
	}
	return A2AENoiseTransformProfile{
		lowName: spec.Low.Name(), highName: spec.High.Name(), levelQ: options.LevelQ, levelP: options.LevelP,
		matrixScale: scale, logDimensions: pair.Low.LogDimensions, rotationIndexes: pair.RotationIndexes(),
		galoisElements: pair.GaloisElements(params),
	}, nil
}

func newA2AENoiseKeyProfile(params ckks.Parameters, v, u CompiledPair, stc, cts ckksdft.MatrixLiteral) A2AENoiseKeyProfile {
	identity := params.GaloisElement(0)
	filter := func(values []uint64) []uint64 {
		result := make([]uint64, 0, len(values))
		for _, value := range values {
			if value != identity {
				result = append(result, value)
			}
		}
		return uniqueGaloisElements(result)
	}
	profile := A2AENoiseKeyProfile{
		fusedT: filter(v.GaloisElements(params)), slotsToCoeffs: filter(stc.GaloisElements(params)),
		trace:         filter(params.GaloisElementsForTrace(params.LogMaxSlots())),
		coeffsToSlots: filter(cts.GaloisElements(params)), fusedTInverse: filter(u.GaloisElements(params)),
		conjugation: filter([]uint64{params.GaloisElementForComplexConjugation()}), relinearization: true,
	}
	profile.all = filter(append(append(append(append(append(
		append([]uint64(nil), profile.fusedT...), profile.slotsToCoeffs...), profile.trace...),
		profile.coeffsToSlots...), profile.fusedTInverse...), profile.conjugation...))
	profile.digest = digestString(fmt.Sprintf(
		"a2ae-keys-v1|fused-t=%v|stc=%v|trace=%v|cts=%v|fused-t-inverse=%v|conjugation=%v|all=%v|relinearization=true|switching=dense-no-switch",
		profile.fusedT, profile.slotsToCoeffs, profile.trace, profile.coeffsToSlots,
		profile.fusedTInverse, profile.conjugation, profile.all,
	))
	return profile
}

func digestA2AENoiseTransformSources(v, u PairSpec) string {
	var canonical strings.Builder
	canonical.WriteString("a2ae-fused-transform-source-v1")
	for _, spec := range []TransformSpec{v.Low, v.High, u.Low, u.High} {
		fmt.Fprintf(&canonical, "|name=%s|layout=%s|words=%d|half=%d|dimensions=%d,%d|matrix=", spec.Name(), spec.Layout(), spec.Words(), spec.HalfWidth(), spec.LogDimensions().Rows, spec.LogDimensions().Cols)
		for _, row := range spec.Matrix() {
			for _, value := range row {
				fmt.Fprintf(&canonical, "%s,%s;", value.Real().Text('x', -1), value.Imag().Text('x', -1))
			}
		}
	}
	return digestString(canonical.String())
}

func canonicalA2AENoiseTransform(p A2AENoiseTransformProfile) string {
	return fmt.Sprintf("%s,%s@Q%d/P%d/scale={%s}/dims=%d,%d/rot=%v/gal=%v",
		p.lowName, p.highName, p.levelQ, p.levelP, p.matrixScale.canonicalString(),
		p.logDimensions.Rows, p.logDimensions.Cols, p.rotationIndexes, p.galoisElements)
}

func digestA2AENoiseProfile(profile A2AENoiseProfile, keys A2AENoiseKeyProfile) string {
	var sineScales strings.Builder
	for index, scale := range profile.sineScaleSchedule {
		fmt.Fprintf(&sineScales, "%d={%s};", index, scale.canonicalString())
	}
	canonical := fmt.Sprintf(
		"a2ae-noise-profile-v2|fidelity=%s|maturity=%s|n=%d|words=%d|slots=%d|precision=%d|logical-depth=%d|post-modup-depth=%d|names=%v|V=%s|U=%s|dft=%s|sine=%s|sine-scales=%s|transform-source=%s|params=%s|keys=%s|max-scaledown-error=%016x",
		profile.fidelity, profile.maturity, profile.wordBits, profile.words, profile.slots,
		profile.encoderPrecision, profile.logicalDepth, profile.postModUpPhysicalDepth, profile.transformNames,
		canonicalA2AENoiseTransform(profile.fusedT), canonicalA2AENoiseTransform(profile.fusedTInverse),
		profile.dft.digest, profile.sineProfileDigest, sineScales.String(), profile.transformSourceDigest, profile.parametersDigest,
		keys.digest, math.Float64bits(profile.maxAbsLog2ScaleDownError),
	)
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

// A2AENoiseDomainVerification records that the encrypted post-CTS domain is
// admitted by an external artifact, not proved by this package.
type A2AENoiseDomainVerification string

const (
	A2AENoiseDomainExternalUnverified A2AENoiseDomainVerification = "external_unverified"
)

// A2AENoiseInputCertificate binds the fixed encrypted input state and the
// externally justified periodic sine domain |I|+|u| <= 16. The ciphertext
// itself cannot reveal I, so this remains an integrity-checked declaration.
type A2AENoiseInputCertificate struct {
	profileDigest         string
	level                 int
	scale                 ExactScaleSnapshot
	logDimensions         ring.Dimensions
	slots                 int
	maxAbsIntegerLift     int64
	maxAbsPerturbationNum *big.Int
	maxAbsPerturbationDen *big.Int
	evidenceArtifact      string
	evidenceDigest        string
	verification          A2AENoiseDomainVerification
	maturity              A2AENoiseMaturity
	digest                string
}

// NewA2AENoiseInputCertificate creates a profile-bound admission. The bound
// is expressed before division by K=16: CTS yields x=(I+u)/16, and the fixed
// sine is periodic in the integer lift I.
func NewA2AENoiseInputCertificate(
	profile A2AENoiseProfile,
	delta rlwe.Scale,
	maxAbsIntegerLift int64,
	maxAbsPerturbation *big.Rat,
	evidenceArtifact, evidenceDigest string,
) (A2AENoiseInputCertificate, error) {
	if profile.digest == "" || profile.fidelity != A2AENoiseLattigoAdaptation ||
		profile.maturity != A2AENoiseFunctionalNotSecure || profile.slots != 16 {
		return A2AENoiseInputCertificate{}, fmt.Errorf("homchain: invalid A2A-e profile for admission")
	}
	if delta.Mod != nil {
		return A2AENoiseInputCertificate{}, fmt.Errorf("homchain: A2A-e Delta must be non-modular")
	}
	if maxAbsIntegerLift < 0 || maxAbsIntegerLift > 15 || maxAbsPerturbation == nil || maxAbsPerturbation.Sign() < 0 {
		return A2AENoiseInputCertificate{}, fmt.Errorf("homchain: invalid A2A-e integer-lift or perturbation bound")
	}
	bound := new(big.Rat).Add(new(big.Rat).SetInt64(maxAbsIntegerLift), maxAbsPerturbation)
	if bound.Cmp(big.NewRat(16, 1)) > 0 {
		return A2AENoiseInputCertificate{}, fmt.Errorf("homchain: A2A-e admitted |I|+|u|=%s exceeds K=16", bound.RatString())
	}
	if evidenceArtifact == "" || evidenceDigest != digestString(evidenceArtifact) {
		return A2AENoiseInputCertificate{}, fmt.Errorf("homchain: A2A-e evidence artifact is empty or has a mismatched digest")
	}
	scale, err := NewExactScaleSnapshot(delta)
	if err != nil {
		return A2AENoiseInputCertificate{}, err
	}
	certificate := A2AENoiseInputCertificate{
		profileDigest: profile.digest, level: 16, scale: scale,
		logDimensions: ring.Dimensions{Rows: 0, Cols: 4}, slots: 16,
		maxAbsIntegerLift:     maxAbsIntegerLift,
		maxAbsPerturbationNum: new(big.Int).Set(maxAbsPerturbation.Num()),
		maxAbsPerturbationDen: new(big.Int).Set(maxAbsPerturbation.Denom()),
		evidenceArtifact:      evidenceArtifact, evidenceDigest: evidenceDigest,
		verification: A2AENoiseDomainExternalUnverified, maturity: A2AENoiseFunctionalNotSecure,
	}
	certificate.digest = digestString(certificate.canonicalString())
	return certificate, nil
}

func (c A2AENoiseInputCertificate) ProfileDigest() string          { return c.profileDigest }
func (c A2AENoiseInputCertificate) Level() int                     { return c.level }
func (c A2AENoiseInputCertificate) Scale() ExactScaleSnapshot      { return c.scale }
func (c A2AENoiseInputCertificate) LogDimensions() ring.Dimensions { return c.logDimensions }
func (c A2AENoiseInputCertificate) Slots() int                     { return c.slots }
func (c A2AENoiseInputCertificate) MaxAbsIntegerLift() int64       { return c.maxAbsIntegerLift }
func (c A2AENoiseInputCertificate) MaxAbsPerturbation() *big.Rat {
	if c.maxAbsPerturbationNum == nil || c.maxAbsPerturbationDen == nil {
		return nil
	}
	return new(big.Rat).SetFrac(new(big.Int).Set(c.maxAbsPerturbationNum), new(big.Int).Set(c.maxAbsPerturbationDen))
}
func (c A2AENoiseInputCertificate) EvidenceArtifact() string { return c.evidenceArtifact }
func (c A2AENoiseInputCertificate) EvidenceDigest() string   { return c.evidenceDigest }
func (c A2AENoiseInputCertificate) VerificationStatus() A2AENoiseDomainVerification {
	return c.verification
}
func (c A2AENoiseInputCertificate) Maturity() A2AENoiseMaturity    { return c.maturity }
func (c A2AENoiseInputCertificate) DomainInternallyVerified() bool { return false }
func (c A2AENoiseInputCertificate) Digest() string                 { return c.digest }

func (c A2AENoiseInputCertificate) canonicalString() string {
	numerator, denominator := "", ""
	if c.maxAbsPerturbationNum != nil {
		numerator = c.maxAbsPerturbationNum.String()
	}
	if c.maxAbsPerturbationDen != nil {
		denominator = c.maxAbsPerturbationDen.String()
	}
	return fmt.Sprintf(
		"a2ae-admission-v1|profile=%s|level=%d|scale={%s}|dimensions=%d,%d|slots=%d|max-lift=%d|max-u=%s/%s|evidence=%s|verification=%s|maturity=%s",
		c.profileDigest, c.level, c.scale.canonicalString(), c.logDimensions.Rows, c.logDimensions.Cols,
		c.slots, c.maxAbsIntegerLift, numerator, denominator, c.evidenceDigest, c.verification, c.maturity,
	)
}

func (c A2AENoiseInputCertificate) validate(profile A2AENoiseProfile) error {
	perturbation := c.MaxAbsPerturbation()
	if perturbation == nil || c.profileDigest != profile.digest || c.level != 16 ||
		c.logDimensions != (ring.Dimensions{Rows: 0, Cols: 4}) || c.slots != 16 ||
		c.maxAbsIntegerLift < 0 || c.maxAbsIntegerLift > 15 || perturbation.Sign() < 0 ||
		new(big.Rat).Add(new(big.Rat).SetInt64(c.maxAbsIntegerLift), perturbation).Cmp(big.NewRat(16, 1)) > 0 ||
		c.evidenceArtifact == "" || c.evidenceDigest != digestString(c.evidenceArtifact) ||
		c.verification != A2AENoiseDomainExternalUnverified || c.maturity != A2AENoiseFunctionalNotSecure ||
		c.digest != digestString(c.canonicalString()) {
		return fmt.Errorf("homchain: invalid or foreign A2A-e input certificate")
	}
	if _, err := c.scale.Scale(); err != nil || c.scale.HasMod() {
		return fmt.Errorf("homchain: invalid A2A-e certificate scale")
	}
	return nil
}

// A2AENoiseStage identifies each physical boundary of the sealed graph.
type A2AENoiseStage string

const (
	A2AENoiseStageKeyPreflight      A2AENoiseStage = "key-preflight"
	A2AENoiseStageInput             A2AENoiseStage = "input"
	A2AENoiseStageFusedTZToC        A2AENoiseStage = "fused-t-z-to-c"
	A2AENoiseStageSlotsToCoeffs     A2AENoiseStage = "slots-to-coeffs"
	A2AENoiseStageScaleDown         A2AENoiseStage = "guarded-scale-down"
	A2AENoiseStageModUp             A2AENoiseStage = "mod-up-full-pack-trace"
	A2AENoiseStageCoeffsToSlots     A2AENoiseStage = "coeffs-to-slots-one-over-16"
	A2AENoiseStageSinePolynomial    A2AENoiseStage = "gao-degree-32-sine"
	A2AENoiseStageDoubleAngle0      A2AENoiseStage = "gao-double-angle-0"
	A2AENoiseStageDoubleAngle1      A2AENoiseStage = "gao-double-angle-1"
	A2AENoiseStageDoubleAngle2      A2AENoiseStage = "gao-double-angle-2"
	A2AENoiseStageRecoveredError    A2AENoiseStage = "fused-t-inverse-c-to-z"
	A2AENoiseStageOriginalDropLevel A2AENoiseStage = "original-drop-level"
	A2AENoiseStageOutputSubtract    A2AENoiseStage = "input-minus-recovered-error"
)

// A2AENoiseLane distinguishes whole-ciphertext states from low/high halves.
type A2AENoiseLane string

const (
	A2AENoiseWhole A2AENoiseLane = "whole"
	A2AENoiseLow   A2AENoiseLane = "low"
	A2AENoiseHigh  A2AENoiseLane = "high"
)

// A2AENoiseCiphertextState is an exact detached level/scale snapshot.
type A2AENoiseCiphertextState struct {
	Lane          A2AENoiseLane
	Stage         A2AENoiseStage
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
	ExpectedScale ExactScaleSnapshot
	ScaleExact    bool
}

// A2AENoiseOperationCounts makes the source-distinguishing graph auditable.
type A2AENoiseOperationCounts struct {
	FusedTZToC               int
	SlotsToCoeffsFactors     int
	ScaleDown                int
	ModUp                    int
	CoeffsToSlotsFactors     int
	SinePolynomialPerHalf    int
	DoubleAnglesPerHalf      int
	FusedTInverseCToZ        int
	OriginalDropLevel        int
	FinalInputMinusRecovered int
}

// A2AENoiseKeyPreflight records the single fail-closed preflight performed
// before a copy or homomorphic operation touches the input.
type A2AENoiseKeyPreflight struct {
	Checked                bool
	GraphChecked           bool
	GraphMatched           bool
	GraphMismatch          string
	MissingGaloisElements  []uint64
	InvalidGaloisElements  []uint64
	RelinearizationPresent bool
	RelinearizationMatched bool
	DenseNoSwitchMatched   bool
}

func cloneA2AENoiseKeyPreflight(p A2AENoiseKeyPreflight) A2AENoiseKeyPreflight {
	result := p
	result.MissingGaloisElements = append([]uint64(nil), p.MissingGaloisElements...)
	result.InvalidGaloisElements = append([]uint64(nil), p.InvalidGaloisElements...)
	return result
}

// A2AENoiseTrace is the immutable evidence record returned by one run.
type A2AENoiseTrace struct {
	fidelity           A2AENoiseFidelity
	maturity           A2AENoiseMaturity
	profileDigest      string
	certificateDigest  string
	transformDigest    string
	dft                A2AENoiseDFTProfile
	sineProfileDigest  string
	states             []A2AENoiseCiphertextState
	keyPreflight       A2AENoiseKeyPreflight
	operationCounts    A2AENoiseOperationCounts
	scaleDownError     ExactScaleSnapshot
	scaleDownLog2Error float64
	periodicDomain     string
	failureStage       A2AENoiseStage
	ctsLow             *rlwe.Ciphertext
	ctsHigh            *rlwe.Ciphertext
	fusedLow           *rlwe.Ciphertext
	fusedHigh          *rlwe.Ciphertext
	raisedCoefficients *rlwe.Ciphertext
	sineLow            *rlwe.Ciphertext
	sineHigh           *rlwe.Ciphertext
	recoveredError     *rlwe.Ciphertext
}

func (t A2AENoiseTrace) Fidelity() A2AENoiseFidelity   { return t.fidelity }
func (t A2AENoiseTrace) Maturity() A2AENoiseMaturity   { return t.maturity }
func (t A2AENoiseTrace) ProfileDigest() string         { return t.profileDigest }
func (t A2AENoiseTrace) CertificateDigest() string     { return t.certificateDigest }
func (t A2AENoiseTrace) TransformSourceDigest() string { return t.transformDigest }
func (t A2AENoiseTrace) DFT() A2AENoiseDFTProfile {
	result := t.dft
	result.stcLiteral = t.dft.SlotsToCoeffsLiteral()
	result.ctsLiteral = t.dft.CoeffsToSlotsLiteral()
	return result
}
func (t A2AENoiseTrace) SineProfileDigest() string { return t.sineProfileDigest }
func (t A2AENoiseTrace) States() []A2AENoiseCiphertextState {
	return append([]A2AENoiseCiphertextState(nil), t.states...)
}
func (t A2AENoiseTrace) State(lane A2AENoiseLane, stage A2AENoiseStage) (A2AENoiseCiphertextState, bool) {
	for _, state := range t.states {
		if state.Lane == lane && state.Stage == stage {
			return state, true
		}
	}
	return A2AENoiseCiphertextState{}, false
}
func (t A2AENoiseTrace) KeyPreflight() A2AENoiseKeyPreflight {
	return cloneA2AENoiseKeyPreflight(t.keyPreflight)
}
func (t A2AENoiseTrace) OperationCounts() A2AENoiseOperationCounts { return t.operationCounts }
func (t A2AENoiseTrace) ScaleDownError() (ExactScaleSnapshot, float64) {
	return t.scaleDownError, t.scaleDownLog2Error
}
func (t A2AENoiseTrace) PeriodicDomain() string       { return t.periodicDomain }
func (t A2AENoiseTrace) FailureStage() A2AENoiseStage { return t.failureStage }
func (t A2AENoiseTrace) CoeffsToSlotsLow() *rlwe.Ciphertext {
	if t.ctsLow == nil {
		return nil
	}
	return t.ctsLow.CopyNew()
}
func (t A2AENoiseTrace) FusedTLow() *rlwe.Ciphertext {
	if t.fusedLow == nil {
		return nil
	}
	return t.fusedLow.CopyNew()
}
func (t A2AENoiseTrace) FusedTHigh() *rlwe.Ciphertext {
	if t.fusedHigh == nil {
		return nil
	}
	return t.fusedHigh.CopyNew()
}
func (t A2AENoiseTrace) RaisedCoefficients() *rlwe.Ciphertext {
	if t.raisedCoefficients == nil {
		return nil
	}
	return t.raisedCoefficients.CopyNew()
}
func (t A2AENoiseTrace) SineLow() *rlwe.Ciphertext {
	if t.sineLow == nil {
		return nil
	}
	return t.sineLow.CopyNew()
}
func (t A2AENoiseTrace) SineHigh() *rlwe.Ciphertext {
	if t.sineHigh == nil {
		return nil
	}
	return t.sineHigh.CopyNew()
}
func (t A2AENoiseTrace) CoeffsToSlotsHigh() *rlwe.Ciphertext {
	if t.ctsHigh == nil {
		return nil
	}
	return t.ctsHigh.CopyNew()
}
func (t A2AENoiseTrace) RecoveredError() *rlwe.Ciphertext {
	if t.recoveredError == nil {
		return nil
	}
	return t.recoveredError.CopyNew()
}

type a2aeNoiseCircuitGraphIdentity struct {
	circuit       *A2AENoiseCircuit
	vLow, vHigh   uintptr
	uLow, uHigh   uintptr
	stcFactors    []uintptr
	ctsFactors    []uintptr
	profileDigest string
	keyDigest     string
}

func a2aeNoiseLinearIdentity(transformation ckkslintrans.LinearTransformation) uintptr {
	if transformation.Vec == nil {
		return 0
	}
	return reflect.ValueOf(transformation.Vec).Pointer()
}

func captureA2AENoiseCircuitGraph(c *A2AENoiseCircuit) (a2aeNoiseCircuitGraphIdentity, error) {
	if c == nil {
		return a2aeNoiseCircuitGraphIdentity{}, fmt.Errorf("homchain: nil A2A-e circuit graph")
	}
	g := a2aeNoiseCircuitGraphIdentity{
		circuit: c, vLow: a2aeNoiseLinearIdentity(c.fusedT.Low), vHigh: a2aeNoiseLinearIdentity(c.fusedT.High),
		uLow: a2aeNoiseLinearIdentity(c.fusedTInverse.Low), uHigh: a2aeNoiseLinearIdentity(c.fusedTInverse.High),
		profileDigest: c.profile.digest, keyDigest: c.keyProfile.digest,
	}
	for _, matrix := range c.stc.Matrices {
		g.stcFactors = append(g.stcFactors, a2aeNoiseLinearIdentity(matrix))
	}
	for _, matrix := range c.cts.Matrices {
		g.ctsFactors = append(g.ctsFactors, a2aeNoiseLinearIdentity(matrix))
	}
	if g.vLow == 0 || g.vHigh == 0 || g.uLow == 0 || g.uHigh == 0 || len(g.stcFactors) != 2 || len(g.ctsFactors) != 3 {
		return a2aeNoiseCircuitGraphIdentity{}, fmt.Errorf("homchain: incomplete A2A-e circuit graph")
	}
	for _, pointer := range append(append([]uintptr(nil), g.stcFactors...), g.ctsFactors...) {
		if pointer == 0 {
			return a2aeNoiseCircuitGraphIdentity{}, fmt.Errorf("homchain: A2A-e DFT graph contains an empty factor")
		}
	}
	return g, nil
}

func (g a2aeNoiseCircuitGraphIdentity) validate() error {
	c := g.circuit
	if c == nil || c.profile.digest != g.profileDigest || c.keyProfile.digest != g.keyDigest ||
		digestA2AENoiseProfile(c.profile, c.keyProfile) != g.profileDigest {
		return fmt.Errorf("circuit, profile, or key digest changed")
	}
	if a2aeNoiseLinearIdentity(c.fusedT.Low) != g.vLow || a2aeNoiseLinearIdentity(c.fusedT.High) != g.vHigh ||
		a2aeNoiseLinearIdentity(c.fusedTInverse.Low) != g.uLow || a2aeNoiseLinearIdentity(c.fusedTInverse.High) != g.uHigh {
		return fmt.Errorf("sealed fused transform graph changed")
	}
	if len(c.stc.Matrices) != len(g.stcFactors) || len(c.cts.Matrices) != len(g.ctsFactors) {
		return fmt.Errorf("sealed DFT factor count changed")
	}
	for i := range g.stcFactors {
		if a2aeNoiseLinearIdentity(c.stc.Matrices[i]) != g.stcFactors[i] {
			return fmt.Errorf("Slots-To-Coeffs factor %d changed", i)
		}
	}
	for i := range g.ctsFactors {
		if a2aeNoiseLinearIdentity(c.cts.Matrices[i]) != g.ctsFactors[i] {
			return fmt.Errorf("Coeffs-To-Slots factor %d changed", i)
		}
	}
	if !a2aeNoiseLiteralEqual(c.stc.MatrixLiteral, c.profile.dft.stcLiteral) ||
		!a2aeNoiseLiteralEqual(c.cts.MatrixLiteral, c.profile.dft.ctsLiteral) {
		return fmt.Errorf("sealed DFT literal changed")
	}
	return nil
}

func a2aeNoiseLiteralStructureEqual(left, right ckksdft.MatrixLiteral) bool {
	return left.Type == right.Type && left.Format == right.Format && left.LogSlots == right.LogSlots &&
		left.LevelQ == right.LevelQ && left.LevelP == right.LevelP && left.LogBSGSRatio == right.LogBSGSRatio &&
		left.BitReversed == right.BitReversed && reflect.DeepEqual(left.Levels, right.Levels)
}

func a2aeNoiseLiteralEqual(left, right ckksdft.MatrixLiteral) bool {
	if !a2aeNoiseLiteralStructureEqual(left, right) || left.Scaling == nil || right.Scaling == nil {
		return false
	}
	return left.Scaling.Cmp(right.Scaling) == 0 && left.Scaling.Prec() == right.Scaling.Prec()
}

func a2aeNoiseInitializedLiteralEqual(initialized, raw ckksdft.MatrixLiteral, factor float64) bool {
	if !a2aeNoiseLiteralStructureEqual(initialized, raw) || initialized.Scaling == nil || raw.Scaling == nil {
		return false
	}
	expected := new(big.Float).SetPrec(initialized.Scaling.Prec()).Set(raw.Scaling)
	expected.Mul(expected, new(big.Float).SetPrec(initialized.Scaling.Prec()).SetFloat64(factor))
	return initialized.Scaling.Cmp(expected) == 0
}

type a2aeNoiseSineEvaluator struct {
	params             ckks.Parameters
	profile            GaoSineKernelProfile
	ckks               *ckks.Evaluator
	polynomial         *ckkspolynomial.Evaluator
	polynomialOperand  ckkspolynomial.PolynomialVector
	recurrenceOperands [3][]*big.Float
	operandPlan        GaoSineOperandEncodingTrace
	polynomialTarget   rlwe.Scale
	expectedScales     []rlwe.Scale
}

func newA2AENoiseSineEvaluator(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	evaluator *ckks.Evaluator,
	profile GaoSineKernelProfile,
	polynomialTarget rlwe.Scale,
	expectedScales []rlwe.Scale,
) (*a2aeNoiseSineEvaluator, error) {
	if encoder == nil || evaluator == nil || evaluator.EvaluationKeySet == nil || encoder.Prec() < profile.Precision() {
		return nil, fmt.Errorf("homchain: incomplete A2A-e sine evaluator")
	}
	operational := evaluator.ShallowCopy()
	operational.Encoder = encoder.ShallowCopy()
	polynomialOperand, recurrence, plan, err := newGaoSinePackedOperands(profile, params.MaxSlots())
	if err != nil {
		return nil, err
	}
	if len(expectedScales) != 5 {
		return nil, fmt.Errorf("homchain: A2A-e sine measured schedule has %d states, want 5", len(expectedScales))
	}
	return &a2aeNoiseSineEvaluator{
		params: params, profile: profile, ckks: operational, polynomial: ckkspolynomial.NewEvaluator(params, operational),
		polynomialOperand: polynomialOperand, recurrenceOperands: recurrence, operandPlan: plan,
		polynomialTarget: polynomialTarget, expectedScales: append([]rlwe.Scale(nil), expectedScales...),
	}, nil
}

func a2aeNoiseSineScaleSchedule(params ckks.Parameters) (rlwe.Scale, []rlwe.Scale, error) {
	if params.MaxLevel() != 16 || len(params.Q()) != 17 {
		return rlwe.Scale{}, nil, fmt.Errorf("homchain: A2A-e sine schedule requires levels 13 through 4")
	}
	target := params.DefaultScale()
	for level := 5; level <= 7; level++ {
		product := target.Mul(rlwe.NewScale(params.Q()[level]))
		target = rlwe.NewScale(new(big.Float).SetPrec(rlwe.ScalePrecision).Sqrt(&product.Value))
	}
	scales := make([]rlwe.Scale, 5)
	scales[0], scales[1] = params.DefaultScale(), target
	current := target
	for round, level := 0, 7; round < 3; round, level = round+1, level-1 {
		current = current.Mul(current).Div(rlwe.NewScale(params.Q()[level]))
		scales[round+2] = current
	}
	return target, scales, nil
}

// measureA2AENoiseSineSchedule executes the exact private packed-vector
// polynomial graph on a zero dummy ciphertext with an ephemeral
// relinearization key. Only deterministic level/scale metadata is retained;
// the ephemeral key and ciphertext are discarded. This closes the few-ULP
// gap between the algebraic backwards-root prediction and Lattigo's actual
// vector coefficient scale rounding at ingress level 13.
func measureA2AENoiseSineSchedule(params ckks.Parameters, encoder *ckks.Encoder, profile GaoSineKernelProfile) (rlwe.Scale, []rlwe.Scale, error) {
	target, _, err := a2aeNoiseSineScaleSchedule(params)
	if err != nil {
		return rlwe.Scale{}, nil, err
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	ephemeralSecret := keyGenerator.GenSecretKeyNew()
	ephemeralEvaluator := ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(keyGenerator.GenRelinearizationKeyNew(ephemeralSecret)))
	ephemeralEvaluator.Encoder = encoder.ShallowCopy()
	polynomialOperand, recurrence, plan, err := newGaoSinePackedOperands(profile, params.MaxSlots())
	if err != nil {
		return rlwe.Scale{}, nil, err
	}
	if _, err = inspectGaoSinePackedOperands(polynomialOperand, recurrence, params.MaxSlots()); err != nil || plan.polynomialSlots != params.MaxSlots() {
		return rlwe.Scale{}, nil, fmt.Errorf("homchain: invalid A2A-e measured packed operand plan")
	}
	dummy := ckks.NewCiphertext(params, 1, 13)
	dummy.LogDimensions = ring.Dimensions{Rows: 0, Cols: 4}
	dummy.Scale = params.DefaultScale()
	dummy.IsBatched = true
	dummy.IsNTT = true
	polynomialEvaluator := ckkspolynomial.NewEvaluator(params, ephemeralEvaluator)
	y, err := polynomialEvaluator.Evaluate(dummy, polynomialOperand, target)
	if err != nil {
		return rlwe.Scale{}, nil, fmt.Errorf("measure degree-32 polynomial: %w", err)
	}
	if y.Level() != 7 || y.Degree() != 1 {
		return rlwe.Scale{}, nil, fmt.Errorf("measured polynomial state is L%d/D%d, want L7/D1", y.Level(), y.Degree())
	}
	scales := []rlwe.Scale{params.DefaultScale(), y.Scale}
	for i := range recurrence {
		y, err = ephemeralEvaluator.MulRelinNew(y, y)
		if err != nil {
			return rlwe.Scale{}, nil, err
		}
		if err = ephemeralEvaluator.Rescale(y, y); err != nil {
			return rlwe.Scale{}, nil, err
		}
		if err = ephemeralEvaluator.Add(y, y, y); err != nil {
			return rlwe.Scale{}, nil, err
		}
		if err = ephemeralEvaluator.Add(y, recurrence[i], y); err != nil {
			return rlwe.Scale{}, nil, err
		}
		scales = append(scales, y.Scale)
	}
	if len(scales) != 5 || y.Level() != 4 || y.Degree() != 1 {
		return rlwe.Scale{}, nil, fmt.Errorf("measured sine schedule ended at L%d/D%d with %d states", y.Level(), y.Degree(), len(scales))
	}
	return target, scales, nil
}

func (s *a2aeNoiseSineEvaluator) evaluate(input *rlwe.Ciphertext, lane A2AENoiseLane) (*rlwe.Ciphertext, []A2AENoiseCiphertextState, error) {
	if s == nil || input == nil || input.MetaData == nil || input.Level() != 13 || input.Degree() != 1 ||
		!a2aeNoiseExactScaleEqual(input.Scale, s.params.DefaultScale()) {
		return nil, nil, fmt.Errorf("homchain: A2A-e %s sine input state is invalid", lane)
	}
	polynomialOperand, err := cloneGaoSinePolynomialVector(s.polynomialOperand)
	if err != nil {
		return nil, nil, err
	}
	recurrence := cloneGaoSineRecurrenceOperands(s.recurrenceOperands)
	plan, err := inspectGaoSinePackedOperands(polynomialOperand, recurrence, s.params.MaxSlots())
	if err != nil || plan != s.operandPlan {
		return nil, nil, fmt.Errorf("homchain: A2A-e sine packed operand graph changed")
	}
	y, err := s.polynomial.Evaluate(input, polynomialOperand, s.polynomialTarget)
	if err != nil {
		return nil, nil, fmt.Errorf("homchain: A2A-e %s Gao polynomial: %w", lane, err)
	}
	if y.Level() != 7 || y.Degree() != 1 {
		return nil, nil, fmt.Errorf("homchain: A2A-e %s polynomial level/degree=%d/%d, want 7/1", lane, y.Level(), y.Degree())
	}
	states := make([]A2AENoiseCiphertextState, 0, 4)
	state, err := snapshotA2AENoiseState(lane, A2AENoiseStageSinePolynomial, y, s.expectedScales[1])
	if err != nil {
		return nil, nil, err
	}
	if !state.ScaleExact {
		return nil, nil, fmt.Errorf("homchain: A2A-e %s polynomial scale=%s, expected=%s", lane, state.Scale.ValueHex(), state.ExpectedScale.ValueHex())
	}
	states = append(states, state)
	stages := [...]A2AENoiseStage{A2AENoiseStageDoubleAngle0, A2AENoiseStageDoubleAngle1, A2AENoiseStageDoubleAngle2}
	for i := range recurrence {
		y, err = s.ckks.MulRelinNew(y, y)
		if err != nil {
			return nil, nil, fmt.Errorf("homchain: A2A-e %s double-angle %d square: %w", lane, i, err)
		}
		if err = s.ckks.Rescale(y, y); err != nil {
			return nil, nil, fmt.Errorf("homchain: A2A-e %s double-angle %d rescale: %w", lane, i, err)
		}
		if err = s.ckks.Add(y, y, y); err != nil {
			return nil, nil, fmt.Errorf("homchain: A2A-e %s double-angle %d double: %w", lane, i, err)
		}
		if err = s.ckks.Add(y, recurrence[i], y); err != nil {
			return nil, nil, fmt.Errorf("homchain: A2A-e %s double-angle %d recurrence: %w", lane, i, err)
		}
		if y.Level() != 6-i || y.Degree() != 1 {
			return nil, nil, fmt.Errorf("homchain: A2A-e %s double-angle %d level/degree=%d/%d", lane, i, y.Level(), y.Degree())
		}
		state, err = snapshotA2AENoiseState(lane, stages[i], y, s.expectedScales[i+2])
		if err != nil {
			return nil, nil, err
		}
		if !state.ScaleExact {
			return nil, nil, fmt.Errorf("homchain: A2A-e %s double-angle %d scale=%s, expected=%s", lane, i, state.Scale.ValueHex(), state.ExpectedScale.ValueHex())
		}
		states = append(states, state)
	}
	return y, states, nil
}

// A2AENoiseEvaluator is obtained only from a sealed circuit/evaluator bind.
type A2AENoiseEvaluator struct {
	circuit        *A2AENoiseCircuit
	bootstrap      *bootstrapping.Evaluator
	triangle       *Evaluator
	sine           *a2aeNoiseSineEvaluator
	sourceGraph    a2aiEvaluatorGraphIdentity
	executionGraph a2aiEvaluatorGraphIdentity
	circuitGraph   a2aeNoiseCircuitGraphIdentity
}

// BindEvaluator seals the evaluator/key graph and validates the metadata used
// by the single guarded ScaleDown/ModUp invocation.
func (c *A2AENoiseCircuit) BindEvaluator(source *bootstrapping.Evaluator) (*A2AENoiseEvaluator, error) {
	if c == nil || source == nil || source.Evaluator == nil || source.DFTEvaluator == nil ||
		source.EvaluationKeys == nil || source.MemEvaluationKeySet == nil {
		return nil, fmt.Errorf("homchain: incomplete A2A-e bootstrap evaluator")
	}
	if !source.ResidualParameters.Equal(&c.params) || !source.BootstrappingParameters.Equal(&c.params) ||
		!c.params.Equal(source.Evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: A2A-e evaluator parameters differ from the circuit")
	}
	if source.EvkDenseToSparse != nil || source.EvkSparseToDense != nil {
		return nil, fmt.Errorf("homchain: A2A-e functional slice requires dense/no-switch ModUp")
	}
	if source.Mod1Parameters.MessageRatio() != 1 {
		return nil, fmt.Errorf("homchain: A2A-e requires MessageRatio=1")
	}
	qDiv := source.Mod1Parameters.ScalingFactor().Float64() /
		math.Exp2(math.Round(math.Log2(float64(c.params.Q()[0]))))
	if qDiv > 1 {
		qDiv = 1
	}
	ctsInitializationFactor := qDiv / (source.Mod1Parameters.K * source.Mod1Parameters.QDiff)
	offset := source.Mod1Parameters.ScalingFactor().Float64() / source.Mod1Parameters.MessageRatio()
	stcInitializationFactor := c.params.DefaultScale().Float64() / offset
	if !a2aeNoiseInitializedLiteralEqual(source.SlotsToCoeffsParameters, c.profile.dft.stcLiteral, stcInitializationFactor) ||
		!a2aeNoiseInitializedLiteralEqual(source.CoeffsToSlotsParameters, c.profile.dft.ctsLiteral, ctsInitializationFactor) {
		return nil, fmt.Errorf("homchain: A2A-e bootstrap DFT metadata differs from the sealed Scaling=1/1/16 profile")
	}
	if gap := 1 << (c.params.LogN() - source.CoeffsToSlotsParameters.LogSlots - 1); gap != 1 {
		return nil, fmt.Errorf("homchain: A2A-e full-packing Trace gap=%d, want 1", gap)
	}
	requestedScale := source.Mod1Parameters.ScalingFactor()
	if !requestedScale.Equal(c.params.DefaultScale()) {
		return nil, fmt.Errorf("homchain: A2A-e ModUp requested scale is not exact Delta")
	}
	bridge := A2AIKeyProfile{All: c.keyProfile.All()}
	if _, err := preflightA2AENoiseKeySet(source, c, bridge); err != nil {
		return nil, err
	}
	sourceGraph, err := captureA2AIEvaluatorGraph(source, bridge)
	if err != nil {
		return nil, fmt.Errorf("homchain: capture A2A-e source evaluator graph: %w", err)
	}
	sealed := sealA2AIBootstrapEvaluator(source, c.params)
	executionGraph, err := captureA2AIEvaluatorGraph(sealed, bridge)
	if err != nil {
		return nil, fmt.Errorf("homchain: capture A2A-e sealed evaluator graph: %w", err)
	}
	circuitGraph, err := captureA2AENoiseCircuitGraph(c)
	if err != nil {
		return nil, err
	}
	sine, err := newA2AENoiseSineEvaluator(
		c.params, c.encoder, sealed.Evaluator, c.sineProfile,
		c.sinePolynomialTarget, c.sineExpectedScales,
	)
	if err != nil {
		return nil, err
	}
	return &A2AENoiseEvaluator{
		circuit: c, bootstrap: sealed, triangle: NewEvaluator(sealed.Evaluator), sine: sine,
		sourceGraph: sourceGraph, executionGraph: executionGraph, circuitGraph: circuitGraph,
	}, nil
}

func preflightA2AENoiseKeySet(source *bootstrapping.Evaluator, circuit *A2AENoiseCircuit, bridge A2AIKeyProfile) (A2AENoiseKeyPreflight, error) {
	result := A2AENoiseKeyPreflight{Checked: true, GraphChecked: true}
	if source == nil || source.Evaluator == nil || source.Evaluator.EvaluationKeySet == nil || source.EvaluationKeys == nil {
		return result, fmt.Errorf("homchain: incomplete A2A-e key graph")
	}
	keys := source.Evaluator.EvaluationKeySet
	result.DenseNoSwitchMatched = source.EvkDenseToSparse == nil && source.EvkSparseToDense == nil
	for _, element := range bridge.All {
		key, err := keys.GetGaloisKey(element)
		if err != nil || key == nil {
			result.MissingGaloisElements = append(result.MissingGaloisElements, element)
			continue
		}
		if key.GaloisElement != element || key.LevelQ() < circuit.params.MaxLevel() || key.LevelP() != circuit.params.MaxLevelP() {
			result.InvalidGaloisElements = append(result.InvalidGaloisElements, element)
		}
	}
	if key, err := keys.GetRelinearizationKey(); err == nil && key != nil {
		result.RelinearizationPresent = true
		result.RelinearizationMatched = key.LevelQ() >= circuit.params.MaxLevel() && key.LevelP() == circuit.params.MaxLevelP()
	}
	if len(result.MissingGaloisElements) != 0 || len(result.InvalidGaloisElements) != 0 ||
		!result.RelinearizationMatched || !result.DenseNoSwitchMatched {
		return result, fmt.Errorf("homchain: A2A-e key preflight failed: missing=%v invalid=%v relin=%t relin-level=%t dense-no-switch=%t",
			result.MissingGaloisElements, result.InvalidGaloisElements, result.RelinearizationPresent,
			result.RelinearizationMatched, result.DenseNoSwitchMatched)
	}
	result.GraphMatched = true
	return result, nil
}

func (e *A2AENoiseEvaluator) preflight() (A2AENoiseKeyPreflight, error) {
	result := A2AENoiseKeyPreflight{Checked: true, GraphChecked: true}
	if e == nil || e.circuit == nil || e.bootstrap == nil || e.triangle == nil || e.sine == nil {
		return result, fmt.Errorf("homchain: nil bound A2A-e evaluator")
	}
	if err := e.circuitGraph.validate(); err != nil {
		result.GraphMismatch = "circuit graph: " + err.Error()
		return result, fmt.Errorf("homchain: A2A-e graph preflight failed: %s", result.GraphMismatch)
	}
	if err := e.sourceGraph.validateTopology(); err != nil {
		result.GraphMismatch = "source evaluator graph: " + err.Error()
		return result, fmt.Errorf("homchain: A2A-e graph preflight failed: %s", result.GraphMismatch)
	}
	if err := e.executionGraph.validateTopology(); err != nil {
		result.GraphMismatch = "sealed evaluator graph: " + err.Error()
		return result, fmt.Errorf("homchain: A2A-e graph preflight failed: %s", result.GraphMismatch)
	}
	bridge := A2AIKeyProfile{All: e.circuit.keyProfile.All()}
	keyResult, err := preflightA2AENoiseKeySet(e.bootstrap, e.circuit, bridge)
	result = keyResult
	if err != nil {
		return result, err
	}
	if err := e.sourceGraph.validateKeyIdentities(); err != nil {
		result.GraphMatched = false
		result.GraphMismatch = "source evaluator keys: " + err.Error()
		return result, fmt.Errorf("homchain: A2A-e graph preflight failed: %s", result.GraphMismatch)
	}
	if err := e.executionGraph.validateKeyIdentities(); err != nil {
		result.GraphMatched = false
		result.GraphMismatch = "sealed evaluator keys: " + err.Error()
		return result, fmt.Errorf("homchain: A2A-e graph preflight failed: %s", result.GraphMismatch)
	}
	if e.sine.ckks.EvaluationKeySet != e.bootstrap.Evaluator.EvaluationKeySet ||
		e.sine.ckks.Encoder == nil || e.sine.ckks.Encoder.Prec() != z2n.DefaultPrecision {
		result.GraphMatched = false
		result.GraphMismatch = "private sine evaluator binding changed"
		return result, fmt.Errorf("homchain: A2A-e graph preflight failed: %s", result.GraphMismatch)
	}
	result.GraphMatched = true
	return result, nil
}

func (c *A2AENoiseCircuit) validateInput(input *rlwe.Ciphertext, certificate A2AENoiseInputCertificate) error {
	if c == nil {
		return fmt.Errorf("homchain: nil A2A-e circuit")
	}
	if err := certificate.validate(c.profile); err != nil {
		return err
	}
	if input == nil || input.MetaData == nil || input.Level() != 16 || input.Degree() != 1 {
		return fmt.Errorf("homchain: A2A-e input is nil or has wrong level/degree")
	}
	if !input.IsBatched || !input.IsNTT || input.LogDimensions != certificate.logDimensions || input.Slots() != certificate.slots {
		return fmt.Errorf("homchain: A2A-e input is not the fixed full-packed NTT ciphertext")
	}
	if !certificate.scale.EqualScale(input.Scale) || !a2aeNoiseExactScaleEqual(input.Scale, c.params.DefaultScale()) {
		return fmt.Errorf("homchain: A2A-e input does not have exact certified Delta")
	}
	return nil
}

func a2aeNoiseExactScaleEqual(left, right rlwe.Scale) bool {
	leftSnapshot, err := NewExactScaleSnapshot(left)
	if err != nil {
		return false
	}
	rightSnapshot, err := NewExactScaleSnapshot(right)
	return err == nil && leftSnapshot.Equal(rightSnapshot)
}

// EvalArithToArithNoise executes the complete fixed A2A-e graph. ScaleDown
// is called exactly once; the original is reduced by legal DropLevel only and
// the returned ciphertext is original minus recovered error.
func (e *A2AENoiseEvaluator) EvalArithToArithNoise(input *rlwe.Ciphertext, certificate A2AENoiseInputCertificate) (*rlwe.Ciphertext, A2AENoiseTrace, error) {
	trace := A2AENoiseTrace{}
	if e == nil || e.circuit == nil {
		return nil, trace, fmt.Errorf("homchain: nil bound A2A-e evaluator")
	}
	trace.fidelity, trace.maturity = e.circuit.profile.fidelity, e.circuit.profile.maturity
	trace.profileDigest, trace.certificateDigest = e.circuit.profile.digest, certificate.digest
	trace.transformDigest, trace.dft = e.circuit.profile.transformSourceDigest, e.circuit.profile.DFT()
	trace.sineProfileDigest = e.circuit.sineProfile.Digest()
	trace.periodicDomain = "CTS x=(I+u)/16; integer lift I is externally admitted and removed by sine periodicity"
	if err := e.circuit.validateInput(input, certificate); err != nil {
		trace.failureStage = A2AENoiseStageInput
		return nil, trace, err
	}
	preflight, err := e.preflight()
	trace.keyPreflight = preflight
	if err != nil {
		trace.failureStage = A2AENoiseStageKeyPreflight
		return nil, trace, err
	}
	trace.operationCounts = A2AENoiseOperationCounts{
		FusedTZToC: 1, SlotsToCoeffsFactors: 2, ScaleDown: 1, ModUp: 1, CoeffsToSlotsFactors: 3,
		SinePolynomialPerHalf: 1, DoubleAnglesPerHalf: 3, FusedTInverseCToZ: 1,
		OriginalDropLevel: 1, FinalInputMinusRecovered: 1,
	}
	inputState, err := snapshotA2AENoiseState(A2AENoiseWhole, A2AENoiseStageInput, input, e.circuit.params.DefaultScale())
	if err != nil || !inputState.ScaleExact {
		trace.failureStage = A2AENoiseStageInput
		return nil, trace, fmt.Errorf("homchain: A2A-e input scale state is invalid")
	}
	trace.states = append(trace.states, inputState)
	inputBefore := input.CopyNew()
	original := input.CopyNew()

	halves, err := e.triangle.ZToCNew(input.CopyNew(), e.circuit.fusedT)
	if err != nil {
		trace.failureStage = A2AENoiseStageFusedTZToC
		return nil, trace, fmt.Errorf("homchain: A2A-e fused-t Z-To-C: %w", err)
	}
	if err = validateCiphertextPairState("A2A-e fused-t Z-To-C", halves); err != nil {
		return nil, trace, err
	}
	for index, lane := range []A2AENoiseLane{A2AENoiseLow, A2AENoiseHigh} {
		state, stateErr := snapshotA2AENoiseState(lane, A2AENoiseStageFusedTZToC, halves[index], e.circuit.params.DefaultScale())
		if stateErr != nil || state.Level != 15 || !state.ScaleExact {
			trace.failureStage = A2AENoiseStageFusedTZToC
			return nil, trace, fmt.Errorf("homchain: A2A-e %s fused-t state is not L15 exact Delta", lane)
		}
		trace.states = append(trace.states, state)
	}
	trace.fusedLow, trace.fusedHigh = halves[0].CopyNew(), halves[1].CopyNew()
	coefficients, err := e.bootstrap.DFTEvaluator.SlotsToCoeffsNew(halves[0], halves[1], e.circuit.stc)
	if err != nil {
		trace.failureStage = A2AENoiseStageSlotsToCoeffs
		return nil, trace, fmt.Errorf("homchain: A2A-e Slots-To-Coeffs: %w", err)
	}
	state, err := snapshotA2AENoiseState(A2AENoiseWhole, A2AENoiseStageSlotsToCoeffs, coefficients, e.circuit.params.DefaultScale())
	if err != nil || state.Level != 13 || !state.ScaleExact {
		trace.failureStage = A2AENoiseStageSlotsToCoeffs
		return nil, trace, fmt.Errorf("homchain: A2A-e Slots-To-Coeffs state is not L13 exact Delta")
	}
	trace.states = append(trace.states, state)
	coefficientsSaved := coefficients.CopyNew()
	scaledDown, errScale, err := e.bootstrap.ScaleDown(coefficients.CopyNew())
	if err != nil || errScale == nil {
		trace.failureStage = A2AENoiseStageScaleDown
		return nil, trace, fmt.Errorf("homchain: A2A-e guarded ScaleDown: %w", err)
	}
	if !coefficients.Equal(coefficientsSaved) {
		return nil, trace, fmt.Errorf("homchain: A2A-e ScaleDown mutated the saved STC core")
	}
	trace.scaleDownLog2Error = errScale.Log2()
	trace.scaleDownError, err = NewExactScaleSnapshot(*errScale)
	if err != nil || trace.scaleDownError.HasMod() || math.IsNaN(trace.scaleDownLog2Error) || math.IsInf(trace.scaleDownLog2Error, 0) ||
		math.Abs(trace.scaleDownLog2Error) > e.circuit.options.MaxAbsLog2ScaleDownError {
		trace.failureStage = A2AENoiseStageScaleDown
		return nil, trace, fmt.Errorf("homchain: A2A-e ScaleDown error metadata is invalid or log2 error %g exceeds bound", trace.scaleDownLog2Error)
	}
	// Lattigo defines errScale = output.Scale/(q0/MessageRatio). BindEvaluator
	// fixes MessageRatio=1, hence the exact raw boundary is q0*errScale.
	expectedScaleDown := rlwe.NewScale(e.circuit.params.Q()[0]).Mul(*errScale)
	state, err = snapshotA2AENoiseState(A2AENoiseWhole, A2AENoiseStageScaleDown, scaledDown, expectedScaleDown)
	if err != nil || state.Level != 0 || !state.ScaleExact {
		trace.failureStage = A2AENoiseStageScaleDown
		return nil, trace, fmt.Errorf("homchain: A2A-e ScaleDown did not land at q0*errScale")
	}
	trace.states = append(trace.states, state)
	preModUpScale, err := NewExactScaleSnapshot(scaledDown.Scale)
	if err != nil {
		return nil, trace, err
	}
	requested := e.bootstrap.Mod1Parameters.ScalingFactor().Float64() / e.bootstrap.Mod1Parameters.MessageRatio()
	if requested/scaledDown.Scale.Float64() > 1 {
		trace.failureStage = A2AENoiseStageModUp
		return nil, trace, fmt.Errorf("homchain: A2A-e ModUp would relabel the raw scale")
	}
	raised, err := e.bootstrap.ModUp(scaledDown)
	if err != nil {
		trace.failureStage = A2AENoiseStageModUp
		return nil, trace, fmt.Errorf("homchain: A2A-e ModUp: %w", err)
	}
	state, err = snapshotA2AENoiseState(A2AENoiseWhole, A2AENoiseStageModUp, raised, scaledDown.Scale)
	if err != nil || state.Level != 16 || !state.ScaleExact || !preModUpScale.EqualScale(raised.Scale) {
		trace.failureStage = A2AENoiseStageModUp
		return nil, trace, fmt.Errorf("homchain: A2A-e ModUp changed level/scale outside the sealed contract")
	}
	trace.states = append(trace.states, state)
	trace.raisedCoefficients = raised.CopyNew()

	realHalf, imaginaryHalf, err := e.bootstrap.DFTEvaluator.CoeffsToSlotsNew(raised, e.circuit.cts)
	if err != nil || realHalf == nil || imaginaryHalf == nil || realHalf == imaginaryHalf {
		trace.failureStage = A2AENoiseStageCoeffsToSlots
		return nil, trace, fmt.Errorf("homchain: A2A-e Coeffs-To-Slots did not produce two distinct halves: %w", err)
	}
	ctsHalves := CiphertextPair{realHalf, imaginaryHalf}
	if err = validateCiphertextPairState("A2A-e Coeffs-To-Slots", ctsHalves); err != nil {
		return nil, trace, err
	}
	for index, lane := range []A2AENoiseLane{A2AENoiseLow, A2AENoiseHigh} {
		state, stateErr := snapshotA2AENoiseState(lane, A2AENoiseStageCoeffsToSlots, ctsHalves[index], e.circuit.params.DefaultScale())
		if stateErr != nil || state.Level != 13 || !state.ScaleExact {
			trace.failureStage = A2AENoiseStageCoeffsToSlots
			return nil, trace, fmt.Errorf("homchain: A2A-e %s CTS state is not L13 exact Delta", lane)
		}
		trace.states = append(trace.states, state)
	}
	trace.ctsLow, trace.ctsHigh = realHalf.CopyNew(), imaginaryHalf.CopyNew()

	sineLow, lowStates, err := e.sine.evaluate(realHalf, A2AENoiseLow)
	if err != nil {
		trace.failureStage = A2AENoiseStageSinePolynomial
		return nil, trace, err
	}
	trace.states = append(trace.states, lowStates...)
	sineHigh, highStates, err := e.sine.evaluate(imaginaryHalf, A2AENoiseHigh)
	if err != nil {
		trace.failureStage = A2AENoiseStageSinePolynomial
		return nil, trace, err
	}
	trace.states = append(trace.states, highStates...)
	trace.sineLow, trace.sineHigh = sineLow.CopyNew(), sineHigh.CopyNew()
	if sineLow == sineHigh {
		return nil, trace, fmt.Errorf("homchain: A2A-e low/high sine paths shared an output")
	}
	recovered, err := e.triangle.CToZNew(CiphertextPair{sineLow, sineHigh}, e.circuit.fusedTInverse)
	if err != nil {
		trace.failureStage = A2AENoiseStageRecoveredError
		return nil, trace, fmt.Errorf("homchain: A2A-e fused-t-inverse C-To-Z: %w", err)
	}
	state, err = snapshotA2AENoiseState(A2AENoiseWhole, A2AENoiseStageRecoveredError, recovered, e.circuit.params.DefaultScale())
	if err != nil || state.Level != 3 || !state.ScaleExact {
		trace.failureStage = A2AENoiseStageRecoveredError
		return nil, trace, fmt.Errorf("homchain: A2A-e recovered error is not L3 exact Delta")
	}
	trace.states = append(trace.states, state)
	trace.recoveredError = recovered.CopyNew()

	e.bootstrap.Evaluator.DropLevel(original, original.Level()-3)
	state, err = snapshotA2AENoiseState(A2AENoiseWhole, A2AENoiseStageOriginalDropLevel, original, e.circuit.params.DefaultScale())
	if err != nil || state.Level != 3 || !state.ScaleExact {
		trace.failureStage = A2AENoiseStageOriginalDropLevel
		return nil, trace, fmt.Errorf("homchain: A2A-e original DropLevel state is not L3 exact Delta")
	}
	trace.states = append(trace.states, state)
	output, err := e.bootstrap.Evaluator.SubNew(original, recovered)
	if err != nil {
		trace.failureStage = A2AENoiseStageOutputSubtract
		return nil, trace, fmt.Errorf("homchain: A2A-e input-minus-recovered-error: %w", err)
	}
	state, err = snapshotA2AENoiseState(A2AENoiseWhole, A2AENoiseStageOutputSubtract, output, e.circuit.params.DefaultScale())
	if err != nil || state.Level != 3 || !state.ScaleExact {
		trace.failureStage = A2AENoiseStageOutputSubtract
		return nil, trace, fmt.Errorf("homchain: A2A-e output is not L3 exact Delta")
	}
	trace.states = append(trace.states, state)
	if !input.Equal(inputBefore) {
		return nil, trace, fmt.Errorf("homchain: A2A-e mutated its input")
	}
	return output, trace, nil
}

func snapshotA2AENoiseState(lane A2AENoiseLane, stage A2AENoiseStage, ciphertext *rlwe.Ciphertext, expected rlwe.Scale) (A2AENoiseCiphertextState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return A2AENoiseCiphertextState{}, fmt.Errorf("homchain: cannot snapshot nil A2A-e %s/%s state", lane, stage)
	}
	actualSnapshot, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return A2AENoiseCiphertextState{}, err
	}
	expectedSnapshot, err := NewExactScaleSnapshot(expected)
	if err != nil {
		return A2AENoiseCiphertextState{}, err
	}
	return A2AENoiseCiphertextState{
		Lane: lane, Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: actualSnapshot, ExpectedScale: expectedSnapshot,
		ScaleExact: actualSnapshot.Equal(expectedSnapshot),
	}, nil
}

// Deterministic ordering is used by source-distinguishing test diagnostics.
func sortedA2AENoiseGalois(values []uint64) []uint64 {
	result := append([]uint64(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
