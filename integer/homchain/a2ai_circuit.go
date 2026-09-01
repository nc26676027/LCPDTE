package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	ckksdft "github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	ckkslintrans "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// a2aiEvaluatorGraphIdentity captures every public evaluator pointer and key
// object whose replacement could otherwise split preflight from execution.
// It is private and is checked before the first homomorphic operation.
type a2aiEvaluatorGraphIdentity struct {
	bootstrap       *bootstrapping.Evaluator
	main            *ckks.Evaluator
	dft             *ckksdft.Evaluator
	dftMain         *ckks.Evaluator
	dftLinear       *ckkslintrans.Evaluator
	dftLinearMain   *ckks.Evaluator
	evaluationKeys  *bootstrapping.EvaluationKeys
	memKeys         *rlwe.MemEvaluationKeySet
	relinearization *rlwe.RelinearizationKey
	galois          map[uint64]*rlwe.GaloisKey
	denseToSparse   *rlwe.EvaluationKey
	sparseToDense   *rlwe.EvaluationKey
}

func captureA2AIEvaluatorGraph(bootstrap *bootstrapping.Evaluator, profile A2AIKeyProfile) (a2aiEvaluatorGraphIdentity, error) {
	if bootstrap == nil || bootstrap.Evaluator == nil || bootstrap.DFTEvaluator == nil || bootstrap.DFTEvaluator.LTEvaluator == nil {
		return a2aiEvaluatorGraphIdentity{}, fmt.Errorf("homchain: incomplete A2A-I evaluator graph")
	}
	if bootstrap.EvaluationKeys == nil || bootstrap.EvaluationKeys.MemEvaluationKeySet == nil || bootstrap.Evaluator.EvaluationKeySet == nil {
		return a2aiEvaluatorGraphIdentity{}, fmt.Errorf("homchain: incomplete A2A-I evaluator key graph")
	}
	boundKeys, ok := bootstrap.Evaluator.EvaluationKeySet.(*bootstrapping.EvaluationKeys)
	if !ok || boundKeys != bootstrap.EvaluationKeys {
		return a2aiEvaluatorGraphIdentity{}, fmt.Errorf("homchain: A2A-I main evaluator is not bound to the bootstrap evaluation-key object")
	}
	linearMain, ok := bootstrap.DFTEvaluator.LTEvaluator.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || bootstrap.DFTEvaluator.Evaluator != bootstrap.Evaluator || linearMain != bootstrap.Evaluator {
		return a2aiEvaluatorGraphIdentity{}, fmt.Errorf("homchain: A2A-I DFT evaluator graph is not bound to the main evaluator")
	}
	relinearization, err := boundKeys.GetRelinearizationKey()
	if err != nil || relinearization == nil {
		return a2aiEvaluatorGraphIdentity{}, fmt.Errorf("homchain: capture A2A-I relinearization key identity: %v", err)
	}
	galois := make(map[uint64]*rlwe.GaloisKey, len(profile.All))
	for _, element := range profile.All {
		key, err := boundKeys.GetGaloisKey(element)
		if err != nil || key == nil {
			return a2aiEvaluatorGraphIdentity{}, fmt.Errorf("homchain: capture A2A-I Galois key %d identity: %v", element, err)
		}
		galois[element] = key
	}
	return a2aiEvaluatorGraphIdentity{
		bootstrap: bootstrap, main: bootstrap.Evaluator, dft: bootstrap.DFTEvaluator,
		dftMain: bootstrap.DFTEvaluator.Evaluator, dftLinear: bootstrap.DFTEvaluator.LTEvaluator,
		dftLinearMain: linearMain, evaluationKeys: bootstrap.EvaluationKeys,
		memKeys: bootstrap.EvaluationKeys.MemEvaluationKeySet, relinearization: relinearization,
		galois: galois, denseToSparse: bootstrap.EvkDenseToSparse, sparseToDense: bootstrap.EvkSparseToDense,
	}, nil
}

func (g a2aiEvaluatorGraphIdentity) validateTopology() error {
	bootstrap := g.bootstrap
	if bootstrap == nil || bootstrap.Evaluator != g.main || bootstrap.DFTEvaluator != g.dft || bootstrap.EvaluationKeys != g.evaluationKeys {
		return fmt.Errorf("top-level evaluator, DFT evaluator, or evaluation-key object was replaced")
	}
	if bootstrap.Evaluator == nil || bootstrap.DFTEvaluator == nil || bootstrap.DFTEvaluator.LTEvaluator == nil || bootstrap.EvaluationKeys == nil {
		return fmt.Errorf("evaluator graph contains a nil component")
	}
	if bootstrap.DFTEvaluator.Evaluator != g.dftMain || bootstrap.DFTEvaluator.LTEvaluator != g.dftLinear {
		return fmt.Errorf("DFT evaluator component was replaced")
	}
	linearMain, ok := bootstrap.DFTEvaluator.LTEvaluator.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || linearMain != g.dftLinearMain || g.dftMain != g.main || g.dftLinearMain != g.main {
		return fmt.Errorf("DFT linear evaluator no longer shares the bound main evaluator")
	}
	boundKeys, ok := bootstrap.Evaluator.EvaluationKeySet.(*bootstrapping.EvaluationKeys)
	if !ok || boundKeys != g.evaluationKeys || bootstrap.EvaluationKeys.MemEvaluationKeySet != g.memKeys {
		return fmt.Errorf("main evaluator key set or bootstrap memory key set was replaced")
	}
	if bootstrap.EvkDenseToSparse != g.denseToSparse || bootstrap.EvkSparseToDense != g.sparseToDense {
		return fmt.Errorf("ModUp switching-key topology was replaced")
	}
	return nil
}

func (g a2aiEvaluatorGraphIdentity) validateKeyIdentities() error {
	if err := g.validateTopology(); err != nil {
		return err
	}
	boundKeys := g.bootstrap.Evaluator.EvaluationKeySet.(*bootstrapping.EvaluationKeys)
	relinearization, err := boundKeys.GetRelinearizationKey()
	if err != nil || relinearization == nil || relinearization != g.relinearization {
		return fmt.Errorf("relinearization key identity changed")
	}
	for element, expected := range g.galois {
		key, err := boundKeys.GetGaloisKey(element)
		if err != nil || key == nil || key != expected {
			return fmt.Errorf("Galois key %d identity changed", element)
		}
	}
	return nil
}

func sealA2AIBootstrapEvaluator(source *bootstrapping.Evaluator, params ckks.Parameters) *bootstrapping.Evaluator {
	keyCopy := *source.EvaluationKeys
	main := ckks.NewEvaluator(params, &keyCopy)
	sealed := *source
	sealed.EvaluationKeys = &keyCopy
	sealed.Evaluator = main
	sealed.DFTEvaluator = ckksdft.NewEvaluator(params, main)
	return &sealed
}

// A2AITransformCompileProfile is the immutable public projection of one
// internally compiled normal transform pair. It exposes compile provenance,
// never the encoded CompiledPair itself.
type A2AITransformCompileProfile struct {
	lowName         TransformName
	highName        TransformName
	levelQ          int
	levelP          int
	scale           ExactScaleSnapshot
	logDimensions   ring.Dimensions
	logBSGSRatio    int
	rotationIndexes []int
	galoisElements  []uint64
}

func (p A2AITransformCompileProfile) LowName() TransformName         { return p.lowName }
func (p A2AITransformCompileProfile) HighName() TransformName        { return p.highName }
func (p A2AITransformCompileProfile) LevelQ() int                    { return p.levelQ }
func (p A2AITransformCompileProfile) LevelP() int                    { return p.levelP }
func (p A2AITransformCompileProfile) Scale() ExactScaleSnapshot      { return p.scale }
func (p A2AITransformCompileProfile) LogDimensions() ring.Dimensions { return p.logDimensions }
func (p A2AITransformCompileProfile) LogBSGSRatio() int              { return p.logBSGSRatio }
func (p A2AITransformCompileProfile) RotationIndexes() []int {
	return append([]int(nil), p.rotationIndexes...)
}
func (p A2AITransformCompileProfile) GaloisElements() []uint64 {
	return append([]uint64(nil), p.galoisElements...)
}

func cloneA2AITransformCompileProfile(input A2AITransformCompileProfile) A2AITransformCompileProfile {
	result := input
	result.rotationIndexes = input.RotationIndexes()
	result.galoisElements = input.GaloisElements()
	return result
}

// A2AIHighProfile identifies the single guarded functional slice implemented
// by A2AIHighCircuit: four full-packed Z2^8 words and normal V/U transforms.
// Every slice-bearing accessor returns detached data.
type A2AIHighProfile struct {
	wordBits              z2n.WordBits
	words                 int
	slots                 int
	encoderPrecision      uint
	maxAbsLog2ScaleError  float64
	transformNames        []TransformName
	vCompile              A2AITransformCompileProfile
	uCompile              A2AITransformCompileProfile
	transformSourceDigest string
	rawDFTDigest          string
	parametersDigest      string
	circuitDigest         string
}

func (p A2AIHighProfile) WordBits() z2n.WordBits            { return p.wordBits }
func (p A2AIHighProfile) Words() int                        { return p.words }
func (p A2AIHighProfile) Slots() int                        { return p.slots }
func (p A2AIHighProfile) EncoderPrecision() uint            { return p.encoderPrecision }
func (p A2AIHighProfile) MaxAbsLog2ScaleDownError() float64 { return p.maxAbsLog2ScaleError }
func (p A2AIHighProfile) TransformSourceDigest() string     { return p.transformSourceDigest }
func (p A2AIHighProfile) RawDFTDigest() string              { return p.rawDFTDigest }
func (p A2AIHighProfile) ParametersDigest() string          { return p.parametersDigest }
func (p A2AIHighProfile) CircuitDigest() string             { return p.circuitDigest }
func (p A2AIHighProfile) Digest() string                    { return p.circuitDigest }
func (p A2AIHighProfile) TransformNames() []TransformName {
	return append([]TransformName(nil), p.transformNames...)
}
func (p A2AIHighProfile) VCompile() A2AITransformCompileProfile {
	return cloneA2AITransformCompileProfile(p.vCompile)
}
func (p A2AIHighProfile) UCompile() A2AITransformCompileProfile {
	return cloneA2AITransformCompileProfile(p.uCompile)
}

// A2AIHighCircuit owns the normal V/U encoded transforms and their source
// provenance. Its fields are deliberately private: callers select neither a
// transform variant nor a CompiledPair at evaluation time.
type A2AIHighCircuit struct {
	params     ckks.Parameters
	rawDFT     RawFullSlotDFT
	v          CompiledPair
	u          CompiledPair
	options    A2AIHighOptions
	profile    A2AIHighProfile
	keyProfile A2AIKeyProfile
}

// NewA2AIHighCircuit constructs the fixed FUNCTIONAL-NOT-SECURE n=8,
// four-word, full-packed guarded A2A-I slice. Normal V is compiled at the
// maximum level and normal U at the raw Coeffs-To-Slots output level; both use
// the exact CKKS default scale.
func NewA2AIHighCircuit(params ckks.Parameters, encoder *ckks.Encoder, rawDFT RawFullSlotDFT, options A2AIHighOptions) (*A2AIHighCircuit, error) {
	if encoder == nil {
		return nil, fmt.Errorf("homchain: A2A-I nil encoder")
	}
	encoderParameters := encoder.GetParameters()
	if !params.Equal(&encoderParameters) {
		return nil, fmt.Errorf("homchain: A2A-I encoder parameters do not match the circuit parameters")
	}
	if encoder.Prec() != z2n.DefaultPrecision {
		return nil, fmt.Errorf("homchain: A2A-I encoder precision=%d, want %d", encoder.Prec(), z2n.DefaultPrecision)
	}
	if err := validateA2AIHighParameters(params); err != nil {
		return nil, err
	}
	if options.MaxAbsLog2ScaleDownError <= 0 || math.IsNaN(options.MaxAbsLog2ScaleDownError) || math.IsInf(options.MaxAbsLog2ScaleDownError, 0) {
		return nil, fmt.Errorf("homchain: invalid ScaleDown log2-error bound %v", options.MaxAbsLog2ScaleDownError)
	}
	if err := validateA2AIHighRawDFT(params, rawDFT); err != nil {
		return nil, err
	}

	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-I construct Z2^8 ring: %w", err)
	}
	const words = 4
	specifications, err := NewSpecificationsFromRing(ringZ, words)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-I construct normal transform sources: %w", err)
	}
	vSpec, uSpec := specifications.VPair(), specifications.UPair()
	vOptions := CompileOptions{
		LevelQ: params.MaxLevel(), LevelP: params.MaxLevelP(), Scale: params.DefaultScale(),
		LogBabyStepGiantStepRatio: 0,
	}
	v, err := CompilePair(params, encoder, vSpec, vOptions)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-I compile sealed normal V pair: %w", err)
	}
	uOptions := vOptions
	uOptions.LevelQ = rawDFT.ctsOutputLevel
	u, err := CompilePair(params, encoder, uSpec, uOptions)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2A-I compile sealed normal U pair: %w", err)
	}
	if err = validateCompiledPairAtLevel("sealed normal V", v, vOptions.LevelQ); err != nil {
		return nil, err
	}
	if err = validateCompiledPairAtLevel("sealed normal U", u, uOptions.LevelQ); err != nil {
		return nil, err
	}

	vProfile, err := newA2AITransformCompileProfile(params, vSpec, v, vOptions)
	if err != nil {
		return nil, err
	}
	uProfile, err := newA2AITransformCompileProfile(params, uSpec, u, uOptions)
	if err != nil {
		return nil, err
	}
	sourceDigest := digestA2AITransformSources(vSpec, uSpec)
	rawTrace := rawDFT.auditTrace()
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal A2A-I parameters for digest: %w", err)
	}
	parametersDigest := sha256Hex(parameterBytes)
	keyProfile := requiredA2AIKeyProfile(params, rawDFT, v, u)
	profile := A2AIHighProfile{
		wordBits: z2n.Word8, words: words, slots: params.MaxSlots(), encoderPrecision: encoder.Prec(),
		maxAbsLog2ScaleError: options.MaxAbsLog2ScaleDownError,
		transformNames:       []TransformName{V0Normal, V1Normal, U0Normal, U1Normal},
		vCompile:             vProfile, uCompile: uProfile, transformSourceDigest: sourceDigest,
		rawDFTDigest: rawTrace.Digest, parametersDigest: parametersDigest,
	}
	profile.circuitDigest = digestA2AIHighCircuit(profile, keyProfile)
	return &A2AIHighCircuit{
		params: params, rawDFT: rawDFT, v: v, u: u, options: options,
		profile: profile, keyProfile: keyProfile,
	}, nil
}

func (c *A2AIHighCircuit) Profile() A2AIHighProfile {
	if c == nil {
		return A2AIHighProfile{}
	}
	result := c.profile
	result.transformNames = c.profile.TransformNames()
	result.vCompile = c.profile.VCompile()
	result.uCompile = c.profile.UCompile()
	return result
}

// RequiredKeyProfile is available before bootstrap key generation and returns
// a detached copy of the exact internal transform/DFT key contract.
func (c *A2AIHighCircuit) RequiredKeyProfile() A2AIKeyProfile {
	if c == nil {
		return A2AIKeyProfile{}
	}
	return cloneA2AIKeyProfile(c.keyProfile)
}

// BindEvaluator binds a bootstrap evaluator to this circuit after key
// generation. The same internal key profile is checked again on every call to
// A2AIHighNew, so post-bind key removal fails closed before Z-To-C.
func (c *A2AIHighCircuit) BindEvaluator(bootstrap *bootstrapping.Evaluator) (*A2AIHighEvaluator, error) {
	if c == nil {
		return nil, fmt.Errorf("homchain: nil A2A-I circuit")
	}
	if c.profile.circuitDigest == "" || c.profile.transformSourceDigest == "" || c.keyProfile.Digest == "" {
		return nil, fmt.Errorf("homchain: uninitialized A2A-I circuit")
	}
	if bootstrap == nil || bootstrap.Evaluator == nil || bootstrap.DFTEvaluator == nil {
		return nil, fmt.Errorf("homchain: nil A2A-I bootstrap evaluator")
	}
	if bootstrap.EvaluationKeys == nil || bootstrap.MemEvaluationKeySet == nil {
		return nil, fmt.Errorf("homchain: nil A2A-I evaluation-key set")
	}
	if bootstrap.EvkDenseToSparse != nil || bootstrap.EvkSparseToDense != nil {
		return nil, fmt.Errorf("homchain: A2A-I guarded adaptation requires dense/no-switch ModUp keys")
	}
	if !bootstrap.ResidualParameters.Equal(&c.params) || !bootstrap.BootstrappingParameters.Equal(&c.params) ||
		!c.params.Equal(bootstrap.Evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: A2A-I residual, bootstrap, or bound evaluator parameters differ from the circuit parameters")
	}
	if ratio := bootstrap.Mod1Parameters.MessageRatio(); ratio != 1 {
		return nil, fmt.Errorf("homchain: A2A-I requires MessageRatio=1, got %g", ratio)
	}
	requestedModUpScale := bootstrap.Mod1Parameters.ScalingFactor().Float64()
	minimumAdmittedScaleDown := float64(c.params.Q()[0]) * math.Exp2(-c.options.MaxAbsLog2ScaleDownError)
	if requestedModUpScale > minimumAdmittedScaleDown {
		return nil, fmt.Errorf("homchain: ModUp scaling factor %.8g can exceed admitted ScaleDown raw scale %.8g", requestedModUpScale, minimumAdmittedScaleDown)
	}
	if bootstrap.CoeffsToSlotsParameters.LogSlots != c.rawDFT.logSlots {
		return nil, fmt.Errorf("homchain: ModUp Trace LogSlots=%d differs from raw DFT LogSlots=%d", bootstrap.CoeffsToSlotsParameters.LogSlots, c.rawDFT.logSlots)
	}
	gap := 1 << (c.params.LogN() - c.rawDFT.logSlots - 1)
	if gap != 1 {
		return nil, fmt.Errorf("homchain: A2A-I full-packing Trace gap is %d, want 1", gap)
	}
	sourceGraph, err := captureA2AIEvaluatorGraph(bootstrap, c.keyProfile)
	if err != nil {
		return nil, err
	}
	sealedBootstrap := sealA2AIBootstrapEvaluator(bootstrap, c.params)
	executionGraph, err := captureA2AIEvaluatorGraph(sealedBootstrap, c.keyProfile)
	if err != nil {
		return nil, fmt.Errorf("homchain: seal A2A-I evaluator graph: %w", err)
	}
	return &A2AIHighEvaluator{
		circuit: c, bootstrap: sealedBootstrap, triangle: NewEvaluator(sealedBootstrap.Evaluator),
		rawDFT: c.rawDFT, options: c.options, gap: gap,
		sourceGraph: sourceGraph, executionGraph: executionGraph,
	}, nil
}

func validateA2AIHighParameters(params ckks.Parameters) error {
	if params.LogN() != 5 || params.RingType() != ring.Standard || params.MaxSlots() != 16 {
		return fmt.Errorf("homchain: A2A-I requires standard LogN=5 with 16 full slots")
	}
	if params.MaxLevel() != 8 || params.MaxLevelP() != 0 || params.LevelsConsumedPerRescaling() != 1 {
		return fmt.Errorf("homchain: A2A-I requires nine Q primes, one P prime, and one level per rescale")
	}
	q, p := params.Q(), params.P()
	if len(q) != 9 || len(p) != 1 || roundedLog2(q[0]) != 50 || roundedLog2(p[0]) != 50 || params.LogDefaultScale() != 35 {
		return fmt.Errorf("homchain: A2A-I requires LogQ=[50,35x8], LogP=[50], LogDefaultScale=35")
	}
	for i := 1; i < len(q); i++ {
		if roundedLog2(q[i]) != 35 {
			return fmt.Errorf("homchain: A2A-I Q[%d] has %d bits, want 35", i, roundedLog2(q[i]))
		}
	}
	return nil
}

func validateA2AIHighRawDFT(params ckks.Parameters, rawDFT RawFullSlotDFT) error {
	if !params.Equal(&rawDFT.params) {
		return fmt.Errorf("homchain: raw DFT and A2A-I circuit CKKS parameters differ")
	}
	if len(rawDFT.slotsToCoeffs.Matrices) == 0 || len(rawDFT.coeffsToSlots.Matrices) == 0 {
		return fmt.Errorf("homchain: uninitialized raw full-slot DFT")
	}
	if rawDFT.encoderPrecision != z2n.DefaultPrecision {
		return fmt.Errorf("homchain: A2A-I raw DFT encoder precision=%d, want %d", rawDFT.encoderPrecision, z2n.DefaultPrecision)
	}
	if rawDFT.generatorPrecision != z2n.DefaultPrecision {
		return fmt.Errorf("homchain: A2A-I raw DFT generator precision=%d, want %d", rawDFT.generatorPrecision, z2n.DefaultPrecision)
	}
	if rawDFT.matrixSourceDigest == "" {
		return fmt.Errorf("homchain: A2A-I raw DFT matrix-source digest is empty")
	}
	if !equalIntSlice(rawDFT.slotsToCoeffs.Levels, []int{1, 1}) ||
		!equalIntSlice(rawDFT.coeffsToSlots.Levels, []int{1, 1, 1}) {
		return fmt.Errorf("homchain: A2A-I raw DFT requires exact factorization [1 1]/[1 1 1]")
	}
	if rawDFT.slotsToCoeffs.LogBSGSRatio != 0 || rawDFT.coeffsToSlots.LogBSGSRatio != 0 {
		return fmt.Errorf("homchain: A2A-I raw DFT requires fixed LogBSGSRatio=0")
	}
	if rawDFT.logSlots != params.LogMaxSlots() || rawDFT.logSlots != 4 {
		return fmt.Errorf("homchain: A2A-I raw DFT is not the fixed 16-slot full packing")
	}
	if rawDFT.slotsToCoeffs.Type != ckksdft.HomomorphicDecode || rawDFT.slotsToCoeffs.Format != ckksdft.SplitRealAndImag ||
		rawDFT.coeffsToSlots.Type != ckksdft.HomomorphicEncode || rawDFT.coeffsToSlots.Format != ckksdft.SplitRealAndImag {
		return fmt.Errorf("homchain: A2A-I raw DFT has an unexpected type or split format")
	}
	if rawDFT.slotsToCoeffs.LevelQ != params.MaxLevel()-params.LevelsConsumedPerRescaling() ||
		rawDFT.coeffsToSlots.LevelQ != params.MaxLevel() ||
		rawDFT.slotsToCoeffs.LevelP != params.MaxLevelP() || rawDFT.coeffsToSlots.LevelP != params.MaxLevelP() {
		return fmt.Errorf("homchain: A2A-I raw DFT levels do not match the fixed profile")
	}
	if rawDFT.stcOutputLevel != rawDFT.slotsToCoeffs.LevelQ-2*params.LevelsConsumedPerRescaling() ||
		rawDFT.ctsOutputLevel != rawDFT.coeffsToSlots.LevelQ-3*params.LevelsConsumedPerRescaling() {
		return fmt.Errorf("homchain: A2A-I raw DFT output levels are inconsistent")
	}
	one := new(big.Float).SetInt64(1)
	if rawDFT.slotsToCoeffs.Scaling == nil || rawDFT.coeffsToSlots.Scaling == nil ||
		rawDFT.slotsToCoeffs.Scaling.Cmp(one) != 0 || rawDFT.coeffsToSlots.Scaling.Cmp(one) != 0 {
		return fmt.Errorf("homchain: A2A-I raw DFT literal scaling must be exactly one")
	}
	return nil
}

func newA2AITransformCompileProfile(params ckks.Parameters, spec PairSpec, pair CompiledPair, options CompileOptions) (A2AITransformCompileProfile, error) {
	scale, err := NewExactScaleSnapshot(options.Scale)
	if err != nil {
		return A2AITransformCompileProfile{}, fmt.Errorf("homchain: snapshot A2A-I compile scale: %w", err)
	}
	if pair.Low.LevelQ != options.LevelQ || pair.High.LevelQ != options.LevelQ || pair.Low.LevelP != options.LevelP || pair.High.LevelP != options.LevelP {
		return A2AITransformCompileProfile{}, fmt.Errorf("homchain: compiled A2A-I pair does not match requested levels")
	}
	if !scale.EqualScale(pair.Low.Scale) || !scale.EqualScale(pair.High.Scale) {
		return A2AITransformCompileProfile{}, fmt.Errorf("homchain: compiled A2A-I pair does not match requested exact scale")
	}
	return A2AITransformCompileProfile{
		lowName: spec.Low.Name(), highName: spec.High.Name(), levelQ: options.LevelQ, levelP: options.LevelP,
		scale: scale, logDimensions: pair.Low.LogDimensions, logBSGSRatio: options.LogBabyStepGiantStepRatio,
		rotationIndexes: pair.RotationIndexes(), galoisElements: pair.GaloisElements(params),
	}, nil
}

func digestA2AITransformSources(v, u PairSpec) string {
	var canonical strings.Builder
	canonical.WriteString("a2ai-normal-source-v1")
	for _, spec := range []TransformSpec{v.Low, v.High, u.Low, u.High} {
		fmt.Fprintf(&canonical, "|name=%s|layout=%s|words=%d|half=%d|dimensions=%d,%d|matrix=", spec.Name(), spec.Layout(), spec.Words(), spec.HalfWidth(), spec.LogDimensions().Rows, spec.LogDimensions().Cols)
		for _, row := range spec.Matrix() {
			for _, value := range row {
				fmt.Fprintf(&canonical, "%s@%d/%d,%s@%d/%d;", value.Real().Text('x', -1), value.Real().Prec(), value.Real().Mode(), value.Imag().Text('x', -1), value.Imag().Prec(), value.Imag().Mode())
			}
		}
	}
	return sha256Hex([]byte(canonical.String()))
}

func digestA2AIHighCircuit(profile A2AIHighProfile, keys A2AIKeyProfile) string {
	canonical := fmt.Sprintf(
		"a2ai-high-circuit-v1|word-bits=%d|words=%d|slots=%d|precision=%d|names=%v|V=%s|U=%s|source=%s|raw-dft=%s|params=%s|keys=%s|max-scale-error-bits=%016x",
		profile.wordBits, profile.words, profile.slots, profile.encoderPrecision, profile.transformNames,
		canonicalA2AICompileProfile(profile.vCompile), canonicalA2AICompileProfile(profile.uCompile),
		profile.transformSourceDigest, profile.rawDFTDigest, profile.parametersDigest, keys.Digest,
		math.Float64bits(profile.maxAbsLog2ScaleError),
	)
	return sha256Hex([]byte(canonical))
}

func canonicalA2AICompileProfile(profile A2AITransformCompileProfile) string {
	return fmt.Sprintf("%s,%s@Q%d/P%d/scale={%s}/dimensions=%d,%d/bsgs=%d/rot=%v/gal=%v",
		profile.lowName, profile.highName, profile.levelQ, profile.levelP, profile.scale.canonicalString(),
		profile.logDimensions.Rows, profile.logDimensions.Cols, profile.logBSGSRatio,
		profile.rotationIndexes, profile.galoisElements)
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func roundedLog2(value uint64) int { return int(math.Round(math.Log2(float64(value)))) }
