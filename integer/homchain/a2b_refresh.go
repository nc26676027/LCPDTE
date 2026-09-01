package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strings"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	ckksdft "github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	ckkslintrans "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	a2bRefreshGeneratorEncoderPrecision uint = 192
	a2bRefreshLogMessageRatio                = 15
)

// A2BRefreshFidelity is the strongest claim carried by this stopped A2B
// vertical slice. It is an executable Lattigo adaptation, not the sparse-key
// construction or security parameters from Gao--Zheng.
type A2BRefreshFidelity string

const (
	A2BRefreshFunctionalLattigoAdaptationNotSecure A2BRefreshFidelity = "functional_lattigo_adaptation_not_secure"
)

// A2BRefreshSchedule prevents the parallel first-iteration evidence from
// being mistaken for the level schedule of the serial second A2B iteration.
type A2BRefreshSchedule string

const (
	A2BRefreshFirstIterationParallelHalfBackbones A2BRefreshSchedule = "first_iteration_parallel_half_backbones_only"
)

// A2BRefreshDFTProfile is an immutable public projection of both paper-level
// DFT literals and their Lattigo-initialized execution literals. Numeric
// payload witnesses bind the latter; encoded matrices remain private.
type A2BRefreshDFTProfile struct {
	stcLiteral          ckksdft.MatrixLiteral
	ctsLiteral          ckksdft.MatrixLiteral
	stcExecutionLiteral ckksdft.MatrixLiteral
	ctsExecutionLiteral ckksdft.MatrixLiteral
	encoderPrecision    uint
	generatorPrecision  uint
	stcRawMatrixDigest  string
	ctsRawMatrixDigest  string
	stcMatrixDigest     string
	ctsMatrixDigest     string
	digest              string
}

func (p A2BRefreshDFTProfile) SlotsToCoeffsLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.stcLiteral)
}

func (p A2BRefreshDFTProfile) CoeffsToSlotsLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.ctsLiteral)
}

func (p A2BRefreshDFTProfile) SlotsToCoeffsExecutionLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.stcExecutionLiteral)
}

func (p A2BRefreshDFTProfile) CoeffsToSlotsExecutionLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.ctsExecutionLiteral)
}

func (p A2BRefreshDFTProfile) EncoderPrecision() uint   { return p.encoderPrecision }
func (p A2BRefreshDFTProfile) GeneratorPrecision() uint { return p.generatorPrecision }
func (p A2BRefreshDFTProfile) SlotsToCoeffsRawMatrixDigest() string {
	return p.stcRawMatrixDigest
}
func (p A2BRefreshDFTProfile) CoeffsToSlotsRawMatrixDigest() string {
	return p.ctsRawMatrixDigest
}
func (p A2BRefreshDFTProfile) SlotsToCoeffsExecutionMatrixDigest() string {
	return p.stcMatrixDigest
}
func (p A2BRefreshDFTProfile) CoeffsToSlotsExecutionMatrixDigest() string {
	return p.ctsMatrixDigest
}
func (p A2BRefreshDFTProfile) SlotsToCoeffsMatrixDigest() string { return p.stcMatrixDigest }
func (p A2BRefreshDFTProfile) CoeffsToSlotsMatrixDigest() string { return p.ctsMatrixDigest }
func (p A2BRefreshDFTProfile) Digest() string                    { return p.digest }

// A2BRefreshTransformProfile records the only accepted ingress transform:
// special-b0 V0 paired with normal V1.
type A2BRefreshTransformProfile struct {
	lowName         TransformName
	highName        TransformName
	levelQ          int
	levelP          int
	scale           ExactScaleSnapshot
	logDimensions   ring.Dimensions
	rotationIndexes []int
	galoisElements  []uint64
}

func (p A2BRefreshTransformProfile) LowName() TransformName         { return p.lowName }
func (p A2BRefreshTransformProfile) HighName() TransformName        { return p.highName }
func (p A2BRefreshTransformProfile) LevelQ() int                    { return p.levelQ }
func (p A2BRefreshTransformProfile) LevelP() int                    { return p.levelP }
func (p A2BRefreshTransformProfile) Scale() ExactScaleSnapshot      { return p.scale }
func (p A2BRefreshTransformProfile) LogDimensions() ring.Dimensions { return p.logDimensions }
func (p A2BRefreshTransformProfile) RotationIndexes() []int {
	return append([]int(nil), p.rotationIndexes...)
}
func (p A2BRefreshTransformProfile) GaloisElements() []uint64 {
	return append([]uint64(nil), p.galoisElements...)
}

func cloneA2BRefreshTransformProfile(p A2BRefreshTransformProfile) A2BRefreshTransformProfile {
	result := p
	result.rotationIndexes = p.RotationIndexes()
	result.galoisElements = p.GaloisElements()
	return result
}

// A2BRefreshKeyProfile is the exact stopped-slice key union. Trace and
// residual rotations are named independently even though full packing and
// n=8,w=4 make both sets empty.
type A2BRefreshKeyProfile struct {
	specialB0       []uint64
	slotsToCoeffs   []uint64
	trace           []uint64
	coeffsToSlots   []uint64
	conjugation     []uint64
	residual        []uint64
	all             []uint64
	relinearization bool
	digest          string
}

func (p A2BRefreshKeyProfile) SpecialB0() []uint64 { return append([]uint64(nil), p.specialB0...) }
func (p A2BRefreshKeyProfile) SlotsToCoeffs() []uint64 {
	return append([]uint64(nil), p.slotsToCoeffs...)
}
func (p A2BRefreshKeyProfile) Trace() []uint64 { return append([]uint64(nil), p.trace...) }
func (p A2BRefreshKeyProfile) CoeffsToSlots() []uint64 {
	return append([]uint64(nil), p.coeffsToSlots...)
}
func (p A2BRefreshKeyProfile) Conjugation() []uint64         { return append([]uint64(nil), p.conjugation...) }
func (p A2BRefreshKeyProfile) Residual() []uint64            { return append([]uint64(nil), p.residual...) }
func (p A2BRefreshKeyProfile) All() []uint64                 { return append([]uint64(nil), p.all...) }
func (p A2BRefreshKeyProfile) RelinearizationRequired() bool { return p.relinearization }
func (p A2BRefreshKeyProfile) Digest() string                { return p.digest }

func cloneA2BRefreshKeyProfile(p A2BRefreshKeyProfile) A2BRefreshKeyProfile {
	result := p
	result.specialB0 = p.SpecialB0()
	result.slotsToCoeffs = p.SlotsToCoeffs()
	result.trace = p.Trace()
	result.coeffsToSlots = p.CoeffsToSlots()
	result.conjugation = p.Conjugation()
	result.residual = p.Residual()
	result.all = p.All()
	return result
}

// A2BRefreshProfile fixes the n=8,w=4 four-word stopped circuit before key
// generation. Every slice and literal accessor returns detached data.
type A2BRefreshProfile struct {
	fidelity              A2BRefreshFidelity
	schedule              A2BRefreshSchedule
	wordBits              z2n.WordBits
	chunkWidth            uint
	words                 int
	slots                 int
	inputLevel            int
	levelP                int
	encoderPrecision      uint
	transformNames        []TransformName
	transform             A2BRefreshTransformProfile
	dft                   A2BRefreshDFTProfile
	maskLevel             int
	maskOutputLevel       int
	maskScale             ExactScaleSnapshot
	transformSourceDigest string
	maskSourceDigest      string
	parametersDigest      string
	logMessageRatio       int
	normalizedCertified   bool
	normalizedVariable    string
	normalizedInvariant   string
	normalizedBlocker     string
	digest                string
}

func (p A2BRefreshProfile) Fidelity() A2BRefreshFidelity { return p.fidelity }
func (p A2BRefreshProfile) Schedule() A2BRefreshSchedule { return p.schedule }
func (p A2BRefreshProfile) WordBits() z2n.WordBits       { return p.wordBits }
func (p A2BRefreshProfile) ChunkWidth() uint             { return p.chunkWidth }
func (p A2BRefreshProfile) Words() int                   { return p.words }
func (p A2BRefreshProfile) Slots() int                   { return p.slots }
func (p A2BRefreshProfile) InputLevel() int              { return p.inputLevel }
func (p A2BRefreshProfile) LevelP() int                  { return p.levelP }
func (p A2BRefreshProfile) EncoderPrecision() uint       { return p.encoderPrecision }
func (p A2BRefreshProfile) TransformNames() []TransformName {
	return append([]TransformName(nil), p.transformNames...)
}
func (p A2BRefreshProfile) Transform() A2BRefreshTransformProfile {
	return cloneA2BRefreshTransformProfile(p.transform)
}
func (p A2BRefreshProfile) DFT() A2BRefreshDFTProfile {
	result := p.dft
	result.stcLiteral = p.dft.SlotsToCoeffsLiteral()
	result.ctsLiteral = p.dft.CoeffsToSlotsLiteral()
	result.stcExecutionLiteral = p.dft.SlotsToCoeffsExecutionLiteral()
	result.ctsExecutionLiteral = p.dft.CoeffsToSlotsExecutionLiteral()
	return result
}
func (p A2BRefreshProfile) MaskLevel() int                { return p.maskLevel }
func (p A2BRefreshProfile) MaskOutputLevel() int          { return p.maskOutputLevel }
func (p A2BRefreshProfile) MaskScale() ExactScaleSnapshot { return p.maskScale }
func (p A2BRefreshProfile) TransformSourceDigest() string { return p.transformSourceDigest }
func (p A2BRefreshProfile) MaskSourceDigest() string      { return p.maskSourceDigest }
func (p A2BRefreshProfile) ParametersDigest() string      { return p.parametersDigest }
func (p A2BRefreshProfile) LogMessageRatio() int          { return p.logMessageRatio }
func (p A2BRefreshProfile) NormalizedInputCertified() bool {
	return p.normalizedCertified
}
func (p A2BRefreshProfile) NormalizedVariable() string  { return p.normalizedVariable }
func (p A2BRefreshProfile) NormalizedInvariant() string { return p.normalizedInvariant }
func (p A2BRefreshProfile) NormalizedInputBlocker() string {
	return p.normalizedBlocker
}
func (p A2BRefreshProfile) Digest() string { return p.digest }

// A2BRefreshCircuit owns the special-b0 transform, two separately encoded
// masks, and both high-precision DFT matrices. Callers cannot replace any of
// these source-scheduled operands.
type A2BRefreshCircuit struct {
	params     ckks.Parameters
	specialB0  CompiledPair
	lowMask    *rlwe.Plaintext
	highMask   *rlwe.Plaintext
	stc        ckksdft.Matrix
	cts        ckksdft.Matrix
	profile    A2BRefreshProfile
	keyProfile A2BRefreshKeyProfile
}

// NewA2BRefreshCircuit constructs the fixed FUNCTIONAL-NOT-SECURE A2B
// ingress plus two Boolean-refresh backbones. The exp46 and ID/MSB LUT stages
// are deliberately outside this stopped slice.
func NewA2BRefreshCircuit(params ckks.Parameters, encoder *ckks.Encoder) (*A2BRefreshCircuit, error) {
	if encoder == nil {
		return nil, fmt.Errorf("homchain: A2B refresh nil encoder")
	}
	encoderParameters := encoder.GetParameters()
	if !params.Equal(&encoderParameters) {
		return nil, fmt.Errorf("homchain: A2B refresh encoder parameters do not match the circuit parameters")
	}
	if encoder.Prec() != a2bRefreshGeneratorEncoderPrecision {
		return nil, fmt.Errorf("homchain: A2B refresh encoder precision=%d, want %d", encoder.Prec(), a2bRefreshGeneratorEncoderPrecision)
	}
	if err := validateA2BRefreshParameters(params); err != nil {
		return nil, err
	}

	ringZ, err := z2n.NewWithPrecision(z2n.Word8, a2bRefreshGeneratorEncoderPrecision)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh construct Z2^8 ring: %w", err)
	}
	const words = 4
	specifications, err := NewSpecificationsFromRing(ringZ, words)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh construct transform specifications: %w", err)
	}
	pairSpec := specifications.VSpecialB0Pair()
	if pairSpec.Low.Name() != V0SpecialB0 || pairSpec.High.Name() != V1Normal {
		return nil, fmt.Errorf("homchain: A2B refresh ingress is not special-b0 V0 plus normal V1")
	}
	compileOptions := CompileOptions{
		LevelQ: params.MaxLevel(), LevelP: params.MaxLevelP(), Scale: rlwe.NewScale(params.Q()[params.MaxLevel()]),
		LogBabyStepGiantStepRatio: 0,
	}
	specialB0, err := CompilePair(params, encoder, pairSpec, compileOptions)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh compile special-b0 ingress: %w", err)
	}
	if err = validateCompiledPairAtLevel("A2B refresh special-b0 ingress", specialB0, params.MaxLevel()); err != nil {
		return nil, err
	}
	transformScale, err := NewExactScaleSnapshot(compileOptions.Scale)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh snapshot transform scale: %w", err)
	}
	transformProfile := A2BRefreshTransformProfile{
		lowName: pairSpec.Low.Name(), highName: pairSpec.High.Name(), levelQ: compileOptions.LevelQ,
		levelP: compileOptions.LevelP, scale: transformScale, logDimensions: specialB0.Low.LogDimensions,
		rotationIndexes: specialB0.RotationIndexes(), galoisElements: specialB0.GaloisElements(params),
	}

	stcLiteral, ctsLiteral := a2bRefreshDFTLiterals(params, encoder.Prec(), 18, params.MaxLevel())
	stcInitializationFactor, ctsInitializationFactor, err := a2bRefreshDFTInitializationFactors(params)
	if err != nil {
		return nil, err
	}
	stcExecutionLiteral := scaleA2BRefreshDFTLiteral(stcLiteral, stcInitializationFactor, encoder.Prec())
	ctsExecutionLiteral := scaleA2BRefreshDFTLiteral(ctsLiteral, ctsInitializationFactor, encoder.Prec())
	stcRawDigest := digestDFTMatrixNumericPayload(stcLiteral, stcLiteral.GenMatrices(params.LogN(), encoder.Prec()))
	ctsRawDigest := digestDFTMatrixNumericPayload(ctsLiteral, ctsLiteral.GenMatrices(params.LogN(), encoder.Prec()))
	stc, stcDigest, err := newDFTMatrixFromLiteralAtPrecision(params, stcExecutionLiteral, encoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh encode Slots-To-Coeffs: %w", err)
	}
	cts, ctsDigest, err := newDFTMatrixFromLiteralAtPrecision(params, ctsExecutionLiteral, encoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh encode Coeffs-To-Slots: %w", err)
	}
	dftProfile := A2BRefreshDFTProfile{
		stcLiteral: cloneDFTLiteral(stcLiteral), ctsLiteral: cloneDFTLiteral(ctsLiteral),
		stcExecutionLiteral: cloneDFTLiteral(stcExecutionLiteral), ctsExecutionLiteral: cloneDFTLiteral(ctsExecutionLiteral),
		encoderPrecision: encoder.Prec(), generatorPrecision: encoder.Prec(),
		stcRawMatrixDigest: stcRawDigest, ctsRawMatrixDigest: ctsRawDigest,
		stcMatrixDigest: stcDigest, ctsMatrixDigest: ctsDigest,
	}
	dftProfile.digest = digestString(fmt.Sprintf(
		"a2b-refresh-dft-v3|raw-stc=%v|raw-cts=%v|execution-stc=%v|execution-cts=%v|encoder=%d|generator=%d|raw-stc-matrix=%s|raw-cts-matrix=%s|execution-stc-matrix=%s|execution-cts-matrix=%s|normalization=lattigo_full_split_gap1_cts_1_over_16_message_ratio_2_pow_15",
		dftLiteralTrace(stcLiteral), dftLiteralTrace(ctsLiteral), dftLiteralTrace(stcExecutionLiteral), dftLiteralTrace(ctsExecutionLiteral),
		encoder.Prec(), encoder.Prec(), stcRawDigest, ctsRawDigest, stcDigest, ctsDigest,
	))

	const maskLevel = 19
	maskScale := rlwe.NewScale(params.Q()[maskLevel])
	lowMask, err := newA2BRefreshMask(params, encoder, maskLevel, maskScale)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh encode low chunk mask: %w", err)
	}
	highMask, err := newA2BRefreshMask(params, encoder, maskLevel, maskScale)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh encode high chunk mask: %w", err)
	}
	maskScaleSnapshot, err := NewExactScaleSnapshot(maskScale)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh snapshot mask scale: %w", err)
	}
	maskSourceDigest := digestString(fmt.Sprintf(
		"a2b-refresh-two-full-half-masks-v1|roles=low,high|slots=%d|value=1|level=%d|scale=%s|encoder-precision=%d",
		params.MaxSlots(), maskLevel, maskScaleSnapshot.canonicalString(), encoder.Prec(),
	))
	transformSourceDigest := digestA2BRefreshTransformSource(pairSpec)
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal A2B refresh parameters for digest: %w", err)
	}
	parametersDigest := sha256Hex(parameterBytes)
	keyProfile := newA2BRefreshKeyProfile(params, specialB0, stcLiteral, ctsLiteral)
	profile := A2BRefreshProfile{
		fidelity: A2BRefreshFunctionalLattigoAdaptationNotSecure,
		schedule: A2BRefreshFirstIterationParallelHalfBackbones,
		wordBits: z2n.Word8, chunkWidth: 4, words: words, slots: params.MaxSlots(),
		inputLevel: params.MaxLevel(), levelP: params.MaxLevelP(), encoderPrecision: encoder.Prec(),
		transformNames: []TransformName{V0SpecialB0, V1Normal}, transform: transformProfile, dft: dftProfile,
		maskLevel: maskLevel, maskOutputLevel: maskLevel - params.LevelsConsumedPerRescaling(), maskScale: maskScaleSnapshot,
		transformSourceDigest: transformSourceDigest, maskSourceDigest: maskSourceDigest, parametersDigest: parametersDigest,
		logMessageRatio:     a2bRefreshLogMessageRatio,
		normalizedCertified: false,
		normalizedVariable:  "exp46-y=(I+a)/16;a=selected-special-b0-raw",
		normalizedInvariant: "16*y-a-is-integral;low-a-congruent-to--u/16-mod-Z;CTS-L17-exact-S35-matches-Gao-kernel-ingress;exp46-then-square^2-cancels-integral-lifts-via-exp(i*2*pi*(I+a))",
		normalizedBlocker:   "Lattigo-ScaleDown/ModUp-integral-lift-I-is-not-source-certified-or-deterministic",
	}
	profile.digest = digestA2BRefreshProfile(profile, keyProfile)
	return &A2BRefreshCircuit{
		params: params, specialB0: specialB0, lowMask: lowMask, highMask: highMask,
		stc: stc, cts: cts, profile: profile, keyProfile: keyProfile,
	}, nil
}

func (c *A2BRefreshCircuit) Profile() A2BRefreshProfile {
	if c == nil {
		return A2BRefreshProfile{}
	}
	result := c.profile
	result.transformNames = c.profile.TransformNames()
	result.transform = c.profile.Transform()
	result.dft = c.profile.DFT()
	return result
}

func (c *A2BRefreshCircuit) RequiredKeyProfile() A2BRefreshKeyProfile {
	if c == nil {
		return A2BRefreshKeyProfile{}
	}
	return cloneA2BRefreshKeyProfile(c.keyProfile)
}

// A2BRefreshHalf names the two physically separate first-iteration refresh
// invocations. WholeInput is used only for the admission state.
type A2BRefreshHalf string

const (
	A2BRefreshWholeInput A2BRefreshHalf = "whole-input"
	A2BRefreshLowHalf    A2BRefreshHalf = "low"
	A2BRefreshHighHalf   A2BRefreshHalf = "high"
)

// A2BRefreshStage is one exact ciphertext transition in the stopped graph.
type A2BRefreshStage string

const (
	A2BRefreshStageInput         A2BRefreshStage = "input"
	A2BRefreshStageSpecialB0     A2BRefreshStage = "special-b0-z2c"
	A2BRefreshStageMaskRescale   A2BRefreshStage = "chunk-mask-rescale"
	A2BRefreshStageSlotsToCoeffs A2BRefreshStage = "slots-to-coeffs"
	A2BRefreshStageScaleDown     A2BRefreshStage = "guarded-scale-down"
	A2BRefreshStageModUpTrace    A2BRefreshStage = "mod-up-full-packing-trace"
	A2BRefreshStageCoeffsToSlots A2BRefreshStage = "coeffs-to-slots-real"
)

// A2BRefreshCiphertextState is a detached exact level/scale snapshot.
type A2BRefreshCiphertextState struct {
	Half          A2BRefreshHalf
	Invocation    A2BRefreshHalf
	Stage         A2BRefreshStage
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

// A2BRefreshKeyPreflight records the fail-closed check completed before the
// evaluator copies or transforms the input ciphertext.
type A2BRefreshKeyPreflight struct {
	Checked                  bool
	GraphChecked             bool
	GraphMatched             bool
	GraphMismatch            string
	MissingGaloisElements    []uint64
	InvalidGaloisElements    []uint64
	UnexpectedGaloisElements []uint64
	RelinearizationPresent   bool
	RelinearizationMatched   bool
	DenseNoSwitchingMatched  bool
}

func cloneA2BRefreshKeyPreflight(input A2BRefreshKeyPreflight) A2BRefreshKeyPreflight {
	result := input
	result.MissingGaloisElements = append([]uint64(nil), input.MissingGaloisElements...)
	result.InvalidGaloisElements = append([]uint64(nil), input.InvalidGaloisElements...)
	result.UnexpectedGaloisElements = append([]uint64(nil), input.UnexpectedGaloisElements...)
	return result
}

// A2BRefreshTrace is the immutable execution evidence for the two backbones.
type A2BRefreshTrace struct {
	fidelity      A2BRefreshFidelity
	schedule      A2BRefreshSchedule
	profileDigest string
	states        []A2BRefreshCiphertextState
	keyPreflight  A2BRefreshKeyPreflight
	lowErrScale   ExactScaleSnapshot
	highErrScale  ExactScaleSnapshot
	lowErrLog2    float64
	highErrLog2   float64
}

func (t A2BRefreshTrace) Fidelity() A2BRefreshFidelity { return t.fidelity }
func (t A2BRefreshTrace) Schedule() A2BRefreshSchedule { return t.schedule }
func (t A2BRefreshTrace) ProfileDigest() string        { return t.profileDigest }
func (t A2BRefreshTrace) States() []A2BRefreshCiphertextState {
	return append([]A2BRefreshCiphertextState(nil), t.states...)
}
func (t A2BRefreshTrace) State(half A2BRefreshHalf, stage A2BRefreshStage) (A2BRefreshCiphertextState, bool) {
	for _, state := range t.states {
		if state.Half == half && state.Stage == stage {
			return state, true
		}
	}
	return A2BRefreshCiphertextState{}, false
}
func (t A2BRefreshTrace) KeyPreflight() A2BRefreshKeyPreflight {
	return cloneA2BRefreshKeyPreflight(t.keyPreflight)
}
func (t A2BRefreshTrace) ScaleDownError(half A2BRefreshHalf) (ExactScaleSnapshot, float64, bool) {
	switch half {
	case A2BRefreshLowHalf:
		return t.lowErrScale, t.lowErrLog2, t.lowErrScale.ValueHex() != ""
	case A2BRefreshHighHalf:
		return t.highErrScale, t.highErrLog2, t.highErrScale.ValueHex() != ""
	default:
		return ExactScaleSnapshot{}, 0, false
	}
}

// A2BRefreshResult retains detached evidence for the special-b0 and mask
// gates plus the two normalized CTS real outputs. Accessors always copy.
type A2BRefreshResult struct {
	specialLow    *rlwe.Ciphertext
	specialHigh   *rlwe.Ciphertext
	maskedLow     *rlwe.Ciphertext
	maskedHigh    *rlwe.Ciphertext
	refreshedLow  *rlwe.Ciphertext
	refreshedHigh *rlwe.Ciphertext
}

func copyA2BRefreshCiphertext(input *rlwe.Ciphertext) *rlwe.Ciphertext {
	if input == nil {
		return nil
	}
	return input.CopyNew()
}

func (r A2BRefreshResult) SpecialB0Low() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.specialLow)
}
func (r A2BRefreshResult) SpecialB0High() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.specialHigh)
}
func (r A2BRefreshResult) MaskedLow() *rlwe.Ciphertext { return copyA2BRefreshCiphertext(r.maskedLow) }
func (r A2BRefreshResult) MaskedHigh() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.maskedHigh)
}
func (r A2BRefreshResult) RefreshedLow() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.refreshedLow)
}
func (r A2BRefreshResult) RefreshedHigh() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.refreshedHigh)
}

type a2bRefreshCircuitGraphIdentity struct {
	circuit        *A2BRefreshCircuit
	lowMask        *rlwe.Plaintext
	highMask       *rlwe.Plaintext
	specialLowVec  uintptr
	specialHighVec uintptr
	stcFactorVecs  []uintptr
	ctsFactorVecs  []uintptr
	profileDigest  string
	keyDigest      string
}

func a2bRefreshLinearIdentity(transformation ckkslintrans.LinearTransformation) uintptr {
	if transformation.Vec == nil {
		return 0
	}
	return reflect.ValueOf(transformation.Vec).Pointer()
}

func captureA2BRefreshCircuitGraph(circuit *A2BRefreshCircuit) (a2bRefreshCircuitGraphIdentity, error) {
	if circuit == nil || circuit.lowMask == nil || circuit.highMask == nil || circuit.lowMask == circuit.highMask {
		return a2bRefreshCircuitGraphIdentity{}, fmt.Errorf("homchain: incomplete or shared A2B refresh mask graph")
	}
	identity := a2bRefreshCircuitGraphIdentity{
		circuit: circuit, lowMask: circuit.lowMask, highMask: circuit.highMask,
		specialLowVec:  a2bRefreshLinearIdentity(circuit.specialB0.Low),
		specialHighVec: a2bRefreshLinearIdentity(circuit.specialB0.High),
		profileDigest:  circuit.profile.digest, keyDigest: circuit.keyProfile.digest,
	}
	if identity.specialLowVec == 0 || identity.specialHighVec == 0 || identity.specialLowVec == identity.specialHighVec {
		return a2bRefreshCircuitGraphIdentity{}, fmt.Errorf("homchain: incomplete or shared A2B refresh special-b0 transform graph")
	}
	for _, matrix := range circuit.stc.Matrices {
		identity.stcFactorVecs = append(identity.stcFactorVecs, a2bRefreshLinearIdentity(matrix))
	}
	for _, matrix := range circuit.cts.Matrices {
		identity.ctsFactorVecs = append(identity.ctsFactorVecs, a2bRefreshLinearIdentity(matrix))
	}
	if len(identity.stcFactorVecs) != 2 || len(identity.ctsFactorVecs) != 3 {
		return a2bRefreshCircuitGraphIdentity{}, fmt.Errorf("homchain: A2B refresh DFT graph has factors STC=%d CTS=%d, want 2/3", len(identity.stcFactorVecs), len(identity.ctsFactorVecs))
	}
	seenFactors := map[uintptr]bool{}
	for _, pointer := range append(append([]uintptr(nil), identity.stcFactorVecs...), identity.ctsFactorVecs...) {
		if pointer == 0 {
			return a2bRefreshCircuitGraphIdentity{}, fmt.Errorf("homchain: A2B refresh DFT graph contains an empty factor")
		}
		if seenFactors[pointer] {
			return a2bRefreshCircuitGraphIdentity{}, fmt.Errorf("homchain: A2B refresh DFT graph contains a shared factor")
		}
		seenFactors[pointer] = true
	}
	return identity, nil
}

func (g a2bRefreshCircuitGraphIdentity) validate() error {
	c := g.circuit
	if c == nil || c.lowMask != g.lowMask || c.highMask != g.highMask || c.lowMask == c.highMask {
		return fmt.Errorf("circuit or separately encoded mask identity changed")
	}
	if c.profile.digest != g.profileDigest || c.keyProfile.digest != g.keyDigest || digestA2BRefreshProfile(c.profile, c.keyProfile) != g.profileDigest {
		return fmt.Errorf("profile or key digest changed")
	}
	if a2bRefreshLinearIdentity(c.specialB0.Low) != g.specialLowVec || a2bRefreshLinearIdentity(c.specialB0.High) != g.specialHighVec {
		return fmt.Errorf("special-b0 compiled transform graph changed")
	}
	if len(c.stc.Matrices) != len(g.stcFactorVecs) || len(c.cts.Matrices) != len(g.ctsFactorVecs) {
		return fmt.Errorf("DFT factor count changed")
	}
	for i := range g.stcFactorVecs {
		if a2bRefreshLinearIdentity(c.stc.Matrices[i]) != g.stcFactorVecs[i] {
			return fmt.Errorf("Slots-To-Coeffs factor %d changed", i)
		}
	}
	for i := range g.ctsFactorVecs {
		if a2bRefreshLinearIdentity(c.cts.Matrices[i]) != g.ctsFactorVecs[i] {
			return fmt.Errorf("Coeffs-To-Slots factor %d changed", i)
		}
	}
	if !a2bRefreshLiteralEqual(c.stc.MatrixLiteral, c.profile.dft.stcExecutionLiteral) ||
		!a2bRefreshLiteralEqual(c.cts.MatrixLiteral, c.profile.dft.ctsExecutionLiteral) {
		return fmt.Errorf("DFT literal graph changed")
	}
	if c.lowMask.Level() != c.profile.maskLevel || c.highMask.Level() != c.profile.maskLevel ||
		!c.profile.maskScale.EqualScale(c.lowMask.Scale) || !c.profile.maskScale.EqualScale(c.highMask.Scale) ||
		c.lowMask.LogDimensions != c.profile.transform.logDimensions || c.highMask.LogDimensions != c.profile.transform.logDimensions {
		return fmt.Errorf("mask level, scale, or dimensions changed")
	}
	return nil
}

// A2BRefreshEvaluator is a graph-sealed evaluator for one circuit profile.
type A2BRefreshEvaluator struct {
	circuit        *A2BRefreshCircuit
	bootstrap      *bootstrapping.Evaluator
	triangle       *Evaluator
	sourceGraph    a2aiEvaluatorGraphIdentity
	executionGraph a2aiEvaluatorGraphIdentity
	circuitGraph   a2bRefreshCircuitGraphIdentity
}

// BindEvaluator seals the source evaluator and verifies that its bootstrap
// metadata describes this exact first-iteration refresh profile.
func (c *A2BRefreshCircuit) BindEvaluator(source *bootstrapping.Evaluator) (*A2BRefreshEvaluator, error) {
	if c == nil {
		return nil, fmt.Errorf("homchain: nil A2B refresh circuit")
	}
	if source == nil || source.Evaluator == nil || source.DFTEvaluator == nil || source.EvaluationKeys == nil || source.MemEvaluationKeySet == nil {
		return nil, fmt.Errorf("homchain: incomplete A2B refresh bootstrap evaluator")
	}
	if !source.ResidualParameters.Equal(&c.params) || !source.BootstrappingParameters.Equal(&c.params) || !c.params.Equal(source.Evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: A2B refresh evaluator parameters differ from the circuit")
	}
	if source.EvkDenseToSparse != nil || source.EvkSparseToDense != nil {
		return nil, fmt.Errorf("homchain: A2B refresh functional slice requires dense/no-switch ModUp")
	}
	if source.Mod1Parameters.LogMessageRatio != c.profile.logMessageRatio ||
		source.Mod1Parameters.MessageRatio() != math.Exp2(float64(c.profile.logMessageRatio)) {
		return nil, fmt.Errorf(
			"homchain: A2B refresh requires LogMessageRatio=%d (MessageRatio=2^%d)",
			c.profile.logMessageRatio, c.profile.logMessageRatio,
		)
	}
	if !a2bRefreshLiteralEqual(source.SlotsToCoeffsParameters, c.profile.dft.stcExecutionLiteral) ||
		!a2bRefreshLiteralEqual(source.CoeffsToSlotsParameters, c.profile.dft.ctsExecutionLiteral) {
		return nil, fmt.Errorf(
			"homchain: A2B refresh bootstrap DFT metadata differs from the sealed raw Scaling=1/1/16 plus MR15 initialization profile: source-stc=%+v sealed-stc=%+v source-cts=%+v sealed-cts=%+v",
			dftLiteralTrace(source.SlotsToCoeffsParameters), dftLiteralTrace(c.profile.dft.stcExecutionLiteral),
			dftLiteralTrace(source.CoeffsToSlotsParameters), dftLiteralTrace(c.profile.dft.ctsExecutionLiteral),
		)
	}
	if gap := 1 << (c.params.LogN() - source.CoeffsToSlotsParameters.LogSlots - 1); gap != 1 {
		return nil, fmt.Errorf("homchain: A2B refresh full-packing Trace gap=%d, want 1", gap)
	}
	minimumScaleDown := float64(c.params.Q()[0]) * math.Exp2(-1e-6)
	requestedModUpScale := source.Mod1Parameters.ScalingFactor().Float64() / source.Mod1Parameters.MessageRatio()
	if requestedModUpScale > minimumScaleDown {
		return nil, fmt.Errorf("homchain: A2B refresh ModUp scaling factor %.8g can exceed admitted ScaleDown raw scale %.8g", requestedModUpScale, minimumScaleDown)
	}
	bridgeProfile := A2AIKeyProfile{All: c.keyProfile.All()}
	if _, err := a2bRefreshPreflightKeySet(source, c, bridgeProfile); err != nil {
		return nil, err
	}
	sourceGraph, err := captureA2AIEvaluatorGraph(source, bridgeProfile)
	if err != nil {
		return nil, fmt.Errorf("homchain: capture A2B refresh source evaluator graph: %w", err)
	}
	sealed := sealA2AIBootstrapEvaluator(source, c.params)
	executionGraph, err := captureA2AIEvaluatorGraph(sealed, bridgeProfile)
	if err != nil {
		return nil, fmt.Errorf("homchain: capture A2B refresh sealed evaluator graph: %w", err)
	}
	circuitGraph, err := captureA2BRefreshCircuitGraph(c)
	if err != nil {
		return nil, err
	}
	return &A2BRefreshEvaluator{
		circuit: c, bootstrap: sealed, triangle: NewEvaluator(sealed.Evaluator),
		sourceGraph: sourceGraph, executionGraph: executionGraph, circuitGraph: circuitGraph,
	}, nil
}

func a2bRefreshLiteralEqual(left, right ckksdft.MatrixLiteral) bool {
	if !a2bRefreshLiteralStructureEqual(left, right) {
		return false
	}
	if left.Scaling == nil || right.Scaling == nil {
		return left.Scaling == nil && right.Scaling == nil
	}
	return left.Scaling.Cmp(right.Scaling) == 0 && left.Scaling.Prec() == right.Scaling.Prec()
}

func a2bRefreshLiteralStructureEqual(left, right ckksdft.MatrixLiteral) bool {
	return left.Type == right.Type && left.Format == right.Format && left.LogSlots == right.LogSlots &&
		left.LevelQ == right.LevelQ && left.LevelP == right.LevelP && left.LogBSGSRatio == right.LogBSGSRatio &&
		left.BitReversed == right.BitReversed && reflect.DeepEqual(left.Levels, right.Levels)
}

func a2bRefreshPreflightKeySet(source *bootstrapping.Evaluator, circuit *A2BRefreshCircuit, bridge A2AIKeyProfile) (A2BRefreshKeyPreflight, error) {
	result := A2BRefreshKeyPreflight{Checked: true, GraphChecked: true}
	if source == nil || source.Evaluator == nil || source.Evaluator.EvaluationKeySet == nil || source.EvaluationKeys == nil {
		return result, fmt.Errorf("homchain: A2B refresh evaluation-key graph is incomplete")
	}
	keys := source.Evaluator.EvaluationKeySet
	result.DenseNoSwitchingMatched = source.EvkDenseToSparse == nil && source.EvkSparseToDense == nil
	required := uniqueGaloisElements(bridge.All)
	provided := uniqueGaloisElements(keys.GetGaloisKeysList())
	requiredSet := make(map[uint64]bool, len(required))
	for _, element := range required {
		requiredSet[element] = true
	}
	for _, element := range provided {
		if !requiredSet[element] {
			result.UnexpectedGaloisElements = append(result.UnexpectedGaloisElements, element)
		}
	}
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
		len(result.UnexpectedGaloisElements) != 0 || !result.RelinearizationMatched || !result.DenseNoSwitchingMatched {
		return result, fmt.Errorf(
			"homchain: A2B refresh key preflight failed: missing-galois=%v invalid-galois=%v unexpected-galois=%v relin=%t relin-level=%t dense-no-switch=%t",
			result.MissingGaloisElements, result.InvalidGaloisElements, result.UnexpectedGaloisElements, result.RelinearizationPresent,
			result.RelinearizationMatched, result.DenseNoSwitchingMatched,
		)
	}
	result.GraphMatched = true
	return result, nil
}

func (e *A2BRefreshEvaluator) preflight() (A2BRefreshKeyPreflight, error) {
	result := A2BRefreshKeyPreflight{Checked: true, GraphChecked: true}
	if e == nil || e.circuit == nil || e.bootstrap == nil || e.triangle == nil {
		return result, fmt.Errorf("homchain: nil bound A2B refresh evaluator")
	}
	if err := e.circuitGraph.validate(); err != nil {
		result.GraphMismatch = "circuit graph: " + err.Error()
		return result, fmt.Errorf("homchain: A2B refresh graph preflight failed: %s", result.GraphMismatch)
	}
	if err := e.sourceGraph.validateTopology(); err != nil {
		result.GraphMismatch = "source evaluator graph: " + err.Error()
		return result, fmt.Errorf("homchain: A2B refresh graph preflight failed: %s", result.GraphMismatch)
	}
	if err := e.executionGraph.validateTopology(); err != nil {
		result.GraphMismatch = "sealed evaluator graph: " + err.Error()
		return result, fmt.Errorf("homchain: A2B refresh graph preflight failed: %s", result.GraphMismatch)
	}
	bridge := A2AIKeyProfile{All: e.circuit.keyProfile.All()}
	keyResult, err := a2bRefreshPreflightKeySet(e.bootstrap, e.circuit, bridge)
	result = keyResult
	if err != nil {
		return result, err
	}
	if err := e.sourceGraph.validateKeyIdentities(); err != nil {
		result.GraphMatched = false
		result.GraphMismatch = "source evaluator keys: " + err.Error()
		return result, fmt.Errorf("homchain: A2B refresh graph preflight failed: %s", result.GraphMismatch)
	}
	if err := e.executionGraph.validateKeyIdentities(); err != nil {
		result.GraphMatched = false
		result.GraphMismatch = "sealed evaluator keys: " + err.Error()
		return result, fmt.Errorf("homchain: A2B refresh graph preflight failed: %s", result.GraphMismatch)
	}
	result.GraphMatched = true
	return result, nil
}

func (c *A2BRefreshCircuit) validateInput(input *rlwe.Ciphertext) error {
	if c == nil {
		return fmt.Errorf("homchain: nil A2B refresh circuit")
	}
	if input == nil || input.MetaData == nil {
		return fmt.Errorf("homchain: A2B refresh input is nil or has nil metadata")
	}
	if input.Level() != c.profile.inputLevel || input.Degree() != 1 {
		return fmt.Errorf("homchain: A2B refresh input level/degree=%d/%d, want %d/1", input.Level(), input.Degree(), c.profile.inputLevel)
	}
	if !input.IsBatched || !input.IsNTT || input.LogDimensions != c.profile.transform.logDimensions || input.Slots() != c.profile.slots {
		return fmt.Errorf("homchain: A2B refresh input is not the fixed full-packed NTT ciphertext")
	}
	if !b2aExactScaleEqual(input.Scale, c.params.DefaultScale()) {
		return fmt.Errorf("homchain: A2B refresh input does not have the exact default Delta")
	}
	return nil
}

// EvaluateNew executes special-b0 Z2C, two separately charged masks, and two
// independent first-iteration refresh backbones. It stops at normalized CTS
// real outputs y=(I+a)/16, where a is the selected special-b0 raw value and I is
// the integral ScaleDown/ModUp lift. Exp46 followed by the two source squares
// cancels I periodically. The q20 transform scale and MessageRatio=2^15 keep
// every pre-refresh state and the returned L17 CTS ciphertext at exact S35, so
// the result satisfies the isolated Gao kernel's exact ingress without another
// charged level. This slice does not implement exp46, LUTs, or residual peeling
// and does not certify a deterministic direct u/16 value.
func (e *A2BRefreshEvaluator) EvaluateNew(input *rlwe.Ciphertext) (A2BRefreshResult, A2BRefreshTrace, error) {
	trace := A2BRefreshTrace{}
	if e == nil || e.circuit == nil {
		return A2BRefreshResult{}, trace, fmt.Errorf("homchain: nil bound A2B refresh evaluator")
	}
	trace.fidelity = e.circuit.profile.fidelity
	trace.schedule = e.circuit.profile.schedule
	trace.profileDigest = e.circuit.profile.digest
	if err := e.circuit.validateInput(input); err != nil {
		return A2BRefreshResult{}, trace, err
	}
	preflight, err := e.preflight()
	trace.keyPreflight = preflight
	if err != nil {
		return A2BRefreshResult{}, trace, err
	}
	inputState, err := snapshotA2BRefreshState(A2BRefreshWholeInput, A2BRefreshStageInput, input)
	if err != nil {
		return A2BRefreshResult{}, trace, err
	}
	trace.states = append(trace.states, inputState)

	// No ciphertext copy or operation occurs before the key/graph preflight.
	inputBefore := input.CopyNew()
	working := input.CopyNew()
	halves, err := e.triangle.ZToCNew(working, e.circuit.specialB0)
	if err != nil {
		return A2BRefreshResult{}, trace, fmt.Errorf("homchain: A2B refresh special-b0 Z-To-C: %w", err)
	}
	if err = validateCiphertextPairState("A2B refresh special-b0", halves); err != nil {
		return A2BRefreshResult{}, trace, err
	}
	expectedSpecialLevel := e.circuit.profile.inputLevel - e.circuit.params.LevelsConsumedPerRescaling()
	transformScale, err := e.circuit.profile.transform.scale.Scale()
	if err != nil {
		return A2BRefreshResult{}, trace, fmt.Errorf("homchain: A2B refresh recover sealed transform scale: %w", err)
	}
	expectedSpecialScale := input.Scale.Mul(transformScale).Div(rlwe.NewScale(e.circuit.params.Q()[e.circuit.profile.inputLevel]))
	if halves[0].Level() != expectedSpecialLevel || halves[1].Level() != expectedSpecialLevel ||
		!b2aExactScaleEqual(halves[0].Scale, expectedSpecialScale) || !b2aExactScaleEqual(halves[1].Scale, expectedSpecialScale) ||
		!b2aExactScaleEqual(expectedSpecialScale, e.circuit.params.DefaultScale()) {
		return A2BRefreshResult{}, trace, fmt.Errorf("homchain: A2B refresh special-b0 level/scale invariant failed")
	}
	specialLow, specialHigh := halves[0].CopyNew(), halves[1].CopyNew()
	for index, half := range []A2BRefreshHalf{A2BRefreshLowHalf, A2BRefreshHighHalf} {
		state, err := snapshotA2BRefreshState(half, A2BRefreshStageSpecialB0, halves[index])
		if err != nil {
			return A2BRefreshResult{}, trace, err
		}
		trace.states = append(trace.states, state)
	}

	maskedLow, err := e.applyMask(halves[0], e.circuit.lowMask, A2BRefreshLowHalf)
	if err != nil {
		return A2BRefreshResult{}, trace, err
	}
	maskedHigh, err := e.applyMask(halves[1], e.circuit.highMask, A2BRefreshHighHalf)
	if err != nil {
		return A2BRefreshResult{}, trace, err
	}
	if !halves[0].Equal(specialLow) || !halves[1].Equal(specialHigh) {
		return A2BRefreshResult{}, trace, fmt.Errorf("homchain: A2B refresh mask gate mutated a saved special-b0 core")
	}
	maskedLowSaved, maskedHighSaved := maskedLow.CopyNew(), maskedHigh.CopyNew()
	for index, item := range []*rlwe.Ciphertext{maskedLow, maskedHigh} {
		half := []A2BRefreshHalf{A2BRefreshLowHalf, A2BRefreshHighHalf}[index]
		state, err := snapshotA2BRefreshState(half, A2BRefreshStageMaskRescale, item)
		if err != nil {
			return A2BRefreshResult{}, trace, err
		}
		trace.states = append(trace.states, state)
	}

	lowOutput, lowStates, lowErrScale, lowErrLog2, err := e.refreshHalf(maskedLow, A2BRefreshLowHalf)
	if err != nil {
		return A2BRefreshResult{}, trace, err
	}
	trace.states = append(trace.states, lowStates...)
	highOutput, highStates, highErrScale, highErrLog2, err := e.refreshHalf(maskedHigh, A2BRefreshHighHalf)
	if err != nil {
		return A2BRefreshResult{}, trace, err
	}
	trace.states = append(trace.states, highStates...)
	trace.lowErrScale, trace.lowErrLog2 = lowErrScale, lowErrLog2
	trace.highErrScale, trace.highErrLog2 = highErrScale, highErrLog2
	if lowOutput == highOutput {
		return A2BRefreshResult{}, trace, fmt.Errorf("homchain: A2B refresh invocations shared an output ciphertext")
	}
	if !maskedLow.Equal(maskedLowSaved) || !maskedHigh.Equal(maskedHighSaved) ||
		!halves[0].Equal(specialLow) || !halves[1].Equal(specialHigh) {
		return A2BRefreshResult{}, trace, fmt.Errorf("homchain: A2B refresh mutated a saved ingress or masked core")
	}
	if !input.Equal(inputBefore) {
		return A2BRefreshResult{}, trace, fmt.Errorf("homchain: A2B refresh mutated its arithmetic input")
	}
	return A2BRefreshResult{
		specialLow: specialLow, specialHigh: specialHigh,
		maskedLow: maskedLowSaved, maskedHigh: maskedHighSaved,
		refreshedLow: lowOutput, refreshedHigh: highOutput,
	}, trace, nil
}

func (e *A2BRefreshEvaluator) applyMask(input *rlwe.Ciphertext, mask *rlwe.Plaintext, half A2BRefreshHalf) (*rlwe.Ciphertext, error) {
	masked, err := e.bootstrap.Evaluator.MulNew(input, mask)
	if err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh %s chunk-mask multiply: %w", half, err)
	}
	if err = e.bootstrap.Evaluator.Rescale(masked, masked); err != nil {
		return nil, fmt.Errorf("homchain: A2B refresh %s chunk-mask rescale: %w", half, err)
	}
	if masked.Level() != e.circuit.profile.maskOutputLevel || !b2aExactScaleEqual(masked.Scale, input.Scale) || masked.Degree() != 1 {
		return nil, fmt.Errorf("homchain: A2B refresh %s chunk-mask level/scale invariant failed", half)
	}
	return masked, nil
}

func (e *A2BRefreshEvaluator) refreshHalf(input *rlwe.Ciphertext, half A2BRefreshHalf) (*rlwe.Ciphertext, []A2BRefreshCiphertextState, ExactScaleSnapshot, float64, error) {
	return e.refreshHalfWithSTC(input, half, e.circuit.stc, e.circuit.profile.maskOutputLevel, 16)
}

func (e *A2BRefreshEvaluator) refreshHalfWithSTC(
	input *rlwe.Ciphertext,
	half A2BRefreshHalf,
	stcMatrix ckksdft.Matrix,
	expectedInputLevel, expectedSTCLevel int,
) (*rlwe.Ciphertext, []A2BRefreshCiphertextState, ExactScaleSnapshot, float64, error) {
	states := make([]A2BRefreshCiphertextState, 0, 4)
	if input == nil || input.MetaData == nil || input.Level() != expectedInputLevel || input.Degree() != 1 ||
		!b2aExactScaleEqual(input.Scale, e.circuit.params.DefaultScale()) || stcMatrix.LevelQ != expectedInputLevel {
		return nil, states, ExactScaleSnapshot{}, 0, fmt.Errorf(
			"homchain: A2B refresh %s STC ingress/matrix level or scale differs from sealed L%d/S35",
			half, expectedInputLevel,
		)
	}
	stc, err := e.bootstrap.DFTEvaluator.SlotsToCoeffsNew(input, nil, stcMatrix)
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B refresh %s Slots-To-Coeffs: %w", half, err)
	}
	if stc.Level() != expectedSTCLevel || !b2aExactScaleEqual(stc.Scale, input.Scale) {
		return nil, states, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B refresh %s Slots-To-Coeffs level/scale invariant failed", half)
	}
	state, err := snapshotA2BRefreshState(half, A2BRefreshStageSlotsToCoeffs, stc)
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, 0, err
	}
	states = append(states, state)
	stcSaved := stc.CopyNew()
	scaledDown, errScale, err := e.bootstrap.ScaleDown(stc.CopyNew())
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B refresh %s guarded ScaleDown: %w", half, err)
	}
	if errScale == nil {
		return nil, states, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B refresh %s ScaleDown returned nil errScale", half)
	}
	if !stc.Equal(stcSaved) {
		return nil, states, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B refresh %s ScaleDown mutated its saved STC core", half)
	}
	errLog2 := errScale.Log2()
	if math.IsNaN(errLog2) || math.IsInf(errLog2, 0) || math.Abs(errLog2) > 1e-6 {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s ScaleDown |log2(errScale)|=%g exceeds 1e-6", half, math.Abs(errLog2))
	}
	errSnapshot, err := NewExactScaleSnapshot(*errScale)
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s snapshot ScaleDown error: %w", half, err)
	}
	if scaledDown.Level() != 0 {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s ScaleDown level=%d, want 0", half, scaledDown.Level())
	}
	targetScale := rlwe.NewScale(e.circuit.params.Q()[0]).Div(rlwe.NewScale(e.bootstrap.Mod1Parameters.MessageRatio()))
	if !scaledDown.Scale.Div(targetScale).Equal(*errScale) {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s ScaleDown raw scale is not (q0/MessageRatio)*errScale", half)
	}
	if !b2aExactScaleEqual(scaledDown.Scale, e.circuit.params.DefaultScale()) {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s ScaleDown scale does not equal the Gao kernel S35 ingress", half)
	}
	state, err = snapshotA2BRefreshState(half, A2BRefreshStageScaleDown, scaledDown)
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, errLog2, err
	}
	states = append(states, state)
	scaleBeforeModUp, err := NewExactScaleSnapshot(scaledDown.Scale)
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, errLog2, err
	}
	requestedScale := e.bootstrap.Mod1Parameters.ScalingFactor().Float64() / e.bootstrap.Mod1Parameters.MessageRatio()
	if requestedScale/scaledDown.Scale.Float64() > 1 {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s ModUp would relabel raw scale", half)
	}
	raised, err := e.bootstrap.ModUp(scaledDown)
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s ModUp/Trace: %w", half, err)
	}
	if raised.Level() != e.circuit.params.MaxLevel() || !scaleBeforeModUp.EqualScale(raised.Scale) ||
		!b2aExactScaleEqual(raised.Scale, e.circuit.params.DefaultScale()) {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s ModUp level/scale invariant failed", half)
	}
	state, err = snapshotA2BRefreshState(half, A2BRefreshStageModUpTrace, raised)
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, errLog2, err
	}
	states = append(states, state)
	realOutput, imaginaryOutput, err := e.bootstrap.DFTEvaluator.CoeffsToSlotsNew(raised, e.circuit.cts)
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s Coeffs-To-Slots: %w", half, err)
	}
	if imaginaryOutput == nil || imaginaryOutput == realOutput {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s full-packed CTS did not produce a distinct discarded imaginary output", half)
	}
	if realOutput.Level() != 17 || !scaleBeforeModUp.EqualScale(realOutput.Scale) ||
		!b2aExactScaleEqual(realOutput.Scale, e.circuit.params.DefaultScale()) || realOutput.Degree() != 1 {
		return nil, states, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B refresh %s Coeffs-To-Slots real level/scale invariant failed", half)
	}
	state, err = snapshotA2BRefreshState(half, A2BRefreshStageCoeffsToSlots, realOutput)
	if err != nil {
		return nil, states, ExactScaleSnapshot{}, errLog2, err
	}
	states = append(states, state)
	return realOutput, states, errSnapshot, errLog2, nil
}

func snapshotA2BRefreshState(half A2BRefreshHalf, stage A2BRefreshStage, ciphertext *rlwe.Ciphertext) (A2BRefreshCiphertextState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return A2BRefreshCiphertextState{}, fmt.Errorf("homchain: cannot snapshot nil A2B refresh %s/%s ciphertext", half, stage)
	}
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return A2BRefreshCiphertextState{}, fmt.Errorf("homchain: snapshot A2B refresh %s/%s scale: %w", half, stage, err)
	}
	return A2BRefreshCiphertextState{
		Half: half, Invocation: half, Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale,
	}, nil
}

func validateA2BRefreshParameters(params ckks.Parameters) error {
	canonical, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		return fmt.Errorf("homchain: construct canonical Gao A2B parameters: %w", err)
	}
	if !params.Equal(&canonical) || params.LogN() != 5 || params.RingType() != ring.Standard ||
		params.MaxSlots() != 16 || params.MaxLevel() != 20 || params.MaxLevelP() != 0 ||
		params.LevelsConsumedPerRescaling() != 1 || params.LogDefaultScale() != 35 {
		return fmt.Errorf("homchain: A2B refresh requires the exact canonical Gao LogN=5, LogQ=[50,35x20], LogP=[50], S35 parameters")
	}
	return nil
}

// a2bRefreshDFTLiterals takes the actual STC ingress explicitly so the future
// serial iter1 circuit cannot accidentally inherit this slice's LevelQ=18.
func a2bRefreshDFTLiterals(params ckks.Parameters, precision uint, stcLevelQ, ctsLevelQ int) (ckksdft.MatrixLiteral, ckksdft.MatrixLiteral) {
	one := new(big.Float).SetPrec(precision).SetInt64(1)
	oneSixteenth := new(big.Float).SetPrec(precision).SetInt64(1)
	oneSixteenth.SetMantExp(oneSixteenth, -4)
	stc := ckksdft.MatrixLiteral{
		Type: ckksdft.HomomorphicDecode, Format: ckksdft.SplitRealAndImag,
		LogSlots: params.LogMaxSlots(), LevelQ: stcLevelQ, LevelP: params.MaxLevelP(),
		Levels: []int{1, 1}, Scaling: one, LogBSGSRatio: 0,
	}
	cts := ckksdft.MatrixLiteral{
		Type: ckksdft.HomomorphicEncode, Format: ckksdft.SplitRealAndImag,
		LogSlots: params.LogMaxSlots(), LevelQ: ctsLevelQ, LevelP: params.MaxLevelP(),
		Levels: []int{1, 1, 1}, Scaling: oneSixteenth, LogBSGSRatio: 0,
	}
	return stc, cts
}

func a2bRefreshDFTInitializationFactors(params ckks.Parameters) (stc, cts float64, err error) {
	parameters, err := mod1.NewParametersFromLiteral(params, mod1.ParametersLiteral{
		LevelQ:          params.MaxLevel() - 3,
		LogScale:        params.LogDefaultScale(),
		Mod1Type:        mod1.SinContinuous,
		LogMessageRatio: a2bRefreshLogMessageRatio,
		K:               1,
		Mod1Degree:      3,
	})
	if err != nil {
		return 0, 0, fmt.Errorf("homchain: construct sealed A2B refresh Mod1 initialization parameters: %w", err)
	}
	qDiv := parameters.ScalingFactor().Float64() /
		math.Exp2(math.Round(math.Log2(float64(params.Q()[0]))))
	if qDiv > 1 {
		qDiv = 1
	}
	offset := parameters.ScalingFactor().Float64() / parameters.MessageRatio()
	return params.DefaultScale().Float64() / offset, qDiv / (parameters.K * parameters.QDiff), nil
}

func scaleA2BRefreshDFTLiteral(raw ckksdft.MatrixLiteral, factor float64, precision uint) ckksdft.MatrixLiteral {
	result := cloneDFTLiteral(raw)
	result.Scaling.Mul(result.Scaling, new(big.Float).SetPrec(precision).SetFloat64(factor))
	return result
}

func newA2BRefreshMask(params ckks.Parameters, encoder *ckks.Encoder, level int, scale rlwe.Scale) (*rlwe.Plaintext, error) {
	mask := make([]*big.Float, params.MaxSlots())
	for i := range mask {
		mask[i] = new(big.Float).SetPrec(encoder.Prec()).SetInt64(1)
	}
	plaintext := ckks.NewPlaintext(params, level)
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: params.LogMaxSlots()}
	plaintext.Scale = scale
	if err := encoder.Encode(mask, plaintext); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func newA2BRefreshKeyProfile(params ckks.Parameters, specialB0 CompiledPair, stc, cts ckksdft.MatrixLiteral) A2BRefreshKeyProfile {
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
	profile := A2BRefreshKeyProfile{
		specialB0:     filter(specialB0.GaloisElements(params)),
		slotsToCoeffs: filter(stc.GaloisElements(params)),
		trace:         filter(params.GaloisElementsForTrace(params.LogMaxSlots())),
		coeffsToSlots: filter(cts.GaloisElements(params)),
		conjugation:   filter([]uint64{params.GaloisElementForComplexConjugation()}),
		residual:      []uint64{}, relinearization: true,
	}
	profile.all = filter(append(append(append(append(
		append([]uint64(nil), profile.specialB0...), profile.slotsToCoeffs...), profile.trace...),
		profile.coeffsToSlots...), profile.conjugation...))
	profile.digest = digestString(fmt.Sprintf(
		"a2b-refresh-keys-v1|special-b0=%v|stc=%v|trace=%v|cts=%v|conjugation=%v|residual=%v|relinearization=%t|switching=dense_no_switch",
		profile.specialB0, profile.slotsToCoeffs, profile.trace, profile.coeffsToSlots,
		profile.conjugation, profile.residual, profile.relinearization,
	))
	return profile
}

func digestA2BRefreshTransformSource(pair PairSpec) string {
	var canonical strings.Builder
	canonical.WriteString("a2b-refresh-special-b0-source-v1")
	for _, spec := range []TransformSpec{pair.Low, pair.High} {
		fmt.Fprintf(&canonical, "|name=%s|layout=%s|words=%d|half=%d|dimensions=%d,%d|matrix=", spec.Name(), spec.Layout(), spec.Words(), spec.HalfWidth(), spec.LogDimensions().Rows, spec.LogDimensions().Cols)
		for _, row := range spec.Matrix() {
			for _, value := range row {
				fmt.Fprintf(&canonical, "%s@%d/%d,%s@%d/%d;", value.Real().Text('x', -1), value.Real().Prec(), value.Real().Mode(), value.Imag().Text('x', -1), value.Imag().Prec(), value.Imag().Mode())
			}
		}
	}
	return digestString(canonical.String())
}

func digestA2BRefreshProfile(profile A2BRefreshProfile, keys A2BRefreshKeyProfile) string {
	canonical := fmt.Sprintf(
		"a2b-refresh-profile-v3|fidelity=%s|schedule=%s|word-bits=%d|chunk-width=%d|words=%d|slots=%d|input-level=%d|level-p=%d|precision=%d|names=%v|transform=%s,%s@Q%d/P%d/scale={%s}/dims=%d,%d/rot=%v/gal=%v|dft=%s|mask-level=%d|mask-output=%d|mask-scale={%s}|transform-source=%s|mask-source=%s|params=%s|log-message-ratio=%d|normalized-certified=%t|normalized-variable=%s|normalized-invariant=%s|normalized-blocker=%s|keys=%s",
		profile.fidelity, profile.schedule, profile.wordBits, profile.chunkWidth, profile.words, profile.slots,
		profile.inputLevel, profile.levelP, profile.encoderPrecision, profile.transformNames,
		profile.transform.lowName, profile.transform.highName, profile.transform.levelQ, profile.transform.levelP,
		profile.transform.scale.canonicalString(), profile.transform.logDimensions.Rows, profile.transform.logDimensions.Cols,
		profile.transform.rotationIndexes, profile.transform.galoisElements, profile.dft.digest,
		profile.maskLevel, profile.maskOutputLevel, profile.maskScale.canonicalString(), profile.transformSourceDigest,
		profile.maskSourceDigest, profile.parametersDigest, profile.logMessageRatio, profile.normalizedCertified,
		profile.normalizedVariable, profile.normalizedInvariant, profile.normalizedBlocker, keys.digest,
	)
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}
