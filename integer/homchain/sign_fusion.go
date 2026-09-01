package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	ckkslintrans "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	commonlintrans "github.com/tuneinsight/lattigo/v6/circuits/common/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	signFusionInputLevel       = 5
	signFusionOutputLevel      = 4
	signFusionWords            = 4
	signFusionSlots            = 16
	signFusionEncoderPrecision = uint(256)
)

// SignFusionClaim is the deliberately narrow semantic claim carried by this
// operator. It is neither a complete signed comparator nor a tree evaluator.
type SignFusionClaim string

const (
	SignFusionDirectRankOneMSBToArithmeticOnly SignFusionClaim = "direct_rank_one_msb_to_arithmetic_fusion_only"
)

// SignFusionFidelity identifies the local Lattigo optimization boundary.
type SignFusionFidelity string

const (
	SignFusionLattigoTreeFusion SignFusionFidelity = "lattigo_tree_fusion"
)

// SignFusionMaturity records the security maturity of the fixed tiny profile.
type SignFusionMaturity string

const (
	SignFusionFunctionalNotSecure SignFusionMaturity = "functional_not_secure"
)

// SignFusionBooleanHalfRole identifies which breaking-into-halves ciphertext
// a caller presents. Only the high half is meaningful for sign extraction.
type SignFusionBooleanHalfRole string

const (
	SignFusionHighBooleanHalf SignFusionBooleanHalfRole = "high"
	SignFusionLowBooleanHalf  SignFusionBooleanHalfRole = "low"
)

// SignFusionBitOrder fixes the within-half Boolean coefficient order.
type SignFusionBitOrder string

const (
	SignFusionLSBFirst SignFusionBitOrder = "lsb_first"
	SignFusionMSBFirst SignFusionBitOrder = "msb_first"
)

// SignFusionOutputEncoding names the arithmetic representation returned by
// the fusion. The output is the arithmetic word b7, not the branch 1-b7.
type SignFusionOutputEncoding string

const (
	SignFusionArithmeticRootSlots SignFusionOutputEncoding = "arithmetic_root_slots"
)

const (
	signFusionTransformName       TransformName = "M-sign-U0-fused-tInv-col0-from-high-col3"
	signFusionProfileDigestSchema               = "sign-fusion-profile-v1"
	signFusionSourceColumn                      = 0
	signFusionInputColumn                       = 3
)

// SignFusionStage identifies one ciphertext boundary of the single-LT graph.
type SignFusionStage string

const (
	SignFusionStageHighBooleanInput SignFusionStage = "high-boolean-half-input"
	SignFusionStageRankOneLinear    SignFusionStage = "rank-one-M-sign-linear-transform"
	SignFusionStageArithmeticSign   SignFusionStage = "arithmetic-sign-word-output"
)

// SignFusionCiphertextState is a detached exact state snapshot.
type SignFusionCiphertextState struct {
	Stage         SignFusionStage
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

// SignFusionOperationCounts records the fixed native graph. Counts describe
// the sealed four-diagonal BSGS implementation selected by the compiler.
type SignFusionOperationCounts struct {
	LinearTransformations              int
	Rotations                          int
	CiphertextPlaintextMultiplications int
	Additions                          int
	Rescales                           int
	KeySwitches                        int
	// LogicalPeakLiveCiphertexts counts the input and detached output at the
	// public graph boundary. It is not a measurement of Lattigo's private
	// linear-transform scratch buffers.
	LogicalPeakLiveCiphertexts int
}

// SignFusionProfile is the immutable public description of the fixed direct
// fusion. It carries an output range declaration, not a range-proof
// certificate.
type SignFusionProfile struct {
	claim            SignFusionClaim
	fidelity         SignFusionFidelity
	maturity         SignFusionMaturity
	wordBits         z2n.WordBits
	words            int
	slots            int
	encoderPrecision uint
	inputHalfRole    SignFusionBooleanHalfRole
	inputBitOrder    SignFusionBitOrder
	outputEncoding   SignFusionOutputEncoding
	outputMinimum    uint64
	outputMaximum    uint64
	transformName    TransformName
	sourceBasis      TransformName
	sourceColumn     int
	inputColumn      int
	inputLevel       int
	outputLevel      int
	logDimensions    ring.Dimensions
	inputScale       ExactScaleSnapshot
	matrixScale      ExactScaleSnapshot
	outputScale      ExactScaleSnapshot
	logBSGSRatio     int
	babyStepSize     int
	rotationIndexes  []int
	galoisElements   []uint64
	operationCounts  SignFusionOperationCounts
	parameterDigest  string
	sourceDigest     string
	compiledDigest   string
	digest           string
}

func (p SignFusionProfile) Claim() SignFusionClaim                   { return p.claim }
func (p SignFusionProfile) Fidelity() SignFusionFidelity             { return p.fidelity }
func (p SignFusionProfile) Maturity() SignFusionMaturity             { return p.maturity }
func (p SignFusionProfile) WordBits() z2n.WordBits                   { return p.wordBits }
func (p SignFusionProfile) Words() int                               { return p.words }
func (p SignFusionProfile) Slots() int                               { return p.slots }
func (p SignFusionProfile) EncoderPrecision() uint                   { return p.encoderPrecision }
func (p SignFusionProfile) InputHalfRole() SignFusionBooleanHalfRole { return p.inputHalfRole }
func (p SignFusionProfile) InputBitOrder() SignFusionBitOrder        { return p.inputBitOrder }
func (p SignFusionProfile) OutputEncoding() SignFusionOutputEncoding { return p.outputEncoding }
func (p SignFusionProfile) OutputMinimum() uint64                    { return p.outputMinimum }
func (p SignFusionProfile) OutputMaximum() uint64                    { return p.outputMaximum }
func (p SignFusionProfile) TransformName() TransformName             { return p.transformName }
func (p SignFusionProfile) SourceBasis() TransformName               { return p.sourceBasis }
func (p SignFusionProfile) SourceColumn() int                        { return p.sourceColumn }
func (p SignFusionProfile) InputColumn() int                         { return p.inputColumn }
func (p SignFusionProfile) InputLevel() int                          { return p.inputLevel }
func (p SignFusionProfile) OutputLevel() int                         { return p.outputLevel }
func (p SignFusionProfile) LogDimensions() ring.Dimensions           { return p.logDimensions }
func (p SignFusionProfile) InputScale() ExactScaleSnapshot           { return p.inputScale }
func (p SignFusionProfile) MatrixScale() ExactScaleSnapshot          { return p.matrixScale }
func (p SignFusionProfile) OutputScale() ExactScaleSnapshot          { return p.outputScale }
func (p SignFusionProfile) LogBabyStepGiantStepRatio() int           { return p.logBSGSRatio }
func (p SignFusionProfile) BabyStepSize() int                        { return p.babyStepSize }
func (p SignFusionProfile) RequiredRotationIndexes() []int {
	return append([]int(nil), p.rotationIndexes...)
}
func (p SignFusionProfile) RequiredGaloisElements() []uint64 {
	return append([]uint64(nil), p.galoisElements...)
}
func (p SignFusionProfile) RequiresRelinearization() bool { return false }
func (p SignFusionProfile) RequiresConjugation() bool     { return false }
func (p SignFusionProfile) OperationCounts() SignFusionOperationCounts {
	return p.operationCounts
}
func (p SignFusionProfile) ParameterDigest() string { return p.parameterDigest }
func (p SignFusionProfile) SourceDigest() string    { return p.sourceDigest }
func (p SignFusionProfile) CompiledDigest() string  { return p.compiledDigest }
func (p SignFusionProfile) Digest() string          { return p.digest }
func (p SignFusionProfile) DigestSchema() string    { return signFusionProfileDigestSchema }

// SignFusionCircuit owns the only accepted source and compiled transform.
type SignFusionCircuit struct {
	params    ckks.Parameters
	encoder   *ckks.Encoder
	source    TransformSpec
	transform ckkslintrans.LinearTransformation
	profile   SignFusionProfile
}

// NewSignFusionCircuit builds M_sign from column zero of U0-fused-tInv and
// places it at input column three of every four-slot high-half block.
func NewSignFusionCircuit(params ckks.Parameters, encoder *ckks.Encoder) (*SignFusionCircuit, error) {
	if err := validateSignFusionParameters(params); err != nil {
		return nil, err
	}
	if encoder == nil {
		return nil, fmt.Errorf("homchain: sign fusion encoder is nil")
	}
	encoderParameters := encoder.GetParameters()
	if !params.Equal(&encoderParameters) {
		return nil, fmt.Errorf("homchain: sign fusion encoder parameters do not match the circuit parameters")
	}
	if encoder.Prec() != signFusionEncoderPrecision {
		return nil, fmt.Errorf("homchain: sign fusion encoder precision=%d, want %d", encoder.Prec(), signFusionEncoderPrecision)
	}

	source, err := newSignFusionSource()
	if err != nil {
		return nil, err
	}
	matrixScale := rlwe.NewScale(params.Q()[signFusionInputLevel])
	options := CompileOptions{
		LevelQ: signFusionInputLevel, LevelP: params.MaxLevelP(), Scale: matrixScale,
		LogBabyStepGiantStepRatio: 0,
	}
	transformation, err := Compile(params, encoder, source, options)
	if err != nil {
		return nil, fmt.Errorf("homchain: compile direct sign-fusion transform: %w", err)
	}
	rotations := signFusionRotationIndexes(transformation)
	galoisElements := withoutIdentity(params, params.GaloisElements(rotations))
	if !equalInts(rotations, []int{1, 2}) || !equalUint64sExact(galoisElements, []uint64{5, 25}) {
		return nil, fmt.Errorf("homchain: sign fusion unexpected key schedule rotations=%v Galois=%v", rotations, galoisElements)
	}

	inputScale, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil, fmt.Errorf("homchain: snapshot sign-fusion input scale: %w", err)
	}
	matrixScaleSnapshot, err := NewExactScaleSnapshot(matrixScale)
	if err != nil {
		return nil, fmt.Errorf("homchain: snapshot sign-fusion matrix scale: %w", err)
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal sign-fusion parameters: %w", err)
	}
	profile := SignFusionProfile{
		claim:    SignFusionDirectRankOneMSBToArithmeticOnly,
		fidelity: SignFusionLattigoTreeFusion, maturity: SignFusionFunctionalNotSecure,
		wordBits: z2n.Word8, words: signFusionWords, slots: signFusionSlots,
		encoderPrecision: signFusionEncoderPrecision,
		inputHalfRole:    SignFusionHighBooleanHalf, inputBitOrder: SignFusionLSBFirst,
		outputEncoding: SignFusionArithmeticRootSlots, outputMinimum: 0, outputMaximum: 1,
		transformName: signFusionTransformName, sourceBasis: U0FusedTInv,
		sourceColumn: signFusionSourceColumn, inputColumn: signFusionInputColumn,
		inputLevel: signFusionInputLevel, outputLevel: signFusionOutputLevel,
		logDimensions: params.LogMaxDimensions(), inputScale: inputScale,
		matrixScale: matrixScaleSnapshot, outputScale: inputScale,
		logBSGSRatio: options.LogBabyStepGiantStepRatio, babyStepSize: transformation.N1,
		rotationIndexes: rotations, galoisElements: galoisElements,
		operationCounts: SignFusionOperationCounts{
			LinearTransformations: 1, Rotations: len(rotations),
			CiphertextPlaintextMultiplications: len(transformation.Vec),
			Additions:                          len(transformation.Vec) - 1, Rescales: 1,
			KeySwitches: len(rotations), LogicalPeakLiveCiphertexts: 2,
		},
		parameterDigest: signFusionDigestBytes(parameterBytes),
		sourceDigest:    digestSignFusionSource(source),
	}
	profile.compiledDigest, err = digestSignFusionCompiled(params, source, transformation, options, rotations, galoisElements)
	if err != nil {
		return nil, fmt.Errorf("homchain: digest sign-fusion compiled transform: %w", err)
	}
	profile.digest = digestSignFusionProfile(profile)
	circuit := &SignFusionCircuit{
		params: params, encoder: encoder.ShallowCopy(), source: source,
		transform: transformation, profile: profile,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func validateSignFusionParameters(params ckks.Parameters) error {
	canonical, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		return fmt.Errorf("homchain: construct canonical Gao parameters for sign fusion: %w", err)
	}
	if !params.Equal(&canonical) {
		return fmt.Errorf("homchain: sign fusion parameters are not the exact canonical Gao chain")
	}
	if params.LogN() != 5 || params.RingType() != ring.Standard || params.MaxSlots() != signFusionSlots ||
		params.MaxLevel() != 20 || params.MaxLevelP() != 0 || params.LevelsConsumedPerRescaling() != 1 ||
		params.LogDefaultScale() != 35 {
		return fmt.Errorf("homchain: sign fusion requires canonical standard LogN=5, L5/S35 Boolean ingress")
	}
	return nil
}

func newSignFusionSource() (TransformSpec, error) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		return TransformSpec{}, fmt.Errorf("homchain: construct sign-fusion Z2^8 ring: %w", err)
	}
	specifications, err := NewSpecificationsFromRing(ringZ, signFusionWords)
	if err != nil {
		return TransformSpec{}, fmt.Errorf("homchain: construct sign-fusion source specifications: %w", err)
	}
	u0 := specifications.UFusedTInvPair().Low
	if u0.Name() != U0FusedTInv || u0.Words() != signFusionWords || u0.HalfWidth() != 4 {
		return TransformSpec{}, fmt.Errorf("homchain: sign fusion source is not the four-word U0-fused-tInv profile")
	}
	u0Matrix := u0.Matrix()
	matrix := makeMatrix(4, 4, matrixPrecision(u0Matrix))
	for row := 0; row < 4; row++ {
		matrix[row][signFusionInputColumn] = u0Matrix[row][signFusionSourceColumn].Clone()
	}
	source, err := newTransformSpec(signFusionTransformName, matrix, signFusionWords)
	if err != nil {
		return TransformSpec{}, fmt.Errorf("homchain: construct rank-one sign-fusion source: %w", err)
	}
	return source, nil
}

func (c *SignFusionCircuit) Profile() SignFusionProfile {
	if c == nil {
		return SignFusionProfile{}
	}
	result := c.profile
	result.rotationIndexes = c.profile.RequiredRotationIndexes()
	result.galoisElements = c.profile.RequiredGaloisElements()
	return result
}

func (c *SignFusionCircuit) validate() error {
	if c == nil || c.encoder == nil {
		return fmt.Errorf("homchain: nil or incomplete sign-fusion circuit")
	}
	if err := validateSignFusionParameters(c.params); err != nil {
		return err
	}
	encoderParameters := c.encoder.GetParameters()
	if !c.params.Equal(&encoderParameters) || c.encoder.Prec() != signFusionEncoderPrecision {
		return fmt.Errorf("homchain: sign-fusion private encoder changed")
	}
	expectedSource, err := newSignFusionSource()
	if err != nil {
		return err
	}
	expectedSourceDigest := digestSignFusionSource(expectedSource)
	profile := c.profile
	if profile.claim != SignFusionDirectRankOneMSBToArithmeticOnly ||
		profile.fidelity != SignFusionLattigoTreeFusion || profile.maturity != SignFusionFunctionalNotSecure ||
		profile.wordBits != z2n.Word8 || profile.words != signFusionWords || profile.slots != signFusionSlots ||
		profile.encoderPrecision != signFusionEncoderPrecision ||
		profile.inputHalfRole != SignFusionHighBooleanHalf || profile.inputBitOrder != SignFusionLSBFirst ||
		profile.outputEncoding != SignFusionArithmeticRootSlots || profile.outputMinimum != 0 || profile.outputMaximum != 1 ||
		profile.transformName != signFusionTransformName || profile.sourceBasis != U0FusedTInv ||
		profile.sourceColumn != signFusionSourceColumn || profile.inputColumn != signFusionInputColumn ||
		profile.inputLevel != signFusionInputLevel || profile.outputLevel != signFusionOutputLevel ||
		profile.logDimensions != c.params.LogMaxDimensions() || profile.inputScale.HasMod() ||
		!profile.inputScale.EqualScale(c.params.DefaultScale()) || !profile.outputScale.Equal(profile.inputScale) ||
		!profile.matrixScale.EqualScale(rlwe.NewScale(c.params.Q()[signFusionInputLevel])) ||
		profile.logBSGSRatio != 0 || profile.babyStepSize != 2 ||
		!equalInts(profile.rotationIndexes, []int{1, 2}) ||
		!equalUint64sExact(profile.galoisElements, []uint64{5, 25}) ||
		profile.sourceDigest != expectedSourceDigest || digestSignFusionSource(c.source) != expectedSourceDigest {
		return fmt.Errorf("homchain: sign-fusion fixed source or profile contract changed")
	}
	parameterBytes, err := c.params.MarshalBinary()
	if err != nil {
		return fmt.Errorf("homchain: remarshal sign-fusion parameters: %w", err)
	}
	if profile.parameterDigest != signFusionDigestBytes(parameterBytes) {
		return fmt.Errorf("homchain: sign-fusion parameter digest changed")
	}
	rotations := signFusionRotationIndexes(c.transform)
	galoisElements := withoutIdentity(c.params, c.params.GaloisElements(rotations))
	if c.transform.N1 != profile.babyStepSize ||
		c.transform.LogBabyStepGiantStepRatio != profile.logBSGSRatio ||
		!equalInts(rotations, profile.rotationIndexes) || !equalUint64sExact(galoisElements, profile.galoisElements) {
		return fmt.Errorf("homchain: sign-fusion compiled key schedule changed")
	}
	matrixScale, err := profile.matrixScale.Scale()
	if err != nil {
		return fmt.Errorf("homchain: restore sign-fusion matrix scale: %w", err)
	}
	options := CompileOptions{
		LevelQ: profile.inputLevel, LevelP: c.params.MaxLevelP(), Scale: matrixScale,
		LogBabyStepGiantStepRatio: 0,
	}
	compiledDigest, err := digestSignFusionCompiled(c.params, c.source, c.transform, options, rotations, galoisElements)
	if err != nil {
		return fmt.Errorf("homchain: recompute sign-fusion compiled digest: %w", err)
	}
	if compiledDigest != profile.compiledDigest || profile.digest != digestSignFusionProfile(profile) {
		return fmt.Errorf("homchain: sign-fusion compiled or profile digest changed")
	}
	wantCounts := SignFusionOperationCounts{
		LinearTransformations: 1, Rotations: len(rotations),
		CiphertextPlaintextMultiplications: len(c.transform.Vec), Additions: len(c.transform.Vec) - 1,
		Rescales: 1, KeySwitches: len(rotations), LogicalPeakLiveCiphertexts: 2,
	}
	if profile.operationCounts != wantCounts {
		return fmt.Errorf("homchain: sign-fusion operation profile changed")
	}
	return nil
}

// SignFusionBooleanInput is a circuit-bound high-half handle.
type SignFusionBooleanInput struct {
	ciphertext *rlwe.Ciphertext
	role       SignFusionBooleanHalfRole
	bitOrder   SignFusionBitOrder
	digest     string
}

// BindBooleanHalf admits only the high, LSB-first Boolean half at exact L5/S35.
func (c *SignFusionCircuit) BindBooleanHalf(ciphertext *rlwe.Ciphertext, role SignFusionBooleanHalfRole, bitOrder SignFusionBitOrder) (SignFusionBooleanInput, error) {
	if err := c.validate(); err != nil {
		return SignFusionBooleanInput{}, err
	}
	if role != SignFusionHighBooleanHalf {
		return SignFusionBooleanInput{}, fmt.Errorf("homchain: sign fusion requires the A2B high Boolean half, got %q", role)
	}
	if bitOrder != SignFusionLSBFirst {
		return SignFusionBooleanInput{}, fmt.Errorf("homchain: sign fusion requires LSB-first bits within the high half, got %q", bitOrder)
	}
	if err := c.validateInputCiphertext(ciphertext); err != nil {
		return SignFusionBooleanInput{}, err
	}
	return SignFusionBooleanInput{ciphertext: ciphertext, role: role, bitOrder: bitOrder, digest: c.profile.digest}, nil
}

func (c *SignFusionCircuit) validateInputCiphertext(ciphertext *rlwe.Ciphertext) error {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return fmt.Errorf("homchain: sign-fusion Boolean input is nil or has nil metadata")
	}
	if ciphertext.Level() != c.profile.inputLevel || ciphertext.Degree() != 1 {
		return fmt.Errorf("homchain: sign-fusion input level=%d degree=%d, want level=%d degree=1", ciphertext.Level(), ciphertext.Degree(), c.profile.inputLevel)
	}
	if ciphertext.LogN() != c.params.LogN() || !ciphertext.IsBatched || !ciphertext.IsNTT ||
		ciphertext.LogDimensions != c.profile.logDimensions || ciphertext.Slots() != c.profile.slots {
		return fmt.Errorf("homchain: sign-fusion input is not a full-packed 16-slot NTT ciphertext")
	}
	if !c.profile.inputScale.EqualScale(ciphertext.Scale) {
		return fmt.Errorf("homchain: sign-fusion input does not have the exact L5/S35 profile scale")
	}
	return nil
}

// SignFusionEvaluator is a private, key-bound single-transform evaluator.
type SignFusionEvaluator struct {
	circuit    *SignFusionCircuit
	ckks       *ckks.Evaluator
	linear     *ckkslintrans.Evaluator
	keySet     *rlwe.MemEvaluationKeySet
	galoisKeys map[uint64]*rlwe.GaloisKey
}

func (c *SignFusionCircuit) BindEvaluator(evaluator *ckks.Evaluator) (*SignFusionEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if evaluator == nil {
		return nil, fmt.Errorf("homchain: sign-fusion evaluator is nil")
	}
	if evaluator.GetParameters() == nil || !c.params.Equal(evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: sign-fusion evaluator parameters do not match the profile")
	}
	keySet, ok := evaluator.EvaluationKeySet.(*rlwe.MemEvaluationKeySet)
	if !ok || keySet == nil {
		return nil, fmt.Errorf("homchain: sign fusion requires an in-memory evaluation key set")
	}
	keys, err := preflightSignFusionKeys(c.profile, keySet, nil)
	if err != nil {
		return nil, err
	}
	linear := ckkslintrans.NewEvaluator(evaluator)
	bound, ok := linear.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || bound != evaluator {
		return nil, fmt.Errorf("homchain: sign-fusion linear graph is not bound to the source evaluator")
	}
	return &SignFusionEvaluator{circuit: c, ckks: evaluator, linear: linear, keySet: keySet, galoisKeys: keys}, nil
}

// SignFusionProvenance is a detached execution record.
type SignFusionProvenance struct {
	profileDigest  string
	sourceDigest   string
	compiledDigest string
	states         []SignFusionCiphertextState
	counts         SignFusionOperationCounts
}

func (p SignFusionProvenance) ProfileDigest() string  { return p.profileDigest }
func (p SignFusionProvenance) SourceDigest() string   { return p.sourceDigest }
func (p SignFusionProvenance) CompiledDigest() string { return p.compiledDigest }
func (p SignFusionProvenance) States() []SignFusionCiphertextState {
	return append([]SignFusionCiphertextState(nil), p.states...)
}
func (p SignFusionProvenance) OperationCounts() SignFusionOperationCounts { return p.counts }

// SignFusionResult owns the arithmetic sign ciphertext and detached trace.
type SignFusionResult struct {
	ciphertext *rlwe.Ciphertext
	provenance SignFusionProvenance
}

func (r SignFusionResult) Ciphertext() *rlwe.Ciphertext {
	if r.ciphertext == nil {
		return nil
	}
	return r.ciphertext.CopyNew()
}
func (r SignFusionResult) Provenance() SignFusionProvenance { return r.provenance }

// EvaluateNew applies exactly one rank-one linear transform and one rescale.
func (e *SignFusionEvaluator) EvaluateNew(input SignFusionBooleanInput) (SignFusionResult, error) {
	if e == nil || e.circuit == nil || e.ckks == nil || e.linear == nil {
		return SignFusionResult{}, fmt.Errorf("homchain: nil bound sign-fusion evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		return SignFusionResult{}, err
	}
	if err := e.preflightGraphAndKeys(); err != nil {
		return SignFusionResult{}, err
	}
	if input.digest != e.circuit.profile.digest || input.role != SignFusionHighBooleanHalf || input.bitOrder != SignFusionLSBFirst {
		return SignFusionResult{}, fmt.Errorf("homchain: sign-fusion input belongs to a different role, order, or profile")
	}
	if err := e.circuit.validateInputCiphertext(input.ciphertext); err != nil {
		return SignFusionResult{}, err
	}
	inputBefore := input.ciphertext.CopyNew()
	states := make([]SignFusionCiphertextState, 0, 3)
	state, err := snapshotSignFusionState(SignFusionStageHighBooleanInput, input.ciphertext)
	if err != nil {
		return SignFusionResult{}, err
	}
	states = append(states, state)

	output, err := e.linear.EvaluateNew(input.ciphertext, e.circuit.transform)
	if err != nil {
		return SignFusionResult{}, fmt.Errorf("homchain: evaluate rank-one sign fusion: %w", err)
	}
	state, err = snapshotSignFusionState(SignFusionStageRankOneLinear, output)
	if err != nil {
		return SignFusionResult{}, err
	}
	states = append(states, state)
	matrixScale, err := e.circuit.profile.matrixScale.Scale()
	if err != nil {
		return SignFusionResult{}, err
	}
	expectedProduct := input.ciphertext.Scale.Mul(matrixScale)
	if output.Level() != e.circuit.profile.inputLevel || output.Degree() != 1 || output.LogN() != e.circuit.params.LogN() ||
		!output.IsBatched || !output.IsNTT || output.Slots() != e.circuit.profile.slots ||
		!signFusionExactScaleEqual(output.Scale, expectedProduct) || output.LogDimensions != e.circuit.profile.logDimensions {
		return SignFusionResult{}, fmt.Errorf("homchain: sign-fusion linear transform violated level, scale, degree, or dimensions")
	}
	if err = e.ckks.Rescale(output, output); err != nil {
		return SignFusionResult{}, fmt.Errorf("homchain: rescale sign-fusion output: %w", err)
	}
	state, err = snapshotSignFusionState(SignFusionStageArithmeticSign, output)
	if err != nil {
		return SignFusionResult{}, err
	}
	states = append(states, state)
	if output.Level() != e.circuit.profile.outputLevel || output.Degree() != 1 || output.LogN() != e.circuit.params.LogN() ||
		!output.IsBatched || !output.IsNTT || output.Slots() != e.circuit.profile.slots ||
		!e.circuit.profile.outputScale.EqualScale(output.Scale) || output.LogDimensions != e.circuit.profile.logDimensions {
		return SignFusionResult{}, fmt.Errorf("homchain: sign-fusion output is not exact L4/S35 full-slot arithmetic state")
	}
	if !input.ciphertext.Equal(inputBefore) {
		return SignFusionResult{}, fmt.Errorf("homchain: sign fusion mutated its Boolean input")
	}
	return SignFusionResult{
		ciphertext: output,
		provenance: SignFusionProvenance{
			profileDigest: e.circuit.profile.digest, sourceDigest: e.circuit.profile.sourceDigest,
			compiledDigest: e.circuit.profile.compiledDigest, states: states, counts: e.circuit.profile.operationCounts,
		},
	}, nil
}

func (e *SignFusionEvaluator) preflightGraphAndKeys() error {
	if e.ckks.EvaluationKeySet != e.keySet || e.keySet == nil {
		return fmt.Errorf("homchain: sign-fusion evaluation key-set identity changed before evaluation")
	}
	bound, ok := e.linear.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || bound != e.ckks {
		return fmt.Errorf("homchain: sign-fusion linear evaluator graph changed before evaluation")
	}
	_, err := preflightSignFusionKeys(e.circuit.profile, e.keySet, e.galoisKeys)
	return err
}

func preflightSignFusionKeys(profile SignFusionProfile, keySet *rlwe.MemEvaluationKeySet, expected map[uint64]*rlwe.GaloisKey) (map[uint64]*rlwe.GaloisKey, error) {
	if keySet == nil {
		return nil, fmt.Errorf("homchain: sign-fusion evaluation key set is nil")
	}
	keys := make(map[uint64]*rlwe.GaloisKey, len(profile.galoisElements))
	for _, element := range profile.galoisElements {
		key, err := keySet.GetGaloisKey(element)
		if err != nil || key == nil {
			return nil, fmt.Errorf("homchain: sign fusion missing required Galois key %d: %v", element, err)
		}
		if key.GaloisElement != element || key.LevelQ() < profile.inputLevel || key.LevelP() != 0 {
			return nil, fmt.Errorf("homchain: sign-fusion Galois key %d has the wrong element or levels", element)
		}
		if expected != nil && expected[element] != key {
			return nil, fmt.Errorf("homchain: sign-fusion Galois key %d identity changed before evaluation", element)
		}
		keys[element] = key
	}
	return keys, nil
}

func snapshotSignFusionState(stage SignFusionStage, ciphertext *rlwe.Ciphertext) (SignFusionCiphertextState, error) {
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return SignFusionCiphertextState{}, fmt.Errorf("homchain: snapshot sign-fusion %s scale: %w", stage, err)
	}
	return SignFusionCiphertextState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale,
	}, nil
}

func signFusionExactScaleEqual(left, right rlwe.Scale) bool {
	leftSnapshot, err := NewExactScaleSnapshot(left)
	if err != nil {
		return false
	}
	rightSnapshot, err := NewExactScaleSnapshot(right)
	return err == nil && leftSnapshot.Equal(rightSnapshot)
}

func signFusionRotationIndexes(transformation ckkslintrans.LinearTransformation) []int {
	rotations := make([]int, 0, len(transformation.Vec))
	if transformation.N1 == 0 {
		for index := range transformation.Vec {
			if index != 0 {
				rotations = append(rotations, index)
			}
		}
	} else {
		_, babySteps, giantSteps := commonlintrans.LinearTransformation(transformation).BSGSIndex()
		rotations = append(rotations, babySteps...)
		rotations = append(rotations, giantSteps...)
	}
	sort.Ints(rotations)
	result := rotations[:0]
	for _, rotation := range rotations {
		if rotation != 0 && (len(result) == 0 || result[len(result)-1] != rotation) {
			result = append(result, rotation)
		}
	}
	return append([]int(nil), result...)
}

func digestSignFusionSource(source TransformSpec) string {
	var canonical strings.Builder
	matrix := source.Matrix()
	fmt.Fprintf(&canonical, "sign-fusion-source-v1|name=%s|layout=%s|precision=%d|words=%d|half=%d|dimensions=%d,%d|matrix=",
		source.Name(), source.Layout(), source.precision, source.Words(), source.HalfWidth(), source.LogDimensions().Rows, source.LogDimensions().Cols)
	for rowIndex, row := range matrix {
		fmt.Fprintf(&canonical, "row=%d:", rowIndex)
		for columnIndex, value := range row {
			fmt.Fprintf(&canonical, "%d=%s@%d/%d,%s@%d/%d;", columnIndex,
				value.Real().Text('x', -1), value.Real().Prec(), value.Real().Mode(),
				value.Imag().Text('x', -1), value.Imag().Prec(), value.Imag().Mode())
		}
	}
	diagonals := source.Diagonals()
	indexes := diagonals.DiagonalsIndexList()
	sort.Ints(indexes)
	for _, index := range indexes {
		fmt.Fprintf(&canonical, "|diagonal=%d:", index)
		for slot, value := range diagonals[index] {
			fmt.Fprintf(&canonical, "%d=%s@%d/%d,%s@%d/%d;", slot,
				value.Real().Text('x', -1), value.Real().Prec(), value.Real().Mode(),
				value.Imag().Text('x', -1), value.Imag().Prec(), value.Imag().Mode())
		}
	}
	return signFusionDigestText(canonical.String())
}

func digestSignFusionCompiled(params ckks.Parameters, source TransformSpec, transformation ckkslintrans.LinearTransformation, options CompileOptions, rotations []int, galoisElements []uint64) (string, error) {
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return "", err
	}
	requestedScale, err := NewExactScaleSnapshot(options.Scale)
	if err != nil {
		return "", err
	}
	if transformation.MetaData == nil {
		return "", fmt.Errorf("compiled sign-fusion transform has nil metadata")
	}
	actualScale, err := NewExactScaleSnapshot(transformation.Scale)
	if err != nil {
		return "", err
	}
	indexes := make([]int, 0, len(transformation.Vec))
	for index := range transformation.Vec {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	var canonical strings.Builder
	fmt.Fprintf(&canonical,
		"sign-fusion-compiled-v1|source=%s|requested=Q%d/P%d/scale={%s}/bsgs=%d|actual=Q%d/P%d/scale={%s}/dimensions=%d,%d/n1=%d|rotations=%v|galois=%v|diagonals=%v|params=%x",
		digestSignFusionSource(source), options.LevelQ, options.LevelP, requestedScale.canonicalString(), options.LogBabyStepGiantStepRatio,
		transformation.LevelQ, transformation.LevelP, actualScale.canonicalString(), transformation.LogDimensions.Rows,
		transformation.LogDimensions.Cols, transformation.N1, rotations, galoisElements, indexes, parameterBytes)
	for _, index := range indexes {
		payload, marshalErr := transformation.Vec[index].MarshalBinary()
		if marshalErr != nil {
			return "", fmt.Errorf("marshal sign-fusion compiled diagonal %d: %w", index, marshalErr)
		}
		fmt.Fprintf(&canonical, "|diagonal=%d/payload=%s", index, signFusionDigestBytes(payload))
	}
	return signFusionDigestText(canonical.String()), nil
}

func digestSignFusionProfile(profile SignFusionProfile) string {
	var canonical strings.Builder
	fmt.Fprintf(&canonical,
		"%s|claim=%s|fidelity=%s|maturity=%s|word-bits=%d|words=%d|slots=%d|encoder-precision=%d|input-role=%s|bit-order=%s|output-encoding=%s|output-range=%d,%d|transform=%s|source-basis=%s/source-column=%d/input-column=%d|input=L%d/{%s}|matrix={%s}|output=L%d/{%s}|dimensions=%d,%d|bsgs-log-ratio=%d/n1=%d|rotations=%v|galois=%v|ops=%+v|params=%s|source=%s|compiled=%s",
		signFusionProfileDigestSchema, profile.claim, profile.fidelity, profile.maturity, profile.wordBits, profile.words, profile.slots,
		profile.encoderPrecision, profile.inputHalfRole, profile.inputBitOrder, profile.outputEncoding,
		profile.outputMinimum, profile.outputMaximum, profile.transformName, profile.sourceBasis,
		profile.sourceColumn, profile.inputColumn, profile.inputLevel, profile.inputScale.canonicalString(),
		profile.matrixScale.canonicalString(), profile.outputLevel, profile.outputScale.canonicalString(),
		profile.logDimensions.Rows, profile.logDimensions.Cols, profile.logBSGSRatio, profile.babyStepSize,
		profile.rotationIndexes, profile.galoisElements,
		profile.operationCounts, profile.parameterDigest, profile.sourceDigest, profile.compiledDigest)
	return signFusionDigestText(canonical.String())
}

func signFusionDigestText(value string) string { return signFusionDigestBytes([]byte(value)) }

func signFusionDigestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
