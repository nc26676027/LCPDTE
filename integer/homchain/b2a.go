package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	ckkslintrans "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// B2AFidelity identifies the implementation claim attached to a B2A result.
type B2AFidelity string

const (
	// B2ALattigoAdaptation means that Gao--Zheng's fused-tau-inverse C-To-Z
	// semantics are implemented with Lattigo's native linear-transform and
	// rescale state transitions. It is deliberately not an upstream raw-state
	// faithfulness claim.
	B2ALattigoAdaptation      B2AFidelity = "gao-b2a-lattigo-adaptation"
	b2aStandaloneDigestSchema             = "b2a-full-v2"
	b2aChainDigestSchema                  = "b2a-full-chain-v1"
	b2aChainInputLevel                    = 5
)

// B2AStage identifies an auditable ciphertext state in standalone B2A.
type B2AStage string

const (
	B2AStageInputLow   B2AStage = "boolean-low-input"
	B2AStageInputHigh  B2AStage = "boolean-high-input"
	B2AStageFusedLow   B2AStage = "fused-tau-inverse-u0"
	B2AStageFusedHigh  B2AStage = "fused-tau-inverse-u1"
	B2AStageRecombined B2AStage = "fused-halves-recombined"
	B2AStageRescaled   B2AStage = "lattigo-rescaled-output"
)

// B2ACiphertextState is a detached state snapshot at one B2A stage.
type B2ACiphertextState struct {
	Stage         B2AStage
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

// ScaleString returns the exact canonical scale representation used by the
// profile digest and audit errors.
func (s B2ACiphertextState) ScaleString() string { return s.Scale.canonicalString() }

// B2AProvenance is the immutable execution record returned with a B2A result.
type B2AProvenance struct {
	fidelity      B2AFidelity
	profileDigest string
	states        []B2ACiphertextState
}

func (p B2AProvenance) Fidelity() B2AFidelity { return p.fidelity }
func (p B2AProvenance) ProfileDigest() string { return p.profileDigest }
func (p B2AProvenance) States() []B2ACiphertextState {
	return append([]B2ACiphertextState(nil), p.states...)
}

// B2AFullProfile describes a fixed n=8 full-slot Lattigo B2A circuit. The
// standalone profile carries two words over eight slots; the A2B-chain
// profile carries four words over sixteen slots. All slice accessors return
// copies.
type B2AFullProfile struct {
	digestSchema           string
	fidelity               B2AFidelity
	wordBits               z2n.WordBits
	words                  int
	slots                  int
	levelQ                 int
	levelP                 int
	logDimensions          ring.Dimensions
	encoderPrecision       uint
	inputScale             ExactScaleSnapshot
	matrixScale            ExactScaleSnapshot
	rotationIndexes        []int
	requiredGaloisElements []uint64
	transformSourceDigest  string
	compiledPlanDigest     string
	digest                 string
}

func (p B2AFullProfile) DigestSchema() string            { return p.digestSchema }
func (p B2AFullProfile) Fidelity() B2AFidelity           { return p.fidelity }
func (p B2AFullProfile) WordBits() z2n.WordBits          { return p.wordBits }
func (p B2AFullProfile) Words() int                      { return p.words }
func (p B2AFullProfile) Slots() int                      { return p.slots }
func (p B2AFullProfile) LevelQ() int                     { return p.levelQ }
func (p B2AFullProfile) LevelP() int                     { return p.levelP }
func (p B2AFullProfile) LogDimensions() ring.Dimensions  { return p.logDimensions }
func (p B2AFullProfile) EncoderPrecision() uint          { return p.encoderPrecision }
func (p B2AFullProfile) InputScale() ExactScaleSnapshot  { return p.inputScale }
func (p B2AFullProfile) MatrixScale() ExactScaleSnapshot { return p.matrixScale }
func (p B2AFullProfile) RequiredRotationIndexes() []int {
	return append([]int(nil), p.rotationIndexes...)
}
func (p B2AFullProfile) RequiredGaloisElements() []uint64 {
	return append([]uint64(nil), p.requiredGaloisElements...)
}
func (p B2AFullProfile) RequiresRelinearization() bool { return false }
func (p B2AFullProfile) RequiresConjugation() bool     { return false }
func (p B2AFullProfile) TransformSourceDigest() string { return p.transformSourceDigest }
func (p B2AFullProfile) CompiledPlanDigest() string    { return p.compiledPlanDigest }
func (p B2AFullProfile) Digest() string                { return p.digest }

// B2AFullCircuit owns the only transform pair accepted by standalone B2A.
// The pair is compiled internally from UFusedTInvPair, so a caller cannot
// substitute the normal U transform.
type B2AFullCircuit struct {
	params  ckks.Parameters
	source  PairSpec
	pair    CompiledPair
	profile B2AFullProfile
}

// NewB2AFullCircuit constructs the fixed functional-not-secure LogN=4 slice.
// Its matrix scale is q1, which makes Lattigo's one-prime rescale preserve an
// input scale exactly. This state adapter differs from upstream's dynamic
// matrix-scale=input-scale convention and is covered by B2ALattigoAdaptation.
func NewB2AFullCircuit(params ckks.Parameters, encoder *ckks.Encoder) (*B2AFullCircuit, error) {
	if encoder == nil {
		return nil, fmt.Errorf("homchain: B2A nil encoder")
	}
	encoderParameters := encoder.GetParameters()
	if !params.Equal(&encoderParameters) {
		return nil, fmt.Errorf("homchain: B2A encoder parameters do not match the circuit parameters")
	}
	if encoder.Prec() != z2n.DefaultPrecision {
		return nil, fmt.Errorf(
			"homchain: B2A encoder precision=%d, want fixed profile precision=%d",
			encoder.Prec(), z2n.DefaultPrecision,
		)
	}
	if params.LogN() != 4 || params.RingType() != ring.Standard || params.MaxSlots() != 8 {
		return nil, fmt.Errorf("homchain: B2A requires standard LogN=4 with 8 full slots")
	}
	if params.MaxLevel() != 1 || params.MaxLevelP() != 0 {
		return nil, fmt.Errorf("homchain: B2A requires exactly two Q primes and one P prime")
	}
	if params.LevelsConsumedPerRescaling() != 1 {
		return nil, fmt.Errorf("homchain: B2A requires one level per rescale")
	}
	q, p := params.Q(), params.P()
	if len(q) != 2 || b2aRoundedLog2(q[0]) != 40 || b2aRoundedLog2(q[1]) != 30 || len(p) != 1 || b2aRoundedLog2(p[0]) != 40 || params.LogDefaultScale() != 30 {
		return nil, fmt.Errorf("homchain: B2A requires LogQ=[40,30], LogP=[40], LogDefaultScale=30; got Q=%v (%d,%d bits) P=%v scale=%d",
			q, b2aRoundedLog2(q[0]), b2aRoundedLog2(q[1]), p, params.LogDefaultScale())
	}

	const words = 2
	matrixScale := rlwe.NewScale(q[1])
	compileOptions := CompileOptions{
		LevelQ:                    1,
		LevelP:                    0,
		Scale:                     matrixScale,
		LogBabyStepGiantStepRatio: 0,
	}
	pairSpec, pair, rotations, galoisElements, err := compileB2AFusedTInv(params, encoder, words, compileOptions)
	if err != nil {
		return nil, fmt.Errorf("homchain: B2A build fused-tau-inverse U pair: %w", err)
	}
	if !equalInts(rotations, []int{1, 2, 4, 6}) || !equalUint64s(galoisElements, []uint64{5, 9, 17, 25}) {
		return nil, fmt.Errorf("homchain: B2A unexpected minimal key profile rotations=%v Galois=%v", rotations, galoisElements)
	}
	scaleSnapshot, err := NewExactScaleSnapshot(matrixScale)
	if err != nil {
		return nil, fmt.Errorf("homchain: B2A snapshot matrix scale: %w", err)
	}
	inputScaleSnapshot, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil, fmt.Errorf("homchain: B2A snapshot required input scale: %w", err)
	}
	if inputScaleSnapshot.HasMod() {
		return nil, fmt.Errorf("homchain: B2A fixed input scale must be non-modular")
	}
	profile := B2AFullProfile{
		digestSchema: b2aStandaloneDigestSchema,
		fidelity:     B2ALattigoAdaptation, wordBits: z2n.Word8, words: words, slots: params.MaxSlots(),
		levelQ: 1, levelP: 0, logDimensions: ring.Dimensions{Rows: 0, Cols: 3},
		encoderPrecision: encoder.Prec(), inputScale: inputScaleSnapshot, matrixScale: scaleSnapshot,
		rotationIndexes: rotations, requiredGaloisElements: galoisElements,
	}
	profile.digest, err = digestB2AProfile(params, profile)
	if err != nil {
		return nil, err
	}
	return &B2AFullCircuit{params: params, source: pairSpec, pair: pair, profile: profile}, nil
}

// NewB2AFullAtLevelCircuit constructs the full-packed n=8 fused-tau-inverse
// B2A adapter on the functional A2B parameter chain. Unlike
// NewB2AFullCircuit's isolated two-prime slice, this constructor binds the
// physical Boolean ingress level explicitly. The fused transform uses q_l as
// its plaintext scale, so its single rescale returns an arithmetic ciphertext
// at level l-1 with the exact default scale.
//
// This remains B2ALattigoAdaptation: it connects local operators without
// claiming Gao's sparse-secret switching or raw OpenFHE state transitions.
func NewB2AFullAtLevelCircuit(params ckks.Parameters, encoder *ckks.Encoder, inputLevel int) (*B2AFullCircuit, error) {
	if encoder == nil {
		return nil, fmt.Errorf("homchain: B2A-at-level nil encoder")
	}
	encoderParameters := encoder.GetParameters()
	if !params.Equal(&encoderParameters) {
		return nil, fmt.Errorf("homchain: B2A-at-level encoder parameters do not match the circuit parameters")
	}
	if encoder.Prec() != z2n.DefaultPrecision {
		return nil, fmt.Errorf(
			"homchain: B2A-at-level encoder precision=%d, want fixed profile precision=%d",
			encoder.Prec(), z2n.DefaultPrecision,
		)
	}
	if err := validateB2AChainParameters(params); err != nil {
		return nil, err
	}
	if inputLevel != b2aChainInputLevel {
		return nil, fmt.Errorf(
			"homchain: B2A-at-level ingress=%d, want the fixed A2B Boolean level %d",
			inputLevel, b2aChainInputLevel,
		)
	}

	const words = 4
	matrixScale := rlwe.NewScale(params.Q()[inputLevel])
	compileOptions := CompileOptions{
		LevelQ:                    inputLevel,
		LevelP:                    params.MaxLevelP(),
		Scale:                     matrixScale,
		LogBabyStepGiantStepRatio: 0,
	}
	pairSpec, pair, rotations, galoisElements, err := compileB2AFusedTInv(params, encoder, words, compileOptions)
	if err != nil {
		return nil, fmt.Errorf("homchain: B2A-at-level build fused-tau-inverse U pair: %w", err)
	}
	if !equalInts(rotations, []int{1, 2, 12, 14}) || !equalUint64s(galoisElements, []uint64{5, 17, 25, 41}) {
		return nil, fmt.Errorf("homchain: B2A-at-level unexpected minimal key profile rotations=%v Galois=%v", rotations, galoisElements)
	}
	matrixScaleSnapshot, err := NewExactScaleSnapshot(matrixScale)
	if err != nil {
		return nil, fmt.Errorf("homchain: B2A-at-level snapshot matrix scale: %w", err)
	}
	inputScaleSnapshot, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil, fmt.Errorf("homchain: B2A-at-level snapshot required input scale: %w", err)
	}
	if inputScaleSnapshot.HasMod() {
		return nil, fmt.Errorf("homchain: B2A-at-level fixed input scale must be non-modular")
	}
	profile := B2AFullProfile{
		digestSchema: b2aChainDigestSchema,
		fidelity:     B2ALattigoAdaptation, wordBits: z2n.Word8, words: words, slots: params.MaxSlots(),
		levelQ: inputLevel, levelP: params.MaxLevelP(), logDimensions: params.LogMaxDimensions(),
		encoderPrecision: encoder.Prec(), inputScale: inputScaleSnapshot, matrixScale: matrixScaleSnapshot,
		rotationIndexes: rotations, requiredGaloisElements: galoisElements,
	}
	profile.transformSourceDigest = digestB2ATransformSource(pairSpec)
	profile.compiledPlanDigest, err = digestB2ACompiledPlan(params, pairSpec, pair, compileOptions, rotations, galoisElements)
	if err != nil {
		return nil, fmt.Errorf("homchain: B2A-at-level digest compiled plan: %w", err)
	}
	profile.digest, err = digestB2AProfile(params, profile)
	if err != nil {
		return nil, err
	}
	return &B2AFullCircuit{params: params, source: pairSpec, pair: pair, profile: profile}, nil
}

// compileB2AFusedTInv is the single private construction path shared by the
// standalone and A2B-chain adapters. It admits no caller-supplied transform:
// both source matrices always come from the fixed Z/2^8Z specifications.
func compileB2AFusedTInv(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	words int,
	options CompileOptions,
) (PairSpec, CompiledPair, []int, []uint64, error) {
	source, err := newB2AFusedTInvSource(words)
	if err != nil {
		return PairSpec{}, CompiledPair{}, nil, nil, err
	}
	compiled, err := CompilePair(params, encoder, source, options)
	if err != nil {
		return PairSpec{}, CompiledPair{}, nil, nil, fmt.Errorf("compile fused-tau-inverse U pair: %w", err)
	}
	return source, compiled, compiled.RotationIndexes(), compiled.GaloisElements(params), nil
}

func newB2AFusedTInvSource(words int) (PairSpec, error) {
	ringZ, err := z2n.New(z2n.Word8)
	if err != nil {
		return PairSpec{}, fmt.Errorf("construct Z2^8 ring: %w", err)
	}
	specifications, err := NewSpecificationsFromRing(ringZ, words)
	if err != nil {
		return PairSpec{}, fmt.Errorf("construct transform specifications: %w", err)
	}
	source := specifications.UFusedTInvPair()
	if source.Low.Name() != U0FusedTInv || source.High.Name() != U1FusedTInv {
		return PairSpec{}, fmt.Errorf("internal transform is not the fused-tau-inverse U pair")
	}
	return source, nil
}

func validateB2AChainParameters(params ckks.Parameters) error {
	canonical, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		return fmt.Errorf("homchain: construct canonical A2B parameter chain: %w", err)
	}
	if !params.Equal(&canonical) {
		return fmt.Errorf("homchain: B2A-at-level parameters are not the exact canonical A2B parameter chain")
	}
	if params.LogN() != 5 || params.RingType() != ring.Standard || params.MaxSlots() != 16 {
		return fmt.Errorf("homchain: B2A-at-level requires standard LogN=5 with 16 full slots")
	}
	if params.MaxLevel() != 20 || params.MaxLevelP() != 0 {
		return fmt.Errorf("homchain: B2A-at-level requires 21 Q primes and one P prime")
	}
	if params.LevelsConsumedPerRescaling() != 1 {
		return fmt.Errorf("homchain: B2A-at-level requires one level per rescale")
	}
	q, p := params.Q(), params.P()
	if len(q) != 21 || len(p) != 1 || b2aRoundedLog2(q[0]) != 50 || b2aRoundedLog2(p[0]) != 50 || params.LogDefaultScale() != 35 {
		return fmt.Errorf("homchain: B2A-at-level requires LogQ=[50,35x20], LogP=[50], LogDefaultScale=35")
	}
	for level := 1; level < len(q); level++ {
		if b2aRoundedLog2(q[level]) != 35 {
			return fmt.Errorf("homchain: B2A-at-level Q[%d] has %d bits, want 35", level, b2aRoundedLog2(q[level]))
		}
	}
	return nil
}

func (c *B2AFullCircuit) Profile() B2AFullProfile {
	if c == nil {
		return B2AFullProfile{}
	}
	result := c.profile
	result.rotationIndexes = c.profile.RequiredRotationIndexes()
	result.requiredGaloisElements = c.profile.RequiredGaloisElements()
	return result
}

// validate authenticates the sealed transform graph. For the chain schema it
// rechecks the exact canonical parameter set and all three digest layers; the
// standalone branch deliberately keeps its v2 digest schema byte-for-byte.
func (c *B2AFullCircuit) validate() error {
	if c == nil {
		return fmt.Errorf("homchain: nil B2A circuit")
	}
	profile := c.profile
	if profile.fidelity != B2ALattigoAdaptation || profile.wordBits != z2n.Word8 ||
		profile.encoderPrecision != z2n.DefaultPrecision || profile.inputScale.HasMod() ||
		!profile.inputScale.EqualScale(c.params.DefaultScale()) {
		return fmt.Errorf("homchain: B2A fixed profile contract changed")
	}
	expectedSource, err := newB2AFusedTInvSource(profile.words)
	if err != nil {
		return fmt.Errorf("homchain: rebuild B2A fused-tau-inverse source: %w", err)
	}
	expectedSourceDigest := digestB2ATransformSource(expectedSource)
	if digestB2ATransformSource(c.source) != expectedSourceDigest {
		return fmt.Errorf("homchain: B2A fused-tau-inverse source matrix changed")
	}
	rotations := c.pair.RotationIndexes()
	galoisElements := c.pair.GaloisElements(c.params)

	switch profile.digestSchema {
	case b2aStandaloneDigestSchema:
		if profile.words != 2 || profile.slots != 8 || profile.levelQ != 1 || profile.levelP != 0 ||
			profile.logDimensions != (ring.Dimensions{Rows: 0, Cols: 3}) ||
			profile.transformSourceDigest != "" || profile.compiledPlanDigest != "" ||
			!equalInts(profile.rotationIndexes, []int{1, 2, 4, 6}) ||
			!equalUint64sExact(profile.requiredGaloisElements, []uint64{5, 9, 17, 25}) ||
			!equalInts(rotations, profile.rotationIndexes) ||
			!equalUint64sExact(galoisElements, profile.requiredGaloisElements) ||
			!profile.matrixScale.EqualScale(rlwe.NewScale(c.params.Q()[1])) {
			return fmt.Errorf("homchain: standalone B2A sealed graph or profile changed")
		}
	case b2aChainDigestSchema:
		if err = validateB2AChainParameters(c.params); err != nil {
			return err
		}
		if profile.words != 4 || profile.slots != 16 || profile.levelQ != b2aChainInputLevel ||
			profile.levelP != c.params.MaxLevelP() || profile.logDimensions != c.params.LogMaxDimensions() ||
			!equalInts(profile.rotationIndexes, []int{1, 2, 12, 14}) ||
			!equalUint64sExact(profile.requiredGaloisElements, []uint64{5, 17, 25, 41}) ||
			!equalInts(rotations, profile.rotationIndexes) ||
			!equalUint64sExact(galoisElements, profile.requiredGaloisElements) ||
			!profile.matrixScale.EqualScale(rlwe.NewScale(c.params.Q()[b2aChainInputLevel])) ||
			profile.transformSourceDigest != expectedSourceDigest {
			return fmt.Errorf("homchain: B2A-at-level sealed source, level, scale, or key profile changed")
		}
		matrixScale, scaleErr := profile.matrixScale.Scale()
		if scaleErr != nil {
			return fmt.Errorf("homchain: restore B2A-at-level matrix scale: %w", scaleErr)
		}
		options := CompileOptions{
			LevelQ:                    profile.levelQ,
			LevelP:                    profile.levelP,
			Scale:                     matrixScale,
			LogBabyStepGiantStepRatio: 0,
		}
		compiledDigest, digestErr := digestB2ACompiledPlan(c.params, c.source, c.pair, options, rotations, galoisElements)
		if digestErr != nil {
			return fmt.Errorf("homchain: recompute B2A-at-level compiled-plan digest: %w", digestErr)
		}
		if compiledDigest != profile.compiledPlanDigest {
			return fmt.Errorf("homchain: B2A-at-level compiled transform plan changed")
		}
	default:
		return fmt.Errorf("homchain: B2A digest schema changed")
	}
	expectedProfileDigest, err := digestB2AProfile(c.params, profile)
	if err != nil {
		return err
	}
	if expectedProfileDigest != profile.digest {
		return fmt.Errorf("homchain: B2A profile digest changed")
	}
	return nil
}

// B2ABooleanLow and B2ABooleanHigh are role-specific, circuit-bound handles.
// Their fields are private so only BindLow and BindHigh can create them.
type B2ABooleanLow struct {
	ciphertext *rlwe.Ciphertext
	digest     string
}

type B2ABooleanHigh struct {
	ciphertext *rlwe.Ciphertext
	digest     string
}

type B2AFullInput struct {
	low    *rlwe.Ciphertext
	high   *rlwe.Ciphertext
	digest string
}

func (c *B2AFullCircuit) BindLow(ciphertext *rlwe.Ciphertext) (B2ABooleanLow, error) {
	if err := c.validateHalf(ciphertext, "low"); err != nil {
		return B2ABooleanLow{}, err
	}
	return B2ABooleanLow{ciphertext: ciphertext, digest: c.profile.digest}, nil
}

func (c *B2AFullCircuit) BindHigh(ciphertext *rlwe.Ciphertext) (B2ABooleanHigh, error) {
	if err := c.validateHalf(ciphertext, "high"); err != nil {
		return B2ABooleanHigh{}, err
	}
	return B2ABooleanHigh{ciphertext: ciphertext, digest: c.profile.digest}, nil
}

func (c *B2AFullCircuit) BindInput(low B2ABooleanLow, high B2ABooleanHigh) (B2AFullInput, error) {
	if c == nil {
		return B2AFullInput{}, fmt.Errorf("homchain: nil B2A circuit")
	}
	if low.digest != c.profile.digest || high.digest != c.profile.digest {
		return B2AFullInput{}, fmt.Errorf("homchain: B2A Boolean halves belong to a different profile")
	}
	if err := c.validateHalf(low.ciphertext, "low"); err != nil {
		return B2AFullInput{}, err
	}
	if err := c.validateHalf(high.ciphertext, "high"); err != nil {
		return B2AFullInput{}, err
	}
	if low.ciphertext.Level() != high.ciphertext.Level() || !b2aExactScaleEqual(low.ciphertext.Scale, high.ciphertext.Scale) || low.ciphertext.LogDimensions != high.ciphertext.LogDimensions {
		return B2AFullInput{}, fmt.Errorf("homchain: B2A Boolean halves have mismatched level, exact scale, or dimensions")
	}
	return B2AFullInput{low: low.ciphertext, high: high.ciphertext, digest: c.profile.digest}, nil
}

func (c *B2AFullCircuit) validateHalf(ciphertext *rlwe.Ciphertext, role string) error {
	if c == nil {
		return fmt.Errorf("homchain: nil B2A circuit")
	}
	if ciphertext == nil || ciphertext.MetaData == nil {
		return fmt.Errorf("homchain: B2A %s Boolean half is nil or has nil metadata", role)
	}
	if ciphertext.Degree() != 1 {
		return fmt.Errorf("homchain: B2A %s Boolean half degree=%d, want 1", role, ciphertext.Degree())
	}
	if ciphertext.Level() != c.profile.levelQ {
		return fmt.Errorf("homchain: B2A %s Boolean half level=%d, want %d", role, ciphertext.Level(), c.profile.levelQ)
	}
	if !ciphertext.IsBatched || ciphertext.LogDimensions != c.profile.logDimensions || ciphertext.Slots() != c.profile.slots {
		return fmt.Errorf("homchain: B2A %s Boolean half is not full-packed over %d slots", role, c.profile.slots)
	}
	if !ciphertext.IsNTT {
		return fmt.Errorf("homchain: B2A %s Boolean half is not in NTT form", role)
	}
	actualScale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return fmt.Errorf("homchain: B2A %s Boolean half scale: %w", role, err)
	}
	if !actualScale.Equal(c.profile.inputScale) {
		return fmt.Errorf("homchain: B2A %s Boolean half does not have the exact profile input scale", role)
	}
	return nil
}

// B2AFullEvaluator is a key-preflighted evaluator for one circuit profile.
type B2AFullEvaluator struct {
	circuit    *B2AFullCircuit
	ckks       *ckks.Evaluator
	linear     *ckkslintrans.Evaluator
	keySet     *rlwe.MemEvaluationKeySet
	galoisKeys map[uint64]*rlwe.GaloisKey
}

func (c *B2AFullCircuit) BindEvaluator(evaluator *ckks.Evaluator) (*B2AFullEvaluator, error) {
	if c == nil {
		return nil, fmt.Errorf("homchain: nil B2A circuit")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if evaluator == nil {
		return nil, fmt.Errorf("homchain: nil B2A evaluator")
	}
	if !c.params.Equal(evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: B2A evaluator parameters do not match the circuit profile")
	}
	keySet, ok := evaluator.EvaluationKeySet.(*rlwe.MemEvaluationKeySet)
	if !ok || keySet == nil {
		return nil, fmt.Errorf("homchain: B2A requires an in-memory evaluation key set")
	}
	galoisKeys, err := preflightB2AKeys(c.profile, keySet, nil)
	if err != nil {
		return nil, err
	}
	linearEvaluator := ckkslintrans.NewEvaluator(evaluator)
	bound, ok := linearEvaluator.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || bound != evaluator {
		return nil, fmt.Errorf("homchain: B2A linear evaluator graph is not bound to the source CKKS evaluator")
	}
	return &B2AFullEvaluator{
		circuit: c, ckks: evaluator, linear: linearEvaluator,
		keySet: keySet, galoisKeys: galoisKeys,
	}, nil
}

// B2AFullResult binds a ciphertext to the profile and execution provenance.
type B2AFullResult struct {
	ciphertext *rlwe.Ciphertext
	provenance B2AProvenance
}

func (r B2AFullResult) Ciphertext() *rlwe.Ciphertext {
	if r.ciphertext == nil {
		return nil
	}
	return r.ciphertext.CopyNew()
}

func (r B2AFullResult) Provenance() B2AProvenance { return r.provenance }

// EvaluateNew executes exactly the full-packed special C-To-Z path: two
// fused-tau-inverse linear transforms, one addition and one CKKS rescale.
func (e *B2AFullEvaluator) EvaluateNew(input B2AFullInput) (B2AFullResult, error) {
	if e == nil || e.circuit == nil || e.ckks == nil || e.linear == nil {
		return B2AFullResult{}, fmt.Errorf("homchain: nil bound B2A evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		return B2AFullResult{}, err
	}
	if err := e.preflightGraphAndKeys(); err != nil {
		return B2AFullResult{}, err
	}
	if input.digest != e.circuit.profile.digest {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A input belongs to a different profile")
	}
	if err := e.circuit.validateHalf(input.low, "low"); err != nil {
		return B2AFullResult{}, err
	}
	if err := e.circuit.validateHalf(input.high, "high"); err != nil {
		return B2AFullResult{}, err
	}
	if input.low.Level() != input.high.Level() || !b2aExactScaleEqual(input.low.Scale, input.high.Scale) || input.low.LogDimensions != input.high.LogDimensions {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A Boolean halves changed to mismatched state after binding")
	}
	lowBefore, highBefore := input.low.CopyNew(), input.high.CopyNew()
	states := make([]B2ACiphertextState, 0, 6)
	lowState, err := snapshotB2AState(B2AStageInputLow, input.low)
	if err != nil {
		return B2AFullResult{}, err
	}
	highState, err := snapshotB2AState(B2AStageInputHigh, input.high)
	if err != nil {
		return B2AFullResult{}, err
	}
	states = append(states, lowState, highState)

	low, err := e.linear.EvaluateNew(input.low, e.circuit.pair.Low)
	if err != nil {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A evaluate fused U0: %w", err)
	}
	high, err := e.linear.EvaluateNew(input.high, e.circuit.pair.High)
	if err != nil {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A evaluate fused U1: %w", err)
	}
	lowFused, err := snapshotB2AState(B2AStageFusedLow, low)
	if err != nil {
		return B2AFullResult{}, err
	}
	highFused, err := snapshotB2AState(B2AStageFusedHigh, high)
	if err != nil {
		return B2AFullResult{}, err
	}
	states = append(states, lowFused, highFused)
	matrixScale, err := e.circuit.profile.matrixScale.Scale()
	if err != nil {
		return B2AFullResult{}, err
	}
	expectedProduct := input.low.Scale.Mul(matrixScale)
	if low.Level() != e.circuit.profile.levelQ || high.Level() != e.circuit.profile.levelQ || !b2aExactScaleEqual(low.Scale, expectedProduct) || !b2aExactScaleEqual(high.Scale, expectedProduct) {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A fused transform violated level/scale invariant")
	}
	if err = e.ckks.Add(low, high, low); err != nil {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A recombine fused halves: %w", err)
	}
	recombined, err := snapshotB2AState(B2AStageRecombined, low)
	if err != nil {
		return B2AFullResult{}, err
	}
	states = append(states, recombined)
	if !b2aExactScaleEqual(low.Scale, expectedProduct) || low.Level() != e.circuit.profile.levelQ {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A recombination violated level/scale invariant")
	}
	if err = e.ckks.Rescale(low, low); err != nil {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A rescale fused result: %w", err)
	}
	rescaled, err := snapshotB2AState(B2AStageRescaled, low)
	if err != nil {
		return B2AFullResult{}, err
	}
	states = append(states, rescaled)
	expectedOutputScale := expectedProduct.Div(rlwe.NewScale(e.circuit.params.Q()[e.circuit.profile.levelQ]))
	expectedOutputLevel := e.circuit.profile.levelQ - e.circuit.params.LevelsConsumedPerRescaling()
	if low.Level() != expectedOutputLevel || !b2aExactScaleEqual(low.Scale, expectedOutputScale) || low.Degree() != 1 || low.LogDimensions != e.circuit.profile.logDimensions {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A rescale violated output state invariant")
	}
	if !input.low.Equal(lowBefore) || !input.high.Equal(highBefore) {
		return B2AFullResult{}, fmt.Errorf("homchain: B2A mutated a Boolean input half")
	}
	return B2AFullResult{
		ciphertext: low,
		provenance: B2AProvenance{fidelity: B2ALattigoAdaptation, profileDigest: e.circuit.profile.digest, states: states},
	}, nil
}

func (e *B2AFullEvaluator) preflightGraphAndKeys() error {
	if e.ckks.EvaluationKeySet != e.keySet || e.keySet == nil {
		return fmt.Errorf("homchain: B2A evaluation key-set identity changed before evaluation")
	}
	bound, ok := e.linear.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || bound != e.ckks {
		return fmt.Errorf("homchain: B2A linear evaluator graph changed before evaluation")
	}
	_, err := preflightB2AKeys(e.circuit.profile, e.keySet, e.galoisKeys)
	return err
}

func preflightB2AKeys(
	profile B2AFullProfile,
	keySet *rlwe.MemEvaluationKeySet,
	expected map[uint64]*rlwe.GaloisKey,
) (map[uint64]*rlwe.GaloisKey, error) {
	if keySet == nil {
		return nil, fmt.Errorf("homchain: B2A evaluation key set is nil")
	}
	keys := make(map[uint64]*rlwe.GaloisKey, len(profile.requiredGaloisElements))
	for _, element := range profile.requiredGaloisElements {
		key, err := keySet.GetGaloisKey(element)
		if err != nil {
			return nil, fmt.Errorf("homchain: B2A missing required Galois key %d: %w", element, err)
		}
		if key == nil {
			return nil, fmt.Errorf("homchain: B2A required Galois key %d is nil", element)
		}
		if key.GaloisElement != element || key.LevelP() != profile.levelP || key.LevelQ() < profile.levelQ {
			return nil, fmt.Errorf("homchain: B2A Galois key %d has element=%d levels Q=%d P=%d, need element=%d Q>=%d P=%d",
				element, key.GaloisElement, key.LevelQ(), key.LevelP(), element, profile.levelQ, profile.levelP)
		}
		if expected != nil && expected[element] != key {
			return nil, fmt.Errorf("homchain: B2A Galois key %d identity changed before evaluation", element)
		}
		keys[element] = key
	}
	return keys, nil
}

func snapshotB2AState(stage B2AStage, ciphertext *rlwe.Ciphertext) (B2ACiphertextState, error) {
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return B2ACiphertextState{}, fmt.Errorf("homchain: B2A snapshot %s scale: %w", stage, err)
	}
	return B2ACiphertextState{Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(), LogDimensions: ciphertext.LogDimensions, Scale: scale}, nil
}

func b2aExactScaleEqual(left, right rlwe.Scale) bool {
	leftSnapshot, err := NewExactScaleSnapshot(left)
	if err != nil {
		return false
	}
	rightSnapshot, err := NewExactScaleSnapshot(right)
	return err == nil && leftSnapshot.Equal(rightSnapshot)
}

func digestB2ATransformSource(pair PairSpec) string {
	var canonical strings.Builder
	canonical.WriteString("b2a-fused-tinv-source-v1")
	for _, spec := range []TransformSpec{pair.Low, pair.High} {
		matrix := spec.Matrix()
		fmt.Fprintf(&canonical, "|name=%s|layout=%s|precision=%d|words=%d|half=%d|dimensions=%d,%d|rows=%d|matrix=",
			spec.Name(), spec.Layout(), spec.precision, spec.Words(), spec.HalfWidth(), spec.LogDimensions().Rows, spec.LogDimensions().Cols, len(matrix))
		for rowIndex, row := range matrix {
			fmt.Fprintf(&canonical, "row=%d/%d:", rowIndex, len(row))
			for columnIndex, value := range row {
				fmt.Fprintf(&canonical, "%d=%s@%d/%d,%s@%d/%d;", columnIndex,
					value.Real().Text('x', -1), value.Real().Prec(), value.Real().Mode(),
					value.Imag().Text('x', -1), value.Imag().Prec(), value.Imag().Mode())
			}
		}
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:])
}

func digestB2ACompiledPlan(
	params ckks.Parameters,
	source PairSpec,
	pair CompiledPair,
	options CompileOptions,
	rotations []int,
	galoisElements []uint64,
) (string, error) {
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("marshal parameters: %w", err)
	}
	requestedScale, err := NewExactScaleSnapshot(options.Scale)
	if err != nil {
		return "", fmt.Errorf("snapshot requested scale: %w", err)
	}
	var canonical strings.Builder
	sourceDigest := digestB2ATransformSource(source)
	fmt.Fprintf(&canonical,
		"b2a-fused-tinv-compiled-plan-v1|source=%s|requested=Q%d/P%d/scale={%s}/bsgs=%d|keys=relinearization:false/conjugation:false/rotations:%v/galois:%v/min-level-q:%d/level-p:%d|params=%x",
		sourceDigest,
		options.LevelQ, options.LevelP, requestedScale.canonicalString(), options.LogBabyStepGiantStepRatio,
		rotations, galoisElements, options.LevelQ, options.LevelP, parameterBytes)
	transformations := []ckkslintrans.LinearTransformation{pair.Low, pair.High}
	specifications := []TransformSpec{source.Low, source.High}
	for index, transformation := range transformations {
		if transformation.MetaData == nil {
			return "", fmt.Errorf("compiled transform %d has nil metadata", index)
		}
		scale, err := NewExactScaleSnapshot(transformation.Scale)
		if err != nil {
			return "", fmt.Errorf("snapshot compiled transform %d scale: %w", index, err)
		}
		diagonalIndexes := make([]int, 0, len(transformation.Vec))
		for diagonalIndex := range transformation.Vec {
			diagonalIndexes = append(diagonalIndexes, diagonalIndex)
		}
		sort.Ints(diagonalIndexes)
		fmt.Fprintf(&canonical,
			"|transform=%d/name=%s/Q%d/P%d/scale={%s}/dimensions=%d,%d/bsgs=%d/n1=%d/diagonals=%v",
			index, specifications[index].Name(), transformation.LevelQ, transformation.LevelP,
			scale.canonicalString(), transformation.LogDimensions.Rows, transformation.LogDimensions.Cols,
			transformation.LogBabyStepGiantStepRatio, transformation.N1, diagonalIndexes)
		for _, diagonalIndex := range diagonalIndexes {
			encoded, marshalErr := transformation.Vec[diagonalIndex].MarshalBinary()
			if marshalErr != nil {
				return "", fmt.Errorf("marshal compiled transform %d diagonal %d: %w", index, diagonalIndex, marshalErr)
			}
			encodedDigest := sha256.Sum256(encoded)
			fmt.Fprintf(&canonical, "/diagonal=%d/payload=%x", diagonalIndex, encodedDigest)
		}
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:]), nil
}

func digestB2AProfile(params ckks.Parameters, profile B2AFullProfile) (string, error) {
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("homchain: marshal B2A parameters for digest: %w", err)
	}
	var canonical strings.Builder
	if profile.digestSchema == b2aChainDigestSchema {
		fmt.Fprintf(&canonical, "b2a-full-chain-v1|fidelity=%s|word-bits=%d|words=%d|slots=%d|level-q=%d|level-p=%d|dimensions=%d,%d|encoder-precision=%d|input-scale=%s|matrix-scale=%s|rotations=%v|galois=%v|fused=%s,%s|transform-source=%s|compiled-plan=%s|params=%x",
			profile.fidelity, profile.wordBits, profile.words, profile.slots, profile.levelQ, profile.levelP,
			profile.logDimensions.Rows, profile.logDimensions.Cols, profile.encoderPrecision,
			profile.inputScale.canonicalString(), profile.matrixScale.canonicalString(),
			profile.rotationIndexes, profile.requiredGaloisElements, U0FusedTInv, U1FusedTInv,
			profile.transformSourceDigest, profile.compiledPlanDigest, parameterBytes)
	} else {
		// Preserve the standalone v2 canonical string and digest byte-for-byte.
		fmt.Fprintf(&canonical, "b2a-full-v2|fidelity=%s|word-bits=%d|words=%d|slots=%d|level-q=%d|level-p=%d|dimensions=%d,%d|encoder-precision=%d|input-scale=%s|matrix-scale=%s|rotations=%v|galois=%v|fused=%s,%s|params=%x",
			profile.fidelity, profile.wordBits, profile.words, profile.slots, profile.levelQ, profile.levelP,
			profile.logDimensions.Rows, profile.logDimensions.Cols, profile.encoderPrecision,
			profile.inputScale.canonicalString(), profile.matrixScale.canonicalString(),
			profile.rotationIndexes, profile.requiredGaloisElements, U0FusedTInv, U1FusedTInv, parameterBytes)
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:]), nil
}

func equalInts(left, right []int) bool {
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

func equalUint64s(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy, rightCopy := append([]uint64(nil), left...), append([]uint64(nil), right...)
	sort.Slice(leftCopy, func(i, j int) bool { return leftCopy[i] < leftCopy[j] })
	sort.Slice(rightCopy, func(i, j int) bool { return rightCopy[i] < rightCopy[j] })
	for i := range leftCopy {
		if leftCopy[i] != rightCopy[i] {
			return false
		}
	}
	return true
}

func equalUint64sExact(left, right []uint64) bool {
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

func b2aRoundedLog2(value uint64) int {
	return int(math.Round(math.Log2(float64(value))))
}
