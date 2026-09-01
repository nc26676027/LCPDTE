package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	ckksdft "github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// A2BFullFidelity is the strongest claim supported by this local graph.
type A2BFullFidelity string

const (
	A2BFullFunctionalLattigoAdaptationNotSecureNotSourceSecure A2BFullFidelity = "functional_lattigo_adaptation_not_secure_not_source_secure"
)

// A2BFullSchedule identifies the only admitted source order.
type A2BFullSchedule string

const (
	A2BFullSerialLowThenHigh   A2BFullSchedule = "serial_low_then_high_two_iteration_gao_a2b"
	a2bFullLevelLedger                         = "input20->special19->iter0-mask18->stc16->sd0->mu20->cts17->kernel5->id0/16-4;high19-drop4-sub->iter1-mask3->stc1->sd0->mu20->cts17->kernel5;low19-drop5-sub-id0;id1-drop4-high-self-remove"
	a2bFullNormalizedInvariant                 = "each CTS output is y=(I+a)/16 with 16*y-a integral; exp46 plus square^2 removes integer lift I; source-secure sparse switching and deterministic lift are not claimed"
)

// A2BFullSecondSTCProfile binds the paper literal and its separately
// initialized 192-bit Lattigo execution matrix.
type A2BFullSecondSTCProfile struct {
	rawLiteral       ckksdft.MatrixLiteral
	executionLiteral ckksdft.MatrixLiteral
	rawMatrixDigest  string
	matrixDigest     string
	digest           string
}

func (p A2BFullSecondSTCProfile) RawLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.rawLiteral)
}

func (p A2BFullSecondSTCProfile) ExecutionLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.executionLiteral)
}

func (p A2BFullSecondSTCProfile) RawMatrixDigest() string       { return p.rawMatrixDigest }
func (p A2BFullSecondSTCProfile) ExecutionMatrixDigest() string { return p.matrixDigest }
func (p A2BFullSecondSTCProfile) Digest() string                { return p.digest }

func cloneA2BFullSecondSTCProfile(p A2BFullSecondSTCProfile) A2BFullSecondSTCProfile {
	result := p
	result.rawLiteral = p.RawLiteral()
	result.executionLiteral = p.ExecutionLiteral()
	return result
}

// A2BFullOperationCounts fixes the charged serial graph. Alignment drops are
// modulus-only operations and never retag the exact scale.
type A2BFullOperationCounts struct {
	SpecialB0Transforms int
	MaskMulRescales     int
	RefreshInvocations  int
	KernelInvocations   int
	IDScaleMulRescales  int
	AlignmentDrops      int
	Subtractions        int
	ResidualRotations   int
	SharedCTSUses       int
}

// A2BFullProfile is an immutable projection of the fixed n=8,w=4,d=2,
// full-packed serial circuit.
type A2BFullProfile struct {
	fidelity             A2BFullFidelity
	schedule             A2BFullSchedule
	wordBits             z2n.WordBits
	chunkWidth           uint
	depth                int
	words                int
	slots                int
	inputLevel           int
	cutoff               int
	outputOrder          [2]string
	bitOrder             string
	inputScale           ExactScaleSnapshot
	firstRefreshDigest   string
	firstSTCDigest       string
	secondSTC            A2BFullSecondSTCProfile
	sharedCTSDigest      string
	sharedCTS            bool
	kernelDigests        [2]string
	kernelArtifactDigest string
	keyDigest            string
	parameterDigest      string
	maskDigest           string
	idScaleDigest        string
	operationCounts      A2BFullOperationCounts
	levelLedger          string
	normalizedCertified  bool
	normalizedInvariant  string
	digest               string
}

func (p A2BFullProfile) Fidelity() A2BFullFidelity { return p.fidelity }
func (p A2BFullProfile) Schedule() A2BFullSchedule { return p.schedule }
func (p A2BFullProfile) WordBits() z2n.WordBits    { return p.wordBits }
func (p A2BFullProfile) ChunkWidth() uint          { return p.chunkWidth }
func (p A2BFullProfile) Depth() int                { return p.depth }
func (p A2BFullProfile) Words() int                { return p.words }
func (p A2BFullProfile) Slots() int                { return p.slots }
func (p A2BFullProfile) InputLevel() int           { return p.inputLevel }
func (p A2BFullProfile) Cutoff() int               { return p.cutoff }
func (p A2BFullProfile) OutputOrder() [2]string    { return p.outputOrder }
func (p A2BFullProfile) BitOrder() string          { return p.bitOrder }
func (p A2BFullProfile) InputScale() ExactScaleSnapshot {
	return p.inputScale
}
func (p A2BFullProfile) FirstRefreshDigest() string { return p.firstRefreshDigest }
func (p A2BFullProfile) FirstSTCExecutionMatrixDigest() string {
	return p.firstSTCDigest
}
func (p A2BFullProfile) SecondSTC() A2BFullSecondSTCProfile {
	return cloneA2BFullSecondSTCProfile(p.secondSTC)
}
func (p A2BFullProfile) SharedCTSExecutionMatrixDigest() string { return p.sharedCTSDigest }
func (p A2BFullProfile) CTSSharedAcrossRefreshes() bool         { return p.sharedCTS }
func (p A2BFullProfile) KernelProfileDigests() [2]string        { return p.kernelDigests }
func (p A2BFullProfile) KernelArtifactDigest() string           { return p.kernelArtifactDigest }
func (p A2BFullProfile) KeyProfileDigest() string               { return p.keyDigest }
func (p A2BFullProfile) ParameterDigest() string                { return p.parameterDigest }
func (p A2BFullProfile) MaskSourceDigest() string               { return p.maskDigest }
func (p A2BFullProfile) IDScaleSourceDigest() string            { return p.idScaleDigest }
func (p A2BFullProfile) OperationCounts() A2BFullOperationCounts {
	return p.operationCounts
}
func (p A2BFullProfile) LevelLedger() string            { return p.levelLedger }
func (p A2BFullProfile) NormalizedInputCertified() bool { return p.normalizedCertified }
func (p A2BFullProfile) NormalizedInvariant() string    { return p.normalizedInvariant }
func (p A2BFullProfile) Digest() string                 { return p.digest }

// A2BFullCircuit is the sealed fixed n=8,w=4,d=2 serial full-packed A2B
// functional Lattigo adaptation.
type A2BFullCircuit struct {
	params     ckks.Parameters
	refresh    *A2BRefreshCircuit
	kernel0    *GaoA2BKernelCircuit
	kernel1    *GaoA2BKernelCircuit
	secondSTC  ckksdft.Matrix
	iter1Mask  *rlwe.Plaintext
	idScale    *rlwe.Plaintext
	profile    A2BFullProfile
	keyProfile A2BRefreshKeyProfile
}

// A2BFullEvaluator binds the sealed serial circuit to one bootstrap source,
// one evaluation-key set, and two distinct Gao kernel evaluators.
type A2BFullEvaluator struct {
	circuit            *A2BFullCircuit
	source             *bootstrapping.Evaluator
	refresh            *A2BRefreshEvaluator
	kernel0            *GaoA2BKernelEvaluator
	kernel1            *GaoA2BKernelEvaluator
	kernelSource0      *ckks.Evaluator
	kernelSource1      *ckks.Evaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	galoisKeys         map[uint64]*rlwe.GaloisKey
	circuitGraph       a2bFullCircuitGraphIdentity
}

func (c *A2BFullCircuit) Profile() A2BFullProfile {
	if c == nil {
		return A2BFullProfile{}
	}
	result := c.profile
	result.secondSTC = cloneA2BFullSecondSTCProfile(c.profile.secondSTC)
	return result
}

func (c *A2BFullCircuit) RequiredKeyProfile() A2BRefreshKeyProfile {
	if c == nil {
		return A2BRefreshKeyProfile{}
	}
	return cloneA2BRefreshKeyProfile(c.keyProfile)
}

func (c *A2BFullCircuit) validate() error {
	if c == nil || c.refresh == nil || c.kernel0 == nil || c.kernel1 == nil || c.iter1Mask == nil || c.idScale == nil {
		return fmt.Errorf("homchain: nil or incomplete A2B full circuit")
	}
	if err := validateA2BRefreshParameters(c.params); err != nil {
		return err
	}
	if refreshGraph, err := captureA2BRefreshCircuitGraph(c.refresh); err != nil {
		return err
	} else if err = refreshGraph.validate(); err != nil {
		return err
	}
	if err := c.kernel0.validate(); err != nil {
		return err
	}
	if err := c.kernel1.validate(); err != nil {
		return err
	}
	maskBytes, err := c.iter1Mask.MarshalBinary()
	if err != nil {
		return fmt.Errorf("homchain: remarshal A2B full iter1 mask: %w", err)
	}
	idScaleBytes, err := c.idScale.MarshalBinary()
	if err != nil {
		return fmt.Errorf("homchain: remarshal A2B full ID0/16 operand: %w", err)
	}
	wantMaskDigest := digestString(fmt.Sprintf(
		"a2b-full-iter1-mask-v1|level=4|output=3|scale=q4|value=1|slots=%d|payload=%s",
		c.params.MaxSlots(), sha256Hex(maskBytes),
	))
	wantIDScaleDigest := digestString(fmt.Sprintf(
		"a2b-full-id0-over-16-v1|level=5|output=4|scale=q5|value=2^-4|slots=%d|payload=%s",
		c.params.MaxSlots(), sha256Hex(idScaleBytes),
	))
	wantSecondRawDigest := digestDFTMatrixNumericPayload(
		c.profile.secondSTC.rawLiteral,
		c.profile.secondSTC.rawLiteral.GenMatrices(c.params.LogN(), a2bRefreshGeneratorEncoderPrecision),
	)
	wantSecondExecutionDigest := digestDFTMatrixNumericPayload(
		c.profile.secondSTC.executionLiteral,
		c.profile.secondSTC.executionLiteral.GenMatrices(c.params.LogN(), a2bRefreshGeneratorEncoderPrecision),
	)
	parameterBytes, err := c.params.MarshalBinary()
	if err != nil {
		return fmt.Errorf("homchain: remarshal A2B full parameters: %w", err)
	}
	wantKernelArtifactDigest := digestString(fmt.Sprintf(
		"exp=%s|lut=%s", c.kernel0.profile.exponentialArtifactDigest, c.kernel0.profile.lutTableDigest,
	))
	for secondIndex, secondFactor := range c.secondSTC.Matrices {
		secondPointer := a2bRefreshLinearIdentity(secondFactor)
		for firstIndex, firstFactor := range c.refresh.stc.Matrices {
			if secondPointer == 0 || secondPointer == a2bRefreshLinearIdentity(firstFactor) {
				return fmt.Errorf("homchain: A2B full second STC factor %d reuses first STC factor %d", secondIndex, firstIndex)
			}
		}
	}
	if c.profile.digest != digestA2BFullProfile(c.profile) || c.profile.keyDigest != c.keyProfile.digest ||
		c.profile.fidelity != A2BFullFunctionalLattigoAdaptationNotSecureNotSourceSecure ||
		c.profile.schedule != A2BFullSerialLowThenHigh || c.profile.wordBits != z2n.Word8 ||
		c.profile.chunkWidth != 4 || c.profile.depth != 2 || c.profile.words != 4 || c.profile.slots != 16 ||
		c.profile.inputLevel != 20 || c.profile.cutoff != -16 || c.profile.outputOrder != [2]string{"low", "high"} ||
		c.profile.bitOrder != "LSB-first" || !c.profile.inputScale.EqualScale(c.params.DefaultScale()) ||
		c.profile.firstRefreshDigest != c.refresh.profile.digest || c.profile.firstSTCDigest != c.refresh.profile.dft.stcMatrixDigest ||
		c.profile.sharedCTSDigest != c.refresh.profile.dft.ctsMatrixDigest || !c.profile.sharedCTS ||
		c.profile.kernelDigests != [2]string{c.kernel0.profile.digest, c.kernel1.profile.digest} ||
		c.profile.kernelArtifactDigest != wantKernelArtifactDigest || c.profile.parameterDigest != sha256Hex(parameterBytes) ||
		c.profile.keyDigest != c.keyProfile.digest || c.profile.maskDigest != wantMaskDigest || c.profile.idScaleDigest != wantIDScaleDigest ||
		c.profile.secondSTC.rawMatrixDigest != wantSecondRawDigest || c.profile.secondSTC.matrixDigest != wantSecondExecutionDigest ||
		c.profile.secondSTC.digest != digestA2BFullSecondSTCProfile(c.profile.secondSTC, a2bRefreshGeneratorEncoderPrecision) ||
		!a2bRefreshLiteralEqual(c.secondSTC.MatrixLiteral, c.profile.secondSTC.executionLiteral) ||
		c.secondSTC.LevelQ != 3 || c.secondSTC.LevelQ-c.secondSTC.Depth(true) != 1 || len(c.secondSTC.Matrices) != 2 ||
		c.iter1Mask.Level() != 4 || c.idScale.Level() != 5 || !rlwe.NewScale(c.params.Q()[4]).Equal(c.iter1Mask.Scale) ||
		!rlwe.NewScale(c.params.Q()[5]).Equal(c.idScale.Scale) || c.profile.normalizedCertified ||
		c.profile.normalizedInvariant != a2bFullNormalizedInvariant || c.profile.levelLedger != a2bFullLevelLedger ||
		c.profile.operationCounts != (A2BFullOperationCounts{1, 2, 2, 2, 1, 3, 3, 0, 2}) || len(c.keyProfile.residual) != 0 {
		return fmt.Errorf("homchain: A2B full sealed graph, profile, or source operand changed")
	}
	return nil
}

type a2bFullCircuitGraphIdentity struct {
	circuit          *A2BFullCircuit
	refresh          *A2BRefreshCircuit
	kernel0          *GaoA2BKernelCircuit
	kernel1          *GaoA2BKernelCircuit
	iter1Mask        *rlwe.Plaintext
	idScale          *rlwe.Plaintext
	iter1MaskSaved   *rlwe.Plaintext
	idScaleSaved     *rlwe.Plaintext
	secondSTCFactors []uintptr
	sharedCTSFactors []uintptr
	profileDigest    string
	keyDigest        string
}

func captureA2BFullCircuitGraph(c *A2BFullCircuit) (a2bFullCircuitGraphIdentity, error) {
	if err := c.validate(); err != nil {
		return a2bFullCircuitGraphIdentity{}, err
	}
	result := a2bFullCircuitGraphIdentity{
		circuit: c, refresh: c.refresh, kernel0: c.kernel0, kernel1: c.kernel1,
		iter1Mask: c.iter1Mask, idScale: c.idScale,
		iter1MaskSaved: c.iter1Mask.CopyNew(), idScaleSaved: c.idScale.CopyNew(),
		profileDigest: c.profile.digest, keyDigest: c.keyProfile.digest,
	}
	for _, matrix := range c.secondSTC.Matrices {
		result.secondSTCFactors = append(result.secondSTCFactors, a2bRefreshLinearIdentity(matrix))
	}
	for _, matrix := range c.refresh.cts.Matrices {
		result.sharedCTSFactors = append(result.sharedCTSFactors, a2bRefreshLinearIdentity(matrix))
	}
	if len(result.secondSTCFactors) != 2 || len(result.sharedCTSFactors) != 3 {
		return a2bFullCircuitGraphIdentity{}, fmt.Errorf("homchain: A2B full DFT factor count changed")
	}
	for _, pointer := range append(append([]uintptr(nil), result.secondSTCFactors...), result.sharedCTSFactors...) {
		if pointer == 0 {
			return a2bFullCircuitGraphIdentity{}, fmt.Errorf("homchain: A2B full DFT graph contains an empty factor")
		}
	}
	return result, nil
}

func (g a2bFullCircuitGraphIdentity) validate() error {
	c := g.circuit
	if c == nil || c.refresh != g.refresh || c.kernel0 != g.kernel0 || c.kernel1 != g.kernel1 ||
		c.iter1Mask != g.iter1Mask || c.idScale != g.idScale || c.profile.digest != g.profileDigest || c.keyProfile.digest != g.keyDigest ||
		!c.iter1Mask.Equal(g.iter1MaskSaved) || !c.idScale.Equal(g.idScaleSaved) {
		return fmt.Errorf("homchain: A2B full circuit object graph changed")
	}
	if err := c.validate(); err != nil {
		return err
	}
	for i, pointer := range g.secondSTCFactors {
		if i >= len(c.secondSTC.Matrices) || a2bRefreshLinearIdentity(c.secondSTC.Matrices[i]) != pointer {
			return fmt.Errorf("homchain: A2B full second STC factor %d changed", i)
		}
	}
	for i, pointer := range g.sharedCTSFactors {
		if i >= len(c.refresh.cts.Matrices) || a2bRefreshLinearIdentity(c.refresh.cts.Matrices[i]) != pointer {
			return fmt.Errorf("homchain: A2B full shared CTS factor %d changed", i)
		}
	}
	return nil
}

// A2BFullStage identifies every ciphertext boundary in source order.
type A2BFullStage string

const (
	A2BFullStageInput           A2BFullStage = "input"
	A2BFullStageSpecialLow      A2BFullStage = "special-b0-low"
	A2BFullStageSpecialHigh     A2BFullStage = "special-b0-high"
	A2BFullStageIter0Mask       A2BFullStage = "iter0-low-mask"
	A2BFullStageIter0STC        A2BFullStage = "iter0-stc"
	A2BFullStageIter0ScaleDown  A2BFullStage = "iter0-scale-down"
	A2BFullStageIter0ModUp      A2BFullStage = "iter0-mod-up"
	A2BFullStageIter0CTS        A2BFullStage = "iter0-cts"
	A2BFullStageIter0ID         A2BFullStage = "iter0-id"
	A2BFullStageIter0MSB        A2BFullStage = "iter0-msb"
	A2BFullStageID0Over16       A2BFullStage = "id0-over-16"
	A2BFullStageHighAligned     A2BFullStage = "high-core-aligned"
	A2BFullStageHighUpdated     A2BFullStage = "high-core-minus-id0-over-16"
	A2BFullStageLowAligned      A2BFullStage = "low-core-aligned"
	A2BFullStageLowSelfRemoved  A2BFullStage = "low-core-minus-id0"
	A2BFullStageIter1Mask       A2BFullStage = "iter1-high-mask"
	A2BFullStageIter1STC        A2BFullStage = "iter1-stc"
	A2BFullStageIter1ScaleDown  A2BFullStage = "iter1-scale-down"
	A2BFullStageIter1ModUp      A2BFullStage = "iter1-mod-up"
	A2BFullStageIter1CTS        A2BFullStage = "iter1-cts"
	A2BFullStageIter1ID         A2BFullStage = "iter1-id"
	A2BFullStageIter1MSB        A2BFullStage = "iter1-msb"
	A2BFullStageID1Aligned      A2BFullStage = "id1-aligned"
	A2BFullStageHighSelfRemoved A2BFullStage = "high-core-minus-id0-over-16-minus-id1"
)

// A2BFullCiphertextState is an exact detached level/scale state.
type A2BFullCiphertextState struct {
	Stage         A2BFullStage
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

// A2BFullTrace is the detached serial execution evidence.
type A2BFullTrace struct {
	profileDigest   string
	states          []A2BFullCiphertextState
	keyPreflight    A2BRefreshKeyPreflight
	operationCounts A2BFullOperationCounts
	iter0ErrScale   ExactScaleSnapshot
	iter0ErrLog2    float64
	iter1ErrScale   ExactScaleSnapshot
	iter1ErrLog2    float64
	iter0Kernel     GaoA2BKernelProvenance
	iter1Kernel     GaoA2BKernelProvenance
}

func (t A2BFullTrace) ProfileDigest() string { return t.profileDigest }
func (t A2BFullTrace) States() []A2BFullCiphertextState {
	return append([]A2BFullCiphertextState(nil), t.states...)
}
func (t A2BFullTrace) State(stage A2BFullStage) (A2BFullCiphertextState, bool) {
	for _, state := range t.states {
		if state.Stage == stage {
			return state, true
		}
	}
	return A2BFullCiphertextState{}, false
}
func (t A2BFullTrace) KeyPreflight() A2BRefreshKeyPreflight {
	return cloneA2BRefreshKeyPreflight(t.keyPreflight)
}
func (t A2BFullTrace) OperationCounts() A2BFullOperationCounts { return t.operationCounts }
func (t A2BFullTrace) ScaleDownError(iteration int) (ExactScaleSnapshot, float64, bool) {
	switch iteration {
	case 0:
		return t.iter0ErrScale, t.iter0ErrLog2, t.iter0ErrScale.ValueHex() != ""
	case 1:
		return t.iter1ErrScale, t.iter1ErrLog2, t.iter1ErrScale.ValueHex() != ""
	default:
		return ExactScaleSnapshot{}, 0, false
	}
}
func (t A2BFullTrace) KernelProvenance(iteration int) (GaoA2BKernelProvenance, bool) {
	if iteration == 0 {
		return t.iter0Kernel, t.iter0Kernel.ProfileDigest() != ""
	}
	if iteration == 1 {
		return t.iter1Kernel, t.iter1Kernel.ProfileDigest() != ""
	}
	return GaoA2BKernelProvenance{}, false
}

// A2BFullResult owns the two full-packed LSB-first Boolean halves.
type A2BFullResult struct {
	lowMSB          *rlwe.Ciphertext
	highMSB         *rlwe.Ciphertext
	specialLow      *rlwe.Ciphertext
	specialHigh     *rlwe.Ciphertext
	iter0Refreshed  *rlwe.Ciphertext
	id0             *rlwe.Ciphertext
	id0Over16       *rlwe.Ciphertext
	highUpdated     *rlwe.Ciphertext
	lowSelfRemoved  *rlwe.Ciphertext
	iter1Masked     *rlwe.Ciphertext
	iter1Refreshed  *rlwe.Ciphertext
	id1             *rlwe.Ciphertext
	highSelfRemoved *rlwe.Ciphertext
}

func NewA2BFullCircuit(params ckks.Parameters, refreshEncoder, kernelEncoder *ckks.Encoder) (*A2BFullCircuit, error) {
	if refreshEncoder == nil || kernelEncoder == nil {
		return nil, fmt.Errorf("homchain: A2B full requires refresh and kernel encoders")
	}
	refresh, err := NewA2BRefreshCircuit(params, refreshEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct A2B full refresh: %w", err)
	}
	kernel0, err := NewGaoA2BKernelCircuit(params, kernelEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct A2B full iter0 kernel: %w", err)
	}
	kernel1, err := NewGaoA2BKernelCircuit(params, kernelEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct A2B full iter1 kernel: %w", err)
	}
	secondRaw, _ := a2bRefreshDFTLiterals(params, refreshEncoder.Prec(), 3, params.MaxLevel())
	stcInitializationFactor, _, err := a2bRefreshDFTInitializationFactors(params)
	if err != nil {
		return nil, err
	}
	secondExecution := scaleA2BRefreshDFTLiteral(secondRaw, stcInitializationFactor, refreshEncoder.Prec())
	secondRawDigest := digestDFTMatrixNumericPayload(secondRaw, secondRaw.GenMatrices(params.LogN(), refreshEncoder.Prec()))
	secondSTC, secondExecutionDigest, err := newDFTMatrixFromLiteralAtPrecision(params, secondExecution, refreshEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: encode A2B full independent iter1 STC: %w", err)
	}
	if secondSTC.LevelQ != 3 || secondSTC.LevelQ-secondSTC.Depth(true) != 1 || len(secondSTC.Matrices) != 2 ||
		reflect.ValueOf(secondSTC.Matrices[0].Vec).Pointer() == reflect.ValueOf(refresh.stc.Matrices[0].Vec).Pointer() {
		return nil, fmt.Errorf("homchain: A2B full second STC is not an independent L3-to-L1 matrix")
	}
	firstSTCGalois := uniqueGaloisElements(refresh.profile.dft.stcLiteral.GaloisElements(params))
	secondSTCGalois := uniqueGaloisElements(secondRaw.GaloisElements(params))
	if !reflect.DeepEqual(firstSTCGalois, secondSTCGalois) {
		return nil, fmt.Errorf("homchain: A2B full second STC changes the fixed key union: first=%v second=%v", firstSTCGalois, secondSTCGalois)
	}
	iter1Mask, err := newA2BRefreshMask(params, refreshEncoder, 4, rlwe.NewScale(params.Q()[4]))
	if err != nil {
		return nil, fmt.Errorf("homchain: encode A2B full iter1 mask: %w", err)
	}
	idScale, err := newA2BFullPlaintextFactor(params, refreshEncoder, 5, rlwe.NewScale(params.Q()[5]), -4)
	if err != nil {
		return nil, fmt.Errorf("homchain: encode A2B full ID0/16 operand: %w", err)
	}
	iter1MaskBytes, err := iter1Mask.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal A2B full iter1 mask: %w", err)
	}
	idScaleBytes, err := idScale.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal A2B full ID0/16 operand: %w", err)
	}
	secondProfile := A2BFullSecondSTCProfile{
		rawLiteral: secondRaw, executionLiteral: secondExecution,
		rawMatrixDigest: secondRawDigest, matrixDigest: secondExecutionDigest,
	}
	secondProfile.digest = digestA2BFullSecondSTCProfile(secondProfile, refreshEncoder.Prec())
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal A2B full parameters: %w", err)
	}
	inputScale, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil, fmt.Errorf("homchain: snapshot A2B full input scale: %w", err)
	}
	keyProfile := refresh.RequiredKeyProfile()
	profile := A2BFullProfile{
		fidelity: A2BFullFunctionalLattigoAdaptationNotSecureNotSourceSecure,
		schedule: A2BFullSerialLowThenHigh,
		wordBits: z2n.Word8, chunkWidth: 4, depth: 2, words: 4, slots: params.MaxSlots(),
		inputLevel: params.MaxLevel(), cutoff: -16, outputOrder: [2]string{"low", "high"}, bitOrder: "LSB-first",
		inputScale: inputScale, firstRefreshDigest: refresh.profile.digest,
		firstSTCDigest: refresh.profile.dft.stcMatrixDigest, secondSTC: secondProfile,
		sharedCTSDigest: refresh.profile.dft.ctsMatrixDigest, sharedCTS: true,
		kernelDigests:        [2]string{kernel0.profile.digest, kernel1.profile.digest},
		kernelArtifactDigest: digestString(fmt.Sprintf("exp=%s|lut=%s", kernel0.profile.exponentialArtifactDigest, kernel0.profile.lutTableDigest)),
		keyDigest:            keyProfile.digest, parameterDigest: sha256Hex(parameterBytes),
		maskDigest:    digestString(fmt.Sprintf("a2b-full-iter1-mask-v1|level=4|output=3|scale=q4|value=1|slots=%d|payload=%s", params.MaxSlots(), sha256Hex(iter1MaskBytes))),
		idScaleDigest: digestString(fmt.Sprintf("a2b-full-id0-over-16-v1|level=5|output=4|scale=q5|value=2^-4|slots=%d|payload=%s", params.MaxSlots(), sha256Hex(idScaleBytes))),
		operationCounts: A2BFullOperationCounts{
			SpecialB0Transforms: 1, MaskMulRescales: 2, RefreshInvocations: 2, KernelInvocations: 2,
			IDScaleMulRescales: 1, AlignmentDrops: 3, Subtractions: 3, ResidualRotations: 0, SharedCTSUses: 2,
		},
		levelLedger:         a2bFullLevelLedger,
		normalizedCertified: false,
		normalizedInvariant: a2bFullNormalizedInvariant,
	}
	profile.digest = digestA2BFullProfile(profile)
	circuit := &A2BFullCircuit{
		params: params, refresh: refresh, kernel0: kernel0, kernel1: kernel1,
		secondSTC: secondSTC, iter1Mask: iter1Mask, idScale: idScale, profile: profile, keyProfile: keyProfile,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *A2BFullCircuit) BindEvaluator(source *bootstrapping.Evaluator) (*A2BFullEvaluator, error) {
	if c == nil || source == nil || source.Evaluator == nil || source.MemEvaluationKeySet == nil {
		return nil, fmt.Errorf("homchain: nil or incomplete A2B full circuit/evaluator")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	refresh, err := c.refresh.BindEvaluator(source)
	if err != nil {
		return nil, err
	}
	kernelSource0 := ckks.NewEvaluator(c.params, source.MemEvaluationKeySet)
	kernelSource1 := ckks.NewEvaluator(c.params, source.MemEvaluationKeySet)
	kernel0, err := c.kernel0.BindEvaluator(kernelSource0)
	if err != nil {
		return nil, err
	}
	kernel1, err := c.kernel1.BindEvaluator(kernelSource1)
	if err != nil {
		return nil, err
	}
	keySet := source.MemEvaluationKeySet
	if kernel0 == kernel1 || kernel0.keySet != keySet || kernel1.keySet != keySet || refresh.bootstrap.MemEvaluationKeySet != keySet {
		return nil, fmt.Errorf("homchain: A2B full did not bind one keyset to two distinct kernels and both refreshes")
	}
	relinearizationKey, err := keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, fmt.Errorf("homchain: A2B full relinearization key is missing: %v", err)
	}
	galoisKeys := make(map[uint64]*rlwe.GaloisKey, len(c.keyProfile.all))
	for _, element := range c.keyProfile.all {
		key, keyErr := keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil {
			return nil, fmt.Errorf("homchain: A2B full Galois key %d is missing: %v", element, keyErr)
		}
		galoisKeys[element] = key
	}
	circuitGraph, err := captureA2BFullCircuitGraph(c)
	if err != nil {
		return nil, err
	}
	return &A2BFullEvaluator{
		circuit: c, source: source, refresh: refresh, kernel0: kernel0, kernel1: kernel1,
		kernelSource0: kernelSource0, kernelSource1: kernelSource1, keySet: keySet,
		relinearizationKey: relinearizationKey, galoisKeys: galoisKeys, circuitGraph: circuitGraph,
	}, nil
}

func (e *A2BFullEvaluator) preflight() (A2BRefreshKeyPreflight, error) {
	result := A2BRefreshKeyPreflight{Checked: true, GraphChecked: true}
	if e == nil || e.circuit == nil || e.source == nil || e.refresh == nil || e.kernel0 == nil || e.kernel1 == nil || e.keySet == nil {
		return result, fmt.Errorf("homchain: nil or incomplete bound A2B full evaluator")
	}
	if err := e.circuitGraph.validate(); err != nil {
		result.GraphMismatch = err.Error()
		return result, fmt.Errorf("homchain: A2B full graph preflight failed: %w", err)
	}
	if e.source.MemEvaluationKeySet != e.keySet || e.refresh.bootstrap.MemEvaluationKeySet != e.keySet ||
		e.kernelSource0 == nil || e.kernelSource1 == nil || e.kernelSource0 == e.kernelSource1 ||
		e.kernelSource0.EvaluationKeySet != e.keySet || e.kernelSource1.EvaluationKeySet != e.keySet ||
		e.kernel0.keySet != e.keySet || e.kernel1.keySet != e.keySet ||
		e.kernel0.source != e.kernelSource0 || e.kernel1.source != e.kernelSource1 || e.kernel0 == e.kernel1 {
		result.GraphMismatch = "shared source/keyset/kernel identity changed"
		return result, fmt.Errorf("homchain: A2B full graph preflight failed: %s", result.GraphMismatch)
	}
	refreshPreflight, err := e.refresh.preflight()
	if err != nil {
		return refreshPreflight, err
	}
	if err = e.kernel0.preflightGraphAndKeys(); err != nil {
		return result, err
	}
	if err = e.kernel1.preflightGraphAndKeys(); err != nil {
		return result, err
	}
	relinearizationKey, err := e.keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil || relinearizationKey != e.relinearizationKey {
		return result, fmt.Errorf("homchain: A2B full relinearization key identity changed before evaluation")
	}
	for element, expected := range e.galoisKeys {
		key, keyErr := e.keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil || key != expected {
			return result, fmt.Errorf("homchain: A2B full Galois key %d identity changed before evaluation", element)
		}
	}
	refreshPreflight.GraphMatched = true
	return refreshPreflight, nil
}

func (e *A2BFullEvaluator) EvaluateNew(input *rlwe.Ciphertext) (A2BFullResult, A2BFullTrace, error) {
	trace := A2BFullTrace{}
	if e == nil || e.circuit == nil || e.refresh == nil || e.kernel0 == nil || e.kernel1 == nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: nil A2B full evaluator")
	}
	trace.profileDigest = e.circuit.profile.digest
	if err := e.circuit.refresh.validateInput(input); err != nil {
		return A2BFullResult{}, trace, err
	}
	preflight, err := e.preflight()
	trace.keyPreflight = preflight
	if err != nil {
		return A2BFullResult{}, trace, err
	}
	appendState := func(stage A2BFullStage, ciphertext *rlwe.Ciphertext) error {
		state, stateErr := snapshotA2BFullState(stage, ciphertext)
		if stateErr == nil {
			trace.states = append(trace.states, state)
		}
		return stateErr
	}
	if err := appendState(A2BFullStageInput, input); err != nil {
		return A2BFullResult{}, trace, err
	}

	inputBefore := input.CopyNew()
	halves, err := e.refresh.triangle.ZToCNew(input.CopyNew(), e.circuit.refresh.specialB0)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full special-b0 Z-To-C: %w", err)
	}
	trace.operationCounts.SpecialB0Transforms++
	if err = validateCiphertextPairState("A2B full special-b0", halves); err != nil {
		return A2BFullResult{}, trace, err
	}
	specialLow, specialHigh := halves[0].CopyNew(), halves[1].CopyNew()
	if err = requireA2BFullState("special low", halves[0], 19); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = requireA2BFullState("special high", halves[1], 19); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageSpecialLow, halves[0]); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageSpecialHigh, halves[1]); err != nil {
		return A2BFullResult{}, trace, err
	}

	iter0Masked, err := e.refresh.applyMask(halves[0], e.circuit.refresh.lowMask, A2BRefreshLowHalf)
	if err != nil {
		return A2BFullResult{}, trace, err
	}
	trace.operationCounts.MaskMulRescales++
	if err = appendState(A2BFullStageIter0Mask, iter0Masked); err != nil {
		return A2BFullResult{}, trace, err
	}
	iter0MaskedSaved := iter0Masked.CopyNew()
	iter0Refreshed, iter0RefreshStates, iter0ErrScale, iter0ErrLog2, err := e.refresh.refreshHalfWithSTC(
		iter0Masked, A2BRefreshLowHalf, e.circuit.refresh.stc, 18, 16,
	)
	if err != nil {
		return A2BFullResult{}, trace, err
	}
	trace.operationCounts.RefreshInvocations++
	trace.operationCounts.SharedCTSUses++
	trace.iter0ErrScale, trace.iter0ErrLog2 = iter0ErrScale, iter0ErrLog2
	if err = appendA2BFullRefreshStates(&trace, 0, iter0RefreshStates); err != nil {
		return A2BFullResult{}, trace, err
	}
	iter0, err := e.kernel0.EvaluateNew(iter0Refreshed)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full iter0 Gao kernel: %w", err)
	}
	trace.operationCounts.KernelInvocations++
	trace.iter0Kernel = iter0.Provenance()
	id0, msb0 := iter0.IDCiphertext(), iter0.MSBCiphertext()
	if err = requireA2BFullState("iter0 ID", id0, 5); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = requireA2BFullState("iter0 MSB", msb0, 5); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageIter0ID, id0); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageIter0MSB, msb0); err != nil {
		return A2BFullResult{}, trace, err
	}
	id0Saved := id0.CopyNew()
	id0Over16, err := e.refresh.bootstrap.Evaluator.MulNew(id0, e.circuit.idScale)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full ID0/16 multiply: %w", err)
	}
	if err = e.refresh.bootstrap.Evaluator.Rescale(id0Over16, id0Over16); err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full ID0/16 rescale: %w", err)
	}
	trace.operationCounts.IDScaleMulRescales++
	if err = requireA2BFullState("ID0/16", id0Over16, 4); err != nil {
		return A2BFullResult{}, trace, err
	}
	if !id0.Equal(id0Saved) {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full ID0/16 mutated ID0")
	}
	if err = appendState(A2BFullStageID0Over16, id0Over16); err != nil {
		return A2BFullResult{}, trace, err
	}
	id0Over16Saved := id0Over16.CopyNew()

	highAligned := specialHigh.CopyNew()
	e.refresh.bootstrap.Evaluator.DropLevel(highAligned, highAligned.Level()-4)
	trace.operationCounts.AlignmentDrops++
	if err = requireA2BFullState("aligned high core", highAligned, 4); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageHighAligned, highAligned); err != nil {
		return A2BFullResult{}, trace, err
	}
	highAlignedSaved := highAligned.CopyNew()
	highUpdated, err := e.refresh.bootstrap.Evaluator.SubNew(highAligned, id0Over16)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full high update: %w", err)
	}
	trace.operationCounts.Subtractions++
	if err = requireA2BFullState("updated high core", highUpdated, 4); err != nil {
		return A2BFullResult{}, trace, err
	}
	highUpdatedSaved := highUpdated.CopyNew()
	if err = appendState(A2BFullStageHighUpdated, highUpdated); err != nil {
		return A2BFullResult{}, trace, err
	}

	lowAligned := specialLow.CopyNew()
	e.refresh.bootstrap.Evaluator.DropLevel(lowAligned, lowAligned.Level()-5)
	trace.operationCounts.AlignmentDrops++
	if err = requireA2BFullState("aligned low core", lowAligned, 5); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageLowAligned, lowAligned); err != nil {
		return A2BFullResult{}, trace, err
	}
	lowAlignedSaved := lowAligned.CopyNew()
	lowSelfRemoved, err := e.refresh.bootstrap.Evaluator.SubNew(lowAligned, id0)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full remove iter0 ID from low core: %w", err)
	}
	trace.operationCounts.Subtractions++
	if err = requireA2BFullState("self-removed low core", lowSelfRemoved, 5); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageLowSelfRemoved, lowSelfRemoved); err != nil {
		return A2BFullResult{}, trace, err
	}

	iter1Masked, err := e.refresh.bootstrap.Evaluator.MulNew(highUpdated, e.circuit.iter1Mask)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full iter1 mask multiply: %w", err)
	}
	if err = e.refresh.bootstrap.Evaluator.Rescale(iter1Masked, iter1Masked); err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full iter1 mask rescale: %w", err)
	}
	trace.operationCounts.MaskMulRescales++
	if err = requireA2BFullState("iter1 mask", iter1Masked, 3); err != nil {
		return A2BFullResult{}, trace, err
	}
	if !highUpdated.Equal(highUpdatedSaved) {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full iter1 mask mutated high core")
	}
	if err = appendState(A2BFullStageIter1Mask, iter1Masked); err != nil {
		return A2BFullResult{}, trace, err
	}
	iter1MaskedSaved := iter1Masked.CopyNew()
	iter1Refreshed, iter1RefreshStates, iter1ErrScale, iter1ErrLog2, err := e.refresh.refreshHalfWithSTC(
		iter1Masked, A2BRefreshHighHalf, e.circuit.secondSTC, 3, 1,
	)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full serial iter1 refresh: %w", err)
	}
	trace.operationCounts.RefreshInvocations++
	trace.operationCounts.SharedCTSUses++
	trace.iter1ErrScale, trace.iter1ErrLog2 = iter1ErrScale, iter1ErrLog2
	if err = appendA2BFullRefreshStates(&trace, 1, iter1RefreshStates); err != nil {
		return A2BFullResult{}, trace, err
	}
	iter1, err := e.kernel1.EvaluateNew(iter1Refreshed)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full iter1 Gao kernel: %w", err)
	}
	trace.operationCounts.KernelInvocations++
	trace.iter1Kernel = iter1.Provenance()
	id1, msb1 := iter1.IDCiphertext(), iter1.MSBCiphertext()
	if err = requireA2BFullState("iter1 ID", id1, 5); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = requireA2BFullState("iter1 MSB", msb1, 5); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageIter1ID, id1); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageIter1MSB, msb1); err != nil {
		return A2BFullResult{}, trace, err
	}
	id1Saved := id1.CopyNew()
	id1Aligned := id1.CopyNew()
	e.refresh.bootstrap.Evaluator.DropLevel(id1Aligned, id1Aligned.Level()-4)
	trace.operationCounts.AlignmentDrops++
	if err = requireA2BFullState("aligned ID1", id1Aligned, 4); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageID1Aligned, id1Aligned); err != nil {
		return A2BFullResult{}, trace, err
	}
	highSelfRemoved, err := e.refresh.bootstrap.Evaluator.SubNew(highUpdated, id1Aligned)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full remove iter1 ID from high core: %w", err)
	}
	trace.operationCounts.Subtractions++
	if err = requireA2BFullState("self-removed high core", highSelfRemoved, 4); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullStageHighSelfRemoved, highSelfRemoved); err != nil {
		return A2BFullResult{}, trace, err
	}
	if !input.Equal(inputBefore) || !specialLow.Equal(halves[0]) || !specialHigh.Equal(halves[1]) ||
		!iter0Masked.Equal(iter0MaskedSaved) || !id0.Equal(id0Saved) || !id0Over16.Equal(id0Over16Saved) ||
		!highAligned.Equal(highAlignedSaved) || !highUpdated.Equal(highUpdatedSaved) ||
		!lowAligned.Equal(lowAlignedSaved) || !iter1Masked.Equal(iter1MaskedSaved) || !id1.Equal(id1Saved) {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B full mutated input or saved serial core")
	}
	if trace.operationCounts != e.circuit.profile.operationCounts {
		return A2BFullResult{}, trace, fmt.Errorf(
			"homchain: A2B full runtime operation ledger=%+v, sealed profile=%+v",
			trace.operationCounts, e.circuit.profile.operationCounts,
		)
	}
	return A2BFullResult{
		lowMSB: msb0, highMSB: msb1, specialLow: specialLow, specialHigh: specialHigh,
		iter0Refreshed: iter0Refreshed, id0: id0, id0Over16: id0Over16,
		highUpdated: highUpdated, lowSelfRemoved: lowSelfRemoved,
		iter1Masked: iter1Masked, iter1Refreshed: iter1Refreshed, id1: id1,
		highSelfRemoved: highSelfRemoved,
	}, trace, nil
}

func (r A2BFullResult) LowMSB() *rlwe.Ciphertext {
	if r.lowMSB == nil {
		return nil
	}
	return r.lowMSB.CopyNew()
}

func (r A2BFullResult) HighMSB() *rlwe.Ciphertext {
	if r.highMSB == nil {
		return nil
	}
	return r.highMSB.CopyNew()
}

func (r A2BFullResult) SpecialB0Low() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.specialLow)
}
func (r A2BFullResult) SpecialB0High() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.specialHigh)
}
func (r A2BFullResult) Iter0Refreshed() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.iter0Refreshed)
}
func (r A2BFullResult) ID0() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.id0)
}
func (r A2BFullResult) ID0Over16() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.id0Over16)
}
func (r A2BFullResult) HighUpdated() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.highUpdated)
}
func (r A2BFullResult) LowSelfRemoved() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.lowSelfRemoved)
}
func (r A2BFullResult) Iter1Masked() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.iter1Masked)
}
func (r A2BFullResult) Iter1Refreshed() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.iter1Refreshed)
}
func (r A2BFullResult) ID1() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.id1)
}
func (r A2BFullResult) HighSelfRemoved() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.highSelfRemoved)
}

func appendA2BFullRefreshStates(trace *A2BFullTrace, iteration int, states []A2BRefreshCiphertextState) error {
	if trace == nil || len(states) != 4 {
		return fmt.Errorf("homchain: A2B full iter%d refresh returned %d states, want 4", iteration, len(states))
	}
	stages := [2][4]A2BFullStage{
		{A2BFullStageIter0STC, A2BFullStageIter0ScaleDown, A2BFullStageIter0ModUp, A2BFullStageIter0CTS},
		{A2BFullStageIter1STC, A2BFullStageIter1ScaleDown, A2BFullStageIter1ModUp, A2BFullStageIter1CTS},
	}
	if iteration < 0 || iteration >= len(stages) {
		return fmt.Errorf("homchain: invalid A2B full refresh iteration %d", iteration)
	}
	for i, state := range states {
		trace.states = append(trace.states, A2BFullCiphertextState{
			Stage: stages[iteration][i], Level: state.Level, Degree: state.Degree,
			LogDimensions: state.LogDimensions, Scale: state.Scale,
		})
	}
	return nil
}

func snapshotA2BFullState(stage A2BFullStage, ciphertext *rlwe.Ciphertext) (A2BFullCiphertextState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return A2BFullCiphertextState{}, fmt.Errorf("homchain: cannot snapshot nil A2B full %s ciphertext", stage)
	}
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return A2BFullCiphertextState{}, fmt.Errorf("homchain: snapshot A2B full %s scale: %w", stage, err)
	}
	return A2BFullCiphertextState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale,
	}, nil
}

func requireA2BFullState(name string, ciphertext *rlwe.Ciphertext, level int) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level || ciphertext.Degree() != 1 ||
		!ciphertext.IsBatched || !ciphertext.IsNTT || !b2aExactScaleEqual(ciphertext.Scale, a2bFullFixedS35Scale()) {
		return fmt.Errorf("homchain: A2B full %s state is not L%d/degree1/exact-S35/full-packed", name, level)
	}
	return nil
}

func a2bFullFixedS35Scale() rlwe.Scale {
	// The fixed canonical parameter profile has exact default scale 2^35.
	return rlwe.NewScale(uint64(1) << 35)
}

func newA2BFullPlaintextFactor(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	level int,
	scale rlwe.Scale,
	mantissaExponent int,
) (*rlwe.Plaintext, error) {
	values := make([]*big.Float, params.MaxSlots())
	for i := range values {
		values[i] = new(big.Float).SetPrec(encoder.Prec()).SetInt64(1)
		values[i].SetMantExp(values[i], mantissaExponent)
	}
	plaintext := ckks.NewPlaintext(params, level)
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: params.LogMaxSlots()}
	plaintext.Scale = scale
	if err := encoder.Encode(values, plaintext); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func digestA2BFullSecondSTCProfile(profile A2BFullSecondSTCProfile, precision uint) string {
	return digestString(fmt.Sprintf(
		"a2b-full-second-stc-v1|raw=%v|execution=%v|precision=%d|raw-matrix=%s|execution-matrix=%s",
		dftLiteralTrace(profile.rawLiteral), dftLiteralTrace(profile.executionLiteral), precision,
		profile.rawMatrixDigest, profile.matrixDigest,
	))
}

func digestA2BFullProfile(profile A2BFullProfile) string {
	canonical := strings.Builder{}
	fmt.Fprintf(&canonical,
		"a2b-full-profile-v1|fidelity=%s|schedule=%s|word=%d|chunk=%d|depth=%d|words=%d|slots=%d|input-level=%d|input-scale={%s}|cutoff=%d|output=%v|bit-order=%s|first-refresh=%s|first-stc=%s|second-stc=%s|shared-cts=%t,%s|kernels=%v|kernel-artifacts=%s|keys=%s|params=%s|mask=%s|id-scale=%s|counts=%+v|ledger=%s|normalized-certified=%t|normalized-invariant=%s",
		profile.fidelity, profile.schedule, profile.wordBits, profile.chunkWidth, profile.depth,
		profile.words, profile.slots, profile.inputLevel, profile.inputScale.canonicalString(), profile.cutoff,
		profile.outputOrder, profile.bitOrder, profile.firstRefreshDigest, profile.firstSTCDigest,
		profile.secondSTC.digest, profile.sharedCTS, profile.sharedCTSDigest, profile.kernelDigests,
		profile.kernelArtifactDigest, profile.keyDigest, profile.parameterDigest, profile.maskDigest,
		profile.idScaleDigest, profile.operationCounts, profile.levelLedger, profile.normalizedCertified,
		profile.normalizedInvariant,
	)
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:])
}
