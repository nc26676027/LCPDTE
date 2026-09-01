package homchain

import (
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	ckksdft "github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	ckkslintrans "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	ckkspolynomial "github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	signed8Depth2ChildSelectorDecodeProfileSchema = "signed8-depth2-child-selector-decode-profile-v1"
	signed8Depth2ChildSelectorDecodeInputSchema   = "signed8-depth2-child-selector-decode-input-v1"
	signed8Depth2ChildSelectorDecodeResultSchema  = "signed8-depth2-child-selector-decode-result-v1"
	signed8Depth2ChildSelectorDecodeTraceSchema   = "signed8-depth2-child-selector-decode-trace-v2"
)

type Signed8Depth2ChildSelectorDecodeStage string

const (
	Signed8Depth2ChildSelectorStageInput        Signed8Depth2ChildSelectorDecodeStage = "child-arithmetic-selector"
	Signed8Depth2ChildSelectorStageVRaw         Signed8Depth2ChildSelectorDecodeStage = "normal-V-projected-raw"
	Signed8Depth2ChildSelectorStageV            Signed8Depth2ChildSelectorDecodeStage = "normal-V-rescaled"
	Signed8Depth2ChildSelectorStageSTCFactor0   Signed8Depth2ChildSelectorDecodeStage = "low-level-STC-factor-0"
	Signed8Depth2ChildSelectorStageSTCFactor1   Signed8Depth2ChildSelectorDecodeStage = "low-level-STC-factor-1"
	Signed8Depth2ChildSelectorStageScaleDown    Signed8Depth2ChildSelectorDecodeStage = "guarded-scale-down"
	Signed8Depth2ChildSelectorStageModUp        Signed8Depth2ChildSelectorDecodeStage = "dense-no-switch-mod-up"
	Signed8Depth2ChildSelectorStageCTSFactor0   Signed8Depth2ChildSelectorDecodeStage = "shared-CTS-factor-0"
	Signed8Depth2ChildSelectorStageCTSFactor1   Signed8Depth2ChildSelectorDecodeStage = "shared-CTS-factor-1"
	Signed8Depth2ChildSelectorStageCTSFactor2   Signed8Depth2ChildSelectorDecodeStage = "shared-CTS-factor-2"
	Signed8Depth2ChildSelectorStageCTS          Signed8Depth2ChildSelectorDecodeStage = "shared-CTS-split"
	Signed8Depth2ChildSelectorStagePeriodicExp  Signed8Depth2ChildSelectorDecodeStage = "accepted-exp46"
	Signed8Depth2ChildSelectorStagePeriodicSq0  Signed8Depth2ChildSelectorDecodeStage = "periodic-square-0"
	Signed8Depth2ChildSelectorStagePeriodicRoot Signed8Depth2ChildSelectorDecodeStage = "periodic-root-of-unity"
	Signed8Depth2ChildSelectorStageAffineRaw    Signed8Depth2ChildSelectorDecodeStage = "slotwise-affine-product-raw"
	Signed8Depth2ChildSelectorStageOutput       Signed8Depth2ChildSelectorDecodeStage = "decoded-child-selector"
)

type Signed8Depth2ChildSelectorDecodeLane string

const (
	Signed8Depth2ChildSelectorDecodeWhole Signed8Depth2ChildSelectorDecodeLane = "whole"
	Signed8Depth2ChildSelectorDecodeLow   Signed8Depth2ChildSelectorDecodeLane = "low"
	Signed8Depth2ChildSelectorDecodeHigh  Signed8Depth2ChildSelectorDecodeLane = "high"
)

type Signed8Depth2ChildSelectorDecodeOperationCounts struct {
	LinearTransformations            int
	DiagonalPlaintextProducts        int
	NonConjugationRotations          int
	Conjugations                     int
	KeySwitches                      int
	CiphertextAdditionsSubtractions  int
	ScalarMultiplicationsPlusMinusI  int
	ExplicitRescales                 int
	ScaleDown                        int
	ModUp                            int
	ExponentialPolynomialEvaluations int
	CiphertextCiphertextProducts     int
	Relinearizations                 int
	CiphertextPlaintextProducts      int
	PlaintextVectorAdditions         int
	IDMSBLUTEvaluations              int
}

type Signed8Depth2ChildSelectorDecodeSerializedBytes struct {
	ChildArithmeticInput        int
	RetainedNormalVLow          int
	RetainedNormalVHigh         int
	RetainedSlotsToCoeffs       int
	RetainedRaisedCoefficients  int
	RetainedCoeffsToSlotsLow    int
	RetainedCoeffsToSlotsHigh   int
	RetainedExponentialBase     int
	RetainedPeriodicRootOfUnity int
	DecodedChildSelector        int
}

func (s Signed8Depth2ChildSelectorDecodeSerializedBytes) InternalBoundaryTotal() int {
	return s.ChildArithmeticInput + s.DecodedChildSelector
}

func (s Signed8Depth2ChildSelectorDecodeSerializedBytes) RetainedTraceTotal() int {
	return s.RetainedNormalVLow + s.RetainedNormalVHigh + s.RetainedSlotsToCoeffs +
		s.RetainedRaisedCoefficients + s.RetainedCoeffsToSlotsLow + s.RetainedCoeffsToSlotsHigh +
		s.RetainedExponentialBase + s.RetainedPeriodicRootOfUnity
}

func (s Signed8Depth2ChildSelectorDecodeSerializedBytes) ModuleTotal() int {
	return s.InternalBoundaryTotal() + s.RetainedTraceTotal()
}

func (s Signed8Depth2ChildSelectorDecodeSerializedBytes) complete() bool {
	return s.ChildArithmeticInput > 0 && s.DecodedChildSelector > 0 &&
		s.RetainedNormalVLow > 0 && s.RetainedNormalVHigh > 0 && s.RetainedSlotsToCoeffs > 0 &&
		s.RetainedRaisedCoefficients > 0 && s.RetainedCoeffsToSlotsLow > 0 &&
		s.RetainedCoeffsToSlotsHigh > 0 && s.RetainedExponentialBase > 0 &&
		s.RetainedPeriodicRootOfUnity > 0
}

type Signed8Depth2ChildSelectorDecodeStateProfile struct {
	level int
	scale ExactScaleSnapshot
}

func (s Signed8Depth2ChildSelectorDecodeStateProfile) Level() int                { return s.level }
func (s Signed8Depth2ChildSelectorDecodeStateProfile) Scale() ExactScaleSnapshot { return s.scale }

type Signed8Depth2ChildSelectorDecodeCiphertextState struct {
	Stage         Signed8Depth2ChildSelectorDecodeStage
	Lane          Signed8Depth2ChildSelectorDecodeLane
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

type Signed8Depth2ChildSelectorDecodeProfile struct {
	fidelity                                   SelectorReraiseDecodeFidelity
	wordBits                                   z2n.WordBits
	words, slots                               int
	encoderPrecision, integerPrecision         uint
	parameterDigest, protocolRangeDigest       string
	treeDigest, scheduleDigest                 string
	childProfileDigest, prefixProfileDigest    string
	baseSelectorProfileDigest                  string
	producerPublicDigest, producerOpaqueDigest string
	representation                             SelectorReraiseDecodeRepresentation
	resultSchema                               string
	normalV                                    SelectorReraiseDecodeTransformProfile
	dft                                        SelectorReraiseDecodeDFTProfile
	periodic                                   SelectorReraiseDecodePeriodicProfile
	operationCounts                            Signed8Depth2ChildSelectorDecodeOperationCounts
	serializedBytes                            Signed8Depth2ChildSelectorDecodeSerializedBytes
	logicalPeak                                int
	states                                     []Signed8Depth2ChildSelectorDecodeStateProfile
	digest                                     string
}

func (p Signed8Depth2ChildSelectorDecodeProfile) Fidelity() SelectorReraiseDecodeFidelity {
	return p.fidelity
}
func (p Signed8Depth2ChildSelectorDecodeProfile) WordBits() z2n.WordBits { return p.wordBits }
func (p Signed8Depth2ChildSelectorDecodeProfile) Words() int             { return p.words }
func (p Signed8Depth2ChildSelectorDecodeProfile) Slots() int             { return p.slots }
func (p Signed8Depth2ChildSelectorDecodeProfile) EncoderPrecision() uint {
	return p.encoderPrecision
}
func (p Signed8Depth2ChildSelectorDecodeProfile) IntegerPrecision() uint {
	return p.integerPrecision
}
func (p Signed8Depth2ChildSelectorDecodeProfile) ParameterDigest() string { return p.parameterDigest }
func (p Signed8Depth2ChildSelectorDecodeProfile) ProtocolRangeDigest() string {
	return p.protocolRangeDigest
}
func (p Signed8Depth2ChildSelectorDecodeProfile) TreeDigest() string     { return p.treeDigest }
func (p Signed8Depth2ChildSelectorDecodeProfile) ScheduleDigest() string { return p.scheduleDigest }
func (p Signed8Depth2ChildSelectorDecodeProfile) ChildProfileDigest() string {
	return p.childProfileDigest
}
func (p Signed8Depth2ChildSelectorDecodeProfile) PrefixProfileDigest() string {
	return p.prefixProfileDigest
}
func (p Signed8Depth2ChildSelectorDecodeProfile) BaseSelectorProfileDigest() string {
	return p.baseSelectorProfileDigest
}
func (p Signed8Depth2ChildSelectorDecodeProfile) ProducerPublicProfileDigest() string {
	return p.producerPublicDigest
}
func (p Signed8Depth2ChildSelectorDecodeProfile) ProducerOpaqueProfileDigest() string {
	return p.producerOpaqueDigest
}
func (p Signed8Depth2ChildSelectorDecodeProfile) SelectorRepresentation() SelectorReraiseDecodeRepresentation {
	return p.representation
}
func (p Signed8Depth2ChildSelectorDecodeProfile) ResultSchema() string { return p.resultSchema }
func (p Signed8Depth2ChildSelectorDecodeProfile) NormalV() SelectorReraiseDecodeTransformProfile {
	return cloneSelectorReraiseDecodeTransformProfile(p.normalV)
}
func (p Signed8Depth2ChildSelectorDecodeProfile) DFT() SelectorReraiseDecodeDFTProfile {
	return cloneSelectorReraiseDecodeDFTProfile(p.dft)
}
func (p Signed8Depth2ChildSelectorDecodeProfile) Periodic() SelectorReraiseDecodePeriodicProfile {
	return p.periodic
}
func (p Signed8Depth2ChildSelectorDecodeProfile) OperationCounts() Signed8Depth2ChildSelectorDecodeOperationCounts {
	return p.operationCounts
}
func (p Signed8Depth2ChildSelectorDecodeProfile) ExpectedSerializedBytes() Signed8Depth2ChildSelectorDecodeSerializedBytes {
	return p.serializedBytes
}
func (p Signed8Depth2ChildSelectorDecodeProfile) LogicalPeakLiveCiphertexts() int {
	return p.logicalPeak
}
func (p Signed8Depth2ChildSelectorDecodeProfile) States() []Signed8Depth2ChildSelectorDecodeStateProfile {
	return append([]Signed8Depth2ChildSelectorDecodeStateProfile(nil), p.states...)
}
func (p Signed8Depth2ChildSelectorDecodeProfile) Digest() string { return p.digest }

type signed8Depth2ChildSelectorDecodeCircuitGraph struct {
	circuit                                *Signed8Depth2ChildSelectorDecodeCircuit
	child                                  *Signed8Depth2ChildComparatorCircuit
	prefix                                 *Signed8Depth2SourcePrefixCircuit
	base                                   *SelectorReraiseDecodeCircuit
	affineMultiplierSeal, affineOffsetSeal *rlwe.Plaintext
	profileDigest                          string
	keyDigest                              string
	childProfileDigest                     string
	prefixProfileDigest                    string
	baseSelectorProfileDigest              string
}

type Signed8Depth2ChildSelectorDecodeCircuit struct {
	child                                  *Signed8Depth2ChildComparatorCircuit
	prefix                                 *Signed8Depth2SourcePrefixCircuit
	base                                   *SelectorReraiseDecodeCircuit
	params                                 ckks.Parameters
	profile                                Signed8Depth2ChildSelectorDecodeProfile
	keyProfile                             SelectorReraiseDecodeKeyProfile
	affineMultiplierSeal, affineOffsetSeal *rlwe.Plaintext
	graph                                  signed8Depth2ChildSelectorDecodeCircuitGraph
}

// Signed8Depth2ChildSelectorDecodeInput is minted only from one exact
// child-input/result pair. It owns independent copies of the complete pair
// and of the arithmetic child branch consumed by the decoder.
type Signed8Depth2ChildSelectorDecodeInput struct {
	branch                      *rlwe.Ciphertext
	childInput                  Signed8Depth2ChildComparatorInput
	childResult                 Signed8Depth2ChildComparatorResult
	profileDigest               string
	childProfileDigest          string
	prefixProfileDigest         string
	parameterDigest             string
	protocolRangeDigest         string
	treeDigest                  string
	scheduleDigest              string
	producerProfileDigest       string
	operandMode                 Signed8ComparatorOperandMode
	childInputBindingDigest     string
	childResultProvenanceDigest string
	operandsProvenanceDigest    string
	payloadDigest               string
	provenanceDigest            string
}

func (i Signed8Depth2ChildSelectorDecodeInput) ProducerProfileDigest() string {
	return i.producerProfileDigest
}
func (i Signed8Depth2ChildSelectorDecodeInput) OperandMode() Signed8ComparatorOperandMode {
	return i.operandMode
}
func (i Signed8Depth2ChildSelectorDecodeInput) ChildInputBindingDigest() string {
	return i.childInputBindingDigest
}
func (i Signed8Depth2ChildSelectorDecodeInput) ChildResultProvenanceDigest() string {
	return i.childResultProvenanceDigest
}
func (i Signed8Depth2ChildSelectorDecodeInput) OperandsProvenanceDigest() string {
	return i.operandsProvenanceDigest
}
func (i Signed8Depth2ChildSelectorDecodeInput) ProvenanceDigest() string {
	return i.provenanceDigest
}

// BindChildResult authenticates both halves of the closed child producer
// seam before copying any ciphertext. No root comparator result is created or
// retagged here.
func (c *Signed8Depth2ChildSelectorDecodeCircuit) BindChildResult(
	childInput Signed8Depth2ChildComparatorInput,
	childResult Signed8Depth2ChildComparatorResult,
) (Signed8Depth2ChildSelectorDecodeInput, error) {
	if err := c.validate(); err != nil {
		return Signed8Depth2ChildSelectorDecodeInput{}, err
	}
	if err := c.child.validateInput(childInput); err != nil {
		return Signed8Depth2ChildSelectorDecodeInput{}, fmt.Errorf("homchain: validate depth2 child decoder input producer: %w", err)
	}
	if err := c.child.validateResult(childResult); err != nil {
		return Signed8Depth2ChildSelectorDecodeInput{}, fmt.Errorf("homchain: validate depth2 child decoder result producer: %w", err)
	}
	if childResult.inputBindingDigest != childInput.bindingDigest ||
		childResult.operandsProvenanceDigest != childInput.operandsProvenance ||
		childInput.operands.provenanceDigest != childInput.operandsProvenance {
		return Signed8Depth2ChildSelectorDecodeInput{}, fmt.Errorf("homchain: depth2 child decoder input/result pair provenance differs")
	}
	if childResult.profileDigest != c.child.profile.digest ||
		childResult.parameterDigest != c.profile.parameterDigest ||
		childResult.protocolRangeDigest != c.profile.protocolRangeDigest ||
		childResult.treeDigest != c.profile.treeDigest || childResult.scheduleDigest != c.profile.scheduleDigest ||
		childInput.profileDigest != c.child.profile.digest ||
		childInput.operands.profileDigest != c.prefix.profile.digest ||
		childInput.operands.parameterDigest != c.profile.parameterDigest ||
		childInput.operands.rangeDigest != c.profile.protocolRangeDigest ||
		childInput.operands.treeDigest != c.profile.treeDigest ||
		childInput.operands.scheduleDigest != c.profile.scheduleDigest {
		return Signed8Depth2ChildSelectorDecodeInput{}, fmt.Errorf("homchain: depth2 child decoder pair has a foreign child, prefix, parameter, range, tree, or schedule")
	}
	mode := selectorModeFromProducerDigest(c.base.producer, childInput.operands.producerProfileDigest)
	producer := c.base.producer.profileForMode(mode)
	if mode != Signed8PublicThresholdCTPT && mode != Signed8OpaqueThresholdCTCT ||
		producer.digest == "" || producer.digest != childInput.operands.producerProfileDigest ||
		producer.digest != map[Signed8ComparatorOperandMode]string{
			Signed8PublicThresholdCTPT: c.profile.producerPublicDigest,
			Signed8OpaqueThresholdCTCT: c.profile.producerOpaqueDigest,
		}[mode] {
		return Signed8Depth2ChildSelectorDecodeInput{}, fmt.Errorf("homchain: depth2 child decoder producer mode is foreign")
	}

	ownedChildInput := cloneSigned8Depth2ChildComparatorInput(childInput)
	ownedChildResult := cloneSigned8Depth2ChildComparatorResult(childResult)
	ownedBranch := copyA2BRefreshCiphertext(childResult.branch)
	payloadDigest, err := signed8CiphertextDigest(ownedBranch)
	if err != nil {
		return Signed8Depth2ChildSelectorDecodeInput{}, err
	}
	input := Signed8Depth2ChildSelectorDecodeInput{
		branch: ownedBranch, childInput: ownedChildInput, childResult: ownedChildResult,
		profileDigest: c.profile.digest, childProfileDigest: c.child.profile.digest,
		prefixProfileDigest: c.prefix.profile.digest, parameterDigest: c.profile.parameterDigest,
		protocolRangeDigest: c.profile.protocolRangeDigest, treeDigest: c.profile.treeDigest,
		scheduleDigest: c.profile.scheduleDigest, producerProfileDigest: producer.digest,
		operandMode: mode, childInputBindingDigest: childInput.bindingDigest,
		childResultProvenanceDigest: childResult.provenanceDigest,
		operandsProvenanceDigest:    childInput.operandsProvenance, payloadDigest: payloadDigest,
	}
	input.provenanceDigest = digestSigned8Depth2ChildSelectorDecodeInput(input)
	if err = c.validateInput(input); err != nil {
		return Signed8Depth2ChildSelectorDecodeInput{}, err
	}
	return input, nil
}

func (c *Signed8Depth2ChildSelectorDecodeCircuit) validateInput(
	input Signed8Depth2ChildSelectorDecodeInput,
) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := c.child.validateInput(input.childInput); err != nil {
		return err
	}
	if err := c.child.validateResult(input.childResult); err != nil {
		return err
	}
	if input.branch == nil || input.childResult.branch == nil {
		return fmt.Errorf("homchain: nil depth2 child selector decoder input")
	}
	if input.childResult.inputBindingDigest != input.childInput.bindingDigest ||
		input.childResult.operandsProvenanceDigest != input.childInput.operandsProvenance ||
		input.childInput.operands.provenanceDigest != input.childInput.operandsProvenance ||
		input.childInputBindingDigest != input.childInput.bindingDigest ||
		input.childResultProvenanceDigest != input.childResult.provenanceDigest ||
		input.operandsProvenanceDigest != input.childInput.operandsProvenance ||
		!input.branch.Equal(input.childResult.branch) {
		return fmt.Errorf("homchain: depth2 child selector decoder closed pair changed")
	}
	mode := selectorModeFromProducerDigest(c.base.producer, input.childInput.operands.producerProfileDigest)
	producer := c.base.producer.profileForMode(mode)
	payloadDigest, err := signed8CiphertextDigest(input.branch)
	if err != nil {
		return err
	}
	if err = requireSigned8Depth2State("depth2 child decoder arithmetic input", input.branch, 4, c.params.DefaultScale(), c.params); err != nil {
		return err
	}
	if producer.digest == "" || (mode != Signed8PublicThresholdCTPT && mode != Signed8OpaqueThresholdCTCT) ||
		input.profileDigest != c.profile.digest || input.childProfileDigest != c.child.profile.digest ||
		input.prefixProfileDigest != c.prefix.profile.digest || input.parameterDigest != c.profile.parameterDigest ||
		input.protocolRangeDigest != c.profile.protocolRangeDigest || input.treeDigest != c.profile.treeDigest ||
		input.scheduleDigest != c.profile.scheduleDigest || input.producerProfileDigest != producer.digest ||
		input.producerProfileDigest != input.childInput.operands.producerProfileDigest || input.operandMode != mode ||
		input.payloadDigest != payloadDigest || input.payloadDigest != input.childResult.outputPayloadDigest ||
		input.provenanceDigest != digestSigned8Depth2ChildSelectorDecodeInput(input) {
		return fmt.Errorf("homchain: depth2 child selector decoder input profile, mode, payload, or provenance changed")
	}
	return nil
}

func cloneSigned8Depth2ChildComparatorInput(
	input Signed8Depth2ChildComparatorInput,
) Signed8Depth2ChildComparatorInput {
	input.operands = cloneSigned8Depth2ChildOperands(input.operands)
	return input
}

func cloneSigned8Depth2ChildComparatorResult(
	result Signed8Depth2ChildComparatorResult,
) Signed8Depth2ChildComparatorResult {
	result.branch = copyA2BRefreshCiphertext(result.branch)
	return result
}

func cloneSigned8Depth2ChildSelectorDecodeInput(
	input Signed8Depth2ChildSelectorDecodeInput,
) Signed8Depth2ChildSelectorDecodeInput {
	input.branch = copyA2BRefreshCiphertext(input.branch)
	input.childInput = cloneSigned8Depth2ChildComparatorInput(input.childInput)
	input.childResult = cloneSigned8Depth2ChildComparatorResult(input.childResult)
	return input
}

func digestSigned8Depth2ChildSelectorDecodeInput(input Signed8Depth2ChildSelectorDecodeInput) string {
	return digestString(fmt.Sprintf(
		"%s|profile=%s|child=%s|prefix=%s|parameters=%s|protocol-range=%s|tree=%s|schedule=%s|producer=%s|mode=%s|child-input=%s|child-result=%s|operands=%s|payload=%s|representation=%s",
		signed8Depth2ChildSelectorDecodeInputSchema, input.profileDigest, input.childProfileDigest,
		input.prefixProfileDigest, input.parameterDigest, input.protocolRangeDigest, input.treeDigest,
		input.scheduleDigest, input.producerProfileDigest, input.operandMode, input.childInputBindingDigest,
		input.childResultProvenanceDigest, input.operandsProvenanceDigest, input.payloadDigest,
		SelectorArithmeticRootCoefficientsToPeriodicBooleanScalarRepeated,
	))
}

type Signed8Depth2ChildSelectorDecodeResult struct {
	selector                    *rlwe.Ciphertext
	profileDigest               string
	childProfileDigest          string
	prefixProfileDigest         string
	parameterDigest             string
	protocolRangeDigest         string
	treeDigest                  string
	scheduleDigest              string
	producerProfileDigest       string
	operandMode                 Signed8ComparatorOperandMode
	path                        SelectorReraiseDecodePath
	inputProvenanceDigest       string
	childInputBindingDigest     string
	childResultProvenanceDigest string
	operandsProvenanceDigest    string
	outputPayloadDigest         string
	provenanceDigest            string
}

func (r Signed8Depth2ChildSelectorDecodeResult) Ciphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.selector)
}
func (r Signed8Depth2ChildSelectorDecodeResult) ProfileDigest() string { return r.profileDigest }
func (r Signed8Depth2ChildSelectorDecodeResult) ChildProfileDigest() string {
	return r.childProfileDigest
}
func (r Signed8Depth2ChildSelectorDecodeResult) PrefixProfileDigest() string {
	return r.prefixProfileDigest
}
func (r Signed8Depth2ChildSelectorDecodeResult) ProducerProfileDigest() string {
	return r.producerProfileDigest
}
func (r Signed8Depth2ChildSelectorDecodeResult) OperandMode() Signed8ComparatorOperandMode {
	return r.operandMode
}
func (r Signed8Depth2ChildSelectorDecodeResult) Path() SelectorReraiseDecodePath { return r.path }
func (r Signed8Depth2ChildSelectorDecodeResult) InputProvenanceDigest() string {
	return r.inputProvenanceDigest
}
func (r Signed8Depth2ChildSelectorDecodeResult) ChildInputBindingDigest() string {
	return r.childInputBindingDigest
}
func (r Signed8Depth2ChildSelectorDecodeResult) ChildResultProvenanceDigest() string {
	return r.childResultProvenanceDigest
}
func (r Signed8Depth2ChildSelectorDecodeResult) OperandsProvenanceDigest() string {
	return r.operandsProvenanceDigest
}
func (r Signed8Depth2ChildSelectorDecodeResult) OutputPayloadDigest() string {
	return r.outputPayloadDigest
}
func (r Signed8Depth2ChildSelectorDecodeResult) ProvenanceDigest() string { return r.provenanceDigest }
func (r Signed8Depth2ChildSelectorDecodeResult) Digest() string           { return r.provenanceDigest }

type Signed8Depth2ChildSelectorDecodeTrace struct {
	profileDigest               string
	childProfileDigest          string
	prefixProfileDigest         string
	producerProfileDigest       string
	operandMode                 Signed8ComparatorOperandMode
	path                        SelectorReraiseDecodePath
	inputProvenanceDigest       string
	childInputBindingDigest     string
	childResultProvenanceDigest string
	operandsProvenanceDigest    string
	failureStage                Signed8Depth2ChildSelectorDecodeStage
	states                      []Signed8Depth2ChildSelectorDecodeCiphertextState
	operationCounts             Signed8Depth2ChildSelectorDecodeOperationCounts
	// attemptedOperationLowerBound records completed primitives plus the
	// top-level helper dispatch known to have begun. Nested helper internals are
	// opaque here, so this is deliberately not an exact primitive-attempt count.
	attemptedOperationLowerBound Signed8Depth2ChildSelectorDecodeOperationCounts
	serializedBytes              Signed8Depth2ChildSelectorDecodeSerializedBytes
	keyPreflight                 A2BRefreshKeyPreflight
	scaleDownError               ExactScaleSnapshot
	scaleDownLog2Error           float64
	logicalPeakLive              int
	wallTime                     time.Duration
	normalVLow, normalVHigh      *rlwe.Ciphertext
	stc, raised                  *rlwe.Ciphertext
	ctsLow, ctsHigh              *rlwe.Ciphertext
	exponential, periodicRoot    *rlwe.Ciphertext
	outputPayloadDigest          string
	resultProvenanceDigest       string
	traceDigest                  string
}

func (t Signed8Depth2ChildSelectorDecodeTrace) ProfileDigest() string { return t.profileDigest }
func (t Signed8Depth2ChildSelectorDecodeTrace) ChildProfileDigest() string {
	return t.childProfileDigest
}
func (t Signed8Depth2ChildSelectorDecodeTrace) PrefixProfileDigest() string {
	return t.prefixProfileDigest
}
func (t Signed8Depth2ChildSelectorDecodeTrace) ProducerProfileDigest() string {
	return t.producerProfileDigest
}
func (t Signed8Depth2ChildSelectorDecodeTrace) OperandMode() Signed8ComparatorOperandMode {
	return t.operandMode
}
func (t Signed8Depth2ChildSelectorDecodeTrace) Path() SelectorReraiseDecodePath { return t.path }
func (t Signed8Depth2ChildSelectorDecodeTrace) InputProvenanceDigest() string {
	return t.inputProvenanceDigest
}
func (t Signed8Depth2ChildSelectorDecodeTrace) ChildInputBindingDigest() string {
	return t.childInputBindingDigest
}
func (t Signed8Depth2ChildSelectorDecodeTrace) ChildResultProvenanceDigest() string {
	return t.childResultProvenanceDigest
}
func (t Signed8Depth2ChildSelectorDecodeTrace) OperandsProvenanceDigest() string {
	return t.operandsProvenanceDigest
}
func (t Signed8Depth2ChildSelectorDecodeTrace) FailureStage() Signed8Depth2ChildSelectorDecodeStage {
	return t.failureStage
}
func (t Signed8Depth2ChildSelectorDecodeTrace) States() []Signed8Depth2ChildSelectorDecodeCiphertextState {
	return append([]Signed8Depth2ChildSelectorDecodeCiphertextState(nil), t.states...)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) OperationCounts() Signed8Depth2ChildSelectorDecodeOperationCounts {
	return t.operationCounts
}
func (t Signed8Depth2ChildSelectorDecodeTrace) AttemptedOperationLowerBound() Signed8Depth2ChildSelectorDecodeOperationCounts {
	return t.attemptedOperationLowerBound
}
func (t Signed8Depth2ChildSelectorDecodeTrace) SerializedBytes() Signed8Depth2ChildSelectorDecodeSerializedBytes {
	return t.serializedBytes
}
func (t Signed8Depth2ChildSelectorDecodeTrace) KeyPreflight() A2BRefreshKeyPreflight {
	return cloneA2BRefreshKeyPreflight(t.keyPreflight)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) ScaleDownError() (ExactScaleSnapshot, float64) {
	return t.scaleDownError, t.scaleDownLog2Error
}
func (t Signed8Depth2ChildSelectorDecodeTrace) LogicalPeakLiveCiphertexts() int {
	return t.logicalPeakLive
}
func (t Signed8Depth2ChildSelectorDecodeTrace) WallTime() time.Duration { return t.wallTime }
func (t Signed8Depth2ChildSelectorDecodeTrace) NormalVLow() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.normalVLow)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) NormalVHigh() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.normalVHigh)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) SlotsToCoeffs() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.stc)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) RaisedCoefficients() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.raised)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) CoeffsToSlotsLow() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.ctsLow)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) CoeffsToSlotsHigh() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.ctsHigh)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) ExponentialBase() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.exponential)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) PeriodicRootOfUnity() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.periodicRoot)
}
func (t Signed8Depth2ChildSelectorDecodeTrace) OutputPayloadDigest() string {
	return t.outputPayloadDigest
}
func (t Signed8Depth2ChildSelectorDecodeTrace) ResultProvenanceDigest() string {
	return t.resultProvenanceDigest
}
func (t Signed8Depth2ChildSelectorDecodeTrace) Digest() string { return t.traceDigest }

type signed8Depth2ChildSelectorDecodeEvaluatorGraph struct {
	evaluator              *Signed8Depth2ChildSelectorDecodeEvaluator
	circuit                *Signed8Depth2ChildSelectorDecodeCircuit
	source                 *bootstrapping.Evaluator
	sourceEvaluationKeys   *bootstrapping.EvaluationKeys
	base                   *SelectorReraiseDecodeEvaluator
	keySet                 *rlwe.MemEvaluationKeySet
	relinearizationKey     *rlwe.RelinearizationKey
	relinearizationBinding signed8Depth2ChildRelinearizationKeyBinding
	galoisKeys             map[uint64]*rlwe.GaloisKey
	galoisMapPointer       uintptr
	galoisBindings         map[uint64]signed8Depth2ChildGaloisKeyBinding
	profileDigest          string
	keyDigest              string
	sourceParameters       string
	sourceExecution        string
	sourceCKKS             ckks.EvaluatorRuntimeIdentity
	sourceDFT              ckksdft.EvaluatorRuntimeIdentity
	linear                 ckkslintrans.EvaluatorRuntimeIdentity
	kernelSource           ckks.EvaluatorRuntimeIdentity
	kernelCKKS             ckks.EvaluatorRuntimeIdentity
	kernelPolynomial       ckkspolynomial.EvaluatorRuntimeIdentity
	kernelEncoder          ckks.EncoderRuntimeIdentity
}

type Signed8Depth2ChildSelectorDecodeEvaluator struct {
	circuit            *Signed8Depth2ChildSelectorDecodeCircuit
	source             *bootstrapping.Evaluator
	base               *SelectorReraiseDecodeEvaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	galoisKeys         map[uint64]*rlwe.GaloisKey
	graph              signed8Depth2ChildSelectorDecodeEvaluatorGraph
}

func (c *Signed8Depth2ChildSelectorDecodeCircuit) BindEvaluator(
	source *bootstrapping.Evaluator,
) (*Signed8Depth2ChildSelectorDecodeEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if source == nil || source.EvaluationKeys == nil || source.Evaluator == nil ||
		source.DFTEvaluator == nil || source.DFTEvaluator.LTEvaluator == nil ||
		source.MemEvaluationKeySet == nil {
		return nil, fmt.Errorf("homchain: depth2 child selector decoder source is nil or incomplete")
	}
	base, err := c.base.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind depth2 child selector helper graph: %w", err)
	}
	if base.circuit != c.base || base.source != source || base.keySet != source.MemEvaluationKeySet ||
		base.linear != source.DFTEvaluator.LTEvaluator || base.kernel == nil {
		return nil, fmt.Errorf("homchain: depth2 child selector helper graph is foreign")
	}
	keySet := source.MemEvaluationKeySet
	relinearizationKey, err := keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, fmt.Errorf("homchain: depth2 child selector relinearization key is missing: %v", err)
	}
	relinearizationBinding, err := captureSigned8Depth2ChildRelinearizationKeyBinding(
		relinearizationKey, c.params.GetRLWEParameters(),
	)
	if err != nil {
		return nil, err
	}
	provided := append([]uint64(nil), keySet.GetGaloisKeysList()...)
	sort.Slice(provided, func(i, j int) bool { return provided[i] < provided[j] })
	if !equalSigned8Depth2ChildGalois(provided, c.keyProfile.all) {
		return nil, fmt.Errorf("homchain: depth2 child selector key inventory=%v, want %v", provided, c.keyProfile.all)
	}
	galoisKeys := make(map[uint64]*rlwe.GaloisKey, len(c.keyProfile.all))
	galoisBindings := make(map[uint64]signed8Depth2ChildGaloisKeyBinding, len(c.keyProfile.all))
	for _, element := range c.keyProfile.all {
		key, keyErr := keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil {
			return nil, fmt.Errorf("homchain: depth2 child selector Galois key %d is missing: %v", element, keyErr)
		}
		binding, bindingErr := captureSigned8Depth2ChildGaloisKeyBinding(key, c.params.GetRLWEParameters())
		if bindingErr != nil {
			return nil, bindingErr
		}
		if binding.element != element || binding.nthRoot != c.params.RingQ().NthRoot() {
			return nil, fmt.Errorf("homchain: depth2 child selector Galois key %d is foreign", element)
		}
		galoisKeys[element] = key
		galoisBindings[element] = binding
	}
	evaluator := &Signed8Depth2ChildSelectorDecodeEvaluator{
		circuit: c, source: source, base: base, keySet: keySet,
		relinearizationKey: relinearizationKey, galoisKeys: galoisKeys,
	}
	graph, err := captureSigned8Depth2ChildSelectorDecodeEvaluatorGraph(
		evaluator, source.EvaluationKeys, relinearizationBinding, galoisBindings,
	)
	if err != nil {
		return nil, err
	}
	evaluator.graph = graph
	if _, err = evaluator.preflight(); err != nil {
		return nil, err
	}
	return evaluator, nil
}

func captureSigned8Depth2ChildSelectorDecodeEvaluatorGraph(
	evaluator *Signed8Depth2ChildSelectorDecodeEvaluator,
	evaluationKeys *bootstrapping.EvaluationKeys,
	relinearizationBinding signed8Depth2ChildRelinearizationKeyBinding,
	galoisBindings map[uint64]signed8Depth2ChildGaloisKeyBinding,
) (signed8Depth2ChildSelectorDecodeEvaluatorGraph, error) {
	var graph signed8Depth2ChildSelectorDecodeEvaluatorGraph
	if evaluator == nil || evaluator.circuit == nil || evaluator.source == nil || evaluator.base == nil ||
		evaluator.base.kernel == nil || evaluator.base.kernel.source == nil || evaluator.base.kernel.ckks == nil ||
		evaluator.base.kernel.polynomial == nil || evaluator.base.kernel.operationalEncoder == nil {
		return graph, fmt.Errorf("homchain: cannot seal incomplete depth2 child selector evaluator")
	}
	var err error
	if graph.sourceCKKS, err = evaluator.source.Evaluator.RuntimeIdentitySnapshot(); err != nil {
		return graph, fmt.Errorf("homchain: seal child selector source CKKS evaluator: %w", err)
	}
	if graph.sourceDFT, err = evaluator.source.DFTEvaluator.RuntimeIdentitySnapshot(); err != nil {
		return graph, fmt.Errorf("homchain: seal child selector DFT evaluator: %w", err)
	}
	if graph.linear, err = evaluator.base.linear.RuntimeIdentitySnapshot(); err != nil {
		return graph, fmt.Errorf("homchain: seal child selector linear evaluator: %w", err)
	}
	if graph.kernelSource, err = evaluator.base.kernel.source.RuntimeIdentitySnapshot(); err != nil {
		return graph, fmt.Errorf("homchain: seal child selector kernel source: %w", err)
	}
	if graph.kernelCKKS, err = evaluator.base.kernel.ckks.RuntimeIdentitySnapshot(); err != nil {
		return graph, fmt.Errorf("homchain: seal child selector kernel CKKS evaluator: %w", err)
	}
	if graph.kernelPolynomial, err = evaluator.base.kernel.polynomial.RuntimeIdentitySnapshot(); err != nil {
		return graph, fmt.Errorf("homchain: seal child selector polynomial evaluator: %w", err)
	}
	if graph.kernelEncoder, err = evaluator.base.kernel.operationalEncoder.RuntimeIdentitySnapshot(); err != nil {
		return graph, fmt.Errorf("homchain: seal child selector 256-bit encoder: %w", err)
	}
	if graph.sourceParameters, graph.sourceExecution, err = signed8Depth2ChildBootstrapParameterDigests(evaluator.source); err != nil {
		return graph, fmt.Errorf("homchain: seal child selector bootstrap execution metadata: %w", err)
	}
	graph.evaluator = evaluator
	graph.circuit = evaluator.circuit
	graph.source = evaluator.source
	graph.sourceEvaluationKeys = evaluationKeys
	graph.base = evaluator.base
	graph.keySet = evaluator.keySet
	graph.relinearizationKey = evaluator.relinearizationKey
	graph.relinearizationBinding = relinearizationBinding
	graph.galoisKeys = evaluator.galoisKeys
	graph.galoisMapPointer = reflect.ValueOf(evaluator.galoisKeys).Pointer()
	graph.galoisBindings = make(map[uint64]signed8Depth2ChildGaloisKeyBinding, len(galoisBindings))
	for element, binding := range galoisBindings {
		graph.galoisBindings[element] = binding
	}
	graph.profileDigest = evaluator.circuit.profile.digest
	graph.keyDigest = evaluator.circuit.keyProfile.digest
	return graph, nil
}

func (e *Signed8Depth2ChildSelectorDecodeEvaluator) preflight() (A2BRefreshKeyPreflight, error) {
	zero := A2BRefreshKeyPreflight{Checked: true, GraphChecked: true}
	if e == nil || e.circuit == nil || e.source == nil || e.base == nil || e.keySet == nil ||
		e.relinearizationKey == nil || e.galoisKeys == nil {
		return zero, fmt.Errorf("homchain: nil or incomplete depth2 child selector evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		zero.GraphMismatch = err.Error()
		return zero, err
	}
	g := e.graph
	if g.evaluator != e || g.circuit != e.circuit || g.source != e.source ||
		g.sourceEvaluationKeys != e.source.EvaluationKeys || g.base != e.base ||
		g.keySet != e.keySet || g.relinearizationKey != e.relinearizationKey ||
		g.galoisKeys == nil || g.galoisMapPointer == 0 ||
		g.galoisMapPointer != reflect.ValueOf(e.galoisKeys).Pointer() ||
		g.profileDigest != e.circuit.profile.digest ||
		g.keyDigest != e.circuit.keyProfile.digest || e.base.circuit != e.circuit.base ||
		e.base.source != e.source || e.base.keySet != e.keySet ||
		e.source.MemEvaluationKeySet != e.keySet || e.source.EvaluationKeys == nil ||
		e.source.EvaluationKeys.MemEvaluationKeySet != e.keySet {
		zero.GraphMismatch = "depth2 child selector evaluator object graph changed"
		return zero, fmt.Errorf("homchain: %s", zero.GraphMismatch)
	}
	preflight, err := e.base.preflight()
	if err != nil {
		return preflight, fmt.Errorf("homchain: depth2 child selector helper preflight: %w", err)
	}
	provided := append([]uint64(nil), e.keySet.GetGaloisKeysList()...)
	sort.Slice(provided, func(i, j int) bool { return provided[i] < provided[j] })
	if !equalSigned8Depth2ChildGalois(provided, e.circuit.keyProfile.all) ||
		len(e.galoisKeys) != len(provided) || len(g.galoisBindings) != len(provided) {
		return preflight, fmt.Errorf("homchain: depth2 child selector exact key inventory changed")
	}
	if key, keyErr := e.keySet.GetRelinearizationKey(); keyErr != nil || key == nil ||
		key != e.relinearizationKey || g.relinearizationBinding.validate(key, e.circuit.params.GetRLWEParameters()) != nil {
		return preflight, fmt.Errorf("homchain: depth2 child selector relinearization key identity changed")
	}
	for _, element := range provided {
		cached, ok := e.galoisKeys[element]
		key, keyErr := e.keySet.GetGaloisKey(element)
		binding, bindingOK := g.galoisBindings[element]
		if !ok || !bindingOK || cached == nil || keyErr != nil || key == nil || key != cached ||
			binding.validate(key, e.circuit.params.GetRLWEParameters()) != nil {
			return preflight, fmt.Errorf("homchain: depth2 child selector Galois key %d identity changed", element)
		}
	}
	if err = validateSigned8Depth2ChildSelectorDecodeRuntimeSnapshots(e, g); err != nil {
		return preflight, err
	}
	return preflight, nil
}

func validateSigned8Depth2ChildSelectorDecodeRuntimeSnapshots(
	e *Signed8Depth2ChildSelectorDecodeEvaluator,
	g signed8Depth2ChildSelectorDecodeEvaluatorGraph,
) error {
	sourceParameters, sourceExecution, err := signed8Depth2ChildBootstrapParameterDigests(e.source)
	if err != nil {
		return fmt.Errorf("homchain: depth2 child selector bootstrap execution metadata changed: %w", err)
	}
	if g.sourceParameters == "" || g.sourceParameters != sourceParameters {
		return fmt.Errorf("homchain: depth2 child selector bootstrap parameter metadata changed")
	}
	if g.sourceExecution == "" || g.sourceExecution != sourceExecution {
		return fmt.Errorf("homchain: depth2 child selector bootstrap Mod1 execution metadata changed")
	}
	sourceCKKS, err := e.source.Evaluator.RuntimeIdentitySnapshot()
	if err != nil || !g.sourceCKKS.Equal(sourceCKKS) {
		return fmt.Errorf("homchain: depth2 child selector source CKKS runtime identity changed: %v", err)
	}
	sourceDFT, err := e.source.DFTEvaluator.RuntimeIdentitySnapshot()
	if err != nil || !g.sourceDFT.Equal(sourceDFT) {
		return fmt.Errorf("homchain: depth2 child selector DFT runtime identity changed: %v", err)
	}
	linear, err := e.base.linear.RuntimeIdentitySnapshot()
	if err != nil || !g.linear.Equal(linear) {
		return fmt.Errorf("homchain: depth2 child selector linear runtime identity changed: %v", err)
	}
	kernelSource, err := e.base.kernel.source.RuntimeIdentitySnapshot()
	if err != nil || !g.kernelSource.Equal(kernelSource) {
		return fmt.Errorf("homchain: depth2 child selector kernel source runtime identity changed: %v", err)
	}
	kernelCKKS, err := e.base.kernel.ckks.RuntimeIdentitySnapshot()
	if err != nil || !g.kernelCKKS.Equal(kernelCKKS) {
		return fmt.Errorf("homchain: depth2 child selector kernel CKKS runtime identity changed: %v", err)
	}
	kernelPolynomial, err := e.base.kernel.polynomial.RuntimeIdentitySnapshot()
	if err != nil || !g.kernelPolynomial.Equal(kernelPolynomial) {
		return fmt.Errorf("homchain: depth2 child selector polynomial runtime identity changed: %v", err)
	}
	kernelEncoder, err := e.base.kernel.operationalEncoder.RuntimeIdentitySnapshot()
	if err != nil || !g.kernelEncoder.Equal(kernelEncoder) {
		return fmt.Errorf("homchain: depth2 child selector encoder runtime identity changed: %v", err)
	}
	return nil
}

func (e *Signed8Depth2ChildSelectorDecodeEvaluator) EvaluateNew(
	input Signed8Depth2ChildSelectorDecodeInput,
) (Signed8Depth2ChildSelectorDecodeResult, Signed8Depth2ChildSelectorDecodeTrace, error) {
	return e.evaluateNew(input)
}

func (e *Signed8Depth2ChildSelectorDecodeEvaluator) evaluateNew(
	input Signed8Depth2ChildSelectorDecodeInput,
) (result Signed8Depth2ChildSelectorDecodeResult, trace Signed8Depth2ChildSelectorDecodeTrace, err error) {
	started := time.Now()
	if e == nil || e.circuit == nil {
		return result, trace, fmt.Errorf("homchain: nil bound depth2 child selector evaluator")
	}
	if err = e.circuit.validateInput(input); err != nil {
		return result, trace, err
	}
	preflight, err := e.preflight()
	if err != nil {
		return result, trace, err
	}
	if err = e.circuit.validateInput(input); err != nil {
		return result, trace, err
	}
	inputBefore := cloneSigned8Depth2ChildSelectorDecodeInput(input)
	helper := SelectorReraiseDecodeTrace{}
	workAttempted := false
	failureStage := Signed8Depth2ChildSelectorDecodeStage("")
	attemptedLowerBound := Signed8Depth2ChildSelectorDecodeOperationCounts{}
	defer func() {
		if err == nil || !workAttempted {
			return
		}
		result = Signed8Depth2ChildSelectorDecodeResult{}
		_, partial, finalizeErr := finalizeSigned8Depth2ChildSelectorDecodeFailure(
			e.circuit, input, helper, preflight, failureStage, attemptedLowerBound, time.Since(started),
		)
		trace = partial
		if finalizeErr != nil {
			err = fmt.Errorf("%w; finalize depth2 child selector failure evidence: %v", err, finalizeErr)
		}
	}()
	if err = appendSelectorReraiseDecodeState(&helper, SelectorStageInput, SelectorReraiseDecodeWhole, input.branch); err != nil {
		return result, trace, err
	}
	helper.logicalPeakLive = 2

	failureStage = Signed8Depth2ChildSelectorStageVRaw
	attemptedLowerBound = attemptedSigned8Depth2ChildSelectorDecodeLowerBound(helper.operationCounts, failureStage)
	workAttempted = true
	vHalves, err := e.base.evaluateNormalV(input.branch, &helper)
	if err != nil {
		return result, trace, err
	}
	helper.normalVLow, helper.normalVHigh = vHalves[0].CopyNew(), vHalves[1].CopyNew()
	helper.logicalPeakLive = maxInt(helper.logicalPeakLive, 6)
	failureStage = Signed8Depth2ChildSelectorStageSTCFactor0
	attemptedLowerBound = attemptedSigned8Depth2ChildSelectorDecodeLowerBound(helper.operationCounts, failureStage)
	coefficients, err := e.base.evaluateSlotsToCoeffs(vHalves, &helper)
	if err != nil {
		return result, trace, err
	}
	helper.stc = coefficients.CopyNew()
	helper.logicalPeakLive = maxInt(helper.logicalPeakLive, 8)
	failureStage = Signed8Depth2ChildSelectorStageScaleDown
	attemptedLowerBound = attemptedSigned8Depth2ChildSelectorDecodeLowerBound(helper.operationCounts, failureStage)
	scaledDown, errScale, err := e.source.ScaleDown(coefficients.CopyNew())
	if err != nil || errScale == nil {
		return result, trace, fmt.Errorf("homchain: depth2 child selector guarded ScaleDown: %w", err)
	}
	helper.operationCounts.ScaleDown++
	if !coefficients.Equal(helper.stc) {
		return result, trace, fmt.Errorf("homchain: depth2 child selector ScaleDown mutated retained STC")
	}
	errLog2 := errScale.Log2()
	if math.IsNaN(errLog2) || math.IsInf(errLog2, 0) || math.Abs(errLog2) > 1e-6 {
		return result, trace, fmt.Errorf("homchain: depth2 child selector ScaleDown |log2(errScale)|=%g exceeds 1e-6", math.Abs(errLog2))
	}
	helper.scaleDownError, err = NewExactScaleSnapshot(*errScale)
	if err != nil {
		return result, trace, err
	}
	helper.scaleDownLog2Error = errLog2
	targetScale := rlwe.NewScale(e.circuit.params.Q()[0]).Div(rlwe.NewScale(e.source.Mod1Parameters.MessageRatio()))
	if scaledDown.Level() != 0 || !scaledDown.Scale.Div(targetScale).Equal(*errScale) ||
		!b2aExactScaleEqual(scaledDown.Scale, e.circuit.params.DefaultScale()) {
		return result, trace, fmt.Errorf("homchain: depth2 child selector ScaleDown did not land at exact L0/S35")
	}
	if err = appendSelectorReraiseDecodeState(&helper, SelectorStageScaleDown, SelectorReraiseDecodeWhole, scaledDown); err != nil {
		return result, trace, err
	}
	preModUpScale, err := NewExactScaleSnapshot(scaledDown.Scale)
	if err != nil {
		return result, trace, err
	}
	requestedScale := e.source.Mod1Parameters.ScalingFactor().Float64() / e.source.Mod1Parameters.MessageRatio()
	if requestedScale/scaledDown.Scale.Float64() > 1 {
		return result, trace, fmt.Errorf("homchain: depth2 child selector ModUp would relabel raw scale")
	}
	failureStage = Signed8Depth2ChildSelectorStageModUp
	attemptedLowerBound = attemptedSigned8Depth2ChildSelectorDecodeLowerBound(helper.operationCounts, failureStage)
	raised, err := e.source.ModUp(scaledDown)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: depth2 child selector dense/no-switch ModUp: %w", err)
	}
	helper.operationCounts.ModUp++
	if raised.Level() != 20 || !preModUpScale.EqualScale(raised.Scale) ||
		!b2aExactScaleEqual(raised.Scale, e.circuit.params.DefaultScale()) {
		return result, trace, fmt.Errorf("homchain: depth2 child selector ModUp changed L20/S35")
	}
	if err = appendSelectorReraiseDecodeState(&helper, SelectorStageModUp, SelectorReraiseDecodeWhole, raised); err != nil {
		return result, trace, err
	}
	helper.raised = raised.CopyNew()
	failureStage = Signed8Depth2ChildSelectorStageCTSFactor0
	attemptedLowerBound = attemptedSigned8Depth2ChildSelectorDecodeLowerBound(helper.operationCounts, failureStage)
	ctsHalves, err := e.base.evaluateCoeffsToSlots(raised, &helper)
	if err != nil {
		return result, trace, err
	}
	helper.ctsLow, helper.ctsHigh = ctsHalves[0].CopyNew(), ctsHalves[1].CopyNew()
	failureStage = Signed8Depth2ChildSelectorStagePeriodicExp
	attemptedLowerBound = attemptedSigned8Depth2ChildSelectorDecodeLowerBound(helper.operationCounts, failureStage)
	output, err := e.base.evaluatePeriodicBoolean(ctsHalves[0], &helper)
	if err != nil {
		return result, trace, err
	}
	failureStage = Signed8Depth2ChildSelectorStageOutput
	attemptedLowerBound = childSelectorDecodeCountsFromBase(helper.operationCounts)
	helper.serializedBytes, err = measureSelectorReraiseDecodeSerializedBytes(input.branch, helper, output)
	if err != nil {
		return result, trace, err
	}
	trace = signed8Depth2ChildSelectorDecodeTraceFromHelper(e.circuit, input, helper, preflight)
	trace.wallTime = time.Since(started)
	outputPayloadDigest, err := signed8CiphertextDigest(output)
	if err != nil {
		return result, trace, err
	}
	result = Signed8Depth2ChildSelectorDecodeResult{
		selector: output, profileDigest: e.circuit.profile.digest,
		childProfileDigest:  e.circuit.profile.childProfileDigest,
		prefixProfileDigest: e.circuit.profile.prefixProfileDigest,
		parameterDigest:     e.circuit.profile.parameterDigest,
		protocolRangeDigest: e.circuit.profile.protocolRangeDigest,
		treeDigest:          e.circuit.profile.treeDigest, scheduleDigest: e.circuit.profile.scheduleDigest,
		producerProfileDigest: input.producerProfileDigest, operandMode: input.operandMode,
		path: SelectorReraiseDecodePeriodicPath, inputProvenanceDigest: input.provenanceDigest,
		childInputBindingDigest:     input.childInputBindingDigest,
		childResultProvenanceDigest: input.childResultProvenanceDigest,
		operandsProvenanceDigest:    input.operandsProvenanceDigest,
		outputPayloadDigest:         outputPayloadDigest,
	}
	result.provenanceDigest = digestSigned8Depth2ChildSelectorDecodeResult(result)
	trace.outputPayloadDigest = outputPayloadDigest
	trace.resultProvenanceDigest = result.provenanceDigest
	trace.traceDigest = digestSigned8Depth2ChildSelectorDecodeTrace(trace)
	if err = e.circuit.validateInput(input); err != nil ||
		!input.branch.Equal(inputBefore.branch) ||
		!input.childInput.operands.feature.Equal(inputBefore.childInput.operands.feature) ||
		!input.childInput.operands.threshold.Equal(inputBefore.childInput.operands.threshold) ||
		!input.childInput.operands.conditionedSelector.Equal(inputBefore.childInput.operands.conditionedSelector) {
		return Signed8Depth2ChildSelectorDecodeResult{}, trace, fmt.Errorf("homchain: depth2 child selector mutated its admitted input: %v", err)
	}
	if _, err = e.preflight(); err != nil {
		return Signed8Depth2ChildSelectorDecodeResult{}, trace, fmt.Errorf("homchain: depth2 child selector postflight: %w", err)
	}
	if err = e.circuit.validateResult(result); err != nil {
		return Signed8Depth2ChildSelectorDecodeResult{}, trace, err
	}
	if err = e.circuit.validateTrace(input, result, trace); err != nil {
		return Signed8Depth2ChildSelectorDecodeResult{}, trace, err
	}
	return result, trace, nil
}

func signed8Depth2ChildSelectorDecodeTraceFromHelper(
	circuit *Signed8Depth2ChildSelectorDecodeCircuit,
	input Signed8Depth2ChildSelectorDecodeInput,
	helper SelectorReraiseDecodeTrace,
	preflight A2BRefreshKeyPreflight,
) Signed8Depth2ChildSelectorDecodeTrace {
	trace := Signed8Depth2ChildSelectorDecodeTrace{
		profileDigest: circuit.profile.digest, childProfileDigest: circuit.profile.childProfileDigest,
		prefixProfileDigest:   circuit.profile.prefixProfileDigest,
		producerProfileDigest: input.producerProfileDigest, operandMode: input.operandMode,
		path: SelectorReraiseDecodePeriodicPath, inputProvenanceDigest: input.provenanceDigest,
		childInputBindingDigest:      input.childInputBindingDigest,
		childResultProvenanceDigest:  input.childResultProvenanceDigest,
		operandsProvenanceDigest:     input.operandsProvenanceDigest,
		operationCounts:              childSelectorDecodeCountsFromBase(helper.operationCounts),
		attemptedOperationLowerBound: childSelectorDecodeCountsFromBase(helper.operationCounts),
		serializedBytes:              childSelectorDecodeBytesFromBase(helper.serializedBytes),
		keyPreflight:                 cloneA2BRefreshKeyPreflight(preflight), scaleDownError: helper.scaleDownError,
		scaleDownLog2Error: helper.scaleDownLog2Error, logicalPeakLive: helper.logicalPeakLive,
		normalVLow: helper.normalVLow, normalVHigh: helper.normalVHigh, stc: helper.stc,
		raised: helper.raised, ctsLow: helper.ctsLow, ctsHigh: helper.ctsHigh,
		exponential: helper.exponential, periodicRoot: helper.periodicRoot,
	}
	trace.states = make([]Signed8Depth2ChildSelectorDecodeCiphertextState, len(helper.states))
	for index, state := range helper.states {
		trace.states[index] = Signed8Depth2ChildSelectorDecodeCiphertextState{
			Stage: signed8Depth2ChildSelectorStageFromBase(state.Stage),
			Lane:  Signed8Depth2ChildSelectorDecodeLane(state.Lane), Level: state.Level,
			Degree: state.Degree, LogDimensions: state.LogDimensions, Scale: state.Scale,
		}
	}
	return trace
}

func signed8Depth2ChildSelectorStageFromBase(stage SelectorReraiseDecodeStage) Signed8Depth2ChildSelectorDecodeStage {
	return map[SelectorReraiseDecodeStage]Signed8Depth2ChildSelectorDecodeStage{
		SelectorStageInput:        Signed8Depth2ChildSelectorStageInput,
		SelectorStageVRaw:         Signed8Depth2ChildSelectorStageVRaw,
		SelectorStageV:            Signed8Depth2ChildSelectorStageV,
		SelectorStageSTCFactor0:   Signed8Depth2ChildSelectorStageSTCFactor0,
		SelectorStageSTCFactor1:   Signed8Depth2ChildSelectorStageSTCFactor1,
		SelectorStageScaleDown:    Signed8Depth2ChildSelectorStageScaleDown,
		SelectorStageModUp:        Signed8Depth2ChildSelectorStageModUp,
		SelectorStageCTSFactor0:   Signed8Depth2ChildSelectorStageCTSFactor0,
		SelectorStageCTSFactor1:   Signed8Depth2ChildSelectorStageCTSFactor1,
		SelectorStageCTSFactor2:   Signed8Depth2ChildSelectorStageCTSFactor2,
		SelectorStageCTS:          Signed8Depth2ChildSelectorStageCTS,
		SelectorStagePeriodicExp:  Signed8Depth2ChildSelectorStagePeriodicExp,
		SelectorStagePeriodicSq0:  Signed8Depth2ChildSelectorStagePeriodicSq0,
		SelectorStagePeriodicRoot: Signed8Depth2ChildSelectorStagePeriodicRoot,
		SelectorStageAffineRaw:    Signed8Depth2ChildSelectorStageAffineRaw,
		SelectorStageOutput:       Signed8Depth2ChildSelectorStageOutput,
	}[stage]
}

// finalizeSigned8Depth2ChildSelectorDecodeFailure converts already-completed
// private helper work into detached failure evidence. It performs no HE work
// and never returns a non-zero result token. A finalization error is returned
// alongside, rather than instead of, the best evidence that could be sealed.
func finalizeSigned8Depth2ChildSelectorDecodeFailure(
	circuit *Signed8Depth2ChildSelectorDecodeCircuit,
	input Signed8Depth2ChildSelectorDecodeInput,
	helper SelectorReraiseDecodeTrace,
	preflight A2BRefreshKeyPreflight,
	failureStage Signed8Depth2ChildSelectorDecodeStage,
	attemptedLowerBound Signed8Depth2ChildSelectorDecodeOperationCounts,
	wallTime time.Duration,
) (Signed8Depth2ChildSelectorDecodeResult, Signed8Depth2ChildSelectorDecodeTrace, error) {
	zeroResult := Signed8Depth2ChildSelectorDecodeResult{}
	if circuit == nil {
		trace := Signed8Depth2ChildSelectorDecodeTrace{
			failureStage: failureStage, attemptedOperationLowerBound: attemptedLowerBound, wallTime: wallTime,
		}
		trace.traceDigest = digestSigned8Depth2ChildSelectorDecodeTrace(trace)
		return zeroResult, trace, fmt.Errorf("homchain: cannot finalize depth2 child selector failure without its circuit")
	}
	trace := signed8Depth2ChildSelectorDecodeTraceFromHelper(circuit, input, helper, preflight)
	trace.failureStage = failureStage
	trace.attemptedOperationLowerBound = maxSigned8Depth2ChildSelectorDecodeCounts(
		trace.operationCounts, attemptedLowerBound,
	)
	trace.wallTime = wallTime
	var finalizeErr error
	if input.branch == nil || failureStage == "" || wallTime <= 0 {
		finalizeErr = fmt.Errorf("homchain: incomplete depth2 child selector failure evidence")
	}
	bytes, measureErr := measureSigned8Depth2ChildSelectorDecodePartialBytes(input.branch, trace)
	trace.serializedBytes = bytes
	trace = cloneSigned8Depth2ChildSelectorDecodeTrace(trace)
	trace.outputPayloadDigest = ""
	trace.resultProvenanceDigest = ""
	trace.traceDigest = digestSigned8Depth2ChildSelectorDecodeTrace(trace)
	appendError := func(next error) {
		if next == nil {
			return
		}
		if finalizeErr == nil {
			finalizeErr = next
			return
		}
		finalizeErr = fmt.Errorf("%v; %w", finalizeErr, next)
	}
	appendError(measureErr)
	appendError(circuit.validateFailureTrace(input, trace))
	return zeroResult, trace, finalizeErr
}

func measureSigned8Depth2ChildSelectorDecodePartialBytes(
	input *rlwe.Ciphertext,
	trace Signed8Depth2ChildSelectorDecodeTrace,
) (Signed8Depth2ChildSelectorDecodeSerializedBytes, error) {
	var result Signed8Depth2ChildSelectorDecodeSerializedBytes
	seen := make(map[*rlwe.Ciphertext]string, 9)
	measure := func(name string, ciphertext *rlwe.Ciphertext) (int, error) {
		if ciphertext == nil {
			return 0, nil
		}
		if previous, exists := seen[ciphertext]; exists {
			return 0, fmt.Errorf("homchain: partial child selector %s aliases %s", name, previous)
		}
		seen[ciphertext] = name
		payload, err := ciphertext.MarshalBinary()
		if err != nil {
			return 0, fmt.Errorf("homchain: marshal partial child selector %s: %w", name, err)
		}
		return len(payload), nil
	}
	boundaries := []struct {
		name       string
		ciphertext *rlwe.Ciphertext
		target     *int
	}{
		{"input", input, &result.ChildArithmeticInput},
		{"normal-V low", trace.normalVLow, &result.RetainedNormalVLow},
		{"normal-V high", trace.normalVHigh, &result.RetainedNormalVHigh},
		{"SlotsToCoeffs", trace.stc, &result.RetainedSlotsToCoeffs},
		{"raised coefficients", trace.raised, &result.RetainedRaisedCoefficients},
		{"CoeffsToSlots low", trace.ctsLow, &result.RetainedCoeffsToSlotsLow},
		{"CoeffsToSlots high", trace.ctsHigh, &result.RetainedCoeffsToSlotsHigh},
		{"exponential base", trace.exponential, &result.RetainedExponentialBase},
		{"periodic root", trace.periodicRoot, &result.RetainedPeriodicRootOfUnity},
	}
	for _, boundary := range boundaries {
		size, err := measure(boundary.name, boundary.ciphertext)
		if err != nil {
			return result, err
		}
		*boundary.target = size
	}
	return result, nil
}

func maxSigned8Depth2ChildSelectorDecodeCounts(
	left, right Signed8Depth2ChildSelectorDecodeOperationCounts,
) Signed8Depth2ChildSelectorDecodeOperationCounts {
	maximum := func(a, b int) int {
		if a > b {
			return a
		}
		return b
	}
	return Signed8Depth2ChildSelectorDecodeOperationCounts{
		LinearTransformations:            maximum(left.LinearTransformations, right.LinearTransformations),
		DiagonalPlaintextProducts:        maximum(left.DiagonalPlaintextProducts, right.DiagonalPlaintextProducts),
		NonConjugationRotations:          maximum(left.NonConjugationRotations, right.NonConjugationRotations),
		Conjugations:                     maximum(left.Conjugations, right.Conjugations),
		KeySwitches:                      maximum(left.KeySwitches, right.KeySwitches),
		CiphertextAdditionsSubtractions:  maximum(left.CiphertextAdditionsSubtractions, right.CiphertextAdditionsSubtractions),
		ScalarMultiplicationsPlusMinusI:  maximum(left.ScalarMultiplicationsPlusMinusI, right.ScalarMultiplicationsPlusMinusI),
		ExplicitRescales:                 maximum(left.ExplicitRescales, right.ExplicitRescales),
		ScaleDown:                        maximum(left.ScaleDown, right.ScaleDown),
		ModUp:                            maximum(left.ModUp, right.ModUp),
		ExponentialPolynomialEvaluations: maximum(left.ExponentialPolynomialEvaluations, right.ExponentialPolynomialEvaluations),
		CiphertextCiphertextProducts:     maximum(left.CiphertextCiphertextProducts, right.CiphertextCiphertextProducts),
		Relinearizations:                 maximum(left.Relinearizations, right.Relinearizations),
		CiphertextPlaintextProducts:      maximum(left.CiphertextPlaintextProducts, right.CiphertextPlaintextProducts),
		PlaintextVectorAdditions:         maximum(left.PlaintextVectorAdditions, right.PlaintextVectorAdditions),
		IDMSBLUTEvaluations:              maximum(left.IDMSBLUTEvaluations, right.IDMSBLUTEvaluations),
	}
}

func boundedSigned8Depth2ChildSelectorDecodeCounts(
	value, bound Signed8Depth2ChildSelectorDecodeOperationCounts,
) bool {
	return value.LinearTransformations >= 0 && value.LinearTransformations <= bound.LinearTransformations &&
		value.DiagonalPlaintextProducts >= 0 && value.DiagonalPlaintextProducts <= bound.DiagonalPlaintextProducts &&
		value.NonConjugationRotations >= 0 && value.NonConjugationRotations <= bound.NonConjugationRotations &&
		value.Conjugations >= 0 && value.Conjugations <= bound.Conjugations &&
		value.KeySwitches >= 0 && value.KeySwitches <= bound.KeySwitches &&
		value.CiphertextAdditionsSubtractions >= 0 && value.CiphertextAdditionsSubtractions <= bound.CiphertextAdditionsSubtractions &&
		value.ScalarMultiplicationsPlusMinusI >= 0 && value.ScalarMultiplicationsPlusMinusI <= bound.ScalarMultiplicationsPlusMinusI &&
		value.ExplicitRescales >= 0 && value.ExplicitRescales <= bound.ExplicitRescales &&
		value.ScaleDown >= 0 && value.ScaleDown <= bound.ScaleDown &&
		value.ModUp >= 0 && value.ModUp <= bound.ModUp &&
		value.ExponentialPolynomialEvaluations >= 0 && value.ExponentialPolynomialEvaluations <= bound.ExponentialPolynomialEvaluations &&
		value.CiphertextCiphertextProducts >= 0 && value.CiphertextCiphertextProducts <= bound.CiphertextCiphertextProducts &&
		value.Relinearizations >= 0 && value.Relinearizations <= bound.Relinearizations &&
		value.CiphertextPlaintextProducts >= 0 && value.CiphertextPlaintextProducts <= bound.CiphertextPlaintextProducts &&
		value.PlaintextVectorAdditions >= 0 && value.PlaintextVectorAdditions <= bound.PlaintextVectorAdditions &&
		value.IDMSBLUTEvaluations >= 0 && value.IDMSBLUTEvaluations <= bound.IDMSBLUTEvaluations
}

func nonzeroSigned8Depth2ChildSelectorDecodeCounts(value Signed8Depth2ChildSelectorDecodeOperationCounts) bool {
	return value != (Signed8Depth2ChildSelectorDecodeOperationCounts{})
}

// attemptedSigned8Depth2ChildSelectorDecodeLowerBound adds only the outer
// dispatch that is observable at this orchestration seam. It does not claim to
// count every primitive attempted inside an opaque package-private helper.
func attemptedSigned8Depth2ChildSelectorDecodeLowerBound(
	completed SelectorReraiseDecodeOperationCounts,
	stage Signed8Depth2ChildSelectorDecodeStage,
) Signed8Depth2ChildSelectorDecodeOperationCounts {
	attempted := childSelectorDecodeCountsFromBase(completed)
	switch stage {
	case Signed8Depth2ChildSelectorStageVRaw:
		attempted.LinearTransformations += 2
	case Signed8Depth2ChildSelectorStageSTCFactor0:
		attempted.ScalarMultiplicationsPlusMinusI++
	case Signed8Depth2ChildSelectorStageScaleDown:
		attempted.ScaleDown++
	case Signed8Depth2ChildSelectorStageModUp:
		attempted.ModUp++
	case Signed8Depth2ChildSelectorStageCTSFactor0:
		attempted.LinearTransformations++
	case Signed8Depth2ChildSelectorStagePeriodicExp:
		attempted.ExponentialPolynomialEvaluations++
	}
	return attempted
}

func validSigned8Depth2ChildSelectorDecodeFailureStage(stage Signed8Depth2ChildSelectorDecodeStage) bool {
	switch stage {
	case Signed8Depth2ChildSelectorStageVRaw, Signed8Depth2ChildSelectorStageV,
		Signed8Depth2ChildSelectorStageSTCFactor0, Signed8Depth2ChildSelectorStageSTCFactor1,
		Signed8Depth2ChildSelectorStageScaleDown, Signed8Depth2ChildSelectorStageModUp,
		Signed8Depth2ChildSelectorStageCTSFactor0, Signed8Depth2ChildSelectorStageCTSFactor1,
		Signed8Depth2ChildSelectorStageCTSFactor2, Signed8Depth2ChildSelectorStageCTS,
		Signed8Depth2ChildSelectorStagePeriodicExp, Signed8Depth2ChildSelectorStagePeriodicSq0,
		Signed8Depth2ChildSelectorStagePeriodicRoot, Signed8Depth2ChildSelectorStageAffineRaw,
		Signed8Depth2ChildSelectorStageOutput:
		return true
	default:
		return false
	}
}

func (c *Signed8Depth2ChildSelectorDecodeCircuit) validateFailureTrace(
	input Signed8Depth2ChildSelectorDecodeInput,
	trace Signed8Depth2ChildSelectorDecodeTrace,
) error {
	if err := c.validateInput(input); err != nil {
		return err
	}
	if trace.profileDigest != c.profile.digest || trace.childProfileDigest != c.profile.childProfileDigest ||
		trace.prefixProfileDigest != c.profile.prefixProfileDigest ||
		trace.producerProfileDigest != input.producerProfileDigest || trace.operandMode != input.operandMode ||
		trace.path != SelectorReraiseDecodePeriodicPath || trace.inputProvenanceDigest != input.provenanceDigest ||
		trace.childInputBindingDigest != input.childInputBindingDigest ||
		trace.childResultProvenanceDigest != input.childResultProvenanceDigest ||
		trace.operandsProvenanceDigest != input.operandsProvenanceDigest ||
		!validSigned8Depth2ChildSelectorDecodeFailureStage(trace.failureStage) || trace.wallTime <= 0 ||
		trace.outputPayloadDigest != "" || trace.resultProvenanceDigest != "" ||
		!boundedSigned8Depth2ChildSelectorDecodeCounts(trace.operationCounts, c.profile.operationCounts) ||
		!boundedSigned8Depth2ChildSelectorDecodeCounts(trace.attemptedOperationLowerBound, c.profile.operationCounts) ||
		!boundedSigned8Depth2ChildSelectorDecodeCounts(trace.operationCounts, trace.attemptedOperationLowerBound) ||
		!nonzeroSigned8Depth2ChildSelectorDecodeCounts(trace.attemptedOperationLowerBound) ||
		trace.logicalPeakLive < 0 || trace.logicalPeakLive > c.profile.logicalPeak {
		return fmt.Errorf("homchain: depth2 child selector partial trace provenance or operation ledger changed")
	}
	observedBytes, err := measureSigned8Depth2ChildSelectorDecodePartialBytes(input.branch, trace)
	if err != nil {
		return err
	}
	if trace.serializedBytes != observedBytes || trace.serializedBytes.ChildArithmeticInput == 0 ||
		trace.serializedBytes.DecodedChildSelector != 0 || trace.serializedBytes.ModuleTotal() >= c.profile.serializedBytes.ModuleTotal() {
		return fmt.Errorf("homchain: depth2 child selector partial serialized-byte ledger changed")
	}
	baseStages, baseLanes := selectorReraiseDecodeExpectedStateOrder()
	if len(trace.states) == 0 || len(trace.states) > len(c.profile.states) {
		return fmt.Errorf("homchain: depth2 child selector partial trace has %d states", len(trace.states))
	}
	for index, state := range trace.states {
		if state.Stage != signed8Depth2ChildSelectorStageFromBase(baseStages[index]) ||
			state.Lane != Signed8Depth2ChildSelectorDecodeLane(baseLanes[index]) ||
			state.Level != c.profile.states[index].level || state.Degree != 1 ||
			state.LogDimensions != input.branch.LogDimensions ||
			!c.profile.states[index].scale.Equal(state.Scale) {
			return fmt.Errorf("homchain: depth2 child selector partial state %d changed: %+v", index, state)
		}
	}
	preflight := trace.keyPreflight
	if !preflight.Checked || !preflight.GraphChecked || !preflight.GraphMatched ||
		!preflight.RelinearizationPresent || !preflight.RelinearizationMatched ||
		!preflight.DenseNoSwitchingMatched || preflight.GraphMismatch != "" ||
		len(preflight.MissingGaloisElements) != 0 || len(preflight.InvalidGaloisElements) != 0 ||
		len(preflight.UnexpectedGaloisElements) != 0 || trace.traceDigest == "" ||
		trace.traceDigest != digestSigned8Depth2ChildSelectorDecodeTrace(trace) {
		return fmt.Errorf("homchain: depth2 child selector partial key or trace seal changed")
	}
	return nil
}

func (c *Signed8Depth2ChildSelectorDecodeCircuit) validateResult(
	result Signed8Depth2ChildSelectorDecodeResult,
) error {
	if err := c.validate(); err != nil {
		return err
	}
	outputScale, err := c.profile.periodic.outputScale.Scale()
	if err != nil {
		return err
	}
	if err = requireSigned8Depth2State(
		"depth2 decoded child selector", result.selector, c.profile.periodic.outputLevel, outputScale, c.params,
	); err != nil {
		return err
	}
	producer := c.base.producer.profileForMode(result.operandMode)
	payloadDigest, err := signed8CiphertextDigest(result.selector)
	if err != nil {
		return err
	}
	if producer.digest == "" || result.profileDigest != c.profile.digest ||
		result.childProfileDigest != c.profile.childProfileDigest ||
		result.prefixProfileDigest != c.profile.prefixProfileDigest ||
		result.parameterDigest != c.profile.parameterDigest ||
		result.protocolRangeDigest != c.profile.protocolRangeDigest ||
		result.treeDigest != c.profile.treeDigest || result.scheduleDigest != c.profile.scheduleDigest ||
		result.producerProfileDigest != producer.digest || result.path != SelectorReraiseDecodePeriodicPath ||
		!isSelectorReraiseDecodeSHA256Digest(result.inputProvenanceDigest) ||
		!isSelectorReraiseDecodeSHA256Digest(result.childInputBindingDigest) ||
		!isSelectorReraiseDecodeSHA256Digest(result.childResultProvenanceDigest) ||
		!isSelectorReraiseDecodeSHA256Digest(result.operandsProvenanceDigest) ||
		result.outputPayloadDigest != payloadDigest ||
		result.provenanceDigest != digestSigned8Depth2ChildSelectorDecodeResult(result) {
		return fmt.Errorf("homchain: depth2 child selector result payload or provenance changed")
	}
	return nil
}

func (c *Signed8Depth2ChildSelectorDecodeCircuit) validateTrace(
	input Signed8Depth2ChildSelectorDecodeInput,
	result Signed8Depth2ChildSelectorDecodeResult,
	trace Signed8Depth2ChildSelectorDecodeTrace,
) error {
	if err := c.validateInput(input); err != nil {
		return err
	}
	if err := c.validateResult(result); err != nil {
		return err
	}
	if result.producerProfileDigest != input.producerProfileDigest || result.operandMode != input.operandMode ||
		result.inputProvenanceDigest != input.provenanceDigest ||
		result.childInputBindingDigest != input.childInputBindingDigest ||
		result.childResultProvenanceDigest != input.childResultProvenanceDigest ||
		result.operandsProvenanceDigest != input.operandsProvenanceDigest {
		return fmt.Errorf("homchain: depth2 child selector result is not linked to the supplied input")
	}
	if trace.profileDigest != c.profile.digest || trace.childProfileDigest != c.profile.childProfileDigest ||
		trace.prefixProfileDigest != c.profile.prefixProfileDigest ||
		trace.producerProfileDigest != input.producerProfileDigest || trace.operandMode != input.operandMode ||
		trace.path != SelectorReraiseDecodePeriodicPath || trace.inputProvenanceDigest != input.provenanceDigest ||
		trace.childInputBindingDigest != input.childInputBindingDigest ||
		trace.childResultProvenanceDigest != input.childResultProvenanceDigest ||
		trace.operandsProvenanceDigest != input.operandsProvenanceDigest || trace.failureStage != "" ||
		trace.outputPayloadDigest != result.outputPayloadDigest ||
		trace.resultProvenanceDigest != result.provenanceDigest || trace.wallTime <= 0 ||
		trace.operationCounts != c.profile.operationCounts ||
		trace.attemptedOperationLowerBound != trace.operationCounts ||
		trace.logicalPeakLive != c.profile.logicalPeak {
		return fmt.Errorf("homchain: depth2 child selector trace provenance or operation ledger changed")
	}
	observedBaseBytes, err := measureSelectorReraiseDecodeSerializedBytes(
		input.branch,
		SelectorReraiseDecodeTrace{
			normalVLow: trace.normalVLow, normalVHigh: trace.normalVHigh, stc: trace.stc,
			raised: trace.raised, ctsLow: trace.ctsLow, ctsHigh: trace.ctsHigh,
			exponential: trace.exponential, periodicRoot: trace.periodicRoot,
		},
		result.selector,
	)
	if err != nil {
		return err
	}
	observedBytes := childSelectorDecodeBytesFromBase(observedBaseBytes)
	if !trace.serializedBytes.complete() || trace.serializedBytes != observedBytes ||
		trace.serializedBytes != c.profile.serializedBytes || trace.serializedBytes.ModuleTotal() != 57404 {
		return fmt.Errorf("homchain: depth2 child selector serialized-byte ledger changed")
	}
	baseStages, baseLanes := selectorReraiseDecodeExpectedStateOrder()
	if len(trace.states) != len(c.profile.states) || len(baseStages) != len(trace.states) {
		return fmt.Errorf("homchain: depth2 child selector recorded %d states, want %d", len(trace.states), len(c.profile.states))
	}
	for index, state := range trace.states {
		if state.Stage != signed8Depth2ChildSelectorStageFromBase(baseStages[index]) ||
			state.Lane != Signed8Depth2ChildSelectorDecodeLane(baseLanes[index]) ||
			state.Level != c.profile.states[index].level || state.Degree != 1 ||
			state.LogDimensions != input.branch.LogDimensions ||
			!c.profile.states[index].scale.Equal(state.Scale) {
			return fmt.Errorf("homchain: depth2 child selector state %d changed: %+v", index, state)
		}
	}
	preflight := trace.keyPreflight
	if !preflight.Checked || !preflight.GraphChecked || !preflight.GraphMatched ||
		!preflight.RelinearizationPresent || !preflight.RelinearizationMatched ||
		!preflight.DenseNoSwitchingMatched || preflight.GraphMismatch != "" ||
		len(preflight.MissingGaloisElements) != 0 || len(preflight.InvalidGaloisElements) != 0 ||
		len(preflight.UnexpectedGaloisElements) != 0 ||
		math.IsNaN(trace.scaleDownLog2Error) || math.IsInf(trace.scaleDownLog2Error, 0) ||
		math.Abs(trace.scaleDownLog2Error) > 1e-6 || trace.traceDigest == "" ||
		trace.traceDigest != digestSigned8Depth2ChildSelectorDecodeTrace(trace) {
		return fmt.Errorf("homchain: depth2 child selector key, scale-down, cache, or trace seal changed")
	}
	return nil
}

func cloneSigned8Depth2ChildSelectorDecodeResult(
	result Signed8Depth2ChildSelectorDecodeResult,
) Signed8Depth2ChildSelectorDecodeResult {
	result.selector = copyA2BRefreshCiphertext(result.selector)
	return result
}

func cloneSigned8Depth2ChildSelectorDecodeTrace(
	trace Signed8Depth2ChildSelectorDecodeTrace,
) Signed8Depth2ChildSelectorDecodeTrace {
	trace.states = append([]Signed8Depth2ChildSelectorDecodeCiphertextState(nil), trace.states...)
	trace.keyPreflight = cloneA2BRefreshKeyPreflight(trace.keyPreflight)
	trace.normalVLow = copyA2BRefreshCiphertext(trace.normalVLow)
	trace.normalVHigh = copyA2BRefreshCiphertext(trace.normalVHigh)
	trace.stc = copyA2BRefreshCiphertext(trace.stc)
	trace.raised = copyA2BRefreshCiphertext(trace.raised)
	trace.ctsLow = copyA2BRefreshCiphertext(trace.ctsLow)
	trace.ctsHigh = copyA2BRefreshCiphertext(trace.ctsHigh)
	trace.exponential = copyA2BRefreshCiphertext(trace.exponential)
	trace.periodicRoot = copyA2BRefreshCiphertext(trace.periodicRoot)
	return trace
}

func digestSigned8Depth2ChildSelectorDecodeResult(
	result Signed8Depth2ChildSelectorDecodeResult,
) string {
	return digestString(fmt.Sprintf(
		"%s|profile=%s|child=%s|prefix=%s|parameters=%s|protocol-range=%s|tree=%s|schedule=%s|producer=%s|mode=%s|path=%s|input=%s|child-input=%s|child-result=%s|operands=%s|output=%s",
		signed8Depth2ChildSelectorDecodeResultSchema, result.profileDigest, result.childProfileDigest,
		result.prefixProfileDigest, result.parameterDigest, result.protocolRangeDigest, result.treeDigest,
		result.scheduleDigest, result.producerProfileDigest, result.operandMode, result.path,
		result.inputProvenanceDigest, result.childInputBindingDigest, result.childResultProvenanceDigest,
		result.operandsProvenanceDigest, result.outputPayloadDigest,
	))
}

func digestSigned8Depth2ChildSelectorDecodeTrace(
	trace Signed8Depth2ChildSelectorDecodeTrace,
) string {
	var stateLedger string
	for _, state := range trace.states {
		stateLedger += fmt.Sprintf("|state=%s/%s/L%d/D%d/dim=%d,%d/scale=%s", state.Stage, state.Lane,
			state.Level, state.Degree, state.LogDimensions.Rows, state.LogDimensions.Cols, state.Scale.canonicalString())
	}
	cacheDigests := ""
	for _, cache := range []struct {
		name  string
		value *rlwe.Ciphertext
	}{
		{"normal-v-low", trace.normalVLow}, {"normal-v-high", trace.normalVHigh},
		{"stc", trace.stc}, {"raised", trace.raised}, {"cts-low", trace.ctsLow},
		{"cts-high", trace.ctsHigh}, {"exp", trace.exponential}, {"root", trace.periodicRoot},
	} {
		digest, err := signed8CiphertextDigest(cache.value)
		if err != nil {
			digest = "invalid"
		}
		cacheDigests += fmt.Sprintf("|cache=%s:%s", cache.name, digest)
	}
	return digestString(fmt.Sprintf(
		"%s|profile=%s|child=%s|prefix=%s|producer=%s|mode=%s|path=%s|input=%s|child-input=%s|child-result=%s|operands=%s|failure=%s|counts=%+v|attempted-lower-bound=%+v|serialized=%+v|preflight=%+v|scale-down=%s/%g|peak=%d|output=%s|result=%s%s%s",
		signed8Depth2ChildSelectorDecodeTraceSchema, trace.profileDigest, trace.childProfileDigest,
		trace.prefixProfileDigest, trace.producerProfileDigest, trace.operandMode, trace.path,
		trace.inputProvenanceDigest, trace.childInputBindingDigest, trace.childResultProvenanceDigest,
		trace.operandsProvenanceDigest, trace.failureStage, trace.operationCounts, trace.attemptedOperationLowerBound, trace.serializedBytes,
		trace.keyPreflight, trace.scaleDownError.canonicalString(), trace.scaleDownLog2Error,
		trace.logicalPeakLive, trace.outputPayloadDigest, trace.resultProvenanceDigest, stateLedger, cacheDigests,
	))
}

func NewSigned8Depth2ChildSelectorDecodeCircuit(
	child *Signed8Depth2ChildComparatorCircuit,
) (*Signed8Depth2ChildSelectorDecodeCircuit, error) {
	if child == nil {
		return nil, fmt.Errorf("homchain: nil depth2 child comparator")
	}
	if err := child.validate(); err != nil {
		return nil, fmt.Errorf("homchain: validate depth2 child comparator for decoder: %w", err)
	}
	prefix := child.prefix
	base := prefix.selector
	if prefix == nil || base == nil {
		return nil, fmt.Errorf("homchain: depth2 child decoder has no owned prefix selector")
	}
	if err := base.validate(); err != nil {
		return nil, fmt.Errorf("homchain: validate depth2 child base selector: %w", err)
	}
	baseProfile := base.Profile()
	childProfile := child.Profile()
	prefixProfile := prefix.Profile()
	profile := Signed8Depth2ChildSelectorDecodeProfile{
		fidelity: SelectorReraiseDecodeFunctionalNotSecure, wordBits: baseProfile.WordBits(),
		words: baseProfile.Words(), slots: baseProfile.Slots(),
		encoderPrecision: baseProfile.EncoderPrecision(), integerPrecision: baseProfile.IntegerPrecision(),
		parameterDigest: childProfile.ParameterDigest(), protocolRangeDigest: childProfile.ProtocolRangeDigest(),
		treeDigest: childProfile.TreeDigest(), scheduleDigest: childProfile.ScheduleDigest(),
		childProfileDigest: childProfile.Digest(), prefixProfileDigest: prefixProfile.Digest(),
		baseSelectorProfileDigest: baseProfile.Digest(),
		producerPublicDigest:      baseProfile.ProducerPublicProfileDigest(),
		producerOpaqueDigest:      baseProfile.ProducerOpaqueProfileDigest(),
		representation:            SelectorArithmeticRootCoefficientsToPeriodicBooleanScalarRepeated,
		resultSchema:              signed8Depth2ChildSelectorDecodeResultSchema,
		normalV:                   baseProfile.NormalV(), dft: baseProfile.DFT(), periodic: baseProfile.Periodic(),
		operationCounts: childSelectorDecodeCountsFromBase(baseProfile.OperationCounts()),
		serializedBytes: childSelectorDecodeBytesFromBase(baseProfile.ExpectedSerializedBytes()),
		logicalPeak:     baseProfile.LogicalPeakLiveCiphertexts(),
		states:          childSelectorDecodeStatesFromBase(baseProfile.States()),
	}
	keyProfile := base.RequiredKeyProfile()
	profile.digest = digestSigned8Depth2ChildSelectorDecodeProfile(profile, keyProfile)
	circuit := &Signed8Depth2ChildSelectorDecodeCircuit{
		child: child, prefix: prefix, base: base, params: child.params,
		profile: profile, keyProfile: keyProfile,
		affineMultiplierSeal: base.affineMultiplier.CopyNew(), affineOffsetSeal: base.affineOffset.CopyNew(),
	}
	circuit.graph = signed8Depth2ChildSelectorDecodeCircuitGraph{
		circuit: circuit, child: child, prefix: prefix, base: base,
		affineMultiplierSeal: circuit.affineMultiplierSeal, affineOffsetSeal: circuit.affineOffsetSeal,
		profileDigest: profile.digest, keyDigest: keyProfile.digest,
		childProfileDigest: childProfile.Digest(), prefixProfileDigest: prefixProfile.Digest(),
		baseSelectorProfileDigest: baseProfile.Digest(),
	}
	if err := circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *Signed8Depth2ChildSelectorDecodeCircuit) Profile() Signed8Depth2ChildSelectorDecodeProfile {
	if c == nil {
		return Signed8Depth2ChildSelectorDecodeProfile{}
	}
	profile := c.profile
	profile.normalV = cloneSelectorReraiseDecodeTransformProfile(c.profile.normalV)
	profile.dft = cloneSelectorReraiseDecodeDFTProfile(c.profile.dft)
	profile.states = c.profile.States()
	return profile
}

func (c *Signed8Depth2ChildSelectorDecodeCircuit) RequiredKeyProfile() SelectorReraiseDecodeKeyProfile {
	if c == nil {
		return SelectorReraiseDecodeKeyProfile{}
	}
	profile := c.keyProfile
	profile.all = c.keyProfile.All()
	return profile
}

func (c *Signed8Depth2ChildSelectorDecodeCircuit) validate() error {
	if c == nil || c.child == nil || c.prefix == nil || c.base == nil ||
		c.affineMultiplierSeal == nil || c.affineOffsetSeal == nil {
		return fmt.Errorf("homchain: nil or incomplete depth2 child selector decoder")
	}
	if err := c.child.validate(); err != nil {
		return err
	}
	if err := c.base.validate(); err != nil {
		return err
	}
	g := c.graph
	if g.circuit != c || g.child != c.child || g.prefix != c.prefix || g.base != c.base ||
		g.affineMultiplierSeal != c.affineMultiplierSeal || g.affineOffsetSeal != c.affineOffsetSeal ||
		g.profileDigest != c.profile.digest || g.keyDigest != c.keyProfile.digest ||
		g.childProfileDigest != c.child.profile.digest || g.prefixProfileDigest != c.prefix.profile.digest ||
		g.baseSelectorProfileDigest != c.base.profile.digest || c.child.prefix != c.prefix ||
		c.prefix.selector != c.base || !c.params.Equal(&c.child.params) || !c.params.Equal(&c.base.params) {
		return fmt.Errorf("homchain: depth2 child selector decoder circuit graph changed")
	}
	if !c.base.affineMultiplier.Equal(c.affineMultiplierSeal) ||
		!c.base.affineOffset.Equal(c.affineOffsetSeal) {
		return fmt.Errorf("homchain: depth2 child selector affine plaintext cache changed")
	}
	baseProfile := c.base.Profile()
	want := Signed8Depth2ChildSelectorDecodeProfile{
		fidelity: SelectorReraiseDecodeFunctionalNotSecure, wordBits: baseProfile.WordBits(),
		words: baseProfile.Words(), slots: baseProfile.Slots(),
		encoderPrecision: baseProfile.EncoderPrecision(), integerPrecision: baseProfile.IntegerPrecision(),
		parameterDigest: c.child.profile.parameter, protocolRangeDigest: c.child.profile.protocolRange,
		treeDigest: c.child.profile.tree, scheduleDigest: c.child.profile.schedule,
		childProfileDigest: c.child.profile.digest, prefixProfileDigest: c.prefix.profile.digest,
		baseSelectorProfileDigest: c.base.profile.digest,
		producerPublicDigest:      baseProfile.ProducerPublicProfileDigest(), producerOpaqueDigest: baseProfile.ProducerOpaqueProfileDigest(),
		representation: SelectorArithmeticRootCoefficientsToPeriodicBooleanScalarRepeated,
		resultSchema:   signed8Depth2ChildSelectorDecodeResultSchema,
		normalV:        baseProfile.NormalV(), dft: baseProfile.DFT(), periodic: baseProfile.Periodic(),
		operationCounts: childSelectorDecodeCountsFromBase(baseProfile.OperationCounts()),
		serializedBytes: childSelectorDecodeBytesFromBase(baseProfile.ExpectedSerializedBytes()),
		logicalPeak:     baseProfile.LogicalPeakLiveCiphertexts(), states: childSelectorDecodeStatesFromBase(baseProfile.States()),
	}
	want.digest = digestSigned8Depth2ChildSelectorDecodeProfile(want, c.keyProfile)
	if !reflect.DeepEqual(c.profile, want) || !reflect.DeepEqual(c.keyProfile, c.base.RequiredKeyProfile()) ||
		len(c.profile.states) != 19 || c.profile.serializedBytes.ModuleTotal() != 57404 ||
		!equalSigned8Depth2ChildGalois(c.keyProfile.all, []uint64{5, 17, 25, 33, 41, 49, 63}) ||
		!c.keyProfile.relinearization {
		return fmt.Errorf("homchain: depth2 child selector decoder profile or key ledger changed")
	}
	return nil
}

func childSelectorDecodeCountsFromBase(value SelectorReraiseDecodeOperationCounts) Signed8Depth2ChildSelectorDecodeOperationCounts {
	return Signed8Depth2ChildSelectorDecodeOperationCounts(value)
}

func childSelectorDecodeCountsToBase(value Signed8Depth2ChildSelectorDecodeOperationCounts) SelectorReraiseDecodeOperationCounts {
	return SelectorReraiseDecodeOperationCounts(value)
}

func childSelectorDecodeBytesFromBase(value SelectorReraiseDecodeSerializedBytes) Signed8Depth2ChildSelectorDecodeSerializedBytes {
	return Signed8Depth2ChildSelectorDecodeSerializedBytes{
		ChildArithmeticInput: value.OnlineInput, DecodedChildSelector: value.OnlineOutput,
		RetainedNormalVLow: value.RetainedNormalVLow, RetainedNormalVHigh: value.RetainedNormalVHigh,
		RetainedSlotsToCoeffs:       value.RetainedSlotsToCoeffs,
		RetainedRaisedCoefficients:  value.RetainedRaisedCoefficients,
		RetainedCoeffsToSlotsLow:    value.RetainedCoeffsToSlotsLow,
		RetainedCoeffsToSlotsHigh:   value.RetainedCoeffsToSlotsHigh,
		RetainedExponentialBase:     value.RetainedExponentialBase,
		RetainedPeriodicRootOfUnity: value.RetainedPeriodicRootOfUnity,
	}
}

func childSelectorDecodeStatesFromBase(values []SelectorReraiseDecodeStateProfile) []Signed8Depth2ChildSelectorDecodeStateProfile {
	result := make([]Signed8Depth2ChildSelectorDecodeStateProfile, len(values))
	for index, value := range values {
		result[index] = Signed8Depth2ChildSelectorDecodeStateProfile{level: value.level, scale: value.scale}
	}
	return result
}

func digestSigned8Depth2ChildSelectorDecodeProfile(
	profile Signed8Depth2ChildSelectorDecodeProfile,
	keys SelectorReraiseDecodeKeyProfile,
) string {
	return digestString(fmt.Sprintf(
		"%s|fidelity=%s|word=%d|words=%d|slots=%d|precision=%d/%d|parameters=%s|protocol-range=%s|tree=%s|schedule=%s|child=%s|prefix=%s|base-selector=%s|producer=%s/%s|representation=%s|result-schema=%s|normal-v=%+v|dft=%s|periodic=%+v|counts=%+v|serialized=%+v|peak=%d|states=%+v|keys=%s",
		signed8Depth2ChildSelectorDecodeProfileSchema, profile.fidelity, profile.wordBits, profile.words,
		profile.slots, profile.encoderPrecision, profile.integerPrecision, profile.parameterDigest,
		profile.protocolRangeDigest, profile.treeDigest, profile.scheduleDigest, profile.childProfileDigest,
		profile.prefixProfileDigest, profile.baseSelectorProfileDigest, profile.producerPublicDigest,
		profile.producerOpaqueDigest, profile.representation, profile.resultSchema, profile.normalV,
		profile.dft.digest, profile.periodic, profile.operationCounts, profile.serializedBytes,
		profile.logicalPeak, profile.states, keys.digest,
	))
}
