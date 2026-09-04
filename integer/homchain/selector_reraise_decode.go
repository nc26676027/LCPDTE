package homchain

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/nc26676027/LCPDTE/integer/z2n"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	ckksdft "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	ckkspolynomial "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/polynomial"
	commonlintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/common/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const (
	selectorReraiseDecodeWords            = 4
	selectorReraiseDecodeHalfWidth        = 4
	selectorReraiseDecodeIntegerPrecision = 256
	selectorReraiseDecodeInputSchema      = "selector-reraise-decode-input-v1"
	selectorReraiseDecodeResultSchema     = "selector-reraise-decode-result-v1"
)

const (
	selectorAcceptedPublicComparatorProfileDigest = "5075bdf6ee94736fb4dc4755c07f14fdf303f149dab5750440ca030f9f9710bc"
	selectorAcceptedOpaqueComparatorProfileDigest = "0d62c312fe3084984a350de3dad44ed4ad90bcaa4e8a8370bddc45c7c2e2ee63"
	selectorAcceptedComparatorAdmissionDigest     = "6815c10bab78ee55ad8c53fdeb30fd665e8cfc38028e8bce4bd384852db9b94b"
	selectorAcceptedComparatorParameterDigest     = "085e0a9b826d469ac5514d3db988672f41ab0a4f1bb2fe82705842226a8eacc2"
	selectorAcceptedComparatorOnePayloadDigest    = "64b6f5a5fac15062c9a3eb83950da2c2abdbb6f77b3db4eb1a44bff097646592"
)

type SelectorReraiseDecodeFidelity string

const SelectorReraiseDecodeFunctionalNotSecure SelectorReraiseDecodeFidelity = "functional_not_secure"

type SelectorReraiseDecodeRepresentation string

const SelectorArithmeticRootCoefficientsToPeriodicBooleanScalarRepeated SelectorReraiseDecodeRepresentation = "arithmetic_root_coefficients_to_periodic_boolean_scalar_repeated_via_exp46_affine"

type SelectorReraiseDecodePath string

const SelectorReraiseDecodePeriodicPath SelectorReraiseDecodePath = "accepted-exp46-two-squares-slotwise-affine"

type SelectorReraiseDecodeLane string

const (
	SelectorReraiseDecodeWhole SelectorReraiseDecodeLane = "whole"
	SelectorReraiseDecodeLow   SelectorReraiseDecodeLane = "low"
	SelectorReraiseDecodeHigh  SelectorReraiseDecodeLane = "high"
)

type SelectorReraiseDecodeStage string

const (
	SelectorStageInput        SelectorReraiseDecodeStage = "comparator-arithmetic-selector"
	SelectorStageVRaw         SelectorReraiseDecodeStage = "normal-V-projected-raw"
	SelectorStageV            SelectorReraiseDecodeStage = "normal-V-rescaled"
	SelectorStageSTCFactor0   SelectorReraiseDecodeStage = "low-level-STC-factor-0"
	SelectorStageSTCFactor1   SelectorReraiseDecodeStage = "low-level-STC-factor-1"
	SelectorStageScaleDown    SelectorReraiseDecodeStage = "guarded-scale-down"
	SelectorStageModUp        SelectorReraiseDecodeStage = "dense-no-switch-mod-up"
	SelectorStageCTSFactor0   SelectorReraiseDecodeStage = "shared-CTS-factor-0"
	SelectorStageCTSFactor1   SelectorReraiseDecodeStage = "shared-CTS-factor-1"
	SelectorStageCTSFactor2   SelectorReraiseDecodeStage = "shared-CTS-factor-2"
	SelectorStageCTS          SelectorReraiseDecodeStage = "shared-CTS-split"
	SelectorStagePeriodicExp  SelectorReraiseDecodeStage = "accepted-exp46"
	SelectorStagePeriodicSq0  SelectorReraiseDecodeStage = "periodic-square-0"
	SelectorStagePeriodicRoot SelectorReraiseDecodeStage = "periodic-root-of-unity"
	SelectorStageAffineRaw    SelectorReraiseDecodeStage = "slotwise-affine-product-raw"
	SelectorStageOutput       SelectorReraiseDecodeStage = "periodic-boolean-scalar"
)

type SelectorReraiseDecodeOperationCounts struct {
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

// SelectorReraiseDecodeSerializedBytes separates online ciphertext boundaries
// from retained diagnostic evidence. OnlineTotal is only the explicit sum of
// the input/output encodings; whether a transport occurred is a benchmark-level
// fact. Retained checkpoints are local evidence storage, never communication.
// Every named ciphertext is marshaled and counted once.
type SelectorReraiseDecodeSerializedBytes struct {
	OnlineInput                 int
	OnlineOutput                int
	RetainedNormalVLow          int
	RetainedNormalVHigh         int
	RetainedSlotsToCoeffs       int
	RetainedRaisedCoefficients  int
	RetainedCoeffsToSlotsLow    int
	RetainedCoeffsToSlotsHigh   int
	RetainedExponentialBase     int
	RetainedPeriodicRootOfUnity int
}

func (s SelectorReraiseDecodeSerializedBytes) OnlineTotal() int {
	return s.OnlineInput + s.OnlineOutput
}

func (s SelectorReraiseDecodeSerializedBytes) RetainedTraceTotal() int {
	return s.RetainedNormalVLow + s.RetainedNormalVHigh + s.RetainedSlotsToCoeffs +
		s.RetainedRaisedCoefficients + s.RetainedCoeffsToSlotsLow + s.RetainedCoeffsToSlotsHigh +
		s.RetainedExponentialBase + s.RetainedPeriodicRootOfUnity
}

func (s SelectorReraiseDecodeSerializedBytes) complete() bool {
	return s.OnlineInput > 0 && s.OnlineOutput > 0 && s.RetainedNormalVLow > 0 &&
		s.RetainedNormalVHigh > 0 && s.RetainedSlotsToCoeffs > 0 && s.RetainedRaisedCoefficients > 0 &&
		s.RetainedCoeffsToSlotsLow > 0 && s.RetainedCoeffsToSlotsHigh > 0 &&
		s.RetainedExponentialBase > 0 && s.RetainedPeriodicRootOfUnity > 0
}

type SelectorReraiseDecodeStateProfile struct {
	level int
	scale ExactScaleSnapshot
}

func (s SelectorReraiseDecodeStateProfile) Level() int                { return s.level }
func (s SelectorReraiseDecodeStateProfile) Scale() ExactScaleSnapshot { return s.scale }

type SelectorReraiseDecodeCiphertextState struct {
	Stage         SelectorReraiseDecodeStage
	Lane          SelectorReraiseDecodeLane
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

// SelectorReraiseDecodeInput owns an authenticated comparator-result copy.
// The raw arithmetic selector is not exposed through the public API.
type SelectorReraiseDecodeInput struct {
	branch                *rlwe.Ciphertext
	pathProfileDigest     string
	producerProfileDigest string
	rangeDigest           string
	operandMode           Signed8ComparatorOperandMode
	payloadDigest         string
	provenanceDigest      string
}

func (i SelectorReraiseDecodeInput) ProducerProfileDigest() string { return i.producerProfileDigest }
func (i SelectorReraiseDecodeInput) RangeDigest() string           { return i.rangeDigest }
func (i SelectorReraiseDecodeInput) OperandMode() Signed8ComparatorOperandMode {
	return i.operandMode
}
func (i SelectorReraiseDecodeInput) ProvenanceDigest() string { return i.provenanceDigest }

type SelectorReraiseDecodeResult struct {
	scalar                *rlwe.Ciphertext
	profileDigest         string
	producerProfileDigest string
	rangeDigest           string
	inputProvenanceDigest string
	operandMode           Signed8ComparatorOperandMode
	path                  SelectorReraiseDecodePath
	outputPayloadDigest   string
	provenanceDigest      string
}

func (r SelectorReraiseDecodeResult) Ciphertext() *rlwe.Ciphertext {
	if r.scalar == nil {
		return nil
	}
	return r.scalar.CopyNew()
}
func (r SelectorReraiseDecodeResult) ProfileDigest() string         { return r.profileDigest }
func (r SelectorReraiseDecodeResult) ProducerProfileDigest() string { return r.producerProfileDigest }
func (r SelectorReraiseDecodeResult) RangeDigest() string           { return r.rangeDigest }
func (r SelectorReraiseDecodeResult) InputProvenanceDigest() string { return r.inputProvenanceDigest }
func (r SelectorReraiseDecodeResult) OperandMode() Signed8ComparatorOperandMode {
	return r.operandMode
}
func (r SelectorReraiseDecodeResult) Path() SelectorReraiseDecodePath { return r.path }
func (r SelectorReraiseDecodeResult) OutputPayloadDigest() string     { return r.outputPayloadDigest }
func (r SelectorReraiseDecodeResult) ProvenanceDigest() string        { return r.provenanceDigest }

type SelectorReraiseDecodeTrace struct {
	profileDigest, producerProfileDigest string
	rangeDigest, inputProvenanceDigest   string
	operandMode                          Signed8ComparatorOperandMode
	path                                 SelectorReraiseDecodePath
	states                               []SelectorReraiseDecodeCiphertextState
	operationCounts                      SelectorReraiseDecodeOperationCounts
	serializedBytes                      SelectorReraiseDecodeSerializedBytes
	keyPreflight                         A2BRefreshKeyPreflight
	scaleDownError                       ExactScaleSnapshot
	scaleDownLog2Error                   float64
	logicalPeakLive                      int
	wallTime                             time.Duration
	normalVLow, normalVHigh              *rlwe.Ciphertext
	stc, raised                          *rlwe.Ciphertext
	ctsLow, ctsHigh                      *rlwe.Ciphertext
	exponential, periodicRoot            *rlwe.Ciphertext
	outputPayloadDigest                  string
	resultProvenanceDigest               string
}

func (t SelectorReraiseDecodeTrace) ProfileDigest() string         { return t.profileDigest }
func (t SelectorReraiseDecodeTrace) ProducerProfileDigest() string { return t.producerProfileDigest }
func (t SelectorReraiseDecodeTrace) RangeDigest() string           { return t.rangeDigest }
func (t SelectorReraiseDecodeTrace) InputProvenanceDigest() string { return t.inputProvenanceDigest }
func (t SelectorReraiseDecodeTrace) OperandMode() Signed8ComparatorOperandMode {
	return t.operandMode
}
func (t SelectorReraiseDecodeTrace) Path() SelectorReraiseDecodePath { return t.path }
func (t SelectorReraiseDecodeTrace) OutputPayloadDigest() string     { return t.outputPayloadDigest }
func (t SelectorReraiseDecodeTrace) ResultProvenanceDigest() string  { return t.resultProvenanceDigest }
func (t SelectorReraiseDecodeTrace) States() []SelectorReraiseDecodeCiphertextState {
	return append([]SelectorReraiseDecodeCiphertextState(nil), t.states...)
}
func (t SelectorReraiseDecodeTrace) OperationCounts() SelectorReraiseDecodeOperationCounts {
	return t.operationCounts
}
func (t SelectorReraiseDecodeTrace) SerializedBytes() SelectorReraiseDecodeSerializedBytes {
	return t.serializedBytes
}
func (t SelectorReraiseDecodeTrace) KeyPreflight() A2BRefreshKeyPreflight {
	return cloneA2BRefreshKeyPreflight(t.keyPreflight)
}
func (t SelectorReraiseDecodeTrace) ScaleDownError() (ExactScaleSnapshot, float64) {
	return t.scaleDownError, t.scaleDownLog2Error
}
func (t SelectorReraiseDecodeTrace) LogicalPeakLiveCiphertexts() int { return t.logicalPeakLive }
func (t SelectorReraiseDecodeTrace) WallTime() time.Duration         { return t.wallTime }
func (t SelectorReraiseDecodeTrace) NormalVLow() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.normalVLow)
}
func (t SelectorReraiseDecodeTrace) NormalVHigh() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.normalVHigh)
}
func (t SelectorReraiseDecodeTrace) SlotsToCoeffs() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.stc)
}
func (t SelectorReraiseDecodeTrace) RaisedCoefficients() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.raised)
}
func (t SelectorReraiseDecodeTrace) CoeffsToSlotsLow() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.ctsLow)
}
func (t SelectorReraiseDecodeTrace) CoeffsToSlotsHigh() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.ctsHigh)
}
func (t SelectorReraiseDecodeTrace) ExponentialBase() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.exponential)
}
func (t SelectorReraiseDecodeTrace) PeriodicRootOfUnity() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.periodicRoot)
}

type SelectorReraiseDecodeTransformProfile struct {
	lowName, highName           TransformName
	levelQ, levelP              int
	lowN1, highN1               int
	lowDiagonals, highDiagonals []int
	rotations                   []int
	galois                      []uint64
	sourceDigest                string
	compiledDigest              string
}

func (p SelectorReraiseDecodeTransformProfile) LowName() TransformName  { return p.lowName }
func (p SelectorReraiseDecodeTransformProfile) HighName() TransformName { return p.highName }
func (p SelectorReraiseDecodeTransformProfile) LevelQ() int             { return p.levelQ }
func (p SelectorReraiseDecodeTransformProfile) LevelP() int             { return p.levelP }
func (p SelectorReraiseDecodeTransformProfile) LowBabyStepSize() int    { return p.lowN1 }
func (p SelectorReraiseDecodeTransformProfile) HighBabyStepSize() int   { return p.highN1 }
func (p SelectorReraiseDecodeTransformProfile) LowDiagonalIndexes() []int {
	return append([]int(nil), p.lowDiagonals...)
}
func (p SelectorReraiseDecodeTransformProfile) HighDiagonalIndexes() []int {
	return append([]int(nil), p.highDiagonals...)
}
func (p SelectorReraiseDecodeTransformProfile) RotationIndexes() []int {
	return append([]int(nil), p.rotations...)
}
func (p SelectorReraiseDecodeTransformProfile) GaloisElements() []uint64 {
	return append([]uint64(nil), p.galois...)
}

func cloneSelectorReraiseDecodeTransformProfile(p SelectorReraiseDecodeTransformProfile) SelectorReraiseDecodeTransformProfile {
	p.lowDiagonals = p.LowDiagonalIndexes()
	p.highDiagonals = p.HighDiagonalIndexes()
	p.rotations = p.RotationIndexes()
	p.galois = p.GaloisElements()
	return p
}

type SelectorReraiseDecodeDFTProfile struct {
	stcRaw, ctsRaw, stcExecution, ctsExecution ckksdft.MatrixLiteral
	encoderPrecision, generatorPrecision       uint
	stcRawDigest, ctsRawDigest                 string
	stcExecutionDigest, ctsExecutionDigest     string
	digest                                     string
}

func (p SelectorReraiseDecodeDFTProfile) SlotsToCoeffsLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.stcRaw)
}
func (p SelectorReraiseDecodeDFTProfile) CoeffsToSlotsLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.ctsRaw)
}
func (p SelectorReraiseDecodeDFTProfile) SlotsToCoeffsExecutionLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.stcExecution)
}
func (p SelectorReraiseDecodeDFTProfile) CoeffsToSlotsExecutionLiteral() ckksdft.MatrixLiteral {
	return cloneDFTLiteral(p.ctsExecution)
}
func (p SelectorReraiseDecodeDFTProfile) EncoderPrecision() uint               { return p.encoderPrecision }
func (p SelectorReraiseDecodeDFTProfile) GeneratorPrecision() uint             { return p.generatorPrecision }
func (p SelectorReraiseDecodeDFTProfile) SlotsToCoeffsRawMatrixDigest() string { return p.stcRawDigest }
func (p SelectorReraiseDecodeDFTProfile) CoeffsToSlotsRawMatrixDigest() string { return p.ctsRawDigest }
func (p SelectorReraiseDecodeDFTProfile) SlotsToCoeffsExecutionMatrixDigest() string {
	return p.stcExecutionDigest
}
func (p SelectorReraiseDecodeDFTProfile) CoeffsToSlotsExecutionMatrixDigest() string {
	return p.ctsExecutionDigest
}
func (p SelectorReraiseDecodeDFTProfile) Digest() string { return p.digest }

func cloneSelectorReraiseDecodeDFTProfile(p SelectorReraiseDecodeDFTProfile) SelectorReraiseDecodeDFTProfile {
	p.stcRaw = p.SlotsToCoeffsLiteral()
	p.ctsRaw = p.CoeffsToSlotsLiteral()
	p.stcExecution = p.SlotsToCoeffsExecutionLiteral()
	p.ctsExecution = p.CoeffsToSlotsExecutionLiteral()
	return p
}

type SelectorReraiseDecodeKeyProfile struct {
	all             []uint64
	relinearization bool
	digest          string
}

func (p SelectorReraiseDecodeKeyProfile) All() []uint64                 { return append([]uint64(nil), p.all...) }
func (p SelectorReraiseDecodeKeyProfile) RelinearizationRequired() bool { return p.relinearization }
func (p SelectorReraiseDecodeKeyProfile) Digest() string                { return p.digest }

// SelectorReraiseDecodeComparatorAuditAnchor is the independently accepted
// narrow-range comparator projection. It is deliberately separate from the
// actual range-bound producer instance carried by a selector circuit.
type SelectorReraiseDecodeComparatorAuditAnchor struct {
	PublicProfileDigest        string
	OpaqueProfileDigest        string
	AdmissionDigest            string
	ParameterDigest            string
	ArithmeticOnePayloadDigest string
}

type SelectorReraiseDecodePeriodicProfile struct {
	kernelProfileDigest, exponentialProfileDigest string
	exponentialArtifactDigest, operandGraphDigest string
	affineSourceDigest                            string
	multiplierPayloadDigest, offsetPayloadDigest  string
	exponentialDepth                              int
	inputLevel, exponentialLevel                  int
	square0Level, rootLevel, outputLevel          int
	inputScale, exponentialScale                  ExactScaleSnapshot
	square0Scale, rootScale, outputScale          ExactScaleSnapshot
	runtimePath                                   string
}

func (p SelectorReraiseDecodePeriodicProfile) KernelProfileDigest() string {
	return p.kernelProfileDigest
}
func (p SelectorReraiseDecodePeriodicProfile) ExponentialProfileDigest() string {
	return p.exponentialProfileDigest
}
func (p SelectorReraiseDecodePeriodicProfile) ExponentialArtifactDigest() string {
	return p.exponentialArtifactDigest
}
func (p SelectorReraiseDecodePeriodicProfile) OperandGraphDigest() string {
	return p.operandGraphDigest
}
func (p SelectorReraiseDecodePeriodicProfile) AffineSourceDigest() string {
	return p.affineSourceDigest
}
func (p SelectorReraiseDecodePeriodicProfile) MultiplierPayloadDigest() string {
	return p.multiplierPayloadDigest
}
func (p SelectorReraiseDecodePeriodicProfile) OffsetPayloadDigest() string {
	return p.offsetPayloadDigest
}
func (p SelectorReraiseDecodePeriodicProfile) ExponentialDepth() int { return p.exponentialDepth }
func (p SelectorReraiseDecodePeriodicProfile) InputLevel() int       { return p.inputLevel }
func (p SelectorReraiseDecodePeriodicProfile) ExponentialLevel() int { return p.exponentialLevel }
func (p SelectorReraiseDecodePeriodicProfile) Square0Level() int     { return p.square0Level }
func (p SelectorReraiseDecodePeriodicProfile) RootLevel() int        { return p.rootLevel }
func (p SelectorReraiseDecodePeriodicProfile) OutputLevel() int      { return p.outputLevel }
func (p SelectorReraiseDecodePeriodicProfile) InputScale() ExactScaleSnapshot {
	return p.inputScale
}
func (p SelectorReraiseDecodePeriodicProfile) ExponentialScale() ExactScaleSnapshot {
	return p.exponentialScale
}
func (p SelectorReraiseDecodePeriodicProfile) Square0Scale() ExactScaleSnapshot {
	return p.square0Scale
}
func (p SelectorReraiseDecodePeriodicProfile) RootScale() ExactScaleSnapshot { return p.rootScale }
func (p SelectorReraiseDecodePeriodicProfile) OutputScale() ExactScaleSnapshot {
	return p.outputScale
}
func (p SelectorReraiseDecodePeriodicProfile) RuntimePath() string { return p.runtimePath }

type SelectorReraiseDecodeProfile struct {
	fidelity                                   SelectorReraiseDecodeFidelity
	wordBits                                   z2n.WordBits
	words, slots                               int
	encoderPrecision, integerPrecision         uint
	parameterDigest, rangeDigest               string
	producerPublicDigest, producerOpaqueDigest string
	producerAdmissionDigest                    string
	producerParameterDigest                    string
	producerOnePayloadDigest                   string
	producerAuditAnchor                        SelectorReraiseDecodeComparatorAuditAnchor
	representation                             SelectorReraiseDecodeRepresentation
	resultSchema                               string
	normalV                                    SelectorReraiseDecodeTransformProfile
	dft                                        SelectorReraiseDecodeDFTProfile
	periodic                                   SelectorReraiseDecodePeriodicProfile
	operationCounts                            SelectorReraiseDecodeOperationCounts
	serializedBytes                            SelectorReraiseDecodeSerializedBytes
	logicalPeak                                int
	states                                     []SelectorReraiseDecodeStateProfile
	digest                                     string
}

func (p SelectorReraiseDecodeProfile) Fidelity() SelectorReraiseDecodeFidelity { return p.fidelity }
func (p SelectorReraiseDecodeProfile) WordBits() z2n.WordBits                  { return p.wordBits }
func (p SelectorReraiseDecodeProfile) Words() int                              { return p.words }
func (p SelectorReraiseDecodeProfile) Slots() int                              { return p.slots }
func (p SelectorReraiseDecodeProfile) EncoderPrecision() uint                  { return p.encoderPrecision }
func (p SelectorReraiseDecodeProfile) IntegerPrecision() uint                  { return p.integerPrecision }
func (p SelectorReraiseDecodeProfile) ParameterDigest() string                 { return p.parameterDigest }
func (p SelectorReraiseDecodeProfile) RangeDigest() string                     { return p.rangeDigest }
func (p SelectorReraiseDecodeProfile) ProducerPublicProfileDigest() string {
	return p.producerPublicDigest
}
func (p SelectorReraiseDecodeProfile) ProducerOpaqueProfileDigest() string {
	return p.producerOpaqueDigest
}
func (p SelectorReraiseDecodeProfile) ProducerInputBindingDigest() string {
	return p.producerAdmissionDigest
}
func (p SelectorReraiseDecodeProfile) ProducerParameterDigest() string {
	return p.producerParameterDigest
}
func (p SelectorReraiseDecodeProfile) ProducerArithmeticOnePayloadDigest() string {
	return p.producerOnePayloadDigest
}
func (p SelectorReraiseDecodeProfile) ProducerAuditAnchor() SelectorReraiseDecodeComparatorAuditAnchor {
	return p.producerAuditAnchor
}
func (p SelectorReraiseDecodeProfile) SelectorRepresentation() SelectorReraiseDecodeRepresentation {
	return p.representation
}
func (p SelectorReraiseDecodeProfile) ResultSchema() string { return p.resultSchema }
func (p SelectorReraiseDecodeProfile) NormalV() SelectorReraiseDecodeTransformProfile {
	return cloneSelectorReraiseDecodeTransformProfile(p.normalV)
}
func (p SelectorReraiseDecodeProfile) DFT() SelectorReraiseDecodeDFTProfile {
	return cloneSelectorReraiseDecodeDFTProfile(p.dft)
}
func (p SelectorReraiseDecodeProfile) Periodic() SelectorReraiseDecodePeriodicProfile {
	return p.periodic
}
func (p SelectorReraiseDecodeProfile) OperationCounts() SelectorReraiseDecodeOperationCounts {
	return p.operationCounts
}
func (p SelectorReraiseDecodeProfile) ExpectedSerializedBytes() SelectorReraiseDecodeSerializedBytes {
	return p.serializedBytes
}
func (p SelectorReraiseDecodeProfile) LogicalPeakLiveCiphertexts() int { return p.logicalPeak }
func (p SelectorReraiseDecodeProfile) States() []SelectorReraiseDecodeStateProfile {
	return append([]SelectorReraiseDecodeStateProfile(nil), p.states...)
}
func (p SelectorReraiseDecodeProfile) Digest() string { return p.digest }

type SelectorReraiseDecodeCircuit struct {
	producer         *Signed8ComparatorCircuit
	params           ckks.Parameters
	refreshEncoder   *ckks.Encoder
	integerEncoder   *ckks.Encoder
	normalVSource    PairSpec
	normalV          CompiledPair
	stc              ckksdft.Matrix
	cts              ckksdft.Matrix
	kernel           *GaoA2BKernelCircuit
	affineSource     selectorPeriodicAffineSource
	affineMultiplier *rlwe.Plaintext
	affineOffset     *rlwe.Plaintext
	profile          SelectorReraiseDecodeProfile
	keyProfile       SelectorReraiseDecodeKeyProfile
	graph            selectorReraiseDecodeCircuitGraphIdentity
}

type SelectorReraiseDecodeEvaluator struct {
	circuit            *SelectorReraiseDecodeCircuit
	source             *bootstrapping.Evaluator
	linear             *ckkslintrans.Evaluator
	producer           *Signed8ComparatorEvaluator
	kernel             *GaoA2BKernelEvaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	galoisKeys         map[uint64]*rlwe.GaloisKey
	sourceGraph        a2aiEvaluatorGraphIdentity
	graph              selectorReraiseDecodeEvaluatorGraphIdentity
}

type selectorReraiseDecodeEvaluatorGraphIdentity struct {
	evaluator               *SelectorReraiseDecodeEvaluator
	circuit                 *SelectorReraiseDecodeCircuit
	source                  *bootstrapping.Evaluator
	sourceMain              *ckks.Evaluator
	sourceDFT               *ckksdft.Evaluator
	linear                  *ckkslintrans.Evaluator
	producer                *Signed8ComparatorEvaluator
	kernel                  *GaoA2BKernelEvaluator
	kernelSource            *ckks.Evaluator
	kernelCKKS              *ckks.Evaluator
	kernelPolynomial        *ckkspolynomial.Evaluator
	kernelEncoder           *ckks.Encoder
	keySet                  *rlwe.MemEvaluationKeySet
	relinearizationKey      *rlwe.RelinearizationKey
	galoisKeyMapPointer     uintptr
	galoisElements          []uint64
	galoisKeyIdentities     []*rlwe.GaloisKey
	profileDigest           string
	producerPublicDigest    string
	producerOpaqueDigest    string
	producerAdmissionDigest string
}

func (c *SelectorReraiseDecodeCircuit) BindEvaluator(source *bootstrapping.Evaluator) (*SelectorReraiseDecodeEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if source == nil || source.Evaluator == nil || source.DFTEvaluator == nil || source.DFTEvaluator.LTEvaluator == nil ||
		source.EvaluationKeys == nil || source.MemEvaluationKeySet == nil {
		return nil, fmt.Errorf("homchain: incomplete selector bootstrap evaluator")
	}
	if !source.ResidualParameters.Equal(&c.params) || !source.BootstrappingParameters.Equal(&c.params) ||
		!c.params.Equal(source.Evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: selector evaluator parameters differ from the circuit")
	}
	if source.EvkDenseToSparse != nil || source.EvkSparseToDense != nil {
		return nil, fmt.Errorf("homchain: selector functional slice requires dense/no-switch ModUp")
	}
	if source.Mod1Parameters.LogMessageRatio != a2bRefreshLogMessageRatio ||
		source.Mod1Parameters.MessageRatio() != math.Exp2(a2bRefreshLogMessageRatio) {
		return nil, fmt.Errorf("homchain: selector requires the accepted A2B MessageRatio=2^15")
	}
	acceptedDFT := c.producer.a2b.refresh.profile.dft
	if !a2bRefreshLiteralEqual(source.SlotsToCoeffsParameters, acceptedDFT.stcExecutionLiteral) ||
		!a2bRefreshLiteralEqual(source.CoeffsToSlotsParameters, c.profile.dft.ctsExecution) {
		return nil, fmt.Errorf("homchain: selector bootstrap metadata differs from the accepted producer STC/shared CTS graph")
	}
	if gap := 1 << (c.params.LogN() - source.CoeffsToSlotsParameters.LogSlots - 1); gap != 1 {
		return nil, fmt.Errorf("homchain: selector full-packing Trace gap=%d, want 1", gap)
	}
	minimumScaleDown := float64(c.params.Q()[0]) * math.Exp2(-1e-6)
	requestedModUpScale := source.Mod1Parameters.ScalingFactor().Float64() / source.Mod1Parameters.MessageRatio()
	if requestedModUpScale > minimumScaleDown {
		return nil, fmt.Errorf("homchain: selector ModUp requested scale can exceed admitted ScaleDown scale")
	}
	producer, err := c.producer.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind selector comparator producer: %w", err)
	}
	keySet := source.MemEvaluationKeySet
	if producer.source != source || producer.keySet != keySet || source.EvaluationKeys.MemEvaluationKeySet != keySet {
		return nil, fmt.Errorf("homchain: selector comparator and reraiser do not share the exact source/keyset")
	}
	kernelSource := source.Evaluator.WithKey(keySet)
	kernel, err := c.kernel.BindEvaluator(kernelSource)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind selector accepted periodic exponential: %w", err)
	}
	if kernel.source != kernelSource || kernel.keySet != keySet || kernel.relinearizationKey == nil ||
		kernel.conjugationKey == nil {
		return nil, fmt.Errorf("homchain: selector periodic exponential does not share the exact source/keyset")
	}
	bridge := A2AIKeyProfile{All: c.keyProfile.All()}
	if _, err = a2bRefreshPreflightKeySet(source, c.producer.a2b.refresh, bridge); err != nil {
		return nil, err
	}
	sourceGraph, err := captureA2AIEvaluatorGraph(source, bridge)
	if err != nil {
		return nil, fmt.Errorf("homchain: capture selector evaluator graph: %w", err)
	}
	relinearizationKey, err := keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, fmt.Errorf("homchain: selector relinearization key is missing: %v", err)
	}
	galoisKeys := make(map[uint64]*rlwe.GaloisKey, len(c.keyProfile.all))
	galoisKeyIdentities := make([]*rlwe.GaloisKey, len(c.keyProfile.all))
	for index, element := range c.keyProfile.all {
		key, keyErr := keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil || key.GaloisElement != element {
			return nil, fmt.Errorf("homchain: selector Galois key %d is missing or invalid: %v", element, keyErr)
		}
		galoisKeys[element] = key
		galoisKeyIdentities[index] = key
	}
	evaluator := &SelectorReraiseDecodeEvaluator{
		circuit: c, source: source, linear: source.DFTEvaluator.LTEvaluator, producer: producer, kernel: kernel, keySet: keySet,
		relinearizationKey: relinearizationKey, galoisKeys: galoisKeys, sourceGraph: sourceGraph,
	}
	evaluator.graph = selectorReraiseDecodeEvaluatorGraphIdentity{
		evaluator: evaluator, circuit: c, source: source, sourceMain: source.Evaluator,
		sourceDFT: source.DFTEvaluator, linear: source.DFTEvaluator.LTEvaluator, producer: producer,
		kernel: kernel, kernelSource: kernelSource, kernelCKKS: kernel.ckks, kernelPolynomial: kernel.polynomial, kernelEncoder: kernel.operationalEncoder,
		keySet: keySet, relinearizationKey: relinearizationKey,
		galoisKeyMapPointer: reflect.ValueOf(galoisKeys).Pointer(),
		galoisElements:      append([]uint64(nil), c.keyProfile.all...), galoisKeyIdentities: galoisKeyIdentities,
		profileDigest:        c.profile.digest,
		producerPublicDigest: c.producer.publicProfile.digest, producerOpaqueDigest: c.producer.opaqueProfile.digest,
		producerAdmissionDigest: c.producer.bindingDigest,
	}
	if _, err = evaluator.preflight(); err != nil {
		return nil, err
	}
	return evaluator, nil
}

func (e *SelectorReraiseDecodeEvaluator) preflight() (A2BRefreshKeyPreflight, error) {
	result := A2BRefreshKeyPreflight{Checked: true, GraphChecked: true}
	if e == nil || e.circuit == nil || e.source == nil || e.linear == nil || e.producer == nil || e.kernel == nil || e.keySet == nil {
		return result, fmt.Errorf("homchain: nil or incomplete bound selector evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		result.GraphMismatch = err.Error()
		return result, err
	}
	g := e.graph
	if g.evaluator != e || g.circuit != e.circuit || g.source != e.source || g.sourceMain != e.source.Evaluator ||
		g.sourceDFT != e.source.DFTEvaluator || g.linear != e.linear || g.producer != e.producer ||
		g.kernel != e.kernel || g.kernelSource != e.kernel.source || g.kernelCKKS != e.kernel.ckks || g.kernelPolynomial != e.kernel.polynomial ||
		g.kernelEncoder != e.kernel.operationalEncoder || g.keySet != e.keySet ||
		g.relinearizationKey != e.relinearizationKey || g.galoisKeyMapPointer != reflect.ValueOf(e.galoisKeys).Pointer() ||
		g.profileDigest != e.circuit.profile.digest || g.producerPublicDigest != e.circuit.producer.publicProfile.digest ||
		g.producerOpaqueDigest != e.circuit.producer.opaqueProfile.digest ||
		g.producerAdmissionDigest != e.circuit.producer.bindingDigest {
		result.GraphMismatch = "selector evaluator object graph changed"
		return result, fmt.Errorf("homchain: selector graph preflight failed: %s", result.GraphMismatch)
	}
	if err := validateSelectorReraiseDecodeGaloisCache(e, g); err != nil {
		result.GraphMismatch = err.Error()
		return result, fmt.Errorf("homchain: selector Galois-cache preflight failed: %w", err)
	}
	linearMain, ok := e.linear.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || linearMain != e.source.Evaluator || e.source.MemEvaluationKeySet != e.keySet ||
		e.source.EvaluationKeys == nil || e.source.EvaluationKeys.MemEvaluationKeySet != e.keySet ||
		e.producer.source != e.source || e.producer.keySet != e.keySet || e.kernel.source != g.kernelSource ||
		e.kernel.keySet != e.keySet {
		result.GraphMismatch = "selector source, linear evaluator, producer, or keyset identity changed"
		return result, fmt.Errorf("homchain: selector graph preflight failed: %s", result.GraphMismatch)
	}
	if err := e.sourceGraph.validateTopology(); err != nil {
		result.GraphMismatch = err.Error()
		return result, fmt.Errorf("homchain: selector source graph preflight failed: %w", err)
	}
	if err := e.sourceGraph.validateKeyIdentities(); err != nil {
		result.GraphMismatch = err.Error()
		return result, fmt.Errorf("homchain: selector source key identity failed: %w", err)
	}
	producerPreflight, err := e.producer.preflight()
	if err != nil {
		return producerPreflight, err
	}
	if err = e.kernel.preflightGraphAndKeys(); err != nil {
		return result, fmt.Errorf("homchain: selector periodic exponential preflight: %w", err)
	}
	if e.kernel.relinearizationKey != e.relinearizationKey || e.kernel.conjugationKey != e.galoisKeys[e.circuit.params.GaloisElementForComplexConjugation()] {
		return result, fmt.Errorf("homchain: selector periodic exponential key identities differ from the sealed selector graph")
	}
	bridge := A2AIKeyProfile{All: e.circuit.keyProfile.All()}
	result, err = a2bRefreshPreflightKeySet(e.source, e.circuit.producer.a2b.refresh, bridge)
	if err != nil {
		return result, err
	}
	relinearizationKey, err := e.keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil || relinearizationKey != e.relinearizationKey {
		return result, fmt.Errorf("homchain: selector relinearization-key identity changed before evaluation")
	}
	result.GraphMatched = true
	return result, nil
}

func validateSelectorReraiseDecodeGaloisCache(
	e *SelectorReraiseDecodeEvaluator,
	g selectorReraiseDecodeEvaluatorGraphIdentity,
) error {
	if e == nil || e.circuit == nil || e.keySet == nil || e.galoisKeys == nil ||
		!reflect.DeepEqual(g.galoisElements, e.circuit.keyProfile.all) ||
		len(g.galoisKeyIdentities) != len(g.galoisElements) {
		return fmt.Errorf("sealed selector Galois-cache inventory is incomplete")
	}
	actualElements := make([]uint64, 0, len(e.galoisKeys))
	for element := range e.galoisKeys {
		actualElements = append(actualElements, element)
	}
	sort.Slice(actualElements, func(i, j int) bool { return actualElements[i] < actualElements[j] })
	if !reflect.DeepEqual(actualElements, g.galoisElements) {
		return fmt.Errorf("selector Galois-cache inventory=%v, want exact closed inventory %v", actualElements, g.galoisElements)
	}
	for index, element := range g.galoisElements {
		expected := g.galoisKeyIdentities[index]
		cached, ok := e.galoisKeys[element]
		keySetIdentity, keyErr := e.keySet.GetGaloisKey(element)
		if !ok || expected == nil || cached == nil || cached != expected || cached.GaloisElement != element ||
			keyErr != nil || keySetIdentity == nil || keySetIdentity != expected || keySetIdentity.GaloisElement != element {
			return fmt.Errorf("selector Galois-cache key %d identity changed", element)
		}
	}
	return nil
}

// EvaluateNew executes the production periodic Boolean decoder. It reuses
// only the accepted Gao exp46 operand and its two squarings; the ID/MSB LUTs
// are not evaluated.
func (e *SelectorReraiseDecodeEvaluator) EvaluateNew(input SelectorReraiseDecodeInput) (SelectorReraiseDecodeResult, SelectorReraiseDecodeTrace, error) {
	return e.evaluateNew(input)
}

func (e *SelectorReraiseDecodeEvaluator) evaluateNew(
	input SelectorReraiseDecodeInput,
) (result SelectorReraiseDecodeResult, trace SelectorReraiseDecodeTrace, err error) {
	started := time.Now()
	if e == nil || e.circuit == nil {
		return result, trace, fmt.Errorf("homchain: nil bound selector evaluator")
	}
	if err = e.circuit.validateInput(input); err != nil {
		return result, trace, err
	}
	preflight, err := e.preflight()
	if err != nil {
		return result, trace, err
	}
	// Re-authenticate the owned result immediately before the first operation.
	if err = e.circuit.validateInput(input); err != nil {
		return result, trace, err
	}
	inputBefore := input.branch.CopyNew()
	defer func() {
		if input.branch != nil && !input.branch.Equal(inputBefore) {
			result = SelectorReraiseDecodeResult{}
			err = fmt.Errorf("homchain: selector reraiser mutated its owned comparator-result input")
		}
	}()
	trace = SelectorReraiseDecodeTrace{
		profileDigest: e.circuit.profile.digest, producerProfileDigest: input.producerProfileDigest,
		rangeDigest: input.rangeDigest, inputProvenanceDigest: input.provenanceDigest,
		operandMode: input.operandMode, path: SelectorReraiseDecodePeriodicPath, keyPreflight: preflight,
	}
	if err = appendSelectorReraiseDecodeState(&trace, SelectorStageInput, SelectorReraiseDecodeWhole, input.branch); err != nil {
		return result, trace, err
	}
	trace.logicalPeakLive = 2 // owned input plus immutability witness

	vHalves, err := e.evaluateNormalV(input.branch, &trace)
	if err != nil {
		return result, trace, err
	}
	trace.normalVLow, trace.normalVHigh = vHalves[0].CopyNew(), vHalves[1].CopyNew()
	trace.logicalPeakLive = maxInt(trace.logicalPeakLive, 6)

	coefficients, err := e.evaluateSlotsToCoeffs(vHalves, &trace)
	if err != nil {
		return result, trace, err
	}
	trace.stc = coefficients.CopyNew()
	trace.logicalPeakLive = maxInt(trace.logicalPeakLive, 8)

	scaledDown, errScale, err := e.source.ScaleDown(coefficients.CopyNew())
	if err != nil || errScale == nil {
		return result, trace, fmt.Errorf("homchain: selector guarded ScaleDown: %w", err)
	}
	trace.operationCounts.ScaleDown++
	if !coefficients.Equal(trace.stc) {
		return result, trace, fmt.Errorf("homchain: selector ScaleDown mutated its saved STC core")
	}
	errLog2 := errScale.Log2()
	if math.IsNaN(errLog2) || math.IsInf(errLog2, 0) || math.Abs(errLog2) > 1e-6 {
		return result, trace, fmt.Errorf("homchain: selector ScaleDown |log2(errScale)|=%g exceeds 1e-6", math.Abs(errLog2))
	}
	trace.scaleDownError, err = NewExactScaleSnapshot(*errScale)
	if err != nil {
		return result, trace, err
	}
	trace.scaleDownLog2Error = errLog2
	targetScale := rlwe.NewScale(e.circuit.params.Q()[0]).Div(rlwe.NewScale(e.source.Mod1Parameters.MessageRatio()))
	if scaledDown.Level() != 0 || !scaledDown.Scale.Div(targetScale).Equal(*errScale) ||
		!b2aExactScaleEqual(scaledDown.Scale, e.circuit.params.DefaultScale()) {
		return result, trace, fmt.Errorf("homchain: selector ScaleDown did not land at exact L0/S35")
	}
	if err = appendSelectorReraiseDecodeState(&trace, SelectorStageScaleDown, SelectorReraiseDecodeWhole, scaledDown); err != nil {
		return result, trace, err
	}
	preModUpScale, err := NewExactScaleSnapshot(scaledDown.Scale)
	if err != nil {
		return result, trace, err
	}
	requestedScale := e.source.Mod1Parameters.ScalingFactor().Float64() / e.source.Mod1Parameters.MessageRatio()
	if requestedScale/scaledDown.Scale.Float64() > 1 {
		return result, trace, fmt.Errorf("homchain: selector ModUp would relabel raw scale")
	}
	raised, err := e.source.ModUp(scaledDown)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selector dense/no-switch ModUp: %w", err)
	}
	trace.operationCounts.ModUp++
	if raised.Level() != 20 || !preModUpScale.EqualScale(raised.Scale) ||
		!b2aExactScaleEqual(raised.Scale, e.circuit.params.DefaultScale()) {
		return result, trace, fmt.Errorf("homchain: selector ModUp changed the sealed L20/S35 state")
	}
	if err = appendSelectorReraiseDecodeState(&trace, SelectorStageModUp, SelectorReraiseDecodeWhole, raised); err != nil {
		return result, trace, err
	}
	trace.raised = raised.CopyNew()

	ctsHalves, err := e.evaluateCoeffsToSlots(raised, &trace)
	if err != nil {
		return result, trace, err
	}
	trace.ctsLow, trace.ctsHigh = ctsHalves[0].CopyNew(), ctsHalves[1].CopyNew()

	output, err := e.evaluatePeriodicBoolean(ctsHalves[0], &trace)
	if err != nil {
		return result, trace, err
	}
	if !input.branch.Equal(inputBefore) {
		return result, trace, fmt.Errorf("homchain: selector reraiser mutated its input")
	}
	trace.serializedBytes, err = measureSelectorReraiseDecodeSerializedBytes(input.branch, trace, output)
	if err != nil {
		return result, trace, err
	}
	trace.wallTime = time.Since(started)
	outputPayloadDigest, err := signed8CiphertextDigest(output)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: digest selector output: %w", err)
	}
	resultProvenanceDigest := digestSelectorReraiseDecodeResult(
		e.circuit.profile.digest, input.producerProfileDigest, input.rangeDigest, input.operandMode,
		SelectorReraiseDecodePeriodicPath, input.provenanceDigest, outputPayloadDigest,
	)
	trace.outputPayloadDigest = outputPayloadDigest
	trace.resultProvenanceDigest = resultProvenanceDigest
	if err = validateSelectorReraiseDecodeRuntimeEvidence(e.circuit.profile, input, trace, output); err != nil {
		return result, trace, err
	}
	result = SelectorReraiseDecodeResult{
		scalar: output, profileDigest: e.circuit.profile.digest, producerProfileDigest: input.producerProfileDigest,
		rangeDigest: input.rangeDigest, inputProvenanceDigest: input.provenanceDigest,
		operandMode: input.operandMode, path: SelectorReraiseDecodePeriodicPath,
		outputPayloadDigest: outputPayloadDigest, provenanceDigest: resultProvenanceDigest,
	}
	if err = e.circuit.validateResult(result); err != nil {
		return SelectorReraiseDecodeResult{}, trace, err
	}
	return result, trace, nil
}

func (e *SelectorReraiseDecodeEvaluator) evaluatePeriodicBoolean(
	input *rlwe.Ciphertext,
	trace *SelectorReraiseDecodeTrace,
) (*rlwe.Ciphertext, error) {
	if err := e.kernel.validateInput(input); err != nil {
		return nil, fmt.Errorf("homchain: selector periodic input: %w", err)
	}
	if err := e.kernel.preflightGraphAndKeys(); err != nil {
		return nil, fmt.Errorf("homchain: selector periodic preflight: %w", err)
	}
	exponentialOperand, err := cloneA2BKernelPolynomialVector(e.circuit.kernel.exponentialOperand)
	if err != nil {
		return nil, err
	}
	identityOperand, err := cloneA2BKernelPolynomialVector(e.circuit.kernel.identityOperand)
	if err != nil {
		return nil, err
	}
	msbOperand, err := cloneA2BKernelPolynomialVector(e.circuit.kernel.msbOperand)
	if err != nil {
		return nil, err
	}
	plan, err := inspectA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, e.circuit.params.MaxSlots())
	if err != nil || plan != e.circuit.kernel.profile.operandPlan ||
		digestA2BKernelOperands(exponentialOperand, identityOperand, msbOperand, plan) != e.circuit.kernel.profile.operandGraphDigest {
		return nil, fmt.Errorf("homchain: selector accepted exponential operand graph changed")
	}
	periodic := e.circuit.profile.periodic
	exponential, err := e.kernel.polynomial.Evaluate(input, exponentialOperand, e.circuit.params.DefaultScale())
	if err != nil {
		return nil, fmt.Errorf("homchain: evaluate selector accepted exp46: %w", err)
	}
	trace.operationCounts.ExponentialPolynomialEvaluations++
	if exponential.Level() != periodic.exponentialLevel || exponential.Degree() != 1 ||
		!periodic.exponentialScale.EqualScale(exponential.Scale) {
		return nil, fmt.Errorf("homchain: selector exp46 state changed: L%d/degree%d/scale=%s", exponential.Level(), exponential.Degree(), exponential.Scale.Value.Text('x', -1))
	}
	if err = appendSelectorReraiseDecodeState(trace, SelectorStagePeriodicExp, SelectorReraiseDecodeLow, exponential); err != nil {
		return nil, err
	}
	trace.exponential = exponential.CopyNew()

	root := exponential
	for round, stage := range [...]SelectorReraiseDecodeStage{SelectorStagePeriodicSq0, SelectorStagePeriodicRoot} {
		previousLevel := root.Level()
		root, err = e.kernel.ckks.MulRelinNew(root, root)
		if err != nil {
			return nil, fmt.Errorf("homchain: selector periodic square %d MulRelinNew: %w", round, err)
		}
		trace.operationCounts.CiphertextCiphertextProducts++
		trace.operationCounts.Relinearizations++
		if err = e.kernel.ckks.Rescale(root, root); err != nil {
			return nil, fmt.Errorf("homchain: selector periodic square %d Rescale: %w", round, err)
		}
		trace.operationCounts.ExplicitRescales++
		wantLevel := []int{periodic.square0Level, periodic.rootLevel}[round]
		wantScale := []ExactScaleSnapshot{periodic.square0Scale, periodic.rootScale}[round]
		if root.Level() != previousLevel-1 || root.Level() != wantLevel || root.Degree() != 1 || !wantScale.EqualScale(root.Scale) {
			return nil, fmt.Errorf("homchain: selector periodic square %d state changed", round)
		}
		if err = appendSelectorReraiseDecodeState(trace, stage, SelectorReraiseDecodeLow, root); err != nil {
			return nil, err
		}
	}
	trace.periodicRoot = root.CopyNew()

	multiplierDigest, err := selectorPeriodicPlaintextDigest(e.circuit.affineMultiplier)
	if err != nil || multiplierDigest != periodic.multiplierPayloadDigest {
		return nil, fmt.Errorf("homchain: selector periodic multiplier payload changed")
	}
	offsetDigest, err := selectorPeriodicPlaintextDigest(e.circuit.affineOffset)
	if err != nil || offsetDigest != periodic.offsetPayloadDigest {
		return nil, fmt.Errorf("homchain: selector periodic offset payload changed")
	}
	output, err := e.kernel.ckks.MulNew(root, e.circuit.affineMultiplier)
	if err != nil {
		return nil, fmt.Errorf("homchain: selector periodic affine multiply: %w", err)
	}
	trace.operationCounts.CiphertextPlaintextProducts++
	if output.Level() != periodic.rootLevel || output.Degree() != 1 {
		return nil, fmt.Errorf("homchain: selector periodic affine raw state changed")
	}
	if err = appendSelectorReraiseDecodeState(trace, SelectorStageAffineRaw, SelectorReraiseDecodeLow, output); err != nil {
		return nil, err
	}
	if err = e.kernel.ckks.Rescale(output, output); err != nil {
		return nil, fmt.Errorf("homchain: selector periodic affine rescale: %w", err)
	}
	trace.operationCounts.ExplicitRescales++
	if output.Level() != periodic.outputLevel || output.Degree() != 1 || !periodic.outputScale.EqualScale(output.Scale) {
		return nil, fmt.Errorf("homchain: selector periodic affine rescaled state changed")
	}
	if err = e.kernel.ckks.Add(output, e.circuit.affineOffset, output); err != nil {
		return nil, fmt.Errorf("homchain: selector periodic affine offset: %w", err)
	}
	trace.operationCounts.CiphertextAdditionsSubtractions++
	trace.operationCounts.PlaintextVectorAdditions++
	if err = appendSelectorReraiseDecodeState(trace, SelectorStageOutput, SelectorReraiseDecodeWhole, output); err != nil {
		return nil, err
	}
	return output, nil
}

func (e *SelectorReraiseDecodeEvaluator) evaluateNormalV(
	input *rlwe.Ciphertext,
	trace *SelectorReraiseDecodeTrace,
) (CiphertextPair, error) {
	outputs, err := e.linear.EvaluateManyNew(input, []ckkslintrans.LinearTransformation{e.circuit.normalV.Low, e.circuit.normalV.High})
	if err != nil {
		return CiphertextPair{}, fmt.Errorf("homchain: selector normal-V pair: %w", err)
	}
	diagonals, rotations, _, err := selectorVPairCounts(e.circuit.normalV)
	if err != nil {
		return CiphertextPair{}, err
	}
	trace.operationCounts.LinearTransformations += 2
	trace.operationCounts.DiagonalPlaintextProducts += diagonals
	trace.operationCounts.NonConjugationRotations += rotations
	trace.operationCounts.KeySwitches += rotations
	trace.operationCounts.CiphertextAdditionsSubtractions += diagonals - 2
	var result CiphertextPair
	for index, output := range outputs {
		lane := []SelectorReraiseDecodeLane{SelectorReraiseDecodeLow, SelectorReraiseDecodeHigh}[index]
		conjugate, conjugateErr := e.source.Evaluator.ConjugateNew(output)
		if conjugateErr != nil {
			return CiphertextPair{}, fmt.Errorf("homchain: selector normal-V %s conjugation: %w", lane, conjugateErr)
		}
		trace.operationCounts.Conjugations++
		trace.operationCounts.KeySwitches++
		if err = e.source.Evaluator.Add(output, conjugate, output); err != nil {
			return CiphertextPair{}, fmt.Errorf("homchain: selector normal-V %s real projection: %w", lane, err)
		}
		trace.operationCounts.CiphertextAdditionsSubtractions++
		if err = appendSelectorReraiseDecodeState(trace, SelectorStageVRaw, lane, output); err != nil {
			return CiphertextPair{}, err
		}
	}
	for index, output := range outputs {
		lane := []SelectorReraiseDecodeLane{SelectorReraiseDecodeLow, SelectorReraiseDecodeHigh}[index]
		if err = e.source.Evaluator.Rescale(output, output); err != nil {
			return CiphertextPair{}, fmt.Errorf("homchain: selector normal-V %s rescale: %w", lane, err)
		}
		trace.operationCounts.ExplicitRescales++
		if err = appendSelectorReraiseDecodeState(trace, SelectorStageV, lane, output); err != nil {
			return CiphertextPair{}, err
		}
		result[index] = output
	}
	return result, nil
}

func (e *SelectorReraiseDecodeEvaluator) evaluateSlotsToCoeffs(
	halves CiphertextPair,
	trace *SelectorReraiseDecodeTrace,
) (*rlwe.Ciphertext, error) {
	imaginary, err := e.source.Evaluator.MulNew(halves[1], 1i)
	if err != nil {
		return nil, fmt.Errorf("homchain: selector STC multiply high by i: %w", err)
	}
	trace.operationCounts.ScalarMultiplicationsPlusMinusI++
	current, err := e.source.Evaluator.AddNew(halves[0], imaginary)
	if err != nil {
		return nil, fmt.Errorf("homchain: selector STC combine coefficient halves: %w", err)
	}
	trace.operationCounts.CiphertextAdditionsSubtractions++
	stages := []SelectorReraiseDecodeStage{SelectorStageSTCFactor0, SelectorStageSTCFactor1}
	for index, factor := range e.circuit.stc.Matrices {
		current, err = e.evaluateLinearFactor(current, factor, stages[index], trace)
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

func (e *SelectorReraiseDecodeEvaluator) evaluateCoeffsToSlots(
	input *rlwe.Ciphertext,
	trace *SelectorReraiseDecodeTrace,
) (CiphertextPair, error) {
	current := input
	stages := []SelectorReraiseDecodeStage{SelectorStageCTSFactor0, SelectorStageCTSFactor1, SelectorStageCTSFactor2}
	var err error
	for index, factor := range e.circuit.cts.Matrices {
		current, err = e.evaluateLinearFactor(current, factor, stages[index], trace)
		if err != nil {
			return CiphertextPair{}, err
		}
	}
	conjugate, err := e.source.Evaluator.ConjugateNew(current)
	if err != nil {
		return CiphertextPair{}, fmt.Errorf("homchain: selector CTS conjugation: %w", err)
	}
	trace.operationCounts.Conjugations++
	trace.operationCounts.KeySwitches++
	imaginary, err := e.source.Evaluator.SubNew(current, conjugate)
	if err != nil {
		return CiphertextPair{}, fmt.Errorf("homchain: selector CTS imaginary subtraction: %w", err)
	}
	trace.operationCounts.CiphertextAdditionsSubtractions++
	if err = e.source.Evaluator.Mul(imaginary, -1i, imaginary); err != nil {
		return CiphertextPair{}, fmt.Errorf("homchain: selector CTS imaginary -i multiply: %w", err)
	}
	trace.operationCounts.ScalarMultiplicationsPlusMinusI++
	real, err := e.source.Evaluator.AddNew(conjugate, current)
	if err != nil {
		return CiphertextPair{}, fmt.Errorf("homchain: selector CTS real addition: %w", err)
	}
	trace.operationCounts.CiphertextAdditionsSubtractions++
	if err = appendSelectorReraiseDecodeState(trace, SelectorStageCTS, SelectorReraiseDecodeLow, real); err != nil {
		return CiphertextPair{}, err
	}
	if err = appendSelectorReraiseDecodeState(trace, SelectorStageCTS, SelectorReraiseDecodeHigh, imaginary); err != nil {
		return CiphertextPair{}, err
	}
	return CiphertextPair{real, imaginary}, nil
}

func (e *SelectorReraiseDecodeEvaluator) evaluateLinearFactor(
	input *rlwe.Ciphertext,
	factor ckkslintrans.LinearTransformation,
	stage SelectorReraiseDecodeStage,
	trace *SelectorReraiseDecodeTrace,
) (*rlwe.Ciphertext, error) {
	output, err := e.linear.EvaluateNew(input, factor)
	if err != nil {
		return nil, fmt.Errorf("homchain: selector %s linear factor: %w", stage, err)
	}
	trace.operationCounts.LinearTransformations++
	trace.operationCounts.DiagonalPlaintextProducts += len(factor.Vec)
	rotations := len(signFusionRotationIndexes(factor))
	trace.operationCounts.NonConjugationRotations += rotations
	trace.operationCounts.KeySwitches += rotations
	trace.operationCounts.CiphertextAdditionsSubtractions += len(factor.Vec) - 1
	if err = e.source.Evaluator.Rescale(output, output); err != nil {
		return nil, fmt.Errorf("homchain: selector %s rescale: %w", stage, err)
	}
	trace.operationCounts.ExplicitRescales++
	if err = appendSelectorReraiseDecodeState(trace, stage, SelectorReraiseDecodeWhole, output); err != nil {
		return nil, err
	}
	return output, nil
}

func appendSelectorReraiseDecodeState(
	trace *SelectorReraiseDecodeTrace,
	stage SelectorReraiseDecodeStage,
	lane SelectorReraiseDecodeLane,
	ciphertext *rlwe.Ciphertext,
) error {
	if trace == nil || ciphertext == nil || ciphertext.MetaData == nil {
		return fmt.Errorf("homchain: cannot snapshot selector %s/%s ciphertext", stage, lane)
	}
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return err
	}
	trace.states = append(trace.states, SelectorReraiseDecodeCiphertextState{
		Stage: stage, Lane: lane, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale,
	})
	return nil
}

func selectorReraiseDecodeExpectedStateOrder() ([]SelectorReraiseDecodeStage, []SelectorReraiseDecodeLane) {
	stages := []SelectorReraiseDecodeStage{
		SelectorStageInput, SelectorStageVRaw, SelectorStageVRaw, SelectorStageV, SelectorStageV,
		SelectorStageSTCFactor0, SelectorStageSTCFactor1, SelectorStageScaleDown, SelectorStageModUp,
		SelectorStageCTSFactor0, SelectorStageCTSFactor1, SelectorStageCTSFactor2,
		SelectorStageCTS, SelectorStageCTS,
	}
	lanes := []SelectorReraiseDecodeLane{
		SelectorReraiseDecodeWhole, SelectorReraiseDecodeLow, SelectorReraiseDecodeHigh,
		SelectorReraiseDecodeLow, SelectorReraiseDecodeHigh,
		SelectorReraiseDecodeWhole, SelectorReraiseDecodeWhole, SelectorReraiseDecodeWhole, SelectorReraiseDecodeWhole,
		SelectorReraiseDecodeWhole, SelectorReraiseDecodeWhole, SelectorReraiseDecodeWhole,
		SelectorReraiseDecodeLow, SelectorReraiseDecodeHigh,
	}
	return append(stages,
			SelectorStagePeriodicExp, SelectorStagePeriodicSq0, SelectorStagePeriodicRoot, SelectorStageAffineRaw, SelectorStageOutput,
		), append(lanes,
			SelectorReraiseDecodeLow, SelectorReraiseDecodeLow, SelectorReraiseDecodeLow, SelectorReraiseDecodeLow, SelectorReraiseDecodeWhole,
		)
}

func validateSelectorReraiseDecodeRuntimeEvidence(
	profile SelectorReraiseDecodeProfile,
	input SelectorReraiseDecodeInput,
	trace SelectorReraiseDecodeTrace,
	output *rlwe.Ciphertext,
) error {
	outputPayloadDigest, err := signed8CiphertextDigest(output)
	if err != nil {
		return fmt.Errorf("homchain: digest selector runtime output: %w", err)
	}
	resultProvenanceDigest := digestSelectorReraiseDecodeResult(
		profile.digest, input.producerProfileDigest, input.rangeDigest, input.operandMode,
		SelectorReraiseDecodePeriodicPath, input.provenanceDigest, outputPayloadDigest,
	)
	if trace.profileDigest != profile.digest || trace.producerProfileDigest != input.producerProfileDigest ||
		trace.rangeDigest != input.rangeDigest || trace.inputProvenanceDigest != input.provenanceDigest ||
		trace.operandMode != input.operandMode || trace.outputPayloadDigest != outputPayloadDigest ||
		trace.resultProvenanceDigest != resultProvenanceDigest || trace.wallTime <= 0 {
		return fmt.Errorf("homchain: selector runtime provenance differs from the actual producer instance")
	}
	wantCounts, wantStates, wantPeak := profile.operationCounts, profile.states, profile.logicalPeak
	if trace.path != SelectorReraiseDecodePeriodicPath {
		return fmt.Errorf("homchain: selector runtime path is invalid")
	}
	if trace.operationCounts != wantCounts || trace.logicalPeakLive != wantPeak {
		return fmt.Errorf("homchain: selector runtime ledger=%+v/peak=%d, want %+v/peak=%d", trace.operationCounts, trace.logicalPeakLive, wantCounts, wantPeak)
	}
	observedBytes, err := measureSelectorReraiseDecodeSerializedBytes(input.branch, trace, output)
	if err != nil {
		return err
	}
	if !trace.serializedBytes.complete() || trace.serializedBytes != observedBytes ||
		trace.serializedBytes != profile.serializedBytes {
		return fmt.Errorf("homchain: selector serialized-byte ledger=%+v, recomputed=%+v, profile=%+v",
			trace.serializedBytes, observedBytes, profile.serializedBytes)
	}
	stages, lanes := selectorReraiseDecodeExpectedStateOrder()
	if len(trace.states) != len(wantStates) || len(stages) != len(wantStates) {
		return fmt.Errorf("homchain: selector runtime recorded %d states, want %d", len(trace.states), len(wantStates))
	}
	for index, state := range trace.states {
		if state.Stage != stages[index] || state.Lane != lanes[index] || state.Level != wantStates[index].level ||
			state.Degree != 1 || state.LogDimensions != input.branch.LogDimensions ||
			!wantStates[index].scale.Equal(state.Scale) {
			return fmt.Errorf("homchain: selector runtime state %d differs from the sealed ordered ledger: %+v", index, state)
		}
	}
	if !trace.keyPreflight.Checked || !trace.keyPreflight.GraphChecked || !trace.keyPreflight.GraphMatched ||
		!trace.keyPreflight.RelinearizationMatched || !trace.keyPreflight.DenseNoSwitchingMatched ||
		len(trace.keyPreflight.MissingGaloisElements) != 0 || len(trace.keyPreflight.InvalidGaloisElements) != 0 ||
		len(trace.keyPreflight.UnexpectedGaloisElements) != 0 {
		return fmt.Errorf("homchain: selector runtime key preflight differs from the sealed graph")
	}
	return nil
}

func measureSelectorReraiseDecodeSerializedBytes(
	input *rlwe.Ciphertext,
	trace SelectorReraiseDecodeTrace,
	output *rlwe.Ciphertext,
) (SelectorReraiseDecodeSerializedBytes, error) {
	boundaries := []struct {
		name       string
		ciphertext *rlwe.Ciphertext
	}{
		{"online input", input},
		{"online output", output},
		{"retained normal-V low", trace.normalVLow},
		{"retained normal-V high", trace.normalVHigh},
		{"retained SlotsToCoeffs", trace.stc},
		{"retained raised coefficients", trace.raised},
		{"retained CoeffsToSlots low", trace.ctsLow},
		{"retained CoeffsToSlots high", trace.ctsHigh},
		{"retained exponential base", trace.exponential},
		{"retained periodic root of unity", trace.periodicRoot},
	}
	seen := make(map[*rlwe.Ciphertext]string, len(boundaries))
	sizes := make([]int, len(boundaries))
	for index, boundary := range boundaries {
		if boundary.ciphertext == nil {
			return SelectorReraiseDecodeSerializedBytes{}, fmt.Errorf("homchain: marshal nil selector %s", boundary.name)
		}
		if previous, exists := seen[boundary.ciphertext]; exists {
			return SelectorReraiseDecodeSerializedBytes{}, fmt.Errorf("homchain: selector %s aliases %s and would be double counted", boundary.name, previous)
		}
		seen[boundary.ciphertext] = boundary.name
		payload, err := boundary.ciphertext.MarshalBinary()
		if err != nil {
			return SelectorReraiseDecodeSerializedBytes{}, fmt.Errorf("homchain: marshal selector %s: %w", boundary.name, err)
		}
		sizes[index] = len(payload)
	}
	return SelectorReraiseDecodeSerializedBytes{
		OnlineInput: sizes[0], OnlineOutput: sizes[1],
		RetainedNormalVLow: sizes[2], RetainedNormalVHigh: sizes[3],
		RetainedSlotsToCoeffs: sizes[4], RetainedRaisedCoefficients: sizes[5],
		RetainedCoeffsToSlotsLow: sizes[6], RetainedCoeffsToSlotsHigh: sizes[7],
		RetainedExponentialBase: sizes[8], RetainedPeriodicRootOfUnity: sizes[9],
	}, nil
}

func newSelectorReraiseDecodeSerializedByteProfile(
	params ckks.Parameters,
	states []SelectorReraiseDecodeStateProfile,
) (SelectorReraiseDecodeSerializedBytes, error) {
	const stateCount = 19
	if len(states) != stateCount {
		return SelectorReraiseDecodeSerializedBytes{}, fmt.Errorf("homchain: selector serialization profile has %d states, want %d", len(states), stateCount)
	}
	newTemplate := func(index int) (*rlwe.Ciphertext, error) {
		ciphertext := ckks.NewCiphertext(params, 1, states[index].level)
		scale, err := states[index].scale.Scale()
		if err != nil {
			return nil, err
		}
		// This is an unencrypted zero serialization template. Assigning its
		// scheduled metadata cannot retag a live or evaluated ciphertext.
		ciphertext.Scale = scale
		return ciphertext, nil
	}
	indexes := []int{0, 18, 3, 4, 6, 8, 12, 13, 14, 16}
	templates := make([]*rlwe.Ciphertext, len(indexes))
	for index, stateIndex := range indexes {
		var err error
		if templates[index], err = newTemplate(stateIndex); err != nil {
			return SelectorReraiseDecodeSerializedBytes{}, err
		}
	}
	return measureSelectorReraiseDecodeSerializedBytes(templates[0], SelectorReraiseDecodeTrace{
		normalVLow: templates[2], normalVHigh: templates[3], stc: templates[4], raised: templates[5],
		ctsLow: templates[6], ctsHigh: templates[7], exponential: templates[8], periodicRoot: templates[9],
	}, templates[1])
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

type selectorReraiseDecodeCircuitGraphIdentity struct {
	circuit                                           *SelectorReraiseDecodeCircuit
	producer                                          *Signed8ComparatorCircuit
	refreshEncoder, integerEncoder                    *ckks.Encoder
	kernel                                            *GaoA2BKernelCircuit
	affineMultiplier, affineOffset                    *rlwe.Plaintext
	normalVLow, normalVHigh                           uintptr
	stcFactors, ctsFactors                            []uintptr
	normalVDigests                                    [2]string
	stcDigests, ctsDigests                            []string
	kernelProfileDigest, kernelOperandGraphDigest     string
	affineSourceDigest                                string
	affineMultiplierDigest, affineOffsetDigest        string
	profileDigest, keyDigest                          string
	producerPublicDigest, producerOpaqueDigest        string
	producerAdmissionDigest, producerRangeDigest      string
	producerParameterDigest, producerOnePayloadDigest string
}

func (c *SelectorReraiseDecodeCircuit) Profile() SelectorReraiseDecodeProfile {
	if c == nil {
		return SelectorReraiseDecodeProfile{}
	}
	return cloneSelectorReraiseDecodeProfile(c.profile)
}
func (c *SelectorReraiseDecodeCircuit) RequiredKeyProfile() SelectorReraiseDecodeKeyProfile {
	if c == nil {
		return SelectorReraiseDecodeKeyProfile{}
	}
	result := c.keyProfile
	result.all = c.keyProfile.All()
	return result
}

func cloneSelectorReraiseDecodeProfile(p SelectorReraiseDecodeProfile) SelectorReraiseDecodeProfile {
	p.normalV = cloneSelectorReraiseDecodeTransformProfile(p.normalV)
	p.dft = cloneSelectorReraiseDecodeDFTProfile(p.dft)
	p.states = p.States()
	return p
}

// BindComparatorResult authenticates an output of this circuit's actual
// range-bound comparator producer and returns an owned selector input.
func (c *SelectorReraiseDecodeCircuit) BindComparatorResult(result Signed8ComparatorResult) (SelectorReraiseDecodeInput, error) {
	if err := c.validate(); err != nil {
		return SelectorReraiseDecodeInput{}, err
	}
	producerProfile := c.producer.profileForMode(result.operandMode)
	if producerProfile.digest == "" || result.branch == nil || result.profileDigest != producerProfile.digest ||
		result.rangeDigest != c.producer.ranges.digest {
		return SelectorReraiseDecodeInput{}, fmt.Errorf("homchain: selector comparator result has a foreign mode, profile, range, or payload")
	}
	if err := requireSigned8CiphertextState("selector comparator result", result.branch, producerProfile.outputState, c.params); err != nil {
		return SelectorReraiseDecodeInput{}, err
	}
	owned := result.branch.CopyNew()
	payloadDigest, err := signed8CiphertextDigest(owned)
	if err != nil {
		return SelectorReraiseDecodeInput{}, err
	}
	provenance := digestSelectorReraiseDecodeInput(
		c.profile.digest, producerProfile.digest, c.producer.ranges.digest, result.operandMode, payloadDigest,
	)
	return SelectorReraiseDecodeInput{
		branch: owned, pathProfileDigest: c.profile.digest, producerProfileDigest: producerProfile.digest,
		rangeDigest: c.producer.ranges.digest, operandMode: result.operandMode,
		payloadDigest: payloadDigest, provenanceDigest: provenance,
	}, nil
}

func digestSelectorReraiseDecodeInput(
	profileDigest, producerProfileDigest, rangeDigest string,
	mode Signed8ComparatorOperandMode,
	payloadDigest string,
) string {
	return digestString(fmt.Sprintf(
		"%s|selector-profile=%s|producer-profile=%s|range=%s|mode=%s|payload=%s|representation=%s",
		selectorReraiseDecodeInputSchema, profileDigest, producerProfileDigest, rangeDigest, mode, payloadDigest,
		SelectorArithmeticRootCoefficientsToPeriodicBooleanScalarRepeated,
	))
}

func digestSelectorReraiseDecodeResult(
	profileDigest, producerProfileDigest, rangeDigest string,
	mode Signed8ComparatorOperandMode,
	path SelectorReraiseDecodePath,
	inputProvenanceDigest, outputPayloadDigest string,
) string {
	return digestString(fmt.Sprintf(
		"%s|selector-profile=%s|producer-profile=%s|range=%s|mode=%s|path=%s|input-provenance=%s|output-payload=%s",
		selectorReraiseDecodeResultSchema, profileDigest, producerProfileDigest, rangeDigest, mode, path,
		inputProvenanceDigest, outputPayloadDigest,
	))
}

func isSelectorReraiseDecodeSHA256Digest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == 64 && len(decoded) == 32
}

func (c *SelectorReraiseDecodeCircuit) validateInput(input SelectorReraiseDecodeInput) error {
	if err := c.validate(); err != nil {
		return err
	}
	producerProfile := c.producer.profileForMode(input.operandMode)
	if producerProfile.digest == "" || input.branch == nil {
		return fmt.Errorf("homchain: nil or unsupported selector input")
	}
	if err := requireSigned8CiphertextState("selector input", input.branch, producerProfile.outputState, c.params); err != nil {
		return err
	}
	payloadDigest, err := signed8CiphertextDigest(input.branch)
	if err != nil {
		return err
	}
	if input.pathProfileDigest != c.profile.digest || input.producerProfileDigest != producerProfile.digest ||
		input.rangeDigest != c.producer.ranges.digest || input.payloadDigest != payloadDigest ||
		input.provenanceDigest != digestSelectorReraiseDecodeInput(
			c.profile.digest, producerProfile.digest, c.producer.ranges.digest, input.operandMode, payloadDigest,
		) {
		return fmt.Errorf("homchain: selector input has foreign profile, producer, range, payload, or provenance")
	}
	return nil
}

// validateResult authenticates an exact selector output produced by this
// range-bound circuit. It is package-private so downstream typed adapters can
// verify the producer seal without admitting a raw ciphertext.
func (c *SelectorReraiseDecodeCircuit) validateResult(result SelectorReraiseDecodeResult) error {
	if err := c.validate(); err != nil {
		return err
	}
	producerProfile := c.producer.profileForMode(result.operandMode)
	periodic := c.profile.periodic
	if producerProfile.digest == "" || result.scalar == nil || result.scalar.MetaData == nil {
		return fmt.Errorf("homchain: nil or unsupported selector result")
	}
	if result.scalar.Level() != periodic.outputLevel || result.scalar.Degree() != 1 ||
		result.scalar.LogN() != c.params.LogN() || result.scalar.LogDimensions != c.params.LogMaxDimensions() ||
		result.scalar.Slots() != c.profile.slots || !result.scalar.IsBatched || !result.scalar.IsNTT ||
		!periodic.outputScale.EqualScale(result.scalar.Scale) {
		return fmt.Errorf("homchain: selector result is not the exact sealed L%d periodic output", periodic.outputLevel)
	}
	outputPayloadDigest, err := signed8CiphertextDigest(result.scalar)
	if err != nil {
		return err
	}
	wantProvenance := digestSelectorReraiseDecodeResult(
		c.profile.digest, producerProfile.digest, c.producer.ranges.digest, result.operandMode,
		SelectorReraiseDecodePeriodicPath, result.inputProvenanceDigest, outputPayloadDigest,
	)
	if result.profileDigest != c.profile.digest || result.producerProfileDigest != producerProfile.digest ||
		result.rangeDigest != c.producer.ranges.digest || result.path != SelectorReraiseDecodePeriodicPath ||
		!isSelectorReraiseDecodeSHA256Digest(result.inputProvenanceDigest) ||
		result.outputPayloadDigest != outputPayloadDigest || result.provenanceDigest != wantProvenance {
		return fmt.Errorf("homchain: selector result has foreign profile, producer, range, mode, path, payload, or provenance")
	}
	return nil
}

func NewSelectorReraiseDecodeCircuit(producer *Signed8ComparatorCircuit) (*SelectorReraiseDecodeCircuit, error) {
	if producer == nil {
		return nil, fmt.Errorf("homchain: nil signed8 comparator producer")
	}
	if err := producer.validate(); err != nil {
		return nil, fmt.Errorf("homchain: validate selector comparator producer: %w", err)
	}
	if err := validateSelectorReraiseDecodeAcceptedProducerProfiles(producer.PublicProfile(), producer.OpaqueProfile()); err != nil {
		return nil, err
	}
	params := producer.params
	if producer.refreshEncoder == nil || producer.refreshEncoder.Prec() != signed8RefreshEncoderPrecision ||
		producer.integerEncoder == nil || producer.integerEncoder.Prec() != signed8IntegerEncoderPrecision {
		return nil, fmt.Errorf("homchain: selector producer encoder graph is incomplete")
	}
	if err := validateA2BRefreshParameters(params); err != nil {
		return nil, err
	}

	refreshRing, err := z2n.NewWithPrecision(z2n.Word8, signed8RefreshEncoderPrecision)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct selector refresh ring: %w", err)
	}
	refreshSpecifications, err := NewSpecificationsFromRing(refreshRing, selectorReraiseDecodeWords)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct selector refresh transform sources: %w", err)
	}
	normalVSource := refreshSpecifications.VPair()
	vOptions := CompileOptions{LevelQ: 4, LevelP: 0, Scale: rlwe.NewScale(params.Q()[4]), LogBabyStepGiantStepRatio: 0}
	normalV, err := CompilePair(params, producer.refreshEncoder, normalVSource, vOptions)
	if err != nil {
		return nil, fmt.Errorf("homchain: compile selector normal V: %w", err)
	}
	normalVProfile, err := newSelectorPairProfile(params, normalVSource, normalV, vOptions)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(normalVProfile.lowDiagonals, []int{0, 1, 2, 3, 13, 14, 15}) ||
		!reflect.DeepEqual(normalVProfile.highDiagonals, []int{0, 1, 2, 3, 13, 14, 15}) ||
		normalVProfile.lowN1 != 2 || normalVProfile.highN1 != 2 ||
		!reflect.DeepEqual(normalVProfile.rotations, []int{1, 2, 12, 14}) ||
		!reflect.DeepEqual(normalVProfile.galois, []uint64{5, 17, 25, 41}) {
		return nil, fmt.Errorf("homchain: compiled selector normal V differs from the audited T1 map")
	}

	stcRaw, ctsRaw := a2bRefreshDFTLiterals(params, producer.refreshEncoder.Prec(), 3, 20)
	stcFactor, ctsFactor, err := a2bRefreshDFTInitializationFactors(params)
	if err != nil {
		return nil, err
	}
	stcExecution := scaleA2BRefreshDFTLiteral(stcRaw, stcFactor, producer.refreshEncoder.Prec())
	ctsExecution := scaleA2BRefreshDFTLiteral(ctsRaw, ctsFactor, producer.refreshEncoder.Prec())
	stcRawDigest := digestDFTMatrixNumericPayload(stcRaw, stcRaw.GenMatrices(params.LogN(), producer.refreshEncoder.Prec()))
	ctsRawDigest := digestDFTMatrixNumericPayload(ctsRaw, ctsRaw.GenMatrices(params.LogN(), producer.refreshEncoder.Prec()))
	stc, stcExecutionDigest, err := newDFTMatrixFromLiteralAtPrecision(params, stcExecution, producer.refreshEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: compile selector low Slots-To-Coeffs: %w", err)
	}
	cts, ctsExecutionDigest, err := newDFTMatrixFromLiteralAtPrecision(params, ctsExecution, producer.refreshEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: compile selector shared Coeffs-To-Slots: %w", err)
	}
	acceptedDFT := producer.a2b.refresh.profile.dft
	if ctsRawDigest != acceptedDFT.ctsRawMatrixDigest || ctsExecutionDigest != producer.a2b.profile.sharedCTSDigest ||
		!a2bRefreshLiteralEqual(ctsRaw, acceptedDFT.ctsLiteral) ||
		!a2bRefreshLiteralEqual(ctsExecution, acceptedDFT.ctsExecutionLiteral) {
		return nil, fmt.Errorf("homchain: selector CTS is not the exact accepted shared A2B CTS")
	}
	dftProfile := SelectorReraiseDecodeDFTProfile{
		stcRaw: cloneDFTLiteral(stcRaw), ctsRaw: cloneDFTLiteral(ctsRaw),
		stcExecution: cloneDFTLiteral(stcExecution), ctsExecution: cloneDFTLiteral(ctsExecution),
		encoderPrecision: producer.refreshEncoder.Prec(), generatorPrecision: producer.refreshEncoder.Prec(),
		stcRawDigest: stcRawDigest, ctsRawDigest: ctsRawDigest,
		stcExecutionDigest: stcExecutionDigest, ctsExecutionDigest: ctsExecutionDigest,
	}
	dftProfile.digest = digestString(fmt.Sprintf(
		"selector-reraise-decode-dft-v1|raw-stc=%v|execution-stc=%v|raw-cts=%v|execution-cts=%v|precision=%d|raw-stc-digest=%s|execution-stc-digest=%s|raw-cts-digest=%s|execution-cts-digest=%s|shared-a2b-cts=%s",
		dftLiteralTrace(stcRaw), dftLiteralTrace(stcExecution), dftLiteralTrace(ctsRaw), dftLiteralTrace(ctsExecution),
		producer.refreshEncoder.Prec(), stcRawDigest, stcExecutionDigest, ctsRawDigest, ctsExecutionDigest,
		producer.a2b.profile.sharedCTSDigest,
	))
	kernel, err := NewGaoA2BKernelCircuit(params, producer.integerEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct selector accepted periodic kernel: %w", err)
	}
	affineSource, err := newSelectorPeriodicAffineSource(producer.integerEncoder.Prec())
	if err != nil {
		return nil, err
	}
	exponentialLevel := kernel.profile.inputLevel - kernel.exponentialOperand.Depth()
	square0Scale := params.DefaultScale().Mul(params.DefaultScale()).Div(rlwe.NewScale(params.Q()[exponentialLevel]))
	rootScale := square0Scale.Mul(square0Scale).Div(rlwe.NewScale(params.Q()[exponentialLevel-1]))
	affineMultiplier, err := newSelectorPeriodicPlaintext(
		params, producer.integerEncoder, affineSource.multiplier, exponentialLevel-2, rlwe.NewScale(params.Q()[exponentialLevel-2]),
	)
	if err != nil {
		return nil, err
	}
	affineOffset, err := newSelectorPeriodicPlaintext(
		params, producer.integerEncoder, affineSource.offset, exponentialLevel-3, rootScale,
	)
	if err != nil {
		return nil, err
	}
	periodicProfile, err := newSelectorPeriodicProfile(params, kernel, affineSource, affineMultiplier, affineOffset)
	if err != nil {
		return nil, err
	}
	periodicCounts, err := deriveSelectorPeriodicCounts(normalV, stc, cts)
	if err != nil {
		return nil, err
	}
	wantPeriodicCounts := SelectorReraiseDecodeOperationCounts{
		LinearTransformations: 7, DiagonalPlaintextProducts: 35, NonConjugationRotations: 19,
		Conjugations: 3, KeySwitches: 22, CiphertextAdditionsSubtractions: 34,
		ScalarMultiplicationsPlusMinusI: 2, ExplicitRescales: 10, ScaleDown: 1, ModUp: 1,
		ExponentialPolynomialEvaluations: 1, CiphertextCiphertextProducts: 2, Relinearizations: 2,
		CiphertextPlaintextProducts: 1, PlaintextVectorAdditions: 1,
	}
	if periodicCounts != wantPeriodicCounts {
		return nil, fmt.Errorf("homchain: runtime-derived selector periodic counts differ from the audited map: %+v", periodicCounts)
	}
	periodicStates, err := newSelectorPeriodicStateProfiles(params, periodicProfile)
	if err != nil {
		return nil, err
	}
	serializedBytes, err := newSelectorReraiseDecodeSerializedByteProfile(params, periodicStates)
	if err != nil {
		return nil, err
	}

	keyProfile := newSelectorPeriodicKeyProfile(params, normalV, stcRaw, ctsRaw)
	if !reflect.DeepEqual(keyProfile.all, []uint64{5, 17, 25, 33, 41, 49, 63}) || !keyProfile.relinearization {
		return nil, fmt.Errorf("homchain: selector exact key union differs from the audited map: %v", keyProfile.all)
	}
	profile := SelectorReraiseDecodeProfile{
		fidelity: SelectorReraiseDecodeFunctionalNotSecure, wordBits: z2n.Word8,
		words: selectorReraiseDecodeWords, slots: selectorReraiseDecodeWords * selectorReraiseDecodeHalfWidth,
		encoderPrecision: producer.refreshEncoder.Prec(), integerPrecision: producer.integerEncoder.Prec(),
		parameterDigest: producer.parameterDigest, rangeDigest: producer.ranges.digest,
		producerPublicDigest: producer.publicProfile.digest, producerOpaqueDigest: producer.opaqueProfile.digest,
		producerAdmissionDigest: producer.bindingDigest, producerParameterDigest: producer.parameterDigest,
		producerOnePayloadDigest: producer.arithmeticOneDigest,
		producerAuditAnchor: SelectorReraiseDecodeComparatorAuditAnchor{
			PublicProfileDigest:        selectorAcceptedPublicComparatorProfileDigest,
			OpaqueProfileDigest:        selectorAcceptedOpaqueComparatorProfileDigest,
			AdmissionDigest:            selectorAcceptedComparatorAdmissionDigest,
			ParameterDigest:            selectorAcceptedComparatorParameterDigest,
			ArithmeticOnePayloadDigest: selectorAcceptedComparatorOnePayloadDigest,
		},
		representation: SelectorArithmeticRootCoefficientsToPeriodicBooleanScalarRepeated,
		resultSchema:   selectorReraiseDecodeResultSchema,
		normalV:        normalVProfile,
		dft:            dftProfile, periodic: periodicProfile, operationCounts: periodicCounts,
		serializedBytes: serializedBytes, logicalPeak: 8, states: periodicStates,
	}
	profile.digest = digestSelectorReraiseDecodeProfile(profile, keyProfile)

	circuit := &SelectorReraiseDecodeCircuit{
		producer: producer, params: params, refreshEncoder: producer.refreshEncoder, integerEncoder: producer.integerEncoder,
		normalVSource: normalVSource, normalV: normalV, stc: stc, cts: cts, kernel: kernel, affineSource: affineSource,
		affineMultiplier: affineMultiplier, affineOffset: affineOffset, profile: profile, keyProfile: keyProfile,
	}
	circuit.graph, err = captureSelectorReraiseDecodeCircuitGraph(circuit)
	if err != nil {
		return nil, err
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func selectorCompiledTransformationPayloadDigest(transformation ckkslintrans.LinearTransformation) (string, error) {
	if transformation.MetaData == nil || transformation.Vec == nil {
		return "", fmt.Errorf("homchain: incomplete selector compiled transformation")
	}
	indexes := selectorTransformDiagonalIndexes(transformation)
	scale, err := NewExactScaleSnapshot(transformation.Scale)
	if err != nil {
		return "", err
	}
	canonical := fmt.Sprintf(
		"selector-compiled-transformation-v1|Q%d/P%d|scale=%s|dimensions=%d,%d|bsgs=%d|n1=%d|diagonals=%v",
		transformation.LevelQ, transformation.LevelP, scale.canonicalString(), transformation.LogDimensions.Rows,
		transformation.LogDimensions.Cols, transformation.LogBabyStepGiantStepRatio, transformation.N1, indexes,
	)
	for _, index := range indexes {
		payload, marshalErr := transformation.Vec[index].MarshalBinary()
		if marshalErr != nil {
			return "", fmt.Errorf("homchain: marshal selector diagonal %d: %w", index, marshalErr)
		}
		canonical += fmt.Sprintf("|%d=%s", index, sha256Hex(payload))
	}
	return digestString(canonical), nil
}

func selectorTransformationPointer(transformation ckkslintrans.LinearTransformation) uintptr {
	return a2bRefreshLinearIdentity(transformation)
}

func captureSelectorReraiseDecodeCircuitGraph(c *SelectorReraiseDecodeCircuit) (selectorReraiseDecodeCircuitGraphIdentity, error) {
	if c == nil || c.producer == nil || c.refreshEncoder == nil || c.integerEncoder == nil || c.kernel == nil ||
		c.affineMultiplier == nil || c.affineOffset == nil {
		return selectorReraiseDecodeCircuitGraphIdentity{}, fmt.Errorf("homchain: incomplete selector circuit graph")
	}
	g := selectorReraiseDecodeCircuitGraphIdentity{
		circuit: c, producer: c.producer, refreshEncoder: c.refreshEncoder, integerEncoder: c.integerEncoder,
		kernel: c.kernel, affineMultiplier: c.affineMultiplier, affineOffset: c.affineOffset,
		normalVLow: selectorTransformationPointer(c.normalV.Low), normalVHigh: selectorTransformationPointer(c.normalV.High),
		kernelProfileDigest: c.kernel.profile.digest, kernelOperandGraphDigest: c.kernel.profile.operandGraphDigest,
		affineSourceDigest: c.affineSource.digest, profileDigest: c.profile.digest, keyDigest: c.keyProfile.digest,
		producerPublicDigest: c.producer.publicProfile.digest, producerOpaqueDigest: c.producer.opaqueProfile.digest,
		producerAdmissionDigest: c.producer.bindingDigest, producerRangeDigest: c.producer.ranges.digest,
		producerParameterDigest: c.producer.parameterDigest, producerOnePayloadDigest: c.producer.arithmeticOneDigest,
	}
	var err error
	if g.affineMultiplierDigest, err = selectorPeriodicPlaintextDigest(c.affineMultiplier); err != nil {
		return g, err
	}
	if g.affineOffsetDigest, err = selectorPeriodicPlaintextDigest(c.affineOffset); err != nil {
		return g, err
	}
	for index, transformation := range []ckkslintrans.LinearTransformation{c.normalV.Low, c.normalV.High} {
		digest, digestErr := selectorCompiledTransformationPayloadDigest(transformation)
		if digestErr != nil {
			return g, digestErr
		}
		g.normalVDigests[index] = digest
	}
	for _, factor := range c.stc.Matrices {
		g.stcFactors = append(g.stcFactors, selectorTransformationPointer(factor))
		digest, digestErr := selectorCompiledTransformationPayloadDigest(factor)
		if digestErr != nil {
			return g, digestErr
		}
		g.stcDigests = append(g.stcDigests, digest)
	}
	for _, factor := range c.cts.Matrices {
		g.ctsFactors = append(g.ctsFactors, selectorTransformationPointer(factor))
		digest, digestErr := selectorCompiledTransformationPayloadDigest(factor)
		if digestErr != nil {
			return g, digestErr
		}
		g.ctsDigests = append(g.ctsDigests, digest)
	}
	allPointers := []uintptr{g.normalVLow, g.normalVHigh}
	allPointers = append(allPointers, g.stcFactors...)
	allPointers = append(allPointers, g.ctsFactors...)
	seen := map[uintptr]bool{}
	for _, pointer := range allPointers {
		if pointer == 0 || seen[pointer] {
			return g, fmt.Errorf("homchain: selector compiled graph contains an empty or shared Vec")
		}
		seen[pointer] = true
	}
	if len(g.stcFactors) != 2 || len(g.ctsFactors) != 3 {
		return g, fmt.Errorf("homchain: selector DFT factor graph=%d/%d, want 2/3", len(g.stcFactors), len(g.ctsFactors))
	}
	if g.affineMultiplier == g.affineOffset || g.affineMultiplierDigest != c.profile.periodic.multiplierPayloadDigest ||
		g.affineOffsetDigest != c.profile.periodic.offsetPayloadDigest {
		return g, fmt.Errorf("homchain: selector periodic affine plaintext graph is shared or differs from the profile")
	}
	return g, nil
}

func (g selectorReraiseDecodeCircuitGraphIdentity) validate(c *SelectorReraiseDecodeCircuit) error {
	if c == nil || g.circuit != c || g.producer != c.producer || g.refreshEncoder != c.refreshEncoder ||
		g.integerEncoder != c.integerEncoder || g.kernel != c.kernel || g.affineMultiplier != c.affineMultiplier ||
		g.affineOffset != c.affineOffset || g.profileDigest != c.profile.digest || g.keyDigest != c.keyProfile.digest ||
		g.producerPublicDigest != c.producer.publicProfile.digest || g.producerOpaqueDigest != c.producer.opaqueProfile.digest ||
		g.producerAdmissionDigest != c.producer.bindingDigest || g.producerRangeDigest != c.producer.ranges.digest ||
		g.producerParameterDigest != c.producer.parameterDigest || g.producerOnePayloadDigest != c.producer.arithmeticOneDigest {
		return fmt.Errorf("homchain: selector circuit object graph or producer instance changed")
	}
	pointers := []uintptr{
		selectorTransformationPointer(c.normalV.Low), selectorTransformationPointer(c.normalV.High),
	}
	wantPointers := []uintptr{g.normalVLow, g.normalVHigh}
	if !reflect.DeepEqual(pointers, wantPointers) || len(c.stc.Matrices) != len(g.stcFactors) || len(c.cts.Matrices) != len(g.ctsFactors) {
		return fmt.Errorf("homchain: selector compiled transform pointer graph changed")
	}
	for index, factor := range c.stc.Matrices {
		if selectorTransformationPointer(factor) != g.stcFactors[index] {
			return fmt.Errorf("homchain: selector STC factor %d pointer changed", index)
		}
	}
	for index, factor := range c.cts.Matrices {
		if selectorTransformationPointer(factor) != g.ctsFactors[index] {
			return fmt.Errorf("homchain: selector CTS factor %d pointer changed", index)
		}
	}
	groups := []struct {
		name  string
		items []ckkslintrans.LinearTransformation
		want  []string
	}{
		{"normal-V", []ckkslintrans.LinearTransformation{c.normalV.Low, c.normalV.High}, g.normalVDigests[:]},
		{"STC", c.stc.Matrices, g.stcDigests}, {"CTS", c.cts.Matrices, g.ctsDigests},
	}
	for _, group := range groups {
		for index, item := range group.items {
			digest, err := selectorCompiledTransformationPayloadDigest(item)
			if err != nil || digest != group.want[index] {
				return fmt.Errorf("homchain: selector %s compiled payload %d changed", group.name, index)
			}
		}
	}
	if err := c.kernel.validate(); err != nil || g.kernelProfileDigest != c.kernel.profile.digest ||
		g.kernelOperandGraphDigest != c.kernel.profile.operandGraphDigest || g.affineSourceDigest != c.affineSource.digest {
		return fmt.Errorf("homchain: selector periodic kernel or affine source graph changed")
	}
	multiplierDigest, err := selectorPeriodicPlaintextDigest(c.affineMultiplier)
	if err != nil || multiplierDigest != g.affineMultiplierDigest || multiplierDigest != c.profile.periodic.multiplierPayloadDigest {
		return fmt.Errorf("homchain: selector periodic multiplier graph changed")
	}
	offsetDigest, err := selectorPeriodicPlaintextDigest(c.affineOffset)
	if err != nil || offsetDigest != g.affineOffsetDigest || offsetDigest != c.profile.periodic.offsetPayloadDigest {
		return fmt.Errorf("homchain: selector periodic offset graph changed")
	}
	return nil
}

func (c *SelectorReraiseDecodeCircuit) validate() error {
	if c == nil || c.producer == nil || c.refreshEncoder == nil || c.integerEncoder == nil ||
		c.normalV.Low.Vec == nil || c.normalV.High.Vec == nil ||
		c.kernel == nil || c.affineMultiplier == nil || c.affineOffset == nil ||
		len(c.stc.Matrices) != 2 || len(c.cts.Matrices) != 3 {
		return fmt.Errorf("homchain: nil or incomplete selector reraiser circuit")
	}
	if err := c.producer.validate(); err != nil {
		return fmt.Errorf("homchain: validate selector comparator producer: %w", err)
	}
	if err := validateSelectorReraiseDecodeAcceptedProducerProfiles(c.producer.PublicProfile(), c.producer.OpaqueProfile()); err != nil {
		return err
	}
	if !c.params.Equal(&c.producer.params) || c.refreshEncoder != c.producer.refreshEncoder ||
		c.integerEncoder != c.producer.integerEncoder || c.refreshEncoder.Prec() != signed8RefreshEncoderPrecision ||
		c.integerEncoder.Prec() != signed8IntegerEncoderPrecision {
		return fmt.Errorf("homchain: selector parameter or encoder identity changed")
	}
	if err := validateA2BRefreshParameters(c.params); err != nil {
		return err
	}
	if err := c.kernel.validate(); err != nil {
		return fmt.Errorf("homchain: validate selector accepted periodic kernel: %w", err)
	}
	canonicalAffine, err := newSelectorPeriodicAffineSource(c.integerEncoder.Prec())
	if err != nil || canonicalAffine.digest != c.affineSource.digest {
		return fmt.Errorf("homchain: selector periodic affine source changed")
	}
	if err := c.graph.validate(c); err != nil {
		return err
	}

	parameterDigest, err := signed8ParameterDigest(c.params)
	if err != nil {
		return err
	}
	if parameterDigest != c.producer.parameterDigest {
		return fmt.Errorf("homchain: selector parameter digest changed")
	}
	canonicalRefreshRing, err := z2n.NewWithPrecision(z2n.Word8, signed8RefreshEncoderPrecision)
	if err != nil {
		return err
	}
	canonicalSpecifications, err := NewSpecificationsFromRing(canonicalRefreshRing, selectorReraiseDecodeWords)
	if err != nil {
		return err
	}
	canonicalV := canonicalSpecifications.VPair()
	if digestB2ATransformSource(c.normalVSource) != digestB2ATransformSource(canonicalV) {
		return fmt.Errorf("homchain: selector normal-V source changed")
	}
	vOptions := CompileOptions{LevelQ: 4, LevelP: 0, Scale: rlwe.NewScale(c.params.Q()[4]), LogBabyStepGiantStepRatio: 0}
	normalVProfile, err := newSelectorPairProfile(c.params, c.normalVSource, c.normalV, vOptions)
	if err != nil {
		return err
	}

	stcRaw, ctsRaw := a2bRefreshDFTLiterals(c.params, c.refreshEncoder.Prec(), 3, 20)
	stcFactor, ctsFactor, err := a2bRefreshDFTInitializationFactors(c.params)
	if err != nil {
		return err
	}
	stcExecution := scaleA2BRefreshDFTLiteral(stcRaw, stcFactor, c.refreshEncoder.Prec())
	ctsExecution := scaleA2BRefreshDFTLiteral(ctsRaw, ctsFactor, c.refreshEncoder.Prec())
	if !a2bRefreshLiteralEqual(c.stc.MatrixLiteral, stcExecution) || !a2bRefreshLiteralEqual(c.cts.MatrixLiteral, ctsExecution) {
		return fmt.Errorf("homchain: selector execution DFT literal graph changed")
	}
	stcRawDigest := digestDFTMatrixNumericPayload(stcRaw, stcRaw.GenMatrices(c.params.LogN(), c.refreshEncoder.Prec()))
	ctsRawDigest := digestDFTMatrixNumericPayload(ctsRaw, ctsRaw.GenMatrices(c.params.LogN(), c.refreshEncoder.Prec()))
	stcExecutionDigest := digestDFTMatrixNumericPayload(stcExecution, stcExecution.GenMatrices(c.params.LogN(), c.refreshEncoder.Prec()))
	ctsExecutionDigest := digestDFTMatrixNumericPayload(ctsExecution, ctsExecution.GenMatrices(c.params.LogN(), c.refreshEncoder.Prec()))
	dftProfile := SelectorReraiseDecodeDFTProfile{
		stcRaw: cloneDFTLiteral(stcRaw), ctsRaw: cloneDFTLiteral(ctsRaw),
		stcExecution: cloneDFTLiteral(stcExecution), ctsExecution: cloneDFTLiteral(ctsExecution),
		encoderPrecision: c.refreshEncoder.Prec(), generatorPrecision: c.refreshEncoder.Prec(),
		stcRawDigest: stcRawDigest, ctsRawDigest: ctsRawDigest,
		stcExecutionDigest: stcExecutionDigest, ctsExecutionDigest: ctsExecutionDigest,
	}
	dftProfile.digest = digestString(fmt.Sprintf(
		"selector-reraise-decode-dft-v1|raw-stc=%v|execution-stc=%v|raw-cts=%v|execution-cts=%v|precision=%d|raw-stc-digest=%s|execution-stc-digest=%s|raw-cts-digest=%s|execution-cts-digest=%s|shared-a2b-cts=%s",
		dftLiteralTrace(stcRaw), dftLiteralTrace(stcExecution), dftLiteralTrace(ctsRaw), dftLiteralTrace(ctsExecution),
		c.refreshEncoder.Prec(), stcRawDigest, stcExecutionDigest, ctsRawDigest, ctsExecutionDigest,
		c.producer.a2b.profile.sharedCTSDigest,
	))
	if ctsRawDigest != c.producer.a2b.refresh.profile.dft.ctsRawMatrixDigest ||
		ctsExecutionDigest != c.producer.a2b.profile.sharedCTSDigest {
		return fmt.Errorf("homchain: selector shared accepted CTS digest changed")
	}
	periodicProfile, err := newSelectorPeriodicProfile(c.params, c.kernel, c.affineSource, c.affineMultiplier, c.affineOffset)
	if err != nil {
		return err
	}
	periodicCounts, err := deriveSelectorPeriodicCounts(c.normalV, c.stc, c.cts)
	if err != nil {
		return err
	}
	periodicStates, err := newSelectorPeriodicStateProfiles(c.params, periodicProfile)
	if err != nil {
		return err
	}
	serializedBytes, err := newSelectorReraiseDecodeSerializedByteProfile(c.params, periodicStates)
	if err != nil {
		return err
	}

	keyProfile := newSelectorPeriodicKeyProfile(c.params, c.normalV, stcRaw, ctsRaw)
	want := SelectorReraiseDecodeProfile{
		fidelity: SelectorReraiseDecodeFunctionalNotSecure, wordBits: z2n.Word8,
		words: selectorReraiseDecodeWords, slots: selectorReraiseDecodeWords * selectorReraiseDecodeHalfWidth,
		encoderPrecision: c.refreshEncoder.Prec(), integerPrecision: c.integerEncoder.Prec(),
		parameterDigest: parameterDigest, rangeDigest: c.producer.ranges.digest,
		producerPublicDigest: c.producer.publicProfile.digest, producerOpaqueDigest: c.producer.opaqueProfile.digest,
		producerAdmissionDigest: c.producer.bindingDigest, producerParameterDigest: c.producer.parameterDigest,
		producerOnePayloadDigest: c.producer.arithmeticOneDigest,
		producerAuditAnchor: SelectorReraiseDecodeComparatorAuditAnchor{
			PublicProfileDigest:        selectorAcceptedPublicComparatorProfileDigest,
			OpaqueProfileDigest:        selectorAcceptedOpaqueComparatorProfileDigest,
			AdmissionDigest:            selectorAcceptedComparatorAdmissionDigest,
			ParameterDigest:            selectorAcceptedComparatorParameterDigest,
			ArithmeticOnePayloadDigest: selectorAcceptedComparatorOnePayloadDigest,
		},
		representation: SelectorArithmeticRootCoefficientsToPeriodicBooleanScalarRepeated,
		resultSchema:   selectorReraiseDecodeResultSchema,
		normalV:        normalVProfile,
		dft:            dftProfile, periodic: periodicProfile, operationCounts: periodicCounts,
		serializedBytes: serializedBytes, logicalPeak: 8, states: periodicStates,
	}
	want.digest = digestSelectorReraiseDecodeProfile(want, keyProfile)
	if !reflect.DeepEqual(c.keyProfile, keyProfile) || !reflect.DeepEqual(c.profile, want) {
		return fmt.Errorf("homchain: selector sealed profile, key ledger, or actual producer binding changed")
	}
	return nil
}

// validateSelectorReraiseDecodeAcceptedProducerProfiles keeps the accepted
// narrow-domain comparator pair as an audit anchor while authenticating the
// actual range-bound producer instance used by this circuit.
func validateSelectorReraiseDecodeAcceptedProducerProfiles(public, opaque Signed8ComparatorProfile) error {
	if public.OperandMode() != Signed8PublicThresholdCTPT || opaque.OperandMode() != Signed8OpaqueThresholdCTCT ||
		public.RangeDigest() == "" || public.RangeDigest() != opaque.RangeDigest() ||
		public.InputBindingDigest() == "" || public.InputBindingDigest() != opaque.InputBindingDigest() {
		return fmt.Errorf("homchain: selector actual range-bound comparator pair is inconsistent")
	}
	actualBinding := digestString(fmt.Sprintf(
		"%s|params=%s|range=%s|a2b=%s|a2b-keys=%s|sign=%s|input=L20/S35/degree1/full-dense/ntt/4x4",
		signed8InputBindingSchema, public.ParameterDigest(), public.RangeDigest(), public.A2BProfileDigest(),
		public.A2BKeyProfileDigest(), public.SignProfileDigest(),
	))
	if public.InputBindingDigest() != actualBinding || public.Digest() != digestSigned8ComparatorProfile(public) ||
		opaque.Digest() != digestSigned8ComparatorProfile(opaque) {
		return fmt.Errorf("homchain: selector actual range-instance admission or profile digest changed")
	}
	if public.ParameterDigest() != selectorAcceptedComparatorParameterDigest ||
		opaque.ParameterDigest() != selectorAcceptedComparatorParameterDigest ||
		public.ArithmeticOnePayloadDigest() != selectorAcceptedComparatorOnePayloadDigest ||
		opaque.ArithmeticOnePayloadDigest() != selectorAcceptedComparatorOnePayloadDigest {
		return fmt.Errorf("homchain: selector comparator parameter or arithmetic-one audit anchor changed")
	}

	narrowRange, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		return err
	}
	narrowBinding := digestString(fmt.Sprintf(
		"%s|params=%s|range=%s|a2b=%s|a2b-keys=%s|sign=%s|input=L20/S35/degree1/full-dense/ntt/4x4",
		signed8InputBindingSchema, public.ParameterDigest(), narrowRange.Digest(), public.A2BProfileDigest(),
		public.A2BKeyProfileDigest(), public.SignProfileDigest(),
	))
	if narrowBinding != selectorAcceptedComparatorAdmissionDigest {
		return fmt.Errorf("homchain: reconstructed selector comparator admission audit anchor changed")
	}
	project := func(profile Signed8ComparatorProfile) string {
		profile.rangeDigest = narrowRange.Digest()
		profile.inputBindingDigest = narrowBinding
		return digestSigned8ComparatorProfile(profile)
	}
	if project(public) != selectorAcceptedPublicComparatorProfileDigest ||
		project(opaque) != selectorAcceptedOpaqueComparatorProfileDigest {
		return fmt.Errorf("homchain: selector comparator invariant projection differs from the accepted narrow audit anchor")
	}
	return nil
}

func newSelectorPairProfile(params ckks.Parameters, source PairSpec, compiled CompiledPair, options CompileOptions) (SelectorReraiseDecodeTransformProfile, error) {
	rotations := compiled.RotationIndexes()
	galois := compiled.GaloisElements(params)
	compiledDigest, err := digestB2ACompiledPlan(params, source, compiled, options, rotations, galois)
	if err != nil {
		return SelectorReraiseDecodeTransformProfile{}, fmt.Errorf("homchain: digest selector compiled pair: %w", err)
	}
	return SelectorReraiseDecodeTransformProfile{
		lowName: source.Low.Name(), highName: source.High.Name(), levelQ: options.LevelQ, levelP: options.LevelP,
		lowN1: compiled.Low.N1, highN1: compiled.High.N1,
		lowDiagonals: selectorTransformDiagonalIndexes(compiled.Low), highDiagonals: selectorTransformDiagonalIndexes(compiled.High),
		rotations: rotations, galois: galois, sourceDigest: digestB2ATransformSource(source), compiledDigest: compiledDigest,
	}, nil
}

func selectorTransformDiagonalIndexes(transformation ckkslintrans.LinearTransformation) []int {
	result := make([]int, 0, len(transformation.Vec))
	for index := range transformation.Vec {
		result = append(result, index)
	}
	sort.Ints(result)
	return result
}

func selectorNonzeroUnion(values ...[]int) []int {
	seen := map[int]struct{}{}
	for _, list := range values {
		for _, value := range list {
			if value != 0 {
				seen[value] = struct{}{}
			}
		}
	}
	result := make([]int, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

func selectorVPairCounts(pair CompiledPair) (diagonals, rotations, additions int, err error) {
	if pair.Low.N1 == 0 || pair.High.N1 == 0 {
		return 0, 0, 0, fmt.Errorf("homchain: selector normal V unexpectedly disabled BSGS")
	}
	_, lowGiant, lowBaby := commonlintrans.LinearTransformation(pair.Low).BSGSIndex()
	_, highGiant, highBaby := commonlintrans.LinearTransformation(pair.High).BSGSIndex()
	diagonals = len(pair.Low.Vec) + len(pair.High.Vec)
	rotations = len(selectorNonzeroUnion(lowBaby, highBaby)) + len(selectorNonzeroUnion(lowGiant)) + len(selectorNonzeroUnion(highGiant))
	additions = diagonals - 2 + 2 // diagonal sums plus two real projections
	return
}

func selectorDFTCounts(matrix ckksdft.Matrix) (diagonals, rotations, additions int) {
	for _, factor := range matrix.Matrices {
		diagonals += len(factor.Vec)
		rotations += len(signFusionRotationIndexes(factor))
		additions += len(factor.Vec) - 1
	}
	return
}

func deriveSelectorPeriodicCounts(normalV CompiledPair, stc, cts ckksdft.Matrix) (SelectorReraiseDecodeOperationCounts, error) {
	vDiag, vRot, vAdd, err := selectorVPairCounts(normalV)
	if err != nil {
		return SelectorReraiseDecodeOperationCounts{}, err
	}
	stcDiag, stcRot, stcAdd := selectorDFTCounts(stc)
	ctsDiag, ctsRot, ctsAdd := selectorDFTCounts(cts)
	counts := SelectorReraiseDecodeOperationCounts{
		LinearTransformations:            2 + len(stc.Matrices) + len(cts.Matrices),
		DiagonalPlaintextProducts:        vDiag + stcDiag + ctsDiag,
		NonConjugationRotations:          vRot + stcRot + ctsRot,
		Conjugations:                     3,
		CiphertextAdditionsSubtractions:  vAdd + (stcAdd + 1) + (ctsAdd + 2) + 1,
		ScalarMultiplicationsPlusMinusI:  2,
		ExplicitRescales:                 2 + len(stc.Matrices) + len(cts.Matrices) + 3,
		ScaleDown:                        1,
		ModUp:                            1,
		ExponentialPolynomialEvaluations: 1,
		CiphertextCiphertextProducts:     2,
		Relinearizations:                 2,
		CiphertextPlaintextProducts:      1,
		PlaintextVectorAdditions:         1,
	}
	counts.KeySwitches = counts.NonConjugationRotations + counts.Conjugations
	return counts, nil
}

func newSelectorPeriodicKeyProfile(params ckks.Parameters, normalV CompiledPair, stc, cts ckksdft.MatrixLiteral) SelectorReraiseDecodeKeyProfile {
	all := append([]uint64(nil), GaloisElementsForZToC(params, normalV)...)
	all = append(all, stc.GaloisElements(params)...)
	all = append(all, params.GaloisElementsForTrace(params.LogMaxSlots())...)
	all = append(all, cts.GaloisElements(params)...)
	all = withoutIdentity(params, all)
	profile := SelectorReraiseDecodeKeyProfile{all: all, relinearization: true}
	profile.digest = digestString(fmt.Sprintf("selector-periodic-reraise-decode-keys-v1|all=%v|relinearization=true|switching=dense_no_switch", all))
	return profile
}

func cloneSelectorPeriodicComplexVector(values []*bignum.Complex) []*bignum.Complex {
	result := make([]*bignum.Complex, len(values))
	for index, value := range values {
		if value != nil {
			result[index] = &bignum.Complex{
				new(big.Float).SetPrec(value.Real().Prec()).SetMode(value.Real().Mode()).Set(value.Real()),
				new(big.Float).SetPrec(value.Imag().Prec()).SetMode(value.Imag().Mode()).Set(value.Imag()),
			}
		}
	}
	return result
}

func selectorPeriodicPlaintextDigest(plaintext *rlwe.Plaintext) (string, error) {
	if plaintext == nil || plaintext.MetaData == nil {
		return "", fmt.Errorf("homchain: nil selector periodic plaintext")
	}
	payload, err := plaintext.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("homchain: marshal selector periodic plaintext: %w", err)
	}
	return sha256Hex(payload), nil
}

func newSelectorPeriodicPlaintext(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	values []*bignum.Complex,
	level int,
	scale rlwe.Scale,
) (*rlwe.Plaintext, error) {
	if encoder == nil || len(values) != params.MaxSlots() || level < 0 || level > params.MaxLevel() {
		return nil, fmt.Errorf("homchain: invalid selector periodic plaintext source")
	}
	plaintext := ckks.NewPlaintext(params, level)
	plaintext.LogDimensions = params.LogMaxDimensions()
	plaintext.Scale = scale
	if err := encoder.Encode(cloneSelectorPeriodicComplexVector(values), plaintext); err != nil {
		return nil, fmt.Errorf("homchain: encode selector periodic plaintext: %w", err)
	}
	return plaintext, nil
}

func newSelectorPeriodicProfile(
	params ckks.Parameters,
	kernel *GaoA2BKernelCircuit,
	source selectorPeriodicAffineSource,
	multiplier, offset *rlwe.Plaintext,
) (SelectorReraiseDecodePeriodicProfile, error) {
	if kernel == nil {
		return SelectorReraiseDecodePeriodicProfile{}, fmt.Errorf("homchain: nil selector periodic kernel")
	}
	if err := kernel.validate(); err != nil {
		return SelectorReraiseDecodePeriodicProfile{}, err
	}
	depth := kernel.exponentialOperand.Depth()
	inputLevel := kernel.profile.inputLevel
	exponentialLevel := inputLevel - depth
	square0Level := exponentialLevel - 1
	rootLevel := square0Level - 1
	outputLevel := rootLevel - 1
	if depth != 6 || inputLevel != 17 || exponentialLevel != 11 || square0Level != 10 || rootLevel != 9 || outputLevel != 8 {
		return SelectorReraiseDecodePeriodicProfile{}, fmt.Errorf("homchain: accepted selector periodic schedule changed: depth=%d levels=%d/%d/%d/%d/%d", depth, inputLevel, exponentialLevel, square0Level, rootLevel, outputLevel)
	}
	inputScale := params.DefaultScale()
	exponentialScale := params.DefaultScale()
	square0Scale := exponentialScale.Mul(exponentialScale).Div(rlwe.NewScale(params.Q()[exponentialLevel]))
	rootScale := square0Scale.Mul(square0Scale).Div(rlwe.NewScale(params.Q()[square0Level]))
	if multiplier == nil || offset == nil || multiplier.Level() != rootLevel || offset.Level() != outputLevel ||
		!b2aExactScaleEqual(multiplier.Scale, rlwe.NewScale(params.Q()[rootLevel])) ||
		!b2aExactScaleEqual(offset.Scale, rootScale) {
		return SelectorReraiseDecodePeriodicProfile{}, fmt.Errorf("homchain: selector periodic affine plaintext states changed")
	}
	multiplierDigest, err := selectorPeriodicPlaintextDigest(multiplier)
	if err != nil {
		return SelectorReraiseDecodePeriodicProfile{}, err
	}
	offsetDigest, err := selectorPeriodicPlaintextDigest(offset)
	if err != nil {
		return SelectorReraiseDecodePeriodicProfile{}, err
	}
	snapshots := make([]ExactScaleSnapshot, 5)
	for index, scale := range []rlwe.Scale{inputScale, exponentialScale, square0Scale, rootScale, rootScale} {
		if snapshots[index], err = NewExactScaleSnapshot(scale); err != nil {
			return SelectorReraiseDecodePeriodicProfile{}, err
		}
	}
	return SelectorReraiseDecodePeriodicProfile{
		kernelProfileDigest: kernel.profile.digest, exponentialProfileDigest: kernel.profile.exponentialProfileDigest,
		exponentialArtifactDigest: kernel.profile.exponentialArtifactDigest, operandGraphDigest: kernel.profile.operandGraphDigest,
		affineSourceDigest: source.digest, multiplierPayloadDigest: multiplierDigest, offsetPayloadDigest: offsetDigest,
		exponentialDepth: depth, inputLevel: inputLevel, exponentialLevel: exponentialLevel,
		square0Level: square0Level, rootLevel: rootLevel, outputLevel: outputLevel,
		inputScale: snapshots[0], exponentialScale: snapshots[1], square0Scale: snapshots[2], rootScale: snapshots[3], outputScale: snapshots[4],
		runtimePath: "shared-CTS-low;accepted-exp46-packed-vector/evaluate;mulrelin-rescale^2;slotwise-affine-mul-rescale-add;no-ID/MSB-LUT",
	}, nil
}

func newSelectorPeriodicStateProfiles(params ckks.Parameters, periodic SelectorReraiseDecodePeriodicProfile) ([]SelectorReraiseDecodeStateProfile, error) {
	// The first fourteen states are the common source-scheduled prefix through
	// the two CTS halves. No legacy U/D state is admitted into this ledger.
	levels := []int{4, 4, 4, 3, 3, 2, 1, 0, 20, 19, 18, 17, 17, 17}
	states := make([]SelectorReraiseDecodeStateProfile, len(levels))
	for index, level := range levels {
		scale := params.DefaultScale()
		if index == 1 || index == 2 {
			scale = scale.Mul(rlwe.NewScale(params.Q()[4]))
		}
		snapshot, err := NewExactScaleSnapshot(scale)
		if err != nil {
			return nil, err
		}
		states[index] = SelectorReraiseDecodeStateProfile{level: level, scale: snapshot}
	}
	rootScale, err := periodic.rootScale.Scale()
	if err != nil {
		return nil, err
	}
	affineRawScale, err := NewExactScaleSnapshot(rootScale.Mul(rlwe.NewScale(params.Q()[periodic.rootLevel])))
	if err != nil {
		return nil, err
	}
	for _, state := range []struct {
		level int
		scale ExactScaleSnapshot
	}{
		{periodic.exponentialLevel, periodic.exponentialScale},
		{periodic.square0Level, periodic.square0Scale},
		{periodic.rootLevel, periodic.rootScale},
		{periodic.rootLevel, affineRawScale},
		{periodic.outputLevel, periodic.outputScale},
	} {
		states = append(states, SelectorReraiseDecodeStateProfile{level: state.level, scale: state.scale})
	}
	return states, nil
}

func digestSelectorReraiseDecodeProfile(profile SelectorReraiseDecodeProfile, keys SelectorReraiseDecodeKeyProfile) string {
	return digestString(fmt.Sprintf(
		"selector-reraise-decode-profile-v5|fidelity=%s|word=%d|words=%d|slots=%d|precision=%d/%d|params=%s|range=%s|producer-instance=%s/%s/admission:%s/params:%s/one:%s|producer-audit-anchor=%+v|representation=%s|result-schema=%s|normal-v=%+v|dft=%s|periodic=%+v|counts=%+v|serialized=%+v|peak=%d|states=%+v|keys=%s",
		profile.fidelity, profile.wordBits, profile.words, profile.slots, profile.encoderPrecision, profile.integerPrecision,
		profile.parameterDigest, profile.rangeDigest, profile.producerPublicDigest, profile.producerOpaqueDigest,
		profile.producerAdmissionDigest, profile.producerParameterDigest, profile.producerOnePayloadDigest, profile.producerAuditAnchor,
		profile.representation, profile.resultSchema, profile.normalV, profile.dft.digest, profile.periodic,
		profile.operationCounts, profile.serializedBytes, profile.logicalPeak, profile.states, keys.digest,
	))
}

const (
	selectorDecodeTransform TransformName = "selector-D"
	selectorFusedU0         TransformName = "selector-D-times-U0"
	selectorFusedU1         TransformName = "selector-D-times-U1"
)

type selectorReraiseDecodeAlgebra struct {
	decoder TransformSpec
	normalU PairSpec
	fused   PairSpec
}

// newSelectorReraiseDecodeAlgebra constructs only the deterministic
// design-falsification control used by the author test. The decoder is
// D=(1/4)*1*tau^T and fusion is left composition D*Ui, but this linear graph
// is integral-lift-sensitive and is never compiled into the production
// selector circuit or admitted to its profile.
func newSelectorReraiseDecodeAlgebra() (selectorReraiseDecodeAlgebra, error) {
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, selectorReraiseDecodeIntegerPrecision)
	if err != nil {
		return selectorReraiseDecodeAlgebra{}, fmt.Errorf("homchain: construct selector Z256 ring: %w", err)
	}
	specifications, err := NewSpecificationsFromRing(ringZ, selectorReraiseDecodeWords)
	if err != nil {
		return selectorReraiseDecodeAlgebra{}, fmt.Errorf("homchain: construct selector normal transforms: %w", err)
	}
	tauSlots, err := ringZ.ToRootSlots(ringZ.Tau())
	if err != nil {
		return selectorReraiseDecodeAlgebra{}, fmt.Errorf("homchain: map selector tau to root slots: %w", err)
	}
	if len(tauSlots) != selectorReraiseDecodeHalfWidth {
		return selectorReraiseDecodeAlgebra{}, fmt.Errorf("homchain: selector tau has %d root slots, want %d", len(tauSlots), selectorReraiseDecodeHalfWidth)
	}

	decoderMatrix := makeMatrix(selectorReraiseDecodeHalfWidth, selectorReraiseDecodeHalfWidth, selectorReraiseDecodeIntegerPrecision)
	four := new(big.Float).SetPrec(selectorReraiseDecodeIntegerPrecision).SetMode(big.ToNearestEven).SetInt64(4)
	for row := range decoderMatrix {
		for column := range decoderMatrix[row] {
			decoderMatrix[row][column].Real().Quo(tauSlots[column].Real(), four)
			decoderMatrix[row][column].Imag().Quo(tauSlots[column].Imag(), four)
		}
	}
	decoder, err := newTransformSpec(selectorDecodeTransform, decoderMatrix, selectorReraiseDecodeWords)
	if err != nil {
		return selectorReraiseDecodeAlgebra{}, fmt.Errorf("homchain: construct selector decoder D: %w", err)
	}

	normalU := specifications.UPair()
	fusedLowMatrix, err := selectorReraiseDecodeMatrixProduct(decoderMatrix, normalU.Low.Matrix())
	if err != nil {
		return selectorReraiseDecodeAlgebra{}, fmt.Errorf("homchain: compose selector D*U0: %w", err)
	}
	fusedHighMatrix, err := selectorReraiseDecodeMatrixProduct(decoderMatrix, normalU.High.Matrix())
	if err != nil {
		return selectorReraiseDecodeAlgebra{}, fmt.Errorf("homchain: compose selector D*U1: %w", err)
	}
	fusedLow, err := newTransformSpec(selectorFusedU0, fusedLowMatrix, selectorReraiseDecodeWords)
	if err != nil {
		return selectorReraiseDecodeAlgebra{}, fmt.Errorf("homchain: construct selector D*U0 transform: %w", err)
	}
	fusedHigh, err := newTransformSpec(selectorFusedU1, fusedHighMatrix, selectorReraiseDecodeWords)
	if err != nil {
		return selectorReraiseDecodeAlgebra{}, fmt.Errorf("homchain: construct selector D*U1 transform: %w", err)
	}

	return selectorReraiseDecodeAlgebra{
		decoder: decoder,
		normalU: normalU,
		fused:   PairSpec{Low: fusedLow, High: fusedHigh},
	}, nil
}

func selectorReraiseDecodeMatrixProduct(lhs, rhs Matrix) (Matrix, error) {
	if len(lhs) == 0 || len(rhs) == 0 {
		return nil, fmt.Errorf("empty matrix product")
	}
	inner := len(rhs)
	if len(lhs[0]) != inner {
		return nil, fmt.Errorf("matrix dimensions %dx%d and %dx%d do not compose", len(lhs), len(lhs[0]), len(rhs), len(rhs[0]))
	}
	columns := len(rhs[0])
	for row := range lhs {
		if len(lhs[row]) != inner {
			return nil, fmt.Errorf("left matrix row %d has width %d, want %d", row, len(lhs[row]), inner)
		}
	}
	for row := range rhs {
		if len(rhs[row]) != columns {
			return nil, fmt.Errorf("right matrix row %d has width %d, want %d", row, len(rhs[row]), columns)
		}
	}
	precision := matrixPrecision(lhs)
	if rhsPrecision := matrixPrecision(rhs); rhsPrecision > precision {
		precision = rhsPrecision
	}
	result := makeMatrix(len(lhs), columns, precision)
	for row := range lhs {
		for column := 0; column < columns; column++ {
			for k := 0; k < inner; k++ {
				result[row][column] = addComplex(result[row][column], multiplyComplex(lhs[row][k], rhs[k][column]))
			}
		}
	}
	return result, nil
}

// selectorPeriodicAffineSource is the source-level Boolean decoder used after
// the accepted Gao exp46 polynomial and its two squarings. The low CTS half
// contains the first four coefficients of tau^{-1}b, one four-slot block per
// packed word. For each coefficient a_j, the map
//
//	(z-1)/(exp(2*pi*i*a_j)-1)
//
// sends z=exp(2*pi*i*(I+a_j*b)) to b for every integral lift I and b in {0,1}.
type selectorPeriodicAffineSource struct {
	multiplier []*bignum.Complex
	offset     []*bignum.Complex
	digest     string
}

func newSelectorPeriodicAffineSource(precision uint) (selectorPeriodicAffineSource, error) {
	if precision < selectorReraiseDecodeIntegerPrecision {
		return selectorPeriodicAffineSource{}, fmt.Errorf("homchain: selector periodic affine precision=%d, want >=%d", precision, selectorReraiseDecodeIntegerPrecision)
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, precision)
	if err != nil {
		return selectorPeriodicAffineSource{}, fmt.Errorf("homchain: construct selector periodic Z256 ring: %w", err)
	}
	coefficients := ringZ.TauInverse().Coefficients()
	if len(coefficients) != 2*selectorReraiseDecodeHalfWidth {
		return selectorPeriodicAffineSource{}, fmt.Errorf("homchain: selector tau inverse has %d coefficients, want %d", len(coefficients), 2*selectorReraiseDecodeHalfWidth)
	}
	result := selectorPeriodicAffineSource{
		multiplier: make([]*bignum.Complex, selectorReraiseDecodeWords*selectorReraiseDecodeHalfWidth),
		offset:     make([]*bignum.Complex, selectorReraiseDecodeWords*selectorReraiseDecodeHalfWidth),
	}
	var canonical strings.Builder
	fmt.Fprintf(&canonical, "selector-periodic-affine-v1|precision=%d|source=tau-inverse-low-coefficients", precision)
	for word := 0; word < selectorReraiseDecodeWords; word++ {
		for slot := 0; slot < selectorReraiseDecodeHalfWidth; slot++ {
			root := selectorPeriodicRootOfUnity(coefficients[slot], precision)
			denominator := &bignum.Complex{
				new(big.Float).SetPrec(precision).Sub(root.Real(), new(big.Float).SetPrec(precision).SetInt64(1)),
				new(big.Float).SetPrec(precision).Set(root.Imag()),
			}
			multiplier, reciprocalErr := selectorPeriodicComplexReciprocal(denominator, precision)
			if reciprocalErr != nil {
				return selectorPeriodicAffineSource{}, fmt.Errorf("homchain: selector periodic affine slot %d: %w", slot, reciprocalErr)
			}
			offset := &bignum.Complex{
				new(big.Float).SetPrec(precision).Neg(multiplier.Real()),
				new(big.Float).SetPrec(precision).Neg(multiplier.Imag()),
			}
			index := word*selectorReraiseDecodeHalfWidth + slot
			result.multiplier[index] = multiplier
			result.offset[index] = offset
			fmt.Fprintf(&canonical, "|slot=%d/a=%s/m=%s,%s/c=%s,%s", index,
				coefficients[slot].Text('x', -1), multiplier.Real().Text('x', -1), multiplier.Imag().Text('x', -1),
				offset.Real().Text('x', -1), offset.Imag().Text('x', -1))
		}
	}
	result.digest = digestString(canonical.String())
	return result, nil
}

func selectorPeriodicRootOfUnity(value *big.Float, precision uint) *bignum.Complex {
	phase := new(big.Float).SetPrec(precision).Mul(bignum.Pi(precision), value)
	phase.Mul(phase, new(big.Float).SetPrec(precision).SetInt64(2))
	return &bignum.Complex{bignum.Cos(phase), bignum.Sin(phase)}
}

func selectorPeriodicComplexReciprocal(value *bignum.Complex, precision uint) (*bignum.Complex, error) {
	if value == nil || value.Real() == nil || value.Imag() == nil {
		return nil, fmt.Errorf("nil complex denominator")
	}
	realSquared := new(big.Float).SetPrec(precision).Mul(value.Real(), value.Real())
	imaginarySquared := new(big.Float).SetPrec(precision).Mul(value.Imag(), value.Imag())
	norm := new(big.Float).SetPrec(precision).Add(realSquared, imaginarySquared)
	if norm.Sign() == 0 {
		return nil, fmt.Errorf("zero complex denominator")
	}
	return &bignum.Complex{
		new(big.Float).SetPrec(precision).Quo(value.Real(), norm),
		new(big.Float).SetPrec(precision).Quo(new(big.Float).SetPrec(precision).Neg(value.Imag()), norm),
	}, nil
}

func selectorPeriodicComplexMul(lhs, rhs *bignum.Complex, precision uint) *bignum.Complex {
	ac := new(big.Float).SetPrec(precision).Mul(lhs.Real(), rhs.Real())
	bd := new(big.Float).SetPrec(precision).Mul(lhs.Imag(), rhs.Imag())
	ad := new(big.Float).SetPrec(precision).Mul(lhs.Real(), rhs.Imag())
	bc := new(big.Float).SetPrec(precision).Mul(lhs.Imag(), rhs.Real())
	return &bignum.Complex{
		new(big.Float).SetPrec(precision).Sub(ac, bd),
		new(big.Float).SetPrec(precision).Add(ad, bc),
	}
}

func evaluateSelectorPeriodicBooleanOracle(
	bits [selectorReraiseDecodeWords]uint64,
	lifts [selectorReraiseDecodeWords * selectorReraiseDecodeHalfWidth]int64,
	precision uint,
) ([]*bignum.Complex, error) {
	source, err := newSelectorPeriodicAffineSource(precision)
	if err != nil {
		return nil, err
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, precision)
	if err != nil {
		return nil, err
	}
	coefficients := ringZ.TauInverse().Coefficients()
	result := make([]*bignum.Complex, len(source.multiplier))
	for word, bit := range bits {
		if bit > 1 {
			return nil, fmt.Errorf("homchain: selector periodic oracle word %d is not Boolean", word)
		}
		for slot := 0; slot < selectorReraiseDecodeHalfWidth; slot++ {
			index := word*selectorReraiseDecodeHalfWidth + slot
			phaseInput := new(big.Float).SetPrec(precision).SetInt64(lifts[index])
			if bit == 1 {
				phaseInput.Add(phaseInput, coefficients[slot])
			}
			root := selectorPeriodicRootOfUnity(phaseInput, precision)
			decoded := selectorPeriodicComplexMul(root, source.multiplier[index], precision)
			decoded.Real().Add(decoded.Real(), source.offset[index].Real())
			decoded.Imag().Add(decoded.Imag(), source.offset[index].Imag())
			result[index] = decoded
		}
	}
	return result, nil
}
