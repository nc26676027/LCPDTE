package homchain

import (
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	signed8Depth2TerminalLeafProfileSchema = "signed8-depth2-terminal-leaf-profile-v1"
	signed8Depth2TerminalLeafInputSchema   = "signed8-depth2-terminal-leaf-input-v1"
	signed8Depth2TerminalLeafResultSchema  = "signed8-depth2-terminal-leaf-result-v1"
	signed8Depth2TerminalLeafTraceSchema   = "signed8-depth2-terminal-leaf-trace-v2"

	signed8Depth2LeafCertificateSchema                  = "signed8-depth2-leaf-magnitude-certificate-v1"
	signed8Depth2LeafCertificatePrecision               = uint(256)
	signed8Depth2LeafMaxAbs                       int64 = 1 << 16
	signed8Depth2IntermediateMaxAbs               int64 = 1 << 20
	signed8Depth2SelectorAbsErrorNumerator              = int64(1)
	signed8Depth2SelectorAbsErrorDenominator            = int64(1 << 8)
	signed8Depth2ArithmeticSlackNumerator               = int64(1)
	signed8Depth2ArithmeticSlackDenominator             = int64(1 << 12)
	signed8Depth2MinimumIdealCenteredHeadroomBits       = uint(192)
	signed8Depth2CacheRoundingPolicy                    = "big-float-256-nearest-even-rat-v1"
	signed8Depth2IdealHeadroomPolicy                    = "exact-rational-cross-multiply-v1"
	signed8Depth2TerminalLeafLevelLedger                = "decoded-b1-L8/R+conditioned-b0-L7/q7->two-CTPT-L8/q8S->two-rescale-L7/S->one-CTCT-relin-L7/q7S->rescale-L6/S+drop-A-L6/S"

	signed8Depth2TerminalDecodedChildBytes = 5054
	signed8Depth2TerminalRootSelectorBytes = 4526
	signed8Depth2TerminalLevel8Bytes       = 5054
	signed8Depth2TerminalLevel7Bytes       = 4526
	signed8Depth2TerminalLevel6Bytes       = 3998
)

// Signed8Depth2TerminalLeafFidelity states the deliberately bounded claim.
// This circuit is decryptor-tested functional evidence, not a security proof.
type Signed8Depth2TerminalLeafFidelity string

const Signed8Depth2TerminalLeafFunctionalNotSecure Signed8Depth2TerminalLeafFidelity = "functional_not_secure"

// Signed8Depth2TerminalLeafOperationCounts is the fixed mux-only ledger. The
// nested child decoder retains its own separately typed operation ledger.
type Signed8Depth2TerminalLeafOperationCounts struct {
	CiphertextPlaintextMultiplications  int
	CiphertextCiphertextMultiplications int
	Relinearizations                    int
	Rescales                            int
	PlaintextVectorAdditions            int
	CiphertextAdditions                 int
	LevelDrops                          int
	Rotations                           int
}

// Signed8Depth2TerminalLeafComposedOperationCounts keeps the child decoder
// and terminal mux ledgers separate. In particular, it does not flatten or
// reinterpret opaque work performed inside the decoder.
type Signed8Depth2TerminalLeafComposedOperationCounts struct {
	ChildDecoder Signed8Depth2ChildSelectorDecodeOperationCounts
	TerminalMux  Signed8Depth2TerminalLeafOperationCounts
}

type Signed8Depth2TerminalLeafStage string

const (
	Signed8Depth2TerminalStageDecodedChild   Signed8Depth2TerminalLeafStage = "decoded-b1"
	Signed8Depth2TerminalStageRootSelector   Signed8Depth2TerminalLeafStage = "root-b0"
	Signed8Depth2TerminalStageRawA           Signed8Depth2TerminalLeafStage = "rawA"
	Signed8Depth2TerminalStageRescaledA      Signed8Depth2TerminalLeafStage = "a"
	Signed8Depth2TerminalStageAffineA        Signed8Depth2TerminalLeafStage = "A"
	Signed8Depth2TerminalStageRawD           Signed8Depth2TerminalLeafStage = "rawD"
	Signed8Depth2TerminalStageRescaledD      Signed8Depth2TerminalLeafStage = "d"
	Signed8Depth2TerminalStageAffineD        Signed8Depth2TerminalLeafStage = "D"
	Signed8Depth2TerminalStageRawY           Signed8Depth2TerminalLeafStage = "rawY"
	Signed8Depth2TerminalStageRescaledY      Signed8Depth2TerminalLeafStage = "z"
	Signed8Depth2TerminalStageAlignedA       Signed8Depth2TerminalLeafStage = "A6"
	Signed8Depth2TerminalStageOutput         Signed8Depth2TerminalLeafStage = "y"
	Signed8Depth2TerminalStageAdmission      Signed8Depth2TerminalLeafStage = "admission"
	Signed8Depth2TerminalStagePreflight      Signed8Depth2TerminalLeafStage = "preflight"
	Signed8Depth2TerminalStageDecoderFailure Signed8Depth2TerminalLeafStage = "decoder-failure"
)

type Signed8Depth2TerminalLeafState struct {
	Stage           Signed8Depth2TerminalLeafStage
	Level           int
	Degree          int
	LogDimensions   ring.Dimensions
	Scale           ExactScaleSnapshot
	SerializedBytes int
}

// Signed8Depth2TerminalLeafSerializedBytes measures each of the twelve actual
// degree-one boundaries once. Only Output is online communication when it is
// really transported.
type Signed8Depth2TerminalLeafSerializedBytes struct {
	DecodedChild, RootSelector        int
	RawA, RescaledA, AffineA          int
	RawD, RescaledD, AffineD          int
	RawY, RescaledY, AlignedA, Output int
}

func (s Signed8Depth2TerminalLeafSerializedBytes) InternalInputBytes() int {
	return s.DecodedChild + s.RootSelector
}
func (s Signed8Depth2TerminalLeafSerializedBytes) RetainedLocalBytes() int {
	return s.RawA + s.RescaledA + s.AffineA + s.RawD + s.RescaledD + s.AffineD + s.RawY + s.RescaledY + s.AlignedA
}
func (s Signed8Depth2TerminalLeafSerializedBytes) OnlineOutputBytes() int { return s.Output }
func (s Signed8Depth2TerminalLeafSerializedBytes) TotalBytes() int {
	return s.InternalInputBytes() + s.RetainedLocalBytes() + s.OnlineOutputBytes()
}
func (s Signed8Depth2TerminalLeafSerializedBytes) Complete() bool {
	return s.DecodedChild > 0 && s.RootSelector > 0 && s.RawA > 0 && s.RescaledA > 0 && s.AffineA > 0 &&
		s.RawD > 0 && s.RescaledD > 0 && s.AffineD > 0 && s.RawY > 0 && s.RescaledY > 0 && s.AlignedA > 0 && s.Output > 0
}

// Signed8Depth2ExactRationalSnapshot is a canonical value-only reduced
// rational. Its accessors always reconstruct detached big numbers.
type Signed8Depth2ExactRationalSnapshot struct {
	numerator, denominator string
}

func newSigned8Depth2ExactRationalSnapshot(value *big.Rat) (Signed8Depth2ExactRationalSnapshot, error) {
	if value == nil || value.Denom().Sign() <= 0 {
		return Signed8Depth2ExactRationalSnapshot{}, fmt.Errorf("homchain: invalid terminal exact rational")
	}
	return Signed8Depth2ExactRationalSnapshot{
		numerator: value.Num().String(), denominator: value.Denom().String(),
	}, nil
}

func (s Signed8Depth2ExactRationalSnapshot) Rat() *big.Rat {
	numerator, okN := new(big.Int).SetString(s.numerator, 10)
	denominator, okD := new(big.Int).SetString(s.denominator, 10)
	if !okN || !okD || denominator.Sign() <= 0 {
		return nil
	}
	return new(big.Rat).SetFrac(numerator, denominator)
}
func (s Signed8Depth2ExactRationalSnapshot) Numerator() string   { return s.numerator }
func (s Signed8Depth2ExactRationalSnapshot) Denominator() string { return s.denominator }
func (s Signed8Depth2ExactRationalSnapshot) RatString() string {
	if value := s.Rat(); value != nil {
		return value.RatString()
	}
	return ""
}

type Signed8Depth2LeafMagnitudeLedger struct {
	leaves                          [4]Signed8Depth2ExactRationalSnapshot
	absLeafMax, absDL, absDR, absDX Signed8Depth2ExactRationalSnapshot
	absCross                        Signed8Depth2ExactRationalSnapshot
	boundRawA, boundA               Signed8Depth2ExactRationalSnapshot
	boundRawD, boundD               Signed8Depth2ExactRationalSnapshot
	boundRawY, boundZ               Signed8Depth2ExactRationalSnapshot
	boundA6, boundY                 Signed8Depth2ExactRationalSnapshot
	cacheErrorL00, cacheErrorDL     Signed8Depth2ExactRationalSnapshot
	cacheErrorDX, cacheErrorCross   Signed8Depth2ExactRationalSnapshot
	cacheErrorTolerance             Signed8Depth2ExactRationalSnapshot
}

func (l Signed8Depth2LeafMagnitudeLedger) Leaves() [4]Signed8Depth2ExactRationalSnapshot {
	return l.leaves
}
func (l Signed8Depth2LeafMagnitudeLedger) AbsoluteLeafMaximum() Signed8Depth2ExactRationalSnapshot {
	return l.absLeafMax
}
func (l Signed8Depth2LeafMagnitudeLedger) AbsoluteDL() Signed8Depth2ExactRationalSnapshot {
	return l.absDL
}
func (l Signed8Depth2LeafMagnitudeLedger) AbsoluteDR() Signed8Depth2ExactRationalSnapshot {
	return l.absDR
}
func (l Signed8Depth2LeafMagnitudeLedger) AbsoluteDX() Signed8Depth2ExactRationalSnapshot {
	return l.absDX
}
func (l Signed8Depth2LeafMagnitudeLedger) AbsoluteCross() Signed8Depth2ExactRationalSnapshot {
	return l.absCross
}
func (l Signed8Depth2LeafMagnitudeLedger) BoundY() Signed8Depth2ExactRationalSnapshot {
	return l.boundY
}
func (l Signed8Depth2LeafMagnitudeLedger) CacheErrorTolerance() Signed8Depth2ExactRationalSnapshot {
	return l.cacheErrorTolerance
}

type Signed8Depth2LeafHeadroomState struct {
	name                           string
	level                          int
	scale                          ExactScaleSnapshot
	bound                          Signed8Depth2ExactRationalSnapshot
	floorIdealCenteredHeadroomBits uint
}

func (s Signed8Depth2LeafHeadroomState) Name() string                              { return s.name }
func (s Signed8Depth2LeafHeadroomState) Level() int                                { return s.level }
func (s Signed8Depth2LeafHeadroomState) Scale() ExactScaleSnapshot                 { return s.scale }
func (s Signed8Depth2LeafHeadroomState) Bound() Signed8Depth2ExactRationalSnapshot { return s.bound }
func (s Signed8Depth2LeafHeadroomState) FloorIdealCenteredHeadroomBits() uint {
	return s.floorIdealCenteredHeadroomBits
}

type Signed8Depth2LeafMagnitudeCertificate struct {
	schema, parameterDigest, treeDigest, scheduleDigest string
	cacheRoundingPolicy, idealHeadroomPolicy            string
	leafBits                                            [4]uint64
	ledger                                              Signed8Depth2LeafMagnitudeLedger
	states                                              []Signed8Depth2LeafHeadroomState
	selectorAbsError, rootSelectorMagnitudeBound        Signed8Depth2ExactRationalSnapshot
	childSelectorMagnitudeBound, arithmeticSlack        Signed8Depth2ExactRationalSnapshot
	outputTolerance                                     Signed8Depth2ExactRationalSnapshot
	digest                                              string
}

func (c Signed8Depth2LeafMagnitudeCertificate) Schema() string          { return c.schema }
func (c Signed8Depth2LeafMagnitudeCertificate) ParameterDigest() string { return c.parameterDigest }
func (c Signed8Depth2LeafMagnitudeCertificate) TreeDigest() string      { return c.treeDigest }
func (c Signed8Depth2LeafMagnitudeCertificate) ScheduleDigest() string  { return c.scheduleDigest }
func (c Signed8Depth2LeafMagnitudeCertificate) CacheRoundingPolicy() string {
	return c.cacheRoundingPolicy
}
func (c Signed8Depth2LeafMagnitudeCertificate) IdealHeadroomPolicy() string {
	return c.idealHeadroomPolicy
}
func (c Signed8Depth2LeafMagnitudeCertificate) LeafBits() [4]uint64 { return c.leafBits }
func (c Signed8Depth2LeafMagnitudeCertificate) Ledger() Signed8Depth2LeafMagnitudeLedger {
	return c.ledger
}
func (c Signed8Depth2LeafMagnitudeCertificate) Leaves() [4]Signed8Depth2ExactRationalSnapshot {
	return c.ledger.leaves
}
func (c Signed8Depth2LeafMagnitudeCertificate) HeadroomStates() []Signed8Depth2LeafHeadroomState {
	return append([]Signed8Depth2LeafHeadroomState(nil), c.states...)
}
func (c Signed8Depth2LeafMagnitudeCertificate) SelectorAbsError() Signed8Depth2ExactRationalSnapshot {
	return c.selectorAbsError
}
func (c Signed8Depth2LeafMagnitudeCertificate) RootSelectorMagnitudeBound() Signed8Depth2ExactRationalSnapshot {
	return c.rootSelectorMagnitudeBound
}
func (c Signed8Depth2LeafMagnitudeCertificate) ChildSelectorMagnitudeBound() Signed8Depth2ExactRationalSnapshot {
	return c.childSelectorMagnitudeBound
}
func (c Signed8Depth2LeafMagnitudeCertificate) ArithmeticSlack() Signed8Depth2ExactRationalSnapshot {
	return c.arithmeticSlack
}
func (c Signed8Depth2LeafMagnitudeCertificate) OutputTolerance() Signed8Depth2ExactRationalSnapshot {
	return c.outputTolerance
}
func (c Signed8Depth2LeafMagnitudeCertificate) OutputToleranceFloat64Up() float64 {
	value := c.outputTolerance.Rat()
	if value == nil || value.Sign() < 0 {
		return math.NaN()
	}
	projected, accuracy := new(big.Float).SetPrec(signed8Depth2LeafCertificatePrecision).SetRat(value).Float64()
	if accuracy == big.Below {
		projected = math.Nextafter(projected, math.Inf(1))
	}
	return projected
}
func (c Signed8Depth2LeafMagnitudeCertificate) Digest() string { return c.digest }
func (c Signed8Depth2LeafMagnitudeCertificate) MinimumIdealCenteredHeadroomBits() uint {
	if len(c.states) == 0 {
		return 0
	}
	minimum := ^uint(0)
	for _, state := range c.states {
		if state.floorIdealCenteredHeadroomBits < minimum {
			minimum = state.floorIdealCenteredHeadroomBits
		}
	}
	return minimum
}

type signed8Depth2TerminalScales struct {
	b1, b0, delta, leaf, rawA, rawY ExactScaleSnapshot
}

type Signed8Depth2TerminalLeafProfile struct {
	fidelity                                        Signed8Depth2TerminalLeafFidelity
	parameterDigest, childProfileDigest             string
	decoderProfileDigest, prefixProfileDigest       string
	protocolRangeDigest, treeDigest, scheduleDigest string
	producerPublicDigest, producerOpaqueDigest      string
	leaves                                          [4]uint64
	certificate                                     Signed8Depth2LeafMagnitudeCertificate
	scales                                          signed8Depth2TerminalScales
	cacheSourceDigests, cachePayloadDigests         [4]string
	counts                                          Signed8Depth2TerminalLeafOperationCounts
	requiredGalois                                  []uint64
	relinearization                                 bool
	expectedStates                                  []Signed8Depth2TerminalLeafState
	expectedBytes                                   Signed8Depth2TerminalLeafSerializedBytes
	levelLedger, digest                             string
}

func (p Signed8Depth2TerminalLeafProfile) Fidelity() Signed8Depth2TerminalLeafFidelity {
	return p.fidelity
}
func (p Signed8Depth2TerminalLeafProfile) ParameterDigest() string    { return p.parameterDigest }
func (p Signed8Depth2TerminalLeafProfile) ChildProfileDigest() string { return p.childProfileDigest }
func (p Signed8Depth2TerminalLeafProfile) DecoderProfileDigest() string {
	return p.decoderProfileDigest
}
func (p Signed8Depth2TerminalLeafProfile) PrefixProfileDigest() string { return p.prefixProfileDigest }
func (p Signed8Depth2TerminalLeafProfile) ProtocolRangeDigest() string { return p.protocolRangeDigest }
func (p Signed8Depth2TerminalLeafProfile) TreeDigest() string          { return p.treeDigest }
func (p Signed8Depth2TerminalLeafProfile) ScheduleDigest() string      { return p.scheduleDigest }
func (p Signed8Depth2TerminalLeafProfile) ProducerPublicProfileDigest() string {
	return p.producerPublicDigest
}
func (p Signed8Depth2TerminalLeafProfile) ProducerOpaqueProfileDigest() string {
	return p.producerOpaqueDigest
}
func (p Signed8Depth2TerminalLeafProfile) LeafBits() [4]uint64 { return p.leaves }
func (p Signed8Depth2TerminalLeafProfile) MagnitudeCertificate() Signed8Depth2LeafMagnitudeCertificate {
	return cloneSigned8Depth2LeafCertificate(p.certificate)
}
func (p Signed8Depth2TerminalLeafProfile) OperationCounts() Signed8Depth2TerminalLeafOperationCounts {
	return p.counts
}
func (p Signed8Depth2TerminalLeafProfile) RequiredGaloisElements() []uint64 {
	return append([]uint64(nil), p.requiredGalois...)
}
func (p Signed8Depth2TerminalLeafProfile) RequiresRelinearization() bool { return p.relinearization }
func (p Signed8Depth2TerminalLeafProfile) ExpectedStates() []Signed8Depth2TerminalLeafState {
	return append([]Signed8Depth2TerminalLeafState(nil), p.expectedStates...)
}
func (p Signed8Depth2TerminalLeafProfile) ExpectedSerializedBytes() Signed8Depth2TerminalLeafSerializedBytes {
	return p.expectedBytes
}
func (p Signed8Depth2TerminalLeafProfile) CacheSourceDigests() [4]string { return p.cacheSourceDigests }
func (p Signed8Depth2TerminalLeafProfile) CachePayloadDigests() [4]string {
	return p.cachePayloadDigests
}
func (p Signed8Depth2TerminalLeafProfile) LevelLedger() string { return p.levelLedger }
func (p Signed8Depth2TerminalLeafProfile) Digest() string      { return p.digest }

type signed8Depth2TerminalCircuitGraph struct {
	circuit, circuitSeal                          *Signed8Depth2TerminalLeafCircuit
	child                                         *Signed8Depth2ChildComparatorCircuit
	decoder                                       *Signed8Depth2ChildSelectorDecodeCircuit
	encoder                                       *ckks.Encoder
	cacheSources, cacheSourceSeals                [4]*big.Float
	deltaL, cross, leaf00, deltaX                 *rlwe.Plaintext
	deltaLSeal, crossSeal, leaf00Seal, deltaXSeal *rlwe.Plaintext
	encoderRuntime                                ckks.EncoderRuntimeIdentity
	profileDigest, certificateDigest              string
}

type Signed8Depth2TerminalLeafCircuit struct {
	child, childSeal               *Signed8Depth2ChildComparatorCircuit
	decoder                        *Signed8Depth2ChildSelectorDecodeCircuit
	params                         ckks.Parameters
	encoder                        *ckks.Encoder
	cacheSources, cacheSourceSeals [4]*big.Float
	deltaL, cross, leaf00, deltaX  *rlwe.Plaintext
	deltaLSeal, crossSeal          *rlwe.Plaintext
	leaf00Seal, deltaXSeal         *rlwe.Plaintext
	profile                        Signed8Depth2TerminalLeafProfile
	graph                          signed8Depth2TerminalCircuitGraph
}

type Signed8Depth2TerminalLeafInput struct {
	decoderInput                             Signed8Depth2ChildSelectorDecodeInput
	rootSelector                             *rlwe.Ciphertext
	profileDigest, parameterDigest           string
	childProfileDigest, decoderProfileDigest string
	prefixProfileDigest, protocolRangeDigest string
	treeDigest, scheduleDigest               string
	childInputBindingDigest                  string
	childResultProvenanceDigest              string
	operandsProvenanceDigest                 string
	decoderInputProvenanceDigest             string
	operandMode                              Signed8ComparatorOperandMode
	producerProfileDigest                    string
	rootPayloadDigest                        string
	provenanceDigest                         string
}

type signed8Depth2TerminalEvaluatorGraph struct {
	evaluator          *Signed8Depth2TerminalLeafEvaluator
	circuit            *Signed8Depth2TerminalLeafCircuit
	source             *bootstrapping.Evaluator
	ckks               *ckks.Evaluator
	decoder            *Signed8Depth2ChildSelectorDecodeEvaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	galoisKeys         map[uint64]*rlwe.GaloisKey
	galoisMapPointer   uintptr
	profileDigest      string
	ckksRuntime        ckks.EvaluatorRuntimeIdentity
	rlweBuffersRuntime rlwe.EvaluatorBuffersRuntimeIdentity
	rlweRuntime        rlwe.EvaluatorRuntimeIdentity
}

type Signed8Depth2TerminalLeafEvaluator struct {
	circuit            *Signed8Depth2TerminalLeafCircuit
	source             *bootstrapping.Evaluator
	ckks               *ckks.Evaluator
	decoder            *Signed8Depth2ChildSelectorDecodeEvaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	galoisKeys         map[uint64]*rlwe.GaloisKey
	graph              signed8Depth2TerminalEvaluatorGraph
}

type Signed8Depth2TerminalLeafResult struct {
	output                                   *rlwe.Ciphertext
	profileDigest, parameterDigest           string
	childProfileDigest, decoderProfileDigest string
	treeDigest, scheduleDigest               string
	certificateDigest                        string
	cachePayloadDigests                      [4]string
	inputProvenanceDigest                    string
	childInputBindingDigest                  string
	childResultProvenanceDigest              string
	operandsProvenanceDigest                 string
	decoderResultDigest, decoderTraceDigest  string
	operandMode                              Signed8ComparatorOperandMode
	producerProfileDigest                    string
	outputPayloadDigest, provenanceDigest    string
}

func (r Signed8Depth2TerminalLeafResult) Ciphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.output)
}
func (r Signed8Depth2TerminalLeafResult) ProfileDigest() string   { return r.profileDigest }
func (r Signed8Depth2TerminalLeafResult) ParameterDigest() string { return r.parameterDigest }
func (r Signed8Depth2TerminalLeafResult) TreeDigest() string      { return r.treeDigest }
func (r Signed8Depth2TerminalLeafResult) ScheduleDigest() string  { return r.scheduleDigest }
func (r Signed8Depth2TerminalLeafResult) MagnitudeCertificateDigest() string {
	return r.certificateDigest
}
func (r Signed8Depth2TerminalLeafResult) InputProvenanceDigest() string {
	return r.inputProvenanceDigest
}
func (r Signed8Depth2TerminalLeafResult) ChildInputBindingDigest() string {
	return r.childInputBindingDigest
}
func (r Signed8Depth2TerminalLeafResult) ChildResultProvenanceDigest() string {
	return r.childResultProvenanceDigest
}
func (r Signed8Depth2TerminalLeafResult) OperandsProvenanceDigest() string {
	return r.operandsProvenanceDigest
}
func (r Signed8Depth2TerminalLeafResult) DecoderResultDigest() string { return r.decoderResultDigest }
func (r Signed8Depth2TerminalLeafResult) DecoderTraceDigest() string  { return r.decoderTraceDigest }
func (r Signed8Depth2TerminalLeafResult) OperandMode() Signed8ComparatorOperandMode {
	return r.operandMode
}
func (r Signed8Depth2TerminalLeafResult) OutputPayloadDigest() string { return r.outputPayloadDigest }
func (r Signed8Depth2TerminalLeafResult) ProvenanceDigest() string    { return r.provenanceDigest }

type Signed8Depth2TerminalLeafTrace struct {
	profileDigest, inputProvenanceDigest    string
	childInputBindingDigest                 string
	childResultProvenanceDigest             string
	operandsProvenanceDigest                string
	decoderInputProvenanceDigest            string
	producerProfileDigest                   string
	operandMode                             Signed8ComparatorOperandMode
	resultProvenanceDigest                  string
	decoderResultDigest, decoderTraceDigest string
	failureStage                            Signed8Depth2TerminalLeafStage
	decoderResult                           Signed8Depth2ChildSelectorDecodeResult
	decoderTrace                            Signed8Depth2ChildSelectorDecodeTrace
	counts                                  Signed8Depth2TerminalLeafOperationCounts
	attemptedOperationLowerBound            Signed8Depth2TerminalLeafComposedOperationCounts
	states                                  []Signed8Depth2TerminalLeafState
	serializedBytes                         Signed8Depth2TerminalLeafSerializedBytes
	runtimeGalois                           []uint64
	relinearizationMatched                  bool
	retainedCiphertexts                     map[Signed8Depth2TerminalLeafStage]*rlwe.Ciphertext
	retainedPayloadDigests                  map[Signed8Depth2TerminalLeafStage]string
	traceDigest                             string
	wallTime                                time.Duration
}

func (t Signed8Depth2TerminalLeafTrace) ProfileDigest() string { return t.profileDigest }
func (t Signed8Depth2TerminalLeafTrace) InputProvenanceDigest() string {
	return t.inputProvenanceDigest
}
func (t Signed8Depth2TerminalLeafTrace) ChildInputBindingDigest() string {
	return t.childInputBindingDigest
}
func (t Signed8Depth2TerminalLeafTrace) ChildResultProvenanceDigest() string {
	return t.childResultProvenanceDigest
}
func (t Signed8Depth2TerminalLeafTrace) OperandsProvenanceDigest() string {
	return t.operandsProvenanceDigest
}
func (t Signed8Depth2TerminalLeafTrace) DecoderInputProvenanceDigest() string {
	return t.decoderInputProvenanceDigest
}
func (t Signed8Depth2TerminalLeafTrace) ProducerProfileDigest() string {
	return t.producerProfileDigest
}
func (t Signed8Depth2TerminalLeafTrace) OperandMode() Signed8ComparatorOperandMode {
	return t.operandMode
}
func (t Signed8Depth2TerminalLeafTrace) ResultProvenanceDigest() string {
	return t.resultProvenanceDigest
}
func (t Signed8Depth2TerminalLeafTrace) DecoderResultDigest() string { return t.decoderResultDigest }
func (t Signed8Depth2TerminalLeafTrace) DecoderTraceDigest() string  { return t.decoderTraceDigest }
func (t Signed8Depth2TerminalLeafTrace) FailureStage() Signed8Depth2TerminalLeafStage {
	return t.failureStage
}
func (t Signed8Depth2TerminalLeafTrace) DecoderTrace() Signed8Depth2ChildSelectorDecodeTrace {
	return cloneSigned8Depth2ChildSelectorDecodeTrace(t.decoderTrace)
}
func (t Signed8Depth2TerminalLeafTrace) DecoderResult() Signed8Depth2ChildSelectorDecodeResult {
	return cloneSigned8Depth2ChildSelectorDecodeResult(t.decoderResult)
}
func (t Signed8Depth2TerminalLeafTrace) OperationCounts() Signed8Depth2TerminalLeafOperationCounts {
	return t.counts
}

// CompletedComposedOperationCounts reports only operations that completed.
func (t Signed8Depth2TerminalLeafTrace) CompletedComposedOperationCounts() Signed8Depth2TerminalLeafComposedOperationCounts {
	return Signed8Depth2TerminalLeafComposedOperationCounts{
		ChildDecoder: t.decoderTrace.OperationCounts(),
		TerminalMux:  t.counts,
	}
}

// AttemptedOperationLowerBound reports completed primitives plus only those
// top-level dispatches known to have started. It is intentionally a lower
// bound because the decoder's helper internals are opaque at this seam.
func (t Signed8Depth2TerminalLeafTrace) AttemptedOperationLowerBound() Signed8Depth2TerminalLeafComposedOperationCounts {
	return t.attemptedOperationLowerBound
}
func (t Signed8Depth2TerminalLeafTrace) States() []Signed8Depth2TerminalLeafState {
	return append([]Signed8Depth2TerminalLeafState(nil), t.states...)
}
func (t Signed8Depth2TerminalLeafTrace) SerializedBytes() Signed8Depth2TerminalLeafSerializedBytes {
	return t.serializedBytes
}
func (t Signed8Depth2TerminalLeafTrace) RuntimeGaloisElements() []uint64 {
	return append([]uint64(nil), t.runtimeGalois...)
}
func (t Signed8Depth2TerminalLeafTrace) RelinearizationKeyMatched() bool {
	return t.relinearizationMatched
}
func (t Signed8Depth2TerminalLeafTrace) RetainedCiphertext(stage Signed8Depth2TerminalLeafStage) (*rlwe.Ciphertext, bool) {
	value, ok := t.retainedCiphertexts[stage]
	return copyA2BRefreshCiphertext(value), ok && value != nil
}
func (t Signed8Depth2TerminalLeafTrace) Digest() string          { return t.traceDigest }
func (t Signed8Depth2TerminalLeafTrace) WallTime() time.Duration { return t.wallTime }
func (t Signed8Depth2TerminalLeafTrace) UniqueComposedMeasuredBytes() int {
	decoderLedger := t.decoderTrace.SerializedBytes()
	decoderBytes := decoderLedger.ModuleTotal()
	localBytes := t.serializedBytes.TotalBytes()
	if decoderLedger.DecodedChildSelector > 0 && t.serializedBytes.DecodedChild > 0 {
		// The decoder output and terminal decoded-child input are the same
		// logical boundary and are counted exactly once in the composition.
		localBytes -= t.serializedBytes.DecodedChild
	}
	return decoderBytes + localBytes
}

func (i Signed8Depth2TerminalLeafInput) OperandMode() Signed8ComparatorOperandMode {
	return i.operandMode
}
func (i Signed8Depth2TerminalLeafInput) ChildInputBindingDigest() string {
	return i.childInputBindingDigest
}
func (i Signed8Depth2TerminalLeafInput) ChildResultProvenanceDigest() string {
	return i.childResultProvenanceDigest
}
func (i Signed8Depth2TerminalLeafInput) OperandsProvenanceDigest() string {
	return i.operandsProvenanceDigest
}
func (i Signed8Depth2TerminalLeafInput) ProvenanceDigest() string { return i.provenanceDigest }
func (i Signed8Depth2TerminalLeafInput) RootSelectorCiphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(i.rootSelector)
}

// NewSigned8Depth2TerminalLeafCircuit derives all leaves, cache operands and
// certificates from the exact child-owned source tree. There is intentionally
// no leaf argument or post-construction setter.
func NewSigned8Depth2TerminalLeafCircuit(child *Signed8Depth2ChildComparatorCircuit) (*Signed8Depth2TerminalLeafCircuit, error) {
	if child == nil {
		return nil, fmt.Errorf("homchain: nil child comparator for terminal leaf circuit")
	}
	if err := child.validate(); err != nil {
		return nil, fmt.Errorf("homchain: validate terminal child comparator: %w", err)
	}
	decoder, err := NewSigned8Depth2ChildSelectorDecodeCircuit(child)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct terminal child decoder: %w", err)
	}
	params := child.prefix.params
	if err = validateSigned8Depth2TerminalParameters(params); err != nil {
		return nil, err
	}
	prefixProfile := child.prefix.Profile()
	tree := prefixProfile.Tree()
	if tree.Depth != 2 || len(tree.Leaves) != 4 {
		return nil, fmt.Errorf("homchain: terminal leaf circuit requires the exact frozen depth-2 four-leaf tree")
	}

	scales, err := deriveSigned8Depth2TerminalScales(params)
	if err != nil {
		return nil, err
	}
	leafRats, leafBits, cacheRats, cacheFloats, cacheErrors, err := deriveSigned8Depth2TerminalLeafValues(tree.Leaves)
	if err != nil {
		return nil, err
	}
	certificate, err := deriveSigned8Depth2LeafMagnitudeCertificate(
		params, child.Profile(), prefixProfile, leafRats, leafBits, cacheRats, cacheErrors, scales,
	)
	if err != nil {
		return nil, err
	}

	encoder := ckks.NewEncoder(params, signed8Depth2LeafCertificatePrecision)
	cacheLevels := [4]int{8, 8, 7, 7}
	cacheScales := [4]ExactScaleSnapshot{scales.delta, scales.delta, scales.leaf, scales.leaf}
	cacheNames := [4]string{"dL", "cross", "l00", "dX"}
	var caches [4]*rlwe.Plaintext
	var seals [4]*rlwe.Plaintext
	var sourceDigests, payloadDigests [4]string
	for index := range caches {
		if caches[index], err = encodeSigned8Depth2TerminalCache(params, encoder, cacheFloats[index], cacheLevels[index], cacheScales[index]); err != nil {
			return nil, fmt.Errorf("homchain: encode terminal cache %s: %w", cacheNames[index], err)
		}
		seals[index] = caches[index].CopyNew()
		if payloadDigests[index], err = signed8PlaintextDigest(caches[index]); err != nil {
			return nil, err
		}
		sourceDigests[index] = digestSigned8Depth2TerminalCacheSource(
			cacheNames[index], cacheRats[index], cacheLevels[index], cacheScales[index],
		)
	}
	encoderRuntime, err := encoder.RuntimeIdentitySnapshot()
	if err != nil {
		return nil, fmt.Errorf("homchain: snapshot terminal cache encoder: %w", err)
	}

	counts := Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications: 2, CiphertextCiphertextMultiplications: 1,
		Relinearizations: 1, Rescales: 3, PlaintextVectorAdditions: 2,
		CiphertextAdditions: 1, LevelDrops: 1,
	}
	expectedBytes := signed8Depth2TerminalExpectedBytes()
	expectedStates := signed8Depth2TerminalExpectedStates(params, scales, expectedBytes)
	keyProfile := decoder.RequiredKeyProfile()
	profile := Signed8Depth2TerminalLeafProfile{
		fidelity:        Signed8Depth2TerminalLeafFunctionalNotSecure,
		parameterDigest: child.Profile().ParameterDigest(), childProfileDigest: child.Profile().Digest(),
		decoderProfileDigest: decoder.Profile().Digest(), prefixProfileDigest: child.Profile().PrefixProfileDigest(),
		protocolRangeDigest: child.Profile().ProtocolRangeDigest(), treeDigest: child.Profile().TreeDigest(),
		scheduleDigest:       child.Profile().ScheduleDigest(),
		producerPublicDigest: child.prefix.selector.Profile().ProducerPublicProfileDigest(),
		producerOpaqueDigest: child.prefix.selector.Profile().ProducerOpaqueProfileDigest(),
		leaves:               leafBits, certificate: certificate, scales: scales,
		cacheSourceDigests: sourceDigests, cachePayloadDigests: payloadDigests,
		counts: counts, requiredGalois: keyProfile.All(), relinearization: keyProfile.RelinearizationRequired(),
		expectedStates: expectedStates, expectedBytes: expectedBytes,
		levelLedger: signed8Depth2TerminalLeafLevelLedger,
	}
	profile.digest = digestSigned8Depth2TerminalLeafProfile(profile)
	circuit := &Signed8Depth2TerminalLeafCircuit{
		child: child, childSeal: child, decoder: decoder, params: params, encoder: encoder,
		cacheSources: cacheFloats,
		deltaL:       caches[0], cross: caches[1], leaf00: caches[2], deltaX: caches[3],
		deltaLSeal: seals[0], crossSeal: seals[1], leaf00Seal: seals[2], deltaXSeal: seals[3],
		profile: profile,
	}
	for index := range circuit.cacheSourceSeals {
		circuit.cacheSourceSeals[index] = new(big.Float).Copy(cacheFloats[index])
	}
	circuit.graph = signed8Depth2TerminalCircuitGraph{
		circuit: circuit, circuitSeal: circuit, child: child, decoder: decoder, encoder: encoder,
		cacheSources: circuit.cacheSources, cacheSourceSeals: circuit.cacheSourceSeals,
		deltaL: caches[0], cross: caches[1], leaf00: caches[2], deltaX: caches[3],
		deltaLSeal: seals[0], crossSeal: seals[1], leaf00Seal: seals[2], deltaXSeal: seals[3],
		encoderRuntime: encoderRuntime, profileDigest: profile.digest, certificateDigest: certificate.digest,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *Signed8Depth2TerminalLeafCircuit) Profile() Signed8Depth2TerminalLeafProfile {
	if c == nil {
		return Signed8Depth2TerminalLeafProfile{}
	}
	return cloneSigned8Depth2TerminalLeafProfile(c.profile)
}

func (c *Signed8Depth2TerminalLeafCircuit) RequiredKeyProfile() SelectorReraiseDecodeKeyProfile {
	if c == nil || c.decoder == nil {
		return SelectorReraiseDecodeKeyProfile{}
	}
	return c.decoder.RequiredKeyProfile()
}

func (c *Signed8Depth2TerminalLeafCircuit) BindChildResult(
	childInput Signed8Depth2ChildComparatorInput,
	childResult Signed8Depth2ChildComparatorResult,
) (Signed8Depth2TerminalLeafInput, error) {
	if err := c.validate(); err != nil {
		return Signed8Depth2TerminalLeafInput{}, err
	}
	decoderInput, err := c.decoder.BindChildResult(childInput, childResult)
	if err != nil {
		return Signed8Depth2TerminalLeafInput{}, fmt.Errorf("homchain: authenticate child pair for terminal leaf: %w", err)
	}
	root := copyA2BRefreshCiphertext(childInput.operands.conditionedSelector)
	rootPayload, err := signed8CiphertextDigest(root)
	if err != nil {
		return Signed8Depth2TerminalLeafInput{}, err
	}
	mode := decoderInput.OperandMode()
	producer := childInput.operands.producerProfileDigest
	if want := c.child.prefix.selector.producer.profileForMode(mode).digest; want == "" || producer != want {
		return Signed8Depth2TerminalLeafInput{}, fmt.Errorf("homchain: terminal root producer mode is foreign")
	}
	input := Signed8Depth2TerminalLeafInput{
		decoderInput: cloneSigned8Depth2ChildSelectorDecodeInput(decoderInput), rootSelector: root,
		profileDigest: c.profile.digest, parameterDigest: c.profile.parameterDigest,
		childProfileDigest: c.profile.childProfileDigest, decoderProfileDigest: c.profile.decoderProfileDigest,
		prefixProfileDigest: c.profile.prefixProfileDigest, protocolRangeDigest: c.profile.protocolRangeDigest,
		treeDigest: c.profile.treeDigest, scheduleDigest: c.profile.scheduleDigest,
		childInputBindingDigest: childInput.BindingDigest(), childResultProvenanceDigest: childResult.ProvenanceDigest(),
		operandsProvenanceDigest:     childInput.OperandsProvenanceDigest(),
		decoderInputProvenanceDigest: decoderInput.ProvenanceDigest(), operandMode: mode,
		producerProfileDigest: producer, rootPayloadDigest: rootPayload,
	}
	input.provenanceDigest = digestSigned8Depth2TerminalLeafInput(input, rootPayload)
	if err = c.validateInput(input); err != nil {
		return Signed8Depth2TerminalLeafInput{}, err
	}
	return input, nil
}

func (c *Signed8Depth2TerminalLeafCircuit) BindEvaluator(
	source *bootstrapping.Evaluator,
) (*Signed8Depth2TerminalLeafEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if source == nil || source.EvaluationKeys == nil || source.Evaluator == nil ||
		source.MemEvaluationKeySet == nil || !source.ResidualParameters.Equal(&c.params) ||
		!source.BootstrappingParameters.Equal(&c.params) || !c.params.Equal(source.Evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: terminal evaluator source is nil, incomplete, or foreign")
	}
	decoder, err := c.decoder.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind terminal child decoder: %w", err)
	}
	if decoder.circuit != c.decoder || decoder.source != source || decoder.keySet != source.MemEvaluationKeySet {
		return nil, fmt.Errorf("homchain: terminal child decoder evaluator graph is foreign")
	}
	keySet := source.MemEvaluationKeySet
	provided := append([]uint64(nil), keySet.GetGaloisKeysList()...)
	sort.Slice(provided, func(i, j int) bool { return provided[i] < provided[j] })
	if !equalSigned8Depth2TerminalUint64Slices(provided, c.profile.requiredGalois) {
		return nil, fmt.Errorf("homchain: terminal exact Galois inventory=%v, want %v", provided, c.profile.requiredGalois)
	}
	relinearizationKey, err := keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil || relinearizationKey != decoder.relinearizationKey {
		return nil, fmt.Errorf("homchain: terminal relinearization key is missing or differs from the decoder: %v", err)
	}
	galoisKeys := make(map[uint64]*rlwe.GaloisKey, len(provided))
	for _, element := range provided {
		key, keyErr := keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil || key != decoder.galoisKeys[element] {
			return nil, fmt.Errorf("homchain: terminal Galois key %d is missing or differs from the decoder", element)
		}
		galoisKeys[element] = key
	}
	evaluator := &Signed8Depth2TerminalLeafEvaluator{
		circuit: c, source: source, ckks: source.Evaluator, decoder: decoder, keySet: keySet,
		relinearizationKey: relinearizationKey, galoisKeys: galoisKeys,
	}
	ckksRuntime, err := source.Evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return nil, fmt.Errorf("homchain: snapshot terminal CKKS evaluator: %w", err)
	}
	rlweBuffersRuntime, err := source.Evaluator.Evaluator.EvaluatorBuffers.RuntimeIdentitySnapshot()
	if err != nil {
		return nil, fmt.Errorf("homchain: snapshot terminal RLWE buffers: %w", err)
	}
	rlweRuntime, err := source.Evaluator.Evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return nil, fmt.Errorf("homchain: snapshot terminal RLWE evaluator: %w", err)
	}
	evaluator.graph = signed8Depth2TerminalEvaluatorGraph{
		evaluator: evaluator, circuit: c, source: source, ckks: source.Evaluator,
		decoder: decoder, keySet: keySet, relinearizationKey: relinearizationKey,
		galoisKeys: galoisKeys, galoisMapPointer: reflect.ValueOf(galoisKeys).Pointer(),
		profileDigest: c.profile.digest, ckksRuntime: ckksRuntime,
		rlweBuffersRuntime: rlweBuffersRuntime, rlweRuntime: rlweRuntime,
	}
	if _, err = evaluator.preflight(); err != nil {
		return nil, err
	}
	return evaluator, nil
}

func (e *Signed8Depth2TerminalLeafEvaluator) preflight() (A2BRefreshKeyPreflight, error) {
	zero := A2BRefreshKeyPreflight{Checked: true, GraphChecked: true}
	if e == nil || e.circuit == nil || e.source == nil || e.ckks == nil || e.decoder == nil ||
		e.keySet == nil || e.relinearizationKey == nil || e.galoisKeys == nil {
		return zero, fmt.Errorf("homchain: nil or incomplete bound terminal evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		zero.GraphMismatch = err.Error()
		return zero, err
	}
	g := e.graph
	if g.evaluator != e || g.circuit != e.circuit || g.source != e.source || g.ckks != e.ckks ||
		g.decoder != e.decoder || g.keySet != e.keySet || g.relinearizationKey != e.relinearizationKey ||
		g.galoisKeys == nil || g.galoisMapPointer != reflect.ValueOf(e.galoisKeys).Pointer() ||
		g.profileDigest != e.circuit.profile.digest || e.source.Evaluator != e.ckks ||
		e.source.MemEvaluationKeySet != e.keySet || e.source.EvaluationKeys == nil ||
		e.source.EvaluationKeys.MemEvaluationKeySet != e.keySet || e.decoder.circuit != e.circuit.decoder ||
		e.decoder.source != e.source || e.decoder.keySet != e.keySet {
		zero.GraphMismatch = "terminal evaluator object graph changed"
		return zero, fmt.Errorf("homchain: %s", zero.GraphMismatch)
	}
	preflight, err := e.decoder.preflight()
	if err != nil {
		return preflight, fmt.Errorf("homchain: terminal child decoder preflight: %w", err)
	}
	provided := append([]uint64(nil), e.keySet.GetGaloisKeysList()...)
	sort.Slice(provided, func(i, j int) bool { return provided[i] < provided[j] })
	if !equalSigned8Depth2TerminalUint64Slices(provided, e.circuit.profile.requiredGalois) || len(e.galoisKeys) != len(provided) {
		return preflight, fmt.Errorf("homchain: terminal exact key inventory changed")
	}
	key, keyErr := e.keySet.GetRelinearizationKey()
	if keyErr != nil || key == nil || key != e.relinearizationKey || key != e.decoder.relinearizationKey {
		return preflight, fmt.Errorf("homchain: terminal relinearization key identity changed")
	}
	for _, element := range provided {
		current, currentErr := e.keySet.GetGaloisKey(element)
		if currentErr != nil || current == nil || current != e.galoisKeys[element] ||
			current != g.galoisKeys[element] || current != e.decoder.galoisKeys[element] {
			return preflight, fmt.Errorf("homchain: terminal Galois key %d identity changed", element)
		}
	}
	ckksRuntime, err := e.ckks.RuntimeIdentitySnapshot()
	if err != nil || !g.ckksRuntime.Equal(ckksRuntime) {
		return preflight, fmt.Errorf("homchain: terminal CKKS evaluator runtime identity changed: %v", err)
	}
	rlweBuffersRuntime, err := e.ckks.Evaluator.EvaluatorBuffers.RuntimeIdentitySnapshot()
	if err != nil || !g.rlweBuffersRuntime.Equal(rlweBuffersRuntime) {
		return preflight, fmt.Errorf("homchain: terminal RLWE buffer runtime identity changed: %v", err)
	}
	rlweRuntime, err := e.ckks.Evaluator.RuntimeIdentitySnapshot()
	if err != nil || !g.rlweRuntime.Equal(rlweRuntime) {
		return preflight, fmt.Errorf("homchain: terminal RLWE evaluator runtime identity changed: %v", err)
	}
	return preflight, nil
}

func (e *Signed8Depth2TerminalLeafEvaluator) EvaluateNew(
	input Signed8Depth2TerminalLeafInput,
) (result Signed8Depth2TerminalLeafResult, trace Signed8Depth2TerminalLeafTrace, err error) {
	if e == nil || e.decoder == nil {
		return e.evaluateNew(input, nil)
	}
	return e.evaluateNew(input, e.decoder.EvaluateNew)
}

func (e *Signed8Depth2TerminalLeafEvaluator) evaluateNew(
	input Signed8Depth2TerminalLeafInput,
	decoderEvaluate func(Signed8Depth2ChildSelectorDecodeInput) (
		Signed8Depth2ChildSelectorDecodeResult,
		Signed8Depth2ChildSelectorDecodeTrace,
		error,
	),
) (result Signed8Depth2TerminalLeafResult, trace Signed8Depth2TerminalLeafTrace, err error) {
	started := time.Now()
	if e == nil || e.circuit == nil {
		return result, trace, fmt.Errorf("homchain: nil bound terminal leaf evaluator")
	}
	if decoderEvaluate == nil {
		return result, trace, fmt.Errorf("homchain: nil terminal child decoder dispatch")
	}
	if _, err = e.preflight(); err != nil {
		return result, trace, err
	}
	if err = e.circuit.validateInput(input); err != nil {
		return result, trace, err
	}
	inputBefore := input
	inputBefore.decoderInput = cloneSigned8Depth2ChildSelectorDecodeInput(input.decoderInput)
	inputBefore.rootSelector = copyA2BRefreshCiphertext(input.rootSelector)

	decoderResult, decoderTrace, err := decoderEvaluate(input.decoderInput)
	if err != nil {
		cause := fmt.Errorf("homchain: terminal child decoder: %w", err)
		if reflect.DeepEqual(decoderResult, Signed8Depth2ChildSelectorDecodeResult{}) &&
			reflect.DeepEqual(decoderTrace, Signed8Depth2ChildSelectorDecodeTrace{}) {
			// The decoder guarantees exact-zero evidence for every rejection
			// before its first HE dispatch.
			return result, trace, cause
		}
		_, partial, finalizeErr := finalizeSigned8Depth2TerminalLeafDecoderFailure(
			e.circuit, input, decoderResult, decoderTrace, time.Since(started),
		)
		if finalizeErr != nil {
			cause = fmt.Errorf("%w; finalize terminal decoder failure evidence: %v", cause, finalizeErr)
		}
		return result, partial, cause
	}

	trace = newSigned8Depth2TerminalLeafTrace(e.circuit, input, decoderResult, decoderTrace)
	postFailure := func(stage Signed8Depth2TerminalLeafStage, cause error) (Signed8Depth2TerminalLeafResult, Signed8Depth2TerminalLeafTrace, error) {
		zeroResult, partial, finalizeErr := finalizeSigned8Depth2TerminalLeafFailure(
			e.circuit, input, trace, stage, time.Since(started),
		)
		if finalizeErr != nil {
			cause = fmt.Errorf("%w; finalize terminal failure evidence: %v", cause, finalizeErr)
		}
		return zeroResult, partial, cause
	}
	if err = e.circuit.decoder.validateResult(decoderResult); err != nil {
		return postFailure(Signed8Depth2TerminalStageDecodedChild, fmt.Errorf("homchain: terminal validate decoder result: %w", err))
	}
	if err = e.circuit.decoder.validateTrace(input.decoderInput, decoderResult, decoderTrace); err != nil {
		return postFailure(Signed8Depth2TerminalStageDecodedChild, fmt.Errorf("homchain: terminal validate decoder trace: %w", err))
	}
	if err = e.circuit.validateInput(input); err != nil ||
		!input.rootSelector.Equal(inputBefore.rootSelector) ||
		!input.decoderInput.branch.Equal(inputBefore.decoderInput.branch) {
		return postFailure(Signed8Depth2TerminalStageAdmission, fmt.Errorf("homchain: terminal decoder mutated the admitted child/root input: %v", err))
	}
	b1 := decoderResult.Ciphertext()
	b0 := copyA2BRefreshCiphertext(input.rootSelector)
	if err = requireSigned8Depth2TerminalCiphertextState("decoded child b1", b1, 8, e.circuit.profile.scales.b1, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageDecodedChild, err)
	}
	if err = requireSigned8Depth2TerminalCiphertextState("root b0", b0, 7, e.circuit.profile.scales.b0, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageRootSelector, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageDecodedChild, b1); err != nil {
		return postFailure(Signed8Depth2TerminalStageDecodedChild, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageRootSelector, b0); err != nil {
		return postFailure(Signed8Depth2TerminalStageRootSelector, err)
	}

	b1Before, b0Before := b1.CopyNew(), b0.CopyNew()
	trace.attemptedOperationLowerBound.TerminalMux.CiphertextPlaintextMultiplications++
	rawA, err := e.ckks.MulNew(b1, e.circuit.deltaL)
	if err != nil {
		return postFailure(Signed8Depth2TerminalStageRawA, fmt.Errorf("homchain: terminal b1*dL: %w", err))
	}
	trace.counts.CiphertextPlaintextMultiplications++
	if !b1.Equal(b1Before) || !b0.Equal(b0Before) {
		return postFailure(Signed8Depth2TerminalStageRawA, fmt.Errorf("homchain: terminal b1*dL mutated an input selector"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("rawA", rawA, 8, e.circuit.profile.scales.rawA, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageRawA, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageRawA, rawA); err != nil {
		return postFailure(Signed8Depth2TerminalStageRawA, err)
	}
	rawABefore := rawA.CopyNew()
	a := rawA.CopyNew()
	trace.attemptedOperationLowerBound.TerminalMux.Rescales++
	if err = e.ckks.Rescale(a, a); err != nil {
		return postFailure(Signed8Depth2TerminalStageRescaledA, fmt.Errorf("homchain: terminal rescale a: %w", err))
	}
	trace.counts.Rescales++
	if !rawA.Equal(rawABefore) {
		return postFailure(Signed8Depth2TerminalStageRescaledA, fmt.Errorf("homchain: terminal rescale a mutated retained rawA"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("a", a, 7, e.circuit.profile.scales.leaf, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageRescaledA, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageRescaledA, a); err != nil {
		return postFailure(Signed8Depth2TerminalStageRescaledA, err)
	}
	aBefore := a.CopyNew()
	trace.attemptedOperationLowerBound.TerminalMux.PlaintextVectorAdditions++
	A, err := e.ckks.AddNew(a, e.circuit.leaf00)
	if err != nil {
		return postFailure(Signed8Depth2TerminalStageAffineA, fmt.Errorf("homchain: terminal add l00: %w", err))
	}
	trace.counts.PlaintextVectorAdditions++
	if !a.Equal(aBefore) {
		return postFailure(Signed8Depth2TerminalStageAffineA, fmt.Errorf("homchain: terminal l00 addition mutated a"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("A", A, 7, e.circuit.profile.scales.leaf, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageAffineA, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageAffineA, A); err != nil {
		return postFailure(Signed8Depth2TerminalStageAffineA, err)
	}

	trace.attemptedOperationLowerBound.TerminalMux.CiphertextPlaintextMultiplications++
	rawD, err := e.ckks.MulNew(b1, e.circuit.cross)
	if err != nil {
		return postFailure(Signed8Depth2TerminalStageRawD, fmt.Errorf("homchain: terminal b1*cross: %w", err))
	}
	trace.counts.CiphertextPlaintextMultiplications++
	if !b1.Equal(b1Before) {
		return postFailure(Signed8Depth2TerminalStageRawD, fmt.Errorf("homchain: terminal b1*cross mutated b1"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("rawD", rawD, 8, e.circuit.profile.scales.rawA, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageRawD, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageRawD, rawD); err != nil {
		return postFailure(Signed8Depth2TerminalStageRawD, err)
	}
	rawDBefore := rawD.CopyNew()
	d := rawD.CopyNew()
	trace.attemptedOperationLowerBound.TerminalMux.Rescales++
	if err = e.ckks.Rescale(d, d); err != nil {
		return postFailure(Signed8Depth2TerminalStageRescaledD, fmt.Errorf("homchain: terminal rescale d: %w", err))
	}
	trace.counts.Rescales++
	if !rawD.Equal(rawDBefore) {
		return postFailure(Signed8Depth2TerminalStageRescaledD, fmt.Errorf("homchain: terminal rescale d mutated retained rawD"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("d", d, 7, e.circuit.profile.scales.leaf, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageRescaledD, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageRescaledD, d); err != nil {
		return postFailure(Signed8Depth2TerminalStageRescaledD, err)
	}
	dBefore := d.CopyNew()
	trace.attemptedOperationLowerBound.TerminalMux.PlaintextVectorAdditions++
	D, err := e.ckks.AddNew(d, e.circuit.deltaX)
	if err != nil {
		return postFailure(Signed8Depth2TerminalStageAffineD, fmt.Errorf("homchain: terminal add dX: %w", err))
	}
	trace.counts.PlaintextVectorAdditions++
	if !d.Equal(dBefore) {
		return postFailure(Signed8Depth2TerminalStageAffineD, fmt.Errorf("homchain: terminal dX addition mutated d"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("D", D, 7, e.circuit.profile.scales.leaf, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageAffineD, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageAffineD, D); err != nil {
		return postFailure(Signed8Depth2TerminalStageAffineD, err)
	}

	DBefore := D.CopyNew()
	trace.attemptedOperationLowerBound.TerminalMux.CiphertextCiphertextMultiplications++
	rawY, err := e.ckks.MulRelinNew(b0, D)
	if err != nil {
		return postFailure(Signed8Depth2TerminalStageRawY, fmt.Errorf("homchain: terminal b0*D: %w", err))
	}
	// A nil return proves that the fused MulRelin dispatch reached and
	// completed its relinearization component. Pre-dispatch validation errors
	// do not justify claiming a relinearization attempt.
	trace.attemptedOperationLowerBound.TerminalMux.Relinearizations++
	trace.counts.CiphertextCiphertextMultiplications++
	trace.counts.Relinearizations++
	if !b0.Equal(b0Before) || !D.Equal(DBefore) {
		return postFailure(Signed8Depth2TerminalStageRawY, fmt.Errorf("homchain: terminal b0*D mutated an operand"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("rawY", rawY, 7, e.circuit.profile.scales.rawY, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageRawY, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageRawY, rawY); err != nil {
		return postFailure(Signed8Depth2TerminalStageRawY, err)
	}
	rawYBefore := rawY.CopyNew()
	z := rawY.CopyNew()
	trace.attemptedOperationLowerBound.TerminalMux.Rescales++
	if err = e.ckks.Rescale(z, z); err != nil {
		return postFailure(Signed8Depth2TerminalStageRescaledY, fmt.Errorf("homchain: terminal rescale z: %w", err))
	}
	trace.counts.Rescales++
	if !rawY.Equal(rawYBefore) {
		return postFailure(Signed8Depth2TerminalStageRescaledY, fmt.Errorf("homchain: terminal rescale z mutated retained rawY"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("z", z, 6, e.circuit.profile.scales.leaf, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageRescaledY, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageRescaledY, z); err != nil {
		return postFailure(Signed8Depth2TerminalStageRescaledY, err)
	}
	ABefore := A.CopyNew()
	trace.attemptedOperationLowerBound.TerminalMux.LevelDrops++
	A6 := e.ckks.DropLevelNew(A, 1)
	trace.counts.LevelDrops++
	if !A.Equal(ABefore) {
		return postFailure(Signed8Depth2TerminalStageAlignedA, fmt.Errorf("homchain: terminal level alignment mutated A"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("A6", A6, 6, e.circuit.profile.scales.leaf, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageAlignedA, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageAlignedA, A6); err != nil {
		return postFailure(Signed8Depth2TerminalStageAlignedA, err)
	}
	A6Before, zBefore := A6.CopyNew(), z.CopyNew()
	trace.attemptedOperationLowerBound.TerminalMux.CiphertextAdditions++
	y, err := e.ckks.AddNew(A6, z)
	if err != nil {
		return postFailure(Signed8Depth2TerminalStageOutput, fmt.Errorf("homchain: terminal A6+z: %w", err))
	}
	trace.counts.CiphertextAdditions++
	if !A6.Equal(A6Before) || !z.Equal(zBefore) {
		return postFailure(Signed8Depth2TerminalStageOutput, fmt.Errorf("homchain: terminal output addition mutated an operand"))
	}
	if err = requireSigned8Depth2TerminalCiphertextState("y", y, 6, e.circuit.profile.scales.leaf, e.circuit.params); err != nil {
		return postFailure(Signed8Depth2TerminalStageOutput, err)
	}
	if err = appendSigned8Depth2TerminalState(&trace, Signed8Depth2TerminalStageOutput, y); err != nil {
		return postFailure(Signed8Depth2TerminalStageOutput, err)
	}

	trace.serializedBytes, err = signed8Depth2TerminalBytesFromStates(trace.states)
	if err != nil || trace.serializedBytes != e.circuit.profile.expectedBytes ||
		!equalSigned8Depth2TerminalStates(trace.states, e.circuit.profile.expectedStates) ||
		trace.counts != e.circuit.profile.counts ||
		trace.attemptedOperationLowerBound != trace.CompletedComposedOperationCounts() {
		return postFailure(Signed8Depth2TerminalStageOutput, fmt.Errorf("homchain: terminal runtime ledger differs from profile: %v", err))
	}
	if _, err = e.preflight(); err != nil {
		return postFailure(Signed8Depth2TerminalStagePreflight, err)
	}
	if err = e.circuit.validateInput(input); err != nil || !input.rootSelector.Equal(inputBefore.rootSelector) ||
		!input.decoderInput.branch.Equal(inputBefore.decoderInput.branch) {
		return postFailure(Signed8Depth2TerminalStageAdmission, fmt.Errorf("homchain: terminal input changed after evaluation: %v", err))
	}

	outputPayload, err := signed8CiphertextDigest(y)
	if err != nil {
		return postFailure(Signed8Depth2TerminalStageOutput, err)
	}
	result = Signed8Depth2TerminalLeafResult{
		output: y, profileDigest: e.circuit.profile.digest, parameterDigest: e.circuit.profile.parameterDigest,
		childProfileDigest: e.circuit.profile.childProfileDigest, decoderProfileDigest: e.circuit.profile.decoderProfileDigest,
		treeDigest: e.circuit.profile.treeDigest, scheduleDigest: e.circuit.profile.scheduleDigest,
		certificateDigest: e.circuit.profile.certificate.digest, cachePayloadDigests: e.circuit.profile.cachePayloadDigests,
		inputProvenanceDigest: input.provenanceDigest, childInputBindingDigest: input.childInputBindingDigest,
		childResultProvenanceDigest: input.childResultProvenanceDigest,
		operandsProvenanceDigest:    input.operandsProvenanceDigest,
		decoderResultDigest:         decoderResult.Digest(), decoderTraceDigest: decoderTrace.Digest(),
		operandMode: input.operandMode, producerProfileDigest: input.producerProfileDigest,
		outputPayloadDigest: outputPayload,
	}
	result.provenanceDigest = digestSigned8Depth2TerminalLeafResult(result, outputPayload)
	trace.resultProvenanceDigest = result.provenanceDigest
	trace.wallTime = time.Since(started)
	if trace.wallTime <= 0 {
		trace.wallTime = time.Nanosecond
	}
	trace.traceDigest = digestSigned8Depth2TerminalLeafTrace(trace)
	if err = e.circuit.validateResult(result); err != nil {
		return postFailure(Signed8Depth2TerminalStageOutput, err)
	}
	if err = e.circuit.validateTrace(input, result, trace); err != nil {
		return postFailure(Signed8Depth2TerminalStageOutput, err)
	}
	return cloneSigned8Depth2TerminalLeafResult(result), cloneSigned8Depth2TerminalLeafTrace(trace), nil
}

func newSigned8Depth2TerminalLeafTrace(
	circuit *Signed8Depth2TerminalLeafCircuit,
	input Signed8Depth2TerminalLeafInput,
	decoderResult Signed8Depth2ChildSelectorDecodeResult,
	decoderTrace Signed8Depth2ChildSelectorDecodeTrace,
) Signed8Depth2TerminalLeafTrace {
	trace := Signed8Depth2TerminalLeafTrace{
		profileDigest:                circuit.profile.digest,
		inputProvenanceDigest:        input.provenanceDigest,
		childInputBindingDigest:      input.childInputBindingDigest,
		childResultProvenanceDigest:  input.childResultProvenanceDigest,
		operandsProvenanceDigest:     input.operandsProvenanceDigest,
		decoderInputProvenanceDigest: input.decoderInputProvenanceDigest,
		producerProfileDigest:        input.producerProfileDigest,
		operandMode:                  input.operandMode,
		decoderResultDigest:          decoderResult.Digest(),
		decoderTraceDigest:           decoderTrace.Digest(),
		decoderResult:                cloneSigned8Depth2ChildSelectorDecodeResult(decoderResult),
		decoderTrace:                 cloneSigned8Depth2ChildSelectorDecodeTrace(decoderTrace),
		runtimeGalois:                append([]uint64(nil), circuit.profile.requiredGalois...),
		relinearizationMatched:       true,
		attemptedOperationLowerBound: Signed8Depth2TerminalLeafComposedOperationCounts{
			ChildDecoder: decoderTrace.AttemptedOperationLowerBound(),
		},
	}
	return trace
}

// finalizeSigned8Depth2TerminalLeafDecoderFailure lifts authenticated child
// partial evidence into the terminal module without inventing terminal mux
// work. It performs no HE operation and always returns an exact-zero result.
func finalizeSigned8Depth2TerminalLeafDecoderFailure(
	circuit *Signed8Depth2TerminalLeafCircuit,
	input Signed8Depth2TerminalLeafInput,
	decoderResult Signed8Depth2ChildSelectorDecodeResult,
	decoderTrace Signed8Depth2ChildSelectorDecodeTrace,
	wallTime time.Duration,
) (Signed8Depth2TerminalLeafResult, Signed8Depth2TerminalLeafTrace, error) {
	zeroResult := Signed8Depth2TerminalLeafResult{}
	if circuit == nil {
		trace := Signed8Depth2TerminalLeafTrace{
			failureStage:        Signed8Depth2TerminalStageDecoderFailure,
			decoderResult:       cloneSigned8Depth2ChildSelectorDecodeResult(decoderResult),
			decoderTrace:        cloneSigned8Depth2ChildSelectorDecodeTrace(decoderTrace),
			decoderResultDigest: decoderResult.Digest(), decoderTraceDigest: decoderTrace.Digest(),
			attemptedOperationLowerBound: Signed8Depth2TerminalLeafComposedOperationCounts{
				ChildDecoder: decoderTrace.AttemptedOperationLowerBound(),
			},
			wallTime: positiveSigned8Depth2TerminalWallTime(wallTime),
		}
		trace.traceDigest = digestSigned8Depth2TerminalLeafTrace(trace)
		return zeroResult, trace, fmt.Errorf("homchain: cannot finalize terminal decoder failure without its circuit")
	}
	trace := newSigned8Depth2TerminalLeafTrace(circuit, input, decoderResult, decoderTrace)
	trace.failureStage = Signed8Depth2TerminalStageDecoderFailure
	trace.resultProvenanceDigest = ""
	trace.wallTime = positiveSigned8Depth2TerminalWallTime(wallTime)
	trace = cloneSigned8Depth2TerminalLeafTrace(trace)
	trace.traceDigest = digestSigned8Depth2TerminalLeafTrace(trace)
	var finalizeErr error
	if !reflect.DeepEqual(decoderResult, Signed8Depth2ChildSelectorDecodeResult{}) {
		finalizeErr = fmt.Errorf("homchain: decoder failure exposed a nonzero result token")
	}
	if err := circuit.validateFailureTrace(input, trace); err != nil {
		finalizeErr = appendSigned8Depth2TerminalFinalizeError(finalizeErr, err)
	}
	return zeroResult, trace, finalizeErr
}

// finalizeSigned8Depth2TerminalLeafFailure seals terminal-local work already
// completed after a successful child decode. It is deliberately best effort:
// validation errors are returned alongside the detached nonzero trace.
func finalizeSigned8Depth2TerminalLeafFailure(
	circuit *Signed8Depth2TerminalLeafCircuit,
	input Signed8Depth2TerminalLeafInput,
	trace Signed8Depth2TerminalLeafTrace,
	failureStage Signed8Depth2TerminalLeafStage,
	wallTime time.Duration,
) (Signed8Depth2TerminalLeafResult, Signed8Depth2TerminalLeafTrace, error) {
	zeroResult := Signed8Depth2TerminalLeafResult{}
	trace.failureStage = failureStage
	trace.resultProvenanceDigest = ""
	trace.wallTime = positiveSigned8Depth2TerminalWallTime(wallTime)
	var finalizeErr error
	if circuit == nil {
		finalizeErr = fmt.Errorf("homchain: cannot finalize terminal failure without its circuit")
	} else {
		trace.profileDigest = circuit.profile.digest
		trace.inputProvenanceDigest = input.provenanceDigest
		trace.childInputBindingDigest = input.childInputBindingDigest
		trace.childResultProvenanceDigest = input.childResultProvenanceDigest
		trace.operandsProvenanceDigest = input.operandsProvenanceDigest
		trace.decoderInputProvenanceDigest = input.decoderInputProvenanceDigest
		trace.producerProfileDigest = input.producerProfileDigest
		trace.operandMode = input.operandMode
		trace.runtimeGalois = append([]uint64(nil), circuit.profile.requiredGalois...)
		trace.relinearizationMatched = true
	}
	trace.decoderResultDigest = trace.decoderResult.Digest()
	trace.decoderTraceDigest = trace.decoderTrace.Digest()
	trace.attemptedOperationLowerBound.ChildDecoder = trace.decoderTrace.AttemptedOperationLowerBound()
	bytes, bytesErr := signed8Depth2TerminalBytesFromStatePrefix(trace.states)
	trace.serializedBytes = bytes
	trace = cloneSigned8Depth2TerminalLeafTrace(trace)
	trace.traceDigest = digestSigned8Depth2TerminalLeafTrace(trace)
	finalizeErr = appendSigned8Depth2TerminalFinalizeError(finalizeErr, bytesErr)
	if circuit != nil {
		finalizeErr = appendSigned8Depth2TerminalFinalizeError(finalizeErr, circuit.validateFailureTrace(input, trace))
	}
	return zeroResult, trace, finalizeErr
}

func positiveSigned8Depth2TerminalWallTime(value time.Duration) time.Duration {
	if value <= 0 {
		return time.Nanosecond
	}
	return value
}

func appendSigned8Depth2TerminalFinalizeError(current, next error) error {
	if next == nil {
		return current
	}
	if current == nil {
		return next
	}
	return fmt.Errorf("%v; %w", current, next)
}

func (c *Signed8Depth2TerminalLeafCircuit) validate() error {
	if c == nil || c.child == nil || c.childSeal == nil || c.decoder == nil || c.encoder == nil ||
		c.deltaL == nil || c.cross == nil || c.leaf00 == nil || c.deltaX == nil ||
		c.deltaLSeal == nil || c.crossSeal == nil || c.leaf00Seal == nil || c.deltaXSeal == nil {
		return fmt.Errorf("homchain: nil or incomplete terminal leaf circuit")
	}
	if err := c.child.validate(); err != nil {
		return err
	}
	if err := c.decoder.validate(); err != nil {
		return err
	}
	if err := validateSigned8Depth2TerminalParameters(c.params); err != nil {
		return err
	}
	g := c.graph
	if g.circuit != c || g.circuitSeal != c || g.child != c.child || c.childSeal != c.child ||
		g.decoder != c.decoder || g.encoder != c.encoder || g.cacheSources != c.cacheSources ||
		g.cacheSourceSeals != c.cacheSourceSeals || g.deltaL != c.deltaL || g.cross != c.cross ||
		g.leaf00 != c.leaf00 || g.deltaX != c.deltaX || g.deltaLSeal != c.deltaLSeal ||
		g.crossSeal != c.crossSeal || g.leaf00Seal != c.leaf00Seal || g.deltaXSeal != c.deltaXSeal ||
		g.profileDigest != c.profile.digest || g.certificateDigest != c.profile.certificate.digest ||
		c.decoder.child != c.child || !c.params.Equal(&c.child.params) || !c.params.Equal(&c.decoder.params) {
		return fmt.Errorf("homchain: terminal leaf circuit object graph changed")
	}
	currentEncoder, err := c.encoder.RuntimeIdentitySnapshot()
	if err != nil || !g.encoderRuntime.Equal(currentEncoder) {
		return fmt.Errorf("homchain: terminal cache encoder runtime identity changed")
	}
	plaintexts := [4]*rlwe.Plaintext{c.deltaL, c.cross, c.leaf00, c.deltaX}
	seals := [4]*rlwe.Plaintext{c.deltaLSeal, c.crossSeal, c.leaf00Seal, c.deltaXSeal}
	levels := [4]int{8, 8, 7, 7}
	scales := [4]ExactScaleSnapshot{c.profile.scales.delta, c.profile.scales.delta, c.profile.scales.leaf, c.profile.scales.leaf}
	for index := range plaintexts {
		if c.cacheSources[index] == nil || c.cacheSourceSeals[index] == nil ||
			g.cacheSources[index] != c.cacheSources[index] || g.cacheSourceSeals[index] != c.cacheSourceSeals[index] ||
			!equalSigned8Depth2TerminalBigFloat(c.cacheSources[index], c.cacheSourceSeals[index]) ||
			!plaintexts[index].Equal(seals[index]) {
			return fmt.Errorf("homchain: terminal cache source or immutable plaintext %d changed", index)
		}
		if err = requireSigned8Depth2TerminalPlaintextState("cached operand", plaintexts[index], levels[index], scales[index], c.params); err != nil {
			return err
		}
		payload, payloadErr := signed8PlaintextDigest(plaintexts[index])
		if payloadErr != nil || payload != c.profile.cachePayloadDigests[index] {
			return fmt.Errorf("homchain: terminal cached plaintext %d payload changed", index)
		}
	}

	childProfile := c.child.Profile()
	prefixProfile := c.child.prefix.Profile()
	decoderProfile := c.decoder.Profile()
	tree := prefixProfile.Tree()
	leafRats, leafBits, cacheRats, cacheFloats, cacheErrors, err := deriveSigned8Depth2TerminalLeafValues(tree.Leaves)
	if err != nil {
		return err
	}
	wantScales, err := deriveSigned8Depth2TerminalScales(c.params)
	if err != nil {
		return err
	}
	if !equalSigned8Depth2TerminalScales(c.profile.scales, wantScales) {
		return fmt.Errorf("homchain: terminal exact scale schedule changed")
	}
	cacheNames := [4]string{"dL", "cross", "l00", "dX"}
	for index := range cacheFloats {
		if !equalSigned8Depth2TerminalBigFloat(c.cacheSources[index], cacheFloats[index]) ||
			c.profile.cacheSourceDigests[index] != digestSigned8Depth2TerminalCacheSource(cacheNames[index], cacheRats[index], levels[index], scales[index]) {
			return fmt.Errorf("homchain: terminal cache source %d differs from the exact frozen tree", index)
		}
	}
	wantCertificate, err := deriveSigned8Depth2LeafMagnitudeCertificate(
		c.params, childProfile, prefixProfile, leafRats, leafBits, cacheRats, cacheErrors, wantScales,
	)
	if err != nil {
		return err
	}
	if c.profile.certificate.digest != wantCertificate.digest ||
		c.profile.certificate.digest != digestSigned8Depth2LeafCertificate(c.profile.certificate) {
		return fmt.Errorf("homchain: terminal magnitude certificate changed")
	}
	wantCounts := Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications: 2, CiphertextCiphertextMultiplications: 1,
		Relinearizations: 1, Rescales: 3, PlaintextVectorAdditions: 2,
		CiphertextAdditions: 1, LevelDrops: 1,
	}
	wantBytes := signed8Depth2TerminalExpectedBytes()
	wantStates := signed8Depth2TerminalExpectedStates(c.params, wantScales, wantBytes)
	wantKeys := []uint64{5, 17, 25, 33, 41, 49, 63}
	keys := append([]uint64(nil), c.profile.requiredGalois...)
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	if c.profile.fidelity != Signed8Depth2TerminalLeafFunctionalNotSecure ||
		c.profile.parameterDigest != childProfile.ParameterDigest() || c.profile.childProfileDigest != childProfile.Digest() ||
		c.profile.decoderProfileDigest != decoderProfile.Digest() || c.profile.prefixProfileDigest != childProfile.PrefixProfileDigest() ||
		c.profile.protocolRangeDigest != childProfile.ProtocolRangeDigest() || c.profile.treeDigest != childProfile.TreeDigest() ||
		c.profile.scheduleDigest != childProfile.ScheduleDigest() ||
		c.profile.producerPublicDigest != decoderProfile.ProducerPublicProfileDigest() ||
		c.profile.producerOpaqueDigest != decoderProfile.ProducerOpaqueProfileDigest() ||
		c.profile.leaves != leafBits || c.profile.counts != wantCounts || c.profile.expectedBytes != wantBytes ||
		!equalSigned8Depth2TerminalStates(c.profile.expectedStates, wantStates) ||
		!equalSigned8Depth2TerminalUint64Slices(keys, wantKeys) || !c.profile.relinearization ||
		c.profile.levelLedger != signed8Depth2TerminalLeafLevelLedger ||
		c.profile.digest != digestSigned8Depth2TerminalLeafProfile(c.profile) {
		return fmt.Errorf("homchain: terminal leaf profile, graph, operation, state, byte, or key ledger changed")
	}
	return nil
}

func (c *Signed8Depth2TerminalLeafCircuit) validateInput(input Signed8Depth2TerminalLeafInput) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := c.decoder.validateInput(input.decoderInput); err != nil {
		return fmt.Errorf("homchain: terminal decoder input authentication failed: %w", err)
	}
	if input.rootSelector == nil {
		return fmt.Errorf("homchain: terminal root selector is nil")
	}
	if err := requireSigned8Depth2TerminalCiphertextState("root selector", input.rootSelector, 7, c.profile.scales.b0, c.params); err != nil {
		return err
	}
	rootPayload, err := signed8CiphertextDigest(input.rootSelector)
	if err != nil {
		return err
	}
	decoderRootPayload, err := signed8CiphertextDigest(input.decoderInput.childInput.operands.conditionedSelector)
	if err != nil {
		return err
	}
	producer := c.child.prefix.selector.producer.profileForMode(input.operandMode)
	if producer.digest == "" || input.profileDigest != c.profile.digest || input.parameterDigest != c.profile.parameterDigest ||
		input.childProfileDigest != c.profile.childProfileDigest || input.decoderProfileDigest != c.profile.decoderProfileDigest ||
		input.prefixProfileDigest != c.profile.prefixProfileDigest || input.protocolRangeDigest != c.profile.protocolRangeDigest ||
		input.treeDigest != c.profile.treeDigest || input.scheduleDigest != c.profile.scheduleDigest ||
		input.childInputBindingDigest != input.decoderInput.ChildInputBindingDigest() ||
		input.childResultProvenanceDigest != input.decoderInput.ChildResultProvenanceDigest() ||
		input.operandsProvenanceDigest != input.decoderInput.OperandsProvenanceDigest() ||
		input.decoderInputProvenanceDigest != input.decoderInput.ProvenanceDigest() ||
		input.operandMode != input.decoderInput.OperandMode() || input.producerProfileDigest != producer.digest ||
		input.producerProfileDigest != input.decoderInput.ProducerProfileDigest() ||
		input.rootPayloadDigest != rootPayload || rootPayload != decoderRootPayload ||
		input.provenanceDigest != digestSigned8Depth2TerminalLeafInput(input, rootPayload) {
		return fmt.Errorf("homchain: terminal input has foreign child pair, mode, root payload, profile, or provenance")
	}
	return nil
}

func (c *Signed8Depth2TerminalLeafCircuit) validateResult(result Signed8Depth2TerminalLeafResult) error {
	if err := c.validate(); err != nil {
		return err
	}
	if result.output == nil {
		return fmt.Errorf("homchain: nil terminal leaf result")
	}
	if err := requireSigned8Depth2TerminalCiphertextState("result", result.output, 6, c.profile.scales.leaf, c.params); err != nil {
		return err
	}
	payload, err := signed8CiphertextDigest(result.output)
	if err != nil {
		return err
	}
	producer := c.child.prefix.selector.producer.profileForMode(result.operandMode)
	if producer.digest == "" || result.profileDigest != c.profile.digest || result.parameterDigest != c.profile.parameterDigest ||
		result.childProfileDigest != c.profile.childProfileDigest || result.decoderProfileDigest != c.profile.decoderProfileDigest ||
		result.treeDigest != c.profile.treeDigest || result.scheduleDigest != c.profile.scheduleDigest ||
		result.certificateDigest != c.profile.certificate.digest || result.cachePayloadDigests != c.profile.cachePayloadDigests ||
		result.childInputBindingDigest == "" || result.childResultProvenanceDigest == "" ||
		result.operandsProvenanceDigest == "" || result.inputProvenanceDigest == "" ||
		result.decoderResultDigest == "" || result.decoderTraceDigest == "" ||
		result.producerProfileDigest != producer.digest || result.outputPayloadDigest != payload ||
		result.provenanceDigest != digestSigned8Depth2TerminalLeafResult(result, payload) {
		return fmt.Errorf("homchain: terminal result has foreign graph, input, decoder, cache, payload, or provenance")
	}
	return nil
}

func (c *Signed8Depth2TerminalLeafCircuit) validateTrace(
	input Signed8Depth2TerminalLeafInput,
	result Signed8Depth2TerminalLeafResult,
	trace Signed8Depth2TerminalLeafTrace,
) error {
	if err := c.validateInput(input); err != nil {
		return err
	}
	if err := c.validateResult(result); err != nil {
		return err
	}
	decoderResult := trace.decoderResult
	if err := c.decoder.validateResult(decoderResult); err != nil {
		return fmt.Errorf("homchain: terminal nested decoder result changed: %w", err)
	}
	if err := c.decoder.validateTrace(input.decoderInput, decoderResult, trace.decoderTrace); err != nil {
		return fmt.Errorf("homchain: terminal nested decoder trace changed: %w", err)
	}
	wantComposed := Signed8Depth2TerminalLeafComposedOperationCounts{
		ChildDecoder: c.decoder.profile.operationCounts,
		TerminalMux:  c.profile.counts,
	}
	if result.inputProvenanceDigest != input.provenanceDigest ||
		result.childInputBindingDigest != input.childInputBindingDigest ||
		result.childResultProvenanceDigest != input.childResultProvenanceDigest ||
		result.operandsProvenanceDigest != input.operandsProvenanceDigest ||
		result.operandMode != input.operandMode || result.producerProfileDigest != input.producerProfileDigest ||
		result.decoderResultDigest != decoderResult.Digest() || result.decoderTraceDigest != trace.decoderTrace.Digest() ||
		decoderResult.InputProvenanceDigest() != input.decoderInputProvenanceDigest ||
		decoderResult.ChildInputBindingDigest() != input.childInputBindingDigest ||
		decoderResult.ChildResultProvenanceDigest() != input.childResultProvenanceDigest ||
		decoderResult.OperandsProvenanceDigest() != input.operandsProvenanceDigest ||
		decoderResult.OperandMode() != input.operandMode || decoderResult.ProducerProfileDigest() != input.producerProfileDigest ||
		trace.profileDigest != c.profile.digest || trace.inputProvenanceDigest != input.provenanceDigest ||
		trace.childInputBindingDigest != input.childInputBindingDigest ||
		trace.childResultProvenanceDigest != input.childResultProvenanceDigest ||
		trace.operandsProvenanceDigest != input.operandsProvenanceDigest ||
		trace.decoderInputProvenanceDigest != input.decoderInputProvenanceDigest ||
		trace.producerProfileDigest != input.producerProfileDigest || trace.operandMode != input.operandMode ||
		trace.resultProvenanceDigest != result.provenanceDigest || trace.decoderResultDigest != result.decoderResultDigest ||
		trace.decoderTraceDigest != result.decoderTraceDigest || trace.decoderResultDigest != decoderResult.Digest() ||
		trace.decoderTraceDigest != trace.decoderTrace.Digest() || trace.failureStage != "" ||
		trace.counts != c.profile.counts || trace.CompletedComposedOperationCounts() != wantComposed ||
		trace.attemptedOperationLowerBound != wantComposed ||
		!equalSigned8Depth2TerminalStates(trace.states, c.profile.expectedStates) ||
		trace.serializedBytes != c.profile.expectedBytes || !trace.serializedBytes.Complete() ||
		trace.decoderTrace.SerializedBytes().DecodedChildSelector != trace.serializedBytes.DecodedChild ||
		trace.UniqueComposedMeasuredBytes() != 106662 ||
		!equalSigned8Depth2TerminalUint64Slices(trace.runtimeGalois, c.profile.requiredGalois) || !trace.relinearizationMatched ||
		len(trace.retainedCiphertexts) != len(c.profile.expectedStates) ||
		len(trace.retainedPayloadDigests) != len(c.profile.expectedStates) ||
		trace.traceDigest != digestSigned8Depth2TerminalLeafTrace(trace) || trace.wallTime <= 0 {
		return fmt.Errorf("homchain: terminal trace graph, decoder, operation, state, byte, key, or provenance evidence changed")
	}
	if err := c.validateSigned8Depth2TerminalRetainedPrefix(input, trace); err != nil {
		return err
	}
	retainedOutput := trace.retainedCiphertexts[Signed8Depth2TerminalStageOutput]
	if retainedOutput == nil || retainedOutput == result.output || result.output == input.rootSelector ||
		result.output == decoderResult.selector ||
		trace.retainedPayloadDigests[Signed8Depth2TerminalStageOutput] != result.outputPayloadDigest {
		return fmt.Errorf("homchain: terminal retained output is foreign, aliased, or unbound to the result")
	}
	for stage, retained := range trace.retainedCiphertexts {
		if retained == result.output {
			return fmt.Errorf("homchain: terminal result output aliases retained state %s", stage)
		}
	}
	return nil
}

// validateFailureTrace authenticates a terminal partial trace. Decoder
// failures contain only the nested decoder prefix; terminal-local failures
// contain a successful decoder tuple plus an exact prefix of mux boundaries.
func (c *Signed8Depth2TerminalLeafCircuit) validateFailureTrace(
	input Signed8Depth2TerminalLeafInput,
	trace Signed8Depth2TerminalLeafTrace,
) error {
	if err := c.validateInput(input); err != nil {
		return err
	}
	if trace.profileDigest != c.profile.digest || trace.inputProvenanceDigest != input.provenanceDigest ||
		trace.childInputBindingDigest != input.childInputBindingDigest ||
		trace.childResultProvenanceDigest != input.childResultProvenanceDigest ||
		trace.operandsProvenanceDigest != input.operandsProvenanceDigest ||
		trace.decoderInputProvenanceDigest != input.decoderInputProvenanceDigest ||
		trace.producerProfileDigest != input.producerProfileDigest || trace.operandMode != input.operandMode ||
		trace.resultProvenanceDigest != "" || trace.wallTime <= 0 ||
		!equalSigned8Depth2TerminalUint64Slices(trace.runtimeGalois, c.profile.requiredGalois) || !trace.relinearizationMatched ||
		trace.traceDigest == "" || trace.traceDigest != digestSigned8Depth2TerminalLeafTrace(trace) {
		return fmt.Errorf("homchain: terminal partial trace runtime, provenance, or digest seal changed")
	}

	if trace.failureStage == Signed8Depth2TerminalStageDecoderFailure {
		if !reflect.DeepEqual(trace.decoderResult, Signed8Depth2ChildSelectorDecodeResult{}) ||
			trace.decoderResultDigest != "" || trace.decoderTraceDigest == "" ||
			trace.decoderTraceDigest != trace.decoderTrace.Digest() ||
			trace.counts != (Signed8Depth2TerminalLeafOperationCounts{}) ||
			trace.attemptedOperationLowerBound.TerminalMux != (Signed8Depth2TerminalLeafOperationCounts{}) ||
			trace.attemptedOperationLowerBound.ChildDecoder != trace.decoderTrace.AttemptedOperationLowerBound() ||
			trace.CompletedComposedOperationCounts() != (Signed8Depth2TerminalLeafComposedOperationCounts{
				ChildDecoder: trace.decoderTrace.OperationCounts(),
			}) ||
			len(trace.states) != 0 || trace.serializedBytes != (Signed8Depth2TerminalLeafSerializedBytes{}) ||
			len(trace.retainedCiphertexts) != 0 || len(trace.retainedPayloadDigests) != 0 {
			return fmt.Errorf("homchain: terminal decoder-failure composition ledger changed")
		}
		if err := c.decoder.validateFailureTrace(input.decoderInput, trace.decoderTrace); err != nil {
			return fmt.Errorf("homchain: terminal nested decoder partial changed: %w", err)
		}
		if trace.UniqueComposedMeasuredBytes() != trace.decoderTrace.SerializedBytes().ModuleTotal() {
			return fmt.Errorf("homchain: terminal nested decoder partial byte composition changed")
		}
		return nil
	}

	if !validSigned8Depth2TerminalLeafFailureStage(trace.failureStage) {
		return fmt.Errorf("homchain: invalid terminal partial failure stage %q", trace.failureStage)
	}
	if err := c.decoder.validateResult(trace.decoderResult); err != nil {
		return fmt.Errorf("homchain: terminal partial nested decoder result changed: %w", err)
	}
	if err := c.decoder.validateTrace(input.decoderInput, trace.decoderResult, trace.decoderTrace); err != nil {
		return fmt.Errorf("homchain: terminal partial nested decoder trace changed: %w", err)
	}
	if trace.decoderResultDigest != trace.decoderResult.Digest() || trace.decoderTraceDigest != trace.decoderTrace.Digest() ||
		trace.decoderResultDigest == "" || trace.decoderTraceDigest == "" ||
		trace.decoderResult.InputProvenanceDigest() != input.decoderInputProvenanceDigest ||
		trace.decoderResult.ChildInputBindingDigest() != input.childInputBindingDigest ||
		trace.decoderResult.ChildResultProvenanceDigest() != input.childResultProvenanceDigest ||
		trace.decoderResult.OperandsProvenanceDigest() != input.operandsProvenanceDigest ||
		trace.decoderResult.OperandMode() != input.operandMode ||
		trace.decoderResult.ProducerProfileDigest() != input.producerProfileDigest ||
		trace.attemptedOperationLowerBound.ChildDecoder != trace.decoderTrace.AttemptedOperationLowerBound() ||
		!boundedSigned8Depth2TerminalLeafCounts(trace.counts, c.profile.counts) ||
		!boundedSigned8Depth2TerminalLeafCounts(trace.attemptedOperationLowerBound.TerminalMux, c.profile.counts) ||
		!boundedSigned8Depth2TerminalLeafCounts(trace.counts, trace.attemptedOperationLowerBound.TerminalMux) {
		return fmt.Errorf("homchain: terminal partial decoder link or operation lower bound changed")
	}
	if !validSigned8Depth2TerminalLeafProgress(
		trace.failureStage, len(trace.states), trace.counts, trace.attemptedOperationLowerBound.TerminalMux,
	) {
		return fmt.Errorf("homchain: terminal partial failure stage, state prefix, and operation progress disagree")
	}
	wantBytes, err := signed8Depth2TerminalBytesFromStatePrefix(trace.states)
	if err != nil || trace.serializedBytes != wantBytes {
		return fmt.Errorf("homchain: terminal partial state-prefix byte ledger changed: %v", err)
	}
	if err = c.validateSigned8Depth2TerminalRetainedPrefix(input, trace); err != nil {
		return err
	}
	decoderBytes := trace.decoderTrace.SerializedBytes()
	wantUnique := decoderBytes.ModuleTotal() + trace.serializedBytes.TotalBytes()
	if decoderBytes.DecodedChildSelector > 0 && trace.serializedBytes.DecodedChild > 0 {
		if decoderBytes.DecodedChildSelector != trace.serializedBytes.DecodedChild {
			return fmt.Errorf("homchain: terminal shared decoded-child byte boundary changed")
		}
		wantUnique -= trace.serializedBytes.DecodedChild
	}
	if trace.UniqueComposedMeasuredBytes() != wantUnique {
		return fmt.Errorf("homchain: terminal partial unique composed byte ledger changed")
	}
	return nil
}

func validSigned8Depth2TerminalLeafFailureStage(stage Signed8Depth2TerminalLeafStage) bool {
	switch stage {
	case Signed8Depth2TerminalStageDecodedChild, Signed8Depth2TerminalStageRootSelector,
		Signed8Depth2TerminalStageRawA, Signed8Depth2TerminalStageRescaledA,
		Signed8Depth2TerminalStageAffineA, Signed8Depth2TerminalStageRawD,
		Signed8Depth2TerminalStageRescaledD, Signed8Depth2TerminalStageAffineD,
		Signed8Depth2TerminalStageRawY, Signed8Depth2TerminalStageRescaledY,
		Signed8Depth2TerminalStageAlignedA, Signed8Depth2TerminalStageOutput,
		Signed8Depth2TerminalStageAdmission, Signed8Depth2TerminalStagePreflight:
		return true
	default:
		return false
	}
}

func boundedSigned8Depth2TerminalLeafCounts(
	value, bound Signed8Depth2TerminalLeafOperationCounts,
) bool {
	return value.CiphertextPlaintextMultiplications >= 0 && value.CiphertextPlaintextMultiplications <= bound.CiphertextPlaintextMultiplications &&
		value.CiphertextCiphertextMultiplications >= 0 && value.CiphertextCiphertextMultiplications <= bound.CiphertextCiphertextMultiplications &&
		value.Relinearizations >= 0 && value.Relinearizations <= bound.Relinearizations &&
		value.Rescales >= 0 && value.Rescales <= bound.Rescales &&
		value.PlaintextVectorAdditions >= 0 && value.PlaintextVectorAdditions <= bound.PlaintextVectorAdditions &&
		value.CiphertextAdditions >= 0 && value.CiphertextAdditions <= bound.CiphertextAdditions &&
		value.LevelDrops >= 0 && value.LevelDrops <= bound.LevelDrops &&
		value.Rotations >= 0 && value.Rotations <= bound.Rotations
}

type signed8Depth2TerminalLeafOperationProgress struct {
	stage                                Signed8Depth2TerminalLeafStage
	statesBefore                         int
	completedBefore, attemptedOnDispatch Signed8Depth2TerminalLeafOperationCounts
	completedAfter, attemptedAfter       Signed8Depth2TerminalLeafOperationCounts
	dispatchCanReturnError               bool
}

func signed8Depth2TerminalLeafOperationProgressLedger() []signed8Depth2TerminalLeafOperationProgress {
	completed := Signed8Depth2TerminalLeafOperationCounts{}
	appendOperation := func(
		ledger *[]signed8Depth2TerminalLeafOperationProgress,
		stage Signed8Depth2TerminalLeafStage,
		statesBefore int,
		dispatchAttempt, success Signed8Depth2TerminalLeafOperationCounts,
		dispatchCanReturnError bool,
	) {
		before := completed
		dispatch := addSigned8Depth2TerminalLeafCounts(before, dispatchAttempt)
		completed = addSigned8Depth2TerminalLeafCounts(before, success)
		*ledger = append(*ledger, signed8Depth2TerminalLeafOperationProgress{
			stage: stage, statesBefore: statesBefore,
			completedBefore: before, attemptedOnDispatch: dispatch,
			completedAfter: completed, attemptedAfter: completed,
			dispatchCanReturnError: dispatchCanReturnError,
		})
	}
	ledger := make([]signed8Depth2TerminalLeafOperationProgress, 0, 10)
	appendOperation(&ledger, Signed8Depth2TerminalStageRawA, 2,
		Signed8Depth2TerminalLeafOperationCounts{CiphertextPlaintextMultiplications: 1},
		Signed8Depth2TerminalLeafOperationCounts{CiphertextPlaintextMultiplications: 1}, true)
	appendOperation(&ledger, Signed8Depth2TerminalStageRescaledA, 3,
		Signed8Depth2TerminalLeafOperationCounts{Rescales: 1},
		Signed8Depth2TerminalLeafOperationCounts{Rescales: 1}, true)
	appendOperation(&ledger, Signed8Depth2TerminalStageAffineA, 4,
		Signed8Depth2TerminalLeafOperationCounts{PlaintextVectorAdditions: 1},
		Signed8Depth2TerminalLeafOperationCounts{PlaintextVectorAdditions: 1}, true)
	appendOperation(&ledger, Signed8Depth2TerminalStageRawD, 5,
		Signed8Depth2TerminalLeafOperationCounts{CiphertextPlaintextMultiplications: 1},
		Signed8Depth2TerminalLeafOperationCounts{CiphertextPlaintextMultiplications: 1}, true)
	appendOperation(&ledger, Signed8Depth2TerminalStageRescaledD, 6,
		Signed8Depth2TerminalLeafOperationCounts{Rescales: 1},
		Signed8Depth2TerminalLeafOperationCounts{Rescales: 1}, true)
	appendOperation(&ledger, Signed8Depth2TerminalStageAffineD, 7,
		Signed8Depth2TerminalLeafOperationCounts{PlaintextVectorAdditions: 1},
		Signed8Depth2TerminalLeafOperationCounts{PlaintextVectorAdditions: 1}, true)
	appendOperation(&ledger, Signed8Depth2TerminalStageRawY, 8,
		Signed8Depth2TerminalLeafOperationCounts{CiphertextCiphertextMultiplications: 1},
		Signed8Depth2TerminalLeafOperationCounts{
			CiphertextCiphertextMultiplications: 1, Relinearizations: 1,
		}, true)
	appendOperation(&ledger, Signed8Depth2TerminalStageRescaledY, 9,
		Signed8Depth2TerminalLeafOperationCounts{Rescales: 1},
		Signed8Depth2TerminalLeafOperationCounts{Rescales: 1}, true)
	appendOperation(&ledger, Signed8Depth2TerminalStageAlignedA, 10,
		Signed8Depth2TerminalLeafOperationCounts{LevelDrops: 1},
		Signed8Depth2TerminalLeafOperationCounts{LevelDrops: 1}, false)
	appendOperation(&ledger, Signed8Depth2TerminalStageOutput, 11,
		Signed8Depth2TerminalLeafOperationCounts{CiphertextAdditions: 1},
		Signed8Depth2TerminalLeafOperationCounts{CiphertextAdditions: 1}, true)
	return ledger
}

func addSigned8Depth2TerminalLeafCounts(
	left, right Signed8Depth2TerminalLeafOperationCounts,
) Signed8Depth2TerminalLeafOperationCounts {
	return Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications:  left.CiphertextPlaintextMultiplications + right.CiphertextPlaintextMultiplications,
		CiphertextCiphertextMultiplications: left.CiphertextCiphertextMultiplications + right.CiphertextCiphertextMultiplications,
		Relinearizations:                    left.Relinearizations + right.Relinearizations,
		Rescales:                            left.Rescales + right.Rescales,
		PlaintextVectorAdditions:            left.PlaintextVectorAdditions + right.PlaintextVectorAdditions,
		CiphertextAdditions:                 left.CiphertextAdditions + right.CiphertextAdditions,
		LevelDrops:                          left.LevelDrops + right.LevelDrops,
		Rotations:                           left.Rotations + right.Rotations,
	}
}

func validSigned8Depth2TerminalLeafProgress(
	stage Signed8Depth2TerminalLeafStage,
	stateCount int,
	completed, attempted Signed8Depth2TerminalLeafOperationCounts,
) bool {
	zero := Signed8Depth2TerminalLeafOperationCounts{}
	full := Signed8Depth2TerminalLeafOperationCounts{
		CiphertextPlaintextMultiplications: 2, CiphertextCiphertextMultiplications: 1,
		Relinearizations: 1, Rescales: 3, PlaintextVectorAdditions: 2,
		CiphertextAdditions: 1, LevelDrops: 1,
	}
	switch stage {
	case Signed8Depth2TerminalStageDecodedChild, Signed8Depth2TerminalStageRootSelector:
		return stateCount == 0 && completed == zero && attempted == zero
	case Signed8Depth2TerminalStageAdmission:
		return (stateCount == 0 && completed == zero && attempted == zero) ||
			(stateCount == 12 && completed == full && attempted == full)
	case Signed8Depth2TerminalStagePreflight:
		return stateCount == 12 && completed == full && attempted == full
	}
	for _, progress := range signed8Depth2TerminalLeafOperationProgressLedger() {
		if progress.stage != stage {
			continue
		}
		if progress.dispatchCanReturnError && stateCount == progress.statesBefore &&
			completed == progress.completedBefore && attempted == progress.attemptedOnDispatch {
			return true
		}
		return completed == progress.completedAfter && attempted == progress.attemptedAfter &&
			(stateCount == progress.statesBefore || stateCount == progress.statesBefore+1)
	}
	return false
}

func (c *Signed8Depth2TerminalLeafCircuit) validateSigned8Depth2TerminalRetainedPrefix(
	input Signed8Depth2TerminalLeafInput,
	trace Signed8Depth2TerminalLeafTrace,
) error {
	if len(trace.states) > len(c.profile.expectedStates) ||
		!equalSigned8Depth2TerminalStates(trace.states, c.profile.expectedStates[:len(trace.states)]) ||
		len(trace.retainedCiphertexts) != len(trace.states) ||
		len(trace.retainedPayloadDigests) != len(trace.states) {
		return fmt.Errorf("homchain: terminal partial retained-state prefix changed")
	}
	seen := make(map[*rlwe.Ciphertext]Signed8Depth2TerminalLeafStage, len(trace.states))
	for _, state := range trace.states {
		retained := trace.retainedCiphertexts[state.Stage]
		if retained == nil {
			return fmt.Errorf("homchain: terminal partial omitted retained state %s", state.Stage)
		}
		if previous, exists := seen[retained]; exists {
			return fmt.Errorf("homchain: terminal partial retained state %s aliases %s", state.Stage, previous)
		}
		seen[retained] = state.Stage
		if retained == trace.decoderResult.selector || retained == input.rootSelector {
			return fmt.Errorf("homchain: terminal partial retained state %s aliases admitted evidence", state.Stage)
		}
		if err := requireSigned8Depth2TerminalCiphertextState(string(state.Stage), retained, state.Level, state.Scale, c.params); err != nil {
			return err
		}
		measured, measureErr := marshalCiphertextSize("terminal partial retained "+string(state.Stage), retained)
		payload, payloadErr := signed8CiphertextDigest(retained)
		if measureErr != nil || measured != state.SerializedBytes || payloadErr != nil ||
			payload != trace.retainedPayloadDigests[state.Stage] {
			return fmt.Errorf("homchain: terminal partial retained state %s payload or bytes changed", state.Stage)
		}
		if state.Stage == Signed8Depth2TerminalStageDecodedChild && payload != trace.decoderResult.OutputPayloadDigest() {
			return fmt.Errorf("homchain: terminal partial decoded-child boundary differs from decoder result")
		}
		if state.Stage == Signed8Depth2TerminalStageRootSelector && payload != input.rootPayloadDigest {
			return fmt.Errorf("homchain: terminal partial root boundary differs from admitted selector")
		}
	}
	return nil
}

func appendSigned8Depth2TerminalState(
	trace *Signed8Depth2TerminalLeafTrace,
	stage Signed8Depth2TerminalLeafStage,
	ciphertext *rlwe.Ciphertext,
) error {
	if trace == nil || ciphertext == nil || ciphertext.MetaData == nil {
		return fmt.Errorf("homchain: cannot snapshot terminal state %s", stage)
	}
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return err
	}
	serialized, err := marshalCiphertextSize("terminal "+string(stage), ciphertext)
	if err != nil {
		return err
	}
	trace.states = append(trace.states, Signed8Depth2TerminalLeafState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale, SerializedBytes: serialized,
	})
	if trace.retainedCiphertexts == nil {
		trace.retainedCiphertexts = make(map[Signed8Depth2TerminalLeafStage]*rlwe.Ciphertext)
	}
	if trace.retainedPayloadDigests == nil {
		trace.retainedPayloadDigests = make(map[Signed8Depth2TerminalLeafStage]string)
	}
	trace.retainedCiphertexts[stage] = copyA2BRefreshCiphertext(ciphertext)
	payload, err := signed8CiphertextDigest(ciphertext)
	if err != nil {
		return err
	}
	trace.retainedPayloadDigests[stage] = payload
	return nil
}

func signed8Depth2TerminalBytesFromStates(states []Signed8Depth2TerminalLeafState) (Signed8Depth2TerminalLeafSerializedBytes, error) {
	if len(states) != 12 {
		return Signed8Depth2TerminalLeafSerializedBytes{}, fmt.Errorf("homchain: terminal runtime states=%d, want 12", len(states))
	}
	return signed8Depth2TerminalBytesFromStatePrefix(states)
}

func signed8Depth2TerminalBytesFromStatePrefix(
	states []Signed8Depth2TerminalLeafState,
) (Signed8Depth2TerminalLeafSerializedBytes, error) {
	var result Signed8Depth2TerminalLeafSerializedBytes
	stages := [...]Signed8Depth2TerminalLeafStage{
		Signed8Depth2TerminalStageDecodedChild, Signed8Depth2TerminalStageRootSelector,
		Signed8Depth2TerminalStageRawA, Signed8Depth2TerminalStageRescaledA, Signed8Depth2TerminalStageAffineA,
		Signed8Depth2TerminalStageRawD, Signed8Depth2TerminalStageRescaledD, Signed8Depth2TerminalStageAffineD,
		Signed8Depth2TerminalStageRawY, Signed8Depth2TerminalStageRescaledY,
		Signed8Depth2TerminalStageAlignedA, Signed8Depth2TerminalStageOutput,
	}
	if len(states) > len(stages) {
		return result, fmt.Errorf("homchain: terminal runtime state prefix=%d, want at most %d", len(states), len(stages))
	}
	for index, state := range states {
		if state.Stage != stages[index] || state.SerializedBytes <= 0 {
			return result, fmt.Errorf("homchain: terminal runtime state prefix %d is %s/%d", index, state.Stage, state.SerializedBytes)
		}
		switch index {
		case 0:
			result.DecodedChild = state.SerializedBytes
		case 1:
			result.RootSelector = state.SerializedBytes
		case 2:
			result.RawA = state.SerializedBytes
		case 3:
			result.RescaledA = state.SerializedBytes
		case 4:
			result.AffineA = state.SerializedBytes
		case 5:
			result.RawD = state.SerializedBytes
		case 6:
			result.RescaledD = state.SerializedBytes
		case 7:
			result.AffineD = state.SerializedBytes
		case 8:
			result.RawY = state.SerializedBytes
		case 9:
			result.RescaledY = state.SerializedBytes
		case 10:
			result.AlignedA = state.SerializedBytes
		case 11:
			result.Output = state.SerializedBytes
		}
	}
	return result, nil
}

func cloneSigned8Depth2TerminalLeafResult(result Signed8Depth2TerminalLeafResult) Signed8Depth2TerminalLeafResult {
	result.output = copyA2BRefreshCiphertext(result.output)
	return result
}

func cloneSigned8Depth2TerminalLeafInput(input Signed8Depth2TerminalLeafInput) Signed8Depth2TerminalLeafInput {
	input.decoderInput = cloneSigned8Depth2ChildSelectorDecodeInput(input.decoderInput)
	input.rootSelector = copyA2BRefreshCiphertext(input.rootSelector)
	return input
}

func cloneSigned8Depth2TerminalLeafTrace(trace Signed8Depth2TerminalLeafTrace) Signed8Depth2TerminalLeafTrace {
	trace.decoderTrace = cloneSigned8Depth2ChildSelectorDecodeTrace(trace.decoderTrace)
	trace.decoderResult = cloneSigned8Depth2ChildSelectorDecodeResult(trace.decoderResult)
	trace.states = append([]Signed8Depth2TerminalLeafState(nil), trace.states...)
	trace.runtimeGalois = append([]uint64(nil), trace.runtimeGalois...)
	retained := make(map[Signed8Depth2TerminalLeafStage]*rlwe.Ciphertext, len(trace.retainedCiphertexts))
	for stage, ciphertext := range trace.retainedCiphertexts {
		retained[stage] = copyA2BRefreshCiphertext(ciphertext)
	}
	trace.retainedCiphertexts = retained
	payloads := make(map[Signed8Depth2TerminalLeafStage]string, len(trace.retainedPayloadDigests))
	for stage, payload := range trace.retainedPayloadDigests {
		payloads[stage] = payload
	}
	trace.retainedPayloadDigests = payloads
	return trace
}

func requireSigned8Depth2TerminalPlaintextState(
	name string,
	plaintext *rlwe.Plaintext,
	level int,
	scale ExactScaleSnapshot,
	params ckks.Parameters,
) error {
	if plaintext == nil || plaintext.MetaData == nil || plaintext.Level() != level || plaintext.Degree() != 0 ||
		plaintext.LogN() != params.LogN() || plaintext.LogDimensions != params.LogMaxDimensions() ||
		plaintext.Slots() != signed8Slots || !plaintext.IsBatched || !plaintext.IsNTT || !scale.EqualScale(plaintext.Scale) {
		return fmt.Errorf("homchain: terminal %s is not exact L%d/degree0/full-dense/NTT at the sealed scale", name, level)
	}
	return nil
}

func requireSigned8Depth2TerminalCiphertextState(
	name string,
	ciphertext *rlwe.Ciphertext,
	level int,
	scale ExactScaleSnapshot,
	params ckks.Parameters,
) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level || ciphertext.Degree() != 1 ||
		ciphertext.LogN() != params.LogN() || ciphertext.LogDimensions != params.LogMaxDimensions() ||
		ciphertext.Slots() != signed8Slots || !ciphertext.IsBatched || !ciphertext.IsNTT || !scale.EqualScale(ciphertext.Scale) {
		return fmt.Errorf("homchain: terminal %s is not exact L%d/degree1/full-dense/NTT at the sealed scale", name, level)
	}
	return nil
}

func equalSigned8Depth2TerminalScales(left, right signed8Depth2TerminalScales) bool {
	return left.b1.Equal(right.b1) && left.b0.Equal(right.b0) && left.delta.Equal(right.delta) &&
		left.leaf.Equal(right.leaf) && left.rawA.Equal(right.rawA) && left.rawY.Equal(right.rawY)
}

func equalSigned8Depth2TerminalStates(left, right []Signed8Depth2TerminalLeafState) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Stage != right[index].Stage || left[index].Level != right[index].Level ||
			left[index].Degree != right[index].Degree || left[index].LogDimensions != right[index].LogDimensions ||
			!left[index].Scale.Equal(right[index].Scale) || left[index].SerializedBytes != right[index].SerializedBytes {
			return false
		}
	}
	return true
}

func equalSigned8Depth2TerminalBigFloat(left, right *big.Float) bool {
	return left != nil && right != nil && left.Prec() == right.Prec() && left.Mode() == right.Mode() &&
		left.Text('x', -1) == right.Text('x', -1)
}

func validateSigned8Depth2TerminalParameters(params ckks.Parameters) error {
	if params.LogN() != 5 || params.MaxSlots() != signed8Slots || params.LogDefaultScale() != 35 ||
		len(params.Q()) != 21 || len(params.P()) != 1 {
		return fmt.Errorf("homchain: terminal leaf requires LogN=5, 16 slots, 21 Q primes, one P prime and LogDefaultScale=35")
	}
	logQ := params.LogQi()
	if len(logQ) != 21 || logQ[0] != 50 {
		return fmt.Errorf("homchain: terminal leaf Q chain is not [50,35x20]")
	}
	for index := 1; index < len(logQ); index++ {
		if logQ[index] != 35 {
			return fmt.Errorf("homchain: terminal leaf Q[%d] has %d bits, want 35", index, logQ[index])
		}
	}
	if logP := params.LogPi(); len(logP) != 1 || logP[0] != 50 {
		return fmt.Errorf("homchain: terminal leaf P chain is not [50]")
	}
	return nil
}

func deriveSigned8Depth2TerminalScales(params ckks.Parameters) (signed8Depth2TerminalScales, error) {
	if err := validateSigned8Depth2TerminalParameters(params); err != nil {
		return signed8Depth2TerminalScales{}, err
	}
	scaleS := params.DefaultScale()
	squared := scaleS.Mul(scaleS)
	scaleR := squared.Mul(squared).Div(
		rlwe.NewScale(params.Q()[11]).Mul(rlwe.NewScale(params.Q()[11])).Mul(rlwe.NewScale(params.Q()[10])),
	)
	scaleB := rlwe.NewScale(params.Q()[8]).Mul(scaleS).Div(scaleR)
	rawA := scaleR.Mul(scaleB)
	rawY := rlwe.NewScale(params.Q()[7]).Mul(scaleS)
	if !b2aExactScaleEqual(rawA, rlwe.NewScale(params.Q()[8]).Mul(scaleS)) {
		return signed8Depth2TerminalScales{}, fmt.Errorf("homchain: terminal exact b1/cache scale algebra changed")
	}
	values := []rlwe.Scale{scaleR, rlwe.NewScale(params.Q()[7]), scaleB, scaleS, rawA, rawY}
	var snapshots [6]ExactScaleSnapshot
	var err error
	for index := range values {
		if snapshots[index], err = NewExactScaleSnapshot(values[index]); err != nil {
			return signed8Depth2TerminalScales{}, err
		}
	}
	return signed8Depth2TerminalScales{
		b1: snapshots[0], b0: snapshots[1], delta: snapshots[2],
		leaf: snapshots[3], rawA: snapshots[4], rawY: snapshots[5],
	}, nil
}

func deriveSigned8Depth2TerminalLeafValues(leaves []float64) (
	leafRats [4]*big.Rat,
	leafBits [4]uint64,
	cacheRats [4]*big.Rat,
	cacheFloats [4]*big.Float,
	cacheErrors [4]*big.Rat,
	err error,
) {
	if len(leaves) != 4 {
		err = fmt.Errorf("homchain: terminal leaf certificate requires four leaves")
		return
	}
	capRat := new(big.Rat).SetInt64(signed8Depth2LeafMaxAbs)
	for index, value := range leaves {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			err = fmt.Errorf("homchain: terminal leaf %d is not finite", index)
			return
		}
		leafBits[index] = math.Float64bits(value)
		leafRats[index] = new(big.Rat).SetFloat64(value)
		if leafRats[index] == nil || absSigned8Depth2Rat(leafRats[index]).Cmp(capRat) > 0 {
			err = fmt.Errorf("homchain: terminal leaf %d magnitude exceeds 2^16", index)
			return
		}
	}
	dL := new(big.Rat).Sub(leafRats[1], leafRats[0])
	dR := new(big.Rat).Sub(leafRats[3], leafRats[2])
	dX := new(big.Rat).Sub(leafRats[2], leafRats[0])
	cross := new(big.Rat).Sub(dR, dL)
	cacheRats = [4]*big.Rat{dL, cross, new(big.Rat).Set(leafRats[0]), dX}
	for index, exact := range cacheRats {
		rounded := new(big.Float).SetPrec(signed8Depth2LeafCertificatePrecision).SetMode(big.ToNearestEven).SetRat(exact)
		if rounded.IsInf() {
			err = fmt.Errorf("homchain: terminal cache %d overflowed 256-bit rounding", index)
			return
		}
		var actual *big.Rat
		var accuracy big.Accuracy
		if actual, accuracy = rounded.Rat(nil); actual == nil || accuracy != big.Exact {
			err = fmt.Errorf("homchain: terminal cache %d has an inexact big.Float-to-rational snapshot", index)
			return
		}
		cacheFloats[index] = new(big.Float).Copy(rounded)
		cacheRats[index] = new(big.Rat).Set(actual)
		cacheErrors[index] = absSigned8Depth2Rat(new(big.Rat).Sub(exact, actual))
	}
	return
}

func deriveSigned8Depth2LeafMagnitudeCertificate(
	params ckks.Parameters,
	childProfile Signed8Depth2ChildComparatorProfile,
	prefixProfile Signed8Depth2SourcePrefixProfile,
	leaves [4]*big.Rat,
	leafBits [4]uint64,
	cacheRats [4]*big.Rat,
	cacheErrors [4]*big.Rat,
	scales signed8Depth2TerminalScales,
) (Signed8Depth2LeafMagnitudeCertificate, error) {
	for index := range leaves {
		if leaves[index] == nil || cacheRats[index] == nil || cacheErrors[index] == nil || cacheErrors[index].Sign() < 0 {
			return Signed8Depth2LeafMagnitudeCertificate{}, fmt.Errorf("homchain: terminal magnitude inputs are incomplete")
		}
	}
	eps := new(big.Rat).SetFrac64(signed8Depth2SelectorAbsErrorNumerator, signed8Depth2SelectorAbsErrorDenominator)
	eta := new(big.Rat).SetFrac64(signed8Depth2ArithmeticSlackNumerator, signed8Depth2ArithmeticSlackDenominator)
	beta := new(big.Rat).Add(new(big.Rat).SetInt64(1), eps)
	dL := new(big.Rat).Sub(leaves[1], leaves[0])
	dR := new(big.Rat).Sub(leaves[3], leaves[2])
	dX := new(big.Rat).Sub(leaves[2], leaves[0])
	cross := new(big.Rat).Sub(dR, dL)
	absLeaves := [4]*big.Rat{}
	absLeafMax := new(big.Rat)
	for index := range leaves {
		absLeaves[index] = absSigned8Depth2Rat(leaves[index])
		if absLeaves[index].Cmp(absLeafMax) > 0 {
			absLeafMax.Set(absLeaves[index])
		}
	}
	absDL, absDR := absSigned8Depth2Rat(dL), absSigned8Depth2Rat(dR)
	absDX, absCross := absSigned8Depth2Rat(dX), absSigned8Depth2Rat(cross)

	cacheAbs := [4]*big.Rat{}
	for index := range cacheRats {
		cacheAbs[index] = absSigned8Depth2Rat(cacheRats[index])
	}
	boundRawA := new(big.Rat).Mul(beta, cacheAbs[0])
	boundA := new(big.Rat).Add(cacheAbs[2], boundRawA)
	boundRawD := new(big.Rat).Mul(beta, cacheAbs[1])
	boundD := new(big.Rat).Add(cacheAbs[3], boundRawD)
	boundRawY := new(big.Rat).Mul(beta, boundD)
	boundZ := new(big.Rat).Set(boundRawY)
	boundA6 := new(big.Rat).Set(boundA)
	boundY := new(big.Rat).Add(boundA6, boundZ)
	intermediateCap := new(big.Rat).SetInt64(signed8Depth2IntermediateMaxAbs)
	for name, value := range map[string]*big.Rat{
		"rawA": boundRawA, "A": boundA, "rawD": boundRawD, "D": boundD,
		"rawY": boundRawY, "z": boundZ, "A6": boundA6, "y": boundY,
	} {
		if value.Sign() < 0 || value.Cmp(intermediateCap) > 0 {
			return Signed8Depth2LeafMagnitudeCertificate{}, fmt.Errorf("homchain: terminal %s bound exceeds 2^20", name)
		}
	}

	cacheTolerance := new(big.Rat).Set(cacheErrors[2])
	cacheTolerance.Add(cacheTolerance, new(big.Rat).Mul(beta, cacheErrors[0]))
	cacheTolerance.Add(cacheTolerance, new(big.Rat).Mul(beta, cacheErrors[3]))
	cacheTolerance.Add(cacheTolerance, new(big.Rat).Mul(new(big.Rat).Mul(beta, beta), cacheErrors[1]))
	tolerance := new(big.Rat).Mul(eps, new(big.Rat).Add(
		new(big.Rat).Add(absDL, absDX), new(big.Rat).Mul(new(big.Rat).SetInt64(2), absCross),
	))
	tolerance.Add(tolerance, new(big.Rat).Mul(new(big.Rat).Mul(eps, eps), absCross))
	etaSum := new(big.Rat).SetInt64(1)
	for _, value := range []*big.Rat{absLeaves[0], absDL, absDR, absDX, absCross} {
		etaSum.Add(etaSum, value)
	}
	tolerance.Add(tolerance, new(big.Rat).Mul(eta, etaSum))
	tolerance.Add(tolerance, cacheTolerance)

	snapshot := func(value *big.Rat) (Signed8Depth2ExactRationalSnapshot, error) {
		return newSigned8Depth2ExactRationalSnapshot(value)
	}
	var ledger Signed8Depth2LeafMagnitudeLedger
	var err error
	for index := range leaves {
		if ledger.leaves[index], err = snapshot(leaves[index]); err != nil {
			return Signed8Depth2LeafMagnitudeCertificate{}, err
		}
	}
	assignments := []struct {
		destination *Signed8Depth2ExactRationalSnapshot
		value       *big.Rat
	}{
		{&ledger.absLeafMax, absLeafMax}, {&ledger.absDL, absDL}, {&ledger.absDR, absDR},
		{&ledger.absDX, absDX}, {&ledger.absCross, absCross},
		{&ledger.boundRawA, boundRawA}, {&ledger.boundA, boundA},
		{&ledger.boundRawD, boundRawD}, {&ledger.boundD, boundD},
		{&ledger.boundRawY, boundRawY}, {&ledger.boundZ, boundZ},
		{&ledger.boundA6, boundA6}, {&ledger.boundY, boundY},
		{&ledger.cacheErrorL00, cacheErrors[2]}, {&ledger.cacheErrorDL, cacheErrors[0]},
		{&ledger.cacheErrorDX, cacheErrors[3]}, {&ledger.cacheErrorCross, cacheErrors[1]},
		{&ledger.cacheErrorTolerance, cacheTolerance},
	}
	for _, assignment := range assignments {
		if *assignment.destination, err = snapshot(assignment.value); err != nil {
			return Signed8Depth2LeafMagnitudeCertificate{}, err
		}
	}

	stateSpecs := []struct {
		name  string
		level int
		scale ExactScaleSnapshot
		bound *big.Rat
	}{
		{"b1", 8, scales.b1, beta}, {"b0", 7, scales.b0, beta},
		{"PT(dL)", 8, scales.delta, cacheAbs[0]}, {"PT(cross)", 8, scales.delta, cacheAbs[1]},
		{"PT(l00)", 7, scales.leaf, cacheAbs[2]}, {"PT(dX)", 7, scales.leaf, cacheAbs[3]},
		{"rawA", 8, scales.rawA, boundRawA}, {"a", 7, scales.leaf, boundRawA},
		{"A", 7, scales.leaf, boundA}, {"rawD", 8, scales.rawA, boundRawD},
		{"d", 7, scales.leaf, boundRawD}, {"D", 7, scales.leaf, boundD},
		{"rawY", 7, scales.rawY, boundRawY}, {"z", 6, scales.leaf, boundZ},
		{"A6", 6, scales.leaf, boundA6}, {"y", 6, scales.leaf, boundY},
	}
	states := make([]Signed8Depth2LeafHeadroomState, len(stateSpecs))
	for index, spec := range stateSpecs {
		boundSnapshot, snapshotErr := snapshot(spec.bound)
		if snapshotErr != nil {
			return Signed8Depth2LeafMagnitudeCertificate{}, snapshotErr
		}
		bits, bitsErr := signed8Depth2FloorIdealHeadroomBits(params, spec.level, spec.scale, spec.bound)
		if bitsErr != nil {
			return Signed8Depth2LeafMagnitudeCertificate{}, fmt.Errorf("homchain: terminal headroom %s: %w", spec.name, bitsErr)
		}
		if bits < signed8Depth2MinimumIdealCenteredHeadroomBits {
			return Signed8Depth2LeafMagnitudeCertificate{}, fmt.Errorf("homchain: terminal headroom %s=%d is below 192", spec.name, bits)
		}
		states[index] = Signed8Depth2LeafHeadroomState{
			name: spec.name, level: spec.level, scale: spec.scale, bound: boundSnapshot,
			floorIdealCenteredHeadroomBits: bits,
		}
	}
	selectorSnapshot, _ := snapshot(eps)
	betaSnapshot, _ := snapshot(beta)
	etaSnapshot, _ := snapshot(eta)
	toleranceSnapshot, _ := snapshot(tolerance)
	certificate := Signed8Depth2LeafMagnitudeCertificate{
		schema:          signed8Depth2LeafCertificateSchema,
		parameterDigest: childProfile.ParameterDigest(), treeDigest: childProfile.TreeDigest(),
		scheduleDigest:      childProfile.ScheduleDigest(),
		cacheRoundingPolicy: signed8Depth2CacheRoundingPolicy,
		idealHeadroomPolicy: signed8Depth2IdealHeadroomPolicy,
		leafBits:            leafBits, ledger: ledger, states: states,
		selectorAbsError: selectorSnapshot, rootSelectorMagnitudeBound: betaSnapshot,
		childSelectorMagnitudeBound: betaSnapshot, arithmeticSlack: etaSnapshot,
		outputTolerance: toleranceSnapshot,
	}
	if prefixProfile.TreeDigest() != certificate.treeDigest || prefixProfile.ScheduleDigest() != certificate.scheduleDigest ||
		prefixProfile.ParameterDigest() != certificate.parameterDigest {
		return Signed8Depth2LeafMagnitudeCertificate{}, fmt.Errorf("homchain: terminal certificate source profile mismatch")
	}
	certificate.digest = digestSigned8Depth2LeafCertificate(certificate)
	return certificate, nil
}

func signed8Depth2FloorIdealHeadroomBits(
	params ckks.Parameters,
	level int,
	scaleSnapshot ExactScaleSnapshot,
	bound *big.Rat,
) (uint, error) {
	if level < 0 || level > params.MaxLevel() || bound == nil || bound.Sign() < 0 {
		return 0, fmt.Errorf("invalid level or message bound")
	}
	if bound.Sign() == 0 {
		return ^uint(0), nil
	}
	scale, err := scaleSnapshot.Scale()
	if err != nil {
		return 0, err
	}
	scaleRat, accuracy := scale.Value.Rat(nil)
	if scaleRat == nil || accuracy != big.Exact || scaleRat.Sign() <= 0 {
		return 0, fmt.Errorf("scale is not an exact positive rational")
	}
	base := new(big.Rat).Mul(bound, scaleRat)
	base.Mul(base, new(big.Rat).SetInt64(2*signed8Slots))
	modulus := new(big.Int).SetInt64(1)
	for index := 0; index <= level; index++ {
		modulus.Mul(modulus, new(big.Int).SetUint64(params.Q()[index]))
	}
	leftNumerator := new(big.Int).Set(base.Num())
	right := new(big.Int).Mul(modulus, base.Denom())
	if leftNumerator.Cmp(right) >= 0 {
		return 0, fmt.Errorf("message already exceeds centered modulus")
	}
	bits := uint(0)
	for {
		candidate := new(big.Int).Lsh(new(big.Int).Set(leftNumerator), bits+1)
		if candidate.Cmp(right) >= 0 {
			return bits, nil
		}
		bits++
	}
}

func encodeSigned8Depth2TerminalCache(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	value *big.Float,
	level int,
	scale ExactScaleSnapshot,
) (*rlwe.Plaintext, error) {
	if encoder == nil || value == nil || value.Prec() != signed8Depth2LeafCertificatePrecision || value.Mode() != big.ToNearestEven {
		return nil, fmt.Errorf("terminal cache source is not the sealed 256-bit nearest-even value")
	}
	actualScale, err := scale.Scale()
	if err != nil {
		return nil, err
	}
	plaintext := ckks.NewPlaintext(params, level)
	plaintext.LogDimensions = params.LogMaxDimensions()
	plaintext.Scale = actualScale
	values := make([]*big.Float, signed8Slots)
	for index := range values {
		values[index] = new(big.Float).Copy(value)
	}
	if err = encoder.Encode(values, plaintext); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func signed8Depth2TerminalExpectedBytes() Signed8Depth2TerminalLeafSerializedBytes {
	return Signed8Depth2TerminalLeafSerializedBytes{
		DecodedChild: signed8Depth2TerminalDecodedChildBytes, RootSelector: signed8Depth2TerminalRootSelectorBytes,
		RawA: signed8Depth2TerminalLevel8Bytes, RescaledA: signed8Depth2TerminalLevel7Bytes, AffineA: signed8Depth2TerminalLevel7Bytes,
		RawD: signed8Depth2TerminalLevel8Bytes, RescaledD: signed8Depth2TerminalLevel7Bytes, AffineD: signed8Depth2TerminalLevel7Bytes,
		RawY: signed8Depth2TerminalLevel7Bytes, RescaledY: signed8Depth2TerminalLevel6Bytes,
		AlignedA: signed8Depth2TerminalLevel6Bytes, Output: signed8Depth2TerminalLevel6Bytes,
	}
}

func signed8Depth2TerminalExpectedStates(
	params ckks.Parameters,
	scales signed8Depth2TerminalScales,
	bytes Signed8Depth2TerminalLeafSerializedBytes,
) []Signed8Depth2TerminalLeafState {
	state := func(stage Signed8Depth2TerminalLeafStage, level int, scale ExactScaleSnapshot, size int) Signed8Depth2TerminalLeafState {
		return Signed8Depth2TerminalLeafState{Stage: stage, Level: level, Degree: 1, LogDimensions: params.LogMaxDimensions(), Scale: scale, SerializedBytes: size}
	}
	return []Signed8Depth2TerminalLeafState{
		state(Signed8Depth2TerminalStageDecodedChild, 8, scales.b1, bytes.DecodedChild),
		state(Signed8Depth2TerminalStageRootSelector, 7, scales.b0, bytes.RootSelector),
		state(Signed8Depth2TerminalStageRawA, 8, scales.rawA, bytes.RawA),
		state(Signed8Depth2TerminalStageRescaledA, 7, scales.leaf, bytes.RescaledA),
		state(Signed8Depth2TerminalStageAffineA, 7, scales.leaf, bytes.AffineA),
		state(Signed8Depth2TerminalStageRawD, 8, scales.rawA, bytes.RawD),
		state(Signed8Depth2TerminalStageRescaledD, 7, scales.leaf, bytes.RescaledD),
		state(Signed8Depth2TerminalStageAffineD, 7, scales.leaf, bytes.AffineD),
		state(Signed8Depth2TerminalStageRawY, 7, scales.rawY, bytes.RawY),
		state(Signed8Depth2TerminalStageRescaledY, 6, scales.leaf, bytes.RescaledY),
		state(Signed8Depth2TerminalStageAlignedA, 6, scales.leaf, bytes.AlignedA),
		state(Signed8Depth2TerminalStageOutput, 6, scales.leaf, bytes.Output),
	}
}

func absSigned8Depth2Rat(value *big.Rat) *big.Rat {
	if value == nil {
		return nil
	}
	return new(big.Rat).Abs(value)
}

func cloneSigned8Depth2LeafCertificate(value Signed8Depth2LeafMagnitudeCertificate) Signed8Depth2LeafMagnitudeCertificate {
	value.states = append([]Signed8Depth2LeafHeadroomState(nil), value.states...)
	return value
}

func cloneSigned8Depth2TerminalLeafProfile(value Signed8Depth2TerminalLeafProfile) Signed8Depth2TerminalLeafProfile {
	value.certificate = cloneSigned8Depth2LeafCertificate(value.certificate)
	value.requiredGalois = append([]uint64(nil), value.requiredGalois...)
	value.expectedStates = append([]Signed8Depth2TerminalLeafState(nil), value.expectedStates...)
	return value
}

func equalSigned8Depth2TerminalUint64Slices(left, right []uint64) bool {
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

func digestSigned8Depth2LeafCertificate(certificate Signed8Depth2LeafMagnitudeCertificate) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s|params=%s|tree=%s|schedule=%s|rounding=%s|headroom=%s|bits=%x|eps=%s|beta0=%s|beta1=%s|eta=%s|tol=%s",
		certificate.schema, certificate.parameterDigest, certificate.treeDigest, certificate.scheduleDigest,
		certificate.cacheRoundingPolicy, certificate.idealHeadroomPolicy, certificate.leafBits,
		certificate.selectorAbsError.RatString(), certificate.rootSelectorMagnitudeBound.RatString(),
		certificate.childSelectorMagnitudeBound.RatString(), certificate.arithmeticSlack.RatString(),
		certificate.outputTolerance.RatString())
	ledgerValues := []Signed8Depth2ExactRationalSnapshot{
		certificate.ledger.leaves[0], certificate.ledger.leaves[1], certificate.ledger.leaves[2], certificate.ledger.leaves[3],
		certificate.ledger.absLeafMax, certificate.ledger.absDL, certificate.ledger.absDR, certificate.ledger.absDX,
		certificate.ledger.absCross, certificate.ledger.boundRawA, certificate.ledger.boundA,
		certificate.ledger.boundRawD, certificate.ledger.boundD, certificate.ledger.boundRawY,
		certificate.ledger.boundZ, certificate.ledger.boundA6, certificate.ledger.boundY,
		certificate.ledger.cacheErrorL00, certificate.ledger.cacheErrorDL, certificate.ledger.cacheErrorDX,
		certificate.ledger.cacheErrorCross, certificate.ledger.cacheErrorTolerance,
	}
	for _, value := range ledgerValues {
		fmt.Fprintf(&builder, "|rat=%s", value.RatString())
	}
	for _, state := range certificate.states {
		fmt.Fprintf(&builder, "|state=%s/L%d/scale={%s}/bound=%s/bits=%d", state.name, state.level,
			state.scale.canonicalString(), state.bound.RatString(), state.floorIdealCenteredHeadroomBits)
	}
	return digestString(builder.String())
}

func digestSigned8Depth2TerminalLeafProfile(profile Signed8Depth2TerminalLeafProfile) string {
	var builder strings.Builder
	fmt.Fprintf(&builder,
		"%s|fidelity=%s|params=%s|child=%s|decoder=%s|prefix=%s|range=%s|tree=%s|schedule=%s|producer=%s/%s|leaves=%x|certificate=%s|scales=%s/%s/%s/%s/%s/%s|sources=%v|payloads=%v|counts=%+v|keys=%v/relin=%v|bytes=%+v|ledger=%s",
		signed8Depth2TerminalLeafProfileSchema, profile.fidelity, profile.parameterDigest,
		profile.childProfileDigest, profile.decoderProfileDigest, profile.prefixProfileDigest,
		profile.protocolRangeDigest, profile.treeDigest, profile.scheduleDigest,
		profile.producerPublicDigest, profile.producerOpaqueDigest, profile.leaves, profile.certificate.digest,
		profile.scales.b1.canonicalString(), profile.scales.b0.canonicalString(), profile.scales.delta.canonicalString(),
		profile.scales.leaf.canonicalString(), profile.scales.rawA.canonicalString(), profile.scales.rawY.canonicalString(),
		profile.cacheSourceDigests, profile.cachePayloadDigests, profile.counts,
		profile.requiredGalois, profile.relinearization, profile.expectedBytes, profile.levelLedger)
	for _, state := range profile.expectedStates {
		fmt.Fprintf(&builder, "|state=%s/L%d/D%d/dim=%d,%d/scale={%s}/bytes=%d", state.Stage, state.Level,
			state.Degree, state.LogDimensions.Rows, state.LogDimensions.Cols, state.Scale.canonicalString(), state.SerializedBytes)
	}
	return digestString(builder.String())
}

func digestSigned8Depth2TerminalLeafInput(input Signed8Depth2TerminalLeafInput, rootPayload string) string {
	return digestString(fmt.Sprintf(
		"%s|profile=%s|params=%s|child=%s|decoder=%s|prefix=%s|range=%s|tree=%s|schedule=%s|child-input=%s|child-result=%s|operands=%s|decoder-input=%s|mode=%s|producer=%s|root=%s",
		signed8Depth2TerminalLeafInputSchema, input.profileDigest, input.parameterDigest,
		input.childProfileDigest, input.decoderProfileDigest, input.prefixProfileDigest,
		input.protocolRangeDigest, input.treeDigest, input.scheduleDigest,
		input.childInputBindingDigest, input.childResultProvenanceDigest,
		input.operandsProvenanceDigest, input.decoderInputProvenanceDigest,
		input.operandMode, input.producerProfileDigest, rootPayload,
	))
}

func digestSigned8Depth2TerminalLeafResult(result Signed8Depth2TerminalLeafResult, outputPayload string) string {
	return digestString(fmt.Sprintf(
		"%s|profile=%s|params=%s|child=%s|decoder=%s|tree=%s|schedule=%s|certificate=%s|caches=%v|input=%s|child-input=%s|child-result=%s|operands=%s|decoder-result=%s|decoder-trace=%s|mode=%s|producer=%s|output=%s",
		signed8Depth2TerminalLeafResultSchema, result.profileDigest, result.parameterDigest,
		result.childProfileDigest, result.decoderProfileDigest, result.treeDigest, result.scheduleDigest,
		result.certificateDigest, result.cachePayloadDigests, result.inputProvenanceDigest,
		result.childInputBindingDigest, result.childResultProvenanceDigest, result.operandsProvenanceDigest,
		result.decoderResultDigest, result.decoderTraceDigest, result.operandMode,
		result.producerProfileDigest, outputPayload,
	))
}

func digestSigned8Depth2TerminalLeafTrace(trace Signed8Depth2TerminalLeafTrace) string {
	var builder strings.Builder
	fmt.Fprintf(&builder,
		"%s|profile=%s|input=%s|child-input=%s|child-result=%s|operands=%s|decoder-input=%s|producer=%s|mode=%s|result=%s|decoder-result=%s|decoder-trace=%s|failure=%s|completed-terminal=%+v|attempted-lower-bound=%+v|bytes=%+v|keys=%v|relin=%v|wall=%d",
		signed8Depth2TerminalLeafTraceSchema, trace.profileDigest, trace.inputProvenanceDigest,
		trace.childInputBindingDigest, trace.childResultProvenanceDigest, trace.operandsProvenanceDigest,
		trace.decoderInputProvenanceDigest, trace.producerProfileDigest, trace.operandMode,
		trace.resultProvenanceDigest, trace.decoderResultDigest, trace.decoderTraceDigest,
		trace.failureStage, trace.counts, trace.attemptedOperationLowerBound, trace.serializedBytes,
		trace.runtimeGalois, trace.relinearizationMatched, trace.wallTime,
	)
	for _, state := range trace.states {
		fmt.Fprintf(&builder, "|state=%s/L%d/D%d/dim=%d,%d/scale={%s}/bytes=%d/payload=%s",
			state.Stage, state.Level, state.Degree, state.LogDimensions.Rows, state.LogDimensions.Cols,
			state.Scale.canonicalString(), state.SerializedBytes, trace.retainedPayloadDigests[state.Stage])
	}
	return digestString(builder.String())
}

func digestSigned8Depth2TerminalCacheSource(
	name string,
	value *big.Rat,
	level int,
	scale ExactScaleSnapshot,
) string {
	if value == nil {
		return ""
	}
	return digestString(fmt.Sprintf(
		"signed8-depth2-terminal-cache-v1|name=%s|rat=%s|precision=%d|mode=%d|policy=%s|level=%d|scale={%s}",
		name, value.RatString(), signed8Depth2LeafCertificatePrecision, big.ToNearestEven,
		signed8Depth2CacheRoundingPolicy, level, scale.canonicalString(),
	))
}
