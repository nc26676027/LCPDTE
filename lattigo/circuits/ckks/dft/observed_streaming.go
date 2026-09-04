package dft

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	ltcommon "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const observedStreamingRequiredPrecision = uint(256)

// ObservedTransformRole binds receipt terminology to the direction of the DFT.
type ObservedTransformRole uint8

const (
	ObservedSlotsToCoeffs ObservedTransformRole = 1
	ObservedCoeffsToSlots ObservedTransformRole = 2
)

type ObservedFactorIndex int32
type ObservedFactorCount uint32

type ObservedStreamingStatus uint8

const (
	ObservedStreamingSuccess ObservedStreamingStatus = 1
	ObservedStreamingFailure ObservedStreamingStatus = 2
)

type ObservedStreamingFailureStage uint8

const (
	ObservedStreamingFailureNone       ObservedStreamingFailureStage = 0
	ObservedStreamingFailureValidation ObservedStreamingFailureStage = 1
	ObservedStreamingFailureConsumer   ObservedStreamingFailureStage = 2
	ObservedStreamingFailureProduct    ObservedStreamingFailureStage = 3
	ObservedStreamingFailureGenerator  ObservedStreamingFailureStage = 4
	ObservedStreamingFailureSeal       ObservedStreamingFailureStage = 5
)

type ObservedStreamingEventCode uint8

const (
	ObservedStreamingTransformStart          ObservedStreamingEventCode = 0x03
	ObservedStreamingFactorGenerated         ObservedStreamingEventCode = 0x04
	ObservedStreamingNumericDigested         ObservedStreamingEventCode = 0x05
	ObservedStreamingFactorEncoded           ObservedStreamingEventCode = 0x06
	ObservedStreamingEncodedDigested         ObservedStreamingEventCode = 0x07
	ObservedStreamingNumericReferenceDropped ObservedStreamingEventCode = 0x08
	ObservedStreamingTransformEnd            ObservedStreamingEventCode = 0x09
	ObservedStreamingGeneratorReturned       ObservedStreamingEventCode = 0x0a
)

type ObservedStreamingPayloadKind uint8

const (
	ObservedStreamingPayloadNone          ObservedStreamingPayloadKind = 0
	ObservedStreamingPayloadNumericFactor ObservedStreamingPayloadKind = 1
	ObservedStreamingPayloadEncodedFactor ObservedStreamingPayloadKind = 2
)

// Cleanup records are deliberately outside Events. On a consumer error or
// panic the vendor must clear its borrowed factor and generator references,
// but those mandatory actions are not a successful lifecycle-event prefix and
// do not assert that an arbitrary consumer retained no alias.
type ObservedStreamingCleanupCode uint8

const (
	ObservedStreamingCleanupFactorReferenceCleared     ObservedStreamingCleanupCode = 1
	ObservedStreamingCleanupProductDiscarded           ObservedStreamingCleanupCode = 2
	ObservedStreamingCleanupMatrixArtifactDiscarded    ObservedStreamingCleanupCode = 3
	ObservedStreamingCleanupGeneratorReferencesCleared ObservedStreamingCleanupCode = 4
)

type ObservedLinearTransformationOwnership uint8

const (
	ObservedLinearTransformationOwnedByMatrix ObservedLinearTransformationOwnership = 1
	ObservedLinearTransformationDiscarded     ObservedLinearTransformationOwnership = 2
)

type ObservedStreamingEvent struct {
	sequence      uint32
	code          ObservedStreamingEventCode
	role          ObservedTransformRole
	factorIndex   ObservedFactorIndex
	factorCount   ObservedFactorCount
	payloadKind   ObservedStreamingPayloadKind
	payloadDigest [sha256.Size]byte
	payloadBytes  uint64
}

func (e ObservedStreamingEvent) Sequence() uint32                          { return e.sequence }
func (e ObservedStreamingEvent) Code() ObservedStreamingEventCode          { return e.code }
func (e ObservedStreamingEvent) Role() ObservedTransformRole               { return e.role }
func (e ObservedStreamingEvent) FactorIndex() ObservedFactorIndex          { return e.factorIndex }
func (e ObservedStreamingEvent) FactorCount() ObservedFactorCount          { return e.factorCount }
func (e ObservedStreamingEvent) PayloadKind() ObservedStreamingPayloadKind { return e.payloadKind }
func (e ObservedStreamingEvent) PayloadDigest() [sha256.Size]byte          { return e.payloadDigest }
func (e ObservedStreamingEvent) PayloadBytes() uint64                      { return e.payloadBytes }

type ObservedStreamingCleanupEvent struct {
	sequence    uint32
	code        ObservedStreamingCleanupCode
	role        ObservedTransformRole
	factorIndex ObservedFactorIndex
	factorCount ObservedFactorCount
}

func (e ObservedStreamingCleanupEvent) Sequence() uint32                   { return e.sequence }
func (e ObservedStreamingCleanupEvent) Code() ObservedStreamingCleanupCode { return e.code }
func (e ObservedStreamingCleanupEvent) Role() ObservedTransformRole        { return e.role }
func (e ObservedStreamingCleanupEvent) FactorIndex() ObservedFactorIndex   { return e.factorIndex }
func (e ObservedStreamingCleanupEvent) FactorCount() ObservedFactorCount   { return e.factorCount }

type ObservedFactorEvidence struct {
	role          ObservedTransformRole
	index         ObservedFactorIndex
	count         ObservedFactorCount
	numericDigest [sha256.Size]byte
	numericBytes  uint64
	encodedDigest [sha256.Size]byte
	encodedBytes  uint64
	ownership     ObservedLinearTransformationOwnership
}

func (e ObservedFactorEvidence) Role() ObservedTransformRole      { return e.role }
func (e ObservedFactorEvidence) Index() ObservedFactorIndex       { return e.index }
func (e ObservedFactorEvidence) Count() ObservedFactorCount       { return e.count }
func (e ObservedFactorEvidence) NumericDigest() [sha256.Size]byte { return e.numericDigest }
func (e ObservedFactorEvidence) NumericBytes() uint64             { return e.numericBytes }
func (e ObservedFactorEvidence) EncodedDigest() [sha256.Size]byte { return e.encodedDigest }
func (e ObservedFactorEvidence) EncodedBytes() uint64             { return e.encodedBytes }
func (e ObservedFactorEvidence) Ownership() ObservedLinearTransformationOwnership {
	return e.ownership
}

type observedFactorInvocation struct {
	active             bool
	role               ObservedTransformRole
	index              ObservedFactorIndex
	count              ObservedFactorCount
	generatorPrecision uint
	encoderPrecision   uint
	literal            MatrixLiteral
	factor             ltcommon.Diagonals[*bignum.Complex]
}

// ObservedFactorInput is a synchronous borrowed factor capability. A retained
// input becomes inactive immediately when ConsumeObservedFactor returns. The
// returned map is borrowed: the private secureeval consumer is independently
// audited not to retain it, and a vendor trace proves only vendor-owned drops.
type ObservedFactorInput struct {
	invocation *observedFactorInvocation
}

func (i ObservedFactorInput) Role() ObservedTransformRole {
	if i.invocation == nil {
		return 0
	}
	return i.invocation.role
}
func (i ObservedFactorInput) Index() ObservedFactorIndex {
	if i.invocation == nil {
		return -1
	}
	return i.invocation.index
}
func (i ObservedFactorInput) Count() ObservedFactorCount {
	if i.invocation == nil {
		return 0
	}
	return i.invocation.count
}
func (i ObservedFactorInput) GeneratorPrecision() uint {
	if i.invocation == nil {
		return 0
	}
	return i.invocation.generatorPrecision
}
func (i ObservedFactorInput) EncoderPrecision() uint {
	if i.invocation == nil {
		return 0
	}
	return i.invocation.encoderPrecision
}
func (i ObservedFactorInput) Literal() MatrixLiteral {
	if i.invocation == nil {
		return MatrixLiteral{}
	}
	return cloneDFTMatrixLiteral(i.invocation.literal)
}
func (i ObservedFactorInput) BorrowedNumericFactor() (ltcommon.Diagonals[*bignum.Complex], bool) {
	if i.invocation == nil || !i.invocation.active || i.invocation.factor == nil {
		return nil, false
	}
	return i.invocation.factor, true
}

// ObservedFactorConsumer is implemented by the private artifact builder. The
// consumer owns numeric hashing, encoding and resident-payload hashing; the
// vendor owns generation order, typed validation and lifecycle evidence.
type ObservedFactorConsumer interface {
	ConsumeObservedFactor(ObservedFactorInput) (*ObservedFactorProduct, error)
}

type observedFactorProductState struct {
	invocation                           *observedFactorInvocation
	role                                 ObservedTransformRole
	index                                ObservedFactorIndex
	count                                ObservedFactorCount
	generatorPrecision, encoderPrecision uint
	numericDigest, encodedDigest         [sha256.Size]byte
	numericBytes, encodedBytes           uint64
	transformation                       ltcommon.LinearTransformation
	available                            bool
	transferred                          bool
}

// ObservedFactorProduct is a one-shot, move-like product. Public accessors do
// not expose the encoded transformation or its Vec/MetaData aliases.
type ObservedFactorProduct struct {
	state *observedFactorProductState
}

// NewObservedFactorProduct seals the fixed-size evidence and moves donor into
// a one-shot product. Clearing donor is a protocol move, not a Go-level proof
// that a malicious consumer did not make a shallow alias beforehand.
func NewObservedFactorProduct(
	input ObservedFactorInput,
	numericDigest [sha256.Size]byte,
	numericBytes uint64,
	encodedDigest [sha256.Size]byte,
	encodedBytes uint64,
	donor *ltcommon.LinearTransformation,
) (*ObservedFactorProduct, error) {
	invocation := input.invocation
	if invocation == nil || !invocation.active || invocation.factor == nil {
		return nil, fmt.Errorf("dft: cannot seal a product for an inactive observed factor")
	}
	if invocation.generatorPrecision != observedStreamingRequiredPrecision || invocation.encoderPrecision != observedStreamingRequiredPrecision {
		return nil, fmt.Errorf("dft: observed product precision is not 256/256")
	}
	if numericDigest == ([sha256.Size]byte{}) || numericBytes == 0 ||
		encodedDigest == ([sha256.Size]byte{}) || encodedBytes == 0 {
		return nil, fmt.Errorf("dft: observed product digest or byte evidence is empty")
	}
	if donor == nil || donor.MetaData == nil || donor.Vec == nil || len(donor.Vec) == 0 {
		return nil, fmt.Errorf("dft: observed product LT donor is empty")
	}
	product := &ObservedFactorProduct{state: &observedFactorProductState{
		invocation: invocation,
		role:       invocation.role, index: invocation.index, count: invocation.count,
		generatorPrecision: invocation.generatorPrecision, encoderPrecision: invocation.encoderPrecision,
		numericDigest: numericDigest, numericBytes: numericBytes,
		encodedDigest: encodedDigest, encodedBytes: encodedBytes,
		transformation: *donor, available: true,
	}}
	*donor = ltcommon.LinearTransformation{}
	return product, nil
}

func (p *ObservedFactorProduct) Role() ObservedTransformRole {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.role
}
func (p *ObservedFactorProduct) Index() ObservedFactorIndex {
	if p == nil || p.state == nil {
		return -1
	}
	return p.state.index
}
func (p *ObservedFactorProduct) Count() ObservedFactorCount {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.count
}
func (p *ObservedFactorProduct) NumericDigest() [sha256.Size]byte {
	if p == nil || p.state == nil {
		return [sha256.Size]byte{}
	}
	return p.state.numericDigest
}
func (p *ObservedFactorProduct) NumericBytes() uint64 {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.numericBytes
}
func (p *ObservedFactorProduct) EncodedDigest() [sha256.Size]byte {
	if p == nil || p.state == nil {
		return [sha256.Size]byte{}
	}
	return p.state.encodedDigest
}
func (p *ObservedFactorProduct) EncodedBytes() uint64 {
	if p == nil || p.state == nil {
		return 0
	}
	return p.state.encodedBytes
}
func (p *ObservedFactorProduct) TransferCompleted() bool {
	return p != nil && p.state != nil && p.state.transferred && !p.state.available &&
		p.state.transformation.MetaData == nil && p.state.transformation.Vec == nil
}

type ObservedStreamingTrace struct {
	status                   ObservedStreamingStatus
	role                     ObservedTransformRole
	factorCount              ObservedFactorCount
	failureStage             ObservedStreamingFailureStage
	completedEventCount      uint32
	attemptedEventLowerBound uint32
	events                   []ObservedStreamingEvent
	cleanup                  []ObservedStreamingCleanupEvent
	factors                  []ObservedFactorEvidence
	digest                   [sha256.Size]byte
}

func (t ObservedStreamingTrace) Status() ObservedStreamingStatus  { return t.status }
func (t ObservedStreamingTrace) Role() ObservedTransformRole      { return t.role }
func (t ObservedStreamingTrace) FactorCount() ObservedFactorCount { return t.factorCount }
func (t ObservedStreamingTrace) FailureStage() ObservedStreamingFailureStage {
	return t.failureStage
}
func (t ObservedStreamingTrace) CompletedEventCount() uint32 { return t.completedEventCount }
func (t ObservedStreamingTrace) AttemptedEventLowerBound() uint32 {
	return t.attemptedEventLowerBound
}
func (t ObservedStreamingTrace) Events() []ObservedStreamingEvent {
	return append([]ObservedStreamingEvent(nil), t.events...)
}
func (t ObservedStreamingTrace) CleanupEvents() []ObservedStreamingCleanupEvent {
	return append([]ObservedStreamingCleanupEvent(nil), t.cleanup...)
}
func (t ObservedStreamingTrace) Factors() []ObservedFactorEvidence {
	return append([]ObservedFactorEvidence(nil), t.factors...)
}
func (t ObservedStreamingTrace) Digest() [sha256.Size]byte { return t.digest }

func (t ObservedStreamingTrace) Validate() error {
	if t.digest == ([sha256.Size]byte{}) || t.digest != digestObservedStreamingTrace(t) {
		return fmt.Errorf("dft: observed trace digest changed")
	}
	count, ok := observedRoleFactorCount(t.role)
	if t.status == ObservedStreamingFailure && t.failureStage == ObservedStreamingFailureValidation {
		if (ok && t.factorCount != count) || (!ok && t.factorCount != 0) ||
			t.completedEventCount != 0 || len(t.events) != 0 || len(t.cleanup) != 0 ||
			len(t.factors) != 0 || t.attemptedEventLowerBound != 0 {
			return fmt.Errorf("dft: observed validation failure ledger changed")
		}
		return nil
	}
	if !ok || t.factorCount != count || t.completedEventCount != uint32(len(t.events)) {
		return fmt.Errorf("dft: observed trace role, factor count or completed count changed")
	}
	if err := validateObservedStreamingEventPrefix(t.role, t.factorCount, t.events); err != nil {
		return err
	}
	for sequence, cleanup := range t.cleanup {
		if cleanup.sequence != uint32(sequence) || cleanup.role != t.role || cleanup.factorCount != t.factorCount {
			return fmt.Errorf("dft: observed cleanup sequence or typed identity changed")
		}
		switch cleanup.code {
		case ObservedStreamingCleanupFactorReferenceCleared, ObservedStreamingCleanupProductDiscarded,
			ObservedStreamingCleanupMatrixArtifactDiscarded:
			if cleanup.factorIndex < 0 || cleanup.factorIndex >= ObservedFactorIndex(t.factorCount) {
				return fmt.Errorf("dft: observed factor cleanup index changed")
			}
		case ObservedStreamingCleanupGeneratorReferencesCleared:
			if cleanup.factorIndex != -1 {
				return fmt.Errorf("dft: observed generator cleanup has a factor index")
			}
		default:
			return fmt.Errorf("dft: observed cleanup code changed")
		}
	}
	if t.status == ObservedStreamingSuccess {
		if t.failureStage != ObservedStreamingFailureNone || len(t.events) != int(5*t.factorCount+3) ||
			t.attemptedEventLowerBound != t.completedEventCount || len(t.cleanup) != 0 ||
			len(t.factors) != int(t.factorCount) {
			return fmt.Errorf("dft: observed success ledger changed")
		}
		for index, factor := range t.factors {
			if factor.role != t.role || factor.index != ObservedFactorIndex(index) || factor.count != t.factorCount ||
				factor.numericDigest == ([sha256.Size]byte{}) || factor.numericBytes == 0 ||
				factor.encodedDigest == ([sha256.Size]byte{}) || factor.encodedBytes == 0 ||
				factor.ownership != ObservedLinearTransformationOwnedByMatrix {
				return fmt.Errorf("dft: observed success factor evidence changed")
			}
			numericEvent := t.events[2+5*index]
			encodedEvent := t.events[4+5*index]
			if numericEvent.payloadDigest != factor.numericDigest || numericEvent.payloadBytes != factor.numericBytes ||
				encodedEvent.payloadDigest != factor.encodedDigest || encodedEvent.payloadBytes != factor.encodedBytes {
				return fmt.Errorf("dft: observed success factor and event evidence disagree")
			}
		}
		return nil
	}
	if t.status != ObservedStreamingFailure || t.failureStage == ObservedStreamingFailureNone {
		return fmt.Errorf("dft: observed trace status changed")
	}
	for index, factor := range t.factors {
		if factor.role != t.role || factor.index != ObservedFactorIndex(index) || factor.count != t.factorCount ||
			factor.numericDigest == ([sha256.Size]byte{}) || factor.numericBytes == 0 ||
			factor.encodedDigest == ([sha256.Size]byte{}) || factor.encodedBytes == 0 ||
			factor.ownership != ObservedLinearTransformationDiscarded {
			return fmt.Errorf("dft: observed failure retained an installable transformation")
		}
		numericEventIndex, encodedEventIndex := 2+5*index, 4+5*index
		if encodedEventIndex >= len(t.events) ||
			t.events[numericEventIndex].payloadDigest != factor.numericDigest ||
			t.events[numericEventIndex].payloadBytes != factor.numericBytes ||
			t.events[encodedEventIndex].payloadDigest != factor.encodedDigest ||
			t.events[encodedEventIndex].payloadBytes != factor.encodedBytes {
			return fmt.Errorf("dft: observed failed factor and event evidence disagree")
		}
	}
	return validateObservedStreamingFailureLedger(t)
}

func validateObservedStreamingFailureLedger(trace ObservedStreamingTrace) error {
	if trace.attemptedEventLowerBound != trace.completedEventCount+1 {
		return fmt.Errorf("dft: observed failure attempted-event lower bound changed")
	}
	switch trace.failureStage {
	case ObservedStreamingFailureConsumer, ObservedStreamingFailureProduct:
		completedFactors := len(trace.factors)
		if completedFactors >= int(trace.factorCount) || len(trace.events) != 2+5*completedFactors {
			return fmt.Errorf("dft: observed consumer/product failure event prefix changed")
		}
		cleanupIndex := 0
		if cleanupIndex < len(trace.cleanup) && trace.cleanup[cleanupIndex].code == ObservedStreamingCleanupProductDiscarded {
			if trace.cleanup[cleanupIndex].factorIndex != ObservedFactorIndex(completedFactors) {
				return fmt.Errorf("dft: observed discarded product index changed")
			}
			cleanupIndex++
		}
		if cleanupIndex >= len(trace.cleanup) ||
			trace.cleanup[cleanupIndex].code != ObservedStreamingCleanupFactorReferenceCleared ||
			trace.cleanup[cleanupIndex].factorIndex != ObservedFactorIndex(completedFactors) {
			return fmt.Errorf("dft: observed failure omitted the current factor-reference clear")
		}
		cleanupIndex++
		for factorIndex := 0; factorIndex < completedFactors; factorIndex++ {
			if cleanupIndex >= len(trace.cleanup) ||
				trace.cleanup[cleanupIndex].code != ObservedStreamingCleanupMatrixArtifactDiscarded ||
				trace.cleanup[cleanupIndex].factorIndex != ObservedFactorIndex(factorIndex) {
				return fmt.Errorf("dft: observed failure matrix-artifact cleanup changed")
			}
			cleanupIndex++
		}
		if cleanupIndex != len(trace.cleanup)-1 ||
			trace.cleanup[cleanupIndex].code != ObservedStreamingCleanupGeneratorReferencesCleared ||
			trace.cleanup[cleanupIndex].factorIndex != -1 {
			return fmt.Errorf("dft: observed failure generator cleanup changed")
		}
		return nil
	case ObservedStreamingFailureGenerator:
		completedFactors := len(trace.factors)
		if completedFactors > int(trace.factorCount) || len(trace.events) != 1+5*completedFactors ||
			len(trace.cleanup) != completedFactors+1 {
			return fmt.Errorf("dft: observed generator failure ledger changed")
		}
		for factorIndex := 0; factorIndex < completedFactors; factorIndex++ {
			if trace.cleanup[factorIndex].code != ObservedStreamingCleanupMatrixArtifactDiscarded ||
				trace.cleanup[factorIndex].factorIndex != ObservedFactorIndex(factorIndex) {
				return fmt.Errorf("dft: observed generator failure artifact cleanup changed")
			}
		}
		last := trace.cleanup[len(trace.cleanup)-1]
		if last.code != ObservedStreamingCleanupGeneratorReferencesCleared || last.factorIndex != -1 {
			return fmt.Errorf("dft: observed generator failure reference cleanup changed")
		}
		return nil
	case ObservedStreamingFailureSeal:
		if len(trace.events) != int(5*trace.factorCount+3) || len(trace.factors) != int(trace.factorCount) ||
			len(trace.cleanup) != int(trace.factorCount)+1 {
			return fmt.Errorf("dft: observed seal failure ledger changed")
		}
		for factorIndex := 0; factorIndex < int(trace.factorCount); factorIndex++ {
			if trace.cleanup[factorIndex].code != ObservedStreamingCleanupMatrixArtifactDiscarded ||
				trace.cleanup[factorIndex].factorIndex != ObservedFactorIndex(factorIndex) {
				return fmt.Errorf("dft: observed seal failure artifact cleanup changed")
			}
		}
		last := trace.cleanup[len(trace.cleanup)-1]
		if last.code != ObservedStreamingCleanupGeneratorReferencesCleared || last.factorIndex != -1 {
			return fmt.Errorf("dft: observed seal failure reference cleanup changed")
		}
		return nil
	default:
		return fmt.Errorf("dft: observed failure stage changed")
	}
}

// NewMatrixFromLiteralWithGeneratorPrecisionObserved is the only observed
// transform-construction entry. It increments only ObservedStreaming before
// every validation and calls the private factor generator directly.
func NewMatrixFromLiteralWithGeneratorPrecisionObserved(
	params ckks.Parameters,
	role ObservedTransformRole,
	literal MatrixLiteral,
	encoder *ckks.Encoder,
	generatorPrecision uint,
	consumer ObservedFactorConsumer,
) (Matrix, ObservedStreamingTrace, error) {
	noteObservedStreamingConstruction()

	factorCount, roleOK := observedRoleFactorCount(role)
	trace := ObservedStreamingTrace{role: role, factorCount: factorCount}
	validationFailure := func(err error) (Matrix, ObservedStreamingTrace, error) {
		trace.status = ObservedStreamingFailure
		trace.failureStage = ObservedStreamingFailureValidation
		trace.seal()
		return Matrix{}, cloneObservedStreamingTrace(trace), err
	}
	if !roleOK {
		return validationFailure(fmt.Errorf("dft: invalid observed transform role %d", role))
	}
	if consumer == nil {
		return validationFailure(fmt.Errorf("dft: observed factor consumer is nil"))
	}
	if encoder == nil {
		return validationFailure(fmt.Errorf("dft: observed encoder is nil"))
	}
	if generatorPrecision != observedStreamingRequiredPrecision || encoder.Prec() != observedStreamingRequiredPrecision {
		return validationFailure(fmt.Errorf("dft: observed generator/encoder precision is %d/%d, want 256/256", generatorPrecision, encoder.Prec()))
	}
	encoderParams := encoder.GetParameters()
	if !encoderParams.Equal(&params) {
		return validationFailure(fmt.Errorf("dft: observed encoder parameters differ from matrix parameters"))
	}
	if err := validateObservedStreamingLiteral(params, role, factorCount, literal); err != nil {
		return validationFailure(err)
	}
	if err := validateExpectedDFTMatrixLiteral(params, literal); err != nil {
		return validationFailure(err)
	}
	validationPlan, err := newDFTMatrixValidationPlan(params, literal)
	if err != nil {
		return validationFailure(err)
	}

	trace.status = ObservedStreamingFailure
	trace.appendEvent(ObservedStreamingTransformStart, -1, ObservedStreamingPayloadNone, [sha256.Size]byte{}, 0)
	factorIndex := ObservedFactorIndex(0)
	pendingDropSuccess := false
	pendingDropIndex := ObservedFactorIndex(-1)
	matrices := make([]ltcommon.LinearTransformation, 0, factorCount)
	observer := matrixFactorGenerationObserver{
		factorDropped: func(index int) {
			if pendingDropIndex != ObservedFactorIndex(index) {
				return
			}
			if pendingDropSuccess {
				trace.appendEvent(ObservedStreamingNumericReferenceDropped, pendingDropIndex, ObservedStreamingPayloadNone, [sha256.Size]byte{}, 0)
			} else {
				trace.appendCleanup(ObservedStreamingCleanupFactorReferenceCleared, pendingDropIndex)
			}
			pendingDropIndex = -1
			pendingDropSuccess = false
		},
		generatorReturned: func(generatorErr error) {
			if generatorErr == nil && factorIndex == ObservedFactorIndex(factorCount) && len(matrices) == int(factorCount) {
				trace.appendEvent(ObservedStreamingTransformEnd, -1, ObservedStreamingPayloadNone, [sha256.Size]byte{}, 0)
				trace.appendEvent(ObservedStreamingGeneratorReturned, -1, ObservedStreamingPayloadNone, [sha256.Size]byte{}, 0)
				return
			}
			if trace.failureStage == ObservedStreamingFailureNone {
				trace.failureStage = ObservedStreamingFailureGenerator
				trace.attemptedEventLowerBound = uint32(len(trace.events) + 1)
			}
			for index := range matrices {
				matrices[index] = ltcommon.LinearTransformation{}
				trace.factors[index].ownership = ObservedLinearTransformationDiscarded
				trace.appendCleanup(ObservedStreamingCleanupMatrixArtifactDiscarded, ObservedFactorIndex(index))
			}
			matrices = nil
			trace.appendCleanup(ObservedStreamingCleanupGeneratorReferencesCleared, -1)
		},
	}

	generatorErr := literal.forEachMatrixFactorWithFreshRootsObserved(
		params.LogN(), generatorPrecision, observer,
		func(factor ltcommon.Diagonals[*bignum.Complex]) error {
			current := factorIndex
			factorIndex++
			pendingDropIndex = current
			pendingDropSuccess = false
			trace.appendEvent(ObservedStreamingFactorGenerated, current, ObservedStreamingPayloadNone, [sha256.Size]byte{}, 0)
			invocation := &observedFactorInvocation{
				active: true, role: role, index: current, count: factorCount,
				generatorPrecision: generatorPrecision, encoderPrecision: encoder.Prec(),
				literal: cloneDFTMatrixLiteral(literal), factor: factor,
			}
			trace.attemptedEventLowerBound = uint32(len(trace.events) + 1)
			product, consumerErr := invokeObservedFactorConsumer(consumer, ObservedFactorInput{invocation: invocation})
			invocation.factor = nil
			invocation.active = false
			if consumerErr != nil {
				trace.failureStage = ObservedStreamingFailureConsumer
				if product != nil {
					product.discard()
					trace.appendCleanup(ObservedStreamingCleanupProductDiscarded, current)
				}
				return consumerErr
			}
			transformation, evidence, productErr := product.take(invocation)
			if productErr != nil {
				trace.failureStage = ObservedStreamingFailureProduct
				if product != nil {
					product.discard()
					trace.appendCleanup(ObservedStreamingCleanupProductDiscarded, current)
				}
				return productErr
			}
			if err := validateDFTMatrixTransformation(params, literal, int(current), transformation, validationPlan); err != nil {
				transformation = ltcommon.LinearTransformation{}
				product.discard()
				trace.failureStage = ObservedStreamingFailureProduct
				trace.appendCleanup(ObservedStreamingCleanupProductDiscarded, current)
				return err
			}
			trace.appendEvent(ObservedStreamingNumericDigested, current, ObservedStreamingPayloadNumericFactor, evidence.numericDigest, evidence.numericBytes)
			trace.appendEvent(ObservedStreamingFactorEncoded, current, ObservedStreamingPayloadNone, [sha256.Size]byte{}, 0)
			trace.appendEvent(ObservedStreamingEncodedDigested, current, ObservedStreamingPayloadEncodedFactor, evidence.encodedDigest, evidence.encodedBytes)
			trace.factors = append(trace.factors, evidence)
			matrices = append(matrices, transformation)
			pendingDropSuccess = true
			return nil
		},
	)
	if generatorErr != nil {
		trace.status = ObservedStreamingFailure
		trace.seal()
		return Matrix{}, cloneObservedStreamingTrace(trace), fmt.Errorf("dft: observed streaming construction: %w", generatorErr)
	}
	if factorIndex != ObservedFactorIndex(factorCount) || len(matrices) != int(factorCount) {
		trace.status = ObservedStreamingFailure
		trace.seal()
		return Matrix{}, cloneObservedStreamingTrace(trace), fmt.Errorf("dft: observed generator returned %d/%d factors", factorIndex, factorCount)
	}
	trace.status = ObservedStreamingSuccess
	trace.failureStage = ObservedStreamingFailureNone
	trace.attemptedEventLowerBound = uint32(len(trace.events))
	trace.seal()
	if err := trace.Validate(); err != nil {
		for index := range matrices {
			matrices[index] = ltcommon.LinearTransformation{}
			trace.factors[index].ownership = ObservedLinearTransformationDiscarded
			trace.appendCleanup(ObservedStreamingCleanupMatrixArtifactDiscarded, ObservedFactorIndex(index))
		}
		matrices = nil
		trace.status = ObservedStreamingFailure
		trace.failureStage = ObservedStreamingFailureSeal
		trace.attemptedEventLowerBound = uint32(len(trace.events) + 1)
		trace.appendCleanup(ObservedStreamingCleanupGeneratorReferencesCleared, -1)
		trace.seal()
		return Matrix{}, cloneObservedStreamingTrace(trace), fmt.Errorf("dft: seal observed success trace: %w", err)
	}
	return Matrix{MatrixLiteral: cloneDFTMatrixLiteral(literal), Matrices: matrices}, cloneObservedStreamingTrace(trace), nil
}

func invokeObservedFactorConsumer(consumer ObservedFactorConsumer, input ObservedFactorInput) (product *ObservedFactorProduct, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			product = nil
			err = fmt.Errorf("observed factor consumer panicked: %v", recovered)
		}
	}()
	return consumer.ConsumeObservedFactor(input)
}

func observedRoleFactorCount(role ObservedTransformRole) (ObservedFactorCount, bool) {
	switch role {
	case ObservedSlotsToCoeffs:
		return 2, true
	case ObservedCoeffsToSlots:
		return 3, true
	default:
		return 0, false
	}
}

func validateObservedStreamingLiteral(params ckks.Parameters, role ObservedTransformRole, factorCount ObservedFactorCount, literal MatrixLiteral) error {
	wantType := HomomorphicDecode
	if role == ObservedCoeffsToSlots {
		wantType = HomomorphicEncode
	}
	if literal.Type != wantType || literal.Depth(false) != int(factorCount) || len(literal.Levels) == 0 {
		return fmt.Errorf("dft: observed role, DFT type and factor count disagree")
	}
	if literal.LogSlots <= 0 || literal.LogSlots > params.LogMaxDimensions().Cols ||
		literal.LevelQ < 0 || literal.LevelQ > params.MaxLevelQ() ||
		literal.LevelP < -1 || literal.LevelP > params.MaxLevelP() ||
		literal.Format < Standard || literal.Format > RepackImagAsReal {
		return fmt.Errorf("dft: observed literal dimensions, levels or format are invalid")
	}
	for _, depth := range literal.Levels {
		if depth <= 0 {
			return fmt.Errorf("dft: observed literal contains a non-positive level group")
		}
	}
	return nil
}

func (t *ObservedStreamingTrace) appendEvent(code ObservedStreamingEventCode, index ObservedFactorIndex, kind ObservedStreamingPayloadKind, digest [sha256.Size]byte, bytes uint64) {
	t.events = append(t.events, ObservedStreamingEvent{
		sequence: uint32(len(t.events)), code: code, role: t.role,
		factorIndex: index, factorCount: t.factorCount,
		payloadKind: kind, payloadDigest: digest, payloadBytes: bytes,
	})
}

func (t *ObservedStreamingTrace) appendCleanup(code ObservedStreamingCleanupCode, index ObservedFactorIndex) {
	t.cleanup = append(t.cleanup, ObservedStreamingCleanupEvent{
		sequence: uint32(len(t.cleanup)), code: code, role: t.role,
		factorIndex: index, factorCount: t.factorCount,
	})
}

func (t *ObservedStreamingTrace) seal() {
	t.completedEventCount = uint32(len(t.events))
	t.digest = digestObservedStreamingTrace(*t)
}

func cloneObservedStreamingTrace(trace ObservedStreamingTrace) ObservedStreamingTrace {
	trace.events = append([]ObservedStreamingEvent(nil), trace.events...)
	trace.cleanup = append([]ObservedStreamingCleanupEvent(nil), trace.cleanup...)
	trace.factors = append([]ObservedFactorEvidence(nil), trace.factors...)
	return trace
}

func cloneDFTMatrixLiteral(literal MatrixLiteral) MatrixLiteral {
	literal.Levels = append([]int(nil), literal.Levels...)
	if literal.Scaling != nil {
		literal.Scaling = new(big.Float).Copy(literal.Scaling)
	}
	return literal
}

func (p *ObservedFactorProduct) discard() {
	if p == nil || p.state == nil {
		return
	}
	*p.state = observedFactorProductState{}
}

func (p *ObservedFactorProduct) take(invocation *observedFactorInvocation) (ltcommon.LinearTransformation, ObservedFactorEvidence, error) {
	if p == nil || p.state == nil || !p.state.available {
		return ltcommon.LinearTransformation{}, ObservedFactorEvidence{}, fmt.Errorf("dft: observed factor product is nil, stale or already consumed")
	}
	state := p.state
	if invocation == nil || state.invocation != invocation || state.role != invocation.role ||
		state.index != invocation.index || state.count != invocation.count ||
		state.generatorPrecision != observedStreamingRequiredPrecision ||
		state.encoderPrecision != observedStreamingRequiredPrecision ||
		state.generatorPrecision != invocation.generatorPrecision || state.encoderPrecision != invocation.encoderPrecision ||
		state.numericDigest == ([sha256.Size]byte{}) || state.numericBytes == 0 ||
		state.encodedDigest == ([sha256.Size]byte{}) || state.encodedBytes == 0 ||
		state.transformation.MetaData == nil || state.transformation.Vec == nil || len(state.transformation.Vec) == 0 {
		return ltcommon.LinearTransformation{}, ObservedFactorEvidence{}, fmt.Errorf("dft: observed factor product token, type, precision or payload changed")
	}
	transformation := state.transformation
	evidence := ObservedFactorEvidence{
		role: state.role, index: state.index, count: state.count,
		numericDigest: state.numericDigest, numericBytes: state.numericBytes,
		encodedDigest: state.encodedDigest, encodedBytes: state.encodedBytes,
		ownership: ObservedLinearTransformationOwnedByMatrix,
	}
	*state = observedFactorProductState{transferred: true}
	return transformation, evidence, nil
}

func validateObservedStreamingEventPrefix(role ObservedTransformRole, count ObservedFactorCount, events []ObservedStreamingEvent) error {
	expected := make([]ObservedStreamingEvent, 0, 5*count+3)
	appendExpected := func(code ObservedStreamingEventCode, index ObservedFactorIndex, kind ObservedStreamingPayloadKind) {
		expected = append(expected, ObservedStreamingEvent{code: code, role: role, factorIndex: index, factorCount: count, payloadKind: kind})
	}
	appendExpected(ObservedStreamingTransformStart, -1, ObservedStreamingPayloadNone)
	for index := ObservedFactorIndex(0); index < ObservedFactorIndex(count); index++ {
		appendExpected(ObservedStreamingFactorGenerated, index, ObservedStreamingPayloadNone)
		appendExpected(ObservedStreamingNumericDigested, index, ObservedStreamingPayloadNumericFactor)
		appendExpected(ObservedStreamingFactorEncoded, index, ObservedStreamingPayloadNone)
		appendExpected(ObservedStreamingEncodedDigested, index, ObservedStreamingPayloadEncodedFactor)
		appendExpected(ObservedStreamingNumericReferenceDropped, index, ObservedStreamingPayloadNone)
	}
	appendExpected(ObservedStreamingTransformEnd, -1, ObservedStreamingPayloadNone)
	appendExpected(ObservedStreamingGeneratorReturned, -1, ObservedStreamingPayloadNone)
	if len(events) > len(expected) {
		return fmt.Errorf("dft: observed event count exceeds the lifecycle")
	}
	for sequence, event := range events {
		want := expected[sequence]
		if event.sequence != uint32(sequence) || event.code != want.code || event.role != want.role ||
			event.factorIndex != want.factorIndex || event.factorCount != want.factorCount || event.payloadKind != want.payloadKind {
			return fmt.Errorf("dft: observed event %d is not a lifecycle prefix", sequence)
		}
		if want.payloadKind == ObservedStreamingPayloadNone {
			if event.payloadDigest != ([sha256.Size]byte{}) || event.payloadBytes != 0 {
				return fmt.Errorf("dft: observed non-payload event %d carries a payload", sequence)
			}
		} else if event.payloadDigest == ([sha256.Size]byte{}) || event.payloadBytes == 0 {
			return fmt.Errorf("dft: observed payload event %d is empty", sequence)
		}
	}
	return nil
}

func digestObservedStreamingTrace(trace ObservedStreamingTrace) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("LCPDTE-DFT-OBSERVED-v3\x00"))
	writeByte := func(value byte) { _, _ = h.Write([]byte{value}) }
	writeU32 := func(value uint32) {
		var encoded [4]byte
		binary.LittleEndian.PutUint32(encoded[:], value)
		_, _ = h.Write(encoded[:])
	}
	writeI32 := func(value int32) { writeU32(uint32(value)) }
	writeU64 := func(value uint64) {
		var encoded [8]byte
		binary.LittleEndian.PutUint64(encoded[:], value)
		_, _ = h.Write(encoded[:])
	}
	writeByte(byte(trace.status))
	writeByte(byte(trace.role))
	writeU32(uint32(trace.factorCount))
	writeByte(byte(trace.failureStage))
	writeU32(trace.completedEventCount)
	writeU32(trace.attemptedEventLowerBound)
	writeU32(uint32(len(trace.events)))
	for _, event := range trace.events {
		writeU32(event.sequence)
		writeByte(byte(event.code))
		writeByte(byte(event.role))
		writeI32(int32(event.factorIndex))
		writeU32(uint32(event.factorCount))
		writeByte(byte(event.payloadKind))
		_, _ = h.Write(event.payloadDigest[:])
		writeU64(event.payloadBytes)
	}
	writeU32(uint32(len(trace.cleanup)))
	for _, cleanup := range trace.cleanup {
		writeU32(cleanup.sequence)
		writeByte(byte(cleanup.code))
		writeByte(byte(cleanup.role))
		writeI32(int32(cleanup.factorIndex))
		writeU32(uint32(cleanup.factorCount))
	}
	writeU32(uint32(len(trace.factors)))
	for _, factor := range trace.factors {
		writeByte(byte(factor.role))
		writeI32(int32(factor.index))
		writeU32(uint32(factor.count))
		_, _ = h.Write(factor.numericDigest[:])
		writeU64(factor.numericBytes)
		_, _ = h.Write(factor.encodedDigest[:])
		writeU64(factor.encodedBytes)
		writeByte(byte(factor.ownership))
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
