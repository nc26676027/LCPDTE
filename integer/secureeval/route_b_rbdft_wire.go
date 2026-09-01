// Package secureeval contains the private Route-B execution seam.
package secureeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	RBDFTMagic = "LCPDTE-RBDFT-v1\x00"

	RBDFTNumericFactorType          byte = 0x01
	RBDFTEncodedFactorType          byte = 0x02
	RBDFTNumericAggregateType       byte = 0x03
	RBDFTEncodedAggregateType       byte = 0x04
	RBDFTArtifactPairType           byte = 0x05
	RBDFTLifecycleType              byte = 0x06
	RBDFTBuildReceiptType           byte = 0x07
	RBDFTRoleNone                   byte = 0x00
	RBDFTRoleSTC                    byte = 0x01
	RBDFTRoleCTS                    byte = 0x02
	RBDFTLifecycleSuccess           byte = 0x01
	RBDFTLifecycleFailure           byte = 0x02
	RBDFTFailureNone                byte = 0x00
	RBDFTFailurePrepare             byte = 0x01
	RBDFTFailureEncoder             byte = 0x02
	RBDFTFailureSTCFactor           byte = 0x03
	RBDFTFailureSTCReturn           byte = 0x04
	RBDFTFailureCTSFactor           byte = 0x05
	RBDFTFailureCTSReturn           byte = 0x06
	RBDFTFailureSeal                byte = 0x07
	RBDFTFailureEncoderDrop         byte = 0x08
	RBDFTSourceSecureEval           byte = 0x01
	RBDFTSourceVendor               byte = 0x02
	RBDFTEventPrepareComplete       byte = 0x01
	RBDFTEventEncoderCreated        byte = 0x02
	RBDFTEventTransformStart        byte = 0x03
	RBDFTEventFactorGenerated       byte = 0x04
	RBDFTEventNumericDigested       byte = 0x05
	RBDFTEventFactorEncoded         byte = 0x06
	RBDFTEventEncodedDigested       byte = 0x07
	RBDFTEventNumericDropped        byte = 0x08
	RBDFTEventTransformEnd          byte = 0x09
	RBDFTEventGeneratorReturned     byte = 0x0a
	RBDFTEventArtifactSealed        byte = 0x0b
	RBDFTEventEncoderDropped        byte = 0x0c
	RBDFTPayloadNone                byte = 0x00
	RBDFTPayloadNumericFactor       byte = 0x01
	RBDFTPayloadEncodedFactor       byte = 0x02
	RBDFTPayloadArtifactPair        byte = 0x03
	RBDFTPayloadPrecision           byte = 0x04
	rbdftHeaderBytes                     = len(RBDFTMagic) + 2
	rbdftDigestBytes                     = sha256.Size
	rbdftFactorReferenceBytes            = 4 + sha256.Size + 8
	rbdftAggregateFixedBytes             = rbdftHeaderBytes + 4 + 8
	rbdftMaxTransformAggregateBytes      = rbdftAggregateFixedBytes + 3*rbdftFactorReferenceBytes
	rbdftPayloadTupleBytes               = sha256.Size + 8
	RBDFTArtifactPairRecordBytes         = rbdftHeaderBytes + sha256.Size + 4*rbdftPayloadTupleBytes
	rbdftLifecyclePrefixBytes            = rbdftHeaderBytes + 1 + 4 + 4 + 1
	rbdftLifecycleEventBytes             = 4 + 1 + 1 + 1 + 4 + 1 + sha256.Size + 8
	RBDFTLifecycleSuccessEventCount      = 35
	RBDFTLifecycleMaxRecordBytes         = rbdftLifecyclePrefixBytes + RBDFTLifecycleSuccessEventCount*rbdftLifecycleEventBytes
	rbdftMaxStringBytes                  = 256
	RBDFTBuildReceiptMaxRecordBytes      = 1934

	RBDFTBuilderID               = RBAUTHBuilderID
	RBDFTDigestID                = RBAUTHDigestID
	RBDFTAllocationID            = RBAUTHAllocationID
	RBDFTReleaseID               = RBAUTHReleaseID
	RBDFTOwnershipID             = RBAUTHOwnershipID
	RBDFTPrivateUninstalledState = RBAUTHPrivateUninstalledState
)

var (
	ErrRBDFTMalformed = errors.New("secureeval: malformed RBDFT-v1 record")
	ErrRBDFTBlocked   = errors.New("secureeval: RBDFT-v1 record links blocked")
)

// RBDFTFactorRecordRef is the identity and canonical byte ledger for one
// numeric or encoded factor record. It contains no factor payload or handle.
type RBDFTFactorRecordRef struct {
	Index       uint32
	Digest      RBAUTHDigest
	RecordBytes uint64
}

// RBDFTTransformAggregateReport is an inert parsed transform aggregate. The
// fixed array prevents a wire count from controlling an allocation.
type RBDFTTransformAggregateReport struct {
	RecordType           byte
	Role                 byte
	FactorCount          uint32
	Factors              [3]RBDFTFactorRecordRef
	AggregateRecordBytes uint64
}

// RBDFTArtifactPairReport is an inert type-0x05 report. Payload preserves the
// required STC-first, numeric-before-encoded ordering.
type RBDFTArtifactPairReport struct {
	BuildPermitDigest RBAUTHDigest
	Payload           RBAUTHActualPayload
}

// RBDFTLifecycleEvent is one immutable-value event from a parsed lifecycle
// report. Events() always returns a defensive copy.
type RBDFTLifecycleEvent struct {
	Sequence      uint32
	Source        byte
	Code          byte
	Role          byte
	FactorIndex   int32
	PayloadKind   byte
	PayloadDigest RBAUTHDigest
	Value         uint64
}

// RBDFTLifecycleReport is an inert type-0x06 parser result. Its fixed backing
// array prevents caller-controlled event-count allocation.
type RBDFTLifecycleReport struct {
	TerminalStatus           byte
	CompletedEventCount      uint32
	AttemptedEventLowerBound uint32
	FailureStage             byte
	events                   [RBDFTLifecycleSuccessEventCount]RBDFTLifecycleEvent
}

// RBDFTBuildReceiptReport is inert parsed type-0x07 evidence. It intentionally
// has no public constructor or MarshalBinary method; receipt minting remains
// inside the private observed builder.
type RBDFTBuildReceiptReport struct {
	BuildPermitDigest             RBAUTHDigest
	PreparedParameterDigest       RBAUTHDigest
	BuilderID                     string
	DigestID                      string
	AllocationID                  string
	ReleaseID                     string
	OwnershipID                   string
	GeneratorPrecisionBits        uint32
	EncoderPrecisionBits          uint32
	DefaultCounterDelta           uint64
	ExplicitWholeCounterDelta     uint64
	RawNumericCounterDelta        uint64
	ObservedStreamingCounterDelta uint64
	LifecycleDigest               RBAUTHDigest
	MaxLiveNumeric                uint32
	STCFactorCount                uint32
	CTSFactorCount                uint32
	Payload                       RBAUTHActualPayload
	BuildWallNanoseconds          uint64
	BuildPeakRSSBytes             uint64
	ArtifactState                 string
	ArtifactManifestDigest        RBAUTHDigest
}

// RBDFTBuildRecordSet groups the seven payload-free metadata records needed
// for cross-record validation. It carries byte values only, never an artifact,
// matrix, encoder, key, or ownership capability.
type RBDFTBuildRecordSet struct {
	STCNumericAggregate []byte
	STCEncodedAggregate []byte
	CTSNumericAggregate []byte
	CTSEncodedAggregate []byte
	ArtifactPair        []byte
	Lifecycle           []byte
	BuildReceipt        []byte
}

// Events returns a defensive copy of the completed lifecycle prefix.
func (value RBDFTLifecycleReport) Events() []RBDFTLifecycleEvent {
	if value.CompletedEventCount > RBDFTLifecycleSuccessEventCount {
		return nil
	}
	result := make([]RBDFTLifecycleEvent, value.CompletedEventCount)
	copy(result, value.events[:value.CompletedEventCount])
	return result
}

// ParseRBDFTNumericTransformAggregate parses and validates a canonical type
// 0x03 record. Every error returns the zero report.
func ParseRBDFTNumericTransformAggregate(encoded []byte) (RBDFTTransformAggregateReport, error) {
	return parseRBDFTTransformAggregate(encoded, RBDFTNumericAggregateType)
}

// ParseRBDFTEncodedTransformAggregate parses and validates a canonical type
// 0x04 record. Every error returns the zero report.
func ParseRBDFTEncodedTransformAggregate(encoded []byte) (RBDFTTransformAggregateReport, error) {
	return parseRBDFTTransformAggregate(encoded, RBDFTEncodedAggregateType)
}

func parseRBDFTTransformAggregate(encoded []byte, expectedType byte) (RBDFTTransformAggregateReport, error) {
	reader, role, err := parseRBDFTEnvelope(encoded, expectedType, rbdftMaxTransformAggregateBytes)
	if err != nil {
		return RBDFTTransformAggregateReport{}, err
	}
	if role != RBDFTRoleSTC && role != RBDFTRoleCTS {
		return RBDFTTransformAggregateReport{}, malformedRBDFT("transform aggregate role is not STC or CTS")
	}

	var value RBDFTTransformAggregateReport
	value.RecordType = expectedType
	value.Role = role
	if value.FactorCount, err = reader.u32(); err != nil {
		return RBDFTTransformAggregateReport{}, err
	}
	if value.FactorCount != expectedRBDFTFactorCount(role) {
		return RBDFTTransformAggregateReport{}, malformedRBDFT("transform aggregate factor count differs from the frozen role")
	}
	for index := uint32(0); index < value.FactorCount; index++ {
		factor := &value.Factors[index]
		if factor.Index, err = reader.u32(); err != nil {
			return RBDFTTransformAggregateReport{}, err
		}
		if factor.Index != index {
			return RBDFTTransformAggregateReport{}, malformedRBDFT("transform aggregate factor indexes are not contiguous")
		}
		if factor.Digest, err = reader.nonzeroDigest(); err != nil {
			return RBDFTTransformAggregateReport{}, err
		}
		if factor.RecordBytes, err = reader.u64(); err != nil {
			return RBDFTTransformAggregateReport{}, err
		}
		if factor.RecordBytes == 0 {
			return RBDFTTransformAggregateReport{}, malformedRBDFT("transform aggregate factor byte count is zero")
		}
	}
	if value.AggregateRecordBytes, err = reader.u64(); err != nil {
		return RBDFTTransformAggregateReport{}, err
	}
	if err = reader.finish(); err != nil {
		return RBDFTTransformAggregateReport{}, err
	}
	if err = validateRBDFTTransformAggregate(value); err != nil {
		return RBDFTTransformAggregateReport{}, err
	}
	return value, nil
}

// marshalRBDFTTransformAggregate is deliberately package-private. The later
// private observed builder owns aggregate creation; public callers receive
// only inert parser reports and validators.
func marshalRBDFTTransformAggregate(value RBDFTTransformAggregateReport) ([]byte, error) {
	if err := validateRBDFTTransformAggregate(value); err != nil {
		return nil, err
	}
	var writer rbdftWriter
	writer.header(value.RecordType, value.Role)
	writer.u32(value.FactorCount)
	for index := uint32(0); index < value.FactorCount; index++ {
		factor := value.Factors[index]
		writer.u32(factor.Index)
		writer.digest(factor.Digest)
		writer.u64(factor.RecordBytes)
	}
	writer.u64(value.AggregateRecordBytes)
	return writer.bytes(), nil
}

func validateRBDFTTransformAggregate(value RBDFTTransformAggregateReport) error {
	if value.RecordType != RBDFTNumericAggregateType && value.RecordType != RBDFTEncodedAggregateType {
		return malformedRBDFT("transform aggregate record type is not numeric or encoded")
	}
	expectedCount := expectedRBDFTFactorCount(value.Role)
	if expectedCount == 0 || value.FactorCount != expectedCount {
		return malformedRBDFT("transform aggregate role or factor count differs from the frozen contract")
	}
	total := uint64(rbdftAggregateFixedBytes) + uint64(value.FactorCount)*rbdftFactorReferenceBytes
	for index := uint32(0); index < value.FactorCount; index++ {
		factor := value.Factors[index]
		if factor.Index != index || isZeroDigest(factor.Digest) || factor.RecordBytes == 0 {
			return malformedRBDFT("transform aggregate factor identity is empty or non-contiguous")
		}
		var ok bool
		if total, ok = checkedAddRBDFTUint64(total, factor.RecordBytes); !ok {
			return malformedRBDFT("transform aggregate byte ledger overflowed")
		}
	}
	if value.AggregateRecordBytes != total {
		return malformedRBDFT("transform aggregate byte ledger does not equal factor bytes plus canonical framing")
	}
	return nil
}

// ParseRBDFTArtifactPairAggregate parses and validates a canonical type-0x05
// pair record. Every error returns the zero report.
func ParseRBDFTArtifactPairAggregate(encoded []byte) (RBDFTArtifactPairReport, error) {
	reader, role, err := parseRBDFTEnvelope(encoded, RBDFTArtifactPairType, RBDFTArtifactPairRecordBytes)
	if err != nil {
		return RBDFTArtifactPairReport{}, err
	}
	if role != RBDFTRoleNone {
		return RBDFTArtifactPairReport{}, malformedRBDFT("artifact pair role is not zero")
	}
	var value RBDFTArtifactPairReport
	if value.BuildPermitDigest, err = reader.nonzeroDigest(); err != nil {
		return RBDFTArtifactPairReport{}, err
	}
	for _, target := range []*RBAUTHPayloadTuple{
		&value.Payload.STCNumeric, &value.Payload.STCEncoded,
		&value.Payload.CTSNumeric, &value.Payload.CTSEncoded,
	} {
		if *target, err = reader.payloadTuple(); err != nil {
			return RBDFTArtifactPairReport{}, err
		}
	}
	if err = reader.finish(); err != nil {
		return RBDFTArtifactPairReport{}, err
	}
	return value, nil
}

// marshalRBDFTArtifactPairAggregate remains package-private so the private
// observed builder, rather than an external caller, owns artifact identities.
func marshalRBDFTArtifactPairAggregate(value RBDFTArtifactPairReport) ([]byte, error) {
	if err := validateRBDFTArtifactPair(value); err != nil {
		return nil, err
	}
	var writer rbdftWriter
	writer.header(RBDFTArtifactPairType, RBDFTRoleNone)
	writer.digest(value.BuildPermitDigest)
	for _, tuple := range []RBAUTHPayloadTuple{
		value.Payload.STCNumeric, value.Payload.STCEncoded,
		value.Payload.CTSNumeric, value.Payload.CTSEncoded,
	} {
		writer.payloadTuple(tuple)
	}
	return writer.bytes(), nil
}

func validateRBDFTArtifactPair(value RBDFTArtifactPairReport) error {
	if isZeroDigest(value.BuildPermitDigest) {
		return malformedRBDFT("artifact pair build-permit digest is zero")
	}
	for _, tuple := range []RBAUTHPayloadTuple{
		value.Payload.STCNumeric, value.Payload.STCEncoded,
		value.Payload.CTSNumeric, value.Payload.CTSEncoded,
	} {
		if isZeroDigest(tuple.AggregateDigest) || tuple.RecordBytes == 0 {
			return malformedRBDFT("artifact pair payload tuple is empty")
		}
	}
	return nil
}

// ParseRBDFTLifecycle parses and validates a canonical type-0x06 lifecycle
// prefix. Every error returns the zero report.
func ParseRBDFTLifecycle(encoded []byte) (RBDFTLifecycleReport, error) {
	reader, role, err := parseRBDFTEnvelope(encoded, RBDFTLifecycleType, RBDFTLifecycleMaxRecordBytes)
	if err != nil {
		return RBDFTLifecycleReport{}, err
	}
	if role != RBDFTRoleNone {
		return RBDFTLifecycleReport{}, malformedRBDFT("lifecycle role is not zero")
	}
	var value RBDFTLifecycleReport
	if value.TerminalStatus, err = reader.u8(); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	if value.CompletedEventCount, err = reader.u32(); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	if value.CompletedEventCount > RBDFTLifecycleSuccessEventCount {
		return RBDFTLifecycleReport{}, malformedRBDFT("lifecycle completed-event count exceeds the frozen sequence")
	}
	if value.AttemptedEventLowerBound, err = reader.u32(); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	if value.FailureStage, err = reader.u8(); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	for index := uint32(0); index < value.CompletedEventCount; index++ {
		event := &value.events[index]
		if event.Sequence, err = reader.u32(); err != nil {
			return RBDFTLifecycleReport{}, err
		}
		if event.Source, err = reader.u8(); err != nil {
			return RBDFTLifecycleReport{}, err
		}
		if event.Code, err = reader.u8(); err != nil {
			return RBDFTLifecycleReport{}, err
		}
		if event.Role, err = reader.u8(); err != nil {
			return RBDFTLifecycleReport{}, err
		}
		if event.FactorIndex, err = reader.i32(); err != nil {
			return RBDFTLifecycleReport{}, err
		}
		if event.PayloadKind, err = reader.u8(); err != nil {
			return RBDFTLifecycleReport{}, err
		}
		if event.PayloadDigest, err = reader.digest(); err != nil {
			return RBDFTLifecycleReport{}, err
		}
		if event.Value, err = reader.u64(); err != nil {
			return RBDFTLifecycleReport{}, err
		}
	}
	if err = reader.finish(); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	if err = validateRBDFTLifecycle(value); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	return value, nil
}

// marshalRBDFTLifecycle is package-private: only the private build state
// machine may turn an observed event prefix into a wire record.
func marshalRBDFTLifecycle(value RBDFTLifecycleReport) ([]byte, error) {
	if err := validateRBDFTLifecycle(value); err != nil {
		return nil, err
	}
	var writer rbdftWriter
	writer.header(RBDFTLifecycleType, RBDFTRoleNone)
	writer.u8(value.TerminalStatus)
	writer.u32(value.CompletedEventCount)
	writer.u32(value.AttemptedEventLowerBound)
	writer.u8(value.FailureStage)
	for index := uint32(0); index < value.CompletedEventCount; index++ {
		event := value.events[index]
		writer.u32(event.Sequence)
		writer.u8(event.Source)
		writer.u8(event.Code)
		writer.u8(event.Role)
		writer.i32(event.FactorIndex)
		writer.u8(event.PayloadKind)
		writer.digest(event.PayloadDigest)
		writer.u64(event.Value)
	}
	return writer.bytes(), nil
}

func validateRBDFTLifecycle(value RBDFTLifecycleReport) error {
	count := value.CompletedEventCount
	switch value.TerminalStatus {
	case RBDFTLifecycleSuccess:
		if count != RBDFTLifecycleSuccessEventCount ||
			value.AttemptedEventLowerBound != count || value.FailureStage != RBDFTFailureNone {
			return malformedRBDFT("success lifecycle does not have exactly 35 completed and attempted events")
		}
	case RBDFTLifecycleFailure:
		if count >= RBDFTLifecycleSuccessEventCount ||
			value.AttemptedEventLowerBound < count ||
			value.AttemptedEventLowerBound > count+1 ||
			value.FailureStage != expectedRBDFTFailureStage(count) {
			return malformedRBDFT("failure lifecycle is not a bounded canonical success prefix")
		}
	default:
		return malformedRBDFT("lifecycle terminal status is not success or failure")
	}
	expected := expectedRBDFTLifecycleEvents()
	for index := uint32(0); index < count; index++ {
		if err := validateRBDFTLifecycleEvent(value.events[index], index, expected[index]); err != nil {
			return err
		}
	}
	return nil
}

type rbdftExpectedLifecycleEvent struct {
	source      byte
	code        byte
	role        byte
	factorIndex int32
	payloadKind byte
}

func expectedRBDFTLifecycleEvents() (result [RBDFTLifecycleSuccessEventCount]rbdftExpectedLifecycleEvent) {
	position := 0
	appendEvent := func(source, code, role byte, factorIndex int32, payloadKind byte) {
		result[position] = rbdftExpectedLifecycleEvent{
			source: source, code: code, role: role, factorIndex: factorIndex, payloadKind: payloadKind,
		}
		position++
	}
	appendEvent(RBDFTSourceSecureEval, RBDFTEventPrepareComplete, RBDFTRoleNone, -1, RBDFTPayloadNone)
	appendEvent(RBDFTSourceSecureEval, RBDFTEventEncoderCreated, RBDFTRoleNone, -1, RBDFTPayloadPrecision)
	for _, roleAndCount := range [][2]byte{{RBDFTRoleSTC, 2}, {RBDFTRoleCTS, 3}} {
		role, count := roleAndCount[0], roleAndCount[1]
		appendEvent(RBDFTSourceVendor, RBDFTEventTransformStart, role, -1, RBDFTPayloadNone)
		for factorIndex := byte(0); factorIndex < count; factorIndex++ {
			appendEvent(RBDFTSourceVendor, RBDFTEventFactorGenerated, role, int32(factorIndex), RBDFTPayloadNone)
			appendEvent(RBDFTSourceVendor, RBDFTEventNumericDigested, role, int32(factorIndex), RBDFTPayloadNumericFactor)
			appendEvent(RBDFTSourceVendor, RBDFTEventFactorEncoded, role, int32(factorIndex), RBDFTPayloadNone)
			appendEvent(RBDFTSourceVendor, RBDFTEventEncodedDigested, role, int32(factorIndex), RBDFTPayloadEncodedFactor)
			appendEvent(RBDFTSourceVendor, RBDFTEventNumericDropped, role, int32(factorIndex), RBDFTPayloadNone)
		}
		appendEvent(RBDFTSourceVendor, RBDFTEventTransformEnd, role, -1, RBDFTPayloadNone)
		appendEvent(RBDFTSourceVendor, RBDFTEventGeneratorReturned, role, -1, RBDFTPayloadNone)
	}
	appendEvent(RBDFTSourceSecureEval, RBDFTEventArtifactSealed, RBDFTRoleNone, -1, RBDFTPayloadArtifactPair)
	appendEvent(RBDFTSourceSecureEval, RBDFTEventEncoderDropped, RBDFTRoleNone, -1, RBDFTPayloadNone)
	return result
}

func validateRBDFTLifecycleEvent(value RBDFTLifecycleEvent, sequence uint32, expected rbdftExpectedLifecycleEvent) error {
	if value.Sequence != sequence ||
		value.Source != expected.source || value.Code != expected.code ||
		value.Role != expected.role || value.FactorIndex != expected.factorIndex ||
		value.PayloadKind != expected.payloadKind {
		return malformedRBDFT("lifecycle event sequence, source, code, role, index, or payload kind changed")
	}
	switch expected.payloadKind {
	case RBDFTPayloadNone:
		if !isZeroDigest(value.PayloadDigest) || value.Value != 0 {
			return malformedRBDFT("payload-free lifecycle event carries a digest or value")
		}
	case RBDFTPayloadPrecision:
		if !isZeroDigest(value.PayloadDigest) || value.Value != 256 {
			return malformedRBDFT("encoder-created event does not carry precision 256")
		}
	case RBDFTPayloadNumericFactor, RBDFTPayloadEncodedFactor:
		if isZeroDigest(value.PayloadDigest) || value.Value == 0 {
			return malformedRBDFT("factor digest event has an empty digest or byte count")
		}
	case RBDFTPayloadArtifactPair:
		if isZeroDigest(value.PayloadDigest) || value.Value != uint64(RBDFTArtifactPairRecordBytes) {
			return malformedRBDFT("artifact-sealed event does not bind the canonical pair record size")
		}
	default:
		return malformedRBDFT("lifecycle payload kind is outside the canonical grammar")
	}
	return nil
}

func expectedRBDFTFailureStage(nextSequence uint32) byte {
	switch {
	case nextSequence == 0:
		return RBDFTFailurePrepare
	case nextSequence == 1:
		return RBDFTFailureEncoder
	case nextSequence >= 2 && nextSequence <= 13:
		return RBDFTFailureSTCFactor
	case nextSequence == 14:
		return RBDFTFailureSTCReturn
	case nextSequence >= 15 && nextSequence <= 31:
		return RBDFTFailureCTSFactor
	case nextSequence == 32:
		return RBDFTFailureCTSReturn
	case nextSequence == 33:
		return RBDFTFailureSeal
	case nextSequence == 34:
		return RBDFTFailureEncoderDrop
	default:
		return RBDFTFailureNone
	}
}

// ParseRBDFTBuildReceipt parses and validates a canonical type-0x07 success
// receipt. Every error returns the zero report.
func ParseRBDFTBuildReceipt(encoded []byte) (RBDFTBuildReceiptReport, error) {
	reader, role, err := parseRBDFTEnvelope(encoded, RBDFTBuildReceiptType, RBDFTBuildReceiptMaxRecordBytes)
	if err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	if role != RBDFTRoleNone {
		return RBDFTBuildReceiptReport{}, malformedRBDFT("build receipt role is not zero")
	}
	var value RBDFTBuildReceiptReport
	if value.BuildPermitDigest, err = reader.nonzeroDigest(); err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	if value.PreparedParameterDigest, err = reader.nonzeroDigest(); err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	for _, target := range []*string{
		&value.BuilderID, &value.DigestID, &value.AllocationID,
		&value.ReleaseID, &value.OwnershipID,
	} {
		if *target, err = reader.string(); err != nil {
			return RBDFTBuildReceiptReport{}, err
		}
	}
	for _, target := range []*uint32{&value.GeneratorPrecisionBits, &value.EncoderPrecisionBits} {
		if *target, err = reader.u32(); err != nil {
			return RBDFTBuildReceiptReport{}, err
		}
	}
	for _, target := range []*uint64{
		&value.DefaultCounterDelta, &value.ExplicitWholeCounterDelta,
		&value.RawNumericCounterDelta, &value.ObservedStreamingCounterDelta,
	} {
		if *target, err = reader.u64(); err != nil {
			return RBDFTBuildReceiptReport{}, err
		}
	}
	if value.LifecycleDigest, err = reader.nonzeroDigest(); err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	for _, target := range []*uint32{&value.MaxLiveNumeric, &value.STCFactorCount, &value.CTSFactorCount} {
		if *target, err = reader.u32(); err != nil {
			return RBDFTBuildReceiptReport{}, err
		}
	}
	tuples := []*RBAUTHPayloadTuple{
		&value.Payload.STCNumeric, &value.Payload.STCEncoded,
		&value.Payload.CTSNumeric, &value.Payload.CTSEncoded,
	}
	for _, target := range tuples {
		if target.AggregateDigest, err = reader.nonzeroDigest(); err != nil {
			return RBDFTBuildReceiptReport{}, err
		}
	}
	for _, target := range tuples {
		if target.RecordBytes, err = reader.u64(); err != nil {
			return RBDFTBuildReceiptReport{}, err
		}
	}
	if value.BuildWallNanoseconds, err = reader.u64(); err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	if value.BuildPeakRSSBytes, err = reader.u64(); err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	if value.ArtifactState, err = reader.string(); err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	if value.ArtifactManifestDigest, err = reader.nonzeroDigest(); err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	if err = reader.finish(); err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	if err = validateRBDFTBuildReceipt(value); err != nil {
		return RBDFTBuildReceiptReport{}, err
	}
	return value, nil
}

// marshalRBDFTBuildReceipt is package-private and is not a public receipt
// minting route. The private builder must still provide and link the observed
// lifecycle, aggregates and artifact pair before its receipt can be admitted.
func marshalRBDFTBuildReceipt(value RBDFTBuildReceiptReport) ([]byte, error) {
	if err := validateRBDFTBuildReceipt(value); err != nil {
		return nil, err
	}
	var writer rbdftWriter
	writer.header(RBDFTBuildReceiptType, RBDFTRoleNone)
	writer.digest(value.BuildPermitDigest)
	writer.digest(value.PreparedParameterDigest)
	for _, identifier := range []string{
		value.BuilderID, value.DigestID, value.AllocationID, value.ReleaseID, value.OwnershipID,
	} {
		writer.stringUnchecked(identifier)
	}
	writer.u32(value.GeneratorPrecisionBits)
	writer.u32(value.EncoderPrecisionBits)
	writer.u64(value.DefaultCounterDelta)
	writer.u64(value.ExplicitWholeCounterDelta)
	writer.u64(value.RawNumericCounterDelta)
	writer.u64(value.ObservedStreamingCounterDelta)
	writer.digest(value.LifecycleDigest)
	writer.u32(value.MaxLiveNumeric)
	writer.u32(value.STCFactorCount)
	writer.u32(value.CTSFactorCount)
	tuples := []RBAUTHPayloadTuple{
		value.Payload.STCNumeric, value.Payload.STCEncoded,
		value.Payload.CTSNumeric, value.Payload.CTSEncoded,
	}
	for _, tuple := range tuples {
		writer.digest(tuple.AggregateDigest)
	}
	for _, tuple := range tuples {
		writer.u64(tuple.RecordBytes)
	}
	writer.u64(value.BuildWallNanoseconds)
	writer.u64(value.BuildPeakRSSBytes)
	writer.stringUnchecked(value.ArtifactState)
	writer.digest(value.ArtifactManifestDigest)
	return writer.bytes(), nil
}

func validateRBDFTBuildReceipt(value RBDFTBuildReceiptReport) error {
	if isZeroDigest(value.BuildPermitDigest) || isZeroDigest(value.PreparedParameterDigest) ||
		isZeroDigest(value.LifecycleDigest) || isZeroDigest(value.ArtifactManifestDigest) {
		return malformedRBDFT("build receipt has an empty named digest")
	}
	if value.BuilderID != RBDFTBuilderID || value.DigestID != RBDFTDigestID ||
		value.AllocationID != RBDFTAllocationID || value.ReleaseID != RBDFTReleaseID ||
		value.OwnershipID != RBDFTOwnershipID {
		return malformedRBDFT("build receipt identifier or identifier order changed")
	}
	if value.GeneratorPrecisionBits != 256 || value.EncoderPrecisionBits != 256 ||
		value.DefaultCounterDelta != 0 || value.ExplicitWholeCounterDelta != 0 ||
		value.RawNumericCounterDelta != 0 || value.ObservedStreamingCounterDelta != 2 ||
		value.MaxLiveNumeric != 1 || value.STCFactorCount != 2 || value.CTSFactorCount != 3 {
		return malformedRBDFT("build receipt precision, counter, liveness, or factor counts changed")
	}
	for _, tuple := range []RBAUTHPayloadTuple{
		value.Payload.STCNumeric, value.Payload.STCEncoded,
		value.Payload.CTSNumeric, value.Payload.CTSEncoded,
	} {
		if isZeroDigest(tuple.AggregateDigest) || tuple.RecordBytes == 0 {
			return malformedRBDFT("build receipt aggregate tuple is empty")
		}
	}
	if value.BuildWallNanoseconds == 0 || value.BuildPeakRSSBytes == 0 {
		return malformedRBDFT("build receipt wall time or peak RSS is zero")
	}
	if value.ArtifactState != RBDFTPrivateUninstalledState {
		return malformedRBDFT("build receipt artifact state is not private-uninstalled")
	}
	return nil
}

// ValidateRBDFTBuildRecordLinks validates canonical grammar and every identity
// available to this pure-wire slice. It does not claim a live private artifact,
// lifecycle authority, numeric-factor payload, or encoded polynomial anchor.
func ValidateRBDFTBuildRecordLinks(
	records RBDFTBuildRecordSet,
	expectedBuildPermitDigest, expectedPreparedParameterDigest RBAUTHDigest,
) error {
	if isZeroDigest(expectedBuildPermitDigest) || isZeroDigest(expectedPreparedParameterDigest) {
		return blockedRBDFT("expected authorization identity is zero")
	}
	stcNumeric, err := ParseRBDFTNumericTransformAggregate(records.STCNumericAggregate)
	if err != nil {
		return err
	}
	stcEncoded, err := ParseRBDFTEncodedTransformAggregate(records.STCEncodedAggregate)
	if err != nil {
		return err
	}
	ctsNumeric, err := ParseRBDFTNumericTransformAggregate(records.CTSNumericAggregate)
	if err != nil {
		return err
	}
	ctsEncoded, err := ParseRBDFTEncodedTransformAggregate(records.CTSEncodedAggregate)
	if err != nil {
		return err
	}
	if stcNumeric.Role != RBDFTRoleSTC || stcEncoded.Role != RBDFTRoleSTC ||
		ctsNumeric.Role != RBDFTRoleCTS || ctsEncoded.Role != RBDFTRoleCTS {
		return blockedRBDFT("aggregate record role or order changed")
	}
	pair, err := ParseRBDFTArtifactPairAggregate(records.ArtifactPair)
	if err != nil {
		return err
	}
	lifecycle, err := ParseRBDFTLifecycle(records.Lifecycle)
	if err != nil {
		return err
	}
	if lifecycle.TerminalStatus != RBDFTLifecycleSuccess {
		return blockedRBDFT("a failure lifecycle cannot authorize a build receipt")
	}
	receipt, err := ParseRBDFTBuildReceipt(records.BuildReceipt)
	if err != nil {
		return err
	}

	payload := RBAUTHActualPayload{
		STCNumeric: rbdftAggregateTuple(records.STCNumericAggregate, stcNumeric),
		STCEncoded: rbdftAggregateTuple(records.STCEncodedAggregate, stcEncoded),
		CTSNumeric: rbdftAggregateTuple(records.CTSNumericAggregate, ctsNumeric),
		CTSEncoded: rbdftAggregateTuple(records.CTSEncodedAggregate, ctsEncoded),
	}
	pairIdentity := RBAUTHDigest(sha256.Sum256(records.ArtifactPair))
	lifecycleIdentity := RBAUTHDigest(sha256.Sum256(records.Lifecycle))
	if pair.BuildPermitDigest != expectedBuildPermitDigest ||
		receipt.BuildPermitDigest != expectedBuildPermitDigest ||
		receipt.PreparedParameterDigest != expectedPreparedParameterDigest {
		return blockedRBDFT("build-permit or prepared-parameter identity changed")
	}
	if pair.Payload != payload || receipt.Payload != payload {
		return blockedRBDFT("aggregate tuple role, order, digest, or byte ledger changed")
	}
	if receipt.LifecycleDigest != lifecycleIdentity || receipt.ArtifactManifestDigest != pairIdentity {
		return blockedRBDFT("lifecycle or artifact-pair record identity changed")
	}
	if receipt.STCFactorCount != stcNumeric.FactorCount || receipt.STCFactorCount != stcEncoded.FactorCount ||
		receipt.CTSFactorCount != ctsNumeric.FactorCount || receipt.CTSFactorCount != ctsEncoded.FactorCount {
		return blockedRBDFT("receipt and aggregate factor counts changed")
	}
	if err = validateRBDFTLifecycleLinks(lifecycle, stcNumeric, stcEncoded, ctsNumeric, ctsEncoded, pairIdentity); err != nil {
		return err
	}
	return nil
}

func rbdftAggregateTuple(encoded []byte, aggregate RBDFTTransformAggregateReport) RBAUTHPayloadTuple {
	return RBAUTHPayloadTuple{
		AggregateDigest: RBAUTHDigest(sha256.Sum256(encoded)),
		RecordBytes:     aggregate.AggregateRecordBytes,
	}
}

func validateRBDFTLifecycleLinks(
	lifecycle RBDFTLifecycleReport,
	stcNumeric, stcEncoded, ctsNumeric, ctsEncoded RBDFTTransformAggregateReport,
	pairIdentity RBAUTHDigest,
) error {
	for index := uint32(0); index < lifecycle.CompletedEventCount; index++ {
		event := lifecycle.events[index]
		switch event.Code {
		case RBDFTEventNumericDigested, RBDFTEventEncodedDigested:
			var aggregate RBDFTTransformAggregateReport
			switch {
			case event.Role == RBDFTRoleSTC && event.Code == RBDFTEventNumericDigested:
				aggregate = stcNumeric
			case event.Role == RBDFTRoleSTC && event.Code == RBDFTEventEncodedDigested:
				aggregate = stcEncoded
			case event.Role == RBDFTRoleCTS && event.Code == RBDFTEventNumericDigested:
				aggregate = ctsNumeric
			case event.Role == RBDFTRoleCTS && event.Code == RBDFTEventEncodedDigested:
				aggregate = ctsEncoded
			default:
				return blockedRBDFT("lifecycle factor digest role or kind changed")
			}
			if event.FactorIndex < 0 || uint32(event.FactorIndex) >= aggregate.FactorCount {
				return blockedRBDFT("lifecycle factor digest index is outside its aggregate")
			}
			factor := aggregate.Factors[uint32(event.FactorIndex)]
			if event.PayloadDigest != factor.Digest || event.Value != factor.RecordBytes {
				return blockedRBDFT("lifecycle factor digest or byte ledger changed")
			}
		case RBDFTEventArtifactSealed:
			if event.PayloadDigest != pairIdentity || event.Value != uint64(RBDFTArtifactPairRecordBytes) {
				return blockedRBDFT("lifecycle artifact-sealed identity changed")
			}
		}
	}
	return nil
}

func expectedRBDFTFactorCount(role byte) uint32 {
	switch role {
	case RBDFTRoleSTC:
		return 2
	case RBDFTRoleCTS:
		return 3
	default:
		return 0
	}
}

func checkedAddRBDFTUint64(left, right uint64) (uint64, bool) {
	if left > ^uint64(0)-right {
		return 0, false
	}
	return left + right, true
}

func parseRBDFTEnvelope(encoded []byte, expectedType byte, maximum int) (*rbdftReader, byte, error) {
	if len(encoded) > maximum {
		return nil, 0, malformedRBDFT("record exceeds its type-specific maximum")
	}
	if len(encoded) < rbdftHeaderBytes {
		return nil, 0, malformedRBDFT("record is truncated")
	}
	if !bytes.Equal(encoded[:len(RBDFTMagic)], []byte(RBDFTMagic)) || encoded[len(RBDFTMagic)] != expectedType {
		return nil, 0, malformedRBDFT("record magic or type changed")
	}
	return &rbdftReader{data: encoded[rbdftHeaderBytes:]}, encoded[len(RBDFTMagic)+1], nil
}

type rbdftWriter struct{ buffer []byte }

func (writer *rbdftWriter) raw(value []byte) { writer.buffer = append(writer.buffer, value...) }
func (writer *rbdftWriter) u8(value byte)    { writer.buffer = append(writer.buffer, value) }
func (writer *rbdftWriter) u32(value uint32) {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	writer.raw(encoded[:])
}
func (writer *rbdftWriter) i32(value int32) { writer.u32(uint32(value)) }
func (writer *rbdftWriter) u64(value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	writer.raw(encoded[:])
}
func (writer *rbdftWriter) digest(value RBAUTHDigest) { writer.raw(value[:]) }
func (writer *rbdftWriter) payloadTuple(value RBAUTHPayloadTuple) {
	writer.digest(value.AggregateDigest)
	writer.u64(value.RecordBytes)
}
func (writer *rbdftWriter) stringUnchecked(value string) {
	writer.u32(uint32(len(value)))
	writer.raw([]byte(value))
}
func (writer *rbdftWriter) header(recordType, role byte) {
	writer.raw([]byte(RBDFTMagic))
	writer.u8(recordType)
	writer.u8(role)
}
func (writer *rbdftWriter) bytes() []byte { return append([]byte(nil), writer.buffer...) }

type rbdftReader struct {
	data   []byte
	offset int
}

func (reader *rbdftReader) remaining() int { return len(reader.data) - reader.offset }
func (reader *rbdftReader) take(length int) ([]byte, error) {
	if length < 0 || reader.offset < 0 || length > reader.remaining() {
		return nil, malformedRBDFT("record is truncated or length overflowed")
	}
	start := reader.offset
	reader.offset += length
	return reader.data[start:reader.offset], nil
}
func (reader *rbdftReader) u8() (byte, error) {
	value, err := reader.take(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}
func (reader *rbdftReader) u32() (uint32, error) {
	value, err := reader.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(value), nil
}
func (reader *rbdftReader) i32() (int32, error) {
	value, err := reader.u32()
	return int32(value), err
}
func (reader *rbdftReader) u64() (uint64, error) {
	value, err := reader.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(value), nil
}
func (reader *rbdftReader) string() (string, error) {
	length, err := reader.u32()
	if err != nil {
		return "", err
	}
	if length == 0 || length > rbdftMaxStringBytes {
		return "", malformedRBDFT("string length is outside [1,256]")
	}
	value, err := reader.take(int(length))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", malformedRBDFT("string is not valid UTF-8")
	}
	return string(value), nil
}
func (reader *rbdftReader) nonzeroDigest() (RBAUTHDigest, error) {
	result, err := reader.digest()
	if err != nil {
		return RBAUTHDigest{}, err
	}
	if isZeroDigest(result) {
		return RBAUTHDigest{}, malformedRBDFT("digest is all zero")
	}
	return result, nil
}
func (reader *rbdftReader) digest() (RBAUTHDigest, error) {
	value, err := reader.take(rbdftDigestBytes)
	if err != nil {
		return RBAUTHDigest{}, err
	}
	var result RBAUTHDigest
	copy(result[:], value)
	return result, nil
}
func (reader *rbdftReader) payloadTuple() (RBAUTHPayloadTuple, error) {
	digest, err := reader.nonzeroDigest()
	if err != nil {
		return RBAUTHPayloadTuple{}, err
	}
	recordBytes, err := reader.u64()
	if err != nil {
		return RBAUTHPayloadTuple{}, err
	}
	if recordBytes == 0 {
		return RBAUTHPayloadTuple{}, malformedRBDFT("payload tuple byte count is zero")
	}
	return RBAUTHPayloadTuple{AggregateDigest: digest, RecordBytes: recordBytes}, nil
}
func (reader *rbdftReader) finish() error {
	if reader.remaining() != 0 {
		return malformedRBDFT("record has trailing or unknown body data")
	}
	return nil
}

func malformedRBDFT(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrRBDFTMalformed, fmt.Sprintf(format, values...))
}

func blockedRBDFT(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrRBDFTBlocked, fmt.Sprintf(format, values...))
}
