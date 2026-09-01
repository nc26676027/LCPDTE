// Package secureeval contains the private Route-B execution seam.
package secureeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

const (
	RBAUTHMagic = "LCPDTE-RBAUTH-v1"

	RBAUTHArtifactBuildSpecType   byte = 0x01
	RBAUTHArtifactBuildPermitType byte = 0x02
	RBAUTHReadySpecType           byte = 0x03
	RBAUTHReadyPermitType         byte = 0x04

	RBAUTHLiteralDigestDomain byte = 0x81
	RBAUTHScalingDigestDomain byte = 0x82
	RBAUTHScratchDigestDomain byte = 0x83
	RBAUTHPeakDigestDomain    byte = 0x84

	RBAUTHRoleSTC        byte = 0x01
	RBAUTHRoleCTS        byte = 0x02
	RBAUTHPhaseRaw       byte = 0x01
	RBAUTHPhaseEffective byte = 0x02

	RBAUTHConstructionOrderSTCDropCTS byte = 0x01

	RBAUTHArtifactBuildSpecMaxBytes   = 3212
	RBAUTHArtifactBuildPermitMaxBytes = 3244
	RBAUTHReadySpecMaxBytes           = 1943
	RBAUTHReadyPermitMaxBytes         = 1975

	rbauthMaxStringBytes = 256
	rbauthSealBytes      = sha256.Size
	rbauthHeaderBytes    = len(RBAUTHMagic) + 1

	rbauthFullArtifactPeakBytes        uint64 = 2_968_063_744
	rbauthPreGuardIncrementalPeakBytes uint64 = 7_129_861_888
	rbauthGuardedRequirementBytes      uint64 = 7_842_848_076
	rbauthDuplicateDefaultBytes        uint64 = 2_641_362_944
)

const (
	RBAUTHAdaptationLabel    = "lattigo_packing_adaptation_r1"
	RBAUTHBuildEvidenceScope = "route_b_artifact_build_authorization_only"
	RBAUTHReadyEvidenceScope = "route_b_artifact_ready_authorization_only"
	RBAUTHMaturity           = "route_b_construction_contract_only_unverified"

	RBAUTHBuilderID    = "lattigo-route-b-prebuilt-dft-streaming-builder-v1"
	RBAUTHDigestID     = "sha256-canonical-streaming-binary-v1"
	RBAUTHAllocationID = "stc-then-cts-single-factor-v1"
	RBAUTHReleaseID    = "logical-reference-drop-v1"
	RBAUTHOwnershipID  = "private-exclusive-transfer-v1"

	RBAUTHPrivateUninstalledState = "private-uninstalled"
)

var (
	ErrRBAUTHMalformed = errors.New("secureeval: malformed RBAUTH-v1 record")
	ErrRBAUTHBlocked   = errors.New("secureeval: RBAUTH-v1 record blocked")
	ErrRBAUTHLineage   = errors.New("secureeval: RBAUTH-v1 lineage rejected")
)

// RBAUTHDigest is one raw SHA-256 identity. It is never hexadecimal on wire.
type RBAUTHDigest [sha256.Size]byte

// RBAUTHClassification is the shared, value-only claim classification.
type RBAUTHClassification struct {
	AdaptationLabel string
	EvidenceScope   string
	Maturity        string
	SourceFaithful  bool
	FullPacked      bool
}

// RBAUTHCapacityBinding is the explicit snapshot and its complete digest chain.
type RBAUTHCapacityBinding struct {
	SnapshotID             string
	TotalPhysicalBytes     uint64
	AvailablePhysicalBytes uint64

	CapacityPlanDigest   RBAUTHDigest
	CapacityProbeDigest  RBAUTHDigest
	CapacityReportDigest RBAUTHDigest
	CapacityPermitDigest RBAUTHDigest
	ParameterDigest      RBAUTHDigest
	ProfileDigest        RBAUTHDigest
	ShapeDigest          RBAUTHDigest
	PolicyDigest         RBAUTHDigest
}

// RBAUTHTransformDigests keeps role and preparation-phase identities separate.
type RBAUTHTransformDigests struct {
	RawSTCLiteralDigest       RBAUTHDigest
	RawSTCScalingDigest       RBAUTHDigest
	EffectiveSTCLiteralDigest RBAUTHDigest
	EffectiveSTCScalingDigest RBAUTHDigest
	RawCTSLiteralDigest       RBAUTHDigest
	RawCTSScalingDigest       RBAUTHDigest
	EffectiveCTSLiteralDigest RBAUTHDigest
	EffectiveCTSScalingDigest RBAUTHDigest
}

// RBAUTHScratchLedger is the accepted, named factor-streaming scratch ledger.
type RBAUTHScratchLedger struct {
	RootsBytes                   uint64
	Pow5Bytes                    uint64
	ABCLayerBytes                uint64
	LargestSTCNumericFactorBytes uint64
	LargestCTSNumericFactorBytes uint64
	STCPhaseMaximumBytes         uint64
	CTSPhaseMaximumBytes         uint64
	ArtifactEnvelopeBytes        uint64
	RemainingEnvelopeBytes       uint64
	Digest                       RBAUTHDigest
}

// RBAUTHPeakContract is the accepted L11 peak and duplicate-default ledger.
type RBAUTHPeakContract struct {
	FullArtifactPeakBytes          uint64
	PreGuardIncrementalPeakBytes   uint64
	GuardedRequirementBytes        uint64
	RemainingBelowLimitBytes       uint64
	ForbiddenDuplicateDefaultBytes uint64
	DuplicateDefaultExcessBytes    uint64
	Digest                         RBAUTHDigest
}

// ArtifactBuildSpec is payload-free pre-allocation evidence.
type ArtifactBuildSpec struct {
	Classification RBAUTHClassification
	Capacity       RBAUTHCapacityBinding

	PreparedParameterDigest RBAUTHDigest
	Transforms              RBAUTHTransformDigests

	GeneratorPrecisionBits uint32
	EncoderPrecisionBits   uint32
	BuilderID              string
	DigestID               string
	AllocationID           string
	ReleaseID              string
	OwnershipID            string
	ConstructionOrder      byte

	STCFactorCount    uint32
	STCDiagonalCounts [2]uint32
	CTSFactorCount    uint32
	CTSDiagonalCounts [3]uint32

	ExpectedDefaultWholeDelta      uint64
	ExpectedExplicitWholeDelta     uint64
	ExpectedRawNumericDelta        uint64
	ExpectedObservedStreamingDelta uint64

	Scratch RBAUTHScratchLedger
	Peak    RBAUTHPeakContract
}

// ArtifactBuildPermitReport is inert parsed evidence. A future live permit is
// a distinct type with an unexported lineage capability.
type ArtifactBuildPermitReport struct {
	BuildSpecDigest RBAUTHDigest
	Spec            ArtifactBuildSpec
}

// RBAUTHPayloadTuple identifies one observed RBDFT aggregate.
type RBAUTHPayloadTuple struct {
	AggregateDigest RBAUTHDigest
	RecordBytes     uint64
}

// RBAUTHActualPayload is the complete role-first, numeric-before-encoded tuple.
type RBAUTHActualPayload struct {
	STCNumeric RBAUTHPayloadTuple
	STCEncoded RBAUTHPayloadTuple
	CTSNumeric RBAUTHPayloadTuple
	CTSEncoded RBAUTHPayloadTuple
}

// ReadySpec is post-build value evidence. It carries identities, never handles.
type ReadySpec struct {
	Classification RBAUTHClassification
	Capacity       RBAUTHCapacityBinding

	PreparedParameterDigest    RBAUTHDigest
	BuildSpecDigest            RBAUTHDigest
	BuildPermitDigest          RBAUTHDigest
	BuildReceiptDigest         RBAUTHDigest
	ArtifactPairManifestDigest RBAUTHDigest
	ActualPayload              RBAUTHActualPayload
	ArtifactState              string
}

// ReadyPermitReport is inert parsed evidence and contains no lineage.
type ReadyPermitReport struct {
	ReadySpecDigest RBAUTHDigest
	Spec            ReadySpec
}

// RBAUTHMatrixLiteralIdentity is the canonical literal fragment input.
type RBAUTHMatrixLiteralIdentity struct {
	Role         byte
	Phase        byte
	Type         byte
	LogSlots     int32
	LevelQ       int32
	LevelP       int32
	Levels       []int32
	Format       byte
	BitReversed  bool
	LogBSGSRatio int32
}

// RBAUTHNullableBigFloat preserves every metadata field used by the scaling
// digest. Parsed values are reports; Accuracy is intentionally retained as
// identity metadata even though math/big does not expose a setter for it.
type RBAUTHNullableBigFloat struct {
	present      bool
	precision    uint32
	roundingMode byte
	accuracy     int8
	signbit      bool
	exactHex     string
}

func NewRBAUTHNullableBigFloat(value *big.Float) (RBAUTHNullableBigFloat, error) {
	if value == nil {
		return RBAUTHNullableBigFloat{}, nil
	}
	if value.IsInf() || value.Prec() == 0 || value.Prec() > 256 {
		return RBAUTHNullableBigFloat{}, malformedf("big.Float must be finite with precision in [1,256]")
	}
	result := RBAUTHNullableBigFloat{
		present:      true,
		precision:    uint32(value.Prec()),
		roundingMode: byte(value.Mode()),
		accuracy:     int8(value.Acc()),
		signbit:      value.Signbit(),
		exactHex:     string(value.Append(nil, 'x', -1)),
	}
	if err := result.validate(); err != nil {
		return RBAUTHNullableBigFloat{}, err
	}
	return result, nil
}

func (value RBAUTHNullableBigFloat) Present() bool      { return value.present }
func (value RBAUTHNullableBigFloat) Precision() uint32  { return value.precision }
func (value RBAUTHNullableBigFloat) RoundingMode() byte { return value.roundingMode }
func (value RBAUTHNullableBigFloat) Accuracy() int8     { return value.accuracy }
func (value RBAUTHNullableBigFloat) Signbit() bool      { return value.signbit }
func (value RBAUTHNullableBigFloat) ExactHex() string   { return value.exactHex }

func (value RBAUTHNullableBigFloat) BigFloat() (*big.Float, error) {
	if err := value.validate(); err != nil {
		return nil, err
	}
	if !value.present {
		return nil, nil
	}
	parsed, ok := new(big.Float).
		SetPrec(uint(value.precision)).
		SetMode(big.RoundingMode(value.roundingMode)).
		SetString(value.exactHex)
	if !ok {
		return nil, malformedf("cannot parse canonical big.Float")
	}
	return parsed, nil
}

func (value RBAUTHNullableBigFloat) MarshalBinary() ([]byte, error) {
	if err := value.validate(); err != nil {
		return nil, err
	}
	var writer wireWriter
	writer.bool(value.present)
	if value.present {
		writer.u32(value.precision)
		writer.u8(value.roundingMode)
		writer.u8(byte(value.accuracy))
		writer.bool(value.signbit)
		writer.stringUnchecked(value.exactHex)
	}
	return writer.bytes(), nil
}

func ParseRBAUTHNullableBigFloat(encoded []byte) (RBAUTHNullableBigFloat, error) {
	reader := wireReader{data: encoded}
	value, err := readNullableBigFloat(&reader)
	if err != nil {
		return RBAUTHNullableBigFloat{}, err
	}
	if reader.remaining() != 0 {
		return RBAUTHNullableBigFloat{}, malformedf("trailing big.Float bytes")
	}
	return value, nil
}

func (value RBAUTHNullableBigFloat) validate() error {
	if !value.present {
		if value.precision != 0 || value.roundingMode != 0 || value.accuracy != 0 || value.signbit || value.exactHex != "" {
			return malformedf("absent big.Float has metadata")
		}
		return nil
	}
	if value.precision == 0 || value.precision > 256 {
		return malformedf("big.Float precision is outside [1,256]")
	}
	if value.roundingMode > byte(big.ToPositiveInf) {
		return malformedf("invalid big.Float rounding mode")
	}
	if value.accuracy < -1 || value.accuracy > 1 {
		return malformedf("invalid big.Float accuracy")
	}
	if len(value.exactHex) == 0 || len(value.exactHex) > rbauthMaxStringBytes || !isLowerASCII(value.exactHex) {
		return malformedf("invalid big.Float exact-hex")
	}
	parsed, ok := new(big.Float).
		SetPrec(uint(value.precision)).
		SetMode(big.RoundingMode(value.roundingMode)).
		SetString(value.exactHex)
	if !ok || parsed.IsInf() || parsed.Signbit() != value.signbit || string(parsed.Append(nil, 'x', -1)) != value.exactHex {
		return malformedf("non-canonical big.Float exact-hex or sign")
	}
	return nil
}

func isLowerASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character > 0x7f || (character >= 'A' && character <= 'Z') {
			return false
		}
	}
	return true
}

// RBAUTHLiteralIdentity returns the typed literal-fragment digest.
func RBAUTHLiteralIdentity(value RBAUTHMatrixLiteralIdentity) (RBAUTHDigest, error) {
	if value.Role != RBAUTHRoleSTC && value.Role != RBAUTHRoleCTS {
		return RBAUTHDigest{}, malformedf("invalid literal role")
	}
	if value.Phase != RBAUTHPhaseRaw && value.Phase != RBAUTHPhaseEffective {
		return RBAUTHDigest{}, malformedf("invalid literal phase")
	}
	if len(value.Levels) == 0 || len(value.Levels) > 3 {
		return RBAUTHDigest{}, malformedf("literal levels count is outside [1,3]")
	}
	var writer wireWriter
	writer.raw([]byte(RBAUTHMagic))
	writer.u8(RBAUTHLiteralDigestDomain)
	writer.u8(value.Role)
	writer.u8(value.Phase)
	writer.u8(value.Type)
	writer.i32(value.LogSlots)
	writer.i32(value.LevelQ)
	writer.i32(value.LevelP)
	writer.u32(uint32(len(value.Levels)))
	for _, level := range value.Levels {
		writer.i32(level)
	}
	writer.u8(value.Format)
	writer.bool(value.BitReversed)
	writer.i32(value.LogBSGSRatio)
	return RBAUTHDigest(sha256.Sum256(writer.bytes())), nil
}

// RBAUTHScalingIdentity returns the typed nullable-scaling fragment digest.
func RBAUTHScalingIdentity(role, phase byte, value RBAUTHNullableBigFloat) (RBAUTHDigest, error) {
	if role != RBAUTHRoleSTC && role != RBAUTHRoleCTS {
		return RBAUTHDigest{}, malformedf("invalid scaling role")
	}
	if phase != RBAUTHPhaseRaw && phase != RBAUTHPhaseEffective {
		return RBAUTHDigest{}, malformedf("invalid scaling phase")
	}
	if phase == RBAUTHPhaseEffective && !value.present {
		return RBAUTHDigest{}, malformedf("effective scaling is absent")
	}
	encoded, err := value.MarshalBinary()
	if err != nil {
		return RBAUTHDigest{}, err
	}
	var writer wireWriter
	writer.raw([]byte(RBAUTHMagic))
	writer.u8(RBAUTHScalingDigestDomain)
	writer.u8(role)
	writer.u8(phase)
	writer.raw(encoded)
	return RBAUTHDigest(sha256.Sum256(writer.bytes())), nil
}

func RBAUTHScratchIdentity(value RBAUTHScratchLedger) RBAUTHDigest {
	var writer wireWriter
	writer.raw([]byte(RBAUTHMagic))
	writer.u8(RBAUTHScratchDigestDomain)
	writeScratchFields(&writer, value)
	return RBAUTHDigest(sha256.Sum256(writer.bytes()))
}

func RBAUTHPeakIdentity(value RBAUTHPeakContract) RBAUTHDigest {
	var writer wireWriter
	writer.raw([]byte(RBAUTHMagic))
	writer.u8(RBAUTHPeakDigestDomain)
	writePeakFields(&writer, value)
	return RBAUTHDigest(sha256.Sum256(writer.bytes()))
}

func (value ArtifactBuildSpec) MarshalBinary() ([]byte, error) {
	if err := validateBuildSpecFraming(value); err != nil {
		return nil, err
	}
	return marshalRecord(RBAUTHArtifactBuildSpecType, RBAUTHArtifactBuildSpecMaxBytes, func(writer *wireWriter) {
		writeBuildSpecBody(writer, value)
	})
}

func (value ArtifactBuildPermitReport) MarshalBinary() ([]byte, error) {
	if isZeroDigest(value.BuildSpecDigest) {
		return nil, malformedf("zero build-spec digest")
	}
	if err := validateBuildSpecFraming(value.Spec); err != nil {
		return nil, err
	}
	return marshalRecord(RBAUTHArtifactBuildPermitType, RBAUTHArtifactBuildPermitMaxBytes, func(writer *wireWriter) {
		writer.digest(value.BuildSpecDigest)
		writeBuildSpecBody(writer, value.Spec)
	})
}

func (value ReadySpec) MarshalBinary() ([]byte, error) {
	if err := validateReadySpecFraming(value); err != nil {
		return nil, err
	}
	return marshalRecord(RBAUTHReadySpecType, RBAUTHReadySpecMaxBytes, func(writer *wireWriter) {
		writeReadySpecBody(writer, value)
	})
}

func (value ReadyPermitReport) MarshalBinary() ([]byte, error) {
	if isZeroDigest(value.ReadySpecDigest) {
		return nil, malformedf("zero ready-spec digest")
	}
	if err := validateReadySpecFraming(value.Spec); err != nil {
		return nil, err
	}
	return marshalRecord(RBAUTHReadyPermitType, RBAUTHReadyPermitMaxBytes, func(writer *wireWriter) {
		writer.digest(value.ReadySpecDigest)
		writeReadySpecBody(writer, value.Spec)
	})
}

func ParseArtifactBuildSpec(encoded []byte) (ArtifactBuildSpec, error) {
	reader, err := parseEnvelope(encoded, RBAUTHArtifactBuildSpecType, RBAUTHArtifactBuildSpecMaxBytes)
	if err != nil {
		return ArtifactBuildSpec{}, err
	}
	value, err := readBuildSpecBody(reader)
	if err != nil {
		return ArtifactBuildSpec{}, err
	}
	if err = reader.finish(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	return value, nil
}

func ParseArtifactBuildPermit(encoded []byte) (ArtifactBuildPermitReport, error) {
	reader, err := parseEnvelope(encoded, RBAUTHArtifactBuildPermitType, RBAUTHArtifactBuildPermitMaxBytes)
	if err != nil {
		return ArtifactBuildPermitReport{}, err
	}
	digest, err := reader.digest()
	if err != nil {
		return ArtifactBuildPermitReport{}, err
	}
	spec, err := readBuildSpecBody(reader)
	if err != nil {
		return ArtifactBuildPermitReport{}, err
	}
	if err = reader.finish(); err != nil {
		return ArtifactBuildPermitReport{}, err
	}
	return ArtifactBuildPermitReport{BuildSpecDigest: digest, Spec: spec}, nil
}

func ParseReadySpec(encoded []byte) (ReadySpec, error) {
	reader, err := parseEnvelope(encoded, RBAUTHReadySpecType, RBAUTHReadySpecMaxBytes)
	if err != nil {
		return ReadySpec{}, err
	}
	value, err := readReadySpecBody(reader)
	if err != nil {
		return ReadySpec{}, err
	}
	if err = reader.finish(); err != nil {
		return ReadySpec{}, err
	}
	return value, nil
}

func ParseReadyPermit(encoded []byte) (ReadyPermitReport, error) {
	reader, err := parseEnvelope(encoded, RBAUTHReadyPermitType, RBAUTHReadyPermitMaxBytes)
	if err != nil {
		return ReadyPermitReport{}, err
	}
	digest, err := reader.digest()
	if err != nil {
		return ReadyPermitReport{}, err
	}
	spec, err := readReadySpecBody(reader)
	if err != nil {
		return ReadyPermitReport{}, err
	}
	if err = reader.finish(); err != nil {
		return ReadyPermitReport{}, err
	}
	return ReadyPermitReport{ReadySpecDigest: digest, Spec: spec}, nil
}

// RBAUTHRecordIdentity validates a complete record and returns its trailing
// seal. It intentionally never hashes the already sealed record again.
func RBAUTHRecordIdentity(encoded []byte) (RBAUTHDigest, error) {
	if len(encoded) < rbauthHeaderBytes+rbauthSealBytes || !bytes.Equal(encoded[:len(RBAUTHMagic)], []byte(RBAUTHMagic)) {
		return RBAUTHDigest{}, malformedf("invalid record identity input")
	}
	var err error
	switch encoded[len(RBAUTHMagic)] {
	case RBAUTHArtifactBuildSpecType:
		_, err = ParseArtifactBuildSpec(encoded)
	case RBAUTHArtifactBuildPermitType:
		_, err = ParseArtifactBuildPermit(encoded)
	case RBAUTHReadySpecType:
		_, err = ParseReadySpec(encoded)
	case RBAUTHReadyPermitType:
		_, err = ParseReadyPermit(encoded)
	default:
		err = malformedf("unknown RBAUTH-v1 record type")
	}
	if err != nil {
		return RBAUTHDigest{}, err
	}
	var result RBAUTHDigest
	copy(result[:], encoded[len(encoded)-rbauthSealBytes:])
	return result, nil
}

// ValidateEmbeddedIdentity checks the permit's cross-record link without
// inventing a live capability.
func (value ArtifactBuildPermitReport) ValidateEmbeddedIdentity() error {
	record, err := value.Spec.MarshalBinary()
	if err != nil {
		return err
	}
	identity, err := RBAUTHRecordIdentity(record)
	if err != nil {
		return err
	}
	if value.BuildSpecDigest != identity {
		return blockedf("build permit does not bind its embedded build spec")
	}
	return nil
}

func (value ReadyPermitReport) ValidateEmbeddedIdentity() error {
	record, err := value.Spec.MarshalBinary()
	if err != nil {
		return err
	}
	identity, err := RBAUTHRecordIdentity(record)
	if err != nil {
		return err
	}
	if value.ReadySpecDigest != identity {
		return blockedf("ready permit does not bind its embedded ready spec")
	}
	return nil
}

// ValidateLinks verifies the four records named by a ReadySpec. Full RBDFT
// grammar validation belongs to the observed-build slice; this method only
// enforces the frozen domain/type and identity rules.
func (value ReadySpec) ValidateLinks(buildSpecRecord, buildPermitRecord, buildReceiptRecord, pairManifestRecord []byte) error {
	if _, err := ParseArtifactBuildSpec(buildSpecRecord); err != nil {
		return err
	}
	buildSpecIdentity, err := RBAUTHRecordIdentity(buildSpecRecord)
	if err != nil {
		return err
	}
	buildPermit, err := ParseArtifactBuildPermit(buildPermitRecord)
	if err != nil {
		return err
	}
	if err = buildPermit.ValidateEmbeddedIdentity(); err != nil {
		return err
	}
	buildPermitIdentity, err := RBAUTHRecordIdentity(buildPermitRecord)
	if err != nil {
		return err
	}
	if err = validateRBDFTHeader(buildReceiptRecord, 0x07); err != nil {
		return err
	}
	if err = validateRBDFTHeader(pairManifestRecord, 0x05); err != nil {
		return err
	}
	receiptIdentity := RBAUTHDigest(sha256.Sum256(buildReceiptRecord))
	manifestIdentity := RBAUTHDigest(sha256.Sum256(pairManifestRecord))
	if value.BuildSpecDigest != buildSpecIdentity || buildPermit.BuildSpecDigest != buildSpecIdentity ||
		value.BuildPermitDigest != buildPermitIdentity ||
		value.BuildReceiptDigest != receiptIdentity || value.ArtifactPairManifestDigest != manifestIdentity {
		return blockedf("ready cross-record identity changed")
	}
	return nil
}

func validateRBDFTHeader(encoded []byte, recordType byte) error {
	magic := []byte("LCPDTE-RBDFT-v1\x00")
	if len(encoded) < len(magic)+2 || !bytes.Equal(encoded[:len(magic)], magic) ||
		encoded[len(magic)] != recordType || encoded[len(magic)+1] != 0 {
		return malformedf("invalid RBDFT-v1 linked record")
	}
	return nil
}

// ValidateFrozenSemantics checks the wire-known constants only. Current
// capacity/preparation/payload authority remains the later authorizer's job.
func (value ArtifactBuildSpec) ValidateFrozenSemantics() error {
	expectedScratch := defaultRBAUTHScratchLedger()
	expectedPeak, err := rbauthPeakContractForCapacity(
		value.Capacity.TotalPhysicalBytes, value.Capacity.AvailablePhysicalBytes,
	)
	if err != nil {
		return err
	}
	if value.Classification != (RBAUTHClassification{
		AdaptationLabel: RBAUTHAdaptationLabel, EvidenceScope: RBAUTHBuildEvidenceScope, Maturity: RBAUTHMaturity,
	}) || value.GeneratorPrecisionBits != 256 || value.EncoderPrecisionBits != 256 ||
		value.BuilderID != RBAUTHBuilderID || value.DigestID != RBAUTHDigestID ||
		value.AllocationID != RBAUTHAllocationID || value.ReleaseID != RBAUTHReleaseID ||
		value.OwnershipID != RBAUTHOwnershipID || value.ConstructionOrder != RBAUTHConstructionOrderSTCDropCTS ||
		value.STCFactorCount != 2 || value.STCDiagonalCounts != [2]uint32{63, 64} ||
		value.CTSFactorCount != 3 || value.CTSDiagonalCounts != [3]uint32{16, 31, 15} ||
		value.ExpectedDefaultWholeDelta != 0 || value.ExpectedExplicitWholeDelta != 0 ||
		value.ExpectedRawNumericDelta != 0 || value.ExpectedObservedStreamingDelta != 2 ||
		value.Scratch != expectedScratch || value.Peak != expectedPeak {
		return blockedf("build wire semantics differ from the frozen Route-B contract")
	}
	return nil
}

func (value ArtifactBuildPermitReport) ValidateFrozenSemantics() error {
	if err := value.ValidateEmbeddedIdentity(); err != nil {
		return err
	}
	return value.Spec.ValidateFrozenSemantics()
}

func (value ReadySpec) ValidateFrozenSemantics() error {
	if value.Classification != (RBAUTHClassification{
		AdaptationLabel: RBAUTHAdaptationLabel, EvidenceScope: RBAUTHReadyEvidenceScope, Maturity: RBAUTHMaturity,
	}) || value.ArtifactState != RBAUTHPrivateUninstalledState {
		return blockedf("ready wire semantics differ from the frozen Route-B contract")
	}
	for _, tuple := range []RBAUTHPayloadTuple{
		value.ActualPayload.STCNumeric, value.ActualPayload.STCEncoded,
		value.ActualPayload.CTSNumeric, value.ActualPayload.CTSEncoded,
	} {
		if tuple.RecordBytes == 0 {
			return blockedf("ready payload byte count is zero")
		}
	}
	return nil
}

func (value ReadyPermitReport) ValidateFrozenSemantics() error {
	if err := value.ValidateEmbeddedIdentity(); err != nil {
		return err
	}
	return value.Spec.ValidateFrozenSemantics()
}

func defaultRBAUTHScratchLedger() RBAUTHScratchLedger {
	value := RBAUTHScratchLedger{
		RootsBytes: 2097408, Pow5Bytes: 32776, ABCLayerBytes: 1572864,
		LargestSTCNumericFactorBytes: 33554432, LargestCTSNumericFactorBytes: 16252928,
		STCPhaseMaximumBytes: 70811912, CTSPhaseMaximumBytes: 36208904,
		ArtifactEnvelopeBytes: 81264640, RemainingEnvelopeBytes: 10452728,
	}
	value.Digest = RBAUTHScratchIdentity(value)
	return value
}

func defaultRBAUTHPeakContract() RBAUTHPeakContract {
	value := RBAUTHPeakContract{
		FullArtifactPeakBytes: rbauthFullArtifactPeakBytes, PreGuardIncrementalPeakBytes: rbauthPreGuardIncrementalPeakBytes,
		GuardedRequirementBytes: rbauthGuardedRequirementBytes, RemainingBelowLimitBytes: 2_585_547_267,
		ForbiddenDuplicateDefaultBytes: rbauthDuplicateDefaultBytes, DuplicateDefaultExcessBytes: 55_815_677,
	}
	value.Digest = RBAUTHPeakIdentity(value)
	return value
}

func rbauthPeakContractForCapacity(totalPhysicalBytes, availablePhysicalBytes uint64) (RBAUTHPeakContract, error) {
	return rbauthPeakContractForRequirement(
		totalPhysicalBytes, availablePhysicalBytes, rbauthPreGuardIncrementalPeakBytes,
	)
}

func rbauthPeakContractForRequirement(
	totalPhysicalBytes, availablePhysicalBytes, preGuardIncrementalPeakBytes uint64,
) (RBAUTHPeakContract, error) {
	if totalPhysicalBytes == 0 || availablePhysicalBytes > totalPhysicalBytes {
		return RBAUTHPeakContract{}, blockedf("physical-memory sample is invalid")
	}
	if preGuardIncrementalPeakBytes == 0 {
		return RBAUTHPeakContract{}, blockedf("incremental peak requirement is zero")
	}
	if totalPhysicalBytes > ^uint64(0)/4 {
		return RBAUTHPeakContract{}, blockedf("physical-memory policy limit overflowed")
	}
	limit := (totalPhysicalBytes * 4) / 5
	used := totalPhysicalBytes - availablePhysicalBytes
	guard := preGuardIncrementalPeakBytes / 10
	if guard < 536_870_912 {
		guard = 536_870_912
	}
	if preGuardIncrementalPeakBytes > ^uint64(0)-guard {
		return RBAUTHPeakContract{}, blockedf("guarded incremental peak overflowed")
	}
	guardedRequirementBytes := preGuardIncrementalPeakBytes + guard
	if used > ^uint64(0)-guardedRequirementBytes {
		return RBAUTHPeakContract{}, blockedf("projected physical-memory use overflowed")
	}
	projected := used + guardedRequirementBytes
	if projected >= limit {
		return RBAUTHPeakContract{}, blockedf("projected physical-memory use is not below the strict limit")
	}
	remaining := limit - projected
	excess := uint64(0)
	if remaining < rbauthDuplicateDefaultBytes {
		excess = rbauthDuplicateDefaultBytes - remaining
	}
	value := RBAUTHPeakContract{
		FullArtifactPeakBytes:          rbauthFullArtifactPeakBytes,
		PreGuardIncrementalPeakBytes:   preGuardIncrementalPeakBytes,
		GuardedRequirementBytes:        guardedRequirementBytes,
		RemainingBelowLimitBytes:       remaining,
		ForbiddenDuplicateDefaultBytes: rbauthDuplicateDefaultBytes,
		DuplicateDefaultExcessBytes:    excess,
	}
	value.Digest = RBAUTHPeakIdentity(value)
	return value, nil
}

func validateBuildSpecFraming(value ArtifactBuildSpec) error {
	if err := validateClassification(value.Classification); err != nil {
		return err
	}
	if err := validateCapacity(value.Capacity); err != nil {
		return err
	}
	for _, digest := range append([]RBAUTHDigest{value.PreparedParameterDigest}, transformDigestSlice(value.Transforms)...) {
		if isZeroDigest(digest) {
			return malformedf("zero build digest")
		}
	}
	for _, field := range []string{value.BuilderID, value.DigestID, value.AllocationID, value.ReleaseID, value.OwnershipID} {
		if err := validateString(field); err != nil {
			return err
		}
	}
	if isZeroDigest(value.Scratch.Digest) || isZeroDigest(value.Peak.Digest) {
		return malformedf("zero scratch or peak digest")
	}
	return nil
}

func validateReadySpecFraming(value ReadySpec) error {
	if err := validateClassification(value.Classification); err != nil {
		return err
	}
	if err := validateCapacity(value.Capacity); err != nil {
		return err
	}
	for _, digest := range []RBAUTHDigest{
		value.PreparedParameterDigest, value.BuildSpecDigest, value.BuildPermitDigest,
		value.BuildReceiptDigest, value.ArtifactPairManifestDigest,
		value.ActualPayload.STCNumeric.AggregateDigest, value.ActualPayload.STCEncoded.AggregateDigest,
		value.ActualPayload.CTSNumeric.AggregateDigest, value.ActualPayload.CTSEncoded.AggregateDigest,
	} {
		if isZeroDigest(digest) {
			return malformedf("zero ready digest")
		}
	}
	return validateString(value.ArtifactState)
}

func validateClassification(value RBAUTHClassification) error {
	for _, field := range []string{value.AdaptationLabel, value.EvidenceScope, value.Maturity} {
		if err := validateString(field); err != nil {
			return err
		}
	}
	return nil
}

func validateCapacity(value RBAUTHCapacityBinding) error {
	if err := validateString(value.SnapshotID); err != nil {
		return err
	}
	if strings.TrimSpace(value.SnapshotID) == "" || value.TotalPhysicalBytes == 0 || value.AvailablePhysicalBytes > value.TotalPhysicalBytes {
		return malformedf("invalid physical-memory snapshot")
	}
	for _, digest := range capacityDigestSlice(value) {
		if isZeroDigest(digest) {
			return malformedf("zero capacity digest")
		}
	}
	return nil
}

func validateString(value string) error {
	if len(value) == 0 || len(value) > rbauthMaxStringBytes || !utf8.ValidString(value) {
		return malformedf("string length or UTF-8 is invalid")
	}
	return nil
}

func capacityDigestSlice(value RBAUTHCapacityBinding) []RBAUTHDigest {
	return []RBAUTHDigest{
		value.CapacityPlanDigest, value.CapacityProbeDigest, value.CapacityReportDigest,
		value.CapacityPermitDigest, value.ParameterDigest, value.ProfileDigest,
		value.ShapeDigest, value.PolicyDigest,
	}
}

func transformDigestSlice(value RBAUTHTransformDigests) []RBAUTHDigest {
	return []RBAUTHDigest{
		value.RawSTCLiteralDigest, value.RawSTCScalingDigest,
		value.EffectiveSTCLiteralDigest, value.EffectiveSTCScalingDigest,
		value.RawCTSLiteralDigest, value.RawCTSScalingDigest,
		value.EffectiveCTSLiteralDigest, value.EffectiveCTSScalingDigest,
	}
}

func writeBuildSpecBody(writer *wireWriter, value ArtifactBuildSpec) {
	writeClassification(writer, value.Classification)
	writeCapacity(writer, value.Capacity)
	writer.digest(value.PreparedParameterDigest)
	for _, digest := range transformDigestSlice(value.Transforms) {
		writer.digest(digest)
	}
	writer.u32(value.GeneratorPrecisionBits)
	writer.u32(value.EncoderPrecisionBits)
	writer.stringUnchecked(value.BuilderID)
	writer.stringUnchecked(value.DigestID)
	writer.stringUnchecked(value.AllocationID)
	writer.stringUnchecked(value.ReleaseID)
	writer.stringUnchecked(value.OwnershipID)
	writer.u8(value.ConstructionOrder)
	writer.u32(value.STCFactorCount)
	writer.u32(uint32(len(value.STCDiagonalCounts)))
	for _, count := range value.STCDiagonalCounts {
		writer.u32(count)
	}
	writer.u32(value.CTSFactorCount)
	writer.u32(uint32(len(value.CTSDiagonalCounts)))
	for _, count := range value.CTSDiagonalCounts {
		writer.u32(count)
	}
	writer.u64(value.ExpectedDefaultWholeDelta)
	writer.u64(value.ExpectedExplicitWholeDelta)
	writer.u64(value.ExpectedRawNumericDelta)
	writer.u64(value.ExpectedObservedStreamingDelta)
	writeScratchFields(writer, value.Scratch)
	writer.digest(value.Scratch.Digest)
	writePeakFields(writer, value.Peak)
	writer.digest(value.Peak.Digest)
}

func readBuildSpecBody(reader *wireReader) (ArtifactBuildSpec, error) {
	var value ArtifactBuildSpec
	var err error
	if value.Classification, err = readClassification(reader); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if value.Capacity, err = readCapacity(reader); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if value.PreparedParameterDigest, err = reader.digest(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	digests := make([]RBAUTHDigest, 8)
	for index := range digests {
		if digests[index], err = reader.digest(); err != nil {
			return ArtifactBuildSpec{}, err
		}
	}
	value.Transforms = RBAUTHTransformDigests{
		RawSTCLiteralDigest: digests[0], RawSTCScalingDigest: digests[1],
		EffectiveSTCLiteralDigest: digests[2], EffectiveSTCScalingDigest: digests[3],
		RawCTSLiteralDigest: digests[4], RawCTSScalingDigest: digests[5],
		EffectiveCTSLiteralDigest: digests[6], EffectiveCTSScalingDigest: digests[7],
	}
	if value.GeneratorPrecisionBits, err = reader.u32(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if value.EncoderPrecisionBits, err = reader.u32(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	stringsOut := make([]string, 5)
	for index := range stringsOut {
		if stringsOut[index], err = reader.string(); err != nil {
			return ArtifactBuildSpec{}, err
		}
	}
	value.BuilderID, value.DigestID, value.AllocationID, value.ReleaseID, value.OwnershipID =
		stringsOut[0], stringsOut[1], stringsOut[2], stringsOut[3], stringsOut[4]
	if value.ConstructionOrder, err = reader.u8(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if value.STCFactorCount, err = reader.u32(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	count, err := reader.u32()
	if err != nil {
		return ArtifactBuildSpec{}, err
	}
	if count != uint32(len(value.STCDiagonalCounts)) {
		return ArtifactBuildSpec{}, malformedf("invalid STC diagonal list count")
	}
	for index := range value.STCDiagonalCounts {
		if value.STCDiagonalCounts[index], err = reader.u32(); err != nil {
			return ArtifactBuildSpec{}, err
		}
	}
	if value.CTSFactorCount, err = reader.u32(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if count, err = reader.u32(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if count != uint32(len(value.CTSDiagonalCounts)) {
		return ArtifactBuildSpec{}, malformedf("invalid CTS diagonal list count")
	}
	for index := range value.CTSDiagonalCounts {
		if value.CTSDiagonalCounts[index], err = reader.u32(); err != nil {
			return ArtifactBuildSpec{}, err
		}
	}
	if value.ExpectedDefaultWholeDelta, err = reader.u64(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if value.ExpectedExplicitWholeDelta, err = reader.u64(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if value.ExpectedRawNumericDelta, err = reader.u64(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if value.ExpectedObservedStreamingDelta, err = reader.u64(); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if value.Scratch, err = readScratch(reader); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if value.Peak, err = readPeak(reader); err != nil {
		return ArtifactBuildSpec{}, err
	}
	if err = validateBuildSpecFraming(value); err != nil {
		return ArtifactBuildSpec{}, err
	}
	return value, nil
}

func writeReadySpecBody(writer *wireWriter, value ReadySpec) {
	writeClassification(writer, value.Classification)
	writeCapacity(writer, value.Capacity)
	writer.digest(value.PreparedParameterDigest)
	writer.digest(value.BuildSpecDigest)
	writer.digest(value.BuildPermitDigest)
	writer.digest(value.BuildReceiptDigest)
	writer.digest(value.ArtifactPairManifestDigest)
	for _, tuple := range []RBAUTHPayloadTuple{
		value.ActualPayload.STCNumeric, value.ActualPayload.STCEncoded,
		value.ActualPayload.CTSNumeric, value.ActualPayload.CTSEncoded,
	} {
		writer.digest(tuple.AggregateDigest)
		writer.u64(tuple.RecordBytes)
	}
	writer.stringUnchecked(value.ArtifactState)
}

func readReadySpecBody(reader *wireReader) (ReadySpec, error) {
	var value ReadySpec
	var err error
	if value.Classification, err = readClassification(reader); err != nil {
		return ReadySpec{}, err
	}
	if value.Capacity, err = readCapacity(reader); err != nil {
		return ReadySpec{}, err
	}
	if value.PreparedParameterDigest, err = reader.digest(); err != nil {
		return ReadySpec{}, err
	}
	if value.BuildSpecDigest, err = reader.digest(); err != nil {
		return ReadySpec{}, err
	}
	if value.BuildPermitDigest, err = reader.digest(); err != nil {
		return ReadySpec{}, err
	}
	if value.BuildReceiptDigest, err = reader.digest(); err != nil {
		return ReadySpec{}, err
	}
	if value.ArtifactPairManifestDigest, err = reader.digest(); err != nil {
		return ReadySpec{}, err
	}
	tuples := make([]RBAUTHPayloadTuple, 4)
	for index := range tuples {
		if tuples[index].AggregateDigest, err = reader.digest(); err != nil {
			return ReadySpec{}, err
		}
		if tuples[index].RecordBytes, err = reader.u64(); err != nil {
			return ReadySpec{}, err
		}
	}
	value.ActualPayload = RBAUTHActualPayload{
		STCNumeric: tuples[0], STCEncoded: tuples[1], CTSNumeric: tuples[2], CTSEncoded: tuples[3],
	}
	if value.ArtifactState, err = reader.string(); err != nil {
		return ReadySpec{}, err
	}
	if err = validateReadySpecFraming(value); err != nil {
		return ReadySpec{}, err
	}
	return value, nil
}

func writeClassification(writer *wireWriter, value RBAUTHClassification) {
	writer.stringUnchecked(value.AdaptationLabel)
	writer.stringUnchecked(value.EvidenceScope)
	writer.stringUnchecked(value.Maturity)
	writer.bool(value.SourceFaithful)
	writer.bool(value.FullPacked)
}

func readClassification(reader *wireReader) (RBAUTHClassification, error) {
	var value RBAUTHClassification
	var err error
	if value.AdaptationLabel, err = reader.string(); err != nil {
		return RBAUTHClassification{}, err
	}
	if value.EvidenceScope, err = reader.string(); err != nil {
		return RBAUTHClassification{}, err
	}
	if value.Maturity, err = reader.string(); err != nil {
		return RBAUTHClassification{}, err
	}
	if value.SourceFaithful, err = reader.bool(); err != nil {
		return RBAUTHClassification{}, err
	}
	if value.FullPacked, err = reader.bool(); err != nil {
		return RBAUTHClassification{}, err
	}
	return value, nil
}

func writeCapacity(writer *wireWriter, value RBAUTHCapacityBinding) {
	writer.stringUnchecked(value.SnapshotID)
	writer.u64(value.TotalPhysicalBytes)
	writer.u64(value.AvailablePhysicalBytes)
	for _, digest := range capacityDigestSlice(value) {
		writer.digest(digest)
	}
}

func readCapacity(reader *wireReader) (RBAUTHCapacityBinding, error) {
	var value RBAUTHCapacityBinding
	var err error
	if value.SnapshotID, err = reader.string(); err != nil {
		return RBAUTHCapacityBinding{}, err
	}
	if value.TotalPhysicalBytes, err = reader.u64(); err != nil {
		return RBAUTHCapacityBinding{}, err
	}
	if value.AvailablePhysicalBytes, err = reader.u64(); err != nil {
		return RBAUTHCapacityBinding{}, err
	}
	digests := make([]RBAUTHDigest, 8)
	for index := range digests {
		if digests[index], err = reader.digest(); err != nil {
			return RBAUTHCapacityBinding{}, err
		}
	}
	value.CapacityPlanDigest, value.CapacityProbeDigest, value.CapacityReportDigest, value.CapacityPermitDigest =
		digests[0], digests[1], digests[2], digests[3]
	value.ParameterDigest, value.ProfileDigest, value.ShapeDigest, value.PolicyDigest =
		digests[4], digests[5], digests[6], digests[7]
	if err = validateCapacity(value); err != nil {
		return RBAUTHCapacityBinding{}, err
	}
	return value, nil
}

func writeScratchFields(writer *wireWriter, value RBAUTHScratchLedger) {
	for _, field := range []uint64{
		value.RootsBytes, value.Pow5Bytes, value.ABCLayerBytes,
		value.LargestSTCNumericFactorBytes, value.LargestCTSNumericFactorBytes,
		value.STCPhaseMaximumBytes, value.CTSPhaseMaximumBytes,
		value.ArtifactEnvelopeBytes, value.RemainingEnvelopeBytes,
	} {
		writer.u64(field)
	}
}

func readScratch(reader *wireReader) (RBAUTHScratchLedger, error) {
	fields := make([]uint64, 9)
	var err error
	for index := range fields {
		if fields[index], err = reader.u64(); err != nil {
			return RBAUTHScratchLedger{}, err
		}
	}
	digest, err := reader.digest()
	if err != nil {
		return RBAUTHScratchLedger{}, err
	}
	return RBAUTHScratchLedger{
		RootsBytes: fields[0], Pow5Bytes: fields[1], ABCLayerBytes: fields[2],
		LargestSTCNumericFactorBytes: fields[3], LargestCTSNumericFactorBytes: fields[4],
		STCPhaseMaximumBytes: fields[5], CTSPhaseMaximumBytes: fields[6],
		ArtifactEnvelopeBytes: fields[7], RemainingEnvelopeBytes: fields[8], Digest: digest,
	}, nil
}

func writePeakFields(writer *wireWriter, value RBAUTHPeakContract) {
	for _, field := range []uint64{
		value.FullArtifactPeakBytes, value.PreGuardIncrementalPeakBytes,
		value.GuardedRequirementBytes, value.RemainingBelowLimitBytes,
		value.ForbiddenDuplicateDefaultBytes, value.DuplicateDefaultExcessBytes,
	} {
		writer.u64(field)
	}
}

func readPeak(reader *wireReader) (RBAUTHPeakContract, error) {
	fields := make([]uint64, 6)
	var err error
	for index := range fields {
		if fields[index], err = reader.u64(); err != nil {
			return RBAUTHPeakContract{}, err
		}
	}
	digest, err := reader.digest()
	if err != nil {
		return RBAUTHPeakContract{}, err
	}
	return RBAUTHPeakContract{
		FullArtifactPeakBytes: fields[0], PreGuardIncrementalPeakBytes: fields[1],
		GuardedRequirementBytes: fields[2], RemainingBelowLimitBytes: fields[3],
		ForbiddenDuplicateDefaultBytes: fields[4], DuplicateDefaultExcessBytes: fields[5], Digest: digest,
	}, nil
}

func readNullableBigFloat(reader *wireReader) (RBAUTHNullableBigFloat, error) {
	present, err := reader.bool()
	if err != nil {
		return RBAUTHNullableBigFloat{}, err
	}
	if !present {
		return RBAUTHNullableBigFloat{}, nil
	}
	precision, err := reader.u32()
	if err != nil {
		return RBAUTHNullableBigFloat{}, err
	}
	roundingMode, err := reader.u8()
	if err != nil {
		return RBAUTHNullableBigFloat{}, err
	}
	accuracyByte, err := reader.u8()
	if err != nil {
		return RBAUTHNullableBigFloat{}, err
	}
	signbit, err := reader.bool()
	if err != nil {
		return RBAUTHNullableBigFloat{}, err
	}
	exactHex, err := reader.string()
	if err != nil {
		return RBAUTHNullableBigFloat{}, err
	}
	value := RBAUTHNullableBigFloat{
		present: true, precision: precision, roundingMode: roundingMode,
		accuracy: int8(accuracyByte), signbit: signbit, exactHex: exactHex,
	}
	if err = value.validate(); err != nil {
		return RBAUTHNullableBigFloat{}, err
	}
	return value, nil
}

func marshalRecord(recordType byte, maximum int, writeBody func(*wireWriter)) ([]byte, error) {
	var writer wireWriter
	writer.raw([]byte(RBAUTHMagic))
	writer.u8(recordType)
	writeBody(&writer)
	if len(writer.buffer)+rbauthSealBytes > maximum {
		return nil, malformedf("record exceeds its type-specific maximum")
	}
	seal := sha256.Sum256(writer.buffer)
	writer.raw(seal[:])
	return writer.bytes(), nil
}

func parseEnvelope(encoded []byte, recordType byte, maximum int) (*wireReader, error) {
	if len(encoded) > maximum {
		return nil, malformedf("record exceeds its type-specific maximum")
	}
	if len(encoded) < rbauthHeaderBytes+rbauthSealBytes {
		return nil, malformedf("record is truncated")
	}
	if !bytes.Equal(encoded[:len(RBAUTHMagic)], []byte(RBAUTHMagic)) || encoded[len(RBAUTHMagic)] != recordType {
		return nil, malformedf("record magic or type changed")
	}
	bodyEnd := len(encoded) - rbauthSealBytes
	expected := sha256.Sum256(encoded[:bodyEnd])
	if !bytes.Equal(expected[:], encoded[bodyEnd:]) {
		return nil, malformedf("record seal changed")
	}
	return &wireReader{data: encoded[rbauthHeaderBytes:bodyEnd]}, nil
}

type wireWriter struct{ buffer []byte }

func (writer *wireWriter) raw(value []byte) { writer.buffer = append(writer.buffer, value...) }
func (writer *wireWriter) u8(value byte)    { writer.buffer = append(writer.buffer, value) }
func (writer *wireWriter) bool(value bool) {
	if value {
		writer.u8(1)
	} else {
		writer.u8(0)
	}
}
func (writer *wireWriter) u32(value uint32) {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	writer.raw(encoded[:])
}
func (writer *wireWriter) i32(value int32) { writer.u32(uint32(value)) }
func (writer *wireWriter) u64(value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	writer.raw(encoded[:])
}
func (writer *wireWriter) stringUnchecked(value string) {
	writer.u32(uint32(len(value)))
	writer.raw([]byte(value))
}
func (writer *wireWriter) digest(value RBAUTHDigest) { writer.raw(value[:]) }
func (writer *wireWriter) bytes() []byte             { return append([]byte(nil), writer.buffer...) }

type wireReader struct {
	data   []byte
	offset int
}

func (reader *wireReader) remaining() int { return len(reader.data) - reader.offset }
func (reader *wireReader) take(length int) ([]byte, error) {
	if length < 0 || reader.offset < 0 || length > reader.remaining() {
		return nil, malformedf("record is truncated or length overflowed")
	}
	start := reader.offset
	reader.offset += length
	return reader.data[start:reader.offset], nil
}
func (reader *wireReader) u8() (byte, error) {
	value, err := reader.take(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}
func (reader *wireReader) bool() (bool, error) {
	value, err := reader.u8()
	if err != nil {
		return false, err
	}
	if value > 1 {
		return false, malformedf("Boolean is not zero or one")
	}
	return value == 1, nil
}
func (reader *wireReader) u32() (uint32, error) {
	value, err := reader.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(value), nil
}
func (reader *wireReader) u64() (uint64, error) {
	value, err := reader.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(value), nil
}
func (reader *wireReader) string() (string, error) {
	length, err := reader.u32()
	if err != nil {
		return "", err
	}
	if length == 0 || length > rbauthMaxStringBytes {
		return "", malformedf("string length is outside [1,256]")
	}
	value, err := reader.take(int(length))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", malformedf("string is not valid UTF-8")
	}
	return string(value), nil
}
func (reader *wireReader) digest() (RBAUTHDigest, error) {
	value, err := reader.take(sha256.Size)
	if err != nil {
		return RBAUTHDigest{}, err
	}
	var result RBAUTHDigest
	copy(result[:], value)
	if isZeroDigest(result) {
		return RBAUTHDigest{}, malformedf("digest is all zero")
	}
	return result, nil
}
func (reader *wireReader) finish() error {
	if reader.remaining() != 0 {
		return malformedf("record has trailing or unknown body data")
	}
	return nil
}

func isZeroDigest(value RBAUTHDigest) bool { return value == (RBAUTHDigest{}) }

func malformedf(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrRBAUTHMalformed, fmt.Sprintf(format, values...))
}

func blockedf(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrRBAUTHBlocked, fmt.Sprintf(format, values...))
}
