package secureeval

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"slices"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	ltcommon "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const (
	rbdftScalarTextMaxBytes = 256
	rbdftStreamBufferBytes  = 32 * 1024

	rbdftL11VectorLength    = 2048
	rbdftL11STCPolyBytes    = 13_631_712
	rbdftL11CTSPolyBytes    = 14_680_304
	rbdftGeneratorPrecision = uint(256)
)

type rbdftFactorProfile struct {
	role              dft.ObservedTransformRole
	wireRole          byte
	factorCount       dft.ObservedFactorCount
	diagonalCounts    [3]uint32
	vectorLength      uint32
	expectedPolyBytes uint64
	canonicalL11      bool
}

type rbdftPayloadIdentity struct {
	digest [sha256.Size]byte
	bytes  uint64
}

type rbdftFactorEvidencePair struct {
	index   uint32
	numeric rbdftPayloadIdentity
	encoded rbdftPayloadIdentity
}

type rbdftPromotedFactorEvidence struct {
	role    dft.ObservedTransformRole
	count   dft.ObservedFactorCount
	factors [3]rbdftFactorEvidencePair
}

type rbdftConsumerFaultMode uint8

const (
	rbdftConsumerNoFault rbdftConsumerFaultMode = iota
	rbdftConsumerReturnErrorAfterProduct
	rbdftConsumerPanicAfterProduct
)

type routeBRBDFTFactorConsumer struct {
	params    ckks.Parameters
	encoder   *ckks.Encoder
	literal   dft.MatrixLiteral
	profile   rbdftFactorProfile
	tentative [3]rbdftFactorEvidencePair
	completed uint32
	failed    bool
	promoted  bool

	// faultMode is a package-private test seam. It carries no callback, factor,
	// input or product alias.
	faultMode rbdftConsumerFaultMode
}

func newRouteBRBDFTFactorConsumer(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	literal dft.MatrixLiteral,
	profile rbdftFactorProfile,
) (*routeBRBDFTFactorConsumer, error) {
	if encoder == nil || encoder.Prec() != rbdftGeneratorPrecision {
		return nil, malformedRBDFT("factor consumer encoder is nil or not 256-bit")
	}
	encoderParams := encoder.GetParameters()
	if !encoderParams.Equal(&params) {
		return nil, malformedRBDFT("factor consumer encoder parameters differ from the build parameters")
	}
	if err := rbdftValidateEffectiveLiteral(params, profile, literal); err != nil {
		return nil, err
	}
	return &routeBRBDFTFactorConsumer{
		params: params, encoder: encoder, literal: rbdftCloneLiteral(literal), profile: profile,
	}, nil
}

func (consumer *routeBRBDFTFactorConsumer) ConsumeObservedFactor(input dft.ObservedFactorInput) (
	product *dft.ObservedFactorProduct,
	err error,
) {
	var donor ltcommon.LinearTransformation
	var factor ltcommon.Diagonals[*bignum.Complex]
	var numericKeys []int
	var literal dft.MatrixLiteral
	defer func() {
		factor = nil
		numericKeys = nil
		literal = dft.MatrixLiteral{}
		donor = ltcommon.LinearTransformation{}
		input = dft.ObservedFactorInput{}
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("secureeval: RBDFT factor consumer panicked: %v", recovered)
		}
		if err != nil && consumer != nil {
			consumer.abortEvidence()
		}
	}()

	if consumer == nil || consumer.encoder == nil || consumer.failed || consumer.promoted {
		return nil, malformedRBDFT("factor consumer is nil, closed, failed, or already promoted")
	}
	index := input.Index()
	if input.Role() != consumer.profile.role || input.Count() != consumer.profile.factorCount ||
		index < 0 || uint32(index) != consumer.completed ||
		input.GeneratorPrecision() != rbdftGeneratorPrecision || input.EncoderPrecision() != rbdftGeneratorPrecision {
		return nil, malformedRBDFT("observed input role, index, count, order, or precision changed")
	}
	literal = input.Literal()
	if !rbdftEqualLiteralExact(literal, consumer.literal) {
		return nil, malformedRBDFT("observed input effective literal changed")
	}
	var active bool
	factor, active = input.BorrowedNumericFactor()
	if !active || factor == nil {
		return nil, malformedRBDFT("observed input numeric factor is inactive")
	}

	numericIdentity, err := rbdftDigestNumericFactor(
		consumer.profile, index, input.GeneratorPrecision(), factor,
	)
	if err != nil {
		return nil, err
	}
	numericKeys = factor.DiagonalsIndexList()
	scale, err := rbdftExpectedFactorScale(consumer.params, literal, int(index))
	if err != nil {
		return nil, err
	}
	donor = ltcommon.NewTransformation(consumer.params, ltcommon.Parameters{
		DiagonalsIndexList:        numericKeys,
		LevelQ:                    literal.LevelQ,
		LevelP:                    literal.LevelP,
		Scale:                     scale,
		LogDimensions:             ring.Dimensions{Rows: 0, Cols: literal.LogSlots},
		LogBabyStepGiantStepRatio: literal.LogBSGSRatio,
	})
	if err = ltcommon.Encode(consumer.encoder, factor, donor); err != nil {
		return nil, fmt.Errorf("secureeval: encode observed RBDFT factor: %w", err)
	}
	// The consumer's borrowed numeric alias is dropped immediately after
	// Encode. The vendor still owns its independent invocation reference until
	// this method returns and records NumericReferenceDropped.
	factor = nil
	encodedIdentity, err := rbdftDigestEncodedFactor(
		consumer.params, consumer.profile, index, input.EncoderPrecision(), literal, numericKeys, donor,
	)
	if err != nil {
		return nil, err
	}
	product, err = dft.NewObservedFactorProduct(
		input,
		numericIdentity.digest, numericIdentity.bytes,
		encodedIdentity.digest, encodedIdentity.bytes,
		&donor,
	)
	if err != nil {
		return nil, err
	}
	switch consumer.faultMode {
	case rbdftConsumerReturnErrorAfterProduct:
		return product, fmt.Errorf("secureeval: injected RBDFT consumer error after product")
	case rbdftConsumerPanicAfterProduct:
		panic("injected RBDFT consumer panic after product")
	case rbdftConsumerNoFault:
	default:
		return product, malformedRBDFT("factor consumer fault mode is invalid")
	}
	consumer.tentative[consumer.completed] = rbdftFactorEvidencePair{
		index: uint32(index), numeric: numericIdentity, encoded: encodedIdentity,
	}
	consumer.completed++
	return product, nil
}

func (consumer *routeBRBDFTFactorConsumer) promote(
	matrix dft.Matrix,
	trace dft.ObservedStreamingTrace,
) (rbdftPromotedFactorEvidence, error) {
	fail := func(err error) (rbdftPromotedFactorEvidence, error) {
		if consumer != nil {
			consumer.abortEvidence()
		}
		return rbdftPromotedFactorEvidence{}, err
	}
	if consumer == nil || consumer.failed || consumer.promoted || consumer.completed != uint32(consumer.profile.factorCount) {
		return fail(malformedRBDFT("factor evidence is incomplete, failed, or already promoted"))
	}
	if err := trace.Validate(); err != nil {
		return fail(fmt.Errorf("secureeval: validate observed factor trace: %w", err))
	}
	if trace.Status() != dft.ObservedStreamingSuccess || trace.Role() != consumer.profile.role ||
		trace.FactorCount() != consumer.profile.factorCount {
		return fail(malformedRBDFT("observed factor trace status, role, or count changed"))
	}
	if err := matrix.ValidateAgainst(consumer.params, consumer.literal); err != nil {
		return fail(fmt.Errorf("secureeval: validate observed DFT matrix: %w", err))
	}
	factors := trace.Factors()
	if len(factors) != int(consumer.profile.factorCount) {
		return fail(malformedRBDFT("observed trace factor evidence count changed"))
	}
	for index, factor := range factors {
		tentative := consumer.tentative[index]
		if factor.Role() != consumer.profile.role || factor.Index() != dft.ObservedFactorIndex(index) ||
			factor.Count() != consumer.profile.factorCount ||
			factor.NumericDigest() != tentative.numeric.digest || factor.NumericBytes() != tentative.numeric.bytes ||
			factor.EncodedDigest() != tentative.encoded.digest || factor.EncodedBytes() != tentative.encoded.bytes ||
			factor.Ownership() != dft.ObservedLinearTransformationOwnedByMatrix {
			return fail(malformedRBDFT("observed trace factor identity or ownership changed"))
		}
	}
	result := rbdftPromotedFactorEvidence{role: consumer.profile.role, count: consumer.profile.factorCount}
	copy(result.factors[:], consumer.tentative[:])
	consumer.tentative = [3]rbdftFactorEvidencePair{}
	consumer.completed = 0
	consumer.promoted = true
	return result, nil
}

func (consumer *routeBRBDFTFactorConsumer) abortEvidence() {
	consumer.tentative = [3]rbdftFactorEvidencePair{}
	consumer.completed = 0
	consumer.failed = true
}

func (consumer *routeBRBDFTFactorConsumer) dropEncoderReference() {
	if consumer == nil {
		return
	}
	consumer.encoder = nil
}

func rbdftCanonicalL11FactorProfile(role dft.ObservedTransformRole) (rbdftFactorProfile, error) {
	switch role {
	case dft.ObservedSlotsToCoeffs:
		return rbdftFactorProfile{
			role: role, wireRole: RBDFTRoleSTC, factorCount: 2,
			diagonalCounts: [3]uint32{63, 64}, vectorLength: rbdftL11VectorLength,
			expectedPolyBytes: rbdftL11STCPolyBytes, canonicalL11: true,
		}, nil
	case dft.ObservedCoeffsToSlots:
		return rbdftFactorProfile{
			role: role, wireRole: RBDFTRoleCTS, factorCount: 3,
			diagonalCounts: [3]uint32{16, 31, 15}, vectorLength: rbdftL11VectorLength,
			expectedPolyBytes: rbdftL11CTSPolyBytes, canonicalL11: true,
		}, nil
	default:
		return rbdftFactorProfile{}, malformedRBDFT("factor profile role is not STC or CTS")
	}
}

func (profile rbdftFactorProfile) validate() error {
	if profile.factorCount == 0 || profile.factorCount > 3 ||
		(profile.role == dft.ObservedSlotsToCoeffs && profile.wireRole != RBDFTRoleSTC) ||
		(profile.role == dft.ObservedCoeffsToSlots && profile.wireRole != RBDFTRoleCTS) ||
		(profile.role == dft.ObservedSlotsToCoeffs && profile.factorCount != 2) ||
		(profile.role == dft.ObservedCoeffsToSlots && profile.factorCount != 3) ||
		(profile.role != dft.ObservedSlotsToCoeffs && profile.role != dft.ObservedCoeffsToSlots) ||
		profile.vectorLength == 0 || profile.expectedPolyBytes == 0 {
		return malformedRBDFT("factor profile role, count, vector length, or polynomial size is invalid")
	}
	for index := uint32(0); index < uint32(profile.factorCount); index++ {
		if profile.diagonalCounts[index] == 0 {
			return malformedRBDFT("factor profile has an empty admitted diagonal count")
		}
	}
	for index := uint32(profile.factorCount); index < uint32(len(profile.diagonalCounts)); index++ {
		if profile.diagonalCounts[index] != 0 {
			return malformedRBDFT("factor profile has a trailing diagonal count")
		}
	}
	if profile.canonicalL11 {
		want, err := rbdftCanonicalL11FactorProfile(profile.role)
		if err != nil || profile != want {
			return malformedRBDFT("canonical L11 factor profile differs from the frozen role constants")
		}
	}
	return nil
}

type rbdftCheckedCountingWriter struct {
	target io.Writer
	count  uint64
}

func (writer *rbdftCheckedCountingWriter) Write(value []byte) (int, error) {
	if writer == nil || writer.target == nil {
		return 0, fmt.Errorf("secureeval: nil RBDFT stream target")
	}
	written, err := writer.target.Write(value)
	if written < 0 || written > len(value) {
		return 0, fmt.Errorf("secureeval: invalid RBDFT writer count %d for %d bytes", written, len(value))
	}
	if uint64(written) > ^uint64(0)-writer.count {
		return 0, fmt.Errorf("secureeval: RBDFT physical byte count overflow")
	}
	writer.count += uint64(written)
	if err != nil {
		return written, err
	}
	if written != len(value) {
		return written, io.ErrShortWrite
	}
	return written, nil
}

type rbdftBufferedStream struct {
	physical *rbdftCheckedCountingWriter
	buffered *bufio.Writer
}

func newRBDFTBufferedStream(target io.Writer) (*rbdftBufferedStream, error) {
	if target == nil {
		return nil, fmt.Errorf("secureeval: nil RBDFT stream target")
	}
	physical := &rbdftCheckedCountingWriter{target: target}
	return &rbdftBufferedStream{
		physical: physical,
		buffered: bufio.NewWriterSize(physical, rbdftStreamBufferBytes),
	}, nil
}

func (stream *rbdftBufferedStream) Write(value []byte) (int, error) {
	if stream == nil || stream.buffered == nil {
		return 0, fmt.Errorf("secureeval: nil RBDFT buffered stream")
	}
	return stream.buffered.Write(value)
}

func (stream *rbdftBufferedStream) flush() error {
	if stream == nil || stream.buffered == nil {
		return fmt.Errorf("secureeval: nil RBDFT buffered stream")
	}
	return stream.buffered.Flush()
}

func (stream *rbdftBufferedStream) physicalBytes() uint64 {
	if stream == nil || stream.physical == nil {
		return 0
	}
	return stream.physical.count
}

func rbdftDigestStreamRecord(writeRecord func(*rbdftBufferedStream) error) (rbdftPayloadIdentity, error) {
	if writeRecord == nil {
		return rbdftPayloadIdentity{}, malformedRBDFT("record stream callback is nil")
	}
	hasher := sha256.New()
	stream, err := newRBDFTBufferedStream(hasher)
	if err != nil {
		return rbdftPayloadIdentity{}, err
	}
	if err = writeRecord(stream); err != nil {
		return rbdftPayloadIdentity{}, err
	}
	if err = stream.flush(); err != nil {
		return rbdftPayloadIdentity{}, fmt.Errorf("secureeval: flush RBDFT record: %w", err)
	}
	var digest [sha256.Size]byte
	hasher.Sum(digest[:0])
	if stream.physicalBytes() == 0 || digest == ([sha256.Size]byte{}) {
		return rbdftPayloadIdentity{}, malformedRBDFT("streamed record identity is empty")
	}
	return rbdftPayloadIdentity{digest: digest, bytes: stream.physicalBytes()}, nil
}

func rbdftDigestNumericFactor(
	profile rbdftFactorProfile,
	index dft.ObservedFactorIndex,
	generatorPrecision uint,
	factor ltcommon.Diagonals[*bignum.Complex],
) (rbdftPayloadIdentity, error) {
	return rbdftDigestStreamRecord(func(stream *rbdftBufferedStream) error {
		return rbdftWriteNumericFactorRecord(stream, profile, index, generatorPrecision, factor)
	})
}

func rbdftWriteNumericFactorRecord(
	stream *rbdftBufferedStream,
	profile rbdftFactorProfile,
	index dft.ObservedFactorIndex,
	generatorPrecision uint,
	factor ltcommon.Diagonals[*bignum.Complex],
) error {
	if err := profile.validate(); err != nil {
		return err
	}
	if index < 0 || uint32(index) >= uint32(profile.factorCount) || generatorPrecision != rbdftGeneratorPrecision {
		return malformedRBDFT("numeric factor index or generator precision changed")
	}
	if factor == nil {
		return malformedRBDFT("numeric factor is nil")
	}
	keys := factor.DiagonalsIndexList()
	slices.Sort(keys)
	if len(keys) != int(profile.diagonalCounts[uint32(index)]) {
		return malformedRBDFT("numeric factor %d diagonal count is %d, want %d", index, len(keys), profile.diagonalCounts[uint32(index)])
	}

	if err := rbdftWriteHeader(stream, RBDFTNumericFactorType, profile.wireRole); err != nil {
		return err
	}
	for _, value := range []uint32{uint32(index), uint32(profile.factorCount), uint32(generatorPrecision), uint32(len(keys))} {
		if err := rbdftWriteU32(stream, value); err != nil {
			return err
		}
	}
	var scratch [rbdftScalarTextMaxBytes]byte
	for _, key := range keys {
		vector := factor[key]
		if len(vector) != int(profile.vectorLength) {
			return malformedRBDFT("numeric factor vector length differs from the admitted profile")
		}
		if err := rbdftWriteI64(stream, int64(key)); err != nil {
			return err
		}
		if err := rbdftWriteU32(stream, uint32(len(vector))); err != nil {
			return err
		}
		for _, value := range vector {
			if value == nil || value[0] == nil || value[1] == nil {
				return malformedRBDFT("numeric factor contains a nil complex scalar")
			}
			if err := rbdftWriteCanonicalScalar(stream, value[0], &scratch); err != nil {
				return err
			}
			if err := rbdftWriteCanonicalScalar(stream, value[1], &scratch); err != nil {
				return err
			}
		}
	}
	return nil
}

func rbdftDigestEncodedFactor(
	params ckks.Parameters,
	profile rbdftFactorProfile,
	index dft.ObservedFactorIndex,
	encoderPrecision uint,
	literal dft.MatrixLiteral,
	numericKeys []int,
	transformation ltcommon.LinearTransformation,
) (rbdftPayloadIdentity, error) {
	return rbdftDigestStreamRecord(func(stream *rbdftBufferedStream) error {
		return rbdftWriteEncodedFactorRecord(
			stream, params, profile, index, encoderPrecision, literal, numericKeys, transformation,
		)
	})
}

func rbdftWriteEncodedFactorRecord(
	stream *rbdftBufferedStream,
	params ckks.Parameters,
	profile rbdftFactorProfile,
	index dft.ObservedFactorIndex,
	encoderPrecision uint,
	literal dft.MatrixLiteral,
	numericKeys []int,
	transformation ltcommon.LinearTransformation,
) error {
	if err := rbdftValidateEffectiveLiteral(params, profile, literal); err != nil {
		return err
	}
	if index < 0 || uint32(index) >= uint32(profile.factorCount) || encoderPrecision != rbdftGeneratorPrecision {
		return malformedRBDFT("encoded factor index or encoder precision changed")
	}
	if len(numericKeys) != int(profile.diagonalCounts[uint32(index)]) {
		return malformedRBDFT("encoded factor numeric topology differs from the admitted diagonal count")
	}
	if err := rbdftValidateEncodedTransformation(params, profile, index, literal, numericKeys, transformation); err != nil {
		return err
	}

	if err := rbdftWriteHeader(stream, RBDFTEncodedFactorType, profile.wireRole); err != nil {
		return err
	}
	for _, value := range []uint32{uint32(index), uint32(profile.factorCount), uint32(encoderPrecision)} {
		if err := rbdftWriteU32(stream, value); err != nil {
			return err
		}
	}
	var scratch [rbdftScalarTextMaxBytes]byte
	if err := rbdftWriteEffectiveLiteral(stream, literal, &scratch); err != nil {
		return err
	}
	if err := rbdftWriteTransformationMetadata(stream, transformation, &scratch); err != nil {
		return err
	}
	keys := make([]int, 0, len(transformation.Vec))
	for key := range transformation.Vec {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if err := rbdftWriteU32(stream, uint32(len(keys))); err != nil {
		return err
	}
	for _, key := range keys {
		poly := transformation.Vec[key]
		declared := profile.expectedPolyBytes
		if err := rbdftWriteI64(stream, int64(key)); err != nil {
			return err
		}
		if err := rbdftWriteU64(stream, declared); err != nil {
			return err
		}
		if err := rbdftStreamSizedPayload(stream, declared, profile.expectedPolyBytes, poly); err != nil {
			return fmt.Errorf("secureeval: encoded factor diagonal %d: %w", key, err)
		}
	}
	return nil
}

type rbdftBinaryWriterTo interface {
	BinarySize() int
	WriteTo(io.Writer) (int64, error)
}

func rbdftStreamSizedPayload(stream *rbdftBufferedStream, declared, roleExpected uint64, source rbdftBinaryWriterTo) error {
	if stream == nil || source == nil || declared == 0 || roleExpected == 0 {
		return malformedRBDFT("encoded payload stream inputs are empty")
	}
	binarySize := source.BinarySize()
	if binarySize < 0 || uint64(binarySize) != declared || declared != roleExpected {
		return malformedRBDFT("encoded payload declared, BinarySize, and role-expected sizes disagree")
	}
	if err := stream.flush(); err != nil {
		return fmt.Errorf("flush encoded payload prefix: %w", err)
	}
	before := stream.physicalBytes()
	returned, err := source.WriteTo(stream.buffered)
	if err != nil {
		return fmt.Errorf("stream encoded payload: %w", err)
	}
	if err = stream.flush(); err != nil {
		return fmt.Errorf("flush encoded payload: %w", err)
	}
	after := stream.physicalBytes()
	if after < before {
		return malformedRBDFT("encoded payload physical byte count moved backwards")
	}
	physicalDelta := after - before
	if returned < 0 || uint64(returned) != declared || physicalDelta != declared {
		return malformedRBDFT("encoded payload declared, returned, and physical byte counts disagree")
	}
	return nil
}

func rbdftValidateEffectiveLiteral(params ckks.Parameters, profile rbdftFactorProfile, literal dft.MatrixLiteral) error {
	if err := profile.validate(); err != nil {
		return err
	}
	wantType := dft.HomomorphicDecode
	if profile.role == dft.ObservedCoeffsToSlots {
		wantType = dft.HomomorphicEncode
	}
	if literal.Type != wantType || literal.Format != dft.SplitRealAndImag || literal.LogSlots <= 0 ||
		literal.LogSlots >= 31 || uint32(1<<literal.LogSlots) != profile.vectorLength ||
		literal.LevelQ < 0 || literal.LevelQ > params.MaxLevelQ() ||
		literal.LevelP < -1 || literal.LevelP > params.MaxLevelP() ||
		literal.Scaling == nil || literal.BitReversed || literal.LogBSGSRatio != 0 ||
		len(literal.Levels) != int(profile.factorCount) {
		return malformedRBDFT("effective literal differs from the admitted role, dimensions, levels, format, or scaling")
	}
	for _, depth := range literal.Levels {
		if depth != 1 {
			return malformedRBDFT("effective literal factorization is not all depth-one groups")
		}
	}
	if err := rbdftValidateScalar(literal.Scaling); err != nil {
		return err
	}
	if profile.canonicalL11 {
		wantLevelQ := 18
		if profile.role == dft.ObservedCoeffsToSlots {
			wantLevelQ = 20
		}
		if params.LogN() != 16 || params.N() != 65_536 || params.LevelsConsumedPerRescaling() != 1 ||
			literal.LogSlots != 11 || literal.LevelQ != wantLevelQ || literal.LevelP != 6 {
			return malformedRBDFT("canonical L11 literal or parameter dimensions differ from the frozen Q/P schedule")
		}
	}
	expectedPolyBytes, ok := rbdftExpectedPolyBytes(params.N(), literal.LevelQ, literal.LevelP)
	if !ok || expectedPolyBytes != profile.expectedPolyBytes {
		return malformedRBDFT("effective literal Q/P/N polynomial size differs from the admitted profile")
	}
	return nil
}

func rbdftValidateEncodedTransformation(
	params ckks.Parameters,
	profile rbdftFactorProfile,
	index dft.ObservedFactorIndex,
	literal dft.MatrixLiteral,
	numericKeys []int,
	transformation ltcommon.LinearTransformation,
) error {
	if transformation.MetaData == nil || transformation.Vec == nil {
		return malformedRBDFT("encoded transformation metadata or Vec is nil")
	}
	expectedScale, err := rbdftExpectedFactorScale(params, literal, int(index))
	if err != nil {
		return err
	}
	wantN1, wantKeys, err := rbdftExpectedN1AndVecKeys(numericKeys, 1<<literal.LogSlots, literal.LogBSGSRatio)
	if err != nil {
		return err
	}
	gotKeys := make([]int, 0, len(transformation.Vec))
	for key := range transformation.Vec {
		gotKeys = append(gotKeys, key)
	}
	slices.Sort(gotKeys)
	metadata := transformation.MetaData
	if transformation.LevelQ != literal.LevelQ || transformation.LevelP != literal.LevelP ||
		transformation.LogBabyStepGiantStepRatio != literal.LogBSGSRatio || transformation.N1 != wantN1 ||
		!slices.Equal(gotKeys, wantKeys) || metadata.LogDimensions != (ring.Dimensions{Rows: 0, Cols: literal.LogSlots}) ||
		!metadata.IsBatched || metadata.IsBitReversed || !metadata.IsNTT || !metadata.IsMontgomery ||
		!rbdftEqualScaleExact(metadata.Scale, expectedScale) {
		return malformedRBDFT("encoded transformation scale, N1, topology, levels, dimensions, or flags changed")
	}
	if len(gotKeys) != int(profile.diagonalCounts[uint32(index)]) {
		return malformedRBDFT("encoded transformation Vec count differs from the admitted profile")
	}
	for _, key := range gotKeys {
		poly := transformation.Vec[key]
		if poly.LevelQ() != literal.LevelQ || poly.LevelP() != literal.LevelP || uint64(poly.BinarySize()) != profile.expectedPolyBytes {
			return malformedRBDFT("encoded transformation polynomial Q/P level or binary size changed")
		}
		for _, coefficients := range poly.Q.Coeffs {
			if len(coefficients) != params.N() {
				return malformedRBDFT("encoded transformation Q coefficient count changed")
			}
		}
		for _, coefficients := range poly.P.Coeffs {
			if len(coefficients) != params.N() {
				return malformedRBDFT("encoded transformation P coefficient count changed")
			}
		}
	}
	return nil
}

func rbdftExpectedFactorScale(params ckks.Parameters, literal dft.MatrixLiteral, factorIndex int) (rlwe.Scale, error) {
	if factorIndex < 0 || factorIndex >= literal.Depth(false) {
		return rlwe.Scale{}, malformedRBDFT("factor index is outside the effective scale schedule")
	}
	consumed := params.LevelsConsumedPerRescaling()
	if consumed <= 0 {
		return rlwe.Scale{}, malformedRBDFT("levels consumed per rescaling is not positive")
	}
	level := literal.LevelQ
	position := 0
	for _, groupDepth := range literal.Levels {
		if groupDepth <= 0 || level-consumed+1 < 0 || level > params.MaxLevelQ() {
			return rlwe.Scale{}, malformedRBDFT("effective scale group exceeds the Q chain")
		}
		scale := rlwe.NewScale(params.Q()[level])
		for offset := 1; offset < consumed; offset++ {
			scale = scale.Mul(rlwe.NewScale(params.Q()[level-offset]))
		}
		if groupDepth > 1 {
			exponent := new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(1)
			exponent.Quo(exponent, new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(int64(groupDepth)))
			scale.Value = *bignum.Pow(&scale.Value, exponent)
		}
		if factorIndex >= position && factorIndex < position+groupDepth {
			return scale, nil
		}
		position += groupDepth
		level -= consumed
	}
	return rlwe.Scale{}, malformedRBDFT("factor index did not resolve to an effective scale group")
}

func rbdftExpectedN1AndVecKeys(numericKeys []int, columns, logRatio int) (int, []int, error) {
	if columns <= 0 || columns&(columns-1) != 0 || len(numericKeys) == 0 || logRatio > 30 {
		return 0, nil, malformedRBDFT("numeric topology dimensions or BSGS ratio are invalid")
	}
	normalized := make([]int, len(numericKeys))
	seen := make(map[int]struct{}, len(numericKeys))
	for index, key := range numericKeys {
		normalized[index] = key & (columns - 1)
		if _, exists := seen[normalized[index]]; exists {
			return 0, nil, malformedRBDFT("numeric topology has duplicate normalized diagonals")
		}
		seen[normalized[index]] = struct{}{}
	}
	if logRatio < 0 {
		slices.Sort(normalized)
		return 0, normalized, nil
	}
	n1 := rbdftFindBestN1(normalized, columns, logRatio)
	if n1 <= 0 {
		return 0, nil, malformedRBDFT("numeric topology produced a non-positive N1")
	}
	vecSet := make(map[int]struct{}, len(normalized))
	for _, rotation := range normalized {
		giant := ((rotation / n1) * n1) & (columns - 1)
		baby := rotation & (n1 - 1)
		vecSet[giant+baby] = struct{}{}
	}
	keys := make([]int, 0, len(vecSet))
	for key := range vecSet {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return n1, keys, nil
}

func rbdftFindBestN1(keys []int, columns, logRatio int) int {
	maxRatio := float64(int64(1) << logRatio)
	for n1 := 1; n1 < columns; n1 <<= 1 {
		rotN1 := map[int]struct{}{}
		rotN2 := map[int]struct{}{}
		for _, rotation := range keys {
			rotN1[((rotation/n1)*n1)&(columns-1)] = struct{}{}
			rotN2[rotation&(n1-1)] = struct{}{}
		}
		ratio := float64(len(rotN2)-1) / float64(len(rotN1)-1)
		if ratio == maxRatio {
			return n1
		}
		if ratio > maxRatio {
			return n1 / 2
		}
	}
	return 1
}

func rbdftExpectedPolyBytes(degree, levelQ, levelP int) (uint64, bool) {
	if degree <= 0 || levelQ < -1 || levelP < -1 {
		return 0, false
	}
	ringBytes := func(level int) (uint64, bool) {
		if level < 0 {
			return 8, true
		}
		limbs := uint64(level + 1)
		if uint64(degree) > (^uint64(0)-8)/8 {
			return 0, false
		}
		perLimb := uint64(8) + uint64(8)*uint64(degree)
		if limbs > (^uint64(0)-8)/perLimb {
			return 0, false
		}
		return 8 + limbs*perLimb, true
	}
	qBytes, ok := ringBytes(levelQ)
	if !ok {
		return 0, false
	}
	pBytes, ok := ringBytes(levelP)
	if !ok || qBytes > ^uint64(0)-pBytes {
		return 0, false
	}
	return qBytes + pBytes, true
}

func rbdftWriteEffectiveLiteral(writer io.Writer, literal dft.MatrixLiteral, scratch *[rbdftScalarTextMaxBytes]byte) error {
	if err := rbdftWriteU8(writer, byte(literal.Type)); err != nil {
		return err
	}
	for _, value := range []int{literal.LogSlots, literal.LevelQ, literal.LevelP} {
		encoded, ok := rbdftInt32(value)
		if !ok {
			return malformedRBDFT("effective literal integer exceeds int32")
		}
		if err := rbdftWriteI32(writer, encoded); err != nil {
			return err
		}
	}
	if len(literal.Levels) > math.MaxUint32 {
		return malformedRBDFT("effective literal level count exceeds uint32")
	}
	if err := rbdftWriteU32(writer, uint32(len(literal.Levels))); err != nil {
		return err
	}
	for _, depth := range literal.Levels {
		encoded, ok := rbdftInt32(depth)
		if !ok {
			return malformedRBDFT("effective literal depth exceeds int32")
		}
		if err := rbdftWriteI32(writer, encoded); err != nil {
			return err
		}
	}
	if err := rbdftWriteU8(writer, byte(literal.Format)); err != nil {
		return err
	}
	if err := rbdftWriteU8(writer, 1); err != nil {
		return err
	}
	if err := rbdftWriteCanonicalScalar(writer, literal.Scaling, scratch); err != nil {
		return err
	}
	if err := rbdftWriteBool(writer, literal.BitReversed); err != nil {
		return err
	}
	logRatio, ok := rbdftInt32(literal.LogBSGSRatio)
	if !ok {
		return malformedRBDFT("effective literal BSGS ratio exceeds int32")
	}
	return rbdftWriteI32(writer, logRatio)
}

func rbdftWriteTransformationMetadata(writer io.Writer, transformation ltcommon.LinearTransformation, scratch *[rbdftScalarTextMaxBytes]byte) error {
	metadata := transformation.MetaData
	if metadata == nil || metadata.Scale.Mod != nil {
		return malformedRBDFT("encoded transformation metadata is nil or has modular scale")
	}
	if err := rbdftWriteU8(writer, 0); err != nil {
		return err
	}
	if err := rbdftWriteCanonicalScalar(writer, &metadata.Scale.Value, scratch); err != nil {
		return err
	}
	for _, value := range []int{
		metadata.LogDimensions.Rows, metadata.LogDimensions.Cols,
	} {
		encoded, ok := rbdftInt32(value)
		if !ok {
			return malformedRBDFT("encoded transformation dimensions exceed int32")
		}
		if err := rbdftWriteI32(writer, encoded); err != nil {
			return err
		}
	}
	for _, value := range []bool{metadata.IsBatched, metadata.IsBitReversed, metadata.IsNTT, metadata.IsMontgomery} {
		if err := rbdftWriteBool(writer, value); err != nil {
			return err
		}
	}
	for _, value := range []int{transformation.N1, transformation.LevelQ, transformation.LevelP, transformation.LogBabyStepGiantStepRatio} {
		encoded, ok := rbdftInt32(value)
		if !ok {
			return malformedRBDFT("encoded transformation metadata integer exceeds int32")
		}
		if err := rbdftWriteI32(writer, encoded); err != nil {
			return err
		}
	}
	return nil
}

func rbdftValidateScalar(value *big.Float) error {
	if value == nil || value.Prec() == 0 || value.Prec() > 256 || value.IsInf() || value.Mode() > big.ToPositiveInf {
		return malformedRBDFT("scalar is non-finite or outside the canonical precision/mode range")
	}
	accuracy := int8(value.Acc())
	if accuracy < -1 || accuracy > 1 {
		return malformedRBDFT("scalar accuracy is outside {-1,0,+1}")
	}
	return nil
}

func rbdftEqualFloatExact(left, right *big.Float) bool {
	return left != nil && right != nil && left.Prec() == right.Prec() && left.Mode() == right.Mode() &&
		left.Acc() == right.Acc() && left.Signbit() == right.Signbit() && left.Cmp(right) == 0
}

func rbdftEqualScaleExact(left, right rlwe.Scale) bool {
	if (left.Mod == nil) != (right.Mod == nil) || !rbdftEqualFloatExact(&left.Value, &right.Value) {
		return false
	}
	return left.Mod == nil || left.Mod.Cmp(right.Mod) == 0
}

func rbdftEqualLiteralExact(left, right dft.MatrixLiteral) bool {
	return left.Type == right.Type && left.LogSlots == right.LogSlots && left.LevelQ == right.LevelQ &&
		left.LevelP == right.LevelP && slices.Equal(left.Levels, right.Levels) && left.Format == right.Format &&
		rbdftEqualFloatExact(left.Scaling, right.Scaling) && left.BitReversed == right.BitReversed &&
		left.LogBSGSRatio == right.LogBSGSRatio
}

func rbdftCloneLiteral(literal dft.MatrixLiteral) dft.MatrixLiteral {
	literal.Levels = append([]int(nil), literal.Levels...)
	if literal.Scaling != nil {
		literal.Scaling = new(big.Float).Copy(literal.Scaling)
	}
	return literal
}

func rbdftInt32(value int) (int32, bool) {
	if int64(value) < math.MinInt32 || int64(value) > math.MaxInt32 {
		return 0, false
	}
	return int32(value), true
}

func rbdftWriteHeader(writer io.Writer, recordType, role byte) error {
	if err := rbdftWriteFull(writer, []byte(RBDFTMagic)); err != nil {
		return fmt.Errorf("secureeval: write RBDFT magic: %w", err)
	}
	return rbdftWriteFull(writer, []byte{recordType, role})
}

func rbdftWriteU8(writer io.Writer, value byte) error {
	return rbdftWriteFull(writer, []byte{value})
}

func rbdftWriteBool(writer io.Writer, value bool) error {
	if value {
		return rbdftWriteU8(writer, 1)
	}
	return rbdftWriteU8(writer, 0)
}

func rbdftWriteU32(writer io.Writer, value uint32) error {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return rbdftWriteFull(writer, encoded[:])
}

func rbdftWriteI32(writer io.Writer, value int32) error {
	return rbdftWriteU32(writer, uint32(value))
}

func rbdftWriteU64(writer io.Writer, value uint64) error {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return rbdftWriteFull(writer, encoded[:])
}

func rbdftWriteI64(writer io.Writer, value int64) error {
	return rbdftWriteU64(writer, uint64(value))
}

func rbdftWriteCanonicalScalar(writer io.Writer, value *big.Float, scratch *[rbdftScalarTextMaxBytes]byte) error {
	if writer == nil || value == nil || scratch == nil {
		return malformedRBDFT("scalar writer, value, or scratch is nil")
	}
	if value.Prec() == 0 || value.Prec() > 256 || value.IsInf() || value.Mode() > big.ToPositiveInf {
		return malformedRBDFT("scalar is non-finite or outside the canonical precision/mode range")
	}
	accuracy := int8(value.Acc())
	if accuracy < -1 || accuracy > 1 {
		return malformedRBDFT("scalar accuracy is outside {-1,0,+1}")
	}
	text := value.Append(scratch[:0], 'x', -1)
	if len(text) == 0 || len(text) > rbdftScalarTextMaxBytes {
		return malformedRBDFT("scalar exact-hex length is outside [1,256]")
	}

	var prefix [11]byte
	binary.LittleEndian.PutUint32(prefix[0:4], uint32(value.Prec()))
	prefix[4] = byte(value.Mode())
	prefix[5] = byte(accuracy)
	if value.Signbit() {
		prefix[6] = 1
	}
	binary.LittleEndian.PutUint32(prefix[7:11], uint32(len(text)))
	if err := rbdftWriteFull(writer, prefix[:]); err != nil {
		return fmt.Errorf("secureeval: write RBDFT scalar metadata: %w", err)
	}
	if err := rbdftWriteFull(writer, text); err != nil {
		return fmt.Errorf("secureeval: write RBDFT scalar exact hex: %w", err)
	}
	return nil
}

func rbdftWriteFull(writer io.Writer, value []byte) error {
	written, err := writer.Write(value)
	if written < 0 || written > len(value) {
		return io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	if written != len(value) {
		return io.ErrShortWrite
	}
	return nil
}
