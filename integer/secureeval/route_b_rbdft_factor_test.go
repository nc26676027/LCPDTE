package secureeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	ltcommon "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/ring/ringqp"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

func TestRBDFTFactorScalarCanonicalGolden(t *testing.T) {
	value := new(big.Float).SetPrec(8).SetMode(big.ToNegativeInf).SetFloat64(-1.5)

	var got bytes.Buffer
	var scratch [rbdftScalarTextMaxBytes]byte
	if err := rbdftWriteCanonicalScalar(&got, value, &scratch); err != nil {
		t.Fatalf("write scalar: %v", err)
	}

	want, err := hex.DecodeString("080000000400010a0000002d3078312e38702b3030")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("canonical scalar = %x, want %x", got.Bytes(), want)
	}
}

func TestRBDFTNumericFactorCanonicalOrderingAndMutation(t *testing.T) {
	profile := rbdftFactorProfile{
		role: dft.ObservedSlotsToCoeffs, wireRole: RBDFTRoleSTC, factorCount: 2,
		diagonalCounts: [3]uint32{2, 1}, vectorLength: 2, expectedPolyBytes: 1,
	}
	factorA := ltcommon.Diagonals[*bignum.Complex]{
		2:  {rbdftTestComplex(0, 0), rbdftTestComplex(3.25, -4.5)},
		-1: {rbdftTestComplex(1, 0), rbdftTestComplex(-2, 0.5)},
	}
	factorB := ltcommon.Diagonals[*bignum.Complex]{
		-1: factorA[-1],
		2:  factorA[2],
	}

	first, err := rbdftDigestNumericFactor(profile, 0, 256, factorA)
	if err != nil {
		t.Fatalf("digest numeric factor: %v", err)
	}
	second, err := rbdftDigestNumericFactor(profile, 0, 256, factorB)
	if err != nil {
		t.Fatalf("digest shuffled numeric factor: %v", err)
	}
	if first != second {
		t.Fatalf("map insertion order changed canonical identity: first=%x/%d second=%x/%d", first.digest, first.bytes, second.digest, second.bytes)
	}
	if first.digest == ([sha256.Size]byte{}) || first.bytes == 0 {
		t.Fatal("numeric factor identity is empty")
	}
	if got := hex.EncodeToString(first.digest[:]); got != "8b3acbc1290355ada1c050bc168aa5ffa9bf83655a1d8d8d055afe2f16cd9baa" || first.bytes != 208 {
		t.Fatalf("freeze numeric factor golden digest=%s bytes=%d", got, first.bytes)
	}

	mutated := rbdftCloneTestFactor(factorA)
	mutated[-1][0][0].Add(mutated[-1][0][0], new(big.Float).SetPrec(8).SetInt64(1))
	third, err := rbdftDigestNumericFactor(profile, 0, 256, mutated)
	if err != nil {
		t.Fatalf("digest mutated numeric factor: %v", err)
	}
	if third.digest == first.digest || third.bytes == 0 {
		t.Fatal("one-coefficient mutation did not change the numeric factor digest")
	}
}

func TestRBDFTEncodedFactorCanonicalOrderingAndMutation(t *testing.T) {
	params := rbdftTestParameters(t)
	literal := dft.MatrixLiteral{
		Type: dft.HomomorphicEncode, LogSlots: 2, LevelQ: 3, LevelP: 0,
		Levels: []int{1, 1, 1}, Format: dft.SplitRealAndImag,
		Scaling: new(big.Float).SetPrec(32).SetMode(big.ToNearestEven).SetInt64(1),
	}
	polyBytes, ok := rbdftExpectedPolyBytes(params.N(), literal.LevelQ, literal.LevelP)
	if !ok {
		t.Fatal("small-profile polynomial byte formula overflowed")
	}
	profile := rbdftFactorProfile{
		role: dft.ObservedCoeffsToSlots, wireRole: RBDFTRoleCTS, factorCount: 3,
		diagonalCounts: [3]uint32{3, 1, 1}, vectorLength: 4, expectedPolyBytes: polyBytes,
	}
	factor := ltcommon.Diagonals[*bignum.Complex]{
		2: {rbdftTestComplex256(2), rbdftTestComplex256(3), rbdftTestComplex256(4), rbdftTestComplex256(5)},
		0: {rbdftTestComplex256(1), rbdftTestComplex256(1), rbdftTestComplex256(1), rbdftTestComplex256(1)},
		1: {rbdftTestComplex256(6), rbdftTestComplex256(7), rbdftTestComplex256(8), rbdftTestComplex256(9)},
	}
	keys := factor.DiagonalsIndexList()
	scale, err := rbdftExpectedFactorScale(params, literal, 0)
	if err != nil {
		t.Fatalf("derive factor scale: %v", err)
	}
	donor := ltcommon.NewTransformation(params, ltcommon.Parameters{
		DiagonalsIndexList: keys, LevelQ: literal.LevelQ, LevelP: literal.LevelP,
		Scale: scale, LogDimensions: ring.Dimensions{Rows: 0, Cols: literal.LogSlots},
		LogBabyStepGiantStepRatio: literal.LogBSGSRatio,
	})
	if err = ltcommon.Encode(ckks.NewEncoder(params, 256), factor, donor); err != nil {
		t.Fatalf("encode small transformation: %v", err)
	}

	first, err := rbdftDigestEncodedFactor(params, profile, 0, 256, literal, keys, donor)
	if err != nil {
		t.Fatalf("digest encoded factor: %v", err)
	}
	shuffled := donor
	shuffled.Vec = make(map[int]ringqp.Poly, len(donor.Vec))
	vecKeys := make([]int, 0, len(donor.Vec))
	for key := range donor.Vec {
		vecKeys = append(vecKeys, key)
	}
	slices.Sort(vecKeys)
	for index := len(vecKeys) - 1; index >= 0; index-- {
		shuffled.Vec[vecKeys[index]] = donor.Vec[vecKeys[index]]
	}
	second, err := rbdftDigestEncodedFactor(params, profile, 0, 256, literal, keys, shuffled)
	if err != nil {
		t.Fatalf("digest shuffled encoded factor: %v", err)
	}
	if first != second {
		t.Fatalf("Vec insertion order changed canonical identity: first=%x/%d second=%x/%d", first.digest, first.bytes, second.digest, second.bytes)
	}
	if got := hex.EncodeToString(first.digest[:]); got != "9af258de4f17291ab3c0688634703c5bf7a0bb9d8a99c4f9221d80be544aeb54" || first.bytes != 2285 {
		t.Fatalf("freeze encoded factor golden digest=%s bytes=%d", got, first.bytes)
	}

	mutated := donor
	mutated.Vec = make(map[int]ringqp.Poly, len(donor.Vec))
	for key, poly := range donor.Vec {
		mutated.Vec[key] = *poly.CopyNew()
	}
	mutated.Vec[vecKeys[0]].Q.Coeffs[0][0] ^= 1
	third, err := rbdftDigestEncodedFactor(params, profile, 0, 256, literal, keys, mutated)
	if err != nil {
		t.Fatalf("digest mutated encoded factor: %v", err)
	}
	if third.digest == first.digest || third.bytes != first.bytes {
		t.Fatal("one-coefficient mutation did not change only the encoded factor digest")
	}
}

func TestRBDFTL11ProfileConstantsAndPolynomialFormula(t *testing.T) {
	stc, err := rbdftCanonicalL11FactorProfile(dft.ObservedSlotsToCoeffs)
	if err != nil {
		t.Fatal(err)
	}
	cts, err := rbdftCanonicalL11FactorProfile(dft.ObservedCoeffsToSlots)
	if err != nil {
		t.Fatal(err)
	}
	if stc.wireRole != RBDFTRoleSTC || stc.factorCount != 2 || stc.diagonalCounts != [3]uint32{63, 64} ||
		stc.vectorLength != 2048 || stc.expectedPolyBytes != 13_631_712 || !stc.canonicalL11 {
		t.Fatalf("L11 STC profile changed: %+v", stc)
	}
	if cts.wireRole != RBDFTRoleCTS || cts.factorCount != 3 || cts.diagonalCounts != [3]uint32{16, 31, 15} ||
		cts.vectorLength != 2048 || cts.expectedPolyBytes != 14_680_304 || !cts.canonicalL11 {
		t.Fatalf("L11 CTS profile changed: %+v", cts)
	}
	if got, ok := rbdftExpectedPolyBytes(65_536, 18, 6); !ok || got != stc.expectedPolyBytes {
		t.Fatalf("L11 STC polynomial formula = %d/%v", got, ok)
	}
	if got, ok := rbdftExpectedPolyBytes(65_536, 20, 6); !ok || got != cts.expectedPolyBytes {
		t.Fatalf("L11 CTS polynomial formula = %d/%v", got, ok)
	}
	mutated := stc
	mutated.diagonalCounts[0]++
	if err := mutated.validate(); err == nil {
		t.Fatal("mutated canonical L11 profile was accepted")
	}
}

func TestRBDFTEncodedFactorRejectsIndependentLocalValidationMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*dft.MatrixLiteral, *ltcommon.LinearTransformation)
	}{
		{name: "effective format", mutate: func(literal *dft.MatrixLiteral, _ *ltcommon.LinearTransformation) { literal.Format = dft.Standard }},
		{name: "effective scaling precision", mutate: func(literal *dft.MatrixLiteral, _ *ltcommon.LinearTransformation) {
			literal.Scaling = new(big.Float).SetPrec(257).SetMode(literal.Scaling.Mode()).Set(literal.Scaling)
		}},
		{name: "local scale", mutate: func(_ *dft.MatrixLiteral, transformation *ltcommon.LinearTransformation) {
			transformation.Scale.Value.Add(&transformation.Scale.Value, new(big.Float).SetPrec(transformation.Scale.Value.Prec()).SetInt64(1))
		}},
		{name: "N1", mutate: func(_ *dft.MatrixLiteral, transformation *ltcommon.LinearTransformation) { transformation.N1++ }},
		{name: "Vec topology", mutate: func(_ *dft.MatrixLiteral, transformation *ltcommon.LinearTransformation) {
			for key := range transformation.Vec {
				delete(transformation.Vec, key)
				break
			}
		}},
		{name: "LT LevelQ", mutate: func(_ *dft.MatrixLiteral, transformation *ltcommon.LinearTransformation) { transformation.LevelQ-- }},
		{name: "Q limb count", mutate: func(_ *dft.MatrixLiteral, transformation *ltcommon.LinearTransformation) {
			rbdftMutateFirstTestPoly(transformation, func(poly *ringqp.Poly) { poly.Q.Coeffs = poly.Q.Coeffs[:len(poly.Q.Coeffs)-1] })
		}},
		{name: "P limb count", mutate: func(_ *dft.MatrixLiteral, transformation *ltcommon.LinearTransformation) {
			rbdftMutateFirstTestPoly(transformation, func(poly *ringqp.Poly) { poly.P.Coeffs = poly.P.Coeffs[:0] })
		}},
		{name: "ring degree", mutate: func(_ *dft.MatrixLiteral, transformation *ltcommon.LinearTransformation) {
			rbdftMutateFirstTestPoly(transformation, func(poly *ringqp.Poly) { poly.Q.Coeffs[0] = poly.Q.Coeffs[0][:len(poly.Q.Coeffs[0])-1] })
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params, literal, profile, keys, transformation := rbdftSmallEncodedFixture(t)
			test.mutate(&literal, &transformation)
			if identity, err := rbdftDigestEncodedFactor(params, profile, 0, 256, literal, keys, transformation); err == nil || identity != (rbdftPayloadIdentity{}) {
				t.Fatalf("mutation was accepted: identity=%x/%d err=%v", identity.digest, identity.bytes, err)
			}
		})
	}
}

func TestRBDFTEncodedPayloadRejectsWriterAndCountFaults(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	tests := []struct {
		name     string
		target   io.Writer
		source   rbdftTestWriterTo
		declared uint64
		expected uint64
	}{
		{name: "BinarySize", target: &bytes.Buffer{}, source: rbdftTestWriterTo{size: 5, payload: payload}, declared: 4, expected: 4},
		{name: "role expected", target: &bytes.Buffer{}, source: rbdftTestWriterTo{size: 4, payload: payload}, declared: 4, expected: 5},
		{name: "returned short", target: &bytes.Buffer{}, source: rbdftTestWriterTo{size: 4, payload: payload, returned: 3, overrideReturned: true}, declared: 4, expected: 4},
		{name: "returned long", target: &bytes.Buffer{}, source: rbdftTestWriterTo{size: 4, payload: payload, returned: 5, overrideReturned: true}, declared: 4, expected: 4},
		{name: "source partial error", target: &bytes.Buffer{}, source: rbdftTestWriterTo{size: 4, payload: payload[:2], returned: 2, overrideReturned: true, err: errors.New("partial")}, declared: 4, expected: 4},
		{name: "prefix target short", target: rbdftTestHostileWriter{kind: "short"}, source: rbdftTestWriterTo{size: 4, payload: payload}, declared: 4, expected: 4},
		{name: "prefix target partial", target: rbdftTestHostileWriter{kind: "partial"}, source: rbdftTestWriterTo{size: 4, payload: payload}, declared: 4, expected: 4},
		{name: "prefix target long", target: rbdftTestHostileWriter{kind: "long"}, source: rbdftTestWriterTo{size: 4, payload: payload}, declared: 4, expected: 4},
		{name: "prefix flush failure", target: rbdftTestHostileWriter{kind: "flush"}, source: rbdftTestWriterTo{size: 4, payload: payload, flush: true}, declared: 4, expected: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stream, err := newRBDFTBufferedStream(test.target)
			if err != nil {
				t.Fatal(err)
			}
			if err = rbdftWriteU64(stream, test.declared); err != nil {
				t.Fatalf("write declared size: %v", err)
			}
			if err = rbdftStreamSizedPayload(stream, test.declared, test.expected, test.source); err == nil {
				t.Fatal("faulty encoded payload stream was accepted")
			}
		})
	}
}

func TestRBDFTEncodedPayloadReachesWriteToBeforeDeepFaults(t *testing.T) {
	t.Run("source error after physical payload flush", func(t *testing.T) {
		payloadReached := false
		target := &bytes.Buffer{}
		stream, err := newRBDFTBufferedStream(target)
		if err != nil {
			t.Fatal(err)
		}
		if err = rbdftWriteU64(stream, 4); err != nil {
			t.Fatalf("write declared size: %v", err)
		}
		source := rbdftTestWriterTo{
			size: 4, payload: []byte{1, 2, 3, 4}, flush: true,
			err: errors.New("source failed after payload flush"), called: &payloadReached,
		}
		if err = rbdftStreamSizedPayload(stream, 4, 4, source); err == nil {
			t.Fatal("source error after payload was accepted")
		}
		if !payloadReached || target.Len() != 8+4 {
			t.Fatalf("source did not physically emit prefix+payload before error: reached=%v bytes=%d", payloadReached, target.Len())
		}
	})

	t.Run("source requested payload flush fails", func(t *testing.T) {
		payloadReached := false
		target := &rbdftTestPostPrefixFaultWriter{failOnCall: 2}
		stream, err := newRBDFTBufferedStream(target)
		if err != nil {
			t.Fatal(err)
		}
		if err = rbdftWriteU64(stream, 4); err != nil {
			t.Fatalf("write declared size: %v", err)
		}
		source := rbdftTestWriterTo{
			size: 4, payload: []byte{1, 2, 3, 4}, flush: true, called: &payloadReached,
		}
		if err = rbdftStreamSizedPayload(stream, 4, 4, source); err == nil {
			t.Fatal("payload flush failure was accepted")
		}
		if !payloadReached || target.calls != 2 || target.accepted.Len() != 8 {
			t.Fatalf("fault was not post-prefix payload flush: reached=%v calls=%d accepted=%d", payloadReached, target.calls, target.accepted.Len())
		}
	})

	t.Run("physical overrun with declared return", func(t *testing.T) {
		payloadReached := false
		target := &bytes.Buffer{}
		stream, err := newRBDFTBufferedStream(target)
		if err != nil {
			t.Fatal(err)
		}
		if err = rbdftWriteU64(stream, 4); err != nil {
			t.Fatalf("write declared size: %v", err)
		}
		source := rbdftTestWriterTo{
			size: 4, payload: []byte{1, 2, 3, 4, 5}, returned: 4,
			overrideReturned: true, called: &payloadReached,
		}
		if err = rbdftStreamSizedPayload(stream, 4, 4, source); err == nil {
			t.Fatal("declared return hid a physical payload overrun")
		}
		if !payloadReached || target.Len() != 8+5 {
			t.Fatalf("overrun source did not physically emit prefix+payload+extra: reached=%v bytes=%d", payloadReached, target.Len())
		}
	})
}

func TestRBDFTSmallObservedSTCCTSIntegration(t *testing.T) {
	params := rbdftTestParameters(t)
	encoder := ckks.NewEncoder(params, 256)
	stcLiteral, stcProfile := rbdftSmallObservedContract(t, params, dft.ObservedSlotsToCoeffs)
	ctsLiteral, ctsProfile := rbdftSmallObservedContract(t, params, dft.ObservedCoeffsToSlots)

	before := dft.SnapshotMatrixConstructionCounters()
	stcConsumer, err := newRouteBRBDFTFactorConsumer(params, encoder, stcLiteral, stcProfile)
	if err != nil {
		t.Fatalf("new STC consumer: %v", err)
	}
	stcLedger := &rbdftIndependentLedgerConsumer{
		inner: stcConsumer, params: params, literal: stcLiteral, profile: stcProfile,
	}
	stcMatrix, stcTrace, err := dft.NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, dft.ObservedSlotsToCoeffs, stcLiteral, encoder, 256, stcLedger,
	)
	if err != nil {
		t.Fatalf("observed STC: %v", err)
	}
	stcEvidence, err := stcConsumer.promote(stcMatrix, stcTrace)
	if err != nil {
		t.Fatalf("promote STC: %v", err)
	}

	ctsConsumer, err := newRouteBRBDFTFactorConsumer(params, encoder, ctsLiteral, ctsProfile)
	if err != nil {
		t.Fatalf("new CTS consumer: %v", err)
	}
	ctsLedger := &rbdftIndependentLedgerConsumer{
		inner: ctsConsumer, params: params, literal: ctsLiteral, profile: ctsProfile,
	}
	ctsMatrix, ctsTrace, err := dft.NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, dft.ObservedCoeffsToSlots, ctsLiteral, encoder, 256, ctsLedger,
	)
	if err != nil {
		t.Fatalf("observed CTS: %v", err)
	}
	ctsEvidence, err := ctsConsumer.promote(ctsMatrix, ctsTrace)
	if err != nil {
		t.Fatalf("promote CTS: %v", err)
	}
	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil {
		t.Fatalf("constructor counter delta: %v", err)
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 || delta.ObservedStreaming() != 2 {
		t.Fatalf("constructor delta = %d/%d/%d/%d, want 0/0/0/2",
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming())
	}
	if stcTrace.CompletedEventCount() != 13 || len(stcTrace.Events()) != 13 || len(stcTrace.CleanupEvents()) != 0 ||
		ctsTrace.CompletedEventCount() != 18 || len(ctsTrace.Events()) != 18 || len(ctsTrace.CleanupEvents()) != 0 ||
		4+stcTrace.CompletedEventCount()+ctsTrace.CompletedEventCount() != RBDFTLifecycleSuccessEventCount {
		t.Fatalf("observed lifecycle counts STC=%d CTS=%d cleanups=%d/%d",
			stcTrace.CompletedEventCount(), ctsTrace.CompletedEventCount(), len(stcTrace.CleanupEvents()), len(ctsTrace.CleanupEvents()))
	}
	if stcEvidence.role != dft.ObservedSlotsToCoeffs || stcEvidence.count != 2 ||
		ctsEvidence.role != dft.ObservedCoeffsToSlots || ctsEvidence.count != 3 {
		t.Fatal("promoted small-profile role or factor count changed")
	}
	independent := append(append([]rbdftIndependentFactorLedger(nil), stcLedger.entries...), ctsLedger.entries...)
	traced := append(stcTrace.Factors(), ctsTrace.Factors()...)
	promoted := []rbdftFactorEvidencePair{
		stcEvidence.factors[0], stcEvidence.factors[1],
		ctsEvidence.factors[0], ctsEvidence.factors[1], ctsEvidence.factors[2],
	}
	if len(independent) != 5 || len(traced) != 5 {
		t.Fatalf("five-factor ledger lengths = independent=%d traced=%d, want 5/5", len(independent), len(traced))
	}
	frozen := []rbdftIndependentFactorLedger{
		{role: dft.ObservedSlotsToCoeffs, index: 0, numericBytes: 1982, encodedBytes: 2689},
		{role: dft.ObservedSlotsToCoeffs, index: 1, numericBytes: 4378, encodedBytes: 3537},
		{role: dft.ObservedCoeffsToSlots, index: 0, numericBytes: 2202, encodedBytes: 2117},
		{role: dft.ObservedCoeffsToSlots, index: 1, numericBytes: 2502, encodedBytes: 3101},
		{role: dft.ObservedCoeffsToSlots, index: 2, numericBytes: 2502, encodedBytes: 3101},
	}
	for position, want := range independent {
		trace := traced[position]
		promotion := promoted[position]
		if want != frozen[position] || trace.Role() != want.role || trace.Index() != want.index ||
			trace.NumericBytes() != want.numericBytes || trace.EncodedBytes() != want.encodedBytes ||
			promotion.index != uint32(want.index) || promotion.numeric.bytes != want.numericBytes ||
			promotion.encoded.bytes != want.encodedBytes ||
			trace.NumericDigest() != promotion.numeric.digest || trace.EncodedDigest() != promotion.encoded.digest {
			t.Fatalf("factor ledger position %d disagrees: independent=%+v trace=%d/%d/%d/%d promotion=%d/%d/%d",
				position, want, trace.Role(), trace.Index(), trace.NumericBytes(), trace.EncodedBytes(),
				promotion.index, promotion.numeric.bytes, promotion.encoded.bytes)
		}
	}
	stcConsumer.dropEncoderReference()
	ctsConsumer.dropEncoderReference()
	encoder = nil
}

type rbdftIndependentFactorLedger struct {
	role                       dft.ObservedTransformRole
	index                      dft.ObservedFactorIndex
	numericBytes, encodedBytes uint64
}

// rbdftIndependentLedgerConsumer is a test-only oracle around the production
// consumer. It derives every factor's byte counts directly from the frozen wire
// grammar and the borrowed numeric values; it does not call either production
// record writer or either production digest/count helper.
type rbdftIndependentLedgerConsumer struct {
	inner   *routeBRBDFTFactorConsumer
	params  ckks.Parameters
	literal dft.MatrixLiteral
	profile rbdftFactorProfile
	entries []rbdftIndependentFactorLedger
}

func (consumer *rbdftIndependentLedgerConsumer) ConsumeObservedFactor(input dft.ObservedFactorInput) (*dft.ObservedFactorProduct, error) {
	factor, active := input.BorrowedNumericFactor()
	if !active || factor == nil {
		return nil, errors.New("independent ledger received an inactive factor")
	}
	numericBytes, err := rbdftIndependentNumericFactorBytes(consumer.profile, input.Index(), factor)
	if err != nil {
		return nil, err
	}
	encodedBytes, err := rbdftIndependentEncodedFactorBytes(
		consumer.params, consumer.literal, consumer.profile, input.Index(),
	)
	if err != nil {
		return nil, err
	}
	product, err := consumer.inner.ConsumeObservedFactor(input)
	if err != nil {
		return product, err
	}
	if product == nil || product.NumericBytes() != numericBytes || product.EncodedBytes() != encodedBytes {
		return product, errors.New("production product disagrees with independent wire byte ledger")
	}
	consumer.entries = append(consumer.entries, rbdftIndependentFactorLedger{
		role: input.Role(), index: input.Index(), numericBytes: numericBytes, encodedBytes: encodedBytes,
	})
	factor = nil
	return product, nil
}

func rbdftIndependentNumericFactorBytes(
	profile rbdftFactorProfile,
	index dft.ObservedFactorIndex,
	factor ltcommon.Diagonals[*bignum.Complex],
) (uint64, error) {
	if index < 0 || uint32(index) >= uint32(profile.factorCount) || factor == nil {
		return 0, errors.New("independent numeric ledger received an invalid factor")
	}
	keys := factor.DiagonalsIndexList()
	slices.Sort(keys)
	if len(keys) != int(profile.diagonalCounts[uint32(index)]) {
		return 0, errors.New("independent numeric ledger diagonal count changed")
	}
	bytes := uint64(len("LCPDTE-RBDFT-v1\x00") + 2 + 4*4)
	for _, key := range keys {
		vector := factor[key]
		if len(vector) != int(profile.vectorLength) {
			return 0, errors.New("independent numeric ledger vector length changed")
		}
		bytes += 8 + 4
		for _, value := range vector {
			if value == nil || value[0] == nil || value[1] == nil {
				return 0, errors.New("independent numeric ledger saw a nil scalar")
			}
			bytes += rbdftIndependentScalarBytes(value[0]) + rbdftIndependentScalarBytes(value[1])
		}
	}
	return bytes, nil
}

func rbdftIndependentEncodedFactorBytes(
	params ckks.Parameters,
	literal dft.MatrixLiteral,
	profile rbdftFactorProfile,
	index dft.ObservedFactorIndex,
) (uint64, error) {
	if index < 0 || uint32(index) >= uint32(profile.factorCount) ||
		params.LevelsConsumedPerRescaling() != 1 || len(literal.Levels) != int(profile.factorCount) {
		return 0, errors.New("independent encoded ledger received an invalid one-level schedule")
	}
	for _, depth := range literal.Levels {
		if depth != 1 {
			return 0, errors.New("independent encoded ledger schedule is not all depth one")
		}
	}
	level := literal.LevelQ - int(index)
	if level < 0 || level > params.MaxLevelQ() {
		return 0, errors.New("independent encoded ledger scale level is outside Q")
	}
	factorScale := rlwe.NewScale(params.Q()[level])
	polyBytes := rbdftIndependentRingPolyBytes(params.N(), literal.LevelQ) +
		rbdftIndependentRingPolyBytes(params.N(), literal.LevelP)
	if polyBytes == 0 || polyBytes != profile.expectedPolyBytes {
		return 0, errors.New("independent encoded ledger polynomial size changed")
	}

	// Header + three u32 fields; effective literal; LT metadata; Vec count;
	// then each sorted Vec entry's i64 key, u64 length, and polynomial bytes.
	bytes := uint64(len("LCPDTE-RBDFT-v1\x00") + 2 + 3*4)
	bytes += uint64(1 + 3*4 + 4 + 4*len(literal.Levels) + 1 + 1 + 1 + 4)
	bytes += rbdftIndependentScalarBytes(literal.Scaling)
	bytes += uint64(1 + 2*4 + 4 + 4*4)
	bytes += rbdftIndependentScalarBytes(&factorScale.Value)
	bytes += 4
	bytes += uint64(profile.diagonalCounts[uint32(index)]) * (8 + 8 + polyBytes)
	return bytes, nil
}

func rbdftIndependentRingPolyBytes(degree, level int) uint64 {
	if degree <= 0 || level < -1 {
		return 0
	}
	if level == -1 {
		return 8
	}
	// A ring polynomial is a matrix: u64 row count, then for every modulus
	// limb a u64 vector length followed by degree uint64 coefficients.
	return 8 + uint64(level+1)*(8+8*uint64(degree))
}

func rbdftIndependentScalarBytes(value *big.Float) uint64 {
	if value == nil {
		return 0
	}
	return uint64(11 + len(value.Append(nil, 'x', -1)))
}

func TestRBDFTConsumerErrorAndPanicReturnDiscardableProduct(t *testing.T) {
	for _, test := range []struct {
		name string
		mode rbdftConsumerFaultMode
	}{
		{name: "error", mode: rbdftConsumerReturnErrorAfterProduct},
		{name: "panic", mode: rbdftConsumerPanicAfterProduct},
	} {
		t.Run(test.name, func(t *testing.T) {
			params := rbdftTestParameters(t)
			encoder := ckks.NewEncoder(params, 256)
			literal, profile := rbdftSmallObservedContract(t, params, dft.ObservedSlotsToCoeffs)
			consumer, err := newRouteBRBDFTFactorConsumer(params, encoder, literal, profile)
			if err != nil {
				t.Fatal(err)
			}
			consumer.faultMode = test.mode
			matrix, trace, err := dft.NewMatrixFromLiteralWithGeneratorPrecisionObserved(
				params, dft.ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
			)
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("consumer %s error = %v", test.name, err)
			}
			if matrix.Matrices != nil || trace.Status() != dft.ObservedStreamingFailure ||
				trace.FailureStage() != dft.ObservedStreamingFailureConsumer || trace.CompletedEventCount() != 2 ||
				trace.AttemptedEventLowerBound() != 3 || trace.Validate() != nil {
				t.Fatalf("consumer %s failure trace changed: status=%d stage=%d completed=%d attempted=%d",
					test.name, trace.Status(), trace.FailureStage(), trace.CompletedEventCount(), trace.AttemptedEventLowerBound())
			}
			cleanup := trace.CleanupEvents()
			if len(cleanup) != 3 || cleanup[0].Code() != dft.ObservedStreamingCleanupProductDiscarded ||
				cleanup[1].Code() != dft.ObservedStreamingCleanupFactorReferenceCleared ||
				cleanup[2].Code() != dft.ObservedStreamingCleanupGeneratorReferencesCleared {
				t.Fatalf("consumer %s cleanup does not discard product/factor/generator: %+v", test.name, cleanup)
			}
			if !consumer.failed || consumer.completed != 0 || consumer.tentative != ([3]rbdftFactorEvidencePair{}) {
				t.Fatalf("consumer %s retained tentative evidence after failure", test.name)
			}
		})
	}
}

func TestRBDFTPromotionRequiresValidatedTraceAndMatrix(t *testing.T) {
	params := rbdftTestParameters(t)
	encoder := ckks.NewEncoder(params, 256)
	literal, profile := rbdftSmallObservedContract(t, params, dft.ObservedSlotsToCoeffs)
	consumer, err := newRouteBRBDFTFactorConsumer(params, encoder, literal, profile)
	if err != nil {
		t.Fatal(err)
	}
	matrix, trace, err := dft.NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, dft.ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err != nil {
		t.Fatal(err)
	}
	matrix.LevelQ--
	if evidence, err := consumer.promote(matrix, trace); err == nil || evidence != (rbdftPromotedFactorEvidence{}) {
		t.Fatalf("mutated matrix was promoted: evidence=%+v err=%v", evidence, err)
	}
	if !consumer.failed || consumer.completed != 0 || consumer.tentative != ([3]rbdftFactorEvidencePair{}) {
		t.Fatal("failed outer Matrix.ValidateAgainst did not abort prior tentative references")
	}
}

func TestRBDFTFactorConsumerASTNonRetentionAndNoAuthorityRoutes(t *testing.T) {
	source, err := os.ReadFile("route_b_rbdft_factor.go")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "route_b_rbdft_factor.go", source, parser.AllErrors)
	if err != nil {
		t.Fatal(err)
	}
	borrowCalls := 0
	forbidden := map[string]bool{
		"GenMatrices": true, "ForEachMatrixFactor": true, "MarshalBinary": true,
		"NewMatrixFromLiteral": true, "NewMatrixFromLiteralWithGeneratorPrecision": true,
		"NewMatrixFromLiteralWithGeneratorPrecisionStreaming": true,
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.CallExpr:
			if selector, ok := value.Fun.(*ast.SelectorExpr); ok {
				if selector.Sel.Name == "BorrowedNumericFactor" {
					borrowCalls++
				}
				if forbidden[selector.Sel.Name] {
					t.Errorf("production factor consumer calls forbidden constructor/writer %s", selector.Sel.Name)
				}
			}
		case *ast.TypeSpec:
			if ast.IsExported(value.Name.Name) {
				t.Errorf("factor evidence slice exports type %s", value.Name.Name)
			}
		case *ast.FuncDecl:
			if value.Recv == nil && ast.IsExported(value.Name.Name) {
				t.Errorf("factor evidence slice exports function %s", value.Name.Name)
			}
		}
		return true
	})
	if borrowCalls != 1 {
		t.Fatalf("BorrowedNumericFactor call sites = %d, want exactly one", borrowCalls)
	}
	consumerType := ""
	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, spec := range general.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "routeBRBDFTFactorConsumer" {
				continue
			}
			consumerType = string(source[typeSpec.Pos()-1 : typeSpec.End()-1])
		}
	}
	if consumerType == "" {
		t.Fatal("private factor consumer type not found")
	}
	for _, forbiddenFieldType := range []string{"ObservedFactorInput", "Diagonals[", "bignum.Complex"} {
		if strings.Contains(consumerType, forbiddenFieldType) {
			t.Fatalf("private consumer retains forbidden numeric/input/product type %q", forbiddenFieldType)
		}
	}
}

func TestRBDFTNumericAliasProofBoundaryIsExplicit(t *testing.T) {
	params := rbdftTestParameters(t)
	encoder := ckks.NewEncoder(params, 256)
	literal, profile := rbdftSmallObservedContract(t, params, dft.ObservedSlotsToCoeffs)
	inner, err := newRouteBRBDFTFactorConsumer(params, encoder, literal, profile)
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &rbdftRetainingTestConsumer{inner: inner}
	matrix, trace, err := dft.NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, dft.ObservedSlotsToCoeffs, literal, encoder, 256, wrapper,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = inner.promote(matrix, trace); err != nil {
		t.Fatal(err)
	}
	if len(wrapper.retained) != int(profile.factorCount) {
		t.Fatalf("malicious test wrapper retained %d factors", len(wrapper.retained))
	}
	before := make([]rbdftPayloadIdentity, len(matrix.Matrices))
	for index, transformation := range matrix.Matrices {
		before[index], err = rbdftDigestEncodedFactor(
			params, profile, dft.ObservedFactorIndex(index), 256, literal,
			wrapper.retained[index].DiagonalsIndexList(), transformation,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, retained := range wrapper.retained {
		for _, vector := range retained {
			vector[0][0].Add(vector[0][0], new(big.Float).SetPrec(vector[0][0].Prec()).SetInt64(1))
			break
		}
	}
	for index, transformation := range matrix.Matrices {
		after, err := rbdftDigestEncodedFactor(
			params, profile, dft.ObservedFactorIndex(index), 256, literal,
			wrapper.retained[index].DiagonalsIndexList(), transformation,
		)
		if err != nil {
			t.Fatal(err)
		}
		if after != before[index] {
			t.Fatalf("post-callback numeric alias mutation reached encoded factor %d", index)
		}
	}
	// This deliberately malicious wrapper demonstrates the proof boundary:
	// Go maps can be retained by an arbitrary callback. The production claim is
	// therefore supported by source/AST non-retention plus encoded-copy
	// detachment, not by a language-level no-alias guarantee.
	wrapper.retained = nil
}

type rbdftRetainingTestConsumer struct {
	inner    *routeBRBDFTFactorConsumer
	retained []ltcommon.Diagonals[*bignum.Complex]
}

func (consumer *rbdftRetainingTestConsumer) ConsumeObservedFactor(input dft.ObservedFactorInput) (*dft.ObservedFactorProduct, error) {
	factor, active := input.BorrowedNumericFactor()
	if !active {
		return nil, errors.New("retaining test wrapper received inactive factor")
	}
	consumer.retained = append(consumer.retained, factor)
	return consumer.inner.ConsumeObservedFactor(input)
}

type rbdftTestWriterTo struct {
	size             int
	payload          []byte
	returned         int64
	overrideReturned bool
	err              error
	flush            bool
	called           *bool
}

func (value rbdftTestWriterTo) BinarySize() int { return value.size }

func (value rbdftTestWriterTo) WriteTo(writer io.Writer) (int64, error) {
	if value.called != nil {
		*value.called = true
	}
	written, writeErr := writer.Write(value.payload)
	if writeErr != nil {
		return int64(written), writeErr
	}
	if value.flush {
		flusher, ok := writer.(interface{ Flush() error })
		if !ok {
			return int64(written), errors.New("writer has no Flush")
		}
		if err := flusher.Flush(); err != nil {
			return int64(written), err
		}
	}
	if value.overrideReturned {
		return value.returned, value.err
	}
	return int64(written), value.err
}

type rbdftTestHostileWriter struct{ kind string }

func (writer rbdftTestHostileWriter) Write(value []byte) (int, error) {
	switch writer.kind {
	case "short":
		return len(value) - 1, nil
	case "partial":
		return len(value) / 2, errors.New("partial target")
	case "long":
		return len(value) + 1, nil
	case "flush":
		return 0, errors.New("flush target")
	default:
		return len(value), nil
	}
}

type rbdftTestPostPrefixFaultWriter struct {
	failOnCall int
	calls      int
	accepted   bytes.Buffer
}

func (writer *rbdftTestPostPrefixFaultWriter) Write(value []byte) (int, error) {
	writer.calls++
	if writer.calls == writer.failOnCall {
		return 0, errors.New("post-prefix payload flush failure")
	}
	return writer.accepted.Write(value)
}

func rbdftTestComplex(real, imaginary float64) *bignum.Complex {
	return &bignum.Complex{
		new(big.Float).SetPrec(8).SetMode(big.ToNearestEven).SetFloat64(real),
		new(big.Float).SetPrec(8).SetMode(big.ToNearestEven).SetFloat64(imaginary),
	}
}

func rbdftTestComplex256(value float64) *bignum.Complex {
	return &bignum.Complex{
		new(big.Float).SetPrec(256).SetMode(big.ToNearestEven).SetFloat64(value),
		new(big.Float).SetPrec(256).SetMode(big.ToNearestEven),
	}
}

func rbdftTestParameters(t *testing.T) ckks.Parameters {
	t.Helper()
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 4, LogQ: []int{50, 50, 50, 50, 50, 50}, LogP: []int{50}, LogDefaultScale: 40,
	})
	if err != nil {
		t.Fatalf("new small CKKS parameters: %v", err)
	}
	return params
}

func rbdftSmallObservedContract(
	t *testing.T,
	params ckks.Parameters,
	role dft.ObservedTransformRole,
) (dft.MatrixLiteral, rbdftFactorProfile) {
	t.Helper()
	literal := dft.MatrixLiteral{
		LogSlots: 3, LevelP: 0, Format: dft.SplitRealAndImag,
		Scaling: new(big.Float).SetPrec(256).SetMode(big.ToNearestEven).SetInt64(1),
	}
	profile := rbdftFactorProfile{role: role, vectorLength: 8}
	switch role {
	case dft.ObservedSlotsToCoeffs:
		literal.Type = dft.HomomorphicDecode
		literal.LevelQ = 4
		literal.Levels = []int{1, 1}
		profile.wireRole = RBDFTRoleSTC
		profile.factorCount = 2
		profile.diagonalCounts = [3]uint32{3, 4}
	case dft.ObservedCoeffsToSlots:
		literal.Type = dft.HomomorphicEncode
		literal.LevelQ = 5
		literal.Levels = []int{1, 1, 1}
		profile.wireRole = RBDFTRoleCTS
		profile.factorCount = 3
		profile.diagonalCounts = [3]uint32{2, 3, 3}
	default:
		t.Fatalf("invalid small observed role %d", role)
	}
	polyBytes, ok := rbdftExpectedPolyBytes(params.N(), literal.LevelQ, literal.LevelP)
	if !ok {
		t.Fatal("small observed polynomial formula overflowed")
	}
	profile.expectedPolyBytes = polyBytes
	return literal, profile
}

func rbdftCloneTestFactor(input ltcommon.Diagonals[*bignum.Complex]) ltcommon.Diagonals[*bignum.Complex] {
	result := make(ltcommon.Diagonals[*bignum.Complex], len(input))
	for key, vector := range input {
		cloned := make([]*bignum.Complex, len(vector))
		for index, value := range vector {
			cloned[index] = value.Clone()
		}
		result[key] = cloned
	}
	return result
}

func rbdftSmallEncodedFixture(t *testing.T) (
	ckks.Parameters,
	dft.MatrixLiteral,
	rbdftFactorProfile,
	[]int,
	ltcommon.LinearTransformation,
) {
	t.Helper()
	params := rbdftTestParameters(t)
	literal := dft.MatrixLiteral{
		Type: dft.HomomorphicEncode, LogSlots: 2, LevelQ: 3, LevelP: 0,
		Levels: []int{1, 1, 1}, Format: dft.SplitRealAndImag,
		Scaling: new(big.Float).SetPrec(32).SetMode(big.ToNearestEven).SetInt64(1),
	}
	polyBytes, ok := rbdftExpectedPolyBytes(params.N(), literal.LevelQ, literal.LevelP)
	if !ok {
		t.Fatal("small encoded fixture polynomial formula overflowed")
	}
	profile := rbdftFactorProfile{
		role: dft.ObservedCoeffsToSlots, wireRole: RBDFTRoleCTS, factorCount: 3,
		diagonalCounts: [3]uint32{3, 1, 1}, vectorLength: 4, expectedPolyBytes: polyBytes,
	}
	factor := ltcommon.Diagonals[*bignum.Complex]{
		0: {rbdftTestComplex256(1), rbdftTestComplex256(1), rbdftTestComplex256(1), rbdftTestComplex256(1)},
		1: {rbdftTestComplex256(2), rbdftTestComplex256(3), rbdftTestComplex256(4), rbdftTestComplex256(5)},
		2: {rbdftTestComplex256(6), rbdftTestComplex256(7), rbdftTestComplex256(8), rbdftTestComplex256(9)},
	}
	keys := factor.DiagonalsIndexList()
	scale, err := rbdftExpectedFactorScale(params, literal, 0)
	if err != nil {
		t.Fatal(err)
	}
	transformation := ltcommon.NewTransformation(params, ltcommon.Parameters{
		DiagonalsIndexList: keys, LevelQ: literal.LevelQ, LevelP: literal.LevelP,
		Scale: scale, LogDimensions: ring.Dimensions{Rows: 0, Cols: literal.LogSlots},
		LogBabyStepGiantStepRatio: literal.LogBSGSRatio,
	})
	if err = ltcommon.Encode(ckks.NewEncoder(params, 256), factor, transformation); err != nil {
		t.Fatal(err)
	}
	transformation = rbdftCloneTestTransformation(transformation)
	return params, literal, profile, keys, transformation
}

func rbdftCloneTestTransformation(input ltcommon.LinearTransformation) ltcommon.LinearTransformation {
	result := input
	if input.MetaData != nil {
		result.MetaData = input.MetaData.CopyNew()
	}
	result.Vec = make(map[int]ringqp.Poly, len(input.Vec))
	for key, poly := range input.Vec {
		result.Vec[key] = *poly.CopyNew()
	}
	return result
}

func rbdftMutateFirstTestPoly(transformation *ltcommon.LinearTransformation, mutate func(*ringqp.Poly)) {
	keys := make([]int, 0, len(transformation.Vec))
	for key := range transformation.Vec {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	poly := transformation.Vec[keys[0]]
	mutate(&poly)
	transformation.Vec[keys[0]] = poly
}
