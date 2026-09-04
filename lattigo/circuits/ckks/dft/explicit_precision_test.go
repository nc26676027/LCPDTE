// Modified by the LCPDTE project for local module integration and, where applicable,
// runtime instrumentation. See lattigo/NOTICE for attribution and modification details.

package dft

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	ltcommon "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

func explicitPrecisionTestParameters(t *testing.T) ckks.Parameters {
	t.Helper()

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{60, 60, 60},
		LogP:            []int{60},
		LogDefaultScale: 43,
	})
	if err != nil {
		t.Fatal(err)
	}

	return params
}

func explicitPrecisionTestLiteral() MatrixLiteral {
	return MatrixLiteral{
		Type:         HomomorphicDecode,
		LogSlots:     3,
		LevelQ:       2,
		LevelP:       0,
		Levels:       []int{1, 1, 1},
		Format:       SplitRealAndImag,
		LogBSGSRatio: 0,
	}
}

func TestNewMatrixFromLiteralWithGeneratorPrecisionMatchesStockAt53Bits(t *testing.T) {
	params := explicitPrecisionTestParameters(t)
	literal := explicitPrecisionTestLiteral()
	encoder := ckks.NewEncoder(params)

	stock, err := NewMatrixFromLiteral(params, literal, encoder)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := NewMatrixFromLiteralWithGeneratorPrecision(params, literal, encoder, 53)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(stock, explicit) {
		t.Fatal("stock and explicit 53-bit DFT matrices differ")
	}
}

func TestNewMatrixFromLiteralWithGeneratorPrecisionRejectsInconsistentEncoder(t *testing.T) {
	params := explicitPrecisionTestParameters(t)
	literal := explicitPrecisionTestLiteral()

	foreignParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            4,
		LogQ:            []int{60, 60, 60},
		LogP:            []int{60},
		LogDefaultScale: 42,
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		encoder *ckks.Encoder
		prec    uint
		wantErr string
	}{
		{name: "nil encoder", encoder: nil, prec: 53, wantErr: "encoder is nil"},
		{name: "precision mismatch", encoder: ckks.NewEncoder(params), prec: 256, wantErr: "generator precision 256 differs from encoder precision 53"},
		{name: "parameter mismatch", encoder: ckks.NewEncoder(foreignParams), prec: 53, wantErr: "encoder parameters differ from matrix parameters"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matrix, err := NewMatrixFromLiteralWithGeneratorPrecision(params, literal, test.encoder, test.prec)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("got error %v, want an error containing %q", err, test.wantErr)
			}
			if len(matrix.Matrices) != 0 {
				t.Fatal("failed construction returned encoded matrices")
			}
		})
	}
}

func TestNewMatrixFromLiteralWithGeneratorPrecisionUses256BitGeneration(t *testing.T) {
	params := explicitPrecisionTestParameters(t)
	literal := explicitPrecisionTestLiteral()
	encoder53 := ckks.NewEncoder(params)
	encoder256 := ckks.NewEncoder(params, 256)

	matrix53, err := NewMatrixFromLiteralWithGeneratorPrecision(params, literal, encoder53, 53)
	if err != nil {
		t.Fatal(err)
	}
	matrix256, err := NewMatrixFromLiteralWithGeneratorPrecision(params, literal, encoder256, 256)
	if err != nil {
		t.Fatal(err)
	}
	reference256 := explicitPrecisionReferenceMatrix(t, params, literal, encoder256, 256)

	assertExplicitPrecisionMatricesEqual(t, matrix256, reference256)
	payload53 := explicitPrecisionMatrixPayload(t, matrix53)
	payload256 := explicitPrecisionMatrixPayload(t, matrix256)
	if bytes.Equal(payload53, payload256) {
		t.Fatal("53-bit and 256-bit generators produced identical encoded payloads")
	}
	if !bytes.Equal(payload256, explicitPrecisionMatrixPayload(t, reference256)) {
		t.Fatal("explicit 256-bit payload differs from independent reference serialization")
	}

	coeff53 := explicitPrecisionCoefficientSentinel(t, literal.GenMatrices(params.LogN(), 53))
	coeff256 := explicitPrecisionCoefficientSentinel(t, literal.GenMatrices(params.LogN(), 256))
	if coeff53 == coeff256 {
		t.Fatal("53-bit and 256-bit generators produced an identical numeric sentinel")
	}
	const wantCoefficient53 = "real=0x1.6a09e667f3bccp-01;imag=0x1.6a09e667f3bccp-01;precision=53"
	const wantCoefficient256 = "real=0x1.6a09e667f3bcc908b2fb1366ea957d3e3adec17512775099da2f590b0667322cp-01;imag=0x1.6a09e667f3bcc908b2fb1366ea957d3e3adec17512775099da2f590b0667322cp-01;precision=256"
	if coeff53 != wantCoefficient53 {
		t.Fatalf("53-bit numeric sentinel changed:\n got: %s\nwant: %s", coeff53, wantCoefficient53)
	}
	if coeff256 != wantCoefficient256 {
		t.Fatalf("256-bit numeric sentinel changed:\n got: %s\nwant: %s", coeff256, wantCoefficient256)
	}

	const wantPayload53 = "4a1a71ae27ee81ea0ed93f9b2e45d6174f3dddc3df541cb872a62937ec55af1a"
	const wantPayload256 = "a43768552496cc0cd881dc1dbcfd363318842c8395d5a8f233e456b27a8790bc"
	if got := explicitPrecisionPayloadDigest(payload53); got != wantPayload53 {
		t.Fatalf("53-bit encoded payload sentinel changed: got %s, want %s", got, wantPayload53)
	}
	if got := explicitPrecisionPayloadDigest(payload256); got != wantPayload256 {
		t.Fatalf("256-bit encoded payload sentinel changed: got %s, want %s", got, wantPayload256)
	}
}

func explicitPrecisionReferenceMatrix(t *testing.T, params ckks.Parameters, literal MatrixLiteral, encoder *ckks.Encoder, precision uint) Matrix {
	t.Helper()

	if params.LevelsConsumedPerRescaling() != 1 || !slices.Equal(literal.Levels, []int{1, 1, 1}) {
		t.Fatal("reference builder is defined only for the fixed three-factor test profile")
	}

	plainMatrices := literal.GenMatrices(params.LogN(), precision)
	matrices := make([]ltcommon.LinearTransformation, len(plainMatrices))
	for i := range plainMatrices {
		transformation := ltcommon.NewTransformation(params, ltcommon.Parameters{
			DiagonalsIndexList:        plainMatrices[i].DiagonalsIndexList(),
			LevelQ:                    literal.LevelQ,
			LevelP:                    literal.LevelP,
			Scale:                     rlwe.NewScale(params.Q()[literal.LevelQ-i]),
			LogDimensions:             ring.Dimensions{Rows: 0, Cols: literal.LogSlots},
			LogBabyStepGiantStepRatio: literal.LogBSGSRatio,
		})
		if err := ltcommon.Encode(encoder, plainMatrices[i], transformation); err != nil {
			t.Fatal(err)
		}
		matrices[i] = transformation
	}

	return Matrix{MatrixLiteral: literal, Matrices: matrices}
}

func assertExplicitPrecisionMatricesEqual(t *testing.T, got, want Matrix) {
	t.Helper()

	if !reflect.DeepEqual(got.MatrixLiteral, want.MatrixLiteral) || len(got.Matrices) != len(want.Matrices) {
		t.Fatalf("matrix shape differs: got %d factors, want %d", len(got.Matrices), len(want.Matrices))
	}
	for factor := range got.Matrices {
		gotFactor := got.Matrices[factor]
		wantFactor := want.Matrices[factor]
		if gotFactor.LogBabyStepGiantStepRatio != wantFactor.LogBabyStepGiantStepRatio ||
			gotFactor.N1 != wantFactor.N1 || gotFactor.LevelQ != wantFactor.LevelQ || gotFactor.LevelP != wantFactor.LevelP {
			t.Fatalf("factor %d metadata differs", factor)
		}
		gotMetadata, err := gotFactor.MetaData.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		wantMetadata, err := wantFactor.MetaData.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotMetadata, wantMetadata) {
			t.Fatalf("factor %d serialized metadata differs", factor)
		}

		gotKeys := utils.GetKeys(gotFactor.Vec)
		wantKeys := utils.GetKeys(wantFactor.Vec)
		slices.Sort(gotKeys)
		slices.Sort(wantKeys)
		if !slices.Equal(gotKeys, wantKeys) {
			t.Fatalf("factor %d diagonal keys differ: got %v, want %v", factor, gotKeys, wantKeys)
		}
		for _, diagonal := range gotKeys {
			gotPoly := gotFactor.Vec[diagonal]
			wantPoly := wantFactor.Vec[diagonal]
			if !gotPoly.Equal(&wantPoly) {
				t.Fatalf("factor %d diagonal %d encoded polynomial differs", factor, diagonal)
			}
		}
	}
}

func explicitPrecisionCoefficientSentinel(t *testing.T, matrices []ltcommon.Diagonals[*bignum.Complex]) string {
	t.Helper()
	if len(matrices) == 0 {
		t.Fatal("numeric matrix list is empty")
	}
	diagonal, ok := matrices[0][1]
	if !ok || len(diagonal) == 0 || diagonal[0] == nil || diagonal[0][0] == nil || diagonal[0][1] == nil {
		t.Fatal("factor 0, diagonal +1, slot 0 numeric sentinel is unavailable")
	}
	value := diagonal[0]
	return fmt.Sprintf("real=%s;imag=%s;precision=%d", value[0].Text('x', -1), value[1].Text('x', -1), value.Prec())
}

func explicitPrecisionMatrixPayload(t *testing.T, matrix Matrix) []byte {
	t.Helper()

	var payload bytes.Buffer
	var word [8]byte
	writeUint64 := func(value uint64) {
		binary.LittleEndian.PutUint64(word[:], value)
		_, _ = payload.Write(word[:])
	}
	writeBytes := func(value []byte) {
		writeUint64(uint64(len(value)))
		_, _ = payload.Write(value)
	}

	writeUint64(uint64(len(matrix.Matrices)))
	for factor, transformation := range matrix.Matrices {
		writeUint64(uint64(factor))
		writeUint64(uint64(transformation.LogBabyStepGiantStepRatio))
		writeUint64(uint64(transformation.N1))
		writeUint64(uint64(transformation.LevelQ))
		writeUint64(uint64(transformation.LevelP))
		metadata, err := transformation.MetaData.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		writeBytes(metadata)

		keys := utils.GetKeys(transformation.Vec)
		slices.Sort(keys)
		writeUint64(uint64(len(keys)))
		for _, diagonal := range keys {
			writeUint64(uint64(diagonal))
			poly, err := transformation.Vec[diagonal].MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			writeBytes(poly)
		}
	}

	return payload.Bytes()
}

func explicitPrecisionPayloadDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
