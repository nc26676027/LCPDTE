package dft

import (
	"math/big"
	"testing"

	ltcommon "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/ring/ringqp"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestMatrixValidateAgainstIsPureAndRejectsForeignBSGSMetadata(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: []int{50, 50, 50, 50}, LogP: []int{50}, LogDefaultScale: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	literal := MatrixLiteral{
		Type: HomomorphicDecode, LogSlots: 3, LevelQ: 3, LevelP: 0,
		Levels: []int{1, 1}, Format: SplitRealAndImag,
	}
	encoder := ckks.NewEncoder(params, 256)
	consumer := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
	matrix, _, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err != nil {
		t.Fatal(err)
	}

	before := SnapshotMatrixConstructionCounters()
	if err = matrix.ValidateAgainst(params, literal); err != nil {
		t.Fatalf("valid observed Matrix rejected: %v", err)
	}
	delta, err := SnapshotMatrixConstructionCounters().Delta(before)
	if err != nil {
		t.Fatal(err)
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 || delta.ObservedStreaming() != 0 {
		t.Fatalf("Matrix.ValidateAgainst counter delta=%d/%d/%d/%d, want 0/0/0/0",
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming())
	}

	foreign := cloneObservedTestMatrix(matrix)
	foreign.Matrices[0].N1++
	if err = foreign.ValidateAgainst(params, literal); err == nil {
		t.Fatal("Matrix with foreign N1 metadata validated")
	}
}

func TestMatrixValidateAgainstRejectsLiteralMetadataTopologyAndQPShapeMutations(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: []int{50, 50, 50, 50}, LogP: []int{50}, LogDefaultScale: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	scaling := new(big.Float).SetPrec(180).SetMode(big.ToZero)
	scaling.SetFloat64(1.25)
	literal := MatrixLiteral{
		Type: HomomorphicDecode, LogSlots: 3, LevelQ: 3, LevelP: 0,
		Levels: []int{1, 1}, Format: SplitRealAndImag, Scaling: scaling,
	}
	encoder := ckks.NewEncoder(params, 256)
	consumer := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
	matrix, _, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := matrix.ValidateAgainst(params, literal); err != nil {
		t.Fatalf("valid Matrix rejected: %v", err)
	}
	before := SnapshotMatrixConstructionCounters()

	literalMutations := []struct {
		name   string
		mutate func(*Matrix)
	}{
		{"type", func(m *Matrix) { m.Type = HomomorphicEncode }},
		{"log slots", func(m *Matrix) { m.LogSlots-- }},
		{"level Q", func(m *Matrix) { m.LevelQ-- }},
		{"level P", func(m *Matrix) { m.LevelP = -1 }},
		{"levels nil", func(m *Matrix) { m.Levels = nil }},
		{"levels empty nonnil", func(m *Matrix) { m.Levels = []int{} }},
		{"levels value", func(m *Matrix) { m.Levels[0]++ }},
		{"format", func(m *Matrix) { m.Format = Standard }},
		{"scaling nil", func(m *Matrix) { m.Scaling = nil }},
		{"scaling value", func(m *Matrix) { m.Scaling.Add(m.Scaling, big.NewFloat(1)) }},
		{"scaling precision", func(m *Matrix) {
			m.Scaling = new(big.Float).SetPrec(m.Scaling.Prec() + 1).SetMode(m.Scaling.Mode()).Set(m.Scaling)
		}},
		{"scaling mode", func(m *Matrix) {
			m.Scaling = new(big.Float).SetPrec(m.Scaling.Prec()).SetMode(big.ToNearestEven).Set(m.Scaling)
		}},
		{"scaling accuracy", func(m *Matrix) { m.Scaling = sameDFTValueDifferentAccuracy(t, m.Scaling) }},
		{"bit reversed", func(m *Matrix) { m.BitReversed = !m.BitReversed }},
		{"log BSGS ratio", func(m *Matrix) { m.LogBSGSRatio-- }},
	}
	for _, test := range literalMutations {
		t.Run("literal/"+test.name, func(t *testing.T) {
			mutated := cloneObservedTestMatrix(matrix)
			test.mutate(&mutated)
			if err := mutated.ValidateAgainst(params, literal); err == nil {
				t.Fatal("literal mutation validated")
			}
		})
	}

	metadataMutations := []struct {
		name   string
		mutate func(*Matrix)
	}{
		{"nil metadata", func(m *Matrix) { m.Matrices[0].MetaData = nil }},
		{"starting level Q", func(m *Matrix) { m.Matrices[0].LevelQ-- }},
		{"level P", func(m *Matrix) { m.Matrices[0].LevelP-- }},
		{"BSGS ratio", func(m *Matrix) { m.Matrices[0].LogBabyStepGiantStepRatio-- }},
		{"N1", func(m *Matrix) { m.Matrices[0].N1++ }},
		{"dimension rows", func(m *Matrix) { m.Matrices[0].LogDimensions.Rows++ }},
		{"dimension cols", func(m *Matrix) { m.Matrices[0].LogDimensions.Cols-- }},
		{"is batched", func(m *Matrix) { m.Matrices[0].IsBatched = false }},
		{"is bit reversed", func(m *Matrix) { m.Matrices[0].IsBitReversed = true }},
		{"is NTT", func(m *Matrix) { m.Matrices[0].IsNTT = false }},
		{"is Montgomery", func(m *Matrix) { m.Matrices[0].IsMontgomery = false }},
		{"scale mod", func(m *Matrix) { m.Matrices[0].Scale.Mod = big.NewInt(17) }},
		{"scale value", func(m *Matrix) { m.Matrices[0].Scale.Value.Add(&m.Matrices[0].Scale.Value, big.NewFloat(1)) }},
		{"scale precision", func(m *Matrix) {
			value := &m.Matrices[0].Scale.Value
			m.Matrices[0].Scale.Value = *new(big.Float).SetPrec(value.Prec() + 1).SetMode(value.Mode()).Set(value)
		}},
		{"scale mode", func(m *Matrix) {
			value := &m.Matrices[0].Scale.Value
			m.Matrices[0].Scale.Value = *new(big.Float).SetPrec(value.Prec()).SetMode(big.ToZero).Set(value)
		}},
		{"scale accuracy", func(m *Matrix) {
			m.Matrices[0].Scale.Value = *sameDFTValueDifferentAccuracy(t, &m.Matrices[0].Scale.Value)
		}},
		{"vec nil", func(m *Matrix) { m.Matrices[0].Vec = nil }},
		{"vec empty", func(m *Matrix) { m.Matrices[0].Vec = map[int]ringqp.Poly{} }},
		{"vec key removed", func(m *Matrix) { delete(m.Matrices[0].Vec, firstObservedTestVecKey(m.Matrices[0])) }},
		{"vec key added", func(m *Matrix) {
			key := firstObservedTestVecKey(m.Matrices[0])
			poly := m.Matrices[0].Vec[key]
			foreignKey := 0
			for {
				if _, exists := m.Matrices[0].Vec[foreignKey]; !exists {
					break
				}
				foreignKey++
			}
			m.Matrices[0].Vec[foreignKey] = *poly.CopyNew()
		}},
		{"Q limb count", func(m *Matrix) {
			key := firstObservedTestVecKey(m.Matrices[0])
			poly := m.Matrices[0].Vec[key]
			poly.Q.Coeffs = poly.Q.Coeffs[:len(poly.Q.Coeffs)-1]
			m.Matrices[0].Vec[key] = poly
		}},
		{"Q coefficient count", func(m *Matrix) {
			key := firstObservedTestVecKey(m.Matrices[0])
			poly := m.Matrices[0].Vec[key]
			poly.Q.Coeffs[0] = poly.Q.Coeffs[0][:len(poly.Q.Coeffs[0])-1]
			m.Matrices[0].Vec[key] = poly
		}},
		{"P limb count", func(m *Matrix) {
			key := firstObservedTestVecKey(m.Matrices[0])
			poly := m.Matrices[0].Vec[key]
			poly.P.Coeffs = poly.P.Coeffs[:0]
			m.Matrices[0].Vec[key] = poly
		}},
		{"P coefficient count", func(m *Matrix) {
			key := firstObservedTestVecKey(m.Matrices[0])
			poly := m.Matrices[0].Vec[key]
			poly.P.Coeffs[0] = poly.P.Coeffs[0][:len(poly.P.Coeffs[0])-1]
			m.Matrices[0].Vec[key] = poly
		}},
	}
	for _, test := range metadataMutations {
		t.Run("factor/"+test.name, func(t *testing.T) {
			mutated := cloneObservedTestMatrix(matrix)
			test.mutate(&mutated)
			if err := mutated.ValidateAgainst(params, literal); err == nil {
				t.Fatal("factor mutation validated")
			}
		})
	}

	for _, test := range []struct {
		name   string
		mutate func(*Matrix)
	}{
		{"factor removed", func(m *Matrix) { m.Matrices = m.Matrices[:len(m.Matrices)-1] }},
		{"factor appended", func(m *Matrix) { m.Matrices = append(m.Matrices, m.Matrices[0]) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := cloneObservedTestMatrix(matrix)
			test.mutate(&mutated)
			if err := mutated.ValidateAgainst(params, literal); err == nil {
				t.Fatal("factor-count mutation validated")
			}
		})
	}

	// A bare Matrix intentionally validates structure, not resident payload
	// identity. The Route-B artifact seal owns the canonical encoded digest.
	payloadOnly := cloneObservedTestMatrix(matrix)
	payloadKey := firstObservedTestVecKey(payloadOnly.Matrices[0])
	payloadPoly := payloadOnly.Matrices[0].Vec[payloadKey]
	payloadPoly.Q.Coeffs[0][0] ^= 1
	payloadOnly.Matrices[0].Vec[payloadKey] = payloadPoly
	if err := payloadOnly.ValidateAgainst(params, literal); err != nil {
		t.Fatalf("bare Matrix validator claimed payload identity: %v", err)
	}

	for iteration := 0; iteration < 3; iteration++ {
		if err := matrix.ValidateAgainst(params, literal); err != nil {
			t.Fatal(err)
		}
	}
	delta, err := SnapshotMatrixConstructionCounters().Delta(before)
	if err != nil {
		t.Fatal(err)
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 || delta.ObservedStreaming() != 0 {
		t.Fatalf("validation matrix counter delta=%d/%d/%d/%d, want zero",
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming())
	}
}

func TestMatrixValidateAgainstRejectsInvalidExpectedLiteralWithoutConstruction(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: []int{50, 50, 50, 50}, LogP: []int{50}, LogDefaultScale: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := MatrixLiteral{
		Type: HomomorphicDecode, LogSlots: 3, LevelQ: 3, LevelP: 0,
		Levels: []int{1, 1}, Format: SplitRealAndImag,
	}
	invalid := []struct {
		name   string
		mutate func(*MatrixLiteral)
	}{
		{"type", func(l *MatrixLiteral) { l.Type = Type(9) }},
		{"format", func(l *MatrixLiteral) { l.Format = Format(9) }},
		{"log slots zero", func(l *MatrixLiteral) { l.LogSlots = 0 }},
		{"log slots too high", func(l *MatrixLiteral) { l.LogSlots = params.LogMaxDimensions().Cols + 1 }},
		{"level Q negative", func(l *MatrixLiteral) { l.LevelQ = -1 }},
		{"level Q too high", func(l *MatrixLiteral) { l.LevelQ = params.MaxLevelQ() + 1 }},
		{"level P too low", func(l *MatrixLiteral) { l.LevelP = -2 }},
		{"level P too high", func(l *MatrixLiteral) { l.LevelP = params.MaxLevelP() + 1 }},
		{"levels nil", func(l *MatrixLiteral) { l.Levels = nil }},
		{"levels empty", func(l *MatrixLiteral) { l.Levels = []int{} }},
		{"level group zero", func(l *MatrixLiteral) { l.Levels[0] = 0 }},
		{"level group negative", func(l *MatrixLiteral) { l.Levels[0] = -1 }},
		{"depth exceeds slots", func(l *MatrixLiteral) { l.Levels = []int{2, 2} }},
		{"depth sum overflow", func(l *MatrixLiteral) { l.Levels = []int{int(^uint(0) >> 1), 1} }},
		{"scale chain underflow", func(l *MatrixLiteral) { l.LevelQ = 0 }},
		{"BSGS ratio overflow", func(l *MatrixLiteral) { l.LogBSGSRatio = int(^uint(0) >> 1) }},
		{"scaling zero precision", func(l *MatrixLiteral) { l.Scaling = &big.Float{} }},
		{"scaling too precise", func(l *MatrixLiteral) { l.Scaling = new(big.Float).SetPrec(257).SetInt64(1) }},
		{"scaling infinity", func(l *MatrixLiteral) { l.Scaling = new(big.Float).SetInf(false) }},
		{"scaling rounding mode", func(l *MatrixLiteral) {
			l.Scaling = new(big.Float).SetPrec(128).SetInt64(1)
			l.Scaling.SetMode(big.RoundingMode(255))
		}},
	}
	before := SnapshotMatrixConstructionCounters()
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			literal := cloneDFTMatrixLiteral(base)
			test.mutate(&literal)
			if err := (Matrix{}).ValidateAgainst(params, literal); err == nil {
				t.Fatal("invalid expected literal validated")
			}
		})
	}
	delta, err := SnapshotMatrixConstructionCounters().Delta(before)
	if err != nil {
		t.Fatal(err)
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 || delta.ObservedStreaming() != 0 {
		t.Fatalf("invalid-literal counter delta=%d/%d/%d/%d, want zero",
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming())
	}

	positiveZero := new(big.Float).SetPrec(128).SetInt64(0)
	negativeZero := new(big.Float).SetPrec(128).SetInt64(0)
	negativeZero.Neg(negativeZero)
	if equalBigFloatExact(positiveZero, negativeZero) {
		t.Fatal("exact big.Float identity ignored signed zero")
	}
	if equalDFTMatrixLiteral(MatrixLiteral{Levels: nil}, MatrixLiteral{Levels: []int{}}) {
		t.Fatal("exact MatrixLiteral identity conflated nil and empty Levels")
	}
	if equalDFTMatrixLiteral(MatrixLiteral{Levels: []int{1, 2}}, MatrixLiteral{Levels: []int{2, 1}}) {
		t.Fatal("exact MatrixLiteral identity ignored factor-group order")
	}
}

func TestMatrixValidateAgainstAcceptsAbsentPAndRejectsForeignPShape(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: []int{50, 50, 50, 50}, LogP: []int{50}, LogDefaultScale: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	literal := MatrixLiteral{
		Type: HomomorphicDecode, LogSlots: 3, LevelQ: 3, LevelP: -1,
		Levels: []int{1, 1}, Format: SplitRealAndImag,
	}
	encoder := ckks.NewEncoder(params, 256)
	consumer := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
	matrix, _, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := matrix.ValidateAgainst(params, literal); err != nil {
		t.Fatalf("valid P-absent Matrix rejected: %v", err)
	}
	for factorIndex, transformation := range matrix.Matrices {
		if transformation.LevelP != -1 {
			t.Fatalf("factor %d LevelP=%d, want -1", factorIndex, transformation.LevelP)
		}
		for key, poly := range transformation.Vec {
			if poly.LevelP() != -1 || len(poly.P.Coeffs) != 0 {
				t.Fatalf("factor %d diagonal %d has foreign P shape", factorIndex, key)
			}
		}
	}

	foreign := cloneObservedTestMatrix(matrix)
	key := firstObservedTestVecKey(foreign.Matrices[0])
	poly := foreign.Matrices[0].Vec[key]
	poly.P.Coeffs = [][]uint64{make([]uint64, params.N())}
	foreign.Matrices[0].Vec[key] = poly
	if err := foreign.ValidateAgainst(params, literal); err == nil {
		t.Fatal("P-absent Matrix with a foreign P limb validated")
	}
}

func firstObservedTestVecKey(transformation ltcommon.LinearTransformation) int {
	for key := range transformation.Vec {
		return key
	}
	panic("test fixture has no Vec key")
}

func sameDFTValueDifferentAccuracy(t *testing.T, value *big.Float) *big.Float {
	t.Helper()
	highPrecision := value.Prec() + 80
	high := new(big.Float).SetPrec(highPrecision).Set(value)
	epsilon := new(big.Float).SetPrec(highPrecision).SetMantExp(new(big.Float).SetPrec(highPrecision).SetInt64(1), -int(value.Prec()))
	high.Add(high, epsilon)
	mutated := new(big.Float).SetPrec(value.Prec()).SetMode(value.Mode()).Set(high)
	if mutated.Cmp(value) != 0 || mutated.Acc() == value.Acc() {
		t.Fatalf("failed to construct same-value/different-accuracy sentinel: value=%s acc=%s mutated=%s acc=%s",
			value.Text('x', -1), value.Acc(), mutated.Text('x', -1), mutated.Acc())
	}
	return mutated
}

func cloneObservedTestMatrix(matrix Matrix) Matrix {
	result := Matrix{MatrixLiteral: cloneDFTMatrixLiteral(matrix.MatrixLiteral)}
	result.Matrices = make([]ltcommon.LinearTransformation, len(matrix.Matrices))
	for index, transformation := range matrix.Matrices {
		copyTransformation := transformation
		copyTransformation.MetaData = transformation.MetaData.CopyNew()
		copyTransformation.MetaData.Scale.Value = *new(big.Float).Copy(&transformation.MetaData.Scale.Value)
		if transformation.MetaData.Scale.Mod != nil {
			copyTransformation.MetaData.Scale.Mod = new(big.Int).Set(transformation.MetaData.Scale.Mod)
		}
		copyTransformation.Vec = make(map[int]ringqp.Poly, len(transformation.Vec))
		for diagonal, polynomial := range transformation.Vec {
			copyTransformation.Vec[diagonal] = *polynomial.CopyNew()
		}
		result.Matrices[index] = copyTransformation
	}
	return result
}
