package dft

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"slices"
	"testing"

	ltcommon "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestMultiplyFFTMatrixDeterministicAcrossShuffledMaps(t *testing.T) {
	const (
		logL       = 7
		N          = 1 << logL
		nextLevel  = 1
		iterations = 100
	)

	one := []*bignum.Complex{bignum.ToComplex(1, 53)}
	entries := []struct {
		key   int
		value float64
	}{
		{key: 0, value: 1 << 60},
		{key: 1, value: 1},
		{key: N - 1, value: -(1 << 60)},
	}

	rng := rand.New(rand.NewSource(0x5eed))
	var want *big.Float
	for iteration := 0; iteration < iterations; iteration++ {
		rng.Shuffle(len(entries), func(i, j int) {
			entries[i], entries[j] = entries[j], entries[i]
		})

		input := make(map[int][]*bignum.Complex, len(entries))
		for _, entry := range entries {
			input[entry.key] = []*bignum.Complex{bignum.ToComplex(entry.value, 53)}
		}

		got := multiplyFFTMatrixWithNextFFTLevel(input, logL, N, nextLevel, one, one, one, HomomorphicEncode, false)
		sentinel := got[0][0][0]
		if iteration == 0 {
			want = new(big.Float).Set(sentinel)
			continue
		}
		if sentinel.Cmp(want) != 0 {
			t.Fatalf("iteration %d produced %s, first iteration produced %s", iteration, sentinel.Text('x', -1), want.Text('x', -1))
		}
	}
	if want.Sign() != 0 {
		t.Fatalf("sorted source-key accumulation produced %s, want exact zero", want.Text('x', -1))
	}
}

func TestForEachMatrixFactorStopsAtCallbackError(t *testing.T) {
	literal := explicitPrecisionTestLiteral()
	sentinel := errors.New("stop after first factor")
	calls := 0

	err := literal.ForEachMatrixFactor(4, 53, func(ltcommon.Diagonals[*bignum.Complex]) error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("got error %v, want callback sentinel", err)
	}
	if calls != 1 {
		t.Fatalf("callback ran %d times, want exactly once", calls)
	}
}

func TestForEachMatrixFactorCallbackErrorSkipsFutureLayers(t *testing.T) {
	literal := MatrixLiteral{
		Type:     HomomorphicEncode,
		LogSlots: 3,
		Levels:   []int{1, 1},
	}
	const (
		logN = 4
		prec = 53
	)
	roots := ckks.GetRootsBigComplex((1<<literal.LogSlots)<<2, prec)

	liveFactors, maxLiveFactors, factorStarts := 0, 0, 0
	liveLayers, maxLiveLayers, layerStarts := 0, 0, 0
	observe := func(live, maximum, starts *int) func(int) {
		return func(delta int) {
			*live += delta
			if delta > 0 {
				(*starts)++
			}
			if *live > *maximum {
				*maximum = *live
			}
			if *live < 0 {
				t.Fatalf("observer count became negative")
			}
		}
	}
	observer := matrixFactorGenerationObserver{
		factorDelta: observe(&liveFactors, &maxLiveFactors, &factorStarts),
		layerDelta:  observe(&liveLayers, &maxLiveLayers, &layerStarts),
	}

	sentinel := errors.New("stop after first completed factor")
	callbacks := 0
	err := literal.forEachMatrixFactorObserved(logN, prec, roots, observer, func(ltcommon.Diagonals[*bignum.Complex]) error {
		callbacks++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("got error %v, want callback sentinel", err)
	}
	if callbacks != 1 || factorStarts != 1 {
		t.Fatalf("callbacks=%d factor starts=%d, want 1/1", callbacks, factorStarts)
	}
	// With LogSlots=3 and two factors, the frozen merge schedule consumes two
	// layers for factor 0 and one future layer for factor 1. The sentinel must
	// prevent generation of that third layer.
	if layerStarts != 2 {
		t.Fatalf("generated %d layers, want only the first factor's 2 layers", layerStarts)
	}
	if liveFactors != 0 || liveLayers != 0 {
		t.Fatalf("live counts after stop are factor=%d layer=%d, want 0/0", liveFactors, liveLayers)
	}
	if maxLiveFactors != 1 || maxLiveLayers != 1 {
		t.Fatalf("max live numeric factor/layer=%d/%d, want 1/1", maxLiveFactors, maxLiveLayers)
	}
}

func TestForEachMatrixFactorMatchesFrozenLegacyAlgorithm(t *testing.T) {
	customScale := new(big.Float).SetPrec(180).SetFloat64(1.25)
	tests := []struct {
		name    string
		logN    int
		prec    uint
		literal MatrixLiteral
	}{
		{
			name:    "encode-standard-forward-nil-scale-depth-2-1",
			logN:    4,
			prec:    53,
			literal: MatrixLiteral{Type: HomomorphicEncode, LogSlots: 3, Levels: []int{2, 1}},
		},
		{
			name:    "decode-split-bit-reversed-custom-scale-depth-1-2",
			logN:    4,
			prec:    128,
			literal: MatrixLiteral{Type: HomomorphicDecode, LogSlots: 3, Levels: []int{1, 2}, Format: SplitRealAndImag, BitReversed: true, Scaling: customScale},
		},
		{
			name:    "encode-sparse-repack-bit-reversed-depth-1-1-1",
			logN:    5,
			prec:    128,
			literal: MatrixLiteral{Type: HomomorphicEncode, LogSlots: 3, Levels: []int{1, 1, 1}, Format: RepackImagAsReal, BitReversed: true},
		},
		{
			name:    "decode-sparse-repack-forward-custom-scale-depth-3",
			logN:    5,
			prec:    128,
			literal: MatrixLiteral{Type: HomomorphicDecode, LogSlots: 3, Levels: []int{3}, Format: RepackImagAsReal, Scaling: customScale},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := legacyGenMatricesReference(test.literal, test.logN, test.prec)
			got := make([]ltcommon.Diagonals[*bignum.Complex], 0, len(want))
			if err := test.literal.ForEachMatrixFactor(test.logN, test.prec, func(factor ltcommon.Diagonals[*bignum.Complex]) error {
				got = append(got, factor)
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			assertPlainMatrixFactorsEqual(t, got, want)
			assertPlainMatrixFactorsEqual(t, test.literal.GenMatrices(test.logN, test.prec), want)
		})
	}
}

func TestForEachMatrixFactorBitReversedOwnsRootsAndFactors(t *testing.T) {
	literal := MatrixLiteral{
		Type:        HomomorphicDecode,
		LogSlots:    3,
		Levels:      []int{1, 1, 1},
		Format:      RepackImagAsReal,
		BitReversed: true,
	}
	const (
		logN = 5
		prec = 128
	)

	roots := ckks.GetRootsBigComplex((1<<literal.LogSlots)<<2, prec)
	rootPointers := append([]*bignum.Complex(nil), roots...)
	rootValues := make([]*bignum.Complex, len(roots))
	for i := range roots {
		rootValues[i] = roots[i].Clone()
	}

	activeCallbacks := 0
	maxActiveCallbacks := 0
	factors := make([]ltcommon.Diagonals[*bignum.Complex], 0, literal.Depth(false))
	if err := literal.forEachMatrixFactor(logN, prec, roots, func(factor ltcommon.Diagonals[*bignum.Complex]) error {
		activeCallbacks++
		if activeCallbacks > maxActiveCallbacks {
			maxActiveCallbacks = activeCallbacks
		}
		factors = append(factors, factor)
		activeCallbacks--
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if maxActiveCallbacks != 1 {
		t.Fatalf("maximum live factor callback count is %d, want 1", maxActiveCallbacks)
	}

	rootSet := make(map[*bignum.Complex]struct{}, len(roots))
	for i := range roots {
		rootSet[roots[i]] = struct{}{}
		if roots[i] != rootPointers[i] {
			t.Fatalf("root %d pointer changed", i)
		}
		if roots[i].Prec() != rootValues[i].Prec() || roots[i][0].Cmp(rootValues[i][0]) != 0 || roots[i][1].Cmp(rootValues[i][1]) != 0 {
			t.Fatalf("root %d changed during bit-reversed generation", i)
		}
	}

	seen := make(map[*bignum.Complex]string)
	for factor, diagonals := range factors {
		for diagonal, vector := range diagonals {
			for slot, value := range vector {
				location := fmt.Sprintf("factor=%d diagonal=%d slot=%d", factor, diagonal, slot)
				if _, aliasesRoot := rootSet[value]; aliasesRoot {
					t.Fatalf("%s aliases a root", location)
				}
				if previous, aliasesFactor := seen[value]; aliasesFactor {
					t.Fatalf("%s aliases %s", location, previous)
				}
				seen[value] = location
			}
		}
	}
}

func TestNewMatrixFromLiteralWithGeneratorPrecisionStreamingMatchesLegacyBuilder(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            5,
		LogQ:            []int{60, 60, 60, 60},
		LogP:            []int{60},
		LogDefaultScale: 43,
	})
	if err != nil {
		t.Fatal(err)
	}
	const precision = uint(256)
	encoder := ckks.NewEncoder(params, precision)
	customScale := new(big.Float).SetPrec(180).SetFloat64(1.25)

	tests := []struct {
		name    string
		literal MatrixLiteral
	}{
		{
			name:    "encode-standard-forward-nil-scale-depth-2-1",
			literal: MatrixLiteral{Type: HomomorphicEncode, LogSlots: 3, LevelQ: 3, LevelP: 0, Levels: []int{2, 1}},
		},
		{
			name:    "decode-split-bit-reversed-custom-scale-depth-1-2",
			literal: MatrixLiteral{Type: HomomorphicDecode, LogSlots: 3, LevelQ: 3, LevelP: 0, Levels: []int{1, 2}, Format: SplitRealAndImag, BitReversed: true, Scaling: customScale},
		},
		{
			name:    "encode-sparse-repack-bit-reversed-depth-1-1-1",
			literal: MatrixLiteral{Type: HomomorphicEncode, LogSlots: 3, LevelQ: 3, LevelP: 0, Levels: []int{1, 1, 1}, Format: RepackImagAsReal, BitReversed: true},
		},
		{
			name:    "decode-sparse-repack-forward-custom-scale-depth-3",
			literal: MatrixLiteral{Type: HomomorphicDecode, LogSlots: 3, LevelQ: 3, LevelP: 0, Levels: []int{3}, Format: RepackImagAsReal, Scaling: customScale},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			legacy, err := NewMatrixFromLiteralWithGeneratorPrecision(params, test.literal, encoder, precision)
			if err != nil {
				t.Fatal(err)
			}
			streaming, err := NewMatrixFromLiteralWithGeneratorPrecisionStreaming(params, test.literal, encoder, precision)
			if err != nil {
				t.Fatal(err)
			}

			assertExplicitPrecisionMatricesEqual(t, streaming, legacy)
			if !bytes.Equal(explicitPrecisionMatrixPayload(t, streaming), explicitPrecisionMatrixPayload(t, legacy)) {
				t.Fatal("canonical encoded payload differs")
			}
			for factor := range streaming.Matrices {
				if streaming.Matrices[factor].LevelQ != test.literal.LevelQ {
					t.Fatalf("factor %d LevelQ=%d, want literal LevelQ=%d", factor, streaming.Matrices[factor].LevelQ, test.literal.LevelQ)
				}
			}
		})
	}
}

// legacyGenMatricesReference freezes the pre-streaming whole-vector control flow.
// It intentionally remains test-only so GenMatrices can become a collector over
// the public factor callback without making this reference circular.
func legacyGenMatricesReference(d MatrixLiteral, logN int, prec uint) (plainVector []ltcommon.Diagonals[*bignum.Complex]) {
	logSlots := d.LogSlots
	slots := 1 << logSlots
	maxDepth := d.Depth(false)
	ltType := d.Type
	bitreversed := d.BitReversed
	imagRepack := d.Format == RepackImagAsReal

	logdSlots := logSlots
	if logdSlots < logN-1 && imagRepack {
		logdSlots++
	}

	roots := ckks.GetRootsBigComplex(slots<<2, prec)
	pow5 := make([]int, (slots<<1)+1)
	pow5[0] = 1
	for i := 1; i < (slots<<1)+1; i++ {
		pow5[i] = pow5[i-1] * 5
		pow5[i] &= (slots << 2) - 1
	}

	var a, b, c [][]*bignum.Complex
	if ltType == HomomorphicEncode {
		a, b, c = ifftPlainVec(logSlots, 1<<logdSlots, roots, pow5)
	} else {
		a, b, c = fftPlainVec(logSlots, 1<<logdSlots, roots, pow5)
	}

	merge := make([]int, maxDepth)
	fftLevel := logSlots
	for i := 0; i < maxDepth; i++ {
		depth := int(math.Ceil(float64(fftLevel) / float64(maxDepth-i)))
		if ltType == HomomorphicEncode {
			merge[i] = depth
		} else {
			merge[len(merge)-i-1] = depth
		}
		fftLevel -= depth
	}

	plainVector = make([]ltcommon.Diagonals[*bignum.Complex], maxDepth)
	fftLevel = logSlots
	for i := 0; i < maxDepth; i++ {
		if logSlots != logdSlots && ltType == HomomorphicDecode && i == 0 && imagRepack {
			plainVector[i] = genRepackMatrix(logSlots, prec, bitreversed)
			plainVector[i] = multiplyFFTMatrixWithNextFFTLevel(plainVector[i], logSlots, 2*slots, fftLevel, a[logSlots-fftLevel], b[logSlots-fftLevel], c[logSlots-fftLevel], ltType, bitreversed)
			nextfftLevel := fftLevel - 1
			for j := 0; j < merge[i]-1; j++ {
				plainVector[i] = multiplyFFTMatrixWithNextFFTLevel(plainVector[i], logSlots, 2*slots, nextfftLevel, a[logSlots-nextfftLevel], b[logSlots-nextfftLevel], c[logSlots-nextfftLevel], ltType, bitreversed)
				nextfftLevel--
			}
		} else {
			plainVector[i] = genFFTDiagMatrix(logSlots, fftLevel, a[logSlots-fftLevel], b[logSlots-fftLevel], c[logSlots-fftLevel], ltType, bitreversed)
			nextfftLevel := fftLevel - 1
			for j := 0; j < merge[i]-1; j++ {
				plainVector[i] = multiplyFFTMatrixWithNextFFTLevel(plainVector[i], logSlots, slots, nextfftLevel, a[logSlots-nextfftLevel], b[logSlots-nextfftLevel], c[logSlots-nextfftLevel], ltType, bitreversed)
				nextfftLevel--
			}
		}
		fftLevel -= merge[i]
	}

	if logSlots != logdSlots && ltType == HomomorphicEncode && imagRepack {
		for j := range plainVector[maxDepth-1] {
			v := plainVector[maxDepth-1][j]
			for x := 0; x < slots; x++ {
				v[x+slots] = bignum.NewComplex().SetPrec(prec)
			}
		}
	}

	scaling := new(big.Float).SetPrec(prec)
	if d.Scaling == nil {
		scaling.SetFloat64(1)
	} else {
		scaling.Set(d.Scaling)
	}
	if ltType == HomomorphicEncode {
		if d.Format == RepackImagAsReal || d.Format == SplitRealAndImag {
			scaling.Quo(scaling, new(big.Float).SetFloat64(float64(2*slots)))
		} else {
			scaling.Quo(scaling, new(big.Float).SetFloat64(float64(slots)))
		}
	}
	scaling = bignum.Pow(scaling, new(big.Float).Quo(new(big.Float).SetPrec(prec).SetFloat64(1), new(big.Float).SetPrec(prec).SetFloat64(float64(d.Depth(false)))))

	for j := range plainVector {
		for x := range plainVector[j] {
			v := plainVector[j][x]
			for i := range v {
				v[i][0].Mul(v[i][0], scaling)
				v[i][1].Mul(v[i][1], scaling)
			}
		}
	}

	return plainVector
}

func assertPlainMatrixFactorsEqual(t *testing.T, got, want []ltcommon.Diagonals[*bignum.Complex]) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d factors, want %d", len(got), len(want))
	}
	for factor := range want {
		gotKeys := got[factor].DiagonalsIndexList()
		wantKeys := want[factor].DiagonalsIndexList()
		slices.Sort(gotKeys)
		slices.Sort(wantKeys)
		if !slices.Equal(gotKeys, wantKeys) {
			t.Fatalf("factor %d keys differ: got %v, want %v", factor, gotKeys, wantKeys)
		}
		for _, diagonal := range wantKeys {
			if len(got[factor][diagonal]) != len(want[factor][diagonal]) {
				t.Fatalf("factor %d diagonal %d length differs", factor, diagonal)
			}
			for slot := range want[factor][diagonal] {
				gotValue := got[factor][diagonal][slot]
				wantValue := want[factor][diagonal][slot]
				if gotValue.Prec() != wantValue.Prec() || gotValue[0].Cmp(wantValue[0]) != 0 || gotValue[1].Cmp(wantValue[1]) != 0 {
					t.Fatalf("factor %d diagonal %d slot %d differs: got (%s,%s)/%d, want (%s,%s)/%d", factor, diagonal, slot, gotValue[0].Text('x', -1), gotValue[1].Text('x', -1), gotValue.Prec(), wantValue[0].Text('x', -1), wantValue[1].Text('x', -1), wantValue.Prec())
				}
			}
		}
	}
}
