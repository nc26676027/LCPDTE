package dft

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"

	ltcommon "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type observedFactorConsumerFunc func(ObservedFactorInput) (*ObservedFactorProduct, error)

func (f observedFactorConsumerFunc) ConsumeObservedFactor(input ObservedFactorInput) (*ObservedFactorProduct, error) {
	return f(input)
}

func TestNewMatrixFromLiteralObservedStreamingCountsBeforeValidation(t *testing.T) {
	before := SnapshotMatrixConstructionCounters()

	_, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		ckks.Parameters{},
		ObservedSlotsToCoeffs,
		MatrixLiteral{},
		nil,
		53,
		nil,
	)
	if err == nil {
		t.Fatal("nil consumer unexpectedly succeeded")
	}
	if trace.CompletedEventCount() != 0 || trace.AttemptedEventLowerBound() != 0 {
		t.Fatalf("pre-construction failure reported completed/attempted events %d/%d, want 0/0", trace.CompletedEventCount(), trace.AttemptedEventLowerBound())
	}

	delta, deltaErr := SnapshotMatrixConstructionCounters().Delta(before)
	if deltaErr != nil {
		t.Fatal(deltaErr)
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 || delta.ObservedStreaming() != 1 {
		t.Fatalf("counter delta=%d/%d/%d/%d, want 0/0/0/1", delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming())
	}
}

func TestObservedStreamingConsumerFailureAndPanicSealCleanupOutsideSuccessPrefix(t *testing.T) {
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
	sentinel := errors.New("consumer stopped")

	for _, test := range []struct {
		name     string
		consumer observedFactorConsumerFunc
		wantText string
	}{
		{
			name: "error",
			consumer: func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
				if input.Role() != ObservedSlotsToCoeffs || input.Index() != 0 || input.Count() != 2 ||
					input.GeneratorPrecision() != 256 || input.EncoderPrecision() != 256 {
					t.Fatalf("consumer received foreign typed input: role=%d index=%d count=%d generator=%d encoder=%d",
						input.Role(), input.Index(), input.Count(), input.GeneratorPrecision(), input.EncoderPrecision())
				}
				if factor, ok := input.BorrowedNumericFactor(); !ok || factor == nil {
					t.Fatal("consumer did not receive the synchronous borrowed factor")
				}
				return nil, sentinel
			},
			wantText: sentinel.Error(),
		},
		{
			name: "panic",
			consumer: func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
				if factor, ok := input.BorrowedNumericFactor(); !ok || factor == nil {
					t.Fatal("consumer did not receive the synchronous borrowed factor")
				}
				panic("consumer panic sentinel")
			},
			wantText: "consumer panic sentinel",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var retainedInput ObservedFactorInput
			consumer := observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
				retainedInput = input
				return test.consumer.ConsumeObservedFactor(input)
			})
			matrix, trace, gotErr := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
				params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
			)
			if gotErr == nil || !strings.Contains(gotErr.Error(), test.wantText) {
				t.Fatalf("got error %v, want text %q", gotErr, test.wantText)
			}
			if !reflect.DeepEqual(matrix, Matrix{}) {
				t.Fatal("consumer failure returned an installable Matrix")
			}
			if _, ok := retainedInput.BorrowedNumericFactor(); ok {
				t.Fatal("vendor borrowed-factor capability remained active after callback")
			}
			events := trace.Events()
			cleanup := trace.CleanupEvents()
			if trace.Status() != ObservedStreamingFailure || trace.FailureStage() != ObservedStreamingFailureConsumer ||
				trace.CompletedEventCount() != 2 || trace.AttemptedEventLowerBound() != 3 ||
				len(events) != 2 || events[0].Code() != ObservedStreamingTransformStart ||
				events[1].Code() != ObservedStreamingFactorGenerated ||
				len(cleanup) != 2 || cleanup[0].Code() != ObservedStreamingCleanupFactorReferenceCleared ||
				cleanup[1].Code() != ObservedStreamingCleanupGeneratorReferencesCleared {
				t.Fatalf("failure grammar changed: status=%d stage=%d events=%+v cleanup=%+v attempted=%d",
					trace.Status(), trace.FailureStage(), events, cleanup, trace.AttemptedEventLowerBound())
			}
			if err := trace.Validate(); err != nil {
				t.Fatalf("sealed consumer failure trace rejected: %v", err)
			}
		})
	}
}

type observedEncodingTestConsumer struct {
	t        *testing.T
	params   ckks.Parameters
	encoder  *ckks.Encoder
	inputs   []ObservedFactorInput
	products []*ObservedFactorProduct
}

func (c *observedEncodingTestConsumer) ConsumeObservedFactor(input ObservedFactorInput) (*ObservedFactorProduct, error) {
	c.t.Helper()
	factor, ok := input.BorrowedNumericFactor()
	if !ok {
		return nil, errors.New("test consumer received an inactive factor")
	}
	literal := input.Literal()
	scale := observedTestFactorScale(c.t, c.params, literal, int(input.Index()))
	logDimensions := ring.Dimensions{Rows: 0, Cols: literal.LogSlots}
	if literal.Format == RepackImagAsReal && literal.LogSlots < c.params.LogMaxDimensions().Cols {
		logDimensions.Cols++
	}
	donor := ltcommon.NewTransformation(c.params, ltcommon.Parameters{
		DiagonalsIndexList: factor.DiagonalsIndexList(), LevelQ: literal.LevelQ, LevelP: literal.LevelP,
		Scale: scale, LogDimensions: logDimensions, LogBabyStepGiantStepRatio: literal.LogBSGSRatio,
	})
	if err := ltcommon.Encode(c.encoder, factor, donor); err != nil {
		return nil, err
	}
	numericDigest, numericBytes := observedTestNumericDigest(c.t, factor)
	encodedDigest, encodedBytes := observedTestEncodedDigest(c.t, donor)
	product, err := NewObservedFactorProduct(
		input, numericDigest, numericBytes, encodedDigest, encodedBytes, &donor,
	)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(donor, ltcommon.LinearTransformation{}) {
		c.t.Fatal("product constructor did not clear the LT donor")
	}
	c.inputs = append(c.inputs, input)
	c.products = append(c.products, product)
	return product, nil
}

func TestObservedStreamingPreservesGroupedScaleScheduleAndStartingLevel(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: []int{50, 50, 50, 50}, LogP: []int{50}, LogDefaultScale: 65,
	})
	if err != nil {
		t.Fatal(err)
	}
	if params.LevelsConsumedPerRescaling() != 2 {
		t.Fatalf("fixture consumes %d levels per rescale, want 2", params.LevelsConsumedPerRescaling())
	}
	encoder := ckks.NewEncoder(params, 256)
	for _, test := range []struct {
		name   string
		levels []int
	}{
		{"one depth-two group", []int{2}},
		{"two depth-one groups", []int{1, 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			literal := MatrixLiteral{
				Type: HomomorphicDecode, LogSlots: 3, LevelQ: 3, LevelP: 0,
				Levels: append([]int(nil), test.levels...), Format: SplitRealAndImag,
			}
			consumer := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
			matrix, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
				params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
			)
			if err != nil {
				t.Fatal(err)
			}
			if trace.Validate() != nil || len(matrix.Matrices) != 2 {
				t.Fatalf("grouped schedule fixture failed: validate=%v factors=%d", trace.Validate(), len(matrix.Matrices))
			}
			for factorIndex, transformation := range matrix.Matrices {
				want := observedTestFactorScale(t, params, literal, factorIndex)
				if transformation.LevelQ != literal.LevelQ || transformation.LevelP != literal.LevelP ||
					!equalRLWEScaleExact(transformation.Scale, want) {
					t.Fatalf("factor %d starting level/scale changed: Q/P=%d/%d scale=%s want Q/P=%d/%d scale=%s",
						factorIndex, transformation.LevelQ, transformation.LevelP, transformation.Scale.Value.Text('x', -1),
						literal.LevelQ, literal.LevelP, want.Value.Text('x', -1))
				}
			}
			if test.levels[0] == 2 && !equalRLWEScaleExact(matrix.Matrices[0].Scale, matrix.Matrices[1].Scale) {
				t.Fatal("two factors in one depth-two group did not share the exact root scale")
			}
			if err := matrix.ValidateAgainst(params, literal); err != nil {
				t.Fatalf("grouped schedule rejected: %v", err)
			}
		})
	}
}

func observedTestFactorScale(t *testing.T, params ckks.Parameters, literal MatrixLiteral, factorIndex int) rlwe.Scale {
	t.Helper()
	consumed := params.LevelsConsumedPerRescaling()
	level := literal.LevelQ
	current := 0
	for _, groupDepth := range literal.Levels {
		scale := rlwe.NewScale(params.Q()[level])
		for offset := 1; offset < consumed; offset++ {
			scale = scale.Mul(rlwe.NewScale(params.Q()[level-offset]))
		}
		if groupDepth > 1 {
			exponent := new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(1)
			exponent.Quo(exponent, new(big.Float).SetPrec(scale.Value.Prec()).SetInt64(int64(groupDepth)))
			scale.Value = *bignum.Pow(&scale.Value, exponent)
		}
		if factorIndex >= current && factorIndex < current+groupDepth {
			return scale
		}
		current += groupDepth
		level -= consumed
	}
	t.Fatalf("factor index %d outside literal depth %d", factorIndex, literal.Depth(false))
	return rlwe.Scale{}
}

func TestObservedStreamingSuccessHasExactTypedLifecycleAndMoveOwnership(t *testing.T) {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: 5, LogQ: []int{50, 50, 50, 50}, LogP: []int{50}, LogDefaultScale: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoder := ckks.NewEncoder(params, 256)
	tests := []struct {
		name       string
		role       ObservedTransformRole
		literal    MatrixLiteral
		wantCount  int
		wantEvents int
	}{
		{
			name: "stc", role: ObservedSlotsToCoeffs, wantCount: 2, wantEvents: 13,
			literal: MatrixLiteral{Type: HomomorphicDecode, LogSlots: 3, LevelQ: 3, LevelP: 0,
				Levels: []int{1, 1}, Format: SplitRealAndImag},
		},
		{
			name: "cts", role: ObservedCoeffsToSlots, wantCount: 3, wantEvents: 18,
			literal: MatrixLiteral{Type: HomomorphicEncode, LogSlots: 3, LevelQ: 3, LevelP: 0,
				Levels: []int{1, 1, 1}, Format: SplitRealAndImag},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			consumer := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
			before := SnapshotMatrixConstructionCounters()
			matrix, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
				params, test.role, test.literal, encoder, 256, consumer,
			)
			if err != nil {
				t.Fatal(err)
			}
			delta, err := SnapshotMatrixConstructionCounters().Delta(before)
			if err != nil {
				t.Fatal(err)
			}
			if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 || delta.ObservedStreaming() != 1 {
				t.Fatalf("success counter delta=%d/%d/%d/%d, want 0/0/0/1", delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming())
			}
			if len(matrix.Matrices) != test.wantCount || len(consumer.inputs) != test.wantCount || len(consumer.products) != test.wantCount {
				t.Fatalf("matrix/input/product factors=%d/%d/%d, want %d", len(matrix.Matrices), len(consumer.inputs), len(consumer.products), test.wantCount)
			}
			for index := range consumer.inputs {
				if _, ok := consumer.inputs[index].BorrowedNumericFactor(); ok {
					t.Fatalf("factor %d borrowed input remained active", index)
				}
				product := consumer.products[index]
				if !product.TransferCompleted() {
					t.Fatalf("factor %d product still owns its LT", index)
				}
				if product.Role() != 0 || product.Index() != 0 || product.Count() != 0 ||
					product.NumericDigest() != ([sha256.Size]byte{}) || product.NumericBytes() != 0 ||
					product.EncodedDigest() != ([sha256.Size]byte{}) || product.EncodedBytes() != 0 {
					t.Fatalf("factor %d transferred product retained typed or payload evidence", index)
				}
			}
			events := trace.Events()
			factors := trace.Factors()
			if trace.Status() != ObservedStreamingSuccess || trace.FailureStage() != ObservedStreamingFailureNone ||
				trace.CompletedEventCount() != uint32(test.wantEvents) || trace.AttemptedEventLowerBound() != uint32(test.wantEvents) ||
				len(events) != test.wantEvents || len(trace.CleanupEvents()) != 0 || len(factors) != test.wantCount ||
				events[0].Code() != ObservedStreamingTransformStart ||
				events[len(events)-2].Code() != ObservedStreamingTransformEnd ||
				events[len(events)-1].Code() != ObservedStreamingGeneratorReturned {
				t.Fatalf("success lifecycle changed: status=%d stage=%d events=%d cleanup=%d factors=%d",
					trace.Status(), trace.FailureStage(), len(events), len(trace.CleanupEvents()), len(factors))
			}
			for index, factor := range factors {
				if factor.Role() != test.role || factor.Index() != ObservedFactorIndex(index) ||
					factor.Count() != ObservedFactorCount(test.wantCount) || factor.NumericBytes() == 0 ||
					factor.EncodedBytes() == 0 || factor.Ownership() != ObservedLinearTransformationOwnedByMatrix {
					t.Fatalf("factor %d evidence changed: %+v", index, factor)
				}
			}
			if err := trace.Validate(); err != nil {
				t.Fatalf("success trace rejected: %v", err)
			}
			events[0].code = ObservedStreamingGeneratorReturned
			factors[0].numericBytes++
			if err := trace.Validate(); err != nil {
				t.Fatalf("trace accessors alias sealed slices: %v", err)
			}
			test.literal.Levels[0] = 99
			if matrix.Levels[0] != 1 {
				t.Fatal("returned Matrix aliases the caller's literal Levels")
			}
		})
	}
}

func TestObservedStreamingRejectsStructurallyForeignConsumerProduct(t *testing.T) {
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
	valid := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
	consumer := observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
		product, err := valid.ConsumeObservedFactor(input)
		if err != nil {
			return nil, err
		}
		product.state.transformation.N1++
		return product, nil
	})

	matrix, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err == nil {
		t.Fatal("structurally foreign consumer LT unexpectedly succeeded")
	}
	if !reflect.DeepEqual(matrix, Matrix{}) {
		t.Fatal("structurally foreign consumer LT returned an installable Matrix")
	}
	cleanup := trace.CleanupEvents()
	if trace.Status() != ObservedStreamingFailure || trace.FailureStage() != ObservedStreamingFailureProduct ||
		trace.CompletedEventCount() != 2 || trace.AttemptedEventLowerBound() != 3 ||
		len(trace.Events()) != 2 || len(trace.Factors()) != 0 || len(cleanup) != 3 ||
		cleanup[0].Code() != ObservedStreamingCleanupProductDiscarded ||
		cleanup[1].Code() != ObservedStreamingCleanupFactorReferenceCleared ||
		cleanup[2].Code() != ObservedStreamingCleanupGeneratorReferencesCleared {
		t.Fatalf("foreign-product failure grammar changed: stage=%d completed/attempted=%d/%d cleanup=%+v",
			trace.FailureStage(), trace.CompletedEventCount(), trace.AttemptedEventLowerBound(), cleanup)
	}
	if err := trace.Validate(); err != nil {
		t.Fatalf("sealed foreign-product trace rejected: %v", err)
	}
	if len(valid.products) != 1 || valid.products[0].TransferCompleted() ||
		valid.products[0].Role() != 0 || valid.products[0].Count() != 0 ||
		valid.products[0].NumericDigest() != ([sha256.Size]byte{}) || valid.products[0].EncodedDigest() != ([sha256.Size]byte{}) {
		t.Fatal("structurally rejected product reported a completed transfer")
	}
}

func TestObservedFactorProductShallowCopiesShareMoveAndZeroingCell(t *testing.T) {
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
	valid := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
	aliases := make([]ObservedFactorProduct, 0, 2)
	consumer := observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
		product, err := valid.ConsumeObservedFactor(input)
		if err != nil {
			return nil, err
		}
		aliases = append(aliases, *product)
		return product, nil
	})
	_, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err != nil || trace.Validate() != nil || len(aliases) != 2 {
		t.Fatalf("shallow-copy fixture failed: err=%v validate=%v aliases=%d", err, trace.Validate(), len(aliases))
	}
	for index := range aliases {
		alias := &aliases[index]
		if !alias.TransferCompleted() || alias.Role() != 0 || alias.Index() != 0 || alias.Count() != 0 ||
			alias.NumericDigest() != ([sha256.Size]byte{}) || alias.NumericBytes() != 0 ||
			alias.EncodedDigest() != ([sha256.Size]byte{}) || alias.EncodedBytes() != 0 ||
			alias.state.invocation != nil || alias.state.transformation.MetaData != nil || alias.state.transformation.Vec != nil {
			t.Fatalf("shallow product copy %d retained ownership payload after take", index)
		}
	}

	rejectedConsumer := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
	var rejectedAlias ObservedFactorProduct
	consumer = observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
		product, err := rejectedConsumer.ConsumeObservedFactor(input)
		if err != nil {
			return nil, err
		}
		rejectedAlias = *product
		product.state.transformation.N1++
		return product, nil
	})
	matrix, failure, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err == nil || !reflect.DeepEqual(matrix, Matrix{}) || failure.Validate() != nil || len(rejectedConsumer.products) != 1 {
		t.Fatalf("rejected shallow-copy fixture failed: matrix=%+v err=%v validate=%v products=%d",
			matrix, err, failure.Validate(), len(rejectedConsumer.products))
	}
	for name, product := range map[string]*ObservedFactorProduct{
		"original": rejectedConsumer.products[0], "copy": &rejectedAlias,
	} {
		if product.TransferCompleted() || product.Role() != 0 || product.Index() != 0 || product.Count() != 0 ||
			product.NumericDigest() != ([sha256.Size]byte{}) || product.NumericBytes() != 0 ||
			product.EncodedDigest() != ([sha256.Size]byte{}) || product.EncodedBytes() != 0 ||
			product.state.invocation != nil || product.state.transformation.MetaData != nil || product.state.transformation.Vec != nil {
			t.Fatalf("%s rejected product retained ownership payload after discard", name)
		}
	}
}

func TestObservedStreamingRejectsTypedProductMutationsAndReplay(t *testing.T) {
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

	mutations := []struct {
		name   string
		mutate func(*ObservedFactorProduct)
	}{
		{"foreign invocation", func(product *ObservedFactorProduct) {
			copyInvocation := *product.state.invocation
			product.state.invocation = &copyInvocation
		}},
		{"role", func(product *ObservedFactorProduct) { product.state.role = ObservedCoeffsToSlots }},
		{"index", func(product *ObservedFactorProduct) { product.state.index++ }},
		{"count", func(product *ObservedFactorProduct) { product.state.count++ }},
		{"generator precision", func(product *ObservedFactorProduct) { product.state.generatorPrecision = 53 }},
		{"encoder precision", func(product *ObservedFactorProduct) { product.state.encoderPrecision = 53 }},
		{"numeric digest", func(product *ObservedFactorProduct) { product.state.numericDigest = [sha256.Size]byte{} }},
		{"numeric bytes", func(product *ObservedFactorProduct) { product.state.numericBytes = 0 }},
		{"encoded digest", func(product *ObservedFactorProduct) { product.state.encodedDigest = [sha256.Size]byte{} }},
		{"encoded bytes", func(product *ObservedFactorProduct) { product.state.encodedBytes = 0 }},
		{"metadata", func(product *ObservedFactorProduct) { product.state.transformation.MetaData = nil }},
		{"vec", func(product *ObservedFactorProduct) { product.state.transformation.Vec = nil }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			valid := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
			consumer := observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
				product, err := valid.ConsumeObservedFactor(input)
				if err != nil {
					return nil, err
				}
				test.mutate(product)
				return product, nil
			})
			matrix, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
				params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
			)
			assertObservedProductFailure(t, matrix, trace, err, 2, 3, 0)
			if len(valid.products) != 1 || valid.products[0].TransferCompleted() ||
				valid.products[0].Role() != 0 || valid.products[0].Count() != 0 ||
				valid.products[0].NumericBytes() != 0 || valid.products[0].EncodedBytes() != 0 {
				t.Fatal("rejected product retained a transferred or typed state")
			}
		})
	}

	t.Run("already consumed replay", func(t *testing.T) {
		valid := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
		var first *ObservedFactorProduct
		consumer := observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
			if input.Index() == 0 {
				product, err := valid.ConsumeObservedFactor(input)
				first = product
				return product, err
			}
			return first, nil
		})
		matrix, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
			params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
		)
		assertObservedProductFailure(t, matrix, trace, err, 7, 8, 1)
		cleanup := trace.CleanupEvents()
		if len(cleanup) != 4 || cleanup[0].Code() != ObservedStreamingCleanupProductDiscarded ||
			cleanup[0].FactorIndex() != 1 || cleanup[1].Code() != ObservedStreamingCleanupFactorReferenceCleared ||
			cleanup[1].FactorIndex() != 1 || cleanup[2].Code() != ObservedStreamingCleanupMatrixArtifactDiscarded ||
			cleanup[2].FactorIndex() != 0 || cleanup[3].Code() != ObservedStreamingCleanupGeneratorReferencesCleared {
			t.Fatalf("stale replay cleanup changed: %+v", cleanup)
		}
		if factors := trace.Factors(); len(factors) != 1 || factors[0].Ownership() != ObservedLinearTransformationDiscarded {
			t.Fatalf("stale replay prior factor ownership changed: %+v", factors)
		}
	})

	t.Run("nil product", func(t *testing.T) {
		consumer := observedFactorConsumerFunc(func(ObservedFactorInput) (*ObservedFactorProduct, error) {
			return nil, nil
		})
		matrix, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
			params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
		)
		assertObservedProductFailure(t, matrix, trace, err, 2, 3, 0)
		cleanup := trace.CleanupEvents()
		if len(cleanup) != 2 || cleanup[0].Code() != ObservedStreamingCleanupFactorReferenceCleared ||
			cleanup[1].Code() != ObservedStreamingCleanupGeneratorReferencesCleared {
			t.Fatalf("nil-product cleanup changed: %+v", cleanup)
		}
	})

	t.Run("product returned with consumer error", func(t *testing.T) {
		valid := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
		sentinel := errors.New("product plus error")
		consumer := observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
			product, err := valid.ConsumeObservedFactor(input)
			if err != nil {
				return nil, err
			}
			return product, sentinel
		})
		matrix, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
			params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
		)
		if err == nil || !strings.Contains(err.Error(), sentinel.Error()) {
			t.Fatalf("got error %v, want %q", err, sentinel)
		}
		if trace.FailureStage() != ObservedStreamingFailureConsumer {
			t.Fatalf("product+error stage=%d, want consumer", trace.FailureStage())
		}
		if !reflect.DeepEqual(matrix, Matrix{}) || len(trace.CleanupEvents()) != 3 || trace.Validate() != nil {
			t.Fatalf("product+error did not seal mandatory cleanup: matrix=%+v cleanup=%+v validate=%v",
				matrix, trace.CleanupEvents(), trace.Validate())
		}
	})
}

func assertObservedProductFailure(t *testing.T, matrix Matrix, trace ObservedStreamingTrace, err error, completed, attempted uint32, priorFactors int) {
	t.Helper()
	if err == nil {
		t.Fatal("mutated or stale product unexpectedly succeeded")
	}
	if !reflect.DeepEqual(matrix, Matrix{}) {
		t.Fatal("mutated or stale product returned an installable Matrix")
	}
	if trace.Status() != ObservedStreamingFailure || trace.FailureStage() != ObservedStreamingFailureProduct ||
		trace.CompletedEventCount() != completed || trace.AttemptedEventLowerBound() != attempted ||
		len(trace.Factors()) != priorFactors {
		t.Fatalf("product failure ledger changed: status=%d stage=%d completed/attempted=%d/%d factors=%d",
			trace.Status(), trace.FailureStage(), trace.CompletedEventCount(), trace.AttemptedEventLowerBound(), len(trace.Factors()))
	}
	if validateErr := trace.Validate(); validateErr != nil {
		t.Fatalf("sealed product failure trace rejected: %v", validateErr)
	}
}

func TestObservedStreamingTraceRejectsResealedMissingMandatoryCleanup(t *testing.T) {
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
	valid := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
	var first *ObservedFactorProduct
	consumer := observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
		if input.Index() == 0 {
			product, err := valid.ConsumeObservedFactor(input)
			first = product
			return product, err
		}
		return first, nil
	})
	_, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err == nil || trace.Validate() != nil {
		t.Fatalf("replay fixture failed: err=%v validate=%v", err, trace.Validate())
	}

	trace.cleanup = append(trace.cleanup[:1], trace.cleanup[2:]...)
	for sequence := range trace.cleanup {
		trace.cleanup[sequence].sequence = uint32(sequence)
	}
	trace.seal()
	if err := trace.Validate(); err == nil {
		t.Fatal("resealed failure trace without mandatory factor-clear cleanup validated")
	}
}

func TestObservedStreamingTraceMutationMatrixAndDefensiveAccessors(t *testing.T) {
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
	valid := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
	_, success, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, valid,
	)
	if err != nil || success.Validate() != nil {
		t.Fatalf("success fixture failed: err=%v validate=%v", err, success.Validate())
	}
	corruptDigest := cloneObservedStreamingTrace(success)
	corruptDigest.digest[0] ^= 1
	if err := corruptDigest.Validate(); err == nil {
		t.Fatal("trace with a corrupted seal validated")
	}

	successMutations := []struct {
		name   string
		mutate func(*ObservedStreamingTrace)
	}{
		{"status", func(trace *ObservedStreamingTrace) { trace.status = ObservedStreamingFailure }},
		{"failure stage", func(trace *ObservedStreamingTrace) { trace.failureStage = ObservedStreamingFailureProduct }},
		{"role", func(trace *ObservedStreamingTrace) { trace.role = ObservedCoeffsToSlots }},
		{"factor count", func(trace *ObservedStreamingTrace) { trace.factorCount++ }},
		{"completed count", func(trace *ObservedStreamingTrace) { trace.completedEventCount-- }},
		{"attempted lower bound", func(trace *ObservedStreamingTrace) { trace.attemptedEventLowerBound-- }},
		{"event code", func(trace *ObservedStreamingTrace) { trace.events[1].code = ObservedStreamingFactorEncoded }},
		{"event role", func(trace *ObservedStreamingTrace) { trace.events[1].role = ObservedCoeffsToSlots }},
		{"event factor index", func(trace *ObservedStreamingTrace) { trace.events[1].factorIndex++ }},
		{"event payload bytes", func(trace *ObservedStreamingTrace) { trace.events[2].payloadBytes++ }},
		{"factor role", func(trace *ObservedStreamingTrace) { trace.factors[0].role = ObservedCoeffsToSlots }},
		{"factor ownership", func(trace *ObservedStreamingTrace) {
			trace.factors[0].ownership = ObservedLinearTransformationDiscarded
		}},
		{"factor digest link", func(trace *ObservedStreamingTrace) { trace.factors[0].numericDigest[0] ^= 1 }},
		{"cleanup appended", func(trace *ObservedStreamingTrace) {
			trace.appendCleanup(ObservedStreamingCleanupGeneratorReferencesCleared, -1)
		}},
	}
	for _, test := range successMutations {
		t.Run("success/"+test.name, func(t *testing.T) {
			mutated := cloneObservedStreamingTrace(success)
			test.mutate(&mutated)
			mutated.digest = digestObservedStreamingTrace(mutated)
			if err := mutated.Validate(); err == nil {
				t.Fatal("resealed success-trace mutation validated")
			}
		})
	}

	var first *ObservedFactorProduct
	replayConsumer := observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
		if input.Index() == 0 {
			product, err := (&observedEncodingTestConsumer{t: t, params: params, encoder: encoder}).ConsumeObservedFactor(input)
			first = product
			return product, err
		}
		return first, nil
	})
	_, failure, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, replayConsumer,
	)
	if err == nil || failure.Validate() != nil {
		t.Fatalf("failure fixture failed: err=%v validate=%v", err, failure.Validate())
	}
	failureMutations := []struct {
		name   string
		mutate func(*ObservedStreamingTrace)
	}{
		{"missing factor clear", func(trace *ObservedStreamingTrace) { trace.cleanup = append(trace.cleanup[:1], trace.cleanup[2:]...) }},
		{"duplicate product cleanup", func(trace *ObservedStreamingTrace) {
			trace.cleanup = append(trace.cleanup[:1], append([]ObservedStreamingCleanupEvent{trace.cleanup[0]}, trace.cleanup[1:]...)...)
		}},
		{"cleanup order", func(trace *ObservedStreamingTrace) {
			trace.cleanup[1], trace.cleanup[2] = trace.cleanup[2], trace.cleanup[1]
		}},
		{"factor clear index", func(trace *ObservedStreamingTrace) { trace.cleanup[1].factorIndex = 0 }},
		{"missing matrix cleanup", func(trace *ObservedStreamingTrace) { trace.cleanup = append(trace.cleanup[:2], trace.cleanup[3:]...) }},
		{"matrix cleanup index", func(trace *ObservedStreamingTrace) { trace.cleanup[2].factorIndex = 1 }},
		{"extra generator cleanup", func(trace *ObservedStreamingTrace) {
			trace.cleanup = append(trace.cleanup, trace.cleanup[len(trace.cleanup)-1])
		}},
		{"attempted lower bound", func(trace *ObservedStreamingTrace) { trace.attemptedEventLowerBound = trace.completedEventCount }},
		{"failure stage", func(trace *ObservedStreamingTrace) { trace.failureStage = ObservedStreamingFailureGenerator }},
		{"prior factor ownership", func(trace *ObservedStreamingTrace) {
			trace.factors[0].ownership = ObservedLinearTransformationOwnedByMatrix
		}},
		{"prior factor digest", func(trace *ObservedStreamingTrace) { trace.factors[0].encodedDigest[0] ^= 1 }},
		{"event prefix", func(trace *ObservedStreamingTrace) { trace.events = trace.events[:len(trace.events)-1] }},
	}
	for _, test := range failureMutations {
		t.Run("failure/"+test.name, func(t *testing.T) {
			mutated := cloneObservedStreamingTrace(failure)
			test.mutate(&mutated)
			for sequence := range mutated.cleanup {
				mutated.cleanup[sequence].sequence = uint32(sequence)
			}
			for sequence := range mutated.events {
				mutated.events[sequence].sequence = uint32(sequence)
			}
			mutated.completedEventCount = uint32(len(mutated.events))
			mutated.digest = digestObservedStreamingTrace(mutated)
			if err := mutated.Validate(); err == nil {
				t.Fatal("resealed failure-trace mutation validated")
			}
		})
	}

	events := success.Events()
	cleanup := failure.CleanupEvents()
	factors := success.Factors()
	events[0].code = ObservedStreamingGeneratorReturned
	cleanup[0].code = ObservedStreamingCleanupGeneratorReferencesCleared
	factors[0].numericBytes++
	if success.Validate() != nil || failure.Validate() != nil {
		t.Fatal("trace accessor mutation reached sealed backing state")
	}
}

func TestObservedStreamingInvalidRoleReturnsSealedZeroWorkValidationTrace(t *testing.T) {
	before := SnapshotMatrixConstructionCounters()
	matrix, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		ckks.Parameters{}, ObservedTransformRole(99), MatrixLiteral{}, nil, 53, nil,
	)
	if err == nil || !reflect.DeepEqual(matrix, Matrix{}) {
		t.Fatalf("invalid role result changed: matrix=%+v err=%v", matrix, err)
	}
	if trace.Status() != ObservedStreamingFailure || trace.FailureStage() != ObservedStreamingFailureValidation ||
		trace.Role() != ObservedTransformRole(99) || trace.FactorCount() != 0 ||
		trace.CompletedEventCount() != 0 || trace.AttemptedEventLowerBound() != 0 || trace.Validate() != nil {
		t.Fatalf("invalid role did not return a sealed zero-work trace: %+v validate=%v", trace, trace.Validate())
	}
	delta, deltaErr := SnapshotMatrixConstructionCounters().Delta(before)
	if deltaErr != nil {
		t.Fatal(deltaErr)
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 || delta.ObservedStreaming() != 1 {
		t.Fatalf("invalid-role counter delta=%d/%d/%d/%d, want 0/0/0/1",
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming())
	}
}

func TestObservedStreamingTraceAcceptsHonestGeneratorReturnFailurePrefix(t *testing.T) {
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
	_, success, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err != nil || success.Validate() != nil {
		t.Fatalf("success fixture failed: err=%v validate=%v", err, success.Validate())
	}

	failure := cloneObservedStreamingTrace(success)
	failure.status = ObservedStreamingFailure
	failure.failureStage = ObservedStreamingFailureGenerator
	failure.events = failure.events[:len(failure.events)-2]
	failure.completedEventCount = uint32(len(failure.events))
	failure.attemptedEventLowerBound = failure.completedEventCount + 1
	failure.cleanup = nil
	for index := range failure.factors {
		failure.factors[index].ownership = ObservedLinearTransformationDiscarded
		failure.appendCleanup(ObservedStreamingCleanupMatrixArtifactDiscarded, ObservedFactorIndex(index))
	}
	failure.appendCleanup(ObservedStreamingCleanupGeneratorReferencesCleared, -1)
	failure.digest = digestObservedStreamingTrace(failure)
	if err := failure.Validate(); err != nil {
		t.Fatalf("honest generator-return failure prefix rejected: %v", err)
	}
}

func TestObservedStreamingTraceClaimsOnlyVendorOwnedReferenceRelease(t *testing.T) {
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
	valid := &observedEncodingTestConsumer{t: t, params: params, encoder: encoder}
	var retainedNumeric ltcommon.Diagonals[*bignum.Complex]
	var retainedLiteral MatrixLiteral
	consumer := observedFactorConsumerFunc(func(input ObservedFactorInput) (*ObservedFactorProduct, error) {
		if input.Index() == 0 {
			retainedNumeric, _ = input.BorrowedNumericFactor()
			retainedLiteral = input.Literal()
		}
		return valid.ConsumeObservedFactor(input)
	})
	matrix, trace, err := NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		params, ObservedSlotsToCoeffs, literal, encoder, 256, consumer,
	)
	if err != nil || trace.Validate() != nil || retainedNumeric == nil {
		t.Fatalf("retention-boundary fixture failed: err=%v validate=%v retained=%t", err, trace.Validate(), retainedNumeric != nil)
	}
	encodedBefore := make([][sha256.Size]byte, len(matrix.Matrices))
	for index, transformation := range matrix.Matrices {
		encodedBefore[index], _ = observedTestEncodedDigest(t, transformation)
	}

	// A Go consumer can keep an alias despite the synchronous capability. The
	// trace therefore proves only that the vendor cleared its own reference;
	// private secureeval non-retention is a separate consumer-side audit gate.
	for _, diagonal := range retainedNumeric {
		diagonal[0][0].Add(diagonal[0][0], new(big.Float).SetPrec(diagonal[0][0].Prec()).SetInt64(1))
		break
	}
	retainedLiteral.Levels[0] = 99
	if matrix.Levels[0] != 1 || trace.Validate() != nil {
		t.Fatal("consumer-side post-callback mutation reached vendor-owned Matrix/trace metadata")
	}
	for index, transformation := range matrix.Matrices {
		digest, _ := observedTestEncodedDigest(t, transformation)
		if digest != encodedBefore[index] {
			t.Fatalf("consumer-side numeric alias mutation changed encoded factor %d", index)
		}
	}
}

func observedTestNumericDigest(t *testing.T, factor ltcommon.Diagonals[*bignum.Complex]) ([sha256.Size]byte, uint64) {
	t.Helper()
	var payload bytes.Buffer
	keys := factor.DiagonalsIndexList()
	slices.Sort(keys)
	for _, key := range keys {
		if err := binary.Write(&payload, binary.LittleEndian, int64(key)); err != nil {
			t.Fatal(err)
		}
		for _, value := range factor[key] {
			payload.Write(value[0].Append(nil, 'x', -1))
			payload.WriteByte(0)
			payload.Write(value[1].Append(nil, 'x', -1))
			payload.WriteByte(0)
		}
	}
	return sha256.Sum256(payload.Bytes()), uint64(payload.Len())
}

func observedTestEncodedDigest(t *testing.T, transformation ltcommon.LinearTransformation) ([sha256.Size]byte, uint64) {
	t.Helper()
	var payload bytes.Buffer
	keys := make([]int, 0, len(transformation.Vec))
	for key := range transformation.Vec {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if err := binary.Write(&payload, binary.LittleEndian, int64(key)); err != nil {
			t.Fatal(err)
		}
		written, err := transformation.Vec[key].WriteTo(&payload)
		if err != nil || written != int64(transformation.Vec[key].BinarySize()) {
			t.Fatalf("encoded factor poly %d wrote %d/%d bytes: %v", key, written, transformation.Vec[key].BinarySize(), err)
		}
	}
	return sha256.Sum256(payload.Bytes()), uint64(payload.Len())
}
