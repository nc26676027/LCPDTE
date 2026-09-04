package bootstrapping

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

func TestNewPrebuiltDFTMatrixCarrierMovesDonorsAndSharesSingleConsumption(t *testing.T) {
	fixture := newPrebuiltEvaluatorTestFixture(t)
	if got := fixture.prepared.EffectiveParameters().BootstrappingParameters.EncodingPrecision(); got != 53 {
		t.Fatalf("structural-boundary fixture precision=%d, want the non-provenance default 53", got)
	}
	wantC2SFactors := len(fixture.c2s.Matrices)
	wantS2CFactors := len(fixture.s2c.Matrices)

	carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.c2s, &fixture.s2c)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixture.c2s, dft.Matrix{}) || !reflect.DeepEqual(fixture.s2c, dft.Matrix{}) {
		t.Fatal("carrier construction retained a donor matrix value")
	}
	carrierCopy := carrier

	movedKeys := fixture.evk
	keyDonor := fixture.evk
	fixture.evk = nil
	before := dft.SnapshotMatrixConstructionCounters()
	evaluator, err := NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrierCopy, &keyDonor)
	if err != nil {
		t.Fatal(err)
	}
	assertPrebuiltCounterDelta(t, before, [4]uint64{})
	if keyDonor != nil {
		t.Fatal("successful assembly retained the evaluation-key donor")
	}
	if evaluator == nil || evaluator.EvaluationKeys != movedKeys {
		t.Fatal("successful assembly did not uniquely install the moved evaluation keys")
	}
	if len(evaluator.C2SDFTMatrix.Matrices) != wantC2SFactors || len(evaluator.S2CDFTMatrix.Matrices) != wantS2CFactors {
		t.Fatalf("installed factor counts are C2S=%d S2C=%d, want %d/%d", len(evaluator.C2SDFTMatrix.Matrices), len(evaluator.S2CDFTMatrix.Matrices), wantC2SFactors, wantS2CFactors)
	}

	secondKeyDonor := &EvaluationKeys{}
	before = dft.SnapshotMatrixConstructionCounters()
	second, err := NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrier, &secondKeyDonor)
	if err == nil || second != nil {
		t.Fatal("a shallow carrier copy consumed the matrix pair twice")
	}
	if secondKeyDonor != nil {
		t.Fatal("already-consumed carrier path retained its evaluation-key donor")
	}
	assertPrebuiltCounterDelta(t, before, [4]uint64{})
}

func TestNewPrebuiltDFTMatrixCarrierClearsReachableDonorsOnError(t *testing.T) {
	t.Run("nil C2S donor", func(t *testing.T) {
		s2c := dft.Matrix{MatrixLiteral: dft.MatrixLiteral{LogSlots: 1}}
		if _, err := NewPrebuiltDFTMatrixCarrier(nil, &s2c); err == nil {
			t.Fatal("nil C2S donor unexpectedly accepted")
		}
		if !reflect.DeepEqual(s2c, dft.Matrix{}) {
			t.Fatal("nil-donor error retained the reachable S2C donor")
		}
	})

	t.Run("nil S2C donor", func(t *testing.T) {
		c2s := dft.Matrix{MatrixLiteral: dft.MatrixLiteral{LogSlots: 1}}
		if _, err := NewPrebuiltDFTMatrixCarrier(&c2s, nil); err == nil {
			t.Fatal("nil S2C donor unexpectedly accepted")
		}
		if !reflect.DeepEqual(c2s, dft.Matrix{}) {
			t.Fatal("nil-donor error retained the reachable C2S donor")
		}
	})

	t.Run("aliased donors", func(t *testing.T) {
		donor := dft.Matrix{MatrixLiteral: dft.MatrixLiteral{LogSlots: 1}}
		if _, err := NewPrebuiltDFTMatrixCarrier(&donor, &donor); err == nil {
			t.Fatal("aliased donors unexpectedly accepted")
		}
		if !reflect.DeepEqual(donor, dft.Matrix{}) {
			t.Fatal("aliased-donor error retained the donor")
		}
	})
}

func TestNewEvaluatorFromPrebuiltMatricesConsumesInputsOnEveryFailure(t *testing.T) {
	t.Run("zero carrier", func(t *testing.T) {
		fixture := newPrebuiltEvaluatorTestFixture(t)
		keyDonor := fixture.evk
		before := dft.SnapshotMatrixConstructionCounters()
		evaluator, err := NewEvaluatorFromPrebuiltMatrices(fixture.prepared, PrebuiltDFTMatrixCarrier{}, &keyDonor)
		if err == nil || evaluator != nil {
			t.Fatal("zero carrier unexpectedly installed an evaluator")
		}
		if keyDonor != nil {
			t.Fatal("zero-carrier error retained its key donor")
		}
		assertPrebuiltCounterDelta(t, before, [4]uint64{})
	})

	t.Run("nil key donor", func(t *testing.T) {
		fixture := newPrebuiltEvaluatorTestFixture(t)
		carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.c2s, &fixture.s2c)
		if err != nil {
			t.Fatal(err)
		}
		carrierCopy := carrier
		before := dft.SnapshotMatrixConstructionCounters()
		evaluator, err := NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrier, nil)
		if err == nil || evaluator != nil {
			t.Fatal("nil key donor unexpectedly installed an evaluator")
		}
		assertPrebuiltCounterDelta(t, before, [4]uint64{})
		retryKey := &EvaluationKeys{}
		if evaluator, err = NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrierCopy, &retryKey); err == nil || evaluator != nil || retryKey != nil {
			t.Fatal("nil-key failure did not leave matrix carrier terminal and key donor consumed")
		}
	})

	t.Run("empty key donor", func(t *testing.T) {
		fixture := newPrebuiltEvaluatorTestFixture(t)
		carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.c2s, &fixture.s2c)
		if err != nil {
			t.Fatal(err)
		}
		carrierCopy := carrier
		var keyDonor *EvaluationKeys
		before := dft.SnapshotMatrixConstructionCounters()
		evaluator, err := NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrier, &keyDonor)
		if err == nil || evaluator != nil || keyDonor != nil {
			t.Fatal("empty key donor unexpectedly installed an evaluator or became non-empty")
		}
		assertPrebuiltCounterDelta(t, before, [4]uint64{})
		retryKey := &EvaluationKeys{}
		if evaluator, err = NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrierCopy, &retryKey); err == nil || evaluator != nil || retryKey != nil {
			t.Fatal("empty-key failure did not leave matrix carrier terminal and retry donor consumed")
		}
	})

	t.Run("invalid prepared value", func(t *testing.T) {
		fixture := newPrebuiltEvaluatorTestFixture(t)
		carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.c2s, &fixture.s2c)
		if err != nil {
			t.Fatal(err)
		}
		carrierCopy := carrier
		fixture.prepared.digest[0] ^= 1
		assertPrebuiltAssemblyFailure(t, fixture.prepared, carrier, fixture.evk)
		retryKey := &EvaluationKeys{}
		if evaluator, retryErr := NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrierCopy, &retryKey); retryErr == nil || evaluator != nil || retryKey != nil {
			t.Fatal("invalid-prepared failure did not leave matrix carrier terminal and key donor consumed")
		}
	})

	t.Run("swapped roles", func(t *testing.T) {
		fixture := newPrebuiltEvaluatorTestFixture(t)
		carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.s2c, &fixture.c2s)
		if err != nil {
			t.Fatal(err)
		}
		assertPrebuiltAssemblyFailure(t, fixture.prepared, carrier, fixture.evk)
	})

	t.Run("structural mutation", func(t *testing.T) {
		fixture := newPrebuiltEvaluatorTestFixture(t)
		fixture.c2s.Matrices = append(fixture.c2s.Matrices[:0:0], fixture.c2s.Matrices...)
		fixture.c2s.Matrices[0].LevelQ++
		carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.c2s, &fixture.s2c)
		if err != nil {
			t.Fatal(err)
		}
		assertPrebuiltAssemblyFailure(t, fixture.prepared, carrier, fixture.evk)
	})

	t.Run("missing key", func(t *testing.T) {
		fixture := newPrebuiltEvaluatorTestFixture(t)
		carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.c2s, &fixture.s2c)
		if err != nil {
			t.Fatal(err)
		}
		assertPrebuiltAssemblyFailure(t, fixture.prepared, carrier, &EvaluationKeys{})
	})
}

type hostilePrebuiltDFTMatrixSource struct {
	c2s     dft.Matrix
	s2c     dft.Matrix
	trigger func(params ckks.Parameters, literal dft.MatrixLiteral)
	panic   bool
}

func (source *hostilePrebuiltDFTMatrixSource) Matrices(params ckks.Parameters, coeffsToSlots, _ dft.MatrixLiteral) (dft.Matrix, dft.Matrix, error) {
	if source.panic {
		panic("hostile prebuilt matrix source")
	}
	source.trigger(params, coeffsToSlots)
	return source.c2s, source.s2c, nil
}

func TestPrebuiltEvaluatorFailsClosedForEveryDFTConstructionCounter(t *testing.T) {
	tests := []struct {
		name    string
		want    [4]uint64
		trigger func(params ckks.Parameters, literal dft.MatrixLiteral)
	}{
		{
			name: "default whole",
			want: [4]uint64{1, 0, 0, 0},
			trigger: func(params ckks.Parameters, literal dft.MatrixLiteral) {
				_, _ = dft.NewMatrixFromLiteral(params, literal, ckks.NewEncoder(params))
			},
		},
		{
			name: "explicit whole",
			want: [4]uint64{0, 1, 0, 0},
			trigger: func(params ckks.Parameters, literal dft.MatrixLiteral) {
				_, _ = dft.NewMatrixFromLiteralWithGeneratorPrecision(params, literal, ckks.NewEncoder(params), params.EncodingPrecision())
			},
		},
		{
			name: "raw numeric",
			want: [4]uint64{0, 0, 1, 0},
			trigger: func(params ckks.Parameters, literal dft.MatrixLiteral) {
				_ = literal.GenMatrices(params.LogN(), params.EncodingPrecision())
			},
		},
		{
			name: "observed streaming",
			want: [4]uint64{0, 0, 0, 1},
			trigger: func(params ckks.Parameters, literal dft.MatrixLiteral) {
				_, _, _ = dft.NewMatrixFromLiteralWithGeneratorPrecisionObserved(params, dft.ObservedTransformRole(255), literal, nil, 0, nil)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPrebuiltEvaluatorTestFixture(t)
			carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.c2s, &fixture.s2c)
			if err != nil {
				t.Fatal(err)
			}
			carrierCopy := carrier
			keyDonor := fixture.evk
			before := dft.SnapshotMatrixConstructionCounters()
			evaluator, err := newEvaluatorFromPrebuiltMatricesWithSourceFactory(fixture.prepared, carrier, &keyDonor, func(c2s, s2c dft.Matrix) evaluatorDFTMatrixSource {
				return &hostilePrebuiltDFTMatrixSource{c2s: c2s, s2c: s2c, trigger: test.trigger}
			})
			if err == nil || evaluator != nil {
				t.Fatal("counter-hostile matrix source returned an evaluator")
			}
			if keyDonor != nil {
				t.Fatal("counter-hostile matrix source retained its key donor")
			}
			assertPrebuiltCounterDelta(t, before, test.want)
			retryKey := &EvaluationKeys{}
			if evaluator, err = NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrierCopy, &retryKey); err == nil || evaluator != nil || retryKey != nil {
				t.Fatal("counter-hostile path did not leave matrix carrier terminal and key donor consumed")
			}
		})
	}
}

func TestPrebuiltEvaluatorRecoversPanicsAfterConsumingInputs(t *testing.T) {
	tests := []struct {
		name    string
		factory prebuiltEvaluatorDFTMatrixSourceFactory
	}{
		{
			name: "source factory",
			factory: func(_, _ dft.Matrix) evaluatorDFTMatrixSource {
				panic("hostile prebuilt source factory")
			},
		},
		{
			name: "source Matrices",
			factory: func(c2s, s2c dft.Matrix) evaluatorDFTMatrixSource {
				return &hostilePrebuiltDFTMatrixSource{c2s: c2s, s2c: s2c, panic: true}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPrebuiltEvaluatorTestFixture(t)
			carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.c2s, &fixture.s2c)
			if err != nil {
				t.Fatal(err)
			}
			carrierCopy := carrier
			keyDonor := fixture.evk
			before := dft.SnapshotMatrixConstructionCounters()
			evaluator, err := newEvaluatorFromPrebuiltMatricesWithSourceFactory(fixture.prepared, carrier, &keyDonor, test.factory)
			if err == nil || evaluator != nil || !strings.Contains(err.Error(), "panicked") {
				t.Fatalf("panic path result=(%v, %v), want nil evaluator and recovered error", evaluator, err)
			}
			if keyDonor != nil {
				t.Fatal("panic path retained its key donor")
			}
			assertPrebuiltCounterDelta(t, before, [4]uint64{})
			retryKey := &EvaluationKeys{}
			if evaluator, err = NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrierCopy, &retryKey); err == nil || evaluator != nil || retryKey != nil {
				t.Fatal("panic path did not leave matrix carrier terminal and key donor consumed")
			}
		})
	}
}

func TestPrebuiltEvaluatorRejectsNilPrivateMatrixSourceAfterConsumingInputs(t *testing.T) {
	fixture := newPrebuiltEvaluatorTestFixture(t)
	carrier, err := NewPrebuiltDFTMatrixCarrier(&fixture.c2s, &fixture.s2c)
	if err != nil {
		t.Fatal(err)
	}
	carrierCopy := carrier
	keyDonor := fixture.evk
	before := dft.SnapshotMatrixConstructionCounters()
	evaluator, err := newEvaluatorFromPrebuiltMatricesWithSourceFactory(fixture.prepared, carrier, &keyDonor, func(_, _ dft.Matrix) evaluatorDFTMatrixSource {
		return nil
	})
	if err == nil || evaluator != nil {
		t.Fatal("nil private matrix source unexpectedly installed an evaluator")
	}
	if keyDonor != nil {
		t.Fatal("nil private matrix source retained its key donor")
	}
	assertPrebuiltCounterDelta(t, before, [4]uint64{})
	retryKey := &EvaluationKeys{}
	if evaluator, err = NewEvaluatorFromPrebuiltMatrices(fixture.prepared, carrierCopy, &retryKey); err == nil || evaluator != nil || retryKey != nil {
		t.Fatal("nil-source path did not leave matrix carrier terminal and retry donor consumed")
	}
}

func TestStockEvaluatorDFTConstructionContractDoesNotDrift(t *testing.T) {
	fixture := newPrebuiltEvaluatorTestFixture(t)
	before := dft.SnapshotMatrixConstructionCounters()
	evaluator, err := NewEvaluator(fixture.input, fixture.evk)
	if err != nil {
		t.Fatal(err)
	}
	if evaluator == nil {
		t.Fatal("stock evaluator is nil")
	}
	assertPrebuiltCounterDelta(t, before, [4]uint64{2, 0, 0, 0})
}

type prebuiltEvaluatorTestFixture struct {
	input    Parameters
	prepared PreparedParameters
	c2s      dft.Matrix
	s2c      dft.Matrix
	evk      *EvaluationKeys
}

func newPrebuiltEvaluatorTestFixture(t *testing.T) prebuiltEvaluatorTestFixture {
	t.Helper()
	input := prepareParametersTestInput(t)
	prepared, err := PrepareParameters(input)
	if err != nil {
		t.Fatal(err)
	}
	effective := prepared.EffectiveParameters()
	params := effective.BootstrappingParameters
	// This intentionally uses the stock 53-bit constructor. Successful vendor
	// installation proves only structural compatibility; it is not 256-bit
	// generator/encoder provenance. The project Ready gate must reject this
	// fixture because it has no observed trace or owner-bound payload anchors.
	encoder := ckks.NewEncoder(params)
	c2s, err := dft.NewMatrixFromLiteral(params, effective.CoeffsToSlotsParameters, encoder)
	if err != nil {
		t.Fatal(err)
	}
	s2c, err := dft.NewMatrixFromLiteral(params, effective.SlotsToCoeffsParameters, encoder)
	if err != nil {
		t.Fatal(err)
	}
	secretKey := rlwe.NewKeyGenerator(input.ResidualParameters).GenSecretKeyNew()
	evaluationKeys, _, err := input.GenEvaluationKeys(secretKey)
	if err != nil {
		t.Fatal(err)
	}
	return prebuiltEvaluatorTestFixture{input: input, prepared: prepared, c2s: c2s, s2c: s2c, evk: evaluationKeys}
}

func assertPrebuiltAssemblyFailure(t *testing.T, prepared PreparedParameters, carrier PrebuiltDFTMatrixCarrier, evaluationKeys *EvaluationKeys) {
	t.Helper()
	keyDonor := evaluationKeys
	before := dft.SnapshotMatrixConstructionCounters()
	evaluator, err := NewEvaluatorFromPrebuiltMatrices(prepared, carrier, &keyDonor)
	if err == nil || evaluator != nil {
		t.Fatal("invalid prebuilt assembly unexpectedly returned an evaluator")
	}
	if keyDonor != nil {
		t.Fatal("failed prebuilt assembly retained its key donor")
	}
	assertPrebuiltCounterDelta(t, before, [4]uint64{})
}

func assertPrebuiltCounterDelta(t *testing.T, before dft.MatrixConstructionCounters, want [4]uint64) {
	t.Helper()
	delta, err := dft.SnapshotMatrixConstructionCounters().Delta(before)
	if err != nil {
		t.Fatal(err)
	}
	got := [4]uint64{delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming()}
	if got != want {
		t.Fatalf("DFT construction delta=%v, want %v", got, want)
	}
}
