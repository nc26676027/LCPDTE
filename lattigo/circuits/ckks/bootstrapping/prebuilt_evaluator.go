// Modified by the LCPDTE project for local module integration and, where applicable,
// runtime instrumentation. See lattigo/NOTICE for attribution and modification details.

package bootstrapping

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

// PrebuiltDFTMatrixCarrier is a consume-on-call move carrier for one encoded
// CoeffsToSlots/SlotsToCoeffs matrix pair. Value copies share the same private
// ownership cell and therefore cannot consume the pair more than once.
type PrebuiltDFTMatrixCarrier struct {
	ownership *prebuiltDFTMatrixOwnership
}

type prebuiltDFTMatrixOwnership struct {
	pair atomic.Pointer[prebuiltDFTMatrixPair]
}

type prebuiltDFTMatrixPair struct {
	c2s dft.Matrix
	s2c dft.Matrix
}

// NewPrebuiltDFTMatrixCarrier moves c2sDonor and s2cDonor into a shared,
// single-consumer ownership cell. Every reachable donor is cleared before the
// function returns, including on invalid nil or aliased donor input.
func NewPrebuiltDFTMatrixCarrier(c2sDonor, s2cDonor *dft.Matrix) (carrier PrebuiltDFTMatrixCarrier, err error) {
	defer func() {
		clearPrebuiltDFTMatrixDonor(c2sDonor)
		clearPrebuiltDFTMatrixDonor(s2cDonor)
	}()

	if c2sDonor == nil || s2cDonor == nil {
		return PrebuiltDFTMatrixCarrier{}, fmt.Errorf("bootstrapping: prebuilt DFT matrix donor is nil")
	}
	if c2sDonor == s2cDonor {
		return PrebuiltDFTMatrixCarrier{}, fmt.Errorf("bootstrapping: prebuilt C2S and S2C donors alias")
	}

	pair := &prebuiltDFTMatrixPair{c2s: *c2sDonor, s2c: *s2cDonor}
	ownership := new(prebuiltDFTMatrixOwnership)
	ownership.pair.Store(pair)
	return PrebuiltDFTMatrixCarrier{ownership: ownership}, nil
}

func clearPrebuiltDFTMatrixDonor(donor *dft.Matrix) {
	if donor != nil {
		*donor = dft.Matrix{}
	}
}

func (carrier PrebuiltDFTMatrixCarrier) consume() (*prebuiltDFTMatrixPair, error) {
	if carrier.ownership == nil {
		return nil, fmt.Errorf("bootstrapping: prebuilt DFT matrix carrier is zero")
	}
	pair := carrier.ownership.pair.Swap(nil)
	if pair == nil {
		return nil, fmt.Errorf("bootstrapping: prebuilt DFT matrix carrier is already consumed")
	}
	return pair, nil
}

type prebuiltEvaluatorDFTMatrixSource struct {
	c2s dft.Matrix
	s2c dft.Matrix
}

type prebuiltEvaluatorDFTMatrixSourceFactory func(c2s, s2c dft.Matrix) evaluatorDFTMatrixSource

func (source *prebuiltEvaluatorDFTMatrixSource) Matrices(params ckks.Parameters, coeffsToSlots, slotsToCoeffs dft.MatrixLiteral) (c2s, s2c dft.Matrix, err error) {
	defer func() {
		source.c2s = dft.Matrix{}
		source.s2c = dft.Matrix{}
	}()

	if coeffsToSlots.Type != dft.HomomorphicEncode {
		return dft.Matrix{}, dft.Matrix{}, fmt.Errorf("bootstrapping: prepared C2S literal is not HomomorphicEncode")
	}
	if slotsToCoeffs.Type != dft.HomomorphicDecode {
		return dft.Matrix{}, dft.Matrix{}, fmt.Errorf("bootstrapping: prepared S2C literal is not HomomorphicDecode")
	}
	if err = source.c2s.ValidateAgainst(params, coeffsToSlots); err != nil {
		return dft.Matrix{}, dft.Matrix{}, fmt.Errorf("bootstrapping: invalid prebuilt C2S matrix: %w", err)
	}
	if err = source.s2c.ValidateAgainst(params, slotsToCoeffs); err != nil {
		return dft.Matrix{}, dft.Matrix{}, fmt.Errorf("bootstrapping: invalid prebuilt S2C matrix: %w", err)
	}

	c2s, s2c = source.c2s, source.s2c
	return c2s, s2c, nil
}

// NewEvaluatorFromPrebuiltMatrices installs an already encoded DFT matrix pair
// and evaluation-key donor into the stock evaluator assembly. It consumes both
// inputs before validating the prepared value and rejects every path that
// constructs additional DFT data. Payload identity and generator/encoder
// precision remain the responsibility of the owner-bound project readiness
// gate, not this bare vendor carrier.
func NewEvaluatorFromPrebuiltMatrices(prepared PreparedParameters, carrier PrebuiltDFTMatrixCarrier, evkDonor **EvaluationKeys) (eval *Evaluator, err error) {
	before := dft.SnapshotMatrixConstructionCounters()
	defer finishPrebuiltEvaluatorAssembly(&eval, &err, before)
	return assemblePrebuiltEvaluator(prepared, carrier, evkDonor, func(c2s, s2c dft.Matrix) evaluatorDFTMatrixSource {
		return &prebuiltEvaluatorDFTMatrixSource{c2s: c2s, s2c: s2c}
	})
}

func assemblePrebuiltEvaluator(prepared PreparedParameters, carrier PrebuiltDFTMatrixCarrier, evkDonor **EvaluationKeys, sourceFactory prebuiltEvaluatorDFTMatrixSourceFactory) (eval *Evaluator, err error) {
	evaluationKeys, keyErr := consumePrebuiltEvaluationKeysDonor(evkDonor)
	pair, matrixErr := carrier.consume()
	if pair != nil {
		defer func() {
			pair.c2s = dft.Matrix{}
			pair.s2c = dft.Matrix{}
		}()
	}
	if keyErr != nil || matrixErr != nil {
		return nil, errors.Join(keyErr, matrixErr)
	}
	if sourceFactory == nil {
		return nil, fmt.Errorf("bootstrapping: prebuilt DFT matrix source factory is nil")
	}

	source := sourceFactory(pair.c2s, pair.s2c)
	return newEvaluatorFromPreparedWithDFTMatrixSource(prepared, evaluationKeys, source)
}

func consumePrebuiltEvaluationKeysDonor(donor **EvaluationKeys) (*EvaluationKeys, error) {
	if donor == nil {
		return nil, fmt.Errorf("bootstrapping: prebuilt evaluation-key donor is nil")
	}
	evaluationKeys := *donor
	*donor = nil
	if evaluationKeys == nil {
		return nil, fmt.Errorf("bootstrapping: prebuilt evaluation-key donor is empty")
	}
	return evaluationKeys, nil
}

// newEvaluatorFromPrebuiltMatricesWithSourceFactory is the private audited seam
// used to verify that any source which touches a public DFT constructor fails
// closed under the same ownership and panic contract as the public entry.
func newEvaluatorFromPrebuiltMatricesWithSourceFactory(prepared PreparedParameters, carrier PrebuiltDFTMatrixCarrier, evkDonor **EvaluationKeys, sourceFactory prebuiltEvaluatorDFTMatrixSourceFactory) (eval *Evaluator, err error) {
	before := dft.SnapshotMatrixConstructionCounters()
	defer finishPrebuiltEvaluatorAssembly(&eval, &err, before)
	return assemblePrebuiltEvaluator(prepared, carrier, evkDonor, sourceFactory)
}

func finishPrebuiltEvaluatorAssembly(eval **Evaluator, errp *error, before dft.MatrixConstructionCounters) {
	if recovered := recover(); recovered != nil {
		*eval = nil
		*errp = errors.Join(*errp, fmt.Errorf("bootstrapping: prebuilt evaluator assembly panicked: %v", recovered))
	}
	enforceZeroPrebuiltDFTConstruction(eval, errp, before)
	if *errp != nil {
		*eval = nil
	}
}

func enforceZeroPrebuiltDFTConstruction(eval **Evaluator, errp *error, before dft.MatrixConstructionCounters) {
	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err == nil {
		got := [4]uint64{delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming()}
		if got != [4]uint64{} {
			err = fmt.Errorf("bootstrapping: prebuilt evaluator DFT construction delta is %v, want [0 0 0 0]", got)
		}
	}
	if err != nil {
		*eval = nil
		*errp = errors.Join(*errp, err)
	}
}
