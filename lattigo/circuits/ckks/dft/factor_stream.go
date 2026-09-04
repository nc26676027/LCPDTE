// Modified by the LCPDTE project for bounded-residency DFT evaluation.

package dft

import (
	"fmt"

	ltcommon "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

// FactorSource supplies one encoded DFT factor at a time in the order fixed by
// Literal. Implementations may keep the factors outside the Go heap and load
// only the requested factor for each call.
type FactorSource interface {
	Literal() MatrixLiteral
	FactorCount() int
	ReadFactor(index int) (ltcommon.LinearTransformation, error)
}

// ValidatedFactor is an encoded matrix factor whose parameter, literal,
// position and structural identity were checked by NewValidatedFactor.
// Its transformation is intentionally private so evaluation can trust the
// validation result without exposing a mutable alias through this value.
type ValidatedFactor struct {
	params         ckks.Parameters
	literal        MatrixLiteral
	index          int
	transformation ltcommon.LinearTransformation
	valid          bool
}

// ValidatedFactorSource is the prepared-online form of FactorSource. A source
// may implement this interface after loading and validating its factors during
// setup or warmup. EvaluateSequentialFromFactors prefers this path and does
// not repeat full factor validation.
type ValidatedFactorSource interface {
	FactorSource
	ReadValidatedFactor(index int) (ValidatedFactor, error)
}

// NewValidatedFactor validates and seals one encoded factor for reuse by a
// ValidatedFactorSource.
func NewValidatedFactor(
	params ckks.Parameters,
	literal MatrixLiteral,
	index int,
	factor ltcommon.LinearTransformation,
) (ValidatedFactor, error) {
	if err := ValidateMatrixFactor(params, literal, index, factor); err != nil {
		return ValidatedFactor{}, err
	}
	return ValidatedFactor{
		params: params, literal: cloneDFTMatrixLiteral(literal), index: index,
		transformation: factor, valid: true,
	}, nil
}

func (factor ValidatedFactor) forEvaluation(
	params ckks.Parameters,
	literal MatrixLiteral,
	index int,
) (ltcommon.LinearTransformation, error) {
	if !factor.valid || factor.index != index || !factor.params.Equal(&params) ||
		!equalDFTMatrixLiteral(factor.literal, literal) {
		return ltcommon.LinearTransformation{}, fmt.Errorf("dft: validated factor %d identity changed", index)
	}
	return factor.transformation, nil
}

// ForEachEncodedMatrixFactor generates, encodes, validates and synchronously
// emits one DFT factor at a time. Neither numeric nor encoded factors are
// retained by this function after emit returns.
func ForEachEncodedMatrixFactor(
	params ckks.Parameters,
	literal MatrixLiteral,
	encoder *ckks.Encoder,
	generatorPrecision uint,
	emit func(index, count int, factor ltcommon.LinearTransformation) error,
) error {
	noteRawNumericConstruction()
	if emit == nil {
		return fmt.Errorf("dft: encoded factor callback is nil")
	}
	if err := validateMatrixGeneratorEncoder(params, encoder, generatorPrecision); err != nil {
		return err
	}
	if err := validateExpectedDFTMatrixLiteral(params, literal); err != nil {
		return err
	}

	logCols := literal.LogSlots
	if literal.Format == RepackImagAsReal && logCols < params.LogMaxDimensions().Cols {
		logCols++
	}
	scales, err := expectedDFTMatrixScales(params, literal)
	if err != nil {
		return err
	}
	count := literal.Depth(false)
	index := 0
	err = literal.forEachMatrixFactorWithFreshRoots(
		params.LogN(), generatorPrecision,
		func(numeric ltcommon.Diagonals[*bignum.Complex]) error {
			if index >= count || index >= len(scales) {
				return fmt.Errorf("dft: generated too many matrix factors")
			}
			factor := ltcommon.NewTransformation(params, ltcommon.Parameters{
				DiagonalsIndexList:        numeric.DiagonalsIndexList(),
				LevelQ:                    literal.LevelQ,
				LevelP:                    literal.LevelP,
				Scale:                     scales[index],
				LogDimensions:             ring.Dimensions{Rows: 0, Cols: logCols},
				LogBabyStepGiantStepRatio: literal.LogBSGSRatio,
			})
			if err := ltcommon.Encode(encoder, numeric, factor); err != nil {
				return fmt.Errorf("dft: encode factor %d: %w", index, err)
			}
			numeric = nil
			if err := ValidateMatrixFactor(params, literal, index, factor); err != nil {
				return err
			}
			if err := emit(index, count, factor); err != nil {
				return err
			}
			factor = ltcommon.LinearTransformation{}
			index++
			return nil
		},
	)
	if err != nil {
		return err
	}
	if index != count {
		return fmt.Errorf("dft: generated %d matrix factors, want %d", index, count)
	}
	return nil
}

// ValidateMatrixFactor checks one encoded factor against its exact literal,
// position, topology, metadata and ring shape without constructing a matrix.
func ValidateMatrixFactor(params ckks.Parameters, literal MatrixLiteral, index int, factor ltcommon.LinearTransformation) error {
	if err := validateExpectedDFTMatrixLiteral(params, literal); err != nil {
		return err
	}
	plan, err := newDFTMatrixValidationPlan(params, literal)
	if err != nil {
		return err
	}
	return validateDFTMatrixTransformation(params, literal, index, factor, plan)
}

// EvaluateSequentialFromFactors evaluates a DFT from a reusable FactorSource.
// Each encoded factor becomes unreachable before the next one is requested.
func (eval *Evaluator) EvaluateSequentialFromFactors(
	ctIn *rlwe.Ciphertext,
	source FactorSource,
	opOut *rlwe.Ciphertext,
) error {
	if eval == nil || eval.LTEvaluator == nil || ctIn == nil || opOut == nil || source == nil {
		return fmt.Errorf("dft: evaluator, input, output or factor source is nil")
	}
	literal := source.Literal()
	if err := validateExpectedDFTMatrixLiteral(eval.parameters, literal); err != nil {
		return err
	}
	count := literal.Depth(false)
	if source.FactorCount() != count {
		return fmt.Errorf("dft: factor source count is %d, want %d", source.FactorCount(), count)
	}
	inputDimensions := ctIn.LogDimensions
	current := ctIn
	validatedSource, useValidated := source.(ValidatedFactorSource)
	for index := 0; index < count; index++ {
		var factor ltcommon.LinearTransformation
		var err error
		if useValidated {
			validated, readErr := validatedSource.ReadValidatedFactor(index)
			if readErr != nil {
				return fmt.Errorf("dft: read validated factor %d: %w", index, readErr)
			}
			if factor, err = validated.forEvaluation(eval.parameters, literal, index); err != nil {
				return err
			}
		} else {
			factor, err = source.ReadFactor(index)
			if err != nil {
				return fmt.Errorf("dft: read factor %d: %w", index, err)
			}
			if err = ValidateMatrixFactor(eval.parameters, literal, index, factor); err != nil {
				return err
			}
		}
		if err = eval.LTEvaluator.Evaluate(current, factor, opOut); err != nil {
			return fmt.Errorf("dft: evaluate factor %d: %w", index, err)
		}
		factor = ltcommon.LinearTransformation{}
		if err = eval.Rescale(opOut, opOut); err != nil {
			return fmt.Errorf("dft: rescale factor %d: %w", index, err)
		}
		current = opOut
	}
	opOut.LogDimensions = inputDimensions
	return nil
}

// CoeffsToSlotsFromFactorsNew applies the regular CoeffsToSlots postprocessing
// around a factor-at-a-time DFT. Dense SplitRealAndImag returns both outputs.
func (eval *Evaluator) CoeffsToSlotsFromFactorsNew(
	ctIn *rlwe.Ciphertext,
	source FactorSource,
) (ctReal, ctImag *rlwe.Ciphertext, err error) {
	if eval == nil || ctIn == nil || source == nil {
		return nil, nil, fmt.Errorf("dft: evaluator, input or factor source is nil")
	}
	literal := source.Literal()
	if literal.Type != HomomorphicEncode {
		return nil, nil, fmt.Errorf("dft: CoeffsToSlots factor source is not HomomorphicEncode")
	}
	ctReal = ckks.NewCiphertext(eval.parameters, 1, literal.LevelQ)
	if literal.LogSlots == eval.parameters.LogMaxSlots() {
		ctImag = ckks.NewCiphertext(eval.parameters, 1, literal.LevelQ)
	}

	if literal.Format != RepackImagAsReal && literal.Format != SplitRealAndImag {
		err = eval.EvaluateSequentialFromFactors(ctIn, source, ctReal)
		return
	}

	zV := ctIn.CopyNew()
	if err = eval.EvaluateSequentialFromFactors(ctIn, source, zV); err != nil {
		return nil, nil, fmt.Errorf("dft: CoeffsToSlots: %w", err)
	}
	if err = eval.Conjugate(zV, ctReal); err != nil {
		return nil, nil, fmt.Errorf("dft: CoeffsToSlots conjugate: %w", err)
	}
	var imaginary *rlwe.Ciphertext
	if ctImag != nil {
		imaginary = ctImag
	} else {
		imaginary, err = rlwe.NewCiphertextAtLevelFromPoly(ctReal.Level(), eval.GetBuffCt().Value[:2])
		if err != nil {
			return nil, nil, fmt.Errorf("dft: CoeffsToSlots scratch output: %w", err)
		}
		imaginary.IsNTT = true
	}
	if err = eval.Sub(zV, ctReal, imaginary); err != nil {
		return nil, nil, fmt.Errorf("dft: CoeffsToSlots imaginary subtraction: %w", err)
	}
	if err = eval.Mul(imaginary, -1i, imaginary); err != nil {
		return nil, nil, fmt.Errorf("dft: CoeffsToSlots imaginary scaling: %w", err)
	}
	if err = eval.Add(ctReal, zV, ctReal); err != nil {
		return nil, nil, fmt.Errorf("dft: CoeffsToSlots real addition: %w", err)
	}
	if literal.Format == RepackImagAsReal && literal.LogSlots < eval.parameters.LogMaxSlots() {
		if err = eval.Rotate(imaginary, 1<<ctIn.LogDimensions.Cols, imaginary); err != nil {
			return nil, nil, fmt.Errorf("dft: CoeffsToSlots repack rotation: %w", err)
		}
		if err = eval.Add(ctReal, imaginary, ctReal); err != nil {
			return nil, nil, fmt.Errorf("dft: CoeffsToSlots repack addition: %w", err)
		}
	}
	return ctReal, ctImag, nil
}

// CoeffsToSlotsRealFromFactorsNew evaluates the dense SplitRealAndImag DFT
// and materializes only its real output. It is the prepared path for callers,
// such as Gao's C2R, that do not consume the imaginary ciphertext.
func (eval *Evaluator) CoeffsToSlotsRealFromFactorsNew(
	ctIn *rlwe.Ciphertext,
	source FactorSource,
) (*rlwe.Ciphertext, error) {
	return eval.coeffsToSlotsRealFromFactorsNew(ctIn, source, false)
}

// CoeffsToSlotsRealFromFactorsConsumeNew is the ownership-transferring form
// of CoeffsToSlotsRealFromFactorsNew. It uses ctIn as the DFT output buffer;
// callers must not use ctIn after this call. The returned real ciphertext is
// newly allocated and remains owned by the caller.
func (eval *Evaluator) CoeffsToSlotsRealFromFactorsConsumeNew(
	ctIn *rlwe.Ciphertext,
	source FactorSource,
) (*rlwe.Ciphertext, error) {
	return eval.coeffsToSlotsRealFromFactorsNew(ctIn, source, true)
}

func (eval *Evaluator) coeffsToSlotsRealFromFactorsNew(
	ctIn *rlwe.Ciphertext,
	source FactorSource,
	consumeInput bool,
) (*rlwe.Ciphertext, error) {
	if eval == nil || ctIn == nil || source == nil {
		return nil, fmt.Errorf("dft: evaluator, input or factor source is nil")
	}
	literal := source.Literal()
	if literal.Type != HomomorphicEncode || literal.Format != SplitRealAndImag ||
		literal.LogSlots != eval.parameters.LogMaxSlots() {
		return nil, fmt.Errorf("dft: real-only CoeffsToSlots requires dense SplitRealAndImag HomomorphicEncode factors")
	}
	zV := ctIn
	if !consumeInput {
		zV = ctIn.CopyNew()
	}
	if err := eval.EvaluateSequentialFromFactors(ctIn, source, zV); err != nil {
		return nil, fmt.Errorf("dft: real-only CoeffsToSlots: %w", err)
	}
	ctReal := ckks.NewCiphertext(eval.parameters, 1, literal.LevelQ)
	if err := eval.Conjugate(zV, ctReal); err != nil {
		return nil, fmt.Errorf("dft: real-only CoeffsToSlots conjugate: %w", err)
	}
	if err := eval.Add(ctReal, zV, ctReal); err != nil {
		return nil, fmt.Errorf("dft: real-only CoeffsToSlots real addition: %w", err)
	}
	return ctReal, nil
}

// SlotsToCoeffsFromFactorsNew applies the regular SlotsToCoeffs preprocessing
// around a factor-at-a-time DFT.
func (eval *Evaluator) SlotsToCoeffsFromFactorsNew(
	ctReal, ctImag *rlwe.Ciphertext,
	source FactorSource,
) (*rlwe.Ciphertext, error) {
	if eval == nil || ctReal == nil || source == nil {
		return nil, fmt.Errorf("dft: evaluator, real input or factor source is nil")
	}
	literal := source.Literal()
	if literal.Type != HomomorphicDecode {
		return nil, fmt.Errorf("dft: SlotsToCoeffs factor source is not HomomorphicDecode")
	}
	if ctReal.Level() < literal.LevelQ || (ctImag != nil && ctImag.Level() < literal.LevelQ) {
		return nil, fmt.Errorf("dft: SlotsToCoeffs input level is below the matrix level")
	}
	opOut := ckks.NewCiphertext(eval.parameters, 1, literal.LevelQ)
	if ctImag != nil {
		if err := eval.Mul(ctImag, 1i, opOut); err != nil {
			return nil, fmt.Errorf("dft: SlotsToCoeffs imaginary scaling: %w", err)
		}
		if err := eval.Add(opOut, ctReal, opOut); err != nil {
			return nil, fmt.Errorf("dft: SlotsToCoeffs input addition: %w", err)
		}
		if err := eval.EvaluateSequentialFromFactors(opOut, source, opOut); err != nil {
			return nil, fmt.Errorf("dft: SlotsToCoeffs: %w", err)
		}
	} else if err := eval.EvaluateSequentialFromFactors(ctReal, source, opOut); err != nil {
		return nil, fmt.Errorf("dft: SlotsToCoeffs: %w", err)
	}
	return opOut, nil
}
