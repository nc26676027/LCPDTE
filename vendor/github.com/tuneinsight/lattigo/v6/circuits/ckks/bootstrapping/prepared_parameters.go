package bootstrapping

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const preparedParametersSealVersion uint64 = 1

// PreparedParameters is an immutable, value-only preparation of Parameters.
// It owns detached raw and effective literals, the derived Mod1 parameters and
// a canonical seal over all three values. Preparing parameters does not create
// an encoder, DFT matrix, evaluation key, evaluator or ciphertext.
type PreparedParameters struct {
	sealVersion    uint64
	raw            Parameters
	effective      Parameters
	mod1Parameters mod1.Parameters
	digest         [sha256.Size]byte
}

// PrepareParameters validates and derives the matrix-free parameter state
// consumed by the bootstrapping evaluator. Caller-owned slices, pointers and
// big.Float values are detached before any effective scaling is applied.
func PrepareParameters(parameters Parameters) (PreparedParameters, error) {
	raw := cloneBootstrappingParameters(parameters)
	effective := cloneBootstrappingParameters(parameters)

	// A standard-to-conjugate-invariant switch multiplies the scale by two.
	// This assignment intentionally matches the legacy evaluator semantics: a
	// caller-provided S2C scaling is retained in raw but replaced in effective.
	if effective.ResidualParameters.RingType() == ring.ConjugateInvariant {
		effective.SlotsToCoeffsParameters.Scaling = new(big.Float).SetFloat64(0.5)
	}

	if effective.Mod1ParametersLiteral.Mod1Degree < 0 {
		return PreparedParameters{}, fmt.Errorf("Mod1 degree cannot be negative")
	}
	if effective.Mod1ParametersLiteral.Mod1InvDegree < 0 {
		return PreparedParameters{}, fmt.Errorf("Mod1 inverse degree cannot be negative")
	}
	if effective.Mod1ParametersLiteral.DoubleAngle < 0 {
		return PreparedParameters{}, fmt.Errorf("Mod1 double angle cannot be negative")
	}
	if scaling := effective.Mod1ParametersLiteral.Scaling; math.IsNaN(scaling) || math.IsInf(scaling, 0) {
		return PreparedParameters{}, fmt.Errorf("Mod1 scaling must be finite")
	}
	if effective.Mod1ParametersLiteral.Scaling < 0 && effective.Mod1ParametersLiteral.Mod1InvDegree == 0 && effective.Mod1ParametersLiteral.DoubleAngle > 0 {
		return PreparedParameters{}, fmt.Errorf("negative Mod1 scaling with double angle requires a non-real scaling root")
	}

	if effective.Mod1ParametersLiteral.Mod1Type == mod1.SinContinuous && effective.Mod1ParametersLiteral.DoubleAngle != 0 {
		return PreparedParameters{}, fmt.Errorf("cannot use double angle formula for Mod1Type = Sin -> must use Mod1Type = Cos")
	}

	if effective.Mod1ParametersLiteral.Mod1Type == mod1.CosDiscrete && effective.Mod1ParametersLiteral.Mod1Degree < 2*(effective.Mod1ParametersLiteral.K-1) {
		return PreparedParameters{}, fmt.Errorf("Mod1Type 'mod1.CosDiscrete' uses a minimum degree of 2*(K-1) but EvalMod degree is smaller")
	}
	if effective.Mod1ParametersLiteral.K <= 0 {
		return PreparedParameters{}, fmt.Errorf("Mod1 K must be positive")
	}
	if ratio := effective.Mod1ParametersLiteral.LogMessageRatio; ratio < 0 || ratio >= bits.UintSize {
		return PreparedParameters{}, fmt.Errorf("Mod1 LogMessageRatio must be in [0, %d)", bits.UintSize)
	}

	switch effective.CircuitOrder {
	case ModUpThenEncode:
		if effective.CoeffsToSlotsParameters.LevelQ-effective.CoeffsToSlotsParameters.Depth(true) != effective.Mod1ParametersLiteral.LevelQ {
			return PreparedParameters{}, fmt.Errorf("starting level and depth of CoeffsToSlotsParameters inconsistent starting level of Mod1ParametersLiteral")
		}

		if effective.Mod1ParametersLiteral.LevelQ-effective.Mod1ParametersLiteral.Depth() != effective.SlotsToCoeffsParameters.LevelQ {
			return PreparedParameters{}, fmt.Errorf("starting level and depth of Mod1ParametersLiteral inconsistent starting level of CoeffsToSlotsParameters")
		}
	case DecodeThenModUp:
		if effective.BootstrappingParameters.MaxLevel()-effective.CoeffsToSlotsParameters.Depth(true) != effective.Mod1ParametersLiteral.LevelQ {
			return PreparedParameters{}, fmt.Errorf("starting level and depth of Mod1ParametersLiteral inconsistent starting level of CoeffsToSlotsParameters")
		}
	case Custom:
	default:
		return PreparedParameters{}, fmt.Errorf("invalid CircuitOrder value")
	}

	params := effective.BootstrappingParameters
	if len(params.Q()) == 0 {
		return PreparedParameters{}, fmt.Errorf("bootstrapping parameters have an empty Q chain")
	}

	mod1Parameters, err := mod1.NewParametersFromLiteral(params, effective.Mod1ParametersLiteral)
	if err != nil {
		return PreparedParameters{}, err
	}

	// Correcting factor for approximate division by Q. The second correcting
	// factor is included in the EvalMod polynomial coefficients.
	qDiv := mod1Parameters.ScalingFactor().Float64() / math.Exp2(math.Round(math.Log2(float64(params.Q()[0]))))
	if qDiv > 1 {
		qDiv = 1
	}

	scale := params.DefaultScale().Float64()
	offset := mod1Parameters.ScalingFactor().Float64() / mod1Parameters.MessageRatio()
	coeffsToSlotsScaling := new(big.Float).SetFloat64(qDiv / (mod1Parameters.K * mod1Parameters.QDiff))
	slotsToCoeffsScaling := new(big.Float).SetFloat64(scale / offset)

	if effective.CoeffsToSlotsParameters.Scaling == nil {
		effective.CoeffsToSlotsParameters.Scaling = coeffsToSlotsScaling
	} else {
		effective.CoeffsToSlotsParameters.Scaling = new(big.Float).Mul(effective.CoeffsToSlotsParameters.Scaling, coeffsToSlotsScaling)
	}

	if effective.SlotsToCoeffsParameters.Scaling == nil {
		effective.SlotsToCoeffsParameters.Scaling = slotsToCoeffsScaling
	} else {
		effective.SlotsToCoeffsParameters.Scaling = new(big.Float).Mul(effective.SlotsToCoeffsParameters.Scaling, slotsToCoeffsScaling)
	}

	prepared := PreparedParameters{
		sealVersion:    preparedParametersSealVersion,
		raw:            raw,
		effective:      effective,
		mod1Parameters: cloneMod1Parameters(mod1Parameters),
	}
	if prepared.digest, err = digestPreparedParameters(prepared.raw, prepared.effective, prepared.mod1Parameters); err != nil {
		return PreparedParameters{}, fmt.Errorf("cannot seal prepared bootstrapping parameters: %w", err)
	}

	return prepared, nil
}

// RawParameters returns a defensive copy of the exact caller-visible
// parameters before conjugate-invariant and runtime DFT scaling adjustments.
func (prepared PreparedParameters) RawParameters() Parameters {
	return cloneBootstrappingParameters(prepared.raw)
}

// EffectiveParameters returns a defensive copy of the validated parameters
// with all runtime DFT scaling adjustments applied.
func (prepared PreparedParameters) EffectiveParameters() Parameters {
	return cloneBootstrappingParameters(prepared.effective)
}

// Mod1Parameters returns a defensive copy of the derived Mod1 parameters.
func (prepared PreparedParameters) Mod1Parameters() mod1.Parameters {
	return cloneMod1Parameters(prepared.mod1Parameters)
}

// Digest returns the canonical prepared-parameter seal by value.
func (prepared PreparedParameters) Digest() [sha256.Size]byte {
	return prepared.digest
}

// Verify recomputes and checks the canonical prepared-parameter seal.
func (prepared PreparedParameters) Verify() error {
	if prepared.sealVersion != preparedParametersSealVersion {
		return fmt.Errorf("invalid prepared-parameter seal version: got %d, want %d", prepared.sealVersion, preparedParametersSealVersion)
	}
	digest, err := digestPreparedParameters(prepared.raw, prepared.effective, prepared.mod1Parameters)
	if err != nil {
		return fmt.Errorf("cannot verify prepared bootstrapping parameters: %w", err)
	}
	if digest != prepared.digest {
		return fmt.Errorf("prepared bootstrapping parameter seal mismatch")
	}
	return nil
}

func cloneBootstrappingParameters(source Parameters) Parameters {
	clone := source
	clone.SlotsToCoeffsParameters = cloneDFTMatrixLiteral(source.SlotsToCoeffsParameters)
	clone.CoeffsToSlotsParameters = cloneDFTMatrixLiteral(source.CoeffsToSlotsParameters)
	if source.IterationsParameters != nil {
		iterations := *source.IterationsParameters
		if source.IterationsParameters.BootstrappingPrecision != nil {
			iterations.BootstrappingPrecision = make([]float64, len(source.IterationsParameters.BootstrappingPrecision))
			copy(iterations.BootstrappingPrecision, source.IterationsParameters.BootstrappingPrecision)
		}
		clone.IterationsParameters = &iterations
	}
	return clone
}

func cloneDFTMatrixLiteral(source dft.MatrixLiteral) dft.MatrixLiteral {
	clone := source
	if source.Levels != nil {
		clone.Levels = make([]int, len(source.Levels))
		copy(clone.Levels, source.Levels)
	}
	if source.Scaling != nil {
		clone.Scaling = new(big.Float).Copy(source.Scaling)
	}
	return clone
}

func cloneMod1Parameters(source mod1.Parameters) mod1.Parameters {
	clone := source
	clone.Mod1Poly = cloneBigPolynomial(source.Mod1Poly)
	if source.Mod1InvPoly != nil {
		inverse := cloneBigPolynomial(*source.Mod1InvPoly)
		clone.Mod1InvPoly = &inverse
	}
	return clone
}

func cloneBigPolynomial(source bignum.Polynomial) bignum.Polynomial {
	clone := source
	clone.A = *new(big.Float).Copy(&source.A)
	clone.B = *new(big.Float).Copy(&source.B)
	if source.Coeffs != nil {
		clone.Coeffs = make([]*bignum.Complex, len(source.Coeffs))
		for i, coefficient := range source.Coeffs {
			if coefficient == nil {
				continue
			}
			coefficientClone := new(bignum.Complex)
			for component := range coefficientClone {
				if coefficient[component] != nil {
					coefficientClone[component] = new(big.Float).Copy(coefficient[component])
				}
			}
			clone.Coeffs[i] = coefficientClone
		}
	}
	return clone
}

func digestPreparedParameters(raw, effective Parameters, mod1Parameters mod1.Parameters) ([sha256.Size]byte, error) {
	var canonical bytes.Buffer
	writeCanonicalBytes(&canonical, []byte("lattigo-bootstrapping-prepared-parameters-v1"))
	writeCanonicalUint64(&canonical, preparedParametersSealVersion)

	for _, parameters := range []Parameters{raw, effective} {
		payload, err := parameters.MarshalBinary()
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		writeCanonicalBytes(&canonical, payload)
		if err := writeCanonicalBigFloat(&canonical, parameters.SlotsToCoeffsParameters.Scaling); err != nil {
			return [sha256.Size]byte{}, err
		}
		if err := writeCanonicalBigFloat(&canonical, parameters.CoeffsToSlotsParameters.Scaling); err != nil {
			return [sha256.Size]byte{}, err
		}
		writeCanonicalUint64(&canonical, uint64(parameters.CircuitOrder))
		if parameters.IterationsParameters == nil {
			writeCanonicalUint64(&canonical, 0)
		} else {
			writeCanonicalUint64(&canonical, 1)
			writeCanonicalUint64(&canonical, uint64(parameters.IterationsParameters.ReservedPrimeBitSize))
			writeCanonicalUint64(&canonical, uint64(len(parameters.IterationsParameters.BootstrappingPrecision)))
			for _, precision := range parameters.IterationsParameters.BootstrappingPrecision {
				writeCanonicalUint64(&canonical, math.Float64bits(precision))
			}
		}
	}

	writeCanonicalUint64(&canonical, uint64(mod1Parameters.LevelQ))
	writeCanonicalUint64(&canonical, uint64(mod1Parameters.LogDefaultScale))
	writeCanonicalUint64(&canonical, uint64(mod1Parameters.Mod1Type))
	writeCanonicalUint64(&canonical, uint64(mod1Parameters.LogMessageRatio))
	writeCanonicalUint64(&canonical, uint64(mod1Parameters.DoubleAngle))
	writeCanonicalUint64(&canonical, math.Float64bits(mod1Parameters.QDiff))
	writeCanonicalUint64(&canonical, math.Float64bits(mod1Parameters.Sqrt2Pi))
	writeCanonicalUint64(&canonical, math.Float64bits(mod1Parameters.K))
	if err := writeCanonicalPolynomial(&canonical, &mod1Parameters.Mod1Poly); err != nil {
		return [sha256.Size]byte{}, err
	}
	if err := writeCanonicalPolynomial(&canonical, mod1Parameters.Mod1InvPoly); err != nil {
		return [sha256.Size]byte{}, err
	}

	return sha256.Sum256(canonical.Bytes()), nil
}

func writeCanonicalPolynomial(buffer *bytes.Buffer, polynomial *bignum.Polynomial) error {
	if polynomial == nil {
		writeCanonicalUint64(buffer, 0)
		return nil
	}
	writeCanonicalUint64(buffer, 1)
	writeCanonicalUint64(buffer, uint64(polynomial.Basis))
	writeCanonicalUint64(buffer, uint64(polynomial.Nodes))
	writeCanonicalBool(buffer, polynomial.IsOdd)
	writeCanonicalBool(buffer, polynomial.IsEven)
	if err := writeCanonicalBigFloat(buffer, &polynomial.A); err != nil {
		return err
	}
	if err := writeCanonicalBigFloat(buffer, &polynomial.B); err != nil {
		return err
	}
	writeCanonicalUint64(buffer, uint64(len(polynomial.Coeffs)))
	for _, coefficient := range polynomial.Coeffs {
		if coefficient == nil {
			writeCanonicalUint64(buffer, 0)
			continue
		}
		writeCanonicalUint64(buffer, 1)
		for _, component := range coefficient {
			if err := writeCanonicalBigFloat(buffer, component); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeCanonicalBigFloat(buffer *bytes.Buffer, value *big.Float) error {
	if value == nil {
		writeCanonicalUint64(buffer, 0)
		return nil
	}
	payload, err := value.GobEncode()
	if err != nil {
		return err
	}
	writeCanonicalUint64(buffer, 1)
	writeCanonicalBytes(buffer, payload)
	return nil
}

func writeCanonicalBool(buffer *bytes.Buffer, value bool) {
	if value {
		writeCanonicalUint64(buffer, 1)
	} else {
		writeCanonicalUint64(buffer, 0)
	}
}

func writeCanonicalBytes(buffer *bytes.Buffer, value []byte) {
	writeCanonicalUint64(buffer, uint64(len(value)))
	_, _ = buffer.Write(value)
}

func writeCanonicalUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	_, _ = buffer.Write(encoded[:])
}
