package homchain

import (
	"fmt"
	"sort"

	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	commonlintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/common/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

// CompileOptions controls the Lattigo plaintext matrix encoding. The scale is
// the linear transform's plaintext scale, not a truncation instruction.
type CompileOptions struct {
	LevelQ                    int
	LevelP                    int
	Scale                     rlwe.Scale
	LogBabyStepGiantStepRatio int
}

// Parameters returns native Lattigo parameters for the trusted full-slot
// representation. Compact repeated-row specs are flattened first, so this
// public path always agrees with Compile and is directly encodable by CKKS.
func (s TransformSpec) Parameters(options CompileOptions) (ckkslintrans.Parameters, error) {
	compiled, err := s.FullSlot()
	if err != nil {
		return ckkslintrans.Parameters{}, fmt.Errorf("homchain: flatten %s parameters: %w", s.name, err)
	}
	return compiled.parameters(options), nil
}

func (s TransformSpec) parameters(options CompileOptions) ckkslintrans.Parameters {
	return ckkslintrans.Parameters{
		DiagonalsIndexList:        s.diagonals.DiagonalsIndexList(),
		LevelQ:                    options.LevelQ,
		LevelP:                    options.LevelP,
		Scale:                     options.Scale,
		LogDimensions:             s.logDimensions,
		LogBabyStepGiantStepRatio: options.LogBabyStepGiantStepRatio,
	}
}

// GaloisElements lists the rotation keys needed by a transform spec for the
// selected BSGS ratio. Invalid transform state is reported rather than folded
// into an empty key set.
func (s TransformSpec) GaloisElements(params rlwe.ParameterProvider, logBabyStepGiantStepRatio int) ([]uint64, error) {
	parameters, err := s.Parameters(CompileOptions{LogBabyStepGiantStepRatio: logBabyStepGiantStepRatio})
	if err != nil {
		return nil, fmt.Errorf("homchain: derive %s Galois elements: %w", s.name, err)
	}
	return withoutIdentity(params, ckkslintrans.GaloisElements(params, parameters)), nil
}

// Compile encodes one high-precision transform as a Lattigo linear
// transformation. Repeated-row specs are first converted to the equivalent
// full-slot block-diagonal layout accepted by the CKKS encoder.
func Compile(params rlwe.ParameterProvider, encoder schemes.Encoder, spec TransformSpec, options CompileOptions) (ckkslintrans.LinearTransformation, error) {
	if encoder == nil {
		return ckkslintrans.LinearTransformation{}, fmt.Errorf("homchain: nil encoder")
	}
	compiledSpec, err := spec.FullSlot()
	if err != nil {
		return ckkslintrans.LinearTransformation{}, fmt.Errorf("homchain: flatten %s: %w", spec.name, err)
	}
	p := params.GetRLWEParameters()
	if options.LevelQ < 0 || options.LevelQ > p.MaxLevel() {
		return ckkslintrans.LinearTransformation{}, fmt.Errorf("homchain: LevelQ %d outside [0,%d]", options.LevelQ, p.MaxLevel())
	}
	if options.LevelP < 0 || options.LevelP > p.MaxLevelP() {
		return ckkslintrans.LinearTransformation{}, fmt.Errorf("homchain: LevelP %d outside [0,%d]", options.LevelP, p.MaxLevelP())
	}

	if compiledSpec.logDimensions.Cols > p.LogN()-1 {
		return ckkslintrans.LinearTransformation{}, fmt.Errorf(
			"homchain: %s needs 2^%d CKKS slots, parameter maximum is 2^%d",
			compiledSpec.name, compiledSpec.logDimensions.Cols, p.LogN()-1,
		)
	}
	transformation := ckkslintrans.NewTransformation(params, compiledSpec.parameters(options))
	if err := ckkslintrans.Encode(encoder, cloneDiagonals(compiledSpec.diagonals), transformation); err != nil {
		return ckkslintrans.LinearTransformation{}, fmt.Errorf("homchain: encode %s: %w", spec.name, err)
	}
	return transformation, nil
}

// CompiledPair is the encoded low/high half of U or V.
type CompiledPair struct {
	Low  ckkslintrans.LinearTransformation
	High ckkslintrans.LinearTransformation
}

// CompilePair encodes both halves with identical Lattigo parameters.
func CompilePair(params rlwe.ParameterProvider, encoder schemes.Encoder, pair PairSpec, options CompileOptions) (CompiledPair, error) {
	low, err := Compile(params, encoder, pair.Low, options)
	if err != nil {
		return CompiledPair{}, err
	}
	high, err := Compile(params, encoder, pair.High, options)
	if err != nil {
		return CompiledPair{}, err
	}
	return CompiledPair{Low: low, High: high}, nil
}

// RotationIndexes returns exactly the non-identity rotations exercised by
// both compiled transforms. For BSGS this is the union of baby and giant
// steps; for the naive evaluator it is the non-zero diagonal indexes.
func (p CompiledPair) RotationIndexes() []int {
	rotations := map[int]struct{}{}
	collect := func(transformation ckkslintrans.LinearTransformation) {
		if transformation.N1 == 0 {
			for index := range transformation.Vec {
				if index != 0 {
					rotations[index] = struct{}{}
				}
			}
			return
		}
		_, babySteps, giantSteps := commonlintrans.LinearTransformation(transformation).BSGSIndex()
		for _, rotation := range append(babySteps, giantSteps...) {
			if rotation != 0 {
				rotations[rotation] = struct{}{}
			}
		}
	}
	collect(p.Low)
	collect(p.High)
	result := make([]int, 0, len(rotations))
	for rotation := range rotations {
		result = append(result, rotation)
	}
	sort.Ints(result)
	return result
}

// GaloisElements returns the exact deduplicated key set for RotationIndexes.
func (p CompiledPair) GaloisElements(params rlwe.ParameterProvider) []uint64 {
	return withoutIdentity(params, params.GetRLWEParameters().GaloisElements(p.RotationIndexes()))
}

// GaloisElementsForZToC includes V rotations plus complex conjugation, which
// implements the required z+conj(z) real projection.
func GaloisElementsForZToC(params rlwe.ParameterProvider, v CompiledPair) []uint64 {
	result := v.GaloisElements(params)
	result = append(result, params.GetRLWEParameters().GaloisElementOrderTwoOrthogonalSubgroup())
	return withoutIdentity(params, result)
}

// GaloisElementsForRoundTrip returns every key needed by Z-To-C followed by
// C-To-Z.
func GaloisElementsForRoundTrip(params rlwe.ParameterProvider, v, u CompiledPair) []uint64 {
	result := GaloisElementsForZToC(params, v)
	result = append(result, u.GaloisElements(params)...)
	return withoutIdentity(params, result)
}

func withoutIdentity(params rlwe.ParameterProvider, input []uint64) []uint64 {
	identity := params.GetRLWEParameters().GaloisElement(0)
	filtered := make([]uint64, 0, len(input))
	for _, element := range input {
		if element != identity {
			filtered = append(filtered, element)
		}
	}
	return uniqueGaloisElements(filtered)
}

func cloneDiagonals(input ckkslintrans.Diagonals[*bignum.Complex]) ckkslintrans.Diagonals[*bignum.Complex] {
	result := make(ckkslintrans.Diagonals[*bignum.Complex], len(input))
	for index, diagonal := range input {
		result[index] = make([]*bignum.Complex, len(diagonal))
		for i, value := range diagonal {
			result[index][i] = value.Clone()
		}
	}
	return result
}

func uniqueGaloisElements(input []uint64) []uint64 {
	seen := make(map[uint64]struct{}, len(input))
	result := make([]uint64, 0, len(input))
	for _, element := range input {
		if _, exists := seen[element]; exists {
			continue
		}
		seen[element] = struct{}{}
		result = append(result, element)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
