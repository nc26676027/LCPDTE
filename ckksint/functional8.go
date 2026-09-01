package ckksint

import (
	"fmt"
	"sync"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	// Functional8Lanes is the fixed SIMD lane count of the functional circuit.
	Functional8Lanes                   = 4
	functional8RefreshEncoderPrecision = uint(192)
	functional8IntegerEncoderPrecision = uint(256)
	functional8BooleanLevel            = 5
)

// Signed8Range is the plaintext interval certificate used by signed
// comparison and tree evaluation. Every x-threshold difference must fit in an
// int8; NewDemoFunctional8 validates that property.
type Signed8Range struct {
	FeatureMin   int8
	FeatureMax   int8
	ThresholdMin int8
	ThresholdMax int8
}

// Functional8Profile describes the fixed four-lane functional circuit.
type Functional8Profile struct {
	SecurityBoundary SecurityBoundary
	WordBits         WordBits
	Lanes            int
	FeatureMin       int8
	FeatureMax       int8
	ThresholdMin     int8
	ThresholdMax     int8
	InputLevel       int
	BooleanLevel     int
}

// EvaluationInfo is the stable, high-level evidence returned by circuit
// operations. Empty fields are omitted only when the underlying circuit has no
// corresponding trace dimension.
type EvaluationInfo struct {
	Operation     string
	ProfileDigest string
	TraceDigest   string
	StageCount    int
	WallTime      time.Duration
}

// Depth2Model is one complete binary depth-2 tree. Splits are breadth-first:
// root, left child, right child. Leaves use path order 00, 01, 10, 11, where a
// zero branch is < threshold and a one branch is >= threshold.
type Depth2Model struct {
	FeatureIDs [3]int
	Thresholds [3]int8
	Leaves     [4]float64
}

type functional8Token struct{ marker byte }

// Functional8 owns the fixed functional-only A2B/B2A, signed comparison, and
// selected-child depth-2 circuits. Construction generates a fresh key domain
// and hides the custom bootstrapping graph from callers.
type Functional8 struct {
	mu sync.Mutex

	params         ckks.Parameters
	ranges         Signed8Range
	profile        Functional8Profile
	refreshEncoder *ckks.Encoder
	integerEncoder *ckks.Encoder
	ringZ          *z2n.Ring
	encryptor      *rlwe.Encryptor
	decryptor      *rlwe.Decryptor
	token          *functional8Token

	source              *bootstrapping.Evaluator
	a2bCircuit          *homchain.A2BFullCircuit
	a2bEvaluator        *homchain.A2BFullEvaluator
	b2aCircuit          *homchain.B2AFullCircuit
	b2aEvaluator        *homchain.B2AFullEvaluator
	comparatorCircuit   *homchain.Signed8ComparatorCircuit
	comparatorEvaluator *homchain.Signed8ComparatorEvaluator
}

// NewDemoFunctional8 constructs the fixed four-lane n=8 functional circuit.
// The LogN=5 tuple is intentionally insecure and is always labeled DemoOnly.
func NewDemoFunctional8(ranges Signed8Range) (*Functional8, error) {
	certificate, err := homchain.NewSigned8NoOverflowRange(
		int64(ranges.FeatureMin), int64(ranges.FeatureMax),
		int64(ranges.ThresholdMin), int64(ranges.ThresholdMax),
	)
	if err != nil {
		return nil, fmt.Errorf("ckksint: signed8 range certificate: %w", err)
	}
	params, err := homchain.GaoA2BKernelFunctionalParameters()
	if err != nil {
		return nil, fmt.Errorf("ckksint: functional8 parameters: %w", err)
	}
	refreshEncoder := ckks.NewEncoder(params, functional8RefreshEncoderPrecision)
	integerEncoder := ckks.NewEncoder(params, functional8IntegerEncoderPrecision)

	refreshCircuit, err := homchain.NewA2BRefreshCircuit(params, refreshEncoder)
	if err != nil {
		return nil, fmt.Errorf("ckksint: functional8 refresh circuit: %w", err)
	}
	a2bCircuit, err := homchain.NewA2BFullCircuit(params, refreshEncoder, integerEncoder)
	if err != nil {
		return nil, fmt.Errorf("ckksint: functional8 A2B circuit: %w", err)
	}
	b2aCircuit, err := homchain.NewB2AFullAtLevelCircuit(params, integerEncoder, functional8BooleanLevel)
	if err != nil {
		return nil, fmt.Errorf("ckksint: functional8 B2A circuit: %w", err)
	}
	comparatorCircuit, err := homchain.NewSigned8ComparatorCircuit(params, refreshEncoder, integerEncoder, certificate)
	if err != nil {
		return nil, fmt.Errorf("ckksint: functional8 comparator circuit: %w", err)
	}

	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	galoisElements := uniqueGaloisElements(
		a2bCircuit.RequiredKeyProfile().All(),
		b2aCircuit.Profile().RequiredGaloisElements(),
		comparatorCircuit.PublicProfile().RequiredGaloisElements(),
	)
	keySet := rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeysNew(galoisElements, secretKey)...,
	)
	dft := refreshCircuit.Profile().DFT()
	bootstrapParameters := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: dft.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: dft.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ:          dft.CoeffsToSlotsLiteral().LevelQ - 3,
			LogScale:        params.LogDefaultScale(),
			Mod1Type:        mod1.SinContinuous,
			LogMessageRatio: 15,
			K:               1,
			Mod1Degree:      3,
		},
		CircuitOrder: bootstrapping.Custom,
	}
	source, err := bootstrapping.NewEvaluator(
		bootstrapParameters,
		&bootstrapping.EvaluationKeys{MemEvaluationKeySet: keySet},
	)
	if err != nil {
		return nil, fmt.Errorf("ckksint: functional8 bootstrap evaluator: %w", err)
	}
	a2bEvaluator, err := a2bCircuit.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("ckksint: bind functional8 A2B: %w", err)
	}
	b2aEvaluator, err := b2aCircuit.BindEvaluator(ckks.NewEvaluator(params, keySet))
	if err != nil {
		return nil, fmt.Errorf("ckksint: bind functional8 B2A: %w", err)
	}
	comparatorEvaluator, err := comparatorCircuit.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("ckksint: bind functional8 comparator: %w", err)
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, functional8IntegerEncoderPrecision)
	if err != nil {
		return nil, fmt.Errorf("ckksint: functional8 integer ring: %w", err)
	}

	return &Functional8{
		params: params, ranges: ranges,
		profile: Functional8Profile{
			SecurityBoundary: DemoOnly,
			WordBits:         Word8,
			Lanes:            Functional8Lanes,
			FeatureMin:       ranges.FeatureMin,
			FeatureMax:       ranges.FeatureMax,
			ThresholdMin:     ranges.ThresholdMin,
			ThresholdMax:     ranges.ThresholdMax,
			InputLevel:       params.MaxLevel(),
			BooleanLevel:     functional8BooleanLevel,
		},
		refreshEncoder: refreshEncoder, integerEncoder: integerEncoder, ringZ: ringZ,
		encryptor: ckks.NewEncryptor(params, secretKey), decryptor: ckks.NewDecryptor(params, secretKey),
		token: new(functional8Token), source: source,
		a2bCircuit: a2bCircuit, a2bEvaluator: a2bEvaluator,
		b2aCircuit: b2aCircuit, b2aEvaluator: b2aEvaluator,
		comparatorCircuit: comparatorCircuit, comparatorEvaluator: comparatorEvaluator,
	}, nil
}

// Profile returns a detached description of the fixed circuit boundary.
func (f *Functional8) Profile() Functional8Profile {
	if f == nil {
		return Functional8Profile{}
	}
	return f.profile
}

// LattigoParameters returns the immutable-by-convention functional CKKS tuple.
func (f *Functional8) LattigoParameters() ckks.Parameters {
	if f == nil {
		return ckks.Parameters{}
	}
	return f.params
}

func (f *Functional8) ready() error {
	if f == nil || f.token == nil || f.encryptor == nil || f.decryptor == nil ||
		f.refreshEncoder == nil || f.integerEncoder == nil || f.ringZ == nil ||
		f.source == nil || f.a2bCircuit == nil || f.a2bEvaluator == nil ||
		f.b2aCircuit == nil || f.b2aEvaluator == nil ||
		f.comparatorCircuit == nil || f.comparatorEvaluator == nil {
		return fmt.Errorf("ckksint: nil or incomplete functional8 engine")
	}
	return nil
}

func uniqueGaloisElements(groups ...[]uint64) []uint64 {
	seen := make(map[uint64]struct{})
	result := make([]uint64, 0)
	for _, group := range groups {
		for _, element := range group {
			if _, exists := seen[element]; exists {
				continue
			}
			seen[element] = struct{}{}
			result = append(result, element)
		}
	}
	return result
}
