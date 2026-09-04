package homchain

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	ckksdft "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	ckkslintrans "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/lintrans"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/mod1"
	ckkspolynomial "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/polynomial"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const (
	signed8Depth2ChildComparatorProfileSchema = "signed8-depth2-child-comparator-profile-v1"
	signed8Depth2ChildComparatorInputSchema   = "signed8-depth2-child-comparator-input-v1"
	signed8Depth2ChildComparatorLevelLedger   = "typed-prefix-F/T-L6->subtract-L6->fixed-ingress6-high-L5->direct-sign-L4->negate-L4->add-arithmetic-root-one-L4"
)

// Signed8Depth2ChildComparatorFidelity deliberately limits the claim to the
// tested functional circuit. It is not a security or complete-tree claim.
type Signed8Depth2ChildComparatorFidelity string

const Signed8Depth2ChildFunctionalNotSecure Signed8Depth2ChildComparatorFidelity = "functional_not_secure"

// Signed8Depth2ChildComparatorOperationCounts is the wrapper-only ledger.
// Nested ingress and sign-fusion work remains in the corresponding profiles.
type Signed8Depth2ChildComparatorOperationCounts struct {
	CiphertextCiphertextSubtractions int
	IngressInvocations               int
	SignFusionInvocations            int
	Negations                        int
	CiphertextPlaintextVectorAdds    int
	Rescales                         int
	Rotations                        int
}

// Signed8Depth2ChildComparatorStage names the wrapper's seven ordered real
// ciphertext boundaries. FailureStage uses the same type but is not a runtime
// state and therefore may be populated while the state ledger remains empty.
type Signed8Depth2ChildComparatorStage string

const (
	Signed8Depth2ChildStageAdmission      Signed8Depth2ChildComparatorStage = "admission"
	Signed8Depth2ChildStagePreflight      Signed8Depth2ChildComparatorStage = "preflight"
	Signed8Depth2ChildStageFeature        Signed8Depth2ChildComparatorStage = "feature-input-L6"
	Signed8Depth2ChildStageThreshold      Signed8Depth2ChildComparatorStage = "threshold-input-L6"
	Signed8Depth2ChildStageDifference     Signed8Depth2ChildComparatorStage = "difference-L6"
	Signed8Depth2ChildStageIngressHigh    Signed8Depth2ChildComparatorStage = "ingress-high-L5"
	Signed8Depth2ChildStageArithmeticSign Signed8Depth2ChildComparatorStage = "arithmetic-sign-L4"
	Signed8Depth2ChildStageNegatedSign    Signed8Depth2ChildComparatorStage = "negated-sign-L4"
	Signed8Depth2ChildStageGreaterEqual   Signed8Depth2ChildComparatorStage = "greater-equal-L4"
)

// Signed8Depth2ChildComparatorState is an exact detached runtime snapshot.
type Signed8Depth2ChildComparatorState struct {
	Stage           Signed8Depth2ChildComparatorStage
	Level           int
	Degree          int
	LogDimensions   ring.Dimensions
	Scale           ExactScaleSnapshot
	SerializedBytes int
}

// Signed8Depth2ChildComparatorSerializedBytes separates the two online inputs
// and final output from retained wrapper evidence. Every entry is measured on
// the corresponding actual runtime ciphertext.
type Signed8Depth2ChildComparatorSerializedBytes struct {
	Feature            int
	Threshold          int
	Difference         int
	IngressHigh        int
	ArithmeticSign     int
	NegatedSign        int
	GreaterEqualOutput int
}

func (s Signed8Depth2ChildComparatorSerializedBytes) OnlineInputBytes() int {
	return s.Feature + s.Threshold
}
func (s Signed8Depth2ChildComparatorSerializedBytes) OnlineOutputBytes() int {
	return s.GreaterEqualOutput
}
func (s Signed8Depth2ChildComparatorSerializedBytes) RetainedLocalBytes() int {
	return s.Difference + s.IngressHigh + s.ArithmeticSign + s.NegatedSign
}
func (s Signed8Depth2ChildComparatorSerializedBytes) TotalBytes() int {
	return s.OnlineInputBytes() + s.RetainedLocalBytes() + s.OnlineOutputBytes()
}
func (s Signed8Depth2ChildComparatorSerializedBytes) Complete() bool {
	return s.Feature > 0 && s.Threshold > 0 && s.Difference > 0 && s.IngressHigh > 0 &&
		s.ArithmeticSign > 0 && s.NegatedSign > 0 && s.GreaterEqualOutput > 0
}

// Signed8Depth2ChildComparatorProfile is the immutable public projection of
// the closed prefix -> ingress-6 -> sign-fusion child-comparison graph.
type Signed8Depth2ChildComparatorProfile struct {
	fidelity         Signed8Depth2ChildComparatorFidelity
	predicate        Signed8ComparatorPredicate
	children         Signed8ChildConvention
	inputLevel       int
	outputLevel      int
	parameter        string
	prefix           string
	protocolRange    string
	tree             string
	schedule         string
	operandSource    Signed8Depth2OperandSourceKind
	ingressProfile   string
	ingressSource    A2BFullIngress6Source
	ingressRange     string
	ingressAdmission string
	ingressSuffix    string
	ingressKey       string
	ingressSpecialB0 string
	ingressMask      string
	ingressFirstSTC  string
	ingressSharedCTS string
	ingressSecondSTC string
	signProfile      string
	signSource       string
	signCompiled     string
	arithmeticOne    string
	counts           Signed8Depth2ChildComparatorOperationCounts
	requiredGalois   []uint64
	relinearization  bool
	expectedStates   []Signed8Depth2ChildComparatorState
	expectedBytes    Signed8Depth2ChildComparatorSerializedBytes
	levelLedger      string
	digest           string
}

func (p Signed8Depth2ChildComparatorProfile) Fidelity() Signed8Depth2ChildComparatorFidelity {
	return p.fidelity
}
func (p Signed8Depth2ChildComparatorProfile) Predicate() Signed8ComparatorPredicate {
	return p.predicate
}
func (p Signed8Depth2ChildComparatorProfile) ChildConvention() Signed8ChildConvention {
	return p.children
}
func (p Signed8Depth2ChildComparatorProfile) InputLevel() int  { return p.inputLevel }
func (p Signed8Depth2ChildComparatorProfile) OutputLevel() int { return p.outputLevel }
func (p Signed8Depth2ChildComparatorProfile) ParameterDigest() string {
	return p.parameter
}
func (p Signed8Depth2ChildComparatorProfile) PrefixProfileDigest() string { return p.prefix }
func (p Signed8Depth2ChildComparatorProfile) ProtocolRangeDigest() string { return p.protocolRange }
func (p Signed8Depth2ChildComparatorProfile) TreeDigest() string          { return p.tree }
func (p Signed8Depth2ChildComparatorProfile) ScheduleDigest() string      { return p.schedule }
func (p Signed8Depth2ChildComparatorProfile) OperandSourceKind() Signed8Depth2OperandSourceKind {
	return p.operandSource
}
func (p Signed8Depth2ChildComparatorProfile) IngressProfileDigest() string {
	return p.ingressProfile
}
func (p Signed8Depth2ChildComparatorProfile) IngressSource() A2BFullIngress6Source {
	return p.ingressSource
}
func (p Signed8Depth2ChildComparatorProfile) IngressRangeDigest() string {
	return p.ingressRange
}
func (p Signed8Depth2ChildComparatorProfile) IngressAdmissionDigest() string {
	return p.ingressAdmission
}
func (p Signed8Depth2ChildComparatorProfile) IngressSuffixProfileDigest() string {
	return p.ingressSuffix
}
func (p Signed8Depth2ChildComparatorProfile) IngressKeyProfileDigest() string {
	return p.ingressKey
}
func (p Signed8Depth2ChildComparatorProfile) IngressSpecialB0Digest() string {
	return p.ingressSpecialB0
}
func (p Signed8Depth2ChildComparatorProfile) IngressMaskPayloadDigest() string {
	return p.ingressMask
}
func (p Signed8Depth2ChildComparatorProfile) IngressFirstSTCEncodedPayloadDigest() string {
	return p.ingressFirstSTC
}
func (p Signed8Depth2ChildComparatorProfile) IngressSharedCTSEncodedPayloadDigest() string {
	return p.ingressSharedCTS
}
func (p Signed8Depth2ChildComparatorProfile) IngressSecondSTCEncodedPayloadDigest() string {
	return p.ingressSecondSTC
}
func (p Signed8Depth2ChildComparatorProfile) SignProfileDigest() string  { return p.signProfile }
func (p Signed8Depth2ChildComparatorProfile) SignSourceDigest() string   { return p.signSource }
func (p Signed8Depth2ChildComparatorProfile) SignCompiledDigest() string { return p.signCompiled }
func (p Signed8Depth2ChildComparatorProfile) ArithmeticOnePayloadDigest() string {
	return p.arithmeticOne
}
func (p Signed8Depth2ChildComparatorProfile) OperationCounts() Signed8Depth2ChildComparatorOperationCounts {
	return p.counts
}
func (p Signed8Depth2ChildComparatorProfile) RequiredGaloisElements() []uint64 {
	return append([]uint64(nil), p.requiredGalois...)
}
func (p Signed8Depth2ChildComparatorProfile) RequiresRelinearization() bool {
	return p.relinearization
}
func (p Signed8Depth2ChildComparatorProfile) ExpectedStates() []Signed8Depth2ChildComparatorState {
	return append([]Signed8Depth2ChildComparatorState(nil), p.expectedStates...)
}
func (p Signed8Depth2ChildComparatorProfile) ExpectedSerializedBytes() Signed8Depth2ChildComparatorSerializedBytes {
	return p.expectedBytes
}
func (p Signed8Depth2ChildComparatorProfile) LevelLedger() string { return p.levelLedger }
func (p Signed8Depth2ChildComparatorProfile) Digest() string      { return p.digest }
func (p Signed8Depth2ChildComparatorProfile) DigestSchema() string {
	return signed8Depth2ChildComparatorProfileSchema
}

type signed8Depth2ChildComparatorCircuitGraph struct {
	circuit             *Signed8Depth2ChildComparatorCircuit
	prefix              *Signed8Depth2SourcePrefixCircuit
	ingress             *A2BFullIngress6Circuit
	sign                *SignFusionCircuit
	arithmeticOne       *rlwe.Plaintext
	arithmeticOneSeal   *rlwe.Plaintext
	arithmeticOneDigest string
	profileDigest       string
	keyProfileDigest    string
}

// Signed8Depth2ChildComparatorCircuit owns every child and admits no raw
// ciphertext constructor seam.
type Signed8Depth2ChildComparatorCircuit struct {
	prefix              *Signed8Depth2SourcePrefixCircuit
	ingress             *A2BFullIngress6Circuit
	sign                *SignFusionCircuit
	params              ckks.Parameters
	arithmeticOne       *rlwe.Plaintext
	arithmeticOneSeal   *rlwe.Plaintext
	arithmeticOneDigest string
	profile             Signed8Depth2ChildComparatorProfile
	keyProfile          A2BRefreshKeyProfile
	graph               signed8Depth2ChildComparatorCircuitGraph
}

// Signed8Depth2ChildComparatorInput owns a detached copy of the complete
// prefix operand token. Raw L6 ciphertexts cannot be admitted through this
// API.
type Signed8Depth2ChildComparatorInput struct {
	operands           Signed8Depth2Operands
	profileDigest      string
	operandsProvenance string
	bindingDigest      string
}

type signed8Depth2ChildComparatorEvaluatorGraph struct {
	evaluator              *Signed8Depth2ChildComparatorEvaluator
	circuit                *Signed8Depth2ChildComparatorCircuit
	source                 *bootstrapping.Evaluator
	sourceCKKS             *ckks.Evaluator
	sourceKeySet           *rlwe.MemEvaluationKeySet
	sourceEvaluationKeys   *bootstrapping.EvaluationKeys
	prefix                 *Signed8Depth2SourcePrefixEvaluator
	ingressSource          *bootstrapping.Evaluator
	ingressKeySet          *rlwe.MemEvaluationKeySet
	ingress                *A2BFullIngress6Evaluator
	signSource             *ckks.Evaluator
	sign                   *SignFusionEvaluator
	relinearizationKey     *rlwe.RelinearizationKey
	relinearizationBinding signed8Depth2ChildRelinearizationKeyBinding
	galoisBindings         map[uint64]signed8Depth2ChildGaloisKeyBinding
	profileDigest          string
	keyProfileDigest       string
	sourceCKKSBinding      signed8Depth2ChildCKKSEvaluatorBinding
	ingressBinding         signed8Depth2ChildIngressEvaluatorBinding
	signBinding            signed8Depth2ChildSignEvaluatorBinding
}

// signed8Depth2ChildCKKSEvaluatorBinding records the shallow evaluator object
// graph that CKKS operations actually dereference. Pointer identity is used for
// buffers and arithmetic helpers because buffer contents legitimately change
// during evaluation.
type signed8Depth2ChildCKKSEvaluatorBinding struct {
	evaluator     *ckks.Evaluator
	keySet        rlwe.EvaluationKeySet
	runtime       ckks.EvaluatorRuntimeIdentity
	encoder       ckks.EncoderRuntimeIdentity
	rlweBuffers   rlwe.EvaluatorBuffersRuntimeIdentity
	rlweEvaluator rlwe.EvaluatorRuntimeIdentity
}

// signed8Depth2ChildIngressEvaluatorBinding is captured once at bind time. It
// ties the otherwise self-consistent nested evaluator graph to this wrapper's
// owned ingress circuit and filtered evaluation-key source.
type signed8Depth2ChildIngressEvaluatorBinding struct {
	ingress                 *A2BFullIngress6Evaluator
	ingressCircuit          *A2BFullIngress6Circuit
	suffix                  *A2BFullEvaluator
	suffixCircuit           *A2BFullCircuit
	suffixSource            *bootstrapping.Evaluator
	suffixSourceCKKS        *ckks.Evaluator
	suffixEvaluationKeys    *bootstrapping.EvaluationKeys
	suffixSourceBinding     signed8Depth2ChildCKKSEvaluatorBinding
	suffixKeySet            *rlwe.MemEvaluationKeySet
	suffixRelin             *rlwe.RelinearizationKey
	suffixGalois            map[uint64]*rlwe.GaloisKey
	refresh                 *A2BRefreshEvaluator
	refreshCircuit          *A2BRefreshCircuit
	refreshBootstrap        *bootstrapping.Evaluator
	refreshBootstrapCKKS    *ckks.Evaluator
	refreshCKKSBinding      signed8Depth2ChildCKKSEvaluatorBinding
	refreshTriangle         *Evaluator
	refreshTriangleCKKS     *ckks.Evaluator
	refreshTriangleLinear   *ckkslintrans.Evaluator
	refreshTriangleBinding  signed8Depth2ChildCKKSEvaluatorBinding
	refreshTriangleRuntime  ckkslintrans.EvaluatorRuntimeIdentity
	refreshDFT              *ckksdft.Evaluator
	refreshDFTRuntime       ckksdft.EvaluatorRuntimeIdentity
	refreshDFTLinear        *ckkslintrans.Evaluator
	refreshDFTLinearRuntime ckkslintrans.EvaluatorRuntimeIdentity
	refreshMod1             *mod1.Evaluator
	refreshMod1Polynomial   *ckkspolynomial.Evaluator
	refreshMod1PolyRuntime  ckkspolynomial.EvaluatorRuntimeIdentity
	refreshEvaluationKeys   *bootstrapping.EvaluationKeys
	sourceParameters        string
	sourceMod1Execution     string
	refreshParameters       string
	refreshMod1Execution    string
	refreshS2CPayload       string
	refreshC2SPayload       string
	kernel0                 *GaoA2BKernelEvaluator
	kernel1                 *GaoA2BKernelEvaluator
	kernelSource0           *ckks.Evaluator
	kernelSource1           *ckks.Evaluator
	kernel0Circuit          *GaoA2BKernelCircuit
	kernel1Circuit          *GaoA2BKernelCircuit
	kernel0CKKS             *ckks.Evaluator
	kernel1CKKS             *ckks.Evaluator
	kernel0Polynomial       *ckkspolynomial.Evaluator
	kernel1Polynomial       *ckkspolynomial.Evaluator
	kernel0PolyRuntime      ckkspolynomial.EvaluatorRuntimeIdentity
	kernel1PolyRuntime      ckkspolynomial.EvaluatorRuntimeIdentity
	kernel0Encoder          *ckks.Encoder
	kernel1Encoder          *ckks.Encoder
	kernel0Relin            *rlwe.RelinearizationKey
	kernel1Relin            *rlwe.RelinearizationKey
	kernel0Conjugation      *rlwe.GaloisKey
	kernel1Conjugation      *rlwe.GaloisKey
	kernelSource0Binding    signed8Depth2ChildCKKSEvaluatorBinding
	kernelSource1Binding    signed8Depth2ChildCKKSEvaluatorBinding
	kernel0CKKSBinding      signed8Depth2ChildCKKSEvaluatorBinding
	kernel1CKKSBinding      signed8Depth2ChildCKKSEvaluatorBinding
}

// signed8Depth2ChildSignEvaluatorBinding closes the same seam for the direct
// sign-fusion suffix, including the evaluator hidden below the linear layer.
type signed8Depth2ChildSignEvaluatorBinding struct {
	sign          *SignFusionEvaluator
	circuit       *SignFusionCircuit
	ckks          *ckks.Evaluator
	linear        *ckkslintrans.Evaluator
	linearSource  *ckks.Evaluator
	linearRuntime ckkslintrans.EvaluatorRuntimeIdentity
	keySet        *rlwe.MemEvaluationKeySet
	galois        map[uint64]*rlwe.GaloisKey
	ckksBinding   signed8Depth2ChildCKKSEvaluatorBinding
}

// Key bindings seal exact object identity, inventory and public runtime
// structure without serializing large coefficient payloads on every preflight.
// Same-pointer coefficient-value changes are outside this identity contract;
// nil, topology, level, element and NthRoot drift fail closed.
type signed8Depth2ChildGadgetKeyBinding struct {
	baseTwoDecomposition int
	degree               int
	levelQ               int
	levelP               int
	shape                [][]int
	coefficientShape     string
}

func captureSigned8Depth2ChildGadgetKeyBinding(
	label string,
	key *rlwe.GadgetCiphertext,
	parameters *rlwe.Parameters,
) (signed8Depth2ChildGadgetKeyBinding, error) {
	if key == nil || len(key.Value) == 0 || parameters == nil || parameters.N() <= 0 {
		return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key is nil or empty", label)
	}
	expectedN := parameters.N()
	shape := make([][]int, len(key.Value))
	var coefficientShape strings.Builder
	wantVectorSize := -1
	for rowIndex, row := range key.Value {
		if len(row) == 0 {
			return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key row %d is empty", label, rowIndex)
		}
		shape[rowIndex] = make([]int, len(row))
		for columnIndex, vector := range row {
			if len(vector) == 0 {
				return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key vector %d,%d is empty", label, rowIndex, columnIndex)
			}
			if wantVectorSize == -1 {
				wantVectorSize = len(vector)
			} else if len(vector) != wantVectorSize {
				return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key vector %d,%d has inconsistent degree", label, rowIndex, columnIndex)
			}
			shape[rowIndex][columnIndex] = len(vector)
			fmt.Fprintf(&coefficientShape, "|%d,%d=%d", rowIndex, columnIndex, len(vector))
			for polyIndex, poly := range vector {
				if len(poly.Q.Coeffs) == 0 {
					return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key Q polynomial %d,%d,%d is empty", label, rowIndex, columnIndex, polyIndex)
				}
				fmt.Fprintf(&coefficientShape, "/%d:q%d", polyIndex, len(poly.Q.Coeffs))
				for coefficientIndex, coefficients := range poly.Q.Coeffs {
					if len(coefficients) != expectedN {
						return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key Q coefficients %d,%d,%d,%d have length %d, want %d", label, rowIndex, columnIndex, polyIndex, coefficientIndex, len(coefficients), expectedN)
					}
					fmt.Fprintf(&coefficientShape, ",%d", len(coefficients))
				}
				fmt.Fprintf(&coefficientShape, ":p%d", len(poly.P.Coeffs))
				for coefficientIndex, coefficients := range poly.P.Coeffs {
					if len(coefficients) != expectedN {
						return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key P coefficients %d,%d,%d,%d have length %d, want %d", label, rowIndex, columnIndex, polyIndex, coefficientIndex, len(coefficients), expectedN)
					}
					fmt.Fprintf(&coefficientShape, ",%d", len(coefficients))
				}
			}
		}
	}
	levelQ, levelP := key.LevelQ(), key.LevelP()
	degree := key.Degree()
	if degree != 1 || key.BaseTwoDecomposition < 0 || levelQ < 0 || levelQ > parameters.MaxLevelQ() ||
		levelP < -1 || levelP > parameters.MaxLevelP() {
		return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key has invalid degree, decomposition, or levels", label)
	}
	wantRows := parameters.BaseRNSDecompositionVectorSize(levelQ, levelP)
	wantColumns := parameters.BaseTwoDecompositionVectorSize(levelQ, levelP, key.BaseTwoDecomposition)
	if len(key.Value) != wantRows || len(wantColumns) < wantRows {
		return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key has %d decomposition rows, want %d", label, len(key.Value), wantRows)
	}
	for rowIndex, row := range key.Value {
		if len(row) != wantColumns[rowIndex] {
			return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key row %d has %d decomposition columns, want %d", label, rowIndex, len(row), wantColumns[rowIndex])
		}
		for columnIndex, vector := range row {
			for polyIndex, poly := range vector {
				if poly.LevelQ() != levelQ || poly.LevelP() != levelP ||
					len(poly.Q.Coeffs) != levelQ+1 || len(poly.P.Coeffs) != levelP+1 {
					return signed8Depth2ChildGadgetKeyBinding{}, fmt.Errorf("homchain: %s gadget key polynomial %d,%d,%d levels differ", label, rowIndex, columnIndex, polyIndex)
				}
			}
		}
	}
	return signed8Depth2ChildGadgetKeyBinding{
		baseTwoDecomposition: key.BaseTwoDecomposition,
		degree:               degree,
		levelQ:               levelQ,
		levelP:               levelP,
		shape:                shape,
		coefficientShape:     coefficientShape.String(),
	}, nil
}

func (binding signed8Depth2ChildGadgetKeyBinding) equal(other signed8Depth2ChildGadgetKeyBinding) bool {
	return binding.baseTwoDecomposition == other.baseTwoDecomposition &&
		binding.degree == other.degree && binding.levelQ == other.levelQ && binding.levelP == other.levelP &&
		binding.coefficientShape == other.coefficientShape && reflect.DeepEqual(binding.shape, other.shape)
}

type signed8Depth2ChildRelinearizationKeyBinding struct {
	key    *rlwe.RelinearizationKey
	gadget signed8Depth2ChildGadgetKeyBinding
}

func captureSigned8Depth2ChildRelinearizationKeyBinding(
	key *rlwe.RelinearizationKey,
	parameters *rlwe.Parameters,
) (signed8Depth2ChildRelinearizationKeyBinding, error) {
	if key == nil {
		return signed8Depth2ChildRelinearizationKeyBinding{}, fmt.Errorf("homchain: nil depth2 child relinearization key")
	}
	gadget, err := captureSigned8Depth2ChildGadgetKeyBinding("depth2 child relinearization", &key.GadgetCiphertext, parameters)
	if err != nil {
		return signed8Depth2ChildRelinearizationKeyBinding{}, err
	}
	return signed8Depth2ChildRelinearizationKeyBinding{key: key, gadget: gadget}, nil
}

func (binding signed8Depth2ChildRelinearizationKeyBinding) validate(key *rlwe.RelinearizationKey, parameters *rlwe.Parameters) error {
	current, err := captureSigned8Depth2ChildRelinearizationKeyBinding(key, parameters)
	if err != nil || key != binding.key || !binding.gadget.equal(current.gadget) {
		return fmt.Errorf("homchain: depth2 child relinearization key identity or public structure changed: %v", err)
	}
	return nil
}

type signed8Depth2ChildGaloisKeyBinding struct {
	key     *rlwe.GaloisKey
	element uint64
	nthRoot uint64
	gadget  signed8Depth2ChildGadgetKeyBinding
}

func captureSigned8Depth2ChildGaloisKeyBinding(
	key *rlwe.GaloisKey,
	parameters *rlwe.Parameters,
) (signed8Depth2ChildGaloisKeyBinding, error) {
	if key == nil {
		return signed8Depth2ChildGaloisKeyBinding{}, fmt.Errorf("homchain: nil depth2 child Galois key")
	}
	gadget, err := captureSigned8Depth2ChildGadgetKeyBinding("depth2 child Galois", &key.GadgetCiphertext, parameters)
	if err != nil {
		return signed8Depth2ChildGaloisKeyBinding{}, err
	}
	return signed8Depth2ChildGaloisKeyBinding{
		key: key, element: key.GaloisElement, nthRoot: key.NthRoot, gadget: gadget,
	}, nil
}

func (binding signed8Depth2ChildGaloisKeyBinding) validate(key *rlwe.GaloisKey, parameters *rlwe.Parameters) error {
	current, err := captureSigned8Depth2ChildGaloisKeyBinding(key, parameters)
	if err != nil || key != binding.key || current.element != binding.element || current.nthRoot != binding.nthRoot ||
		!binding.gadget.equal(current.gadget) {
		return fmt.Errorf("homchain: depth2 child Galois key identity or public structure changed: %v", err)
	}
	return nil
}

func captureSigned8Depth2ChildCKKSEvaluatorBinding(
	evaluator *ckks.Evaluator,
	wantKeySet rlwe.EvaluationKeySet,
	galoisElements []uint64,
) (signed8Depth2ChildCKKSEvaluatorBinding, error) {
	if evaluator == nil || evaluator.Evaluator == nil {
		return signed8Depth2ChildCKKSEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal incomplete depth2 child CKKS evaluator")
	}
	// The first snapshot is a nil-safe completeness gate. Required rotation
	// indexes are then primed before the binding snapshot is taken so ordinary
	// lazy cache population cannot invalidate an accepted evaluator later.
	if _, err := evaluator.RuntimeIdentitySnapshot(); err != nil {
		return signed8Depth2ChildCKKSEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child CKKS evaluator runtime: %w", err)
	}
	if wantKeySet != nil && evaluator.Evaluator.EvaluationKeySet != wantKeySet {
		return signed8Depth2ChildCKKSEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child CKKS evaluator with foreign key set")
	}
	for _, element := range galoisElements {
		key, err := evaluator.Evaluator.CheckAndGetGaloisKey(element)
		if err != nil || key == nil || key.GaloisElement != element {
			return signed8Depth2ChildCKKSEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child automorphism index %d: %v", element, err)
		}
	}
	runtime, err := evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildCKKSEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child CKKS evaluator runtime: %w", err)
	}
	encoder, err := evaluator.Encoder.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildCKKSEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child encoder runtime: %w", err)
	}
	rlweBuffers, err := evaluator.Evaluator.EvaluatorBuffers.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildCKKSEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child RLWE buffer runtime: %w", err)
	}
	rlweEvaluator, err := evaluator.Evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildCKKSEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child RLWE evaluator runtime: %w", err)
	}
	return signed8Depth2ChildCKKSEvaluatorBinding{
		evaluator: evaluator, keySet: evaluator.Evaluator.EvaluationKeySet, runtime: runtime,
		encoder: encoder, rlweBuffers: rlweBuffers, rlweEvaluator: rlweEvaluator,
	}, nil
}

func (b signed8Depth2ChildCKKSEvaluatorBinding) validate(
	evaluator *ckks.Evaluator,
	wantKeySet rlwe.EvaluationKeySet,
) error {
	if evaluator == nil || b.evaluator == nil || b.keySet == nil {
		return fmt.Errorf("homchain: depth2 child CKKS evaluator graph is incomplete")
	}
	runtime, err := evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return fmt.Errorf("homchain: depth2 child CKKS evaluator runtime is incomplete: %w", err)
	}
	if evaluator != b.evaluator || evaluator.Evaluator.EvaluationKeySet != b.keySet ||
		(wantKeySet != nil && evaluator.Evaluator.EvaluationKeySet != wantKeySet) {
		return fmt.Errorf("homchain: depth2 child CKKS evaluator runtime identity changed")
	}
	if !b.runtime.Equal(runtime) {
		encoder, encoderErr := evaluator.Encoder.RuntimeIdentitySnapshot()
		if encoderErr != nil || !b.encoder.Equal(encoder) {
			return fmt.Errorf("homchain: depth2 child CKKS encoder runtime identity changed: %v", encoderErr)
		}
		buffers, buffersErr := evaluator.Evaluator.EvaluatorBuffers.RuntimeIdentitySnapshot()
		if buffersErr != nil || !b.rlweBuffers.Equal(buffers) {
			return fmt.Errorf("homchain: depth2 child RLWE buffer runtime identity changed: %v", buffersErr)
		}
		rlweEvaluator, rlweErr := evaluator.Evaluator.RuntimeIdentitySnapshot()
		if rlweErr != nil || !b.rlweEvaluator.Equal(rlweEvaluator) {
			return fmt.Errorf("homchain: depth2 child RLWE evaluator configuration or automorphism index changed: %v", rlweErr)
		}
		return fmt.Errorf("homchain: depth2 child CKKS private evaluator buffer topology changed")
	}
	return nil
}

func signed8Depth2ChildBigFloatPayload(value interface{ GobEncode() ([]byte, error) }) (string, error) {
	payload, err := value.GobEncode()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%s", len(payload), sha256Hex(payload)), nil
}

func signed8Depth2ChildDFTLiteralDigest(literal ckksdft.MatrixLiteral) (string, error) {
	scaling := "nil"
	var err error
	if literal.Scaling != nil {
		if scaling, err = signed8Depth2ChildBigFloatPayload(literal.Scaling); err != nil {
			return "", err
		}
	}
	return digestString(fmt.Sprintf("type=%d|slots=%d|q=%d|p=%d|levels=%v|format=%d|scaling=%s|reversed=%t|bsgs=%d",
		literal.Type, literal.LogSlots, literal.LevelQ, literal.LevelP, literal.Levels, literal.Format,
		scaling, literal.BitReversed, literal.LogBSGSRatio)), nil
}

func signed8Depth2ChildMod1PolynomialDigest(label string, polynomial interface {
	Degree() int
}) string {
	// This helper only provides the scalar header; coefficient payloads are
	// appended by signed8Depth2ChildMod1ParametersDigest below.
	return fmt.Sprintf("%s:degree=%d", label, polynomial.Degree())
}

func signed8Depth2ChildMod1ParametersDigest(label string, parameters mod1.Parameters) (string, error) {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s|q=%d|scale=%d|type=%d|ratio=%d|double=%d|qdiff=%016x|sqrt=%016x|k=%016x",
		label, parameters.LevelQ, parameters.LogDefaultScale, parameters.Mod1Type, parameters.LogMessageRatio,
		parameters.DoubleAngle, math.Float64bits(parameters.QDiff), math.Float64bits(parameters.Sqrt2Pi), math.Float64bits(parameters.K))
	appendPolynomial := func(name string, polynomial *bignum.Polynomial) error {
		if polynomial == nil {
			fmt.Fprintf(&builder, "|%s=nil", name)
			return nil
		}
		a, err := signed8Depth2ChildBigFloatPayload(&polynomial.A)
		if err != nil {
			return err
		}
		b, err := signed8Depth2ChildBigFloatPayload(&polynomial.B)
		if err != nil {
			return err
		}
		fmt.Fprintf(&builder, "|%s=basis:%d/nodes:%d/a:%s/b:%s/odd:%t/even:%t/coeffs:%d",
			name, polynomial.Basis, polynomial.Nodes, a, b, polynomial.IsOdd, polynomial.IsEven, len(polynomial.Coeffs))
		for index, coefficient := range polynomial.Coeffs {
			if coefficient == nil {
				fmt.Fprintf(&builder, "/%d:nil", index)
				continue
			}
			for component := 0; component < 2; component++ {
				if coefficient[component] == nil {
					fmt.Fprintf(&builder, "/%d.%d:nil", index, component)
					continue
				}
				payload, payloadErr := signed8Depth2ChildBigFloatPayload(coefficient[component])
				if payloadErr != nil {
					return payloadErr
				}
				fmt.Fprintf(&builder, "/%d.%d:%s", index, component, payload)
			}
		}
		return nil
	}
	if err := appendPolynomial("mod1", &parameters.Mod1Poly); err != nil {
		return "", err
	}
	if err := appendPolynomial("inverse", parameters.Mod1InvPoly); err != nil {
		return "", err
	}
	return digestString(builder.String()), nil
}

func signed8Depth2ChildDeriveMod1Parameters(
	parameters ckks.Parameters,
	literal mod1.ParametersLiteral,
) (derived mod1.Parameters, err error) {
	if len(parameters.Q()) == 0 {
		return mod1.Parameters{}, fmt.Errorf("homchain: depth2 child bootstrap parameters have no Q moduli")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			derived = mod1.Parameters{}
			err = fmt.Errorf("homchain: derive depth2 child bootstrap Mod1 execution parameters: %v", recovered)
		}
	}()
	return mod1.NewParametersFromLiteral(parameters, literal)
}

func signed8Depth2ChildBootstrapParameterDigests(source *bootstrapping.Evaluator) (parameters, execution string, err error) {
	if source == nil {
		return "", "", fmt.Errorf("homchain: nil depth2 child bootstrap parameter source")
	}
	canonical, err := source.Parameters.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	residual, err := source.ResidualParameters.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	bootstrap, err := source.BootstrappingParameters.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	stc, err := signed8Depth2ChildDFTLiteralDigest(source.SlotsToCoeffsParameters)
	if err != nil {
		return "", "", err
	}
	cts, err := signed8Depth2ChildDFTLiteralDigest(source.CoeffsToSlotsParameters)
	if err != nil {
		return "", "", err
	}
	parameters = digestString(fmt.Sprintf("canonical=%s|residual=%s|bootstrap=%s|stc=%s|cts=%s|mod1=%+v|order=%d|ephemeral=%d",
		sha256Hex(canonical), sha256Hex(residual), sha256Hex(bootstrap), stc, cts,
		source.Mod1ParametersLiteral, source.CircuitOrder, source.EphemeralSecretWeight))
	execution, err = signed8Depth2ChildMod1ParametersDigest("bootstrap-mod1-execution", source.Mod1Parameters)
	if err != nil {
		return "", "", err
	}
	derived, err := signed8Depth2ChildDeriveMod1Parameters(source.BootstrappingParameters, source.Mod1ParametersLiteral)
	if err != nil {
		return "", "", fmt.Errorf("homchain: derive depth2 child bootstrap Mod1 execution parameters: %w", err)
	}
	derivedExecution, err := signed8Depth2ChildMod1ParametersDigest("bootstrap-mod1-execution", derived)
	if err != nil {
		return "", "", err
	}
	if execution != derivedExecution {
		return "", "", fmt.Errorf("homchain: depth2 child bootstrap Mod1 execution parameters differ from their literal")
	}
	return parameters, execution, nil
}

func cloneSigned8Depth2ChildGaloisBindings(source map[uint64]*rlwe.GaloisKey) map[uint64]*rlwe.GaloisKey {
	result := make(map[uint64]*rlwe.GaloisKey, len(source))
	for element, key := range source {
		result[element] = key
	}
	return result
}

func captureSigned8Depth2ChildIngressEvaluatorBinding(
	circuit *Signed8Depth2ChildComparatorCircuit,
	ingress *A2BFullIngress6Evaluator,
	source *bootstrapping.Evaluator,
	keySet *rlwe.MemEvaluationKeySet,
) (signed8Depth2ChildIngressEvaluatorBinding, error) {
	if circuit == nil || circuit.ingress == nil || circuit.ingress.suffix == nil || ingress == nil ||
		ingress.circuit == nil || ingress.suffix == nil || source == nil || source.Evaluator == nil ||
		source.EvaluationKeys == nil || source.MemEvaluationKeySet == nil || keySet == nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal incomplete depth2 child ingress evaluator graph")
	}
	suffix := ingress.suffix
	if suffix.circuit == nil || suffix.source == nil || suffix.source.Evaluator == nil || suffix.keySet == nil ||
		suffix.relinearizationKey == nil || suffix.refresh == nil || suffix.refresh.circuit == nil ||
		suffix.refresh.bootstrap == nil || suffix.refresh.bootstrap.Evaluator == nil ||
		suffix.refresh.bootstrap.EvaluationKeys == nil || suffix.refresh.bootstrap.MemEvaluationKeySet == nil ||
		suffix.refresh.bootstrap.DFTEvaluator == nil || suffix.refresh.bootstrap.DFTEvaluator.LTEvaluator == nil ||
		suffix.refresh.bootstrap.Mod1Evaluator == nil || suffix.refresh.bootstrap.Mod1Evaluator.PolynomialEvaluator == nil ||
		suffix.refresh.triangle == nil || suffix.refresh.triangle.ckks == nil || suffix.refresh.triangle.linear == nil ||
		suffix.kernel0 == nil || suffix.kernel1 == nil || suffix.kernelSource0 == nil || suffix.kernelSource1 == nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal incomplete depth2 child suffix evaluator graph")
	}
	elements := circuit.keyProfile.All()
	suffixSourceBinding, err := captureSigned8Depth2ChildCKKSEvaluatorBinding(suffix.source.Evaluator, suffix.source.EvaluationKeys, elements)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	refreshBinding, err := captureSigned8Depth2ChildCKKSEvaluatorBinding(suffix.refresh.bootstrap.Evaluator, suffix.refresh.bootstrap.EvaluationKeys, elements)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	triangleBinding, err := captureSigned8Depth2ChildCKKSEvaluatorBinding(suffix.refresh.triangle.ckks, suffix.refresh.bootstrap.EvaluationKeys, elements)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	triangleLinearSource, ok := suffix.refresh.triangle.linear.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || triangleLinearSource != suffix.refresh.triangle.ckks ||
		suffix.refresh.triangle.ckks != suffix.refresh.bootstrap.Evaluator {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child refresh triangle binding")
	}
	if suffix.refresh.bootstrap.DFTEvaluator.Evaluator != suffix.refresh.bootstrap.Evaluator {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child refresh DFT binding")
	}
	dftLinearSource, ok := suffix.refresh.bootstrap.DFTEvaluator.LTEvaluator.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || dftLinearSource != suffix.refresh.bootstrap.Evaluator {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child refresh DFT linear binding")
	}
	sourceParameters, sourceExecution, err := signed8Depth2ChildBootstrapParameterDigests(source)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	refreshParameters, refreshExecution, err := signed8Depth2ChildBootstrapParameterDigests(suffix.refresh.bootstrap)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	_, s2cPayload, err := digestA2BFullIngress6EncodedFactorGroup("first-stc", suffix.refresh.bootstrap.S2CDFTMatrix.Matrices)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	_, c2sPayload, err := digestA2BFullIngress6EncodedFactorGroup("shared-cts", suffix.refresh.bootstrap.C2SDFTMatrix.Matrices)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	triangleRuntime, err := suffix.refresh.triangle.linear.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child refresh triangle linear evaluator: %w", err)
	}
	dftRuntime, err := suffix.refresh.bootstrap.DFTEvaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child refresh DFT evaluator: %w", err)
	}
	dftLinearRuntime, err := suffix.refresh.bootstrap.DFTEvaluator.LTEvaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child refresh DFT linear evaluator: %w", err)
	}
	mod1PolynomialRuntime, err := suffix.refresh.bootstrap.Mod1Evaluator.PolynomialEvaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child refresh Mod1 polynomial evaluator: %w", err)
	}
	kernelSource0Binding, err := captureSigned8Depth2ChildCKKSEvaluatorBinding(suffix.kernelSource0, keySet, elements)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	kernelSource1Binding, err := captureSigned8Depth2ChildCKKSEvaluatorBinding(suffix.kernelSource1, keySet, elements)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	for index, kernel := range []*GaoA2BKernelEvaluator{suffix.kernel0, suffix.kernel1} {
		if kernel.circuit == nil || kernel.source == nil || kernel.ckks == nil || kernel.polynomial == nil ||
			kernel.keySet == nil || kernel.relinearizationKey == nil || kernel.conjugationKey == nil ||
			kernel.operationalEncoder == nil {
			return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal incomplete depth2 child kernel %d graph", index)
		}
		bound, ok := kernel.polynomial.Evaluator.Evaluator.(*ckks.Evaluator)
		if !ok || bound != kernel.ckks {
			return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child kernel %d polynomial binding", index)
		}
	}
	kernel0Binding, err := captureSigned8Depth2ChildCKKSEvaluatorBinding(suffix.kernel0.ckks, keySet, elements)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	kernel1Binding, err := captureSigned8Depth2ChildCKKSEvaluatorBinding(suffix.kernel1.ckks, keySet, elements)
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, err
	}
	kernel0PolynomialRuntime, err := suffix.kernel0.polynomial.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child kernel 0 polynomial evaluator: %w", err)
	}
	kernel1PolynomialRuntime, err := suffix.kernel1.polynomial.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildIngressEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child kernel 1 polynomial evaluator: %w", err)
	}
	return signed8Depth2ChildIngressEvaluatorBinding{
		ingress: ingress, ingressCircuit: ingress.circuit,
		suffix: suffix, suffixCircuit: suffix.circuit, suffixSource: suffix.source,
		suffixSourceCKKS: suffix.source.Evaluator, suffixEvaluationKeys: suffix.source.EvaluationKeys,
		suffixSourceBinding: suffixSourceBinding, suffixKeySet: suffix.keySet,
		suffixRelin: suffix.relinearizationKey, suffixGalois: cloneSigned8Depth2ChildGaloisBindings(suffix.galoisKeys),
		refresh: suffix.refresh, refreshCircuit: suffix.refresh.circuit,
		refreshBootstrap: suffix.refresh.bootstrap, refreshBootstrapCKKS: suffix.refresh.bootstrap.Evaluator,
		refreshCKKSBinding: refreshBinding, refreshTriangle: suffix.refresh.triangle,
		refreshTriangleCKKS: suffix.refresh.triangle.ckks, refreshTriangleLinear: suffix.refresh.triangle.linear,
		refreshTriangleBinding: triangleBinding, refreshTriangleRuntime: triangleRuntime,
		refreshDFT: suffix.refresh.bootstrap.DFTEvaluator, refreshDFTRuntime: dftRuntime,
		refreshDFTLinear:        suffix.refresh.bootstrap.DFTEvaluator.LTEvaluator,
		refreshDFTLinearRuntime: dftLinearRuntime,
		refreshMod1:             suffix.refresh.bootstrap.Mod1Evaluator,
		refreshMod1Polynomial:   suffix.refresh.bootstrap.Mod1Evaluator.PolynomialEvaluator,
		refreshMod1PolyRuntime:  mod1PolynomialRuntime,
		refreshEvaluationKeys:   suffix.refresh.bootstrap.EvaluationKeys,
		sourceParameters:        sourceParameters, sourceMod1Execution: sourceExecution,
		refreshParameters: refreshParameters, refreshMod1Execution: refreshExecution,
		refreshS2CPayload: s2cPayload, refreshC2SPayload: c2sPayload,
		kernel0: suffix.kernel0, kernel1: suffix.kernel1,
		kernelSource0: suffix.kernelSource0, kernelSource1: suffix.kernelSource1,
		kernel0Circuit: suffix.kernel0.circuit, kernel1Circuit: suffix.kernel1.circuit,
		kernel0CKKS: suffix.kernel0.ckks, kernel1CKKS: suffix.kernel1.ckks,
		kernel0Polynomial: suffix.kernel0.polynomial, kernel1Polynomial: suffix.kernel1.polynomial,
		kernel0PolyRuntime: kernel0PolynomialRuntime, kernel1PolyRuntime: kernel1PolynomialRuntime,
		kernel0Encoder: suffix.kernel0.operationalEncoder, kernel1Encoder: suffix.kernel1.operationalEncoder,
		kernel0Relin: suffix.kernel0.relinearizationKey, kernel1Relin: suffix.kernel1.relinearizationKey,
		kernel0Conjugation: suffix.kernel0.conjugationKey, kernel1Conjugation: suffix.kernel1.conjugationKey,
		kernelSource0Binding: kernelSource0Binding, kernelSource1Binding: kernelSource1Binding,
		kernel0CKKSBinding: kernel0Binding, kernel1CKKSBinding: kernel1Binding,
	}, nil
}

func captureSigned8Depth2ChildSignEvaluatorBinding(
	circuit *Signed8Depth2ChildComparatorCircuit,
	sign *SignFusionEvaluator,
	source *ckks.Evaluator,
	keySet *rlwe.MemEvaluationKeySet,
) (signed8Depth2ChildSignEvaluatorBinding, error) {
	if circuit == nil || circuit.sign == nil || sign == nil || sign.circuit == nil || sign.ckks == nil ||
		sign.linear == nil || sign.keySet == nil || source == nil || keySet == nil {
		return signed8Depth2ChildSignEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal incomplete depth2 child sign evaluator graph")
	}
	linearSource, ok := sign.linear.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || linearSource == nil {
		return signed8Depth2ChildSignEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child sign linear evaluator binding")
	}
	ckksBinding, err := captureSigned8Depth2ChildCKKSEvaluatorBinding(source, keySet, circuit.keyProfile.All())
	if err != nil {
		return signed8Depth2ChildSignEvaluatorBinding{}, err
	}
	linearRuntime, err := sign.linear.RuntimeIdentitySnapshot()
	if err != nil {
		return signed8Depth2ChildSignEvaluatorBinding{}, fmt.Errorf("homchain: cannot seal depth2 child sign linear evaluator: %w", err)
	}
	return signed8Depth2ChildSignEvaluatorBinding{
		sign: sign, circuit: sign.circuit, ckks: sign.ckks, linear: sign.linear,
		linearSource: linearSource, linearRuntime: linearRuntime, keySet: sign.keySet,
		galois:      cloneSigned8Depth2ChildGaloisBindings(sign.galoisKeys),
		ckksBinding: ckksBinding,
	}, nil
}

func validateSigned8Depth2ChildGaloisBindings(
	actual, sealed map[uint64]*rlwe.GaloisKey,
	keySet *rlwe.MemEvaluationKeySet,
) error {
	if actual == nil || sealed == nil || keySet == nil || len(actual) != len(sealed) {
		return fmt.Errorf("homchain: depth2 child nested Galois inventory changed")
	}
	for element, expected := range sealed {
		current, ok := actual[element]
		fromSet, err := keySet.GetGaloisKey(element)
		if !ok || current == nil || current != expected || err != nil || fromSet != current ||
			current.GaloisElement != element {
			return fmt.Errorf("homchain: depth2 child nested Galois key %d identity changed", element)
		}
	}
	return nil
}

func (b signed8Depth2ChildIngressEvaluatorBinding) validate(
	circuit *Signed8Depth2ChildComparatorCircuit,
	ingress *A2BFullIngress6Evaluator,
	source *bootstrapping.Evaluator,
	keySet *rlwe.MemEvaluationKeySet,
) error {
	if circuit == nil || circuit.ingress == nil || circuit.ingress.suffix == nil || ingress == nil ||
		ingress.circuit == nil || ingress.suffix == nil || source == nil || source.Evaluator == nil ||
		source.EvaluationKeys == nil || source.MemEvaluationKeySet == nil || keySet == nil ||
		b.ingress == nil || b.ingressCircuit == nil || b.suffix == nil || b.suffixCircuit == nil ||
		b.suffixSource == nil || b.refreshBootstrap == nil ||
		b.suffix.source == nil || b.suffix.source.Evaluator == nil || b.suffix.source.EvaluationKeys == nil ||
		b.suffix.keySet == nil || b.suffix.relinearizationKey == nil || b.refresh == nil || b.refresh.circuit == nil ||
		b.refresh.bootstrap == nil || b.refresh.bootstrap.Evaluator == nil || b.refresh.bootstrap.EvaluationKeys == nil ||
		b.refresh.bootstrap.MemEvaluationKeySet == nil || b.refresh.bootstrap.DFTEvaluator == nil ||
		b.refresh.bootstrap.DFTEvaluator.LTEvaluator == nil || b.refresh.bootstrap.Mod1Evaluator == nil ||
		b.refresh.bootstrap.Mod1Evaluator.PolynomialEvaluator == nil || b.refresh.triangle == nil ||
		b.refresh.triangle.ckks == nil || b.refresh.triangle.linear == nil ||
		b.kernel0 == nil || b.kernel1 == nil || b.kernelSource0 == nil || b.kernelSource1 == nil ||
		b.kernel0.circuit == nil || b.kernel1.circuit == nil || b.kernel0.ckks == nil || b.kernel1.ckks == nil ||
		b.kernel0.polynomial == nil || b.kernel1.polynomial == nil || b.kernel0.operationalEncoder == nil ||
		b.kernel1.operationalEncoder == nil || b.kernel0.keySet == nil || b.kernel1.keySet == nil {
		return fmt.Errorf("homchain: depth2 child ingress evaluator binding is incomplete")
	}
	if err := b.suffixSourceBinding.validate(b.suffixSourceCKKS, b.suffixSource.EvaluationKeys); err != nil {
		return fmt.Errorf("homchain: depth2 child suffix source evaluator: %w", err)
	}
	if err := b.refreshCKKSBinding.validate(b.refreshBootstrapCKKS, b.refreshBootstrap.EvaluationKeys); err != nil {
		return fmt.Errorf("homchain: depth2 child refresh evaluator: %w", err)
	}
	if err := b.refreshTriangleBinding.validate(b.refreshTriangleCKKS, b.refreshBootstrap.EvaluationKeys); err != nil {
		return fmt.Errorf("homchain: depth2 child refresh triangle evaluator: %w", err)
	}
	if err := b.kernelSource0Binding.validate(b.kernelSource0, keySet); err != nil {
		return fmt.Errorf("homchain: depth2 child kernel source 0 evaluator: %w", err)
	}
	if err := b.kernelSource1Binding.validate(b.kernelSource1, keySet); err != nil {
		return fmt.Errorf("homchain: depth2 child kernel source 1 evaluator: %w", err)
	}
	if err := b.kernel0CKKSBinding.validate(b.kernel0CKKS, keySet); err != nil {
		return fmt.Errorf("homchain: depth2 child kernel 0 evaluator: %w", err)
	}
	if err := b.kernel1CKKSBinding.validate(b.kernel1CKKS, keySet); err != nil {
		return fmt.Errorf("homchain: depth2 child kernel 1 evaluator: %w", err)
	}
	triangleRuntime, err := b.refreshTriangleLinear.RuntimeIdentitySnapshot()
	if err != nil || !b.refreshTriangleRuntime.Equal(triangleRuntime) {
		return fmt.Errorf("homchain: depth2 child refresh triangle linear evaluator runtime changed: %v", err)
	}
	dftRuntime, err := b.refreshDFT.RuntimeIdentitySnapshot()
	if err != nil || !b.refreshDFTRuntime.Equal(dftRuntime) {
		return fmt.Errorf("homchain: depth2 child refresh DFT evaluator runtime changed: %v", err)
	}
	dftLinearRuntime, err := b.refreshDFTLinear.RuntimeIdentitySnapshot()
	if err != nil || !b.refreshDFTLinearRuntime.Equal(dftLinearRuntime) {
		return fmt.Errorf("homchain: depth2 child refresh DFT linear evaluator runtime changed: %v", err)
	}
	mod1PolynomialRuntime, err := b.refreshMod1Polynomial.RuntimeIdentitySnapshot()
	if err != nil || !b.refreshMod1PolyRuntime.Equal(mod1PolynomialRuntime) {
		return fmt.Errorf("homchain: depth2 child refresh Mod1 polynomial evaluator runtime changed: %v", err)
	}
	kernel0PolynomialRuntime, err := b.kernel0Polynomial.RuntimeIdentitySnapshot()
	if err != nil || !b.kernel0PolyRuntime.Equal(kernel0PolynomialRuntime) {
		return fmt.Errorf("homchain: depth2 child kernel 0 polynomial evaluator runtime changed: %v", err)
	}
	kernel1PolynomialRuntime, err := b.kernel1Polynomial.RuntimeIdentitySnapshot()
	if err != nil || !b.kernel1PolyRuntime.Equal(kernel1PolynomialRuntime) {
		return fmt.Errorf("homchain: depth2 child kernel 1 polynomial evaluator runtime changed: %v", err)
	}
	if ingress != b.ingress || ingress.circuit != circuit.ingress || ingress.circuit != b.ingressCircuit ||
		ingress.suffix != b.suffix || b.suffix.circuit != circuit.ingress.suffix ||
		b.suffixCircuit != circuit.ingress.suffix || b.suffix.source != source || b.suffix.source != b.suffixSource ||
		b.suffix.source.Evaluator != b.suffixSourceCKKS || b.suffix.source.EvaluationKeys != b.suffixEvaluationKeys ||
		b.suffix.source.MemEvaluationKeySet != keySet || source.MemEvaluationKeySet != keySet ||
		b.suffix.keySet != keySet || b.suffix.keySet != b.suffixKeySet ||
		b.suffix.relinearizationKey != b.suffixRelin {
		return fmt.Errorf("homchain: depth2 child ingress/suffix evaluator identity changed")
	}
	if b.suffix.refresh != b.refresh || b.refresh.circuit != circuit.ingress.suffix.refresh ||
		b.refresh.circuit != b.refreshCircuit || b.refresh.bootstrap != b.refreshBootstrap ||
		b.refresh.bootstrap.Evaluator != b.refreshBootstrapCKKS ||
		b.refresh.bootstrap.EvaluationKeys != b.refreshEvaluationKeys ||
		b.refresh.bootstrap.MemEvaluationKeySet != keySet || b.refresh.triangle != b.refreshTriangle ||
		b.refresh.triangle.ckks != b.refreshTriangleCKKS || b.refresh.triangle.ckks != b.refreshBootstrapCKKS ||
		b.refresh.triangle.linear != b.refreshTriangleLinear ||
		b.refresh.bootstrap.DFTEvaluator != b.refreshDFT ||
		b.refresh.bootstrap.DFTEvaluator.LTEvaluator != b.refreshDFTLinear ||
		b.refresh.bootstrap.Mod1Evaluator != b.refreshMod1 ||
		b.refresh.bootstrap.Mod1Evaluator.PolynomialEvaluator != b.refreshMod1Polynomial {
		return fmt.Errorf("homchain: depth2 child refresh evaluator identity changed")
	}
	triangleLinearSource, triangleOK := b.refresh.triangle.linear.Evaluator.Evaluator.(*ckks.Evaluator)
	dftLinearSource, dftOK := b.refresh.bootstrap.DFTEvaluator.LTEvaluator.Evaluator.Evaluator.(*ckks.Evaluator)
	if !triangleOK || !dftOK || triangleLinearSource != b.refreshTriangleCKKS ||
		b.refresh.bootstrap.DFTEvaluator.Evaluator != b.refreshBootstrapCKKS ||
		dftLinearSource != b.refreshBootstrapCKKS {
		return fmt.Errorf("homchain: depth2 child refresh linear/DFT evaluator binding changed")
	}
	sourceParameters, sourceExecution, err := signed8Depth2ChildBootstrapParameterDigests(source)
	if err != nil || sourceParameters != b.sourceParameters || sourceExecution != b.sourceMod1Execution {
		return fmt.Errorf("homchain: depth2 child ingress bootstrap parameters changed")
	}
	refreshParameters, refreshExecution, err := signed8Depth2ChildBootstrapParameterDigests(b.refresh.bootstrap)
	if err != nil || refreshParameters != b.refreshParameters || refreshExecution != b.refreshMod1Execution {
		return fmt.Errorf("homchain: depth2 child refresh bootstrap parameters changed")
	}
	_, s2cPayload, err := digestA2BFullIngress6EncodedFactorGroup("first-stc", b.refresh.bootstrap.S2CDFTMatrix.Matrices)
	if err != nil || s2cPayload != b.refreshS2CPayload {
		return fmt.Errorf("homchain: depth2 child refresh S2C payload changed")
	}
	_, c2sPayload, err := digestA2BFullIngress6EncodedFactorGroup("shared-cts", b.refresh.bootstrap.C2SDFTMatrix.Matrices)
	if err != nil || c2sPayload != b.refreshC2SPayload {
		return fmt.Errorf("homchain: depth2 child refresh C2S payload changed")
	}
	if b.suffix.kernel0 != b.kernel0 || b.suffix.kernel1 != b.kernel1 || b.kernel0 == b.kernel1 ||
		b.suffix.kernelSource0 != b.kernelSource0 || b.suffix.kernelSource1 != b.kernelSource1 ||
		b.kernelSource0 == b.kernelSource1 || b.kernelSource0.EvaluationKeySet != keySet ||
		b.kernelSource1.EvaluationKeySet != keySet ||
		b.kernel0.circuit != circuit.ingress.suffix.kernel0 || b.kernel0.circuit != b.kernel0Circuit ||
		b.kernel1.circuit != circuit.ingress.suffix.kernel1 || b.kernel1.circuit != b.kernel1Circuit ||
		b.kernel0.source != b.kernelSource0 || b.kernel1.source != b.kernelSource1 ||
		b.kernel0.ckks != b.kernel0CKKS || b.kernel1.ckks != b.kernel1CKKS ||
		b.kernel0.ckks.EvaluationKeySet != keySet || b.kernel1.ckks.EvaluationKeySet != keySet ||
		b.kernel0.polynomial != b.kernel0Polynomial || b.kernel1.polynomial != b.kernel1Polynomial ||
		b.kernel0.operationalEncoder != b.kernel0Encoder || b.kernel1.operationalEncoder != b.kernel1Encoder ||
		b.kernel0.keySet != keySet || b.kernel1.keySet != keySet ||
		b.kernel0.relinearizationKey != b.kernel0Relin || b.kernel1.relinearizationKey != b.kernel1Relin ||
		b.kernel0.conjugationKey != b.kernel0Conjugation || b.kernel1.conjugationKey != b.kernel1Conjugation {
		return fmt.Errorf("homchain: depth2 child kernel evaluator identity changed")
	}
	bound0, ok0 := b.kernel0.polynomial.Evaluator.Evaluator.(*ckks.Evaluator)
	bound1, ok1 := b.kernel1.polynomial.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok0 || !ok1 || bound0 != b.kernel0CKKS || bound1 != b.kernel1CKKS {
		return fmt.Errorf("homchain: depth2 child kernel polynomial evaluator binding changed")
	}
	if err := validateSigned8Depth2ChildGaloisBindings(b.suffix.galoisKeys, b.suffixGalois, keySet); err != nil {
		return err
	}
	currentRelin, err := keySet.GetRelinearizationKey()
	if err != nil || currentRelin != b.suffixRelin || currentRelin != b.kernel0Relin || currentRelin != b.kernel1Relin {
		return fmt.Errorf("homchain: depth2 child nested relinearization key identity changed")
	}
	return nil
}

func (b signed8Depth2ChildSignEvaluatorBinding) validate(
	circuit *Signed8Depth2ChildComparatorCircuit,
	sign *SignFusionEvaluator,
	source *ckks.Evaluator,
	keySet *rlwe.MemEvaluationKeySet,
) error {
	if circuit == nil || circuit.sign == nil || sign == nil || source == nil || source.Encoder == nil ||
		source.Evaluator == nil || keySet == nil || b.sign == nil || b.circuit == nil || b.ckks == nil ||
		b.linear == nil || b.linearSource == nil || b.keySet == nil || sign.circuit == nil ||
		sign.ckks == nil || sign.linear == nil || sign.keySet == nil {
		return fmt.Errorf("homchain: depth2 child sign evaluator binding is incomplete")
	}
	if err := b.ckksBinding.validate(source, keySet); err != nil {
		return fmt.Errorf("homchain: depth2 child sign source evaluator: %w", err)
	}
	linearRuntime, err := sign.linear.RuntimeIdentitySnapshot()
	if err != nil || !b.linearRuntime.Equal(linearRuntime) {
		return fmt.Errorf("homchain: depth2 child sign linear evaluator runtime changed: %v", err)
	}
	linearSource, ok := sign.linear.Evaluator.Evaluator.(*ckks.Evaluator)
	if !ok || linearSource == nil || sign != b.sign || sign.circuit != circuit.sign || sign.circuit != b.circuit ||
		sign.ckks != source || sign.ckks != b.ckks || sign.linear != b.linear ||
		linearSource != source || linearSource != b.linearSource || sign.keySet != keySet || sign.keySet != b.keySet ||
		sign.ckks.EvaluationKeySet != keySet {
		return fmt.Errorf("homchain: depth2 child sign evaluator identity changed")
	}
	if err := validateSigned8Depth2ChildGaloisBindings(sign.galoisKeys, b.galois, keySet); err != nil {
		return err
	}
	return nil
}

// Signed8Depth2ChildComparatorEvaluator binds the wrapper to the caller's
// exact required key identities. Nested ingress receives an isolated view of
// those required keys so unrelated valid caller keys remain out of its exact
// stopped-slice inventory.
type Signed8Depth2ChildComparatorEvaluator struct {
	circuit            *Signed8Depth2ChildComparatorCircuit
	source             *bootstrapping.Evaluator
	sourceCKKS         *ckks.Evaluator
	sourceKeySet       *rlwe.MemEvaluationKeySet
	prefix             *Signed8Depth2SourcePrefixEvaluator
	ingressSource      *bootstrapping.Evaluator
	ingressKeySet      *rlwe.MemEvaluationKeySet
	ingress            *A2BFullIngress6Evaluator
	signSource         *ckks.Evaluator
	sign               *SignFusionEvaluator
	relinearizationKey *rlwe.RelinearizationKey
	galoisKeys         map[uint64]*rlwe.GaloisKey
	graph              signed8Depth2ChildComparatorEvaluatorGraph
}

// Signed8Depth2ChildComparatorResult is the first external provenance token
// after the closed ingress/sign pipeline. It is intentionally distinct from
// the legacy L20 Signed8ComparatorResult.
type Signed8Depth2ChildComparatorResult struct {
	branch                    *rlwe.Ciphertext
	profileDigest             string
	parameterDigest           string
	protocolRangeDigest       string
	treeDigest                string
	scheduleDigest            string
	inputBindingDigest        string
	operandsProvenanceDigest  string
	ingressProfileDigest      string
	ingressRangeDigest        string
	ingressAdmissionDigest    string
	ingressInputBindingDigest string
	ingressTraceDigest        string
	signProfileDigest         string
	signSourceDigest          string
	signCompiledDigest        string
	signTraceDigest           string
	outputPayloadDigest       string
	provenanceDigest          string
}

func (r Signed8Depth2ChildComparatorResult) Ciphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(r.branch)
}
func (r Signed8Depth2ChildComparatorResult) ProfileDigest() string { return r.profileDigest }
func (r Signed8Depth2ChildComparatorResult) ParameterDigest() string {
	return r.parameterDigest
}
func (r Signed8Depth2ChildComparatorResult) ProtocolRangeDigest() string {
	return r.protocolRangeDigest
}
func (r Signed8Depth2ChildComparatorResult) TreeDigest() string     { return r.treeDigest }
func (r Signed8Depth2ChildComparatorResult) ScheduleDigest() string { return r.scheduleDigest }
func (r Signed8Depth2ChildComparatorResult) InputBindingDigest() string {
	return r.inputBindingDigest
}
func (r Signed8Depth2ChildComparatorResult) OperandsProvenanceDigest() string {
	return r.operandsProvenanceDigest
}
func (r Signed8Depth2ChildComparatorResult) OutputPayloadDigest() string {
	return r.outputPayloadDigest
}
func (r Signed8Depth2ChildComparatorResult) IngressTraceDigest() string {
	return r.ingressTraceDigest
}
func (r Signed8Depth2ChildComparatorResult) SignTraceDigest() string { return r.signTraceDigest }
func (r Signed8Depth2ChildComparatorResult) ProvenanceDigest() string {
	return r.provenanceDigest
}

// Signed8Depth2ChildComparatorTrace keeps the wrapper evidence separate from
// both nested ledgers.
type Signed8Depth2ChildComparatorTrace struct {
	profileDigest            string
	inputBindingDigest       string
	operandsProvenanceDigest string
	resultProvenanceDigest   string
	failureStage             Signed8Depth2ChildComparatorStage
	states                   []Signed8Depth2ChildComparatorState
	counts                   Signed8Depth2ChildComparatorOperationCounts
	ingressTrace             A2BFullIngress6Trace
	signProvenance           SignFusionProvenance
	keyPreflight             A2BRefreshKeyPreflight
	runtimeGalois            []uint64
	relinearizationMatched   bool
	serializedBytes          Signed8Depth2ChildComparatorSerializedBytes
	retainedCiphertexts      map[Signed8Depth2ChildComparatorStage]*rlwe.Ciphertext
	traceDigest              string
	wallTime                 time.Duration
}

func (t Signed8Depth2ChildComparatorTrace) ProfileDigest() string { return t.profileDigest }
func (t Signed8Depth2ChildComparatorTrace) InputBindingDigest() string {
	return t.inputBindingDigest
}
func (t Signed8Depth2ChildComparatorTrace) OperandsProvenanceDigest() string {
	return t.operandsProvenanceDigest
}
func (t Signed8Depth2ChildComparatorTrace) ResultProvenanceDigest() string {
	return t.resultProvenanceDigest
}
func (t Signed8Depth2ChildComparatorTrace) FailureStage() Signed8Depth2ChildComparatorStage {
	return t.failureStage
}
func (t Signed8Depth2ChildComparatorTrace) States() []Signed8Depth2ChildComparatorState {
	return append([]Signed8Depth2ChildComparatorState(nil), t.states...)
}
func (t Signed8Depth2ChildComparatorTrace) OperationCounts() Signed8Depth2ChildComparatorOperationCounts {
	return t.counts
}
func (t Signed8Depth2ChildComparatorTrace) IngressTrace() A2BFullIngress6Trace {
	return cloneSigned8Depth2ChildIngressTrace(t.ingressTrace)
}
func (t Signed8Depth2ChildComparatorTrace) SignProvenance() SignFusionProvenance {
	return cloneSigned8SignProvenance(t.signProvenance)
}
func (t Signed8Depth2ChildComparatorTrace) KeyPreflight() A2BRefreshKeyPreflight {
	return cloneA2BRefreshKeyPreflight(t.keyPreflight)
}
func (t Signed8Depth2ChildComparatorTrace) RuntimeGaloisElements() []uint64 {
	return append([]uint64(nil), t.runtimeGalois...)
}
func (t Signed8Depth2ChildComparatorTrace) RelinearizationKeyMatched() bool {
	return t.relinearizationMatched
}
func (t Signed8Depth2ChildComparatorTrace) SerializedBytes() Signed8Depth2ChildComparatorSerializedBytes {
	return t.serializedBytes
}
func (t Signed8Depth2ChildComparatorTrace) RetainedCiphertext(
	stage Signed8Depth2ChildComparatorStage,
) (*rlwe.Ciphertext, bool) {
	ciphertext, ok := t.retainedCiphertexts[stage]
	if !ok || ciphertext == nil {
		return nil, false
	}
	return ciphertext.CopyNew(), true
}
func (t Signed8Depth2ChildComparatorTrace) Digest() string          { return t.traceDigest }
func (t Signed8Depth2ChildComparatorTrace) WallTime() time.Duration { return t.wallTime }

func (i Signed8Depth2ChildComparatorInput) FeatureCiphertext() *rlwe.Ciphertext {
	return i.operands.FeatureCiphertext()
}
func (i Signed8Depth2ChildComparatorInput) ThresholdCiphertext() *rlwe.Ciphertext {
	return i.operands.ThresholdCiphertext()
}
func (i Signed8Depth2ChildComparatorInput) OperandsProvenanceDigest() string {
	return i.operandsProvenance
}
func (i Signed8Depth2ChildComparatorInput) BindingDigest() string { return i.bindingDigest }

// NewSigned8Depth2ChildComparatorCircuit closes the fixed L6 child graph.
func NewSigned8Depth2ChildComparatorCircuit(prefix *Signed8Depth2SourcePrefixCircuit) (*Signed8Depth2ChildComparatorCircuit, error) {
	if prefix == nil {
		return nil, fmt.Errorf("homchain: nil depth2 source prefix")
	}
	if err := prefix.validate(); err != nil {
		return nil, fmt.Errorf("homchain: validate depth2 source prefix: %w", err)
	}
	refreshEncoder := prefix.selector.producer.refreshEncoder
	integerEncoder := prefix.integerEncoder
	ingress, err := NewA2BFullIngress6Circuit(
		prefix.params,
		refreshEncoder,
		integerEncoder,
		A2BFullIngress6Depth2PrefixL6V1,
		NewA2BFullIngress6FullRingRangeCertificate(),
	)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct fixed L6 child ingress: %w", err)
	}
	sign, err := NewSignFusionCircuit(prefix.params, integerEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct child sign fusion: %w", err)
	}
	one, err := newSigned8WordPlaintext(
		prefix.params,
		integerEncoder,
		signed8IntegerEncoderPrecision,
		signed8OutputLevel,
		[signed8Words]uint64{1, 1, 1, 1},
	)
	if err != nil {
		return nil, fmt.Errorf("homchain: encode child arithmetic-root one: %w", err)
	}
	oneDigest, err := signed8PlaintextDigest(one)
	if err != nil {
		return nil, err
	}

	prefixProfile := prefix.Profile()
	ingressProfile := ingress.Profile()
	signProfile := sign.Profile()
	keyProfile := ingress.RequiredKeyProfile()
	profile := Signed8Depth2ChildComparatorProfile{
		fidelity:         Signed8Depth2ChildFunctionalNotSecure,
		predicate:        Signed8GreaterThanOrEqual,
		children:         Signed8ZeroLTOneGE,
		inputLevel:       signed8Depth2OutputLevel,
		outputLevel:      signed8OutputLevel,
		parameter:        prefixProfile.ParameterDigest(),
		prefix:           prefixProfile.Digest(),
		protocolRange:    prefixProfile.RangeDigest(),
		tree:             prefixProfile.TreeDigest(),
		schedule:         prefixProfile.ScheduleDigest(),
		operandSource:    prefixProfile.SourceKind(),
		ingressProfile:   ingressProfile.Digest(),
		ingressSource:    ingressProfile.Source(),
		ingressRange:     ingressProfile.RangeDigest(),
		ingressAdmission: ingressProfile.AdmissionDigest(),
		ingressSuffix:    ingressProfile.SuffixProfileDigest(),
		ingressKey:       ingressProfile.KeyProfileDigest(),
		ingressSpecialB0: ingressProfile.SpecialB0CompiledDigest(),
		ingressMask:      ingressProfile.MaskPayloadDigest(),
		ingressFirstSTC:  ingressProfile.FirstSTCEncodedPayloadDigest(),
		ingressSharedCTS: ingressProfile.SharedCTSEncodedPayloadDigest(),
		ingressSecondSTC: ingressProfile.SecondSTCEncodedPayloadDigest(),
		signProfile:      signProfile.Digest(),
		signSource:       signProfile.SourceDigest(),
		signCompiled:     signProfile.CompiledDigest(),
		arithmeticOne:    oneDigest,
		counts: Signed8Depth2ChildComparatorOperationCounts{
			CiphertextCiphertextSubtractions: 1,
			IngressInvocations:               1,
			SignFusionInvocations:            1,
			Negations:                        1,
			CiphertextPlaintextVectorAdds:    1,
		},
		requiredGalois:  keyProfile.All(),
		relinearization: keyProfile.RelinearizationRequired(),
		levelLedger:     signed8Depth2ChildComparatorLevelLedger,
	}
	profile.expectedBytes = Signed8Depth2ChildComparatorSerializedBytes{
		Feature: 3998, Threshold: 3998, Difference: 3998, IngressHigh: 3470,
		ArithmeticSign: 2942, NegatedSign: 2942, GreaterEqualOutput: 2942,
	}
	defaultScale, err := NewExactScaleSnapshot(prefix.params.DefaultScale())
	if err != nil {
		return nil, err
	}
	profile.expectedStates = []Signed8Depth2ChildComparatorState{
		{Stage: Signed8Depth2ChildStageFeature, Level: 6, Degree: 1, LogDimensions: prefix.params.LogMaxDimensions(), Scale: defaultScale, SerializedBytes: 3998},
		{Stage: Signed8Depth2ChildStageThreshold, Level: 6, Degree: 1, LogDimensions: prefix.params.LogMaxDimensions(), Scale: defaultScale, SerializedBytes: 3998},
		{Stage: Signed8Depth2ChildStageDifference, Level: 6, Degree: 1, LogDimensions: prefix.params.LogMaxDimensions(), Scale: defaultScale, SerializedBytes: 3998},
		{Stage: Signed8Depth2ChildStageIngressHigh, Level: 5, Degree: 1, LogDimensions: prefix.params.LogMaxDimensions(), Scale: defaultScale, SerializedBytes: 3470},
		{Stage: Signed8Depth2ChildStageArithmeticSign, Level: 4, Degree: 1, LogDimensions: prefix.params.LogMaxDimensions(), Scale: defaultScale, SerializedBytes: 2942},
		{Stage: Signed8Depth2ChildStageNegatedSign, Level: 4, Degree: 1, LogDimensions: prefix.params.LogMaxDimensions(), Scale: defaultScale, SerializedBytes: 2942},
		{Stage: Signed8Depth2ChildStageGreaterEqual, Level: 4, Degree: 1, LogDimensions: prefix.params.LogMaxDimensions(), Scale: defaultScale, SerializedBytes: 2942},
	}
	profile.digest = digestSigned8Depth2ChildComparatorProfile(profile)
	circuit := &Signed8Depth2ChildComparatorCircuit{
		prefix: prefix, ingress: ingress, sign: sign, params: prefix.params,
		arithmeticOne: one, arithmeticOneSeal: one.CopyNew(), arithmeticOneDigest: oneDigest,
		profile: profile, keyProfile: keyProfile,
	}
	circuit.graph = signed8Depth2ChildComparatorCircuitGraph{
		circuit: circuit, prefix: prefix, ingress: ingress, sign: sign,
		arithmeticOne: one, arithmeticOneSeal: circuit.arithmeticOneSeal,
		arithmeticOneDigest: oneDigest, profileDigest: profile.digest,
		keyProfileDigest: circuit.keyProfile.Digest(),
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *Signed8Depth2ChildComparatorCircuit) Profile() Signed8Depth2ChildComparatorProfile {
	if c == nil {
		return Signed8Depth2ChildComparatorProfile{}
	}
	result := c.profile
	result.requiredGalois = c.profile.RequiredGaloisElements()
	result.expectedStates = c.profile.ExpectedStates()
	return result
}

func (c *Signed8Depth2ChildComparatorCircuit) RequiredKeyProfile() A2BRefreshKeyProfile {
	if c == nil {
		return A2BRefreshKeyProfile{}
	}
	return cloneA2BRefreshKeyProfile(c.keyProfile)
}

// BindOperands authenticates the sole prefix output type and takes ownership
// of detached ciphertext copies.
func (c *Signed8Depth2ChildComparatorCircuit) BindOperands(
	operands Signed8Depth2Operands,
) (Signed8Depth2ChildComparatorInput, error) {
	if err := c.validate(); err != nil {
		return Signed8Depth2ChildComparatorInput{}, err
	}
	if err := c.prefix.validateOperands(operands); err != nil {
		return Signed8Depth2ChildComparatorInput{}, err
	}
	owned := cloneSigned8Depth2ChildOperands(operands)
	input := Signed8Depth2ChildComparatorInput{
		operands:           owned,
		profileDigest:      c.profile.digest,
		operandsProvenance: owned.provenanceDigest,
	}
	input.bindingDigest = digestSigned8Depth2ChildComparatorInput(input)
	if err := c.validateInput(input); err != nil {
		return Signed8Depth2ChildComparatorInput{}, err
	}
	return input, nil
}

// BindEvaluator seals wrapper and nested evaluators before any online input
// can be executed.
func (c *Signed8Depth2ChildComparatorCircuit) BindEvaluator(
	source *bootstrapping.Evaluator,
) (*Signed8Depth2ChildComparatorEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if source == nil || source.EvaluationKeys == nil || source.Evaluator == nil {
		return nil, fmt.Errorf("homchain: depth2 child comparator bootstrap source is nil, incomplete, or foreign")
	}
	if _, err := source.Evaluator.RuntimeIdentitySnapshot(); err != nil {
		return nil, fmt.Errorf("homchain: seal depth2 child wrapper CKKS evaluator: %w", err)
	}
	if source.MemEvaluationKeySet == nil ||
		!source.ResidualParameters.Equal(&c.params) || !source.BootstrappingParameters.Equal(&c.params) ||
		!c.params.Equal(source.Evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: depth2 child comparator bootstrap source is nil, incomplete, or foreign")
	}
	sourceBinding, err := captureSigned8Depth2ChildCKKSEvaluatorBinding(source.Evaluator, source.EvaluationKeys, c.keyProfile.All())
	if err != nil {
		return nil, fmt.Errorf("homchain: seal depth2 child wrapper CKKS evaluator: %w", err)
	}
	relinearizationKey, err := source.MemEvaluationKeySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, fmt.Errorf("homchain: depth2 child comparator relinearization key is missing: %v", err)
	}
	relinearizationBinding, err := captureSigned8Depth2ChildRelinearizationKeyBinding(relinearizationKey, c.params.GetRLWEParameters())
	if err != nil {
		return nil, err
	}
	galoisKeys := make(map[uint64]*rlwe.GaloisKey, len(c.keyProfile.all))
	galoisBindings := make(map[uint64]signed8Depth2ChildGaloisKeyBinding, len(c.keyProfile.all))
	orderedKeys := make([]*rlwe.GaloisKey, 0, len(c.keyProfile.all))
	for _, element := range c.keyProfile.all {
		key, keyErr := source.MemEvaluationKeySet.GetGaloisKey(element)
		if keyErr != nil || key == nil {
			return nil, fmt.Errorf("homchain: depth2 child comparator missing Galois key %d: %v", element, keyErr)
		}
		binding, bindingErr := captureSigned8Depth2ChildGaloisKeyBinding(key, c.params.GetRLWEParameters())
		if bindingErr != nil {
			return nil, bindingErr
		}
		if binding.element != element || binding.nthRoot != c.params.RingQ().NthRoot() ||
			binding.gadget.levelQ < signed8Depth2OutputLevel || binding.gadget.levelP != 0 {
			return nil, fmt.Errorf("homchain: depth2 child comparator Galois key %d has wrong element or levels", element)
		}
		galoisKeys[element] = key
		galoisBindings[element] = binding
		orderedKeys = append(orderedKeys, key)
	}
	prefixEvaluator, err := c.prefix.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind depth2 child prefix: %w", err)
	}
	filteredKeySet := rlwe.NewMemEvaluationKeySet(relinearizationKey, orderedKeys...)
	ingressSource, err := newSigned8Depth2ChildBootstrapSource(c, filteredKeySet)
	if err != nil {
		return nil, err
	}
	ingressEvaluator, err := c.ingress.BindEvaluator(ingressSource)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind depth2 child ingress: %w", err)
	}
	signSource := ckks.NewEvaluator(c.params, filteredKeySet)
	signEvaluator, err := c.sign.BindEvaluator(signSource)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind depth2 child sign fusion: %w", err)
	}
	ingressBinding, err := captureSigned8Depth2ChildIngressEvaluatorBinding(c, ingressEvaluator, ingressSource, filteredKeySet)
	if err != nil {
		return nil, fmt.Errorf("homchain: seal depth2 child ingress evaluator: %w", err)
	}
	signBinding, err := captureSigned8Depth2ChildSignEvaluatorBinding(c, signEvaluator, signSource, filteredKeySet)
	if err != nil {
		return nil, fmt.Errorf("homchain: seal depth2 child sign evaluator: %w", err)
	}
	evaluator := &Signed8Depth2ChildComparatorEvaluator{
		circuit: c, source: source, sourceCKKS: source.Evaluator,
		sourceKeySet: source.MemEvaluationKeySet, prefix: prefixEvaluator,
		ingressSource: ingressSource, ingressKeySet: filteredKeySet, ingress: ingressEvaluator,
		signSource: signSource, sign: signEvaluator,
		relinearizationKey: relinearizationKey, galoisKeys: galoisKeys,
	}
	evaluator.graph = signed8Depth2ChildComparatorEvaluatorGraph{
		evaluator: evaluator, circuit: c, source: source, sourceCKKS: source.Evaluator,
		sourceKeySet: source.MemEvaluationKeySet, sourceEvaluationKeys: source.EvaluationKeys, prefix: prefixEvaluator,
		ingressSource: ingressSource, ingressKeySet: filteredKeySet, ingress: ingressEvaluator,
		signSource: signSource, sign: signEvaluator,
		relinearizationKey: relinearizationKey, relinearizationBinding: relinearizationBinding,
		galoisBindings: galoisBindings, profileDigest: c.profile.digest,
		keyProfileDigest:  c.keyProfile.Digest(),
		sourceCKKSBinding: sourceBinding, ingressBinding: ingressBinding, signBinding: signBinding,
	}
	if err = evaluator.preflight(); err != nil {
		return nil, err
	}
	return evaluator, nil
}

func newSigned8Depth2ChildBootstrapSource(
	circuit *Signed8Depth2ChildComparatorCircuit,
	keySet *rlwe.MemEvaluationKeySet,
) (*bootstrapping.Evaluator, error) {
	if circuit == nil || keySet == nil {
		return nil, fmt.Errorf("homchain: nil child bootstrap graph")
	}
	dft := circuit.ingress.suffix.refresh.profile.dft
	parameters := bootstrapping.Parameters{
		ResidualParameters:      circuit.params,
		BootstrappingParameters: circuit.params,
		SlotsToCoeffsParameters: dft.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: dft.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ:   dft.CoeffsToSlotsLiteral().LevelQ - 3,
			LogScale: circuit.params.LogDefaultScale(), Mod1Type: mod1.SinContinuous,
			LogMessageRatio: 15, K: 1, Mod1Degree: 3,
		},
		CircuitOrder: bootstrapping.Custom,
	}
	result, err := bootstrapping.NewEvaluator(parameters, &bootstrapping.EvaluationKeys{MemEvaluationKeySet: keySet})
	if err != nil {
		return nil, fmt.Errorf("homchain: construct filtered depth2 child bootstrap source: %w", err)
	}
	return result, nil
}

func (e *Signed8Depth2ChildComparatorEvaluator) preflight() error {
	if e == nil || e.circuit == nil || e.source == nil || e.sourceCKKS == nil || e.sourceKeySet == nil ||
		e.prefix == nil || e.ingressSource == nil || e.ingressKeySet == nil || e.ingress == nil ||
		e.signSource == nil || e.signSource.Evaluator == nil || e.sign == nil || e.relinearizationKey == nil ||
		e.source.EvaluationKeys == nil || e.ingressSource.EvaluationKeys == nil {
		return fmt.Errorf("homchain: nil or incomplete depth2 child comparator evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		return err
	}
	g := e.graph
	if g.evaluator != e || g.circuit != e.circuit || g.source != e.source || g.sourceCKKS != e.sourceCKKS ||
		g.sourceKeySet != e.sourceKeySet || g.sourceEvaluationKeys != e.source.EvaluationKeys ||
		g.prefix != e.prefix || g.ingressSource != e.ingressSource ||
		g.ingressKeySet != e.ingressKeySet || g.ingress != e.ingress || g.signSource != e.signSource ||
		g.sign != e.sign || g.relinearizationKey != e.relinearizationKey ||
		g.relinearizationBinding.key != e.relinearizationKey ||
		len(g.galoisBindings) != len(e.circuit.keyProfile.all) ||
		g.profileDigest != e.circuit.profile.digest || g.keyProfileDigest != e.circuit.keyProfile.Digest() ||
		e.source.Evaluator != e.sourceCKKS || e.source.MemEvaluationKeySet != e.sourceKeySet ||
		e.ingressSource.MemEvaluationKeySet != e.ingressKeySet || e.signSource.EvaluationKeySet != e.ingressKeySet {
		return fmt.Errorf("homchain: depth2 child comparator evaluator graph changed")
	}
	// These wrapper-owned identity checks intentionally precede every nested
	// self-consistency preflight. A foreign nested graph may be internally valid
	// yet still be unrelated to the filtered key source sealed by this wrapper.
	if err := g.sourceCKKSBinding.validate(e.sourceCKKS, e.source.EvaluationKeys); err != nil {
		return fmt.Errorf("homchain: depth2 child wrapper source evaluator: %w", err)
	}
	if err := g.ingressBinding.validate(e.circuit, e.ingress, e.ingressSource, e.ingressKeySet); err != nil {
		return err
	}
	if err := g.signBinding.validate(e.circuit, e.sign, e.signSource, e.ingressKeySet); err != nil {
		return err
	}
	if err := e.prefix.preflight(); err != nil {
		return err
	}
	currentRelin, err := e.sourceKeySet.GetRelinearizationKey()
	if err != nil || currentRelin != e.relinearizationKey ||
		g.relinearizationBinding.validate(currentRelin, e.circuit.params.GetRLWEParameters()) != nil {
		return fmt.Errorf("homchain: depth2 child comparator relinearization key identity changed")
	}
	for _, element := range e.circuit.keyProfile.all {
		current, keyErr := e.sourceKeySet.GetGaloisKey(element)
		binding, present := g.galoisBindings[element]
		if keyErr != nil || current == nil || current != e.galoisKeys[element] || !present ||
			binding.element != element || binding.nthRoot != e.circuit.params.RingQ().NthRoot() ||
			binding.gadget.levelQ < signed8Depth2OutputLevel || binding.gadget.levelP != 0 ||
			binding.validate(current, e.circuit.params.GetRLWEParameters()) != nil {
			return fmt.Errorf("homchain: depth2 child comparator Galois key %d identity changed", element)
		}
		filtered, filteredErr := e.ingressKeySet.GetGaloisKey(element)
		if filteredErr != nil || filtered != current {
			return fmt.Errorf("homchain: depth2 child filtered Galois key %d changed", element)
		}
	}
	filteredRelin, err := e.ingressKeySet.GetRelinearizationKey()
	if err != nil || filteredRelin != e.relinearizationKey {
		return fmt.Errorf("homchain: depth2 child filtered relinearization key changed")
	}
	if err = e.ingress.graph.validate(); err != nil {
		return err
	}
	if e.ingress.suffix == nil || e.ingress.suffix.circuit == nil || e.ingress.suffix.refresh == nil ||
		e.sign.circuit == nil || e.sign.ckks == nil || e.sign.linear == nil || e.sign.keySet == nil {
		return fmt.Errorf("homchain: depth2 child nested evaluator graph is incomplete")
	}
	if _, err = e.ingress.suffix.preflight(); err != nil {
		return err
	}
	if _, _, err = e.ingress.runtimeKeyGraph(); err != nil {
		return err
	}
	if err = e.sign.preflightGraphAndKeys(); err != nil {
		return err
	}
	return nil
}

// EvaluateNew executes the closed L6 child comparison. All admission, graph,
// cache and key checks complete before the first ciphertext subtraction.
func (e *Signed8Depth2ChildComparatorEvaluator) EvaluateNew(
	input Signed8Depth2ChildComparatorInput,
) (Signed8Depth2ChildComparatorResult, Signed8Depth2ChildComparatorTrace, error) {
	trace := Signed8Depth2ChildComparatorTrace{}
	if e == nil || e.circuit == nil {
		return Signed8Depth2ChildComparatorResult{}, trace, fmt.Errorf("homchain: nil depth2 child comparator evaluator")
	}
	trace.profileDigest = e.circuit.profile.digest
	trace.inputBindingDigest = input.bindingDigest
	trace.operandsProvenanceDigest = input.operandsProvenance
	if err := e.circuit.prefix.validateOperands(input.operands); err != nil {
		trace.failureStage = Signed8Depth2ChildStageAdmission
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	if err := e.preflight(); err != nil {
		trace.failureStage = Signed8Depth2ChildStagePreflight
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	if err := e.circuit.validateInput(input); err != nil {
		trace.failureStage = Signed8Depth2ChildStageAdmission
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}

	started := time.Now()
	featureBefore := input.operands.feature.CopyNew()
	thresholdBefore := input.operands.threshold.CopyNew()
	selectorBefore := input.operands.conditionedSelector.CopyNew()
	oneBefore := e.circuit.arithmeticOne.CopyNew()
	trace.retainedCiphertexts = make(map[Signed8Depth2ChildComparatorStage]*rlwe.Ciphertext, 7)
	appendState := func(stage Signed8Depth2ChildComparatorStage, ciphertext *rlwe.Ciphertext) error {
		if _, exists := trace.retainedCiphertexts[stage]; exists {
			return fmt.Errorf("homchain: depth2 child runtime stage %s retained twice", stage)
		}
		state, err := snapshotSigned8Depth2ChildState(stage, ciphertext)
		if err != nil {
			return err
		}
		trace.states = append(trace.states, state)
		trace.retainedCiphertexts[stage] = ciphertext.CopyNew()
		return nil
	}
	if err := appendState(Signed8Depth2ChildStageFeature, input.operands.feature); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	if err := appendState(Signed8Depth2ChildStageThreshold, input.operands.threshold); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}

	difference, err := e.sourceCKKS.SubNew(input.operands.feature, input.operands.threshold)
	if err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, fmt.Errorf("homchain: depth2 child subtract selected feature and threshold: %w", err)
	}
	trace.counts.CiphertextCiphertextSubtractions++
	if err = requireSigned8Depth2State("depth2 child difference", difference, 6, e.circuit.params.DefaultScale(), e.circuit.params); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	if err = appendState(Signed8Depth2ChildStageDifference, difference); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}

	ingressInput, err := e.circuit.ingress.BindInput(difference, e.circuit.params)
	if err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, fmt.Errorf("homchain: bind depth2 child difference to fixed ingress: %w", err)
	}
	ingressResult, ingressTrace, err := e.ingress.EvaluateNew(ingressInput)
	if err != nil {
		trace.failureStage = Signed8Depth2ChildStageIngressHigh
		trace.ingressTrace = cloneSigned8Depth2ChildIngressTrace(ingressTrace)
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	trace.counts.IngressInvocations++
	high := ingressResult.HighMSB()
	if err = validateSigned8Depth2ChildIngressEvidence(e.circuit, ingressInput, high, ingressTrace); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	trace.ingressTrace = cloneSigned8Depth2ChildIngressTrace(ingressTrace)
	if err = appendState(Signed8Depth2ChildStageIngressHigh, high); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}

	signInput, err := e.circuit.sign.BindBooleanHalf(high, SignFusionHighBooleanHalf, SignFusionLSBFirst)
	if err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, fmt.Errorf("homchain: bind depth2 child ingress high to sign fusion: %w", err)
	}
	signResult, err := e.sign.EvaluateNew(signInput)
	if err != nil {
		trace.failureStage = Signed8Depth2ChildStageArithmeticSign
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	trace.counts.SignFusionInvocations++
	sign := signResult.Ciphertext()
	signProvenance := signResult.Provenance()
	if err = validateSigned8Depth2ChildSignEvidence(e.circuit, high, sign, signProvenance); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	trace.signProvenance = cloneSigned8SignProvenance(signProvenance)
	if err = appendState(Signed8Depth2ChildStageArithmeticSign, sign); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}

	negated := negateSigned8CiphertextNew(e.circuit.params, sign)
	trace.counts.Negations++
	if err = requireSigned8Depth2State("depth2 child negated sign", negated, 4, e.circuit.params.DefaultScale(), e.circuit.params); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	if err = appendState(Signed8Depth2ChildStageNegatedSign, negated); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	branch, err := e.sourceCKKS.AddNew(negated, e.circuit.arithmeticOne)
	if err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, fmt.Errorf("homchain: depth2 child add arithmetic-root one: %w", err)
	}
	trace.counts.CiphertextPlaintextVectorAdds++
	if err = requireSigned8Depth2State("depth2 child GE branch", branch, 4, e.circuit.params.DefaultScale(), e.circuit.params); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	if err = appendState(Signed8Depth2ChildStageGreaterEqual, branch); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}

	if !input.operands.feature.Equal(featureBefore) || !input.operands.threshold.Equal(thresholdBefore) ||
		!input.operands.conditionedSelector.Equal(selectorBefore) ||
		!e.circuit.arithmeticOne.Equal(oneBefore) || !e.circuit.arithmeticOne.Equal(e.circuit.arithmeticOneSeal) {
		return Signed8Depth2ChildComparatorResult{}, trace, fmt.Errorf("homchain: depth2 child evaluation mutated admitted input or cached one")
	}
	trace.serializedBytes = signed8Depth2ChildBytesFromStates(trace.states)
	if trace.counts != e.circuit.profile.counts ||
		!reflect.DeepEqual(trace.states, e.circuit.profile.expectedStates) ||
		trace.serializedBytes != e.circuit.profile.expectedBytes {
		return Signed8Depth2ChildComparatorResult{}, trace, fmt.Errorf("homchain: depth2 child runtime state, operation, or serialized-byte ledger changed")
	}
	trace.runtimeGalois = append([]uint64(nil), e.circuit.keyProfile.all...)
	sort.Slice(trace.runtimeGalois, func(i, j int) bool { return trace.runtimeGalois[i] < trace.runtimeGalois[j] })
	trace.relinearizationMatched = true
	trace.keyPreflight = cloneA2BRefreshKeyPreflight(ingressTrace.keyPreflight)

	outputPayload, err := signed8CiphertextDigest(branch)
	if err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	result := Signed8Depth2ChildComparatorResult{
		branch: branch, profileDigest: e.circuit.profile.digest,
		parameterDigest: e.circuit.profile.parameter, protocolRangeDigest: e.circuit.profile.protocolRange,
		treeDigest: e.circuit.profile.tree, scheduleDigest: e.circuit.profile.schedule,
		inputBindingDigest: input.bindingDigest, operandsProvenanceDigest: input.operandsProvenance,
		ingressProfileDigest:      e.circuit.profile.ingressProfile,
		ingressRangeDigest:        e.circuit.profile.ingressRange,
		ingressAdmissionDigest:    e.circuit.profile.ingressAdmission,
		ingressInputBindingDigest: ingressTrace.InputBindingDigest(),
		ingressTraceDigest:        digestSigned8Depth2ChildIngressTrace(ingressTrace),
		signProfileDigest:         e.circuit.profile.signProfile,
		signSourceDigest:          e.circuit.profile.signSource,
		signCompiledDigest:        e.circuit.profile.signCompiled,
		signTraceDigest:           digestSigned8Depth2ChildSignProvenance(signProvenance),
		outputPayloadDigest:       outputPayload,
	}
	result.provenanceDigest = digestSigned8Depth2ChildComparatorResult(result)
	if err = e.circuit.validateResult(result); err != nil {
		return Signed8Depth2ChildComparatorResult{}, trace, err
	}
	trace.resultProvenanceDigest = result.provenanceDigest
	trace.wallTime = time.Since(started)
	trace.traceDigest = digestSigned8Depth2ChildComparatorTrace(trace)
	return result, trace, nil
}

// validateResult is the package-private downstream admission seam.
func (c *Signed8Depth2ChildComparatorCircuit) validateResult(result Signed8Depth2ChildComparatorResult) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := requireSigned8Depth2State("depth2 child sealed result", result.branch, 4, c.params.DefaultScale(), c.params); err != nil {
		return err
	}
	payload, err := signed8CiphertextDigest(result.branch)
	if err != nil {
		return err
	}
	if result.profileDigest != c.profile.digest || result.parameterDigest != c.profile.parameter ||
		result.protocolRangeDigest != c.profile.protocolRange || result.treeDigest != c.profile.tree ||
		result.scheduleDigest != c.profile.schedule || result.inputBindingDigest == "" ||
		result.operandsProvenanceDigest == "" || result.ingressProfileDigest != c.profile.ingressProfile ||
		result.ingressRangeDigest != c.profile.ingressRange || result.ingressAdmissionDigest != c.profile.ingressAdmission ||
		result.ingressInputBindingDigest == "" || result.ingressTraceDigest == "" ||
		result.signProfileDigest != c.profile.signProfile || result.signSourceDigest != c.profile.signSource ||
		result.signCompiledDigest != c.profile.signCompiled || result.signTraceDigest == "" ||
		result.outputPayloadDigest != payload || result.provenanceDigest == "" ||
		result.provenanceDigest != digestSigned8Depth2ChildComparatorResult(result) {
		return fmt.Errorf("homchain: depth2 child result payload or provenance changed")
	}
	return nil
}

func (c *Signed8Depth2ChildComparatorCircuit) validateInput(input Signed8Depth2ChildComparatorInput) error {
	if err := c.prefix.validateOperands(input.operands); err != nil {
		return err
	}
	if input.profileDigest != c.profile.digest || input.operandsProvenance != input.operands.provenanceDigest ||
		input.bindingDigest == "" || input.bindingDigest != digestSigned8Depth2ChildComparatorInput(input) {
		return fmt.Errorf("homchain: depth2 child comparator input binding changed")
	}
	return nil
}

func (c *Signed8Depth2ChildComparatorCircuit) validate() error {
	if c == nil || c.prefix == nil || c.ingress == nil || c.sign == nil ||
		c.arithmeticOne == nil || c.arithmeticOneSeal == nil {
		return fmt.Errorf("homchain: nil or incomplete depth2 child comparator circuit")
	}
	if err := c.prefix.validate(); err != nil {
		return err
	}
	if err := c.ingress.validate(); err != nil {
		return err
	}
	if err := c.sign.validate(); err != nil {
		return err
	}
	g := c.graph
	if g.circuit != c || g.prefix != c.prefix || g.ingress != c.ingress || g.sign != c.sign ||
		g.arithmeticOne != c.arithmeticOne || g.arithmeticOneSeal != c.arithmeticOneSeal ||
		g.arithmeticOneDigest != c.arithmeticOneDigest || g.profileDigest != c.profile.digest ||
		g.keyProfileDigest != c.keyProfile.Digest() {
		return fmt.Errorf("homchain: depth2 child comparator circuit graph changed")
	}
	if !c.arithmeticOne.Equal(c.arithmeticOneSeal) {
		return fmt.Errorf("homchain: depth2 child arithmetic-root one changed")
	}
	oneDigest, err := signed8PlaintextDigest(c.arithmeticOne)
	if err != nil || oneDigest != c.arithmeticOneDigest {
		return fmt.Errorf("homchain: depth2 child arithmetic-root one payload changed")
	}
	state := Signed8ComparatorStateProfile{
		level: signed8OutputLevel, degree: 0,
		logDimensions: c.params.LogMaxDimensions(), scale: c.sign.profile.outputScale,
	}
	if err = requireSigned8PlaintextState("depth2 child arithmetic-root one", c.arithmeticOne, state, c.params); err != nil {
		return err
	}
	if c.keyProfile.Digest() != c.ingress.profile.keyProfileDigest ||
		!c.keyProfile.relinearization || !equalSigned8Depth2ChildGalois(c.keyProfile.all, []uint64{5, 17, 25, 33, 41, 49, 63}) {
		return fmt.Errorf("homchain: depth2 child required key profile changed")
	}
	prefix := c.prefix.profile
	ingress := c.ingress.profile
	sign := c.sign.profile
	wantCounts := Signed8Depth2ChildComparatorOperationCounts{
		CiphertextCiphertextSubtractions: 1,
		IngressInvocations:               1,
		SignFusionInvocations:            1,
		Negations:                        1,
		CiphertextPlaintextVectorAdds:    1,
	}
	wantBytes := Signed8Depth2ChildComparatorSerializedBytes{
		Feature: 3998, Threshold: 3998, Difference: 3998, IngressHigh: 3470,
		ArithmeticSign: 2942, NegatedSign: 2942, GreaterEqualOutput: 2942,
	}
	parameterDigest, err := signed8ParameterDigest(c.params)
	if err != nil {
		return err
	}
	if c.profile.fidelity != Signed8Depth2ChildFunctionalNotSecure ||
		c.profile.predicate != Signed8GreaterThanOrEqual || c.profile.children != Signed8ZeroLTOneGE ||
		c.profile.inputLevel != 6 || c.profile.outputLevel != 4 || c.profile.parameter != parameterDigest ||
		c.profile.prefix != prefix.digest || c.profile.protocolRange != prefix.rangeDigest ||
		c.profile.tree != prefix.treeDigest || c.profile.schedule != prefix.scheduleDigest ||
		c.profile.operandSource != Signed8Depth2PrefixL6V1 ||
		c.profile.ingressProfile != ingress.digest || c.profile.ingressSource != A2BFullIngress6Depth2PrefixL6V1 ||
		c.profile.ingressRange != ingress.rangeDigest || c.profile.ingressAdmission != ingress.admissionDigest ||
		c.profile.ingressSuffix != ingress.suffixProfileDigest || c.profile.ingressKey != ingress.keyProfileDigest ||
		c.profile.ingressSpecialB0 != ingress.specialB0CompiledDigest || c.profile.ingressMask != ingress.maskPayloadDigest ||
		c.profile.ingressFirstSTC != ingress.firstSTCEncodedPayloadDigest ||
		c.profile.ingressSharedCTS != ingress.sharedCTSEncodedPayloadDigest ||
		c.profile.ingressSecondSTC != ingress.secondSTCEncodedPayloadDigest ||
		c.profile.signProfile != sign.digest || c.profile.signSource != sign.sourceDigest ||
		c.profile.signCompiled != sign.compiledDigest || c.profile.arithmeticOne != c.arithmeticOneDigest ||
		c.profile.counts != wantCounts || !equalSigned8Depth2ChildGalois(c.profile.requiredGalois, c.keyProfile.all) ||
		!c.profile.relinearization || c.profile.expectedBytes != wantBytes ||
		!reflect.DeepEqual(c.profile.expectedStates, signed8Depth2ChildExpectedStates(c.params)) ||
		c.profile.levelLedger != signed8Depth2ChildComparatorLevelLedger {
		return fmt.Errorf("homchain: depth2 child comparator profile differs from the closed child graph")
	}
	if digestSigned8Depth2ChildComparatorProfile(c.profile) != c.profile.digest {
		return fmt.Errorf("homchain: depth2 child comparator profile digest changed")
	}
	return nil
}

func signed8Depth2ChildExpectedStates(params ckks.Parameters) []Signed8Depth2ChildComparatorState {
	scale, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil
	}
	dimensions := params.LogMaxDimensions()
	return []Signed8Depth2ChildComparatorState{
		{Stage: Signed8Depth2ChildStageFeature, Level: 6, Degree: 1, LogDimensions: dimensions, Scale: scale, SerializedBytes: 3998},
		{Stage: Signed8Depth2ChildStageThreshold, Level: 6, Degree: 1, LogDimensions: dimensions, Scale: scale, SerializedBytes: 3998},
		{Stage: Signed8Depth2ChildStageDifference, Level: 6, Degree: 1, LogDimensions: dimensions, Scale: scale, SerializedBytes: 3998},
		{Stage: Signed8Depth2ChildStageIngressHigh, Level: 5, Degree: 1, LogDimensions: dimensions, Scale: scale, SerializedBytes: 3470},
		{Stage: Signed8Depth2ChildStageArithmeticSign, Level: 4, Degree: 1, LogDimensions: dimensions, Scale: scale, SerializedBytes: 2942},
		{Stage: Signed8Depth2ChildStageNegatedSign, Level: 4, Degree: 1, LogDimensions: dimensions, Scale: scale, SerializedBytes: 2942},
		{Stage: Signed8Depth2ChildStageGreaterEqual, Level: 4, Degree: 1, LogDimensions: dimensions, Scale: scale, SerializedBytes: 2942},
	}
}

func digestSigned8Depth2ChildComparatorProfile(p Signed8Depth2ChildComparatorProfile) string {
	return digestString(fmt.Sprintf(
		"%s|fidelity=%s|predicate=%s|children=%s|input=%d|output=%d|parameters=%s|prefix=%s|protocol-range=%s|tree=%s|schedule=%s|operand-source=%d|ingress-profile=%s|ingress-source=%s|ingress-range=%s|ingress-admission=%s|ingress-suffix=%s|ingress-key=%s|ingress-special-b0=%s|ingress-mask=%s|ingress-first-stc=%s|ingress-shared-cts=%s|ingress-second-stc=%s|sign-profile=%s|sign-source=%s|sign-compiled=%s|one=%s|counts=%+v|required-galois=%v|relinearization=%t|states=%s|bytes=%+v|ledger=%s",
		signed8Depth2ChildComparatorProfileSchema, p.fidelity, p.predicate, p.children,
		p.inputLevel, p.outputLevel, p.parameter, p.prefix, p.protocolRange, p.tree,
		p.schedule, p.operandSource, p.ingressProfile, p.ingressSource, p.ingressRange,
		p.ingressAdmission, p.ingressSuffix, p.ingressKey, p.ingressSpecialB0,
		p.ingressMask, p.ingressFirstSTC, p.ingressSharedCTS, p.ingressSecondSTC,
		p.signProfile, p.signSource, p.signCompiled, p.arithmeticOne, p.counts,
		p.requiredGalois, p.relinearization, digestSigned8Depth2ChildStates(p.expectedStates),
		p.expectedBytes, p.levelLedger,
	))
}

func digestSigned8Depth2ChildStates(states []Signed8Depth2ChildComparatorState) string {
	var builder strings.Builder
	for _, state := range states {
		fmt.Fprintf(&builder, "%s/L%d/D%d/dim=%d,%d/scale=%s/bytes=%d;", state.Stage,
			state.Level, state.Degree, state.LogDimensions.Rows, state.LogDimensions.Cols,
			state.Scale.canonicalString(), state.SerializedBytes)
	}
	return builder.String()
}

func equalSigned8Depth2ChildGalois(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneSigned8Depth2ChildOperands(input Signed8Depth2Operands) Signed8Depth2Operands {
	input.feature = copyA2BRefreshCiphertext(input.feature)
	input.threshold = copyA2BRefreshCiphertext(input.threshold)
	input.conditionedSelector = copyA2BRefreshCiphertext(input.conditionedSelector)
	return input
}

func digestSigned8Depth2ChildComparatorInput(input Signed8Depth2ChildComparatorInput) string {
	operands := input.operands
	return digestString(fmt.Sprintf(
		"%s|profile=%s|operands-provenance=%s|source=%d|parameter=%s|range=%s|tree=%s|schedule=%s|selector=%s|producer=%s|conditioner=%s|selector-input=%s|feature-input=%s,%s|feature-payload=%s|threshold-payload=%s|selector-payload=%s",
		signed8Depth2ChildComparatorInputSchema, input.profileDigest, input.operandsProvenance,
		operands.sourceKind, operands.parameterDigest, operands.rangeDigest, operands.treeDigest,
		operands.scheduleDigest, operands.selectorProfileDigest, operands.producerProfileDigest,
		operands.conditionerProfileDigest, operands.selectorInputProvenanceDigest,
		operands.featureInputPayloadDigests[0], operands.featureInputPayloadDigests[1],
		operands.featurePayloadDigest, operands.thresholdPayloadDigest,
		operands.conditionedSelectorPayloadDigest,
	))
}

func snapshotSigned8Depth2ChildState(
	stage Signed8Depth2ChildComparatorStage,
	ciphertext *rlwe.Ciphertext,
) (Signed8Depth2ChildComparatorState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return Signed8Depth2ChildComparatorState{}, fmt.Errorf("homchain: cannot snapshot nil depth2 child %s", stage)
	}
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return Signed8Depth2ChildComparatorState{}, err
	}
	bytes, err := marshalCiphertextSize(string(stage), ciphertext)
	if err != nil {
		return Signed8Depth2ChildComparatorState{}, err
	}
	return Signed8Depth2ChildComparatorState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale, SerializedBytes: bytes,
	}, nil
}

func signed8Depth2ChildBytesFromStates(
	states []Signed8Depth2ChildComparatorState,
) Signed8Depth2ChildComparatorSerializedBytes {
	result := Signed8Depth2ChildComparatorSerializedBytes{}
	for _, state := range states {
		switch state.Stage {
		case Signed8Depth2ChildStageFeature:
			result.Feature = state.SerializedBytes
		case Signed8Depth2ChildStageThreshold:
			result.Threshold = state.SerializedBytes
		case Signed8Depth2ChildStageDifference:
			result.Difference = state.SerializedBytes
		case Signed8Depth2ChildStageIngressHigh:
			result.IngressHigh = state.SerializedBytes
		case Signed8Depth2ChildStageArithmeticSign:
			result.ArithmeticSign = state.SerializedBytes
		case Signed8Depth2ChildStageNegatedSign:
			result.NegatedSign = state.SerializedBytes
		case Signed8Depth2ChildStageGreaterEqual:
			result.GreaterEqualOutput = state.SerializedBytes
		}
	}
	return result
}

func validateSigned8Depth2ChildIngressEvidence(
	circuit *Signed8Depth2ChildComparatorCircuit,
	input A2BFullIngress6Input,
	high *rlwe.Ciphertext,
	trace A2BFullIngress6Trace,
) error {
	if circuit == nil || high == nil {
		return fmt.Errorf("homchain: nil depth2 child ingress evidence")
	}
	profile := circuit.ingress.profile
	if trace.profileDigest != profile.digest || trace.rangeDigest != profile.rangeDigest ||
		trace.admissionDigest != profile.admissionDigest || trace.inputBindingDigest != input.bindingDigest ||
		trace.failureStage != "" || trace.operationCounts != profile.operationCounts ||
		!reflect.DeepEqual(trace.states, profile.expectedStates) ||
		!reflect.DeepEqual(trace.serializedBytes, profile.serializedBytes) ||
		!equalSigned8Depth2ChildGalois(trace.runtimeGalois, circuit.keyProfile.all) ||
		!trace.relinearizationKeyMatched {
		return fmt.Errorf("homchain: depth2 child ingress runtime evidence changed")
	}
	preflight := trace.keyPreflight
	if !preflight.Checked || !preflight.GraphChecked || !preflight.GraphMatched || preflight.GraphMismatch != "" ||
		len(preflight.MissingGaloisElements) != 0 || len(preflight.InvalidGaloisElements) != 0 ||
		len(preflight.UnexpectedGaloisElements) != 0 || !preflight.RelinearizationPresent ||
		!preflight.RelinearizationMatched || !preflight.DenseNoSwitchingMatched {
		return fmt.Errorf("homchain: depth2 child ingress key preflight evidence changed")
	}
	retained, ok := trace.retainedCiphertexts[A2BFullIngress6StageIter1MSB]
	if !ok || retained == nil || !retained.Equal(high) {
		return fmt.Errorf("homchain: depth2 child ingress high output differs from retained runtime evidence")
	}
	kernelDigests := circuit.ingress.suffix.profile.KernelProfileDigests()
	for iteration := 0; iteration < 2; iteration++ {
		provenance, present := trace.KernelProvenance(iteration)
		if !present || provenance.ProfileDigest() != kernelDigests[iteration] {
			return fmt.Errorf("homchain: depth2 child ingress kernel %d evidence changed", iteration)
		}
	}
	return nil
}

func validateSigned8Depth2ChildSignEvidence(
	circuit *Signed8Depth2ChildComparatorCircuit,
	high, sign *rlwe.Ciphertext,
	provenance SignFusionProvenance,
) error {
	if circuit == nil || high == nil || sign == nil {
		return fmt.Errorf("homchain: nil depth2 child sign evidence")
	}
	profile := circuit.sign.profile
	if provenance.profileDigest != profile.digest || provenance.sourceDigest != profile.sourceDigest ||
		provenance.compiledDigest != profile.compiledDigest || provenance.counts != profile.operationCounts {
		return fmt.Errorf("homchain: depth2 child sign provenance changed")
	}
	if err := circuit.sign.validateInputCiphertext(high); err != nil {
		return err
	}
	if err := requireSigned8Depth2State("depth2 child arithmetic sign", sign, 4, circuit.params.DefaultScale(), circuit.params); err != nil {
		return err
	}
	states := provenance.states
	if len(states) != 3 || states[0].Stage != SignFusionStageHighBooleanInput ||
		states[1].Stage != SignFusionStageRankOneLinear || states[2].Stage != SignFusionStageArithmeticSign ||
		states[0].Level != 5 || states[1].Level != 5 || states[2].Level != 4 ||
		states[0].Degree != 1 || states[1].Degree != 1 || states[2].Degree != 1 ||
		states[0].LogDimensions != circuit.params.LogMaxDimensions() ||
		states[1].LogDimensions != circuit.params.LogMaxDimensions() ||
		states[2].LogDimensions != circuit.params.LogMaxDimensions() ||
		profile.inputScale != states[0].Scale || profile.outputScale != states[2].Scale {
		return fmt.Errorf("homchain: depth2 child sign ordered states changed")
	}
	return nil
}

func cloneSigned8Depth2ChildIngressTrace(trace A2BFullIngress6Trace) A2BFullIngress6Trace {
	result := trace
	result.states = append([]A2BFullIngress6CiphertextState(nil), trace.states...)
	result.keyPreflight = cloneA2BRefreshKeyPreflight(trace.keyPreflight)
	result.runtimeGalois = append([]uint64(nil), trace.runtimeGalois...)
	result.serializedBytes = cloneA2BFullIngress6SerializedBytes(trace.serializedBytes)
	if trace.retainedCiphertexts != nil {
		result.retainedCiphertexts = make(map[A2BFullIngress6Stage]*rlwe.Ciphertext, len(trace.retainedCiphertexts))
		for stage, ciphertext := range trace.retainedCiphertexts {
			result.retainedCiphertexts[stage] = copyA2BRefreshCiphertext(ciphertext)
		}
	}
	result.iter0Kernel = cloneSigned8KernelProvenance(trace.iter0Kernel)
	result.iter1Kernel = cloneSigned8KernelProvenance(trace.iter1Kernel)
	return result
}

func digestSigned8Depth2ChildIngressTrace(trace A2BFullIngress6Trace) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "depth2-child-ingress-trace-v1|profile=%s|range=%s|admission=%s|input=%s|failure=%s|counts=%+v|keys=%v|relin=%t|bytes=%+v",
		trace.profileDigest, trace.rangeDigest, trace.admissionDigest, trace.inputBindingDigest,
		trace.failureStage, trace.operationCounts, trace.runtimeGalois, trace.relinearizationKeyMatched,
		trace.serializedBytes)
	for _, state := range trace.states {
		fmt.Fprintf(&builder, "|state=%s/L%d/D%d/dim=%d,%d/scale=%s/bytes=%d", state.Stage,
			state.Level, state.Degree, state.LogDimensions.Rows, state.LogDimensions.Cols,
			state.Scale.canonicalString(), state.SerializedBytes)
	}
	for iteration := 0; iteration < 2; iteration++ {
		if provenance, ok := trace.KernelProvenance(iteration); ok {
			fmt.Fprintf(&builder, "|kernel%d=%s/%+v", iteration, provenance.ProfileDigest(), provenance.OperationCounts())
		}
	}
	return digestString(builder.String())
}

func digestSigned8Depth2ChildSignProvenance(provenance SignFusionProvenance) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "depth2-child-sign-trace-v1|profile=%s|source=%s|compiled=%s|counts=%+v",
		provenance.profileDigest, provenance.sourceDigest, provenance.compiledDigest, provenance.counts)
	for _, state := range provenance.states {
		fmt.Fprintf(&builder, "|state=%s/L%d/D%d/dim=%d,%d/scale=%s", state.Stage,
			state.Level, state.Degree, state.LogDimensions.Rows, state.LogDimensions.Cols,
			state.Scale.canonicalString())
	}
	return digestString(builder.String())
}

func digestSigned8Depth2ChildComparatorResult(result Signed8Depth2ChildComparatorResult) string {
	return digestString(fmt.Sprintf(
		"depth2-child-result-v1|profile=%s|parameters=%s|protocol-range=%s|tree=%s|schedule=%s|input=%s|operands=%s|ingress-profile=%s|ingress-range=%s|ingress-admission=%s|ingress-input=%s|ingress-trace=%s|sign-profile=%s|sign-source=%s|sign-compiled=%s|sign-trace=%s|output=%s",
		result.profileDigest, result.parameterDigest, result.protocolRangeDigest, result.treeDigest,
		result.scheduleDigest, result.inputBindingDigest, result.operandsProvenanceDigest,
		result.ingressProfileDigest, result.ingressRangeDigest, result.ingressAdmissionDigest,
		result.ingressInputBindingDigest, result.ingressTraceDigest, result.signProfileDigest,
		result.signSourceDigest, result.signCompiledDigest, result.signTraceDigest,
		result.outputPayloadDigest,
	))
}

func digestSigned8Depth2ChildComparatorTrace(trace Signed8Depth2ChildComparatorTrace) string {
	return digestString(fmt.Sprintf(
		"depth2-child-wrapper-trace-v1|profile=%s|input=%s|operands=%s|result=%s|failure=%s|counts=%+v|states=%s|ingress=%s|sign=%s|key-preflight=%+v|keys=%v|relin=%t|bytes=%+v",
		trace.profileDigest, trace.inputBindingDigest, trace.operandsProvenanceDigest,
		trace.resultProvenanceDigest, trace.failureStage, trace.counts,
		digestSigned8Depth2ChildStates(trace.states), digestSigned8Depth2ChildIngressTrace(trace.ingressTrace),
		digestSigned8Depth2ChildSignProvenance(trace.signProvenance), trace.keyPreflight, trace.runtimeGalois,
		trace.relinearizationMatched, trace.serializedBytes,
	))
}
