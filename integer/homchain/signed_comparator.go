package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"time"

	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	signed8NoOverflowRangeDigestSchema = "signed8-no-overflow-range-v1"
	signed8ComparatorProfileSchema     = "signed8-ge-comparator-profile-v1"
	signed8InputBindingSchema          = "signed8-comparator-input-binding-v1"
	signed8InputProvenanceSchema       = "signed8-input-provenance-v2"
	signed8Words                       = 4
	signed8Slots                       = 16
	signed8RefreshEncoderPrecision     = uint(192)
	signed8IntegerEncoderPrecision     = uint(256)
	signed8InputLevel                  = 20
	signed8SignInputLevel              = 5
	signed8OutputLevel                 = 4
	signed8AcceptedA2BProfileDigest    = "d9c156fb3347daa8a10976b04c69a118f4b07cd34b4b6f4d92b1d71c133dfc90"
	signed8AcceptedSecondRawSTCDigest  = "b40ce04fb171af270ea77e0142bd7d695c58e670e733e5e09eab97a4cd2a854e"
	signed8AcceptedSecondExecSTCDigest = "6381e519b59a10832ad615399b29b416941c8c7185bff9a7802dc06418395ae0"
	signed8AcceptedSecondSTCDigest     = "b4d1cb37cf6cb73f9f3411266a04d3b9686064d56492f0cda01a691f6245b882"
	signed8AcceptedSignParameterDigest = "085e0a9b826d469ac5514d3db988672f41ab0a4f1bb2fe82705842226a8eacc2"
	signed8AcceptedSignSourceDigest    = "c5bda437c079d1b60671cf2909460a3f2a0f29d0bef81bacb4fa8d2dd147849f"
	signed8AcceptedSignCompiledDigest  = "da9827044a8ee1f07769b47fff01213e23f6ea5e7d644f6dd03fd133d8031b0b"
	signed8AcceptedSignProfileDigest   = "68b3bcc5edd24e7e2aeefbf184534b750a3d94506cbf10afb1839ebed474a4ae"
	signed8ComparatorLevelLedger       = "feature/threshold-L20->difference-L20->serial-A2B-high-L5->rank-one-sign-L4->negate-L4->add-arithmetic-root-one-L4"
	signed8TrustedAdmissionAssumption  = "trusted_declared_source_plus_encoder_or_protocol_admission_not_a_cryptographic_origin_or_range_proof"
)

// Signed8Signedness fixes the only representation admitted by this circuit.
type Signed8Signedness string

const Signed8TwosComplement Signed8Signedness = "twos_complement"

// Signed8ComparatorPredicate fixes the branch predicate returned by the
// comparator.
type Signed8ComparatorPredicate string

const Signed8GreaterThanOrEqual Signed8ComparatorPredicate = "ge"

// Signed8ChildConvention fixes the tree branch orientation.
type Signed8ChildConvention string

const Signed8ZeroLTOneGE Signed8ChildConvention = "0=lt,1=ge"

// Signed8RangeProofStatus identifies how the subtraction interval was proved.
type Signed8RangeProofStatus string

const Signed8InternallyDerivedEndpointInterval Signed8RangeProofStatus = "internally_derived_endpoint_interval"

// Signed8OverflowContract fixes same-width subtraction whose mathematical
// result remains representable in signed eight-bit two's complement.
type Signed8OverflowContract string

const Signed8SameWidthSubtractionNoOverflow Signed8OverflowContract = "same_width_subtraction_no_overflow"

// Signed8NoOverflowRange is an opaque, self-authenticating range certificate.
// Its source endpoints and derived subtraction endpoints are intentionally
// private so callers cannot assemble partially valid evidence.
type Signed8NoOverflowRange struct {
	xMin          int64
	xMax          int64
	tMin          int64
	tMax          int64
	differenceMin int64
	differenceMax int64
	wordBits      z2n.WordBits
	signedness    Signed8Signedness
	predicate     Signed8ComparatorPredicate
	children      Signed8ChildConvention
	proofStatus   Signed8RangeProofStatus
	overflow      Signed8OverflowContract
	digest        string
}

func (r Signed8NoOverflowRange) XMinimum() int64          { return r.xMin }
func (r Signed8NoOverflowRange) XMaximum() int64          { return r.xMax }
func (r Signed8NoOverflowRange) ThresholdMinimum() int64  { return r.tMin }
func (r Signed8NoOverflowRange) ThresholdMaximum() int64  { return r.tMax }
func (r Signed8NoOverflowRange) DifferenceMinimum() int64 { return r.differenceMin }
func (r Signed8NoOverflowRange) DifferenceMaximum() int64 { return r.differenceMax }
func (r Signed8NoOverflowRange) WordBits() z2n.WordBits   { return r.wordBits }
func (r Signed8NoOverflowRange) Signedness() Signed8Signedness {
	return r.signedness
}
func (r Signed8NoOverflowRange) Predicate() Signed8ComparatorPredicate { return r.predicate }
func (r Signed8NoOverflowRange) ChildConvention() Signed8ChildConvention {
	return r.children
}
func (r Signed8NoOverflowRange) ProofStatus() Signed8RangeProofStatus { return r.proofStatus }
func (r Signed8NoOverflowRange) OverflowContract() Signed8OverflowContract {
	return r.overflow
}
func (r Signed8NoOverflowRange) DigestSchema() string { return signed8NoOverflowRangeDigestSchema }
func (r Signed8NoOverflowRange) Digest() string       { return r.digest }

// NewSigned8NoOverflowRange constructs the fixed signed-eight-bit range
// certificate. All derived endpoints are evaluated with big.Int so host
// integer overflow can never become range evidence.
func NewSigned8NoOverflowRange(xMin, xMax, tMin, tMax int64) (Signed8NoOverflowRange, error) {
	if xMin > xMax {
		return Signed8NoOverflowRange{}, fmt.Errorf("homchain: signed8 feature range is reversed: [%d,%d]", xMin, xMax)
	}
	if tMin > tMax {
		return Signed8NoOverflowRange{}, fmt.Errorf("homchain: signed8 threshold range is reversed: [%d,%d]", tMin, tMax)
	}

	signedMinimum := big.NewInt(-128)
	signedMaximum := big.NewInt(127)
	for _, candidate := range []struct {
		label    string
		endpoint int64
	}{
		{label: "feature minimum", endpoint: xMin},
		{label: "feature maximum", endpoint: xMax},
		{label: "threshold minimum", endpoint: tMin},
		{label: "threshold maximum", endpoint: tMax},
	} {
		label, endpoint := candidate.label, candidate.endpoint
		value := new(big.Int).SetInt64(endpoint)
		if value.Cmp(signedMinimum) < 0 || value.Cmp(signedMaximum) > 0 {
			return Signed8NoOverflowRange{}, fmt.Errorf("homchain: signed8 %s=%s lies outside [-128,127]", label, value.String())
		}
	}

	differenceMin := new(big.Int).Sub(new(big.Int).SetInt64(xMin), new(big.Int).SetInt64(tMax))
	differenceMax := new(big.Int).Sub(new(big.Int).SetInt64(xMax), new(big.Int).SetInt64(tMin))
	if differenceMin.Cmp(signedMinimum) < 0 || differenceMax.Cmp(signedMaximum) > 0 {
		return Signed8NoOverflowRange{}, fmt.Errorf(
			"homchain: signed8 subtraction interval [%s,%s] is not contained in [-128,127]",
			differenceMin.String(), differenceMax.String(),
		)
	}

	certificate := Signed8NoOverflowRange{
		xMin: xMin, xMax: xMax, tMin: tMin, tMax: tMax,
		differenceMin: differenceMin.Int64(), differenceMax: differenceMax.Int64(),
		wordBits: z2n.Word8, signedness: Signed8TwosComplement,
		predicate: Signed8GreaterThanOrEqual, children: Signed8ZeroLTOneGE,
		proofStatus: Signed8InternallyDerivedEndpointInterval,
		overflow:    Signed8SameWidthSubtractionNoOverflow,
	}
	certificate.digest = digestSigned8NoOverflowRange(certificate)
	return certificate, nil
}

func validateSigned8NoOverflowRange(ranges Signed8NoOverflowRange) error {
	expected, err := NewSigned8NoOverflowRange(ranges.xMin, ranges.xMax, ranges.tMin, ranges.tMax)
	if err != nil {
		return fmt.Errorf("homchain: invalid signed8 no-overflow range evidence: %w", err)
	}
	if ranges != expected {
		return fmt.Errorf("homchain: signed8 no-overflow range metadata or digest does not match internally derived evidence")
	}
	return nil
}

func digestSigned8NoOverflowRange(ranges Signed8NoOverflowRange) string {
	payload := fmt.Sprintf(
		"%s|x_min=%d|x_max=%d|t_min=%d|t_max=%d|difference_min=%d|difference_max=%d|word_bits=%d|signedness=%s|predicate=%s|child_convention=%s|proof_status=%s|overflow_contract=%s",
		signed8NoOverflowRangeDigestSchema,
		ranges.xMin, ranges.xMax, ranges.tMin, ranges.tMax,
		ranges.differenceMin, ranges.differenceMax, ranges.wordBits,
		ranges.signedness, ranges.predicate, ranges.children, ranges.proofStatus, ranges.overflow,
	)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:])
}

// Signed8ComparatorFidelity names the deliberately bounded local composition.
type Signed8ComparatorFidelity string

const Signed8ComparatorLattigoFunctionalComposition Signed8ComparatorFidelity = "lattigo_functional_composition"

// Signed8ComparatorMaturity prevents the tiny exact functional parameter set
// from being described as a secure deployment profile.
type Signed8ComparatorMaturity string

const Signed8ComparatorFunctionalNotSecure Signed8ComparatorMaturity = "functional_not_secure"

// Signed8ComparatorOperandMode keeps public CT--PT and opaque CT--CT threshold
// evaluation distinct in profiles and measurements.
type Signed8ComparatorOperandMode string

const (
	Signed8PublicThresholdCTPT Signed8ComparatorOperandMode = "ct_pt_public_threshold"
	Signed8OpaqueThresholdCTCT Signed8ComparatorOperandMode = "ct_ct_opaque_threshold"
)

// Signed8ComparatorStage identifies every wrapper-owned ciphertext boundary.
type Signed8ComparatorStage string

const (
	Signed8StageFeatureInput   Signed8ComparatorStage = "feature-input"
	Signed8StageThresholdInput Signed8ComparatorStage = "opaque-threshold-input"
	Signed8StageDifference     Signed8ComparatorStage = "arithmetic-difference"
	Signed8StageHighMSB        Signed8ComparatorStage = "serial-a2b-high-msb"
	Signed8StageArithmeticSign Signed8ComparatorStage = "arithmetic-sign-b7"
	Signed8StageNegatedSign    Signed8ComparatorStage = "negated-arithmetic-sign"
	Signed8StageGreaterEqual   Signed8ComparatorStage = "right-branch-ge"
)

// Signed8ComparatorCiphertextState is a detached exact state snapshot.
type Signed8ComparatorCiphertextState struct {
	Stage         Signed8ComparatorStage
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

// Signed8ComparatorStateProfile fixes an expected ciphertext boundary.
type Signed8ComparatorStateProfile struct {
	level         int
	degree        int
	logDimensions ring.Dimensions
	scale         ExactScaleSnapshot
}

func (p Signed8ComparatorStateProfile) Level() int                     { return p.level }
func (p Signed8ComparatorStateProfile) Degree() int                    { return p.degree }
func (p Signed8ComparatorStateProfile) LogDimensions() ring.Dimensions { return p.logDimensions }
func (p Signed8ComparatorStateProfile) Scale() ExactScaleSnapshot      { return p.scale }

// Signed8ComparatorWrapperOperationCounts records only wrapper-native
// homomorphic operations. Child ledgers remain nested and separately checked.
type Signed8ComparatorWrapperOperationCounts struct {
	CiphertextPlaintextSubtractions    int
	CiphertextCiphertextSubtractions   int
	Negations                          int
	CiphertextPlaintextVectorAdditions int
}

// Signed8ComparatorSetupCounts separates encodings and internal refresh calls
// from the homomorphic-operation ledger.
type Signed8ComparatorSetupCounts struct {
	CachedArithmeticOneEncodings        int
	PerEvaluationThresholdEncodings     int
	InternalSerialA2BRefreshInvocations int
}

// Signed8ComparatorProfile is an immutable projection of one threshold mode.
type Signed8ComparatorProfile struct {
	fidelity                   Signed8ComparatorFidelity
	maturity                   Signed8ComparatorMaturity
	operandMode                Signed8ComparatorOperandMode
	wordBits                   z2n.WordBits
	words                      int
	slots                      int
	refreshEncoderPrecision    uint
	integerEncoderPrecision    uint
	predicate                  Signed8ComparatorPredicate
	childConvention            Signed8ChildConvention
	bindingAssumption          string
	rangeDigest                string
	parameterDigest            string
	inputBindingDigest         string
	a2bProfileDigest           string
	a2bKeyProfileDigest        string
	a2bKernelProfileDigests    [2]string
	signParameterDigest        string
	signSourceDigest           string
	signCompiledDigest         string
	signProfileDigest          string
	arithmeticOnePayloadDigest string
	inputState                 Signed8ComparatorStateProfile
	differenceState            Signed8ComparatorStateProfile
	highMSBState               Signed8ComparatorStateProfile
	signState                  Signed8ComparatorStateProfile
	outputState                Signed8ComparatorStateProfile
	wrapperCounts              Signed8ComparatorWrapperOperationCounts
	a2bCounts                  A2BFullOperationCounts
	kernelCounts               [2]GaoA2BKernelOperationCounts
	signCounts                 SignFusionOperationCounts
	setupCounts                Signed8ComparatorSetupCounts
	wrapperPeakLive            int
	requiredGaloisElements     []uint64
	relinearizationRequired    bool
	levelLedger                string
	normalizedCertified        bool
	digest                     string
}

func (p Signed8ComparatorProfile) DigestSchema() string                      { return signed8ComparatorProfileSchema }
func (p Signed8ComparatorProfile) Fidelity() Signed8ComparatorFidelity       { return p.fidelity }
func (p Signed8ComparatorProfile) Maturity() Signed8ComparatorMaturity       { return p.maturity }
func (p Signed8ComparatorProfile) OperandMode() Signed8ComparatorOperandMode { return p.operandMode }
func (p Signed8ComparatorProfile) WordBits() z2n.WordBits                    { return p.wordBits }
func (p Signed8ComparatorProfile) Words() int                                { return p.words }
func (p Signed8ComparatorProfile) Slots() int                                { return p.slots }
func (p Signed8ComparatorProfile) RefreshEncoderPrecision() uint             { return p.refreshEncoderPrecision }
func (p Signed8ComparatorProfile) IntegerEncoderPrecision() uint             { return p.integerEncoderPrecision }
func (p Signed8ComparatorProfile) Predicate() Signed8ComparatorPredicate     { return p.predicate }
func (p Signed8ComparatorProfile) ChildConvention() Signed8ChildConvention   { return p.childConvention }
func (p Signed8ComparatorProfile) BindingAssumption() string                 { return p.bindingAssumption }
func (p Signed8ComparatorProfile) RangeDigest() string                       { return p.rangeDigest }
func (p Signed8ComparatorProfile) ParameterDigest() string                   { return p.parameterDigest }
func (p Signed8ComparatorProfile) InputBindingDigest() string                { return p.inputBindingDigest }
func (p Signed8ComparatorProfile) A2BProfileDigest() string                  { return p.a2bProfileDigest }
func (p Signed8ComparatorProfile) A2BKeyProfileDigest() string               { return p.a2bKeyProfileDigest }
func (p Signed8ComparatorProfile) A2BKernelProfileDigests() [2]string {
	return p.a2bKernelProfileDigests
}
func (p Signed8ComparatorProfile) SignParameterDigest() string { return p.signParameterDigest }
func (p Signed8ComparatorProfile) SignSourceDigest() string    { return p.signSourceDigest }
func (p Signed8ComparatorProfile) SignCompiledDigest() string  { return p.signCompiledDigest }
func (p Signed8ComparatorProfile) SignProfileDigest() string   { return p.signProfileDigest }
func (p Signed8ComparatorProfile) ArithmeticOnePayloadDigest() string {
	return p.arithmeticOnePayloadDigest
}
func (p Signed8ComparatorProfile) InputState() Signed8ComparatorStateProfile { return p.inputState }
func (p Signed8ComparatorProfile) DifferenceState() Signed8ComparatorStateProfile {
	return p.differenceState
}
func (p Signed8ComparatorProfile) HighMSBState() Signed8ComparatorStateProfile { return p.highMSBState }
func (p Signed8ComparatorProfile) SignState() Signed8ComparatorStateProfile    { return p.signState }
func (p Signed8ComparatorProfile) OutputState() Signed8ComparatorStateProfile  { return p.outputState }
func (p Signed8ComparatorProfile) WrapperOperationCounts() Signed8ComparatorWrapperOperationCounts {
	return p.wrapperCounts
}
func (p Signed8ComparatorProfile) SerialA2BOperationCounts() A2BFullOperationCounts {
	return p.a2bCounts
}
func (p Signed8ComparatorProfile) KernelOperationCounts() [2]GaoA2BKernelOperationCounts {
	return p.kernelCounts
}
func (p Signed8ComparatorProfile) SignOperationCounts() SignFusionOperationCounts {
	return p.signCounts
}
func (p Signed8ComparatorProfile) SetupCounts() Signed8ComparatorSetupCounts { return p.setupCounts }
func (p Signed8ComparatorProfile) WrapperLogicalPeakLiveCiphertexts() int    { return p.wrapperPeakLive }
func (p Signed8ComparatorProfile) RequiredGaloisElements() []uint64 {
	return append([]uint64(nil), p.requiredGaloisElements...)
}
func (p Signed8ComparatorProfile) RequiresRelinearization() bool  { return p.relinearizationRequired }
func (p Signed8ComparatorProfile) LevelLedger() string            { return p.levelLedger }
func (p Signed8ComparatorProfile) NormalizedInputCertified() bool { return p.normalizedCertified }
func (p Signed8ComparatorProfile) Digest() string                 { return p.digest }

func cloneSigned8ComparatorProfile(profile Signed8ComparatorProfile) Signed8ComparatorProfile {
	result := profile
	result.requiredGaloisElements = profile.RequiredGaloisElements()
	return result
}

type signed8InputRole string

const (
	signed8FeatureRole   signed8InputRole = "feature"
	signed8ThresholdRole signed8InputRole = "opaque-threshold"
)

// Signed8FeatureInput is the opaque arithmetic-root-slot feature handle.
type Signed8FeatureInput struct {
	ciphertext            *rlwe.Ciphertext
	role                  signed8InputRole
	profileDigest         string
	rangeDigest           string
	sourceParameterDigest string
	payloadDigest         string
	provenanceDigest      string
}

// Signed8OpaqueThresholdInput is the opaque arithmetic-root-slot threshold
// handle. It is distinct from the public-threshold path by construction.
type Signed8OpaqueThresholdInput struct {
	ciphertext            *rlwe.Ciphertext
	role                  signed8InputRole
	profileDigest         string
	rangeDigest           string
	sourceParameterDigest string
	payloadDigest         string
	provenanceDigest      string
}

// Signed8ComparatorResult owns the encrypted arithmetic-root-slot GE branch.
type Signed8ComparatorResult struct {
	branch        *rlwe.Ciphertext
	profileDigest string
	rangeDigest   string
	operandMode   Signed8ComparatorOperandMode
}

func (r Signed8ComparatorResult) Ciphertext() *rlwe.Ciphertext {
	if r.branch == nil {
		return nil
	}
	return r.branch.CopyNew()
}
func (r Signed8ComparatorResult) ProfileDigest() string                     { return r.profileDigest }
func (r Signed8ComparatorResult) RangeDigest() string                       { return r.rangeDigest }
func (r Signed8ComparatorResult) OperandMode() Signed8ComparatorOperandMode { return r.operandMode }

// Signed8ComparatorSerializedBytes records measured boundary serialization
// sizes without flattening private child scratch buffers into a fabricated sum.
type Signed8ComparatorSerializedBytes struct {
	Feature            int
	ThresholdOperand   int
	Difference         int
	HighMSB            int
	ArithmeticSign     int
	GreaterEqualOutput int
}

// Signed8ComparatorTrace contains wrapper states and detached child evidence.
type Signed8ComparatorTrace struct {
	profileDigest          string
	rangeDigest            string
	operandMode            Signed8ComparatorOperandMode
	thresholdOperandDigest string
	arithmeticOneDigest    string
	states                 []Signed8ComparatorCiphertextState
	wrapperCounts          Signed8ComparatorWrapperOperationCounts
	a2bTrace               A2BFullTrace
	signProvenance         SignFusionProvenance
	keyPreflight           A2BRefreshKeyPreflight
	serializedBytes        Signed8ComparatorSerializedBytes
	wrapperPeakLive        int
	wallTime               time.Duration
}

func (t Signed8ComparatorTrace) ProfileDigest() string                     { return t.profileDigest }
func (t Signed8ComparatorTrace) RangeDigest() string                       { return t.rangeDigest }
func (t Signed8ComparatorTrace) OperandMode() Signed8ComparatorOperandMode { return t.operandMode }
func (t Signed8ComparatorTrace) ThresholdOperandDigest() string            { return t.thresholdOperandDigest }
func (t Signed8ComparatorTrace) ArithmeticOnePayloadDigest() string        { return t.arithmeticOneDigest }
func (t Signed8ComparatorTrace) States() []Signed8ComparatorCiphertextState {
	return append([]Signed8ComparatorCiphertextState(nil), t.states...)
}
func (t Signed8ComparatorTrace) State(stage Signed8ComparatorStage) (Signed8ComparatorCiphertextState, bool) {
	for _, state := range t.states {
		if state.Stage == stage {
			return state, true
		}
	}
	return Signed8ComparatorCiphertextState{}, false
}
func (t Signed8ComparatorTrace) WrapperOperationCounts() Signed8ComparatorWrapperOperationCounts {
	return t.wrapperCounts
}
func (t Signed8ComparatorTrace) SerialA2BTrace() A2BFullTrace {
	return cloneSigned8A2BTrace(t.a2bTrace)
}
func (t Signed8ComparatorTrace) SignProvenance() SignFusionProvenance {
	return cloneSigned8SignProvenance(t.signProvenance)
}
func (t Signed8ComparatorTrace) KeyPreflight() A2BRefreshKeyPreflight {
	return cloneA2BRefreshKeyPreflight(t.keyPreflight)
}
func (t Signed8ComparatorTrace) SerializedBytes() Signed8ComparatorSerializedBytes {
	return t.serializedBytes
}
func (t Signed8ComparatorTrace) WrapperLogicalPeakLiveCiphertexts() int { return t.wrapperPeakLive }
func (t Signed8ComparatorTrace) WallTime() time.Duration                { return t.wallTime }

type signed8ComparatorCircuitGraphIdentity struct {
	circuit         *Signed8ComparatorCircuit
	refreshEncoder  *ckks.Encoder
	integerEncoder  *ckks.Encoder
	a2b             *A2BFullCircuit
	sign            *SignFusionCircuit
	one             *rlwe.Plaintext
	oneSeal         *rlwe.Plaintext
	oneDigest       string
	parameterDigest string
	publicDigest    string
	opaqueDigest    string
	bindingDigest   string
}

// Signed8ComparatorCircuit owns the accepted serial A2B, direct sign fusion,
// and the high-precision arithmetic-root-slot word-one plaintext.
type Signed8ComparatorCircuit struct {
	params              ckks.Parameters
	refreshEncoder      *ckks.Encoder
	integerEncoder      *ckks.Encoder
	ranges              Signed8NoOverflowRange
	a2b                 *A2BFullCircuit
	sign                *SignFusionCircuit
	arithmeticOne       *rlwe.Plaintext
	arithmeticOneSeal   *rlwe.Plaintext
	arithmeticOneDigest string
	parameterDigest     string
	bindingDigest       string
	publicProfile       Signed8ComparatorProfile
	opaqueProfile       Signed8ComparatorProfile
	graph               signed8ComparatorCircuitGraphIdentity
}

func (c *Signed8ComparatorCircuit) PublicProfile() Signed8ComparatorProfile {
	if c == nil {
		return Signed8ComparatorProfile{}
	}
	return cloneSigned8ComparatorProfile(c.publicProfile)
}
func (c *Signed8ComparatorCircuit) OpaqueProfile() Signed8ComparatorProfile {
	if c == nil {
		return Signed8ComparatorProfile{}
	}
	return cloneSigned8ComparatorProfile(c.opaqueProfile)
}
func (c *Signed8ComparatorCircuit) Ranges() Signed8NoOverflowRange {
	if c == nil {
		return Signed8NoOverflowRange{}
	}
	return c.ranges
}

type signed8ComparatorEvaluatorGraphIdentity struct {
	circuit       *Signed8ComparatorCircuit
	source        *bootstrapping.Evaluator
	sourceCKKS    *ckks.Evaluator
	signSource    *ckks.Evaluator
	keySet        *rlwe.MemEvaluationKeySet
	a2b           *A2BFullEvaluator
	sign          *SignFusionEvaluator
	publicDigest  string
	opaqueDigest  string
	bindingDigest string
}

// Signed8ComparatorEvaluator binds both children to one exact bootstrapping
// evaluator and one MemEvaluationKeySet.
type Signed8ComparatorEvaluator struct {
	circuit            *Signed8ComparatorCircuit
	source             *bootstrapping.Evaluator
	signSource         *ckks.Evaluator
	a2b                *A2BFullEvaluator
	sign               *SignFusionEvaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	galoisKeys         map[uint64]*rlwe.GaloisKey
	graph              signed8ComparatorEvaluatorGraphIdentity
}

// NewSigned8ComparatorCircuit seals both accepted child profiles and the
// arithmetic-root-slot complement operand.
func NewSigned8ComparatorCircuit(
	params ckks.Parameters,
	refreshEncoder *ckks.Encoder,
	integerEncoder *ckks.Encoder,
	ranges Signed8NoOverflowRange,
) (*Signed8ComparatorCircuit, error) {
	if err := validateSigned8NoOverflowRange(ranges); err != nil {
		return nil, err
	}
	if err := validateA2BRefreshParameters(params); err != nil {
		return nil, err
	}
	if err := validateSigned8ComparatorEncoders(params, refreshEncoder, integerEncoder); err != nil {
		return nil, err
	}
	a2b, err := NewA2BFullCircuit(params, refreshEncoder, integerEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct signed8 serial A2B child: %w", err)
	}
	sign, err := NewSignFusionCircuit(params, integerEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct signed8 sign-fusion child: %w", err)
	}
	if err = validateSigned8AcceptedChildren(a2b, sign); err != nil {
		return nil, err
	}
	one, err := newSigned8WordPlaintext(params, integerEncoder, signed8IntegerEncoderPrecision, signed8OutputLevel, [signed8Words]uint64{1, 1, 1, 1})
	if err != nil {
		return nil, fmt.Errorf("homchain: encode signed8 arithmetic-root-slot one: %w", err)
	}
	oneDigest, err := signed8PlaintextDigest(one)
	if err != nil {
		return nil, err
	}
	parameterDigest, err := signed8ParameterDigest(params)
	if err != nil {
		return nil, err
	}
	bindingDigest := digestString(fmt.Sprintf(
		"%s|params=%s|range=%s|a2b=%s|a2b-keys=%s|sign=%s|input=L20/S35/degree1/full-dense/ntt/4x4",
		signed8InputBindingSchema, parameterDigest, ranges.digest, a2b.profile.digest,
		a2b.keyProfile.digest, sign.profile.digest,
	))
	publicProfile, err := buildSigned8ComparatorProfile(
		params, ranges, a2b, sign, bindingDigest, oneDigest, parameterDigest, Signed8PublicThresholdCTPT,
	)
	if err != nil {
		return nil, err
	}
	opaqueProfile, err := buildSigned8ComparatorProfile(
		params, ranges, a2b, sign, bindingDigest, oneDigest, parameterDigest, Signed8OpaqueThresholdCTCT,
	)
	if err != nil {
		return nil, err
	}
	circuit := &Signed8ComparatorCircuit{
		params: params, refreshEncoder: refreshEncoder, integerEncoder: integerEncoder,
		ranges: ranges, a2b: a2b, sign: sign, arithmeticOne: one, arithmeticOneSeal: one.CopyNew(),
		arithmeticOneDigest: oneDigest, parameterDigest: parameterDigest,
		bindingDigest: bindingDigest, publicProfile: publicProfile, opaqueProfile: opaqueProfile,
	}
	circuit.graph = signed8ComparatorCircuitGraphIdentity{
		circuit: circuit, refreshEncoder: refreshEncoder, integerEncoder: integerEncoder,
		a2b: a2b, sign: sign, one: one, oneSeal: circuit.arithmeticOneSeal,
		oneDigest: oneDigest, parameterDigest: parameterDigest, publicDigest: publicProfile.digest,
		opaqueDigest: opaqueProfile.digest, bindingDigest: bindingDigest,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

// BindFeature admits a canonical L20/S35 arithmetic-root-slot feature under
// this circuit's trusted encoder/protocol assumption. declaredSource is hashed
// and matched byte-for-byte to the circuit parameters, and the returned handle
// owns a ciphertext copy whose payload digest is sealed into its provenance.
// This verifies the caller's declaration and exact ciphertext state; it is not
// a cryptographic proof that a raw ciphertext was created by declaredSource.
func (c *Signed8ComparatorCircuit) BindFeature(ciphertext *rlwe.Ciphertext, declaredSource ckks.Parameters) (Signed8FeatureInput, error) {
	if err := c.validate(); err != nil {
		return Signed8FeatureInput{}, err
	}
	sourceDigest, err := c.validateDeclaredSource(declaredSource)
	if err != nil {
		return Signed8FeatureInput{}, fmt.Errorf("homchain: signed8 feature declared source: %w", err)
	}
	if err := c.validateArithmeticInput("feature", ciphertext); err != nil {
		return Signed8FeatureInput{}, err
	}
	owned := ciphertext.CopyNew()
	payloadDigest, err := signed8CiphertextDigest(owned)
	if err != nil {
		return Signed8FeatureInput{}, err
	}
	provenance := digestSigned8InputProvenance(c.bindingDigest, c.ranges.digest, sourceDigest, payloadDigest, signed8FeatureRole)
	return Signed8FeatureInput{
		ciphertext: owned, role: signed8FeatureRole, profileDigest: c.bindingDigest, rangeDigest: c.ranges.digest,
		sourceParameterDigest: sourceDigest, payloadDigest: payloadDigest, provenanceDigest: provenance,
	}, nil
}

// BindOpaqueThreshold applies the same trusted declared-origin admission and
// defensive ownership boundary to an encrypted threshold. It does not expose a
// raw Boolean half or claim a cryptographic proof of raw-ciphertext origin.
func (c *Signed8ComparatorCircuit) BindOpaqueThreshold(ciphertext *rlwe.Ciphertext, declaredSource ckks.Parameters) (Signed8OpaqueThresholdInput, error) {
	if err := c.validate(); err != nil {
		return Signed8OpaqueThresholdInput{}, err
	}
	sourceDigest, err := c.validateDeclaredSource(declaredSource)
	if err != nil {
		return Signed8OpaqueThresholdInput{}, fmt.Errorf("homchain: signed8 opaque threshold declared source: %w", err)
	}
	if err := c.validateArithmeticInput("opaque threshold", ciphertext); err != nil {
		return Signed8OpaqueThresholdInput{}, err
	}
	owned := ciphertext.CopyNew()
	payloadDigest, err := signed8CiphertextDigest(owned)
	if err != nil {
		return Signed8OpaqueThresholdInput{}, err
	}
	provenance := digestSigned8InputProvenance(c.bindingDigest, c.ranges.digest, sourceDigest, payloadDigest, signed8ThresholdRole)
	return Signed8OpaqueThresholdInput{
		ciphertext: owned, role: signed8ThresholdRole, profileDigest: c.bindingDigest, rangeDigest: c.ranges.digest,
		sourceParameterDigest: sourceDigest, payloadDigest: payloadDigest, provenanceDigest: provenance,
	}, nil
}

func (c *Signed8ComparatorCircuit) BindEvaluator(source *bootstrapping.Evaluator) (*Signed8ComparatorEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if source == nil || source.Evaluator == nil || source.MemEvaluationKeySet == nil {
		return nil, fmt.Errorf("homchain: signed8 comparator requires a complete bootstrapping evaluator")
	}
	a2b, err := c.a2b.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind signed8 serial A2B: %w", err)
	}
	keySet := source.MemEvaluationKeySet
	signSource := ckks.NewEvaluator(c.params, keySet)
	sign, err := c.sign.BindEvaluator(signSource)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind signed8 sign fusion: %w", err)
	}
	if a2b.keySet != keySet || sign.keySet != keySet || sign.ckks != signSource || signSource.EvaluationKeySet != keySet {
		return nil, fmt.Errorf("homchain: signed8 children do not share the exact source MemEvaluationKeySet")
	}
	relinearizationKey, err := keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, fmt.Errorf("homchain: signed8 relinearization key is missing: %v", err)
	}
	galoisKeys := make(map[uint64]*rlwe.GaloisKey, len(c.publicProfile.requiredGaloisElements))
	for _, element := range c.publicProfile.requiredGaloisElements {
		key, keyErr := keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil {
			return nil, fmt.Errorf("homchain: signed8 Galois key %d is missing: %v", element, keyErr)
		}
		galoisKeys[element] = key
	}
	evaluator := &Signed8ComparatorEvaluator{
		circuit: c, source: source, signSource: signSource, a2b: a2b, sign: sign, keySet: keySet,
		relinearizationKey: relinearizationKey, galoisKeys: galoisKeys,
	}
	evaluator.graph = signed8ComparatorEvaluatorGraphIdentity{
		circuit: c, source: source, sourceCKKS: source.Evaluator, signSource: signSource, keySet: keySet,
		a2b: a2b, sign: sign, publicDigest: c.publicProfile.digest,
		opaqueDigest: c.opaqueProfile.digest, bindingDigest: c.bindingDigest,
	}
	if _, err = evaluator.preflight(); err != nil {
		return nil, err
	}
	return evaluator, nil
}

func (e *Signed8ComparatorEvaluator) CompareGEPublicNew(
	feature Signed8FeatureInput,
	thresholds [signed8Words]int64,
) (Signed8ComparatorResult, Signed8ComparatorTrace, error) {
	started := time.Now()
	if e == nil || e.circuit == nil {
		return Signed8ComparatorResult{}, Signed8ComparatorTrace{}, fmt.Errorf("homchain: nil signed8 comparator evaluator")
	}
	if err := e.circuit.validateFeatureHandle(feature); err != nil {
		return Signed8ComparatorResult{}, Signed8ComparatorTrace{}, err
	}
	residues, err := e.circuit.validatePublicThresholds(thresholds)
	if err != nil {
		return Signed8ComparatorResult{}, Signed8ComparatorTrace{}, err
	}
	plaintext, err := newSigned8WordPlaintext(e.circuit.params, e.circuit.refreshEncoder, signed8RefreshEncoderPrecision, signed8InputLevel, residues)
	if err != nil {
		return Signed8ComparatorResult{}, Signed8ComparatorTrace{}, fmt.Errorf("homchain: encode signed8 public thresholds: %w", err)
	}
	operandDigest, err := signed8PlaintextDigest(plaintext)
	if err != nil {
		return Signed8ComparatorResult{}, Signed8ComparatorTrace{}, err
	}
	return e.compareNew(feature, nil, plaintext, Signed8PublicThresholdCTPT, operandDigest, started)
}

func (e *Signed8ComparatorEvaluator) CompareGEOpaqueNew(
	feature Signed8FeatureInput,
	threshold Signed8OpaqueThresholdInput,
) (Signed8ComparatorResult, Signed8ComparatorTrace, error) {
	started := time.Now()
	if e == nil || e.circuit == nil {
		return Signed8ComparatorResult{}, Signed8ComparatorTrace{}, fmt.Errorf("homchain: nil signed8 comparator evaluator")
	}
	if err := e.circuit.validateFeatureHandle(feature); err != nil {
		return Signed8ComparatorResult{}, Signed8ComparatorTrace{}, err
	}
	if err := e.circuit.validateThresholdHandle(threshold); err != nil {
		return Signed8ComparatorResult{}, Signed8ComparatorTrace{}, err
	}
	return e.compareNew(feature, &threshold, nil, Signed8OpaqueThresholdCTCT, threshold.provenanceDigest, started)
}

func (e *Signed8ComparatorEvaluator) compareNew(
	feature Signed8FeatureInput,
	threshold *Signed8OpaqueThresholdInput,
	thresholdPlaintext *rlwe.Plaintext,
	mode Signed8ComparatorOperandMode,
	operandDigest string,
	started time.Time,
) (result Signed8ComparatorResult, trace Signed8ComparatorTrace, err error) {
	profile := e.circuit.profileForMode(mode)
	if profile.digest == "" {
		return result, trace, fmt.Errorf("homchain: unsupported signed8 comparator operand mode %q", mode)
	}
	featureBefore := feature.ciphertext.CopyNew()
	var thresholdCiphertext *rlwe.Ciphertext
	var thresholdBefore *rlwe.Ciphertext
	if threshold != nil {
		thresholdCiphertext = threshold.ciphertext
		thresholdBefore = thresholdCiphertext.CopyNew()
	}
	oneBefore := e.circuit.arithmeticOne.CopyNew()
	defer func() {
		if feature.ciphertext != nil && !feature.ciphertext.Equal(featureBefore) {
			result = Signed8ComparatorResult{}
			err = fmt.Errorf("homchain: signed8 comparator mutated the feature input")
		}
		if thresholdCiphertext != nil && !thresholdCiphertext.Equal(thresholdBefore) {
			result = Signed8ComparatorResult{}
			err = fmt.Errorf("homchain: signed8 comparator mutated the opaque threshold input")
		}
		if e.circuit.arithmeticOne != nil && !e.circuit.arithmeticOne.Equal(oneBefore) {
			result = Signed8ComparatorResult{}
			err = fmt.Errorf("homchain: signed8 comparator mutated the cached arithmetic-one plaintext")
		}
	}()
	preflight, err := e.preflight()
	if err != nil {
		return result, trace, err
	}
	// Re-authenticate the owned payloads after the complete child/key graph
	// preflight and immediately before the first homomorphic operation.
	if err = e.circuit.validateFeatureHandle(feature); err != nil {
		return result, trace, err
	}
	if threshold != nil {
		if err = e.circuit.validateThresholdHandle(*threshold); err != nil {
			return result, trace, err
		}
	}
	if mode == Signed8PublicThresholdCTPT {
		if err = requireSigned8PlaintextState("public threshold", thresholdPlaintext, profile.inputState, e.circuit.params); err != nil {
			return result, trace, err
		}
		var currentDigest string
		if currentDigest, err = signed8PlaintextDigest(thresholdPlaintext); err != nil || currentDigest != operandDigest {
			if err == nil {
				err = fmt.Errorf("homchain: signed8 public-threshold payload changed before subtraction")
			}
			return result, trace, err
		}
	}
	trace = Signed8ComparatorTrace{
		profileDigest: profile.digest, rangeDigest: profile.rangeDigest, operandMode: mode,
		thresholdOperandDigest: operandDigest, arithmeticOneDigest: profile.arithmeticOnePayloadDigest,
		keyPreflight: preflight,
	}
	// Counts wrapper-visible ciphertexts plus immutable-input snapshots. Child
	// scratch remains in its nested ledger and is not fabricated into this peak.
	liveCiphertexts := 2
	if thresholdCiphertext != nil {
		liveCiphertexts += 2
	}
	recordPeak := func() {
		if liveCiphertexts > trace.wrapperPeakLive {
			trace.wrapperPeakLive = liveCiphertexts
		}
	}
	recordPeak()
	if err = appendSigned8State(&trace, Signed8StageFeatureInput, feature.ciphertext); err != nil {
		return result, trace, err
	}
	if thresholdCiphertext != nil {
		if err = appendSigned8State(&trace, Signed8StageThresholdInput, thresholdCiphertext); err != nil {
			return result, trace, err
		}
	}
	var difference *rlwe.Ciphertext
	switch mode {
	case Signed8PublicThresholdCTPT:
		difference, err = e.source.Evaluator.SubNew(feature.ciphertext, thresholdPlaintext)
		trace.wrapperCounts.CiphertextPlaintextSubtractions++
	case Signed8OpaqueThresholdCTCT:
		difference, err = e.source.Evaluator.SubNew(feature.ciphertext, thresholdCiphertext)
		trace.wrapperCounts.CiphertextCiphertextSubtractions++
	default:
		return result, trace, fmt.Errorf("homchain: unsupported signed8 comparator operand mode %q", mode)
	}
	if err != nil {
		return result, trace, fmt.Errorf("homchain: signed8 arithmetic subtraction: %w", err)
	}
	if err = requireSigned8CiphertextState("difference", difference, profile.differenceState, e.circuit.params); err != nil {
		return result, trace, err
	}
	liveCiphertexts++
	recordPeak()
	if err = appendSigned8State(&trace, Signed8StageDifference, difference); err != nil {
		return result, trace, err
	}
	differenceBefore := difference.CopyNew()
	liveCiphertexts++
	recordPeak()
	high, a2bTrace, err := e.evaluateHighMSB(difference)
	if err != nil {
		return result, trace, err
	}
	liveCiphertexts++
	recordPeak()
	trace.a2bTrace = cloneSigned8A2BTrace(a2bTrace)
	if !difference.Equal(differenceBefore) {
		return result, trace, fmt.Errorf("homchain: signed8 serial A2B mutated the difference")
	}
	liveCiphertexts--
	if err = requireSigned8CiphertextState("A2B high MSB", high, profile.highMSBState, e.circuit.params); err != nil {
		return result, trace, err
	}
	if err = appendSigned8State(&trace, Signed8StageHighMSB, high); err != nil {
		return result, trace, err
	}
	highBefore := high.CopyNew()
	liveCiphertexts++
	recordPeak()
	highHandle, err := e.circuit.sign.BindBooleanHalf(high, SignFusionHighBooleanHalf, SignFusionLSBFirst)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: internally bind signed8 high LSB-first half: %w", err)
	}
	signResult, err := e.sign.EvaluateNew(highHandle)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: evaluate signed8 sign fusion: %w", err)
	}
	liveCiphertexts++
	recordPeak()
	trace.signProvenance = cloneSigned8SignProvenance(signResult.Provenance())
	if !high.Equal(highBefore) {
		return result, trace, fmt.Errorf("homchain: signed8 sign fusion mutated the A2B high half")
	}
	liveCiphertexts--
	signCiphertext := signResult.Ciphertext()
	if err = requireSigned8CiphertextState("arithmetic sign", signCiphertext, profile.signState, e.circuit.params); err != nil {
		return result, trace, err
	}
	if err = appendSigned8State(&trace, Signed8StageArithmeticSign, signCiphertext); err != nil {
		return result, trace, err
	}
	signBefore := signCiphertext.CopyNew()
	liveCiphertexts++
	recordPeak()
	negated := negateSigned8CiphertextNew(e.circuit.params, signCiphertext)
	trace.wrapperCounts.Negations++
	liveCiphertexts++
	recordPeak()
	if !signCiphertext.Equal(signBefore) {
		return result, trace, fmt.Errorf("homchain: signed8 negation mutated the sign ciphertext")
	}
	liveCiphertexts--
	if err = requireSigned8CiphertextState("negated sign", negated, profile.signState, e.circuit.params); err != nil {
		return result, trace, err
	}
	if err = appendSigned8State(&trace, Signed8StageNegatedSign, negated); err != nil {
		return result, trace, err
	}
	negatedBefore := negated.CopyNew()
	liveCiphertexts++
	recordPeak()
	branch, err := e.source.Evaluator.AddNew(negated, e.circuit.arithmeticOne)
	trace.wrapperCounts.CiphertextPlaintextVectorAdditions++
	liveCiphertexts++
	recordPeak()
	if err != nil {
		return result, trace, fmt.Errorf("homchain: add signed8 arithmetic-root-slot one: %w", err)
	}
	if !negated.Equal(negatedBefore) {
		return result, trace, fmt.Errorf("homchain: signed8 complement addition mutated the negated sign")
	}
	liveCiphertexts--
	if err = requireSigned8CiphertextState("GE branch", branch, profile.outputState, e.circuit.params); err != nil {
		return result, trace, err
	}
	if err = appendSigned8State(&trace, Signed8StageGreaterEqual, branch); err != nil {
		return result, trace, err
	}
	if err = validateSigned8RuntimeEvidence(profile, trace); err != nil {
		return result, trace, err
	}
	trace.serializedBytes, err = measureSigned8BoundaryBytes(feature.ciphertext, thresholdCiphertext, thresholdPlaintext, difference, high, signCiphertext, branch)
	if err != nil {
		return result, trace, err
	}
	trace.wallTime = time.Since(started)
	return Signed8ComparatorResult{
		branch: branch, profileDigest: profile.digest, rangeDigest: profile.rangeDigest, operandMode: mode,
	}, trace, nil
}

func (e *Signed8ComparatorEvaluator) evaluateHighMSB(difference *rlwe.Ciphertext) (*rlwe.Ciphertext, A2BFullTrace, error) {
	result, trace, err := e.a2b.EvaluateNew(difference)
	if err != nil {
		return nil, trace, fmt.Errorf("homchain: evaluate signed8 serial A2B: %w", err)
	}
	high := result.HighMSB()
	if high == nil {
		return nil, trace, fmt.Errorf("homchain: signed8 serial A2B returned nil high half")
	}
	return high, trace, nil
}

func (e *Signed8ComparatorEvaluator) preflight() (A2BRefreshKeyPreflight, error) {
	empty := A2BRefreshKeyPreflight{}
	if e == nil || e.circuit == nil || e.source == nil || e.a2b == nil || e.sign == nil || e.keySet == nil {
		return empty, fmt.Errorf("homchain: nil or incomplete signed8 comparator evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		return empty, err
	}
	g := e.graph
	if g.circuit != e.circuit || g.source != e.source || g.sourceCKKS != e.source.Evaluator || g.signSource != e.signSource ||
		g.keySet != e.keySet || g.a2b != e.a2b || g.sign != e.sign ||
		g.publicDigest != e.circuit.publicProfile.digest || g.opaqueDigest != e.circuit.opaqueProfile.digest ||
		g.bindingDigest != e.circuit.bindingDigest {
		return empty, fmt.Errorf("homchain: signed8 evaluator graph identity changed before evaluation")
	}
	if e.source.MemEvaluationKeySet != e.keySet || e.source.Evaluator == nil || e.signSource == nil ||
		e.signSource.EvaluationKeySet != e.keySet || e.a2b.keySet != e.keySet ||
		e.sign.keySet != e.keySet || e.sign.ckks != e.signSource {
		return empty, fmt.Errorf("homchain: signed8 shared source or key-set identity changed before evaluation")
	}
	preflight, err := e.a2b.preflight()
	if err != nil {
		return preflight, err
	}
	if err = e.sign.preflightGraphAndKeys(); err != nil {
		return empty, err
	}
	relinearizationKey, err := e.keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil || relinearizationKey != e.relinearizationKey {
		return empty, fmt.Errorf("homchain: signed8 relinearization-key identity changed before evaluation")
	}
	for element, expected := range e.galoisKeys {
		key, keyErr := e.keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil || key != expected || key.GaloisElement != element {
			return empty, fmt.Errorf("homchain: signed8 Galois-key %d identity changed before evaluation", element)
		}
	}
	return preflight, nil
}

func validateSigned8ComparatorEncoders(params ckks.Parameters, refreshEncoder, integerEncoder *ckks.Encoder) error {
	if refreshEncoder == nil || integerEncoder == nil {
		return fmt.Errorf("homchain: signed8 comparator requires refresh and integer encoders")
	}
	refreshParameters, integerParameters := refreshEncoder.GetParameters(), integerEncoder.GetParameters()
	if !params.Equal(&refreshParameters) || !params.Equal(&integerParameters) {
		return fmt.Errorf("homchain: signed8 comparator encoder parameters do not match the circuit")
	}
	if refreshEncoder.Prec() != signed8RefreshEncoderPrecision {
		return fmt.Errorf("homchain: signed8 refresh encoder precision=%d, want %d", refreshEncoder.Prec(), signed8RefreshEncoderPrecision)
	}
	if integerEncoder.Prec() != signed8IntegerEncoderPrecision {
		return fmt.Errorf("homchain: signed8 integer encoder precision=%d, want %d", integerEncoder.Prec(), signed8IntegerEncoderPrecision)
	}
	return nil
}

func validateSigned8AcceptedChildren(a2b *A2BFullCircuit, sign *SignFusionCircuit) error {
	if a2b == nil || sign == nil {
		return fmt.Errorf("homchain: signed8 comparator child circuit is nil")
	}
	if err := a2b.validate(); err != nil {
		return err
	}
	if err := sign.validate(); err != nil {
		return err
	}
	a2bProfile, signProfile := a2b.profile, sign.profile
	second := a2bProfile.secondSTC
	if a2bProfile.digest != signed8AcceptedA2BProfileDigest ||
		second.rawMatrixDigest != signed8AcceptedSecondRawSTCDigest ||
		second.matrixDigest != signed8AcceptedSecondExecSTCDigest ||
		second.digest != signed8AcceptedSecondSTCDigest ||
		a2bProfile.schedule != A2BFullSerialLowThenHigh || a2bProfile.wordBits != z2n.Word8 ||
		a2bProfile.words != signed8Words || a2bProfile.slots != signed8Slots ||
		a2bProfile.inputLevel != signed8InputLevel || a2bProfile.outputOrder != [2]string{"low", "high"} ||
		a2bProfile.bitOrder != "LSB-first" || !a2bProfile.inputScale.EqualScale(a2b.params.DefaultScale()) {
		return fmt.Errorf("homchain: signed8 comparator serial A2B child is not the independently accepted profile")
	}
	if signProfile.parameterDigest != signed8AcceptedSignParameterDigest ||
		signProfile.sourceDigest != signed8AcceptedSignSourceDigest ||
		signProfile.compiledDigest != signed8AcceptedSignCompiledDigest ||
		signProfile.digest != signed8AcceptedSignProfileDigest ||
		signProfile.inputHalfRole != SignFusionHighBooleanHalf || signProfile.inputBitOrder != SignFusionLSBFirst ||
		signProfile.inputLevel != signed8SignInputLevel || signProfile.outputLevel != signed8OutputLevel ||
		!signProfile.inputScale.EqualScale(sign.params.DefaultScale()) || !signProfile.outputScale.EqualScale(sign.params.DefaultScale()) {
		return fmt.Errorf("homchain: signed8 comparator sign-fusion child is not the independently accepted profile")
	}
	keyProfile := a2b.RequiredKeyProfile()
	if !keyProfile.RelinearizationRequired() || len(keyProfile.Residual()) != 0 {
		return fmt.Errorf("homchain: signed8 comparator A2B key profile changed")
	}
	all := map[uint64]bool{}
	for _, element := range keyProfile.All() {
		all[element] = true
	}
	for _, element := range signProfile.galoisElements {
		if !all[element] {
			return fmt.Errorf("homchain: sign-fusion Galois element %d is not a subset of the sealed A2B key union", element)
		}
	}
	return nil
}

func buildSigned8ComparatorProfile(
	params ckks.Parameters,
	ranges Signed8NoOverflowRange,
	a2b *A2BFullCircuit,
	sign *SignFusionCircuit,
	bindingDigest, oneDigest, parameterDigest string,
	mode Signed8ComparatorOperandMode,
) (Signed8ComparatorProfile, error) {
	if err := validateSigned8AcceptedChildren(a2b, sign); err != nil {
		return Signed8ComparatorProfile{}, err
	}
	inputScale, highScale, signScale := a2b.profile.inputScale, sign.profile.inputScale, sign.profile.outputScale
	state := func(level int, scale ExactScaleSnapshot) Signed8ComparatorStateProfile {
		return Signed8ComparatorStateProfile{level: level, degree: 1, logDimensions: params.LogMaxDimensions(), scale: scale}
	}
	wrapper := Signed8ComparatorWrapperOperationCounts{Negations: 1, CiphertextPlaintextVectorAdditions: 1}
	setup := Signed8ComparatorSetupCounts{CachedArithmeticOneEncodings: 1, InternalSerialA2BRefreshInvocations: 2}
	peak := 0
	switch mode {
	case Signed8PublicThresholdCTPT:
		wrapper.CiphertextPlaintextSubtractions = 1
		setup.PerEvaluationThresholdEncodings = 1
		peak = 8
	case Signed8OpaqueThresholdCTCT:
		wrapper.CiphertextCiphertextSubtractions = 1
		peak = 10
	default:
		return Signed8ComparatorProfile{}, fmt.Errorf("homchain: invalid signed8 operand mode %q", mode)
	}
	kernelCounts := GaoA2BKernelOperationCounts{
		ExpPolynomialEvaluations: 1, ComplexSquarings: 2, MultiPolynomialEvaluations: 1,
		SharedPowerBases: 1, GenericLUTEvaluations: 0, Conjugations: 2, RealRecoveries: 2,
	}
	profile := Signed8ComparatorProfile{
		fidelity: Signed8ComparatorLattigoFunctionalComposition, maturity: Signed8ComparatorFunctionalNotSecure,
		operandMode: mode, wordBits: z2n.Word8, words: signed8Words, slots: signed8Slots,
		refreshEncoderPrecision: signed8RefreshEncoderPrecision, integerEncoderPrecision: signed8IntegerEncoderPrecision,
		predicate: Signed8GreaterThanOrEqual, childConvention: Signed8ZeroLTOneGE,
		bindingAssumption: signed8TrustedAdmissionAssumption, rangeDigest: ranges.digest,
		parameterDigest: parameterDigest, inputBindingDigest: bindingDigest,
		a2bProfileDigest: a2b.profile.digest, a2bKeyProfileDigest: a2b.keyProfile.digest,
		a2bKernelProfileDigests: a2b.profile.kernelDigests,
		signParameterDigest:     sign.profile.parameterDigest, signSourceDigest: sign.profile.sourceDigest,
		signCompiledDigest: sign.profile.compiledDigest, signProfileDigest: sign.profile.digest,
		arithmeticOnePayloadDigest: oneDigest,
		inputState:                 state(signed8InputLevel, inputScale), differenceState: state(signed8InputLevel, inputScale),
		highMSBState: state(signed8SignInputLevel, highScale), signState: state(signed8OutputLevel, signScale),
		outputState: state(signed8OutputLevel, signScale), wrapperCounts: wrapper,
		a2bCounts: a2b.profile.operationCounts, kernelCounts: [2]GaoA2BKernelOperationCounts{kernelCounts, kernelCounts},
		signCounts: sign.profile.operationCounts, setupCounts: setup, wrapperPeakLive: peak,
		requiredGaloisElements: a2b.keyProfile.All(), relinearizationRequired: true,
		levelLedger: signed8ComparatorLevelLedger, normalizedCertified: false,
	}
	profile.digest = digestSigned8ComparatorProfile(profile)
	return profile, nil
}

func digestSigned8ComparatorProfile(profile Signed8ComparatorProfile) string {
	return digestString(fmt.Sprintf(
		"%s|fidelity=%s|maturity=%s|mode=%s|word-bits=%d|words=%d|slots=%d|encoder-precision=%d,%d|predicate=%s|children=%s|binding-assumption=%s|range=%s|params=%s|input-binding=%s|a2b=%s|a2b-keys=%s|kernels=%v|sign=params:%s/source:%s/compiled:%s/profile:%s|one=%s|states=input:%d/%s,difference:%d/%s,high:%d/%s,sign:%d/%s,output:%d/%s/dimensions:%d,%d/degree1|wrapper=%+v|a2b-ops=%+v|kernel-ops=%+v|sign-ops=%+v|setup=%+v|wrapper-peak=%d|galois=%v|relinearization=%t|ledger=%s|normalized-certified=%t",
		signed8ComparatorProfileSchema, profile.fidelity, profile.maturity, profile.operandMode,
		profile.wordBits, profile.words, profile.slots, profile.refreshEncoderPrecision, profile.integerEncoderPrecision,
		profile.predicate, profile.childConvention, profile.bindingAssumption, profile.rangeDigest,
		profile.parameterDigest, profile.inputBindingDigest, profile.a2bProfileDigest, profile.a2bKeyProfileDigest,
		profile.a2bKernelProfileDigests, profile.signParameterDigest, profile.signSourceDigest,
		profile.signCompiledDigest, profile.signProfileDigest, profile.arithmeticOnePayloadDigest,
		profile.inputState.level, profile.inputState.scale.canonicalString(),
		profile.differenceState.level, profile.differenceState.scale.canonicalString(),
		profile.highMSBState.level, profile.highMSBState.scale.canonicalString(),
		profile.signState.level, profile.signState.scale.canonicalString(),
		profile.outputState.level, profile.outputState.scale.canonicalString(),
		profile.inputState.logDimensions.Rows, profile.inputState.logDimensions.Cols,
		profile.wrapperCounts, profile.a2bCounts, profile.kernelCounts, profile.signCounts, profile.setupCounts,
		profile.wrapperPeakLive, profile.requiredGaloisElements, profile.relinearizationRequired,
		profile.levelLedger, profile.normalizedCertified,
	))
}

func (c *Signed8ComparatorCircuit) validate() error {
	if c == nil || c.refreshEncoder == nil || c.integerEncoder == nil || c.a2b == nil || c.sign == nil ||
		c.arithmeticOne == nil || c.arithmeticOneSeal == nil || c.arithmeticOneDigest == "" || c.parameterDigest == "" {
		return fmt.Errorf("homchain: nil or incomplete signed8 comparator circuit")
	}
	if err := validateSigned8NoOverflowRange(c.ranges); err != nil {
		return err
	}
	if err := validateA2BRefreshParameters(c.params); err != nil {
		return err
	}
	if err := validateSigned8ComparatorEncoders(c.params, c.refreshEncoder, c.integerEncoder); err != nil {
		return err
	}
	if err := validateSigned8AcceptedChildren(c.a2b, c.sign); err != nil {
		return err
	}
	g := c.graph
	if g.circuit != c || g.refreshEncoder != c.refreshEncoder || g.integerEncoder != c.integerEncoder ||
		g.a2b != c.a2b || g.sign != c.sign || g.one != c.arithmeticOne ||
		g.oneSeal != c.arithmeticOneSeal || g.oneDigest != c.arithmeticOneDigest || g.parameterDigest != c.parameterDigest ||
		g.publicDigest != c.publicProfile.digest || g.opaqueDigest != c.opaqueProfile.digest ||
		g.bindingDigest != c.bindingDigest {
		return fmt.Errorf("homchain: signed8 comparator circuit graph identity changed")
	}
	if err := requireSigned8PlaintextState("cached arithmetic-root-slot one", c.arithmeticOne, c.publicProfile.outputState, c.params); err != nil {
		return err
	}
	if err := requireSigned8PlaintextState("sealed arithmetic-root-slot one", c.arithmeticOneSeal, c.publicProfile.outputState, c.params); err != nil {
		return err
	}
	if !c.arithmeticOne.Equal(c.arithmeticOneSeal) {
		return fmt.Errorf("homchain: signed8 arithmetic-root-slot one plaintext changed")
	}
	oneDigest, err := signed8PlaintextDigest(c.arithmeticOne)
	if err != nil {
		return err
	}
	sealDigest, err := signed8PlaintextDigest(c.arithmeticOneSeal)
	if err != nil {
		return err
	}
	if oneDigest != c.arithmeticOneDigest || sealDigest != c.arithmeticOneDigest ||
		c.publicProfile.arithmeticOnePayloadDigest != c.arithmeticOneDigest || c.opaqueProfile.arithmeticOnePayloadDigest != c.arithmeticOneDigest {
		return fmt.Errorf("homchain: signed8 cached arithmetic-root-slot one digest changed")
	}
	parameterDigest, err := signed8ParameterDigest(c.params)
	if err != nil {
		return err
	}
	if parameterDigest != c.parameterDigest || c.publicProfile.parameterDigest != c.parameterDigest || c.opaqueProfile.parameterDigest != c.parameterDigest {
		return fmt.Errorf("homchain: signed8 parameter digest changed")
	}
	expectedBinding := digestString(fmt.Sprintf(
		"%s|params=%s|range=%s|a2b=%s|a2b-keys=%s|sign=%s|input=L20/S35/degree1/full-dense/ntt/4x4",
		signed8InputBindingSchema, parameterDigest, c.ranges.digest, c.a2b.profile.digest,
		c.a2b.keyProfile.digest, c.sign.profile.digest,
	))
	if c.bindingDigest != expectedBinding {
		return fmt.Errorf("homchain: signed8 input binding digest changed")
	}
	expectedPublic, err := buildSigned8ComparatorProfile(c.params, c.ranges, c.a2b, c.sign, expectedBinding, c.arithmeticOneDigest, parameterDigest, Signed8PublicThresholdCTPT)
	if err != nil {
		return err
	}
	expectedOpaque, err := buildSigned8ComparatorProfile(c.params, c.ranges, c.a2b, c.sign, expectedBinding, c.arithmeticOneDigest, parameterDigest, Signed8OpaqueThresholdCTCT)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(c.publicProfile, expectedPublic) || !reflect.DeepEqual(c.opaqueProfile, expectedOpaque) {
		return fmt.Errorf("homchain: signed8 comparator profile or nested ledger changed")
	}
	return nil
}

func (c *Signed8ComparatorCircuit) profileForMode(mode Signed8ComparatorOperandMode) Signed8ComparatorProfile {
	if c == nil {
		return Signed8ComparatorProfile{}
	}
	switch mode {
	case Signed8PublicThresholdCTPT:
		return c.publicProfile
	case Signed8OpaqueThresholdCTCT:
		return c.opaqueProfile
	default:
		return Signed8ComparatorProfile{}
	}
}

func (c *Signed8ComparatorCircuit) validateArithmeticInput(name string, ciphertext *rlwe.Ciphertext) error {
	if c == nil || c.a2b == nil || c.a2b.refresh == nil {
		return fmt.Errorf("homchain: incomplete signed8 input circuit")
	}
	if err := requireSigned8CiphertextState(name, ciphertext, c.publicProfile.inputState, c.params); err != nil {
		return err
	}
	if err := c.a2b.refresh.validateInput(ciphertext); err != nil {
		return fmt.Errorf("homchain: signed8 %s does not satisfy canonical arithmetic ingress: %w", name, err)
	}
	return nil
}

func (c *Signed8ComparatorCircuit) validateDeclaredSource(declaredSource ckks.Parameters) (string, error) {
	if c == nil || c.parameterDigest == "" {
		return "", fmt.Errorf("homchain: incomplete signed8 declared-source verifier")
	}
	digest, err := signed8ParameterDigest(declaredSource)
	if err != nil {
		return "", err
	}
	if digest != c.parameterDigest {
		return "", fmt.Errorf("homchain: declared source parameter digest=%s, want %s", digest, c.parameterDigest)
	}
	return digest, nil
}

func (c *Signed8ComparatorCircuit) validateFeatureHandle(feature Signed8FeatureInput) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := c.validateArithmeticInput("feature", feature.ciphertext); err != nil {
		return err
	}
	payloadDigest, err := signed8CiphertextDigest(feature.ciphertext)
	if err != nil {
		return err
	}
	if feature.role != signed8FeatureRole || feature.profileDigest != c.bindingDigest || feature.rangeDigest != c.ranges.digest ||
		feature.sourceParameterDigest != c.parameterDigest || feature.payloadDigest != payloadDigest ||
		feature.provenanceDigest != digestSigned8InputProvenance(c.bindingDigest, c.ranges.digest, c.parameterDigest, payloadDigest, signed8FeatureRole) {
		return fmt.Errorf("homchain: signed8 feature handle has foreign role, range, declared source, payload, or provenance")
	}
	return nil
}

func (c *Signed8ComparatorCircuit) validateThresholdHandle(threshold Signed8OpaqueThresholdInput) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := c.validateArithmeticInput("opaque threshold", threshold.ciphertext); err != nil {
		return err
	}
	payloadDigest, err := signed8CiphertextDigest(threshold.ciphertext)
	if err != nil {
		return err
	}
	if threshold.role != signed8ThresholdRole || threshold.profileDigest != c.bindingDigest || threshold.rangeDigest != c.ranges.digest ||
		threshold.sourceParameterDigest != c.parameterDigest || threshold.payloadDigest != payloadDigest ||
		threshold.provenanceDigest != digestSigned8InputProvenance(c.bindingDigest, c.ranges.digest, c.parameterDigest, payloadDigest, signed8ThresholdRole) {
		return fmt.Errorf("homchain: signed8 opaque threshold handle has foreign role, range, declared source, payload, or provenance")
	}
	return nil
}

func (c *Signed8ComparatorCircuit) validatePublicThresholds(thresholds [signed8Words]int64) ([signed8Words]uint64, error) {
	var residues [signed8Words]uint64
	for index, threshold := range thresholds {
		if threshold < c.ranges.tMin || threshold > c.ranges.tMax || threshold < -128 || threshold > 127 {
			return residues, fmt.Errorf("homchain: signed8 public threshold[%d]=%d lies outside certified [%d,%d]", index, threshold, c.ranges.tMin, c.ranges.tMax)
		}
		residues[index] = uint64(threshold) & 0xff
	}
	return residues, nil
}

func digestSigned8InputProvenance(bindingDigest, rangeDigest, sourceParameterDigest, payloadDigest string, role signed8InputRole) string {
	return digestString(fmt.Sprintf(
		"%s|binding=%s|range=%s|source-parameters=%s|ciphertext-payload=%s|role=%s",
		signed8InputProvenanceSchema, bindingDigest, rangeDigest, sourceParameterDigest, payloadDigest, role,
	))
}

func newSigned8WordPlaintext(params ckks.Parameters, encoder *ckks.Encoder, requiredPrecision uint, level int, words [signed8Words]uint64) (*rlwe.Plaintext, error) {
	if encoder == nil {
		return nil, fmt.Errorf("homchain: signed8 word plaintext encoder is nil")
	}
	if encoder.Prec() != requiredPrecision {
		return nil, fmt.Errorf("homchain: signed8 word plaintext encoder precision=%d, want %d", encoder.Prec(), requiredPrecision)
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, encoder.Prec())
	if err != nil {
		return nil, err
	}
	values := make([]*bignum.Complex, signed8Slots)
	for wordIndex, word := range words {
		rootSlots := ringZ.ArithmeticRootSlots(word & 0xff)
		if len(rootSlots) != 4 {
			return nil, fmt.Errorf("homchain: signed8 arithmetic word has %d root slots, want 4", len(rootSlots))
		}
		for slot := 0; slot < 4; slot++ {
			values[4*wordIndex+slot] = bignum.ToComplex(rootSlots[slot], encoder.Prec())
		}
	}
	plaintext := ckks.NewPlaintext(params, level)
	plaintext.LogDimensions = params.LogMaxDimensions()
	plaintext.Scale = params.DefaultScale()
	if err = encoder.Encode(values, plaintext); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func signed8PlaintextDigest(plaintext *rlwe.Plaintext) (string, error) {
	if plaintext == nil {
		return "", fmt.Errorf("homchain: nil signed8 plaintext")
	}
	payload, err := plaintext.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("homchain: marshal signed8 plaintext: %w", err)
	}
	return sha256Hex(payload), nil
}

func signed8CiphertextDigest(ciphertext *rlwe.Ciphertext) (string, error) {
	if ciphertext == nil {
		return "", fmt.Errorf("homchain: nil signed8 ciphertext")
	}
	payload, err := ciphertext.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("homchain: marshal signed8 ciphertext: %w", err)
	}
	return sha256Hex(payload), nil
}

func signed8ParameterDigest(params ckks.Parameters) (string, error) {
	payload, err := params.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("homchain: marshal signed8 parameters: %w", err)
	}
	return sha256Hex(payload), nil
}

func requireSigned8CiphertextState(name string, ciphertext *rlwe.Ciphertext, profile Signed8ComparatorStateProfile, params ckks.Parameters) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != profile.level || ciphertext.Degree() != profile.degree ||
		ciphertext.LogN() != params.LogN() || ciphertext.LogDimensions != profile.logDimensions || ciphertext.Slots() != signed8Slots ||
		!ciphertext.IsBatched || !ciphertext.IsNTT || !profile.scale.EqualScale(ciphertext.Scale) {
		return fmt.Errorf("homchain: signed8 %s is not exact L%d/S35/degree%d/full-dense/NTT", name, profile.level, profile.degree)
	}
	return nil
}

func requireSigned8PlaintextState(name string, plaintext *rlwe.Plaintext, profile Signed8ComparatorStateProfile, params ckks.Parameters) error {
	if plaintext == nil || plaintext.MetaData == nil || plaintext.Level() != profile.level || plaintext.Degree() != 0 ||
		plaintext.LogN() != params.LogN() || plaintext.LogDimensions != profile.logDimensions || plaintext.Slots() != signed8Slots ||
		!plaintext.IsBatched || !plaintext.IsNTT || !profile.scale.EqualScale(plaintext.Scale) {
		return fmt.Errorf("homchain: signed8 %s plaintext is not exact L%d/S35/full-dense/NTT", name, profile.level)
	}
	return nil
}

func appendSigned8State(trace *Signed8ComparatorTrace, stage Signed8ComparatorStage, ciphertext *rlwe.Ciphertext) error {
	if trace == nil || ciphertext == nil || ciphertext.MetaData == nil {
		return fmt.Errorf("homchain: cannot snapshot signed8 %s", stage)
	}
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return err
	}
	trace.states = append(trace.states, Signed8ComparatorCiphertextState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale,
	})
	return nil
}

func negateSigned8CiphertextNew(params ckks.Parameters, ciphertext *rlwe.Ciphertext) *rlwe.Ciphertext {
	result := ciphertext.CopyNew()
	ringQ := params.RingQ().AtLevel(result.Level())
	for index := range result.Value {
		ringQ.Neg(result.Value[index], result.Value[index])
	}
	return result
}

func validateSigned8RuntimeEvidence(profile Signed8ComparatorProfile, trace Signed8ComparatorTrace) error {
	if trace.profileDigest != profile.digest || trace.rangeDigest != profile.rangeDigest || trace.operandMode != profile.operandMode ||
		trace.arithmeticOneDigest != profile.arithmeticOnePayloadDigest || trace.thresholdOperandDigest == "" {
		return fmt.Errorf("homchain: signed8 runtime provenance differs from the sealed profile")
	}
	if trace.wrapperCounts != profile.wrapperCounts {
		return fmt.Errorf("homchain: signed8 wrapper operation ledger=%+v, want %+v", trace.wrapperCounts, profile.wrapperCounts)
	}
	if trace.wrapperPeakLive != profile.wrapperPeakLive {
		return fmt.Errorf("homchain: signed8 wrapper peak-live=%d, want %d", trace.wrapperPeakLive, profile.wrapperPeakLive)
	}
	if trace.a2bTrace.ProfileDigest() != profile.a2bProfileDigest || trace.a2bTrace.OperationCounts() != profile.a2bCounts || len(trace.a2bTrace.States()) != 24 {
		return fmt.Errorf("homchain: signed8 nested serial A2B evidence changed")
	}
	for iteration := 0; iteration < 2; iteration++ {
		provenance, ok := trace.a2bTrace.KernelProvenance(iteration)
		if !ok || provenance.ProfileDigest() != profile.a2bKernelProfileDigests[iteration] || provenance.OperationCounts() != profile.kernelCounts[iteration] {
			return fmt.Errorf("homchain: signed8 nested kernel %d evidence changed", iteration)
		}
	}
	if trace.signProvenance.ProfileDigest() != profile.signProfileDigest ||
		trace.signProvenance.SourceDigest() != profile.signSourceDigest ||
		trace.signProvenance.CompiledDigest() != profile.signCompiledDigest ||
		trace.signProvenance.OperationCounts() != profile.signCounts || len(trace.signProvenance.States()) != 3 {
		return fmt.Errorf("homchain: signed8 nested sign-fusion evidence changed")
	}
	wantStates := 6
	if profile.operandMode == Signed8OpaqueThresholdCTCT {
		wantStates = 7
	}
	if len(trace.states) != wantStates {
		return fmt.Errorf("homchain: signed8 wrapper recorded %d states, want %d", len(trace.states), wantStates)
	}
	return nil
}

func measureSigned8BoundaryBytes(
	feature, thresholdCiphertext *rlwe.Ciphertext,
	thresholdPlaintext *rlwe.Plaintext,
	difference, high, sign, branch *rlwe.Ciphertext,
) (Signed8ComparatorSerializedBytes, error) {
	ctSize := func(name string, ciphertext *rlwe.Ciphertext) (int, error) {
		payload, err := ciphertext.MarshalBinary()
		if err != nil {
			return 0, fmt.Errorf("homchain: marshal signed8 %s: %w", name, err)
		}
		return len(payload), nil
	}
	result := Signed8ComparatorSerializedBytes{}
	var err error
	if result.Feature, err = ctSize("feature", feature); err != nil {
		return result, err
	}
	if thresholdCiphertext != nil {
		if result.ThresholdOperand, err = ctSize("threshold", thresholdCiphertext); err != nil {
			return result, err
		}
	} else {
		payload, marshalErr := thresholdPlaintext.MarshalBinary()
		if marshalErr != nil {
			return result, fmt.Errorf("homchain: marshal signed8 threshold plaintext: %w", marshalErr)
		}
		result.ThresholdOperand = len(payload)
	}
	if result.Difference, err = ctSize("difference", difference); err != nil {
		return result, err
	}
	if result.HighMSB, err = ctSize("high MSB", high); err != nil {
		return result, err
	}
	if result.ArithmeticSign, err = ctSize("arithmetic sign", sign); err != nil {
		return result, err
	}
	if result.GreaterEqualOutput, err = ctSize("GE output", branch); err != nil {
		return result, err
	}
	return result, nil
}

func cloneSigned8A2BTrace(trace A2BFullTrace) A2BFullTrace {
	result := trace
	result.states = append([]A2BFullCiphertextState(nil), trace.states...)
	result.keyPreflight = cloneA2BRefreshKeyPreflight(trace.keyPreflight)
	result.iter0Kernel = cloneSigned8KernelProvenance(trace.iter0Kernel)
	result.iter1Kernel = cloneSigned8KernelProvenance(trace.iter1Kernel)
	return result
}

func cloneSigned8KernelProvenance(provenance GaoA2BKernelProvenance) GaoA2BKernelProvenance {
	result := provenance
	result.states = append([]GaoA2BKernelCiphertextState(nil), provenance.states...)
	result.operandPlan = provenance.OperandPlan()
	return result
}

func cloneSigned8SignProvenance(provenance SignFusionProvenance) SignFusionProvenance {
	result := provenance
	result.states = append([]SignFusionCiphertextState(nil), provenance.states...)
	return result
}
