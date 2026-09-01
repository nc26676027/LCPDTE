package homchain

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	signed8RootTreeProfileSchema                      = "signed8-root-tree-profile-v3"
	signed8RootTreeWords                              = 4
	signed8RootTreeWordSlots                          = 4
	signed8RootTreeSlots                              = signed8RootTreeWords * signed8RootTreeWordSlots
	signed8RootTreeCiphertextDegree                   = 1
	signed8RootTreePlaintextDegree                    = 0
	signed8RootTreeStateCount                         = 4
	signed8RootTreeBranchLevel                        = 4
	signed8RootTreeOutputLevel                        = 3
	signed8RootTreeLevelLedger                        = "comparator-ge-L4/S35->ct-pt-corrected-delta-product-L4/(S35*Q4)->rescale-L3/S35->add-left-L3/S35"
	signed8RootTreeMeasurementPolicy                  = "exact_marshaled_wrapper_boundaries_and_monotonic_total_comparator_selection_intervals"
	signed8RootTreeAcceptedComparatorPublicDigest     = "5075bdf6ee94736fb4dc4755c07f14fdf303f149dab5750440ca030f9f9710bc"
	signed8RootTreeAcceptedComparatorOpaqueDigest     = "0d62c312fe3084984a350de3dad44ed4ad90bcaa4e8a8370bddc45c7c2e2ee63"
	signed8RootTreeAcceptedComparatorAdmissionDigest  = "6815c10bab78ee55ad8c53fdeb30fd665e8cfc38028e8bce4bd384852db9b94b"
	signed8RootTreeAcceptedComparatorParameterDigest  = "085e0a9b826d469ac5514d3db988672f41ab0a4f1bb2fe82705842226a8eacc2"
	signed8RootTreeAcceptedComparatorOnePayloadDigest = "64b6f5a5fac15062c9a3eb83950da2c2abdbb6f77b3db4eb1a44bff097646592"
	signed8RootTreeAcceptedPublicProfileDigest        = "217dee6f265ec8c53819552838d9c9d64ea56e43df185b936f97d360b1e17be3"
	signed8RootTreeAcceptedOpaqueProfileDigest        = "09e8c10628c8a6820dbc439d31f9fa6f61d1e6d1ef607db7a8a8b977edeb5073"
	signed8RootTreeAcceptedLeavesDigest               = "c19e4bfefafb24ae95e85f170b28412db58b8875f113d6dbb327cc3686de5dfd"
	signed8RootTreeAcceptedLeftSourceDigest           = "aff26b45421f4d1bee7d2c6c7e7bc85267b5d6a391c2e64da12dfd3071f6ec85"
	signed8RootTreeAcceptedDeltaSourceDigest          = "228fac2755adcc26725318cb44919b83b1c5d5d43325088631bf496bef573251"
	signed8RootTreeAcceptedLeftPayloadDigest          = "e668d439e8ba6fe95fa9fb6522a3a012a54ab1cd508608af778fdf9d02190f71"
	signed8RootTreeAcceptedDeltaPayloadDigest         = "78d37dba79cef9d7bac05130cc16bb8d47567c973b7b664765d21a7662419e58"
)

const (
	signed8RootTreeComparatorStateIndex = iota
	signed8RootTreeRawProductStateIndex
	signed8RootTreeRescaledStateIndex
	signed8RootTreeOutputStateIndex
)

// Signed8RootTreeFidelity fixes the bounded status of this one-level module.
type Signed8RootTreeFidelity string

const Signed8RootTreeFunctionalNotSecure Signed8RootTreeFidelity = "functional_not_secure"

// Signed8RootTreeOutputEncoding identifies the arithmetic Gao root-slot
// representation returned by the integer-leaf selector.
type Signed8RootTreeOutputEncoding string

const Signed8RootTreeArithmeticRootSlots Signed8RootTreeOutputEncoding = "signed8_arithmetic_root_slots"

// Signed8RootTreeRepresentativePolicy distinguishes the source-scheduled
// modular representative from a fresh canonical re-encoding of the residue.
type Signed8RootTreeRepresentativePolicy string

const Signed8RootTreeSourceScheduledArithmeticRepresentative Signed8RootTreeRepresentativePolicy = "valid_source_scheduled_arithmetic_representative"

// Signed8RootTreeStage identifies every wrapper-owned ciphertext boundary.
type Signed8RootTreeStage string

const (
	Signed8RootTreeStageComparatorGE    Signed8RootTreeStage = "comparator-ge"
	Signed8RootTreeStageRawProduct      Signed8RootTreeStage = "corrected-delta-raw-product"
	Signed8RootTreeStageRescaledProduct Signed8RootTreeStage = "corrected-delta-rescaled-product"
	Signed8RootTreeStageOutput          Signed8RootTreeStage = "selected-arithmetic-leaf"
)

// Signed8RootTreeStateProfile is an immutable exact state contract.
type Signed8RootTreeStateProfile struct {
	stage         Signed8RootTreeStage
	level         int
	degree        int
	logDimensions ring.Dimensions
	scale         ExactScaleSnapshot
}

func (p Signed8RootTreeStateProfile) Stage() Signed8RootTreeStage    { return p.stage }
func (p Signed8RootTreeStateProfile) Level() int                     { return p.level }
func (p Signed8RootTreeStateProfile) Degree() int                    { return p.degree }
func (p Signed8RootTreeStateProfile) LogDimensions() ring.Dimensions { return p.logDimensions }
func (p Signed8RootTreeStateProfile) Scale() ExactScaleSnapshot      { return p.scale }

// Signed8RootTreeOperationCounts records only actual wrapper evaluation
// operations. Comparator work remains nested in its own trace.
type Signed8RootTreeOperationCounts struct {
	ComparatorInvocations              int
	CiphertextPlaintextMultiplications int
	Rescales                           int
	CiphertextPlaintextVectorAdditions int
	Rotations                          int
	Relinearizations                   int
	KeySwitches                        int
}

// Signed8RootTreeSetupCounts separates the two cached public encodings from
// runtime homomorphic operations.
type Signed8RootTreeSetupCounts struct {
	LeftPlaintextEncodings           int
	CorrectedDeltaPlaintextEncodings int
}

// Signed8RootTreeComparatorAuditAnchor is the independently accepted narrow
// comparator projection. It is distinct from the actual range-bound child
// profile used by a particular tree circuit.
type Signed8RootTreeComparatorAuditAnchor struct {
	PublicProfileDigest        string
	OpaqueProfileDigest        string
	AdmissionDigest            string
	ParameterDigest            string
	ArithmeticOnePayloadDigest string
}

// Signed8RootTreeProfile seals one comparator mode and the common public leaf
// operands without exposing mutable plaintexts.
type Signed8RootTreeProfile struct {
	fidelity                    Signed8RootTreeFidelity
	operandMode                 Signed8ComparatorOperandMode
	wordBits                    z2n.WordBits
	words                       int
	slots                       int
	rangeDigest                 string
	parameterDigest             string
	comparatorProfileDigest     string
	comparatorAdmissionDigest   string
	comparatorParameterDigest   string
	comparatorOnePayloadDigest  string
	comparatorAuditAnchor       Signed8RootTreeComparatorAuditAnchor
	leaves                      Signed8PackedLeaves
	leavesDigest                string
	leftSourceDigest            string
	correctedDeltaSourceDigest  string
	leftPayloadDigest           string
	correctedDeltaPayloadDigest string
	outputEncoding              Signed8RootTreeOutputEncoding
	representativePolicy        Signed8RootTreeRepresentativePolicy
	states                      []Signed8RootTreeStateProfile
	operationCounts             Signed8RootTreeOperationCounts
	setupCounts                 Signed8RootTreeSetupCounts
	requiredGaloisElements      []uint64
	requiresRelinearization     bool
	additionalEvaluationKeys    int
	levelLedger                 string
	measurementPolicy           string
	digest                      string
}

func (p Signed8RootTreeProfile) Fidelity() Signed8RootTreeFidelity { return p.fidelity }
func (p Signed8RootTreeProfile) ComparatorOperandMode() Signed8ComparatorOperandMode {
	return p.operandMode
}
func (p Signed8RootTreeProfile) WordBits() z2n.WordBits  { return p.wordBits }
func (p Signed8RootTreeProfile) Words() int              { return p.words }
func (p Signed8RootTreeProfile) Slots() int              { return p.slots }
func (p Signed8RootTreeProfile) RangeDigest() string     { return p.rangeDigest }
func (p Signed8RootTreeProfile) ParameterDigest() string { return p.parameterDigest }
func (p Signed8RootTreeProfile) ComparatorProfileDigest() string {
	return p.comparatorProfileDigest
}
func (p Signed8RootTreeProfile) ComparatorRangeInstanceProfileDigest() string {
	return p.comparatorProfileDigest
}
func (p Signed8RootTreeProfile) ComparatorAdmissionDigest() string {
	return p.comparatorAdmissionDigest
}
func (p Signed8RootTreeProfile) ComparatorRangeInstanceAdmissionDigest() string {
	return p.comparatorAdmissionDigest
}
func (p Signed8RootTreeProfile) ComparatorParameterDigest() string {
	return p.comparatorParameterDigest
}
func (p Signed8RootTreeProfile) ComparatorArithmeticOnePayloadDigest() string {
	return p.comparatorOnePayloadDigest
}
func (p Signed8RootTreeProfile) ComparatorAuditAnchor() Signed8RootTreeComparatorAuditAnchor {
	return p.comparatorAuditAnchor
}
func (p Signed8RootTreeProfile) Leaves() Signed8PackedLeaves { return p.leaves }
func (p Signed8RootTreeProfile) LeavesDigest() string        { return p.leavesDigest }
func (p Signed8RootTreeProfile) LeftOperandSourceDigest() string {
	return p.leftSourceDigest
}
func (p Signed8RootTreeProfile) CorrectedDeltaSourceDigest() string {
	return p.correctedDeltaSourceDigest
}
func (p Signed8RootTreeProfile) LeftOperandPayloadDigest() string {
	return p.leftPayloadDigest
}
func (p Signed8RootTreeProfile) CorrectedDeltaPayloadDigest() string {
	return p.correctedDeltaPayloadDigest
}
func (p Signed8RootTreeProfile) OutputEncoding() Signed8RootTreeOutputEncoding {
	return p.outputEncoding
}
func (p Signed8RootTreeProfile) RepresentativePolicy() Signed8RootTreeRepresentativePolicy {
	return p.representativePolicy
}
func (p Signed8RootTreeProfile) States() []Signed8RootTreeStateProfile {
	return append([]Signed8RootTreeStateProfile(nil), p.states...)
}
func (p Signed8RootTreeProfile) OperationCounts() Signed8RootTreeOperationCounts {
	return p.operationCounts
}
func (p Signed8RootTreeProfile) SetupCounts() Signed8RootTreeSetupCounts { return p.setupCounts }
func (p Signed8RootTreeProfile) RequiredGaloisElements() []uint64 {
	return append([]uint64(nil), p.requiredGaloisElements...)
}
func (p Signed8RootTreeProfile) RequiresRelinearization() bool { return p.requiresRelinearization }
func (p Signed8RootTreeProfile) AdditionalEvaluationKeys() int { return p.additionalEvaluationKeys }
func (p Signed8RootTreeProfile) LevelLedger() string           { return p.levelLedger }
func (p Signed8RootTreeProfile) MeasurementPolicy() string     { return p.measurementPolicy }
func (p Signed8RootTreeProfile) Digest() string                { return p.digest }

func cloneSigned8RootTreeProfile(profile Signed8RootTreeProfile) Signed8RootTreeProfile {
	result := profile
	result.states = profile.States()
	result.requiredGaloisElements = profile.RequiredGaloisElements()
	return result
}

// Signed8LeafPair fixes the public left/right leaves for one packed word.
// Branch zero selects Left and branch one selects Right.
type Signed8LeafPair struct {
	Left  int8
	Right int8
}

// Signed8PackedLeaves contains one public leaf pair per four-slot word block.
type Signed8PackedLeaves [signed8RootTreeWords]Signed8LeafPair

// Signed8RootTreeCircuit owns the accepted comparator plus the two immutable
// public operands used by the integer-leaf selection.
type Signed8RootTreeCircuit struct {
	params         ckks.Parameters
	refreshEncoder *ckks.Encoder
	integerEncoder *ckks.Encoder
	ranges         Signed8NoOverflowRange
	leaves         Signed8PackedLeaves
	comparator     *Signed8ComparatorCircuit
	left           *rlwe.Plaintext
	correctedDelta *rlwe.Plaintext
	leftSeal       *rlwe.Plaintext
	deltaSeal      *rlwe.Plaintext
	publicProfile  Signed8RootTreeProfile
	opaqueProfile  Signed8RootTreeProfile
	graph          signed8RootTreeCircuitGraphIdentity
}

type signed8RootTreeCircuitGraphIdentity struct {
	circuit                *Signed8RootTreeCircuit
	refreshEncoder         *ckks.Encoder
	integerEncoder         *ckks.Encoder
	comparator             *Signed8ComparatorCircuit
	left                   *rlwe.Plaintext
	correctedDelta         *rlwe.Plaintext
	leftSaved              *rlwe.Plaintext
	deltaSaved             *rlwe.Plaintext
	publicDigest           string
	opaqueDigest           string
	comparatorPublicDigest string
	comparatorOpaqueDigest string
}

// Signed8RootTreeCiphertextState is a detached runtime state snapshot.
type Signed8RootTreeCiphertextState struct {
	Stage         Signed8RootTreeStage
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

// Signed8RootTreeSerializedBytes records exact marshaled wrapper boundaries.
// Comparator-owned boundaries remain available in the nested comparator trace.
type Signed8RootTreeSerializedBytes struct {
	ComparatorGE    int
	RawProduct      int
	RescaledProduct int
	Output          int
}

// Signed8RootTreeTrace keeps wrapper evidence separate from the nested
// comparator evidence and returns defensive copies of both.
type Signed8RootTreeTrace struct {
	profileDigest           string
	rangeDigest             string
	comparatorProfileDigest string
	leavesDigest            string
	operandMode             Signed8ComparatorOperandMode
	outputEncoding          Signed8RootTreeOutputEncoding
	representativePolicy    Signed8RootTreeRepresentativePolicy
	states                  []Signed8RootTreeCiphertextState
	operationCounts         Signed8RootTreeOperationCounts
	comparatorTrace         Signed8ComparatorTrace
	keyPreflight            A2BRefreshKeyPreflight
	serializedBytes         Signed8RootTreeSerializedBytes
	timingMeasured          bool
	totalWallTime           time.Duration
	leafSelectionWallTime   time.Duration
}

func (t Signed8RootTreeTrace) ProfileDigest() string { return t.profileDigest }
func (t Signed8RootTreeTrace) RangeDigest() string   { return t.rangeDigest }
func (t Signed8RootTreeTrace) ComparatorProfileDigest() string {
	return t.comparatorProfileDigest
}
func (t Signed8RootTreeTrace) LeavesDigest() string { return t.leavesDigest }
func (t Signed8RootTreeTrace) OperandMode() Signed8ComparatorOperandMode {
	return t.operandMode
}
func (t Signed8RootTreeTrace) OutputEncoding() Signed8RootTreeOutputEncoding {
	return t.outputEncoding
}
func (t Signed8RootTreeTrace) RepresentativePolicy() Signed8RootTreeRepresentativePolicy {
	return t.representativePolicy
}
func (t Signed8RootTreeTrace) States() []Signed8RootTreeCiphertextState {
	return append([]Signed8RootTreeCiphertextState(nil), t.states...)
}
func (t Signed8RootTreeTrace) OperationCounts() Signed8RootTreeOperationCounts {
	return t.operationCounts
}
func (t Signed8RootTreeTrace) ComparatorTrace() Signed8ComparatorTrace {
	return cloneSigned8RootTreeComparatorTrace(t.comparatorTrace)
}
func (t Signed8RootTreeTrace) KeyPreflight() A2BRefreshKeyPreflight {
	return cloneA2BRefreshKeyPreflight(t.keyPreflight)
}
func (t Signed8RootTreeTrace) SerializedBytes() Signed8RootTreeSerializedBytes {
	return t.serializedBytes
}
func (t Signed8RootTreeTrace) TimingMeasured() bool         { return t.timingMeasured }
func (t Signed8RootTreeTrace) TotalWallTime() time.Duration { return t.totalWallTime }
func (t Signed8RootTreeTrace) ComparatorWallTime() time.Duration {
	return t.comparatorTrace.WallTime()
}
func (t Signed8RootTreeTrace) LeafSelectionWallTime() time.Duration {
	return t.leafSelectionWallTime
}

// Signed8RootTreeResult owns the selected signed-byte arithmetic root slots.
type Signed8RootTreeResult struct {
	ciphertext              *rlwe.Ciphertext
	profileDigest           string
	rangeDigest             string
	comparatorProfileDigest string
	leavesDigest            string
	operandMode             Signed8ComparatorOperandMode
	outputEncoding          Signed8RootTreeOutputEncoding
	representativePolicy    Signed8RootTreeRepresentativePolicy
}

func (r Signed8RootTreeResult) Ciphertext() *rlwe.Ciphertext {
	if r.ciphertext == nil {
		return nil
	}
	return r.ciphertext.CopyNew()
}
func (r Signed8RootTreeResult) ProfileDigest() string { return r.profileDigest }
func (r Signed8RootTreeResult) RangeDigest() string   { return r.rangeDigest }
func (r Signed8RootTreeResult) ComparatorProfileDigest() string {
	return r.comparatorProfileDigest
}
func (r Signed8RootTreeResult) LeavesDigest() string { return r.leavesDigest }
func (r Signed8RootTreeResult) OperandMode() Signed8ComparatorOperandMode {
	return r.operandMode
}
func (r Signed8RootTreeResult) OutputEncoding() Signed8RootTreeOutputEncoding {
	return r.outputEncoding
}
func (r Signed8RootTreeResult) RepresentativePolicy() Signed8RootTreeRepresentativePolicy {
	return r.representativePolicy
}

// Signed8RootTreeEvaluator binds the tree, comparator, and leaf selector to
// one exact bootstrap source and MemEvaluationKeySet.
type Signed8RootTreeEvaluator struct {
	circuit            *Signed8RootTreeCircuit
	source             *bootstrapping.Evaluator
	comparator         *Signed8ComparatorEvaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	galoisKeys         map[uint64]*rlwe.GaloisKey
	graph              signed8RootTreeEvaluatorGraphIdentity
}

type signed8RootTreeEvaluatorGraphIdentity struct {
	evaluator              *Signed8RootTreeEvaluator
	circuit                *Signed8RootTreeCircuit
	source                 *bootstrapping.Evaluator
	sourceCKKS             *ckks.Evaluator
	comparator             *Signed8ComparatorEvaluator
	keySet                 *rlwe.MemEvaluationKeySet
	relinearizationKey     *rlwe.RelinearizationKey
	galoisKeyMapPointer    uintptr
	publicDigest           string
	opaqueDigest           string
	comparatorPublicDigest string
	comparatorOpaqueDigest string
}

func (c *Signed8RootTreeCircuit) PublicProfile() Signed8RootTreeProfile {
	if c == nil {
		return Signed8RootTreeProfile{}
	}
	return cloneSigned8RootTreeProfile(c.publicProfile)
}

func (c *Signed8RootTreeCircuit) OpaqueProfile() Signed8RootTreeProfile {
	if c == nil {
		return Signed8RootTreeProfile{}
	}
	return cloneSigned8RootTreeProfile(c.opaqueProfile)
}

func (c *Signed8RootTreeCircuit) Ranges() Signed8NoOverflowRange {
	if c == nil {
		return Signed8NoOverflowRange{}
	}
	return c.ranges
}

func (c *Signed8RootTreeCircuit) Leaves() Signed8PackedLeaves {
	if c == nil {
		return Signed8PackedLeaves{}
	}
	return c.leaves
}

// BindFeature delegates canonical-parameter admission to the sealed
// comparator. The returned handle owns a ciphertext copy and binds the
// declared source parameter and payload digests.
func (c *Signed8RootTreeCircuit) BindFeature(ciphertext *rlwe.Ciphertext, declaredSource ckks.Parameters) (Signed8FeatureInput, error) {
	if err := c.validate(); err != nil {
		return Signed8FeatureInput{}, err
	}
	return c.comparator.BindFeature(ciphertext, declaredSource)
}

// BindOpaqueThreshold delegates canonical-parameter admission to the sealed
// comparator while preserving the distinct CT--CT threshold role.
func (c *Signed8RootTreeCircuit) BindOpaqueThreshold(ciphertext *rlwe.Ciphertext, declaredSource ckks.Parameters) (Signed8OpaqueThresholdInput, error) {
	if err := c.validate(); err != nil {
		return Signed8OpaqueThresholdInput{}, err
	}
	return c.comparator.BindOpaqueThreshold(ciphertext, declaredSource)
}

// BindEvaluator seals the comparator and leaf selector to the same exact
// source evaluator and evaluation-key pointers.
func (c *Signed8RootTreeCircuit) BindEvaluator(source *bootstrapping.Evaluator) (*Signed8RootTreeEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if source == nil || source.Evaluator == nil || source.MemEvaluationKeySet == nil {
		return nil, fmt.Errorf("homchain: signed8 root-tree requires a complete bootstrap evaluator")
	}
	comparator, err := c.comparator.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind signed8 root-tree comparator: %w", err)
	}
	keySet := source.MemEvaluationKeySet
	if comparator.keySet != keySet {
		return nil, fmt.Errorf("homchain: signed8 root-tree comparator keyset differs from the bootstrap source MemEvaluationKeySet")
	}
	if comparator.source != source {
		return nil, fmt.Errorf("homchain: signed8 root-tree comparator source differs from the bootstrap source")
	}
	relinearizationKey, err := keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, fmt.Errorf("homchain: signed8 root-tree inherited relinearization key is missing: %v", err)
	}
	if !reflect.DeepEqual(c.publicProfile.requiredGaloisElements, c.opaqueProfile.requiredGaloisElements) {
		return nil, fmt.Errorf("homchain: signed8 root-tree comparator modes require different key unions")
	}
	galoisKeys := make(map[uint64]*rlwe.GaloisKey, len(c.publicProfile.requiredGaloisElements))
	for _, element := range c.publicProfile.requiredGaloisElements {
		key, keyErr := keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil {
			return nil, fmt.Errorf("homchain: signed8 root-tree inherited Galois key %d is missing: %v", element, keyErr)
		}
		galoisKeys[element] = key
	}
	evaluator := &Signed8RootTreeEvaluator{
		circuit: c, source: source, comparator: comparator, keySet: keySet,
		relinearizationKey: relinearizationKey, galoisKeys: galoisKeys,
	}
	evaluator.graph = signed8RootTreeEvaluatorGraphIdentity{
		evaluator: evaluator, circuit: c, source: source, sourceCKKS: source.Evaluator,
		comparator: comparator, keySet: keySet, relinearizationKey: relinearizationKey,
		galoisKeyMapPointer: reflect.ValueOf(galoisKeys).Pointer(),
		publicDigest:        c.publicProfile.digest, opaqueDigest: c.opaqueProfile.digest,
		comparatorPublicDigest: c.comparator.publicProfile.digest,
		comparatorOpaqueDigest: c.comparator.opaqueProfile.digest,
	}
	// Binding validates the evaluator graph and keys without requiring an input
	// handle. Input admission remains an evaluation-time gate.
	if _, err = evaluator.preflightGraphAndKeys(); err != nil {
		return nil, err
	}
	return evaluator, nil
}

// NewSigned8RootTreeCircuit constructs the bounded four-word SIMD T0 integer
// root-tree circuit. Leaves are server-public signed bytes.
func NewSigned8RootTreeCircuit(
	params ckks.Parameters,
	refreshEncoder *ckks.Encoder,
	integerEncoder *ckks.Encoder,
	ranges Signed8NoOverflowRange,
	leaves Signed8PackedLeaves,
) (*Signed8RootTreeCircuit, error) {
	if err := validateSigned8NoOverflowRange(ranges); err != nil {
		return nil, err
	}
	if err := validateA2BRefreshParameters(params); err != nil {
		return nil, err
	}
	if err := validateSigned8ComparatorEncoders(params, refreshEncoder, integerEncoder); err != nil {
		return nil, err
	}
	comparator, err := NewSigned8ComparatorCircuit(params, refreshEncoder, integerEncoder, ranges)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct signed8 root-tree comparator: %w", err)
	}
	if err = validateSigned8RootTreeAcceptedComparatorProfiles(comparator.PublicProfile(), comparator.OpaqueProfile()); err != nil {
		return nil, err
	}
	left, correctedDelta, err := newSigned8RootTreeOperands(params, integerEncoder, leaves)
	if err != nil {
		return nil, err
	}
	leftDigest, err := signed8PlaintextDigest(left)
	if err != nil {
		return nil, err
	}
	deltaDigest, err := signed8PlaintextDigest(correctedDelta)
	if err != nil {
		return nil, err
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal signed8 root-tree parameters: %w", err)
	}
	parameterDigest := sha256Hex(parameterBytes)
	leftSourceDigest, deltaSourceDigest, err := digestSigned8RootTreeOperandSources(leaves, integerEncoder.Prec())
	if err != nil {
		return nil, err
	}
	publicProfile, err := buildSigned8RootTreeProfile(params, ranges, leaves, leftSourceDigest, deltaSourceDigest, leftDigest, deltaDigest, parameterDigest, comparator.PublicProfile())
	if err != nil {
		return nil, err
	}
	opaqueProfile, err := buildSigned8RootTreeProfile(params, ranges, leaves, leftSourceDigest, deltaSourceDigest, leftDigest, deltaDigest, parameterDigest, comparator.OpaqueProfile())
	if err != nil {
		return nil, err
	}
	if err = validateSigned8RootTreeCanonicalAuditPins(ranges, leaves, publicProfile, opaqueProfile); err != nil {
		return nil, err
	}
	leftSeal, deltaSeal := left.CopyNew(), correctedDelta.CopyNew()
	circuit := &Signed8RootTreeCircuit{
		params: params, refreshEncoder: refreshEncoder, integerEncoder: integerEncoder,
		ranges: ranges, leaves: leaves, comparator: comparator, left: left, correctedDelta: correctedDelta,
		leftSeal: leftSeal, deltaSeal: deltaSeal,
		publicProfile: publicProfile, opaqueProfile: opaqueProfile,
	}
	circuit.graph = signed8RootTreeCircuitGraphIdentity{
		circuit: circuit, refreshEncoder: refreshEncoder, integerEncoder: integerEncoder,
		comparator: comparator, left: left, correctedDelta: correctedDelta,
		leftSaved: leftSeal, deltaSaved: deltaSeal,
		publicDigest: publicProfile.digest, opaqueDigest: opaqueProfile.digest,
		comparatorPublicDigest: comparator.publicProfile.digest,
		comparatorOpaqueDigest: comparator.opaqueProfile.digest,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func validateSigned8RootTreeAcceptedComparatorProfiles(public, opaque Signed8ComparatorProfile) error {
	if public.OperandMode() != Signed8PublicThresholdCTPT || opaque.OperandMode() != Signed8OpaqueThresholdCTCT ||
		public.RangeDigest() == "" || public.RangeDigest() != opaque.RangeDigest() ||
		public.InputBindingDigest() == "" || public.InputBindingDigest() != opaque.InputBindingDigest() {
		return fmt.Errorf("homchain: signed8 root-tree actual range-bound comparator pair is inconsistent")
	}
	actualBinding := digestString(fmt.Sprintf(
		"%s|params=%s|range=%s|a2b=%s|a2b-keys=%s|sign=%s|input=L20/S35/degree1/full-dense/ntt/4x4",
		signed8InputBindingSchema, public.ParameterDigest(), public.RangeDigest(), public.A2BProfileDigest(),
		public.A2BKeyProfileDigest(), public.SignProfileDigest(),
	))
	if public.InputBindingDigest() != actualBinding || public.Digest() != digestSigned8ComparatorProfile(public) ||
		opaque.Digest() != digestSigned8ComparatorProfile(opaque) {
		return fmt.Errorf("homchain: signed8 root-tree actual range-instance admission or profile digest changed")
	}
	if public.ParameterDigest() != signed8RootTreeAcceptedComparatorParameterDigest ||
		opaque.ParameterDigest() != signed8RootTreeAcceptedComparatorParameterDigest ||
		public.ArithmeticOnePayloadDigest() != signed8RootTreeAcceptedComparatorOnePayloadDigest ||
		opaque.ArithmeticOnePayloadDigest() != signed8RootTreeAcceptedComparatorOnePayloadDigest {
		return fmt.Errorf("homchain: signed8 root-tree comparator parameter or arithmetic-one audit anchor changed")
	}
	narrowRange, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		return err
	}
	narrowBinding := digestString(fmt.Sprintf(
		"%s|params=%s|range=%s|a2b=%s|a2b-keys=%s|sign=%s|input=L20/S35/degree1/full-dense/ntt/4x4",
		signed8InputBindingSchema, public.ParameterDigest(), narrowRange.Digest(), public.A2BProfileDigest(),
		public.A2BKeyProfileDigest(), public.SignProfileDigest(),
	))
	if narrowBinding != signed8RootTreeAcceptedComparatorAdmissionDigest {
		return fmt.Errorf("homchain: signed8 root-tree reconstructed comparator admission audit anchor changed")
	}
	project := func(profile Signed8ComparatorProfile) string {
		profile.rangeDigest = narrowRange.Digest()
		profile.inputBindingDigest = narrowBinding
		return digestSigned8ComparatorProfile(profile)
	}
	if project(public) != signed8RootTreeAcceptedComparatorPublicDigest ||
		project(opaque) != signed8RootTreeAcceptedComparatorOpaqueDigest {
		return fmt.Errorf("homchain: signed8 root-tree comparator invariant projection differs from the accepted narrow audit anchor")
	}
	return nil
}

func signed8RootTreeCanonicalAuditLeaves() Signed8PackedLeaves {
	return Signed8PackedLeaves{
		{Left: -128, Right: 127},
		{Left: 127, Right: -128},
		{Left: -7, Right: 19},
		{Left: 42, Right: -99},
	}
}

// validateSigned8RootTreeCanonicalAuditPins freezes the narrow T0 evidence
// independently from the profile builder. Other admitted ranges and public
// leaf tables remain range-instance profiles rather than being retagged with
// this audit anchor.
func validateSigned8RootTreeCanonicalAuditPins(
	ranges Signed8NoOverflowRange,
	leaves Signed8PackedLeaves,
	public, opaque Signed8RootTreeProfile,
) error {
	narrow, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		return err
	}
	if ranges != narrow || leaves != signed8RootTreeCanonicalAuditLeaves() {
		return nil
	}
	if public.digest != signed8RootTreeAcceptedPublicProfileDigest ||
		opaque.digest != signed8RootTreeAcceptedOpaqueProfileDigest ||
		public.leavesDigest != signed8RootTreeAcceptedLeavesDigest ||
		opaque.leavesDigest != signed8RootTreeAcceptedLeavesDigest ||
		public.leftSourceDigest != signed8RootTreeAcceptedLeftSourceDigest ||
		opaque.leftSourceDigest != signed8RootTreeAcceptedLeftSourceDigest ||
		public.correctedDeltaSourceDigest != signed8RootTreeAcceptedDeltaSourceDigest ||
		opaque.correctedDeltaSourceDigest != signed8RootTreeAcceptedDeltaSourceDigest ||
		public.leftPayloadDigest != signed8RootTreeAcceptedLeftPayloadDigest ||
		opaque.leftPayloadDigest != signed8RootTreeAcceptedLeftPayloadDigest ||
		public.correctedDeltaPayloadDigest != signed8RootTreeAcceptedDeltaPayloadDigest ||
		opaque.correctedDeltaPayloadDigest != signed8RootTreeAcceptedDeltaPayloadDigest ||
		public.outputEncoding != Signed8RootTreeArithmeticRootSlots ||
		opaque.outputEncoding != Signed8RootTreeArithmeticRootSlots {
		return fmt.Errorf("homchain: canonical narrow signed8 root-tree audit pin changed")
	}
	return nil
}

func buildSigned8RootTreeProfile(
	params ckks.Parameters,
	ranges Signed8NoOverflowRange,
	leaves Signed8PackedLeaves,
	leftSourceDigest, deltaSourceDigest string,
	leftDigest, deltaDigest, parameterDigest string,
	comparatorProfile Signed8ComparatorProfile,
) (Signed8RootTreeProfile, error) {
	inputScale, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return Signed8RootTreeProfile{}, err
	}
	productScale, err := NewExactScaleSnapshot(params.DefaultScale().Mul(rlwe.NewScale(params.Q()[signed8RootTreeBranchLevel])))
	if err != nil {
		return Signed8RootTreeProfile{}, err
	}
	states := []Signed8RootTreeStateProfile{
		{stage: Signed8RootTreeStageComparatorGE, level: signed8RootTreeBranchLevel, degree: signed8RootTreeCiphertextDegree, logDimensions: params.LogMaxDimensions(), scale: inputScale},
		{stage: Signed8RootTreeStageRawProduct, level: signed8RootTreeBranchLevel, degree: signed8RootTreeCiphertextDegree, logDimensions: params.LogMaxDimensions(), scale: productScale},
		{stage: Signed8RootTreeStageRescaledProduct, level: signed8RootTreeOutputLevel, degree: signed8RootTreeCiphertextDegree, logDimensions: params.LogMaxDimensions(), scale: inputScale},
		{stage: Signed8RootTreeStageOutput, level: signed8RootTreeOutputLevel, degree: signed8RootTreeCiphertextDegree, logDimensions: params.LogMaxDimensions(), scale: inputScale},
	}
	profile := Signed8RootTreeProfile{
		fidelity: Signed8RootTreeFunctionalNotSecure, operandMode: comparatorProfile.OperandMode(),
		wordBits: z2n.Word8, words: signed8RootTreeWords, slots: signed8RootTreeSlots,
		rangeDigest: ranges.Digest(), parameterDigest: parameterDigest,
		comparatorProfileDigest:    comparatorProfile.Digest(),
		comparatorAdmissionDigest:  comparatorProfile.InputBindingDigest(),
		comparatorParameterDigest:  comparatorProfile.ParameterDigest(),
		comparatorOnePayloadDigest: comparatorProfile.ArithmeticOnePayloadDigest(),
		comparatorAuditAnchor: Signed8RootTreeComparatorAuditAnchor{
			PublicProfileDigest:        signed8RootTreeAcceptedComparatorPublicDigest,
			OpaqueProfileDigest:        signed8RootTreeAcceptedComparatorOpaqueDigest,
			AdmissionDigest:            signed8RootTreeAcceptedComparatorAdmissionDigest,
			ParameterDigest:            signed8RootTreeAcceptedComparatorParameterDigest,
			ArithmeticOnePayloadDigest: signed8RootTreeAcceptedComparatorOnePayloadDigest,
		},
		leaves:       leaves,
		leavesDigest: digestSigned8RootTreeLeaves(leaves), leftSourceDigest: leftSourceDigest,
		correctedDeltaSourceDigest: deltaSourceDigest, leftPayloadDigest: leftDigest,
		correctedDeltaPayloadDigest: deltaDigest, outputEncoding: Signed8RootTreeArithmeticRootSlots,
		representativePolicy: Signed8RootTreeSourceScheduledArithmeticRepresentative,
		states:               states,
		operationCounts: Signed8RootTreeOperationCounts{
			ComparatorInvocations: 1, CiphertextPlaintextMultiplications: 1, Rescales: 1,
			CiphertextPlaintextVectorAdditions: 1,
		},
		setupCounts:              Signed8RootTreeSetupCounts{LeftPlaintextEncodings: 1, CorrectedDeltaPlaintextEncodings: 1},
		requiredGaloisElements:   comparatorProfile.RequiredGaloisElements(),
		requiresRelinearization:  comparatorProfile.RequiresRelinearization(),
		additionalEvaluationKeys: 0, levelLedger: signed8RootTreeLevelLedger,
		measurementPolicy: signed8RootTreeMeasurementPolicy,
	}
	profile.digest = digestSigned8RootTreeProfile(profile)
	return profile, nil
}

func (c *Signed8RootTreeCircuit) validate() error {
	if c == nil || c.refreshEncoder == nil || c.integerEncoder == nil || c.comparator == nil || c.left == nil || c.correctedDelta == nil ||
		c.leftSeal == nil || c.deltaSeal == nil {
		return fmt.Errorf("homchain: nil or incomplete signed8 root-tree circuit")
	}
	if err := validateA2BRefreshParameters(c.params); err != nil {
		return err
	}
	if err := validateSigned8ComparatorEncoders(c.params, c.refreshEncoder, c.integerEncoder); err != nil {
		return err
	}
	if err := validateSigned8NoOverflowRange(c.ranges); err != nil {
		return err
	}
	if err := c.comparator.validate(); err != nil {
		return err
	}
	if err := validateSigned8RootTreeAcceptedComparatorProfiles(c.comparator.PublicProfile(), c.comparator.OpaqueProfile()); err != nil {
		return err
	}
	g := c.graph
	if g.circuit != c || g.refreshEncoder != c.refreshEncoder || g.integerEncoder != c.integerEncoder ||
		g.comparator != c.comparator || g.left != c.left || g.correctedDelta != c.correctedDelta ||
		g.leftSaved != c.leftSeal || g.deltaSaved != c.deltaSeal ||
		!c.left.Equal(c.leftSeal) || !c.correctedDelta.Equal(c.deltaSeal) ||
		g.publicDigest != c.publicProfile.digest || g.opaqueDigest != c.opaqueProfile.digest ||
		g.comparatorPublicDigest != c.comparator.publicProfile.digest || g.comparatorOpaqueDigest != c.comparator.opaqueProfile.digest {
		return fmt.Errorf("homchain: signed8 root-tree circuit object graph changed")
	}
	if c.comparator.ranges != c.ranges || c.left == c.correctedDelta {
		return fmt.Errorf("homchain: signed8 root-tree comparator range or operand identity changed")
	}
	defaultScale, err := NewExactScaleSnapshot(c.params.DefaultScale())
	if err != nil {
		return err
	}
	leftState := Signed8ComparatorStateProfile{level: signed8RootTreeOutputLevel, degree: signed8RootTreePlaintextDegree, logDimensions: c.params.LogMaxDimensions(), scale: defaultScale}
	deltaScale, err := NewExactScaleSnapshot(rlwe.NewScale(c.params.Q()[signed8RootTreeBranchLevel]))
	if err != nil {
		return err
	}
	deltaState := Signed8ComparatorStateProfile{level: signed8RootTreeBranchLevel, degree: signed8RootTreePlaintextDegree, logDimensions: c.params.LogMaxDimensions(), scale: deltaScale}
	if err = requireSigned8PlaintextState("root-tree left", c.left, leftState, c.params); err != nil {
		return err
	}
	if err = requireSigned8PlaintextState("root-tree corrected delta", c.correctedDelta, deltaState, c.params); err != nil {
		return err
	}
	leftDigest, err := signed8PlaintextDigest(c.left)
	if err != nil {
		return err
	}
	deltaDigest, err := signed8PlaintextDigest(c.correctedDelta)
	if err != nil {
		return err
	}
	parameterBytes, err := c.params.MarshalBinary()
	if err != nil {
		return err
	}
	leftSourceDigest, deltaSourceDigest, err := digestSigned8RootTreeOperandSources(c.leaves, c.integerEncoder.Prec())
	if err != nil {
		return err
	}
	wantPublic, err := buildSigned8RootTreeProfile(c.params, c.ranges, c.leaves, leftSourceDigest, deltaSourceDigest, leftDigest, deltaDigest, sha256Hex(parameterBytes), c.comparator.PublicProfile())
	if err != nil {
		return err
	}
	wantOpaque, err := buildSigned8RootTreeProfile(c.params, c.ranges, c.leaves, leftSourceDigest, deltaSourceDigest, leftDigest, deltaDigest, sha256Hex(parameterBytes), c.comparator.OpaqueProfile())
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(c.publicProfile, wantPublic) || !reflect.DeepEqual(c.opaqueProfile, wantOpaque) {
		return fmt.Errorf("homchain: signed8 root-tree sealed profiles or payload digests changed")
	}
	if err = validateSigned8RootTreeCanonicalAuditPins(c.ranges, c.leaves, c.publicProfile, c.opaqueProfile); err != nil {
		return err
	}
	return nil
}

func (e *Signed8RootTreeEvaluator) preflightGraphAndKeys() (A2BRefreshKeyPreflight, error) {
	result := A2BRefreshKeyPreflight{Checked: true, GraphChecked: true}
	if e == nil || e.circuit == nil || e.source == nil || e.comparator == nil || e.keySet == nil {
		return result, fmt.Errorf("homchain: nil or incomplete signed8 root-tree evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		result.GraphMismatch = err.Error()
		return result, err
	}
	g := e.graph
	if g.evaluator != e || g.circuit != e.circuit || g.source != e.source || g.sourceCKKS != e.source.Evaluator ||
		g.comparator != e.comparator || g.keySet != e.keySet || g.relinearizationKey != e.relinearizationKey ||
		g.galoisKeyMapPointer != reflect.ValueOf(e.galoisKeys).Pointer() ||
		g.publicDigest != e.circuit.publicProfile.digest || g.opaqueDigest != e.circuit.opaqueProfile.digest ||
		g.comparatorPublicDigest != e.circuit.comparator.publicProfile.digest ||
		g.comparatorOpaqueDigest != e.circuit.comparator.opaqueProfile.digest ||
		e.source.MemEvaluationKeySet != e.keySet ||
		e.comparator.source != e.source || e.comparator.keySet != e.keySet {
		result.GraphMismatch = "source, comparator, profile, or keyset identity changed"
		return result, fmt.Errorf("homchain: signed8 root-tree graph preflight failed: %s", result.GraphMismatch)
	}
	childPreflight, err := e.comparator.preflight()
	if err != nil {
		return childPreflight, err
	}
	relinearizationKey, err := e.keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil || relinearizationKey != e.relinearizationKey {
		return result, fmt.Errorf("homchain: signed8 root-tree inherited relinearization key identity changed")
	}
	for element, expected := range e.galoisKeys {
		key, keyErr := e.keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil || key != expected {
			return result, fmt.Errorf("homchain: signed8 root-tree inherited Galois key %d identity changed", element)
		}
	}
	if len(e.galoisKeys) != len(e.circuit.publicProfile.requiredGaloisElements) {
		return result, fmt.Errorf("homchain: signed8 root-tree captured Galois-key map cardinality changed")
	}
	childPreflight.GraphMatched = true
	return childPreflight, nil
}

func (e *Signed8RootTreeEvaluator) preflightPublic(feature Signed8FeatureInput, thresholds [signed8RootTreeWords]int64) (A2BRefreshKeyPreflight, error) {
	preflight, err := e.preflightGraphAndKeys()
	if err != nil {
		return preflight, err
	}
	if err = e.circuit.comparator.validateFeatureHandle(feature); err != nil {
		return preflight, err
	}
	if _, err = e.circuit.comparator.validatePublicThresholds(thresholds); err != nil {
		return preflight, err
	}
	return preflight, nil
}

func (e *Signed8RootTreeEvaluator) preflightOpaque(feature Signed8FeatureInput, threshold Signed8OpaqueThresholdInput) (A2BRefreshKeyPreflight, error) {
	preflight, err := e.preflightGraphAndKeys()
	if err != nil {
		return preflight, err
	}
	if err = e.circuit.comparator.validateFeatureHandle(feature); err != nil {
		return preflight, err
	}
	if err = e.circuit.comparator.validateThresholdHandle(threshold); err != nil {
		return preflight, err
	}
	return preflight, nil
}

// EvaluatePublicNew evaluates the CT--PT root comparison and selects one
// server-public int8 leaf per packed word.
func (e *Signed8RootTreeEvaluator) EvaluatePublicNew(
	feature Signed8FeatureInput,
	thresholds [signed8RootTreeWords]int64,
) (Signed8RootTreeResult, Signed8RootTreeTrace, error) {
	started := time.Now()
	if e == nil || e.circuit == nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: nil signed8 root-tree evaluator")
	}
	preflight, err := e.preflightPublic(feature, thresholds)
	if err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	return e.evaluateNew(feature, Signed8OpaqueThresholdInput{}, thresholds, Signed8PublicThresholdCTPT, preflight, started)
}

// EvaluateOpaqueNew evaluates the CT--CT root comparison and the same public
// integer-leaf selection without merging the two provenance modes.
func (e *Signed8RootTreeEvaluator) EvaluateOpaqueNew(
	feature Signed8FeatureInput,
	threshold Signed8OpaqueThresholdInput,
) (Signed8RootTreeResult, Signed8RootTreeTrace, error) {
	started := time.Now()
	if e == nil || e.circuit == nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: nil signed8 root-tree evaluator")
	}
	preflight, err := e.preflightOpaque(feature, threshold)
	if err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	return e.evaluateNew(feature, threshold, [signed8RootTreeWords]int64{}, Signed8OpaqueThresholdCTCT, preflight, started)
}

func (e *Signed8RootTreeEvaluator) evaluateNew(
	feature Signed8FeatureInput,
	threshold Signed8OpaqueThresholdInput,
	publicThresholds [signed8RootTreeWords]int64,
	mode Signed8ComparatorOperandMode,
	preflight A2BRefreshKeyPreflight,
	started time.Time,
) (Signed8RootTreeResult, Signed8RootTreeTrace, error) {
	var comparatorResult Signed8ComparatorResult
	var comparatorTrace Signed8ComparatorTrace
	var err error
	featureBefore := feature.ciphertext.CopyNew()
	var thresholdBefore *rlwe.Ciphertext
	if mode == Signed8OpaqueThresholdCTCT {
		thresholdBefore = threshold.ciphertext.CopyNew()
		comparatorResult, comparatorTrace, err = e.comparator.CompareGEOpaqueNew(feature, threshold)
	} else {
		comparatorResult, comparatorTrace, err = e.comparator.CompareGEPublicNew(feature, publicThresholds)
	}
	if err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	profile := e.circuit.profileForMode(mode)
	branch, err := validateSigned8RootTreeComparatorEvidence(e.circuit, profile, comparatorResult, comparatorTrace, preflight)
	if err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	if !feature.ciphertext.Equal(featureBefore) || (thresholdBefore != nil && !threshold.ciphertext.Equal(thresholdBefore)) {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: signed8 root-tree comparator mutated an admitted operand")
	}
	trace := Signed8RootTreeTrace{
		profileDigest: profile.digest, rangeDigest: profile.rangeDigest,
		comparatorProfileDigest: profile.comparatorProfileDigest, leavesDigest: profile.leavesDigest,
		operandMode: mode, outputEncoding: profile.outputEncoding,
		representativePolicy: profile.representativePolicy,
		comparatorTrace:      cloneSigned8RootTreeComparatorTrace(comparatorTrace), keyPreflight: cloneA2BRefreshKeyPreflight(preflight),
	}
	trace.operationCounts.ComparatorInvocations++
	if err = appendSigned8RootTreeState(&trace, Signed8RootTreeStageComparatorGE, branch); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}

	selectionStarted := time.Now()
	branchBefore := branch.CopyNew()
	rawProduct, err := e.source.Evaluator.MulNew(branch, e.circuit.correctedDelta)
	if err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: signed8 root-tree corrected-delta multiply: %w", err)
	}
	trace.operationCounts.CiphertextPlaintextMultiplications++
	if !branch.Equal(branchBefore) {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: signed8 root-tree multiply mutated comparator branch")
	}
	if err = requireSigned8RootTreeState("raw corrected-delta product", rawProduct, profile.states[signed8RootTreeRawProductStateIndex], e.circuit.params); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	if err = appendSigned8RootTreeState(&trace, Signed8RootTreeStageRawProduct, rawProduct); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	rawBefore := rawProduct.CopyNew()
	rescaled := rawProduct.CopyNew()
	if err = e.source.Evaluator.Rescale(rescaled, rescaled); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: signed8 root-tree corrected-delta rescale: %w", err)
	}
	trace.operationCounts.Rescales++
	if !rawProduct.Equal(rawBefore) {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: signed8 root-tree rescale mutated saved raw product")
	}
	if err = requireSigned8RootTreeState("rescaled corrected-delta product", rescaled, profile.states[signed8RootTreeRescaledStateIndex], e.circuit.params); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	if err = appendSigned8RootTreeState(&trace, Signed8RootTreeStageRescaledProduct, rescaled); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	rescaledBefore := rescaled.CopyNew()
	output, err := e.source.Evaluator.AddNew(rescaled, e.circuit.left)
	if err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: signed8 root-tree add left leaves: %w", err)
	}
	trace.operationCounts.CiphertextPlaintextVectorAdditions++
	if !rescaled.Equal(rescaledBefore) {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: signed8 root-tree left addition mutated rescaled product")
	}
	if err = requireSigned8RootTreeState("selected leaf output", output, profile.states[signed8RootTreeOutputStateIndex], e.circuit.params); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	if err = appendSigned8RootTreeState(&trace, Signed8RootTreeStageOutput, output); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	trace.leafSelectionWallTime = time.Since(selectionStarted)
	trace.serializedBytes, err = measureSigned8RootTreeBoundaryBytes(branch, rawProduct, rescaled, output)
	if err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	if err = validateSigned8RootTreeRuntimeEvidenceBeforeTiming(profile, trace); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	if !e.circuit.left.Equal(e.circuit.leftSeal) || !e.circuit.correctedDelta.Equal(e.circuit.deltaSeal) {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, fmt.Errorf("homchain: signed8 root-tree mutated a cached public operand")
	}
	trace.totalWallTime = time.Since(started)
	trace.timingMeasured = true
	if err = validateSigned8RootTreeTimingEvidence(trace); err != nil {
		return Signed8RootTreeResult{}, Signed8RootTreeTrace{}, err
	}
	return Signed8RootTreeResult{
		ciphertext: output, profileDigest: profile.digest, rangeDigest: profile.rangeDigest,
		comparatorProfileDigest: profile.comparatorProfileDigest, leavesDigest: profile.leavesDigest,
		operandMode: mode, outputEncoding: profile.outputEncoding, representativePolicy: profile.representativePolicy,
	}, trace, nil
}

func (c *Signed8RootTreeCircuit) profileForMode(mode Signed8ComparatorOperandMode) Signed8RootTreeProfile {
	if c == nil {
		return Signed8RootTreeProfile{}
	}
	switch mode {
	case Signed8PublicThresholdCTPT:
		return c.publicProfile
	case Signed8OpaqueThresholdCTCT:
		return c.opaqueProfile
	default:
		return Signed8RootTreeProfile{}
	}
}

func validateSigned8RootTreeComparatorEvidence(
	circuit *Signed8RootTreeCircuit,
	profile Signed8RootTreeProfile,
	result Signed8ComparatorResult,
	trace Signed8ComparatorTrace,
	preflight A2BRefreshKeyPreflight,
) (*rlwe.Ciphertext, error) {
	if circuit == nil || profile.digest == "" {
		return nil, fmt.Errorf("homchain: signed8 root-tree comparator evidence has no sealed profile")
	}
	childProfile := circuit.comparator.profileForMode(profile.operandMode)
	if result.ProfileDigest() != profile.comparatorProfileDigest || result.RangeDigest() != profile.rangeDigest ||
		result.OperandMode() != profile.operandMode || trace.ProfileDigest() != profile.comparatorProfileDigest ||
		trace.RangeDigest() != profile.rangeDigest || trace.OperandMode() != profile.operandMode ||
		!reflect.DeepEqual(trace.KeyPreflight(), preflight) {
		return nil, fmt.Errorf("homchain: signed8 root-tree comparator result or trace provenance changed")
	}
	if err := validateSigned8RuntimeEvidence(childProfile, trace); err != nil {
		return nil, fmt.Errorf("homchain: signed8 root-tree comparator evidence: %w", err)
	}
	branch := result.Ciphertext()
	if err := requireSigned8RootTreeState("comparator GE branch", branch, profile.states[signed8RootTreeComparatorStateIndex], circuit.params); err != nil {
		return nil, err
	}
	return branch, nil
}

func requireSigned8RootTreeState(name string, ciphertext *rlwe.Ciphertext, profile Signed8RootTreeStateProfile, params ckks.Parameters) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != profile.level || ciphertext.Degree() != profile.degree ||
		ciphertext.LogN() != params.LogN() || ciphertext.LogDimensions != profile.logDimensions || ciphertext.Slots() != signed8RootTreeSlots ||
		!ciphertext.IsBatched || !ciphertext.IsNTT || !profile.scale.EqualScale(ciphertext.Scale) {
		return fmt.Errorf("homchain: signed8 root-tree %s is not exact L%d/degree%d/full-packed/NTT at the sealed scale", name, profile.level, profile.degree)
	}
	return nil
}

func appendSigned8RootTreeState(trace *Signed8RootTreeTrace, stage Signed8RootTreeStage, ciphertext *rlwe.Ciphertext) error {
	if trace == nil || ciphertext == nil || ciphertext.MetaData == nil {
		return fmt.Errorf("homchain: cannot snapshot signed8 root-tree %s", stage)
	}
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return err
	}
	trace.states = append(trace.states, Signed8RootTreeCiphertextState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale,
	})
	return nil
}

func measureSigned8RootTreeBoundaryBytes(
	branch, rawProduct, rescaledProduct, output *rlwe.Ciphertext,
) (Signed8RootTreeSerializedBytes, error) {
	measure := func(name string, ciphertext *rlwe.Ciphertext) (int, error) {
		if ciphertext == nil {
			return 0, fmt.Errorf("homchain: marshal nil signed8 root-tree %s", name)
		}
		payload, err := ciphertext.MarshalBinary()
		if err != nil {
			return 0, fmt.Errorf("homchain: marshal signed8 root-tree %s: %w", name, err)
		}
		return len(payload), nil
	}
	result := Signed8RootTreeSerializedBytes{}
	var err error
	if result.ComparatorGE, err = measure("comparator GE", branch); err != nil {
		return result, err
	}
	if result.RawProduct, err = measure("raw corrected-delta product", rawProduct); err != nil {
		return result, err
	}
	if result.RescaledProduct, err = measure("rescaled corrected-delta product", rescaledProduct); err != nil {
		return result, err
	}
	if result.Output, err = measure("selected leaf output", output); err != nil {
		return result, err
	}
	return result, nil
}

func validateSigned8RootTreeRuntimeEvidenceBeforeTiming(profile Signed8RootTreeProfile, trace Signed8RootTreeTrace) error {
	if trace.profileDigest != profile.digest || trace.rangeDigest != profile.rangeDigest ||
		trace.comparatorProfileDigest != profile.comparatorProfileDigest || trace.leavesDigest != profile.leavesDigest ||
		trace.operandMode != profile.operandMode || trace.outputEncoding != profile.outputEncoding ||
		trace.representativePolicy != profile.representativePolicy {
		return fmt.Errorf("homchain: signed8 root-tree runtime provenance differs from the sealed profile")
	}
	if trace.operationCounts != profile.operationCounts {
		return fmt.Errorf("homchain: signed8 root-tree runtime counts=%+v, want %+v", trace.operationCounts, profile.operationCounts)
	}
	serialized := trace.serializedBytes
	if serialized.ComparatorGE <= 0 || serialized.RawProduct <= 0 || serialized.RescaledProduct <= 0 || serialized.Output <= 0 {
		return fmt.Errorf("homchain: signed8 root-tree boundary serialization measurement is incomplete")
	}
	if len(trace.states) != len(profile.states) {
		return fmt.Errorf("homchain: signed8 root-tree runtime states=%d, want %d", len(trace.states), len(profile.states))
	}
	for index, state := range trace.states {
		want := profile.states[index]
		if state.Stage != want.stage || state.Level != want.level || state.Degree != want.degree ||
			state.LogDimensions != want.logDimensions || !state.Scale.Equal(want.scale) {
			return fmt.Errorf("homchain: signed8 root-tree runtime state %d differs from the ordered profile", index)
		}
	}
	return nil
}

func validateSigned8RootTreeTimingEvidence(trace Signed8RootTreeTrace) error {
	if !trace.timingMeasured || trace.totalWallTime < 0 || trace.leafSelectionWallTime < 0 ||
		trace.totalWallTime < trace.comparatorTrace.WallTime()+trace.leafSelectionWallTime {
		return fmt.Errorf("homchain: signed8 root-tree total/comparator/selection timing provenance is invalid")
	}
	return nil
}

func cloneSigned8RootTreeComparatorTrace(trace Signed8ComparatorTrace) Signed8ComparatorTrace {
	result := trace
	result.states = trace.States()
	result.a2bTrace = trace.SerialA2BTrace()
	result.signProvenance = trace.SignProvenance()
	result.keyPreflight = trace.KeyPreflight()
	return result
}

func newSigned8RootTreeOperands(params ckks.Parameters, encoder *ckks.Encoder, leaves Signed8PackedLeaves) (*rlwe.Plaintext, *rlwe.Plaintext, error) {
	var leftWords [signed8RootTreeWords]uint64
	for index, pair := range leaves {
		leftWords[index] = uint64(uint8(pair.Left))
	}
	left, err := newSigned8WordPlaintext(params, encoder, signed8IntegerEncoderPrecision, signed8RootTreeOutputLevel, leftWords)
	if err != nil {
		return nil, nil, fmt.Errorf("homchain: encode signed8 root-tree left leaves: %w", err)
	}
	delta, err := newSigned8CorrectedDeltaPlaintext(params, encoder, leaves)
	if err != nil {
		return nil, nil, err
	}
	return left, delta, nil
}

func newSigned8CorrectedDeltaPlaintext(params ckks.Parameters, encoder *ckks.Encoder, leaves Signed8PackedLeaves) (*rlwe.Plaintext, error) {
	if encoder == nil || encoder.Prec() != signed8IntegerEncoderPrecision {
		return nil, fmt.Errorf("homchain: signed8 root-tree corrected-delta encoder must have precision %d", signed8IntegerEncoderPrecision)
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, encoder.Prec())
	if err != nil {
		return nil, err
	}
	values := make([]*bignum.Complex, signed8RootTreeSlots)
	for wordIndex, pair := range leaves {
		delta := uint64(uint8(int16(pair.Right) - int16(pair.Left)))
		rootSlots, rootErr := ringZ.ToRootSlots(ringZ.BinaryEncode(delta))
		if rootErr != nil {
			return nil, fmt.Errorf("homchain: encode corrected delta[%d]: %w", wordIndex, rootErr)
		}
		if len(rootSlots) != signed8RootTreeWordSlots {
			return nil, fmt.Errorf("homchain: corrected delta[%d] has %d root slots, want %d", wordIndex, len(rootSlots), signed8RootTreeWordSlots)
		}
		for slot := 0; slot < signed8RootTreeWordSlots; slot++ {
			values[signed8RootTreeWordSlots*wordIndex+slot] = bignum.ToComplex(rootSlots[slot], encoder.Prec())
		}
	}
	plaintext := ckks.NewPlaintext(params, signed8RootTreeBranchLevel)
	plaintext.LogDimensions = params.LogMaxDimensions()
	plaintext.Scale = rlwe.NewScale(params.Q()[signed8RootTreeBranchLevel])
	if err = encoder.Encode(values, plaintext); err != nil {
		return nil, fmt.Errorf("homchain: encode signed8 root-tree corrected-delta plaintext: %w", err)
	}
	return plaintext, nil
}

func digestSigned8RootTreeLeaves(leaves Signed8PackedLeaves) string {
	var canonical strings.Builder
	canonical.WriteString("signed8-root-tree-leaves-v1")
	for index, pair := range leaves {
		fmt.Fprintf(&canonical, "|word=%d/left=%d/right=%d/delta=%d", index, pair.Left, pair.Right,
			uint8(int16(pair.Right)-int16(pair.Left)))
	}
	return digestString(canonical.String())
}

func digestSigned8RootTreeOperandSources(leaves Signed8PackedLeaves, precision uint) (string, string, error) {
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, precision)
	if err != nil {
		return "", "", err
	}
	var leftCanonical, deltaCanonical strings.Builder
	fmt.Fprintf(&leftCanonical, "signed8-root-tree-left-source-v1|precision=%d", precision)
	fmt.Fprintf(&deltaCanonical, "signed8-root-tree-corrected-delta-source-v1|precision=%d|encoding=ToRootSlots(BinaryEncode(delta))", precision)
	for wordIndex, pair := range leaves {
		left := ringZ.ArithmeticRootSlots(uint64(uint8(pair.Left)))
		delta := uint64(uint8(int16(pair.Right) - int16(pair.Left)))
		corrected, rootErr := ringZ.ToRootSlots(ringZ.BinaryEncode(delta))
		if rootErr != nil {
			return "", "", rootErr
		}
		for slot := range left {
			fmt.Fprintf(&leftCanonical, "|w=%d/s=%d/%s,%s", wordIndex, slot,
				left[slot].Real().Text('x', -1), left[slot].Imag().Text('x', -1))
			fmt.Fprintf(&deltaCanonical, "|w=%d/s=%d/%s,%s", wordIndex, slot,
				corrected[slot].Real().Text('x', -1), corrected[slot].Imag().Text('x', -1))
		}
	}
	return digestString(leftCanonical.String()), digestString(deltaCanonical.String()), nil
}

func digestSigned8RootTreeProfile(profile Signed8RootTreeProfile) string {
	var canonical strings.Builder
	fmt.Fprintf(&canonical,
		"%s|fidelity=%s|mode=%s|word=%d|words=%d|slots=%d|range=%s|params=%s|actual-range-instance-profile=%s|actual-range-instance-admission=%s|actual-range-instance-params=%s|actual-range-instance-one=%s|audit-anchor-public=%s|audit-anchor-opaque=%s|audit-anchor-admission=%s|audit-anchor-params=%s|audit-anchor-one=%s|leaves=%v/%s|left-source=%s|corrected-delta-source=%s|left=%s|corrected-delta=%s|output=%s|representative=%s|counts=%+v|setup=%+v|galois=%v|relinearization=%t|additional-keys=%d|ledger=%s|measurement=%s",
		signed8RootTreeProfileSchema, profile.fidelity, profile.operandMode, profile.wordBits,
		profile.words, profile.slots, profile.rangeDigest, profile.parameterDigest,
		profile.comparatorProfileDigest, profile.comparatorAdmissionDigest, profile.comparatorParameterDigest,
		profile.comparatorOnePayloadDigest, profile.comparatorAuditAnchor.PublicProfileDigest,
		profile.comparatorAuditAnchor.OpaqueProfileDigest, profile.comparatorAuditAnchor.AdmissionDigest,
		profile.comparatorAuditAnchor.ParameterDigest, profile.comparatorAuditAnchor.ArithmeticOnePayloadDigest,
		profile.leaves, profile.leavesDigest, profile.leftSourceDigest,
		profile.correctedDeltaSourceDigest, profile.leftPayloadDigest,
		profile.correctedDeltaPayloadDigest, profile.outputEncoding, profile.representativePolicy, profile.operationCounts,
		profile.setupCounts, profile.requiredGaloisElements, profile.requiresRelinearization,
		profile.additionalEvaluationKeys, profile.levelLedger, profile.measurementPolicy)
	for _, state := range profile.states {
		fmt.Fprintf(&canonical, "|state=%s/L%d/D%d/dim=%d,%d/scale={%s}", state.stage, state.level,
			state.degree, state.logDimensions.Rows, state.logDimensions.Cols, state.scale.canonicalString())
	}
	return digestString(canonical.String())
}

// signed8RootTreeSelectSlots is the plaintext algebraic specification for the
// tau-corrected arithmetic-root selection used by the ciphertext circuit.
func signed8RootTreeSelectSlots(ringZ *z2n.Ring, leaves Signed8LeafPair, branch uint64) ([]*bignum.Complex, error) {
	if ringZ == nil {
		return nil, fmt.Errorf("homchain: signed8 root-tree ring is nil")
	}
	if branch > 1 {
		return nil, fmt.Errorf("homchain: signed8 root-tree branch=%d, want 0 or 1", branch)
	}
	delta := uint64(uint8(int16(leaves.Right) - int16(leaves.Left)))
	correctedDelta, err := ringZ.ToRootSlots(ringZ.BinaryEncode(delta))
	if err != nil {
		return nil, fmt.Errorf("homchain: encode signed8 root-tree corrected delta: %w", err)
	}
	left := ringZ.ArithmeticRootSlots(uint64(uint8(leaves.Left)))
	selector := ringZ.ArithmeticRootSlots(branch)
	if len(left) != len(correctedDelta) || len(selector) != len(left) {
		return nil, fmt.Errorf("homchain: signed8 root-tree root-slot dimensions differ")
	}
	selected := make([]*bignum.Complex, len(left))
	for slot := range selected {
		selected[slot] = addComplex(left[slot], multiplyComplex(selector[slot], correctedDelta[slot]))
	}
	return selected, nil
}
