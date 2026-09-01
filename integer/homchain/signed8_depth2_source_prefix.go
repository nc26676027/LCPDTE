package homchain

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/nc26676027/LCPDTE/integer/treeplan"
	"github.com/nc26676027/LCPDTE/integer/z2n"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	signed8Depth2SourcePrefixProfileSchema = "signed8-depth2-source-prefix-profile-v1"
	signed8Depth2OperandsSchema            = "signed8-depth2-operands-v1"
	signed8Depth2CandidateLevel            = 20
	signed8Depth2ConditionedLevel          = 7
	signed8Depth2OutputLevel               = 6
)

// Signed8Depth2OperandSourceKind is a closed provenance tag. The zero value
// is invalid and callers cannot manufacture an arbitrary string token.
type Signed8Depth2OperandSourceKind uint8

const Signed8Depth2PrefixL6V1 Signed8Depth2OperandSourceKind = 1

type Signed8Depth2SourcePrefixFidelity string

const Signed8Depth2SourcePrefixFunctionalNotSecure Signed8Depth2SourcePrefixFidelity = "functional_not_secure"

// Signed8Depth2SelectionForm keeps the source schedule's logical two-term
// control distinct from the algebraically equivalent physical delta circuit.
type Signed8Depth2SelectionForm string

const (
	Signed8Depth2LogicalWidthTwoSourceControl       Signed8Depth2SelectionForm = "logical_width2_two_term_source_control"
	Signed8Depth2PhysicalLeftPlusSelectorTimesDelta Signed8Depth2SelectionForm = "physical_left_plus_selector_times_right_minus_left"
)

type Signed8Depth2FeatureSelectionCounts struct {
	CiphertextCiphertextMultiplications int
	Relinearizations                    int
	Rescales                            int
	CiphertextSubtractions              int
	CiphertextAdditions                 int
	LevelAlignments                     int
}

type Signed8Depth2ThresholdSelectionCounts struct {
	CiphertextPlaintextMultiplications int
	Rescales                           int
	PlaintextVectorAdditions           int
}

type Signed8Depth2SourcePrefixOperationCounts struct {
	Conditioner ScalarSelectorConditionOperationCounts
	Feature     Signed8Depth2FeatureSelectionCounts
	Threshold   Signed8Depth2ThresholdSelectionCounts
	Rotations   int
}

// Signed8Depth2SourcePrefixState records an exact runtime state without
// retaining mutable metadata aliases.
type Signed8Depth2SourcePrefixState struct {
	Stage         string
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

// Signed8Depth2SourcePrefixSerializedBytes separates external feature inputs,
// the internal selector, output operands, and retained local evidence. None of
// the internal or retained fields is described as communication.
type Signed8Depth2SourcePrefixSerializedBytes struct {
	ExternalFeatureLeft, ExternalFeatureRight          int
	InternalSelectorInput, InternalConditionedSelector int
	OutputFeature, OutputThreshold                     int
	RetainedConditionerRaw                             int
	RetainedFeatureDelta, RetainedFeatureRaw           int
	RetainedFeatureLeftAligned                         int
	RetainedThresholdRaw                               int
}

func (s Signed8Depth2SourcePrefixSerializedBytes) ExternalInputTotal() int {
	return s.ExternalFeatureLeft + s.ExternalFeatureRight
}
func (s Signed8Depth2SourcePrefixSerializedBytes) InternalSelectorTotal() int {
	return s.InternalSelectorInput + s.InternalConditionedSelector
}
func (s Signed8Depth2SourcePrefixSerializedBytes) OutputOperandTotal() int {
	return s.OutputFeature + s.OutputThreshold
}
func (s Signed8Depth2SourcePrefixSerializedBytes) RetainedEvidenceTotal() int {
	return s.RetainedConditionerRaw + s.RetainedFeatureDelta + s.RetainedFeatureRaw +
		s.RetainedFeatureLeftAligned + s.RetainedThresholdRaw
}

type Signed8Depth2SourcePrefixProfile struct {
	fidelity                                    Signed8Depth2SourcePrefixFidelity
	sourceKind                                  Signed8Depth2OperandSourceKind
	logicalSelectionForm, physicalSelectionForm Signed8Depth2SelectionForm
	wordBits                                    z2n.WordBits
	words, slots                                int
	parameterDigest, rangeDigest                string
	treeDigest, scheduleDigest                  string
	selectorProfileDigest                       string
	producerPublicDigest, producerOpaqueDigest  string
	conditioner                                 ScalarSelectorConditionProfile
	tree                                        treeplan.BinaryTree[int8, float64]
	schedule                                    treeplan.R0SchedulePlan
	leftThreshold, rightThreshold               int8
	leftThresholdSourceDigest                   string
	thresholdDeltaSourceDigest                  string
	leftThresholdPayloadDigest                  string
	thresholdDeltaPayloadDigest                 string
	conditionerOutputState                      Signed8Depth2SourcePrefixState
	featureOutputState, thresholdOutputState    Signed8Depth2SourcePrefixState
	operationCounts                             Signed8Depth2SourcePrefixOperationCounts
	digest                                      string
}

func (p Signed8Depth2SourcePrefixProfile) Fidelity() Signed8Depth2SourcePrefixFidelity {
	return p.fidelity
}
func (p Signed8Depth2SourcePrefixProfile) SourceKind() Signed8Depth2OperandSourceKind {
	return p.sourceKind
}
func (p Signed8Depth2SourcePrefixProfile) LogicalSelectionForm() Signed8Depth2SelectionForm {
	return p.logicalSelectionForm
}
func (p Signed8Depth2SourcePrefixProfile) PhysicalSelectionForm() Signed8Depth2SelectionForm {
	return p.physicalSelectionForm
}
func (p Signed8Depth2SourcePrefixProfile) WordBits() z2n.WordBits  { return p.wordBits }
func (p Signed8Depth2SourcePrefixProfile) Words() int              { return p.words }
func (p Signed8Depth2SourcePrefixProfile) Slots() int              { return p.slots }
func (p Signed8Depth2SourcePrefixProfile) ParameterDigest() string { return p.parameterDigest }
func (p Signed8Depth2SourcePrefixProfile) RangeDigest() string     { return p.rangeDigest }
func (p Signed8Depth2SourcePrefixProfile) TreeDigest() string      { return p.treeDigest }
func (p Signed8Depth2SourcePrefixProfile) ScheduleDigest() string  { return p.scheduleDigest }
func (p Signed8Depth2SourcePrefixProfile) SelectorProfileDigest() string {
	return p.selectorProfileDigest
}
func (p Signed8Depth2SourcePrefixProfile) Conditioner() ScalarSelectorConditionProfile {
	return p.conditioner
}
func (p Signed8Depth2SourcePrefixProfile) Tree() treeplan.BinaryTree[int8, float64] {
	return cloneSigned8Depth2Tree(p.tree)
}
func (p Signed8Depth2SourcePrefixProfile) Schedule() treeplan.R0SchedulePlan {
	return p.schedule.Clone()
}
func (p Signed8Depth2SourcePrefixProfile) OperationCounts() Signed8Depth2SourcePrefixOperationCounts {
	return p.operationCounts
}
func (p Signed8Depth2SourcePrefixProfile) LeftThreshold() int8  { return p.leftThreshold }
func (p Signed8Depth2SourcePrefixProfile) RightThreshold() int8 { return p.rightThreshold }
func (p Signed8Depth2SourcePrefixProfile) LeftThresholdSourceDigest() string {
	return p.leftThresholdSourceDigest
}
func (p Signed8Depth2SourcePrefixProfile) ThresholdDeltaSourceDigest() string {
	return p.thresholdDeltaSourceDigest
}
func (p Signed8Depth2SourcePrefixProfile) LeftThresholdPayloadDigest() string {
	return p.leftThresholdPayloadDigest
}
func (p Signed8Depth2SourcePrefixProfile) ThresholdDeltaPayloadDigest() string {
	return p.thresholdDeltaPayloadDigest
}
func (p Signed8Depth2SourcePrefixProfile) Digest() string { return p.digest }

func cloneSigned8Depth2Profile(profile Signed8Depth2SourcePrefixProfile) Signed8Depth2SourcePrefixProfile {
	profile.tree = cloneSigned8Depth2Tree(profile.tree)
	profile.schedule = profile.schedule.Clone()
	return profile
}

// Signed8Depth2Operands is the sole trusted output seam for the L6 prefix.
// F1, T1 and the conditioned selector remain private; accessors return copies.
type Signed8Depth2Operands struct {
	feature, threshold, conditionedSelector      *rlwe.Ciphertext
	sourceKind                                   Signed8Depth2OperandSourceKind
	profileDigest, parameterDigest               string
	rangeDigest, treeDigest, scheduleDigest      string
	selectorProfileDigest                        string
	producerProfileDigest                        string
	conditionerProfileDigest                     string
	selectorInputProvenanceDigest                string
	featureInputPayloadDigests                   [2]string
	featurePayloadDigest, thresholdPayloadDigest string
	conditionedSelectorPayloadDigest             string
	provenanceDigest                             string
}

func (o Signed8Depth2Operands) FeatureCiphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(o.feature)
}
func (o Signed8Depth2Operands) ThresholdCiphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(o.threshold)
}
func (o Signed8Depth2Operands) ConditionedSelectorCiphertext() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(o.conditionedSelector)
}
func (o Signed8Depth2Operands) SourceKind() Signed8Depth2OperandSourceKind { return o.sourceKind }
func (o Signed8Depth2Operands) ProfileDigest() string                      { return o.profileDigest }
func (o Signed8Depth2Operands) ParameterDigest() string                    { return o.parameterDigest }
func (o Signed8Depth2Operands) RangeDigest() string                        { return o.rangeDigest }
func (o Signed8Depth2Operands) TreeDigest() string                         { return o.treeDigest }
func (o Signed8Depth2Operands) ScheduleDigest() string                     { return o.scheduleDigest }
func (o Signed8Depth2Operands) FeaturePayloadDigest() string               { return o.featurePayloadDigest }
func (o Signed8Depth2Operands) ThresholdPayloadDigest() string             { return o.thresholdPayloadDigest }
func (o Signed8Depth2Operands) ProvenanceDigest() string                   { return o.provenanceDigest }

type Signed8Depth2SourcePrefixTrace struct {
	profileDigest, operandsProvenanceDigest string
	conditionerTrace                        ScalarSelectorConditionTrace
	states                                  []Signed8Depth2SourcePrefixState
	operationCounts                         Signed8Depth2SourcePrefixOperationCounts
	serializedBytes                         Signed8Depth2SourcePrefixSerializedBytes
	featureDelta, featureRaw                *rlwe.Ciphertext
	featureLeftAligned, thresholdRaw        *rlwe.Ciphertext
}

func (t Signed8Depth2SourcePrefixTrace) ProfileDigest() string { return t.profileDigest }
func (t Signed8Depth2SourcePrefixTrace) OperandsProvenanceDigest() string {
	return t.operandsProvenanceDigest
}
func (t Signed8Depth2SourcePrefixTrace) ConditionerTrace() ScalarSelectorConditionTrace {
	return t.conditionerTrace
}
func (t Signed8Depth2SourcePrefixTrace) States() []Signed8Depth2SourcePrefixState {
	return append([]Signed8Depth2SourcePrefixState(nil), t.states...)
}
func (t Signed8Depth2SourcePrefixTrace) OperationCounts() Signed8Depth2SourcePrefixOperationCounts {
	return t.operationCounts
}
func (t Signed8Depth2SourcePrefixTrace) SerializedBytes() Signed8Depth2SourcePrefixSerializedBytes {
	return t.serializedBytes
}

type Signed8Depth2SourcePrefixCircuit struct {
	selector, selectorSeal                *SelectorReraiseDecodeCircuit
	conditioner                           *ScalarSelectorConditionCircuit
	params                                ckks.Parameters
	integerEncoder                        *ckks.Encoder
	ranges                                Signed8NoOverflowRange
	tree                                  treeplan.BinaryTree[int8, float64]
	schedule                              treeplan.R0SchedulePlan
	thresholdLeft, thresholdDelta         *rlwe.Plaintext
	thresholdLeftSeal, thresholdDeltaSeal *rlwe.Plaintext
	profile                               Signed8Depth2SourcePrefixProfile
	graph                                 signed8Depth2SourcePrefixCircuitGraph
}

type signed8Depth2SourcePrefixCircuitGraph struct {
	circuit                               *Signed8Depth2SourcePrefixCircuit
	selector                              *SelectorReraiseDecodeCircuit
	conditioner                           *ScalarSelectorConditionCircuit
	integerEncoder                        *ckks.Encoder
	thresholdLeft, thresholdDelta         *rlwe.Plaintext
	thresholdLeftSeal, thresholdDeltaSeal *rlwe.Plaintext
	profileDigest                         string
}

type Signed8Depth2SourcePrefixEvaluator struct {
	circuit            *Signed8Depth2SourcePrefixCircuit
	source             *bootstrapping.Evaluator
	ckks               *ckks.Evaluator
	conditioner        *ScalarSelectorConditionEvaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	graph              signed8Depth2SourcePrefixEvaluatorGraph
}

type signed8Depth2SourcePrefixEvaluatorGraph struct {
	evaluator          *Signed8Depth2SourcePrefixEvaluator
	circuit            *Signed8Depth2SourcePrefixCircuit
	source             *bootstrapping.Evaluator
	ckks               *ckks.Evaluator
	conditioner        *ScalarSelectorConditionEvaluator
	keySet             *rlwe.MemEvaluationKeySet
	relinearizationKey *rlwe.RelinearizationKey
	profileDigest      string
}

func NewSigned8Depth2SourcePrefixCircuit(
	selector *SelectorReraiseDecodeCircuit,
	tree treeplan.BinaryTree[int8, float64],
) (*Signed8Depth2SourcePrefixCircuit, error) {
	if selector == nil {
		return nil, fmt.Errorf("homchain: nil selector for depth2 source prefix")
	}
	if err := selector.validate(); err != nil {
		return nil, fmt.Errorf("homchain: validate depth2 selector: %w", err)
	}
	if tree.Depth != 2 {
		return nil, fmt.Errorf("homchain: depth2 source prefix requires depth=2, got %d", tree.Depth)
	}
	if err := tree.Validate(); err != nil {
		return nil, fmt.Errorf("homchain: invalid depth2 source tree: %w", err)
	}
	ranges := selector.producer.ranges
	for splitIndex, split := range tree.Splits {
		threshold := int64(split.Threshold)
		if threshold < ranges.tMin || threshold > ranges.tMax {
			return nil, fmt.Errorf("homchain: depth2 split %d threshold=%d lies outside sealed range [%d,%d]", splitIndex, threshold, ranges.tMin, ranges.tMax)
		}
	}
	ownedTree := cloneSigned8Depth2Tree(tree)
	radix, err := treeplan.CompileR0(ownedTree, 2)
	if err != nil {
		return nil, fmt.Errorf("homchain: compile depth2 R0 source plan: %w", err)
	}
	request := treeplan.R0ScheduleRequest{Schedule: treeplan.R0SequentialSourceFaithfulOBO}
	schedule, err := radix.PlanSchedule(request)
	if err != nil {
		return nil, fmt.Errorf("homchain: plan depth2 source-faithful schedule: %w", err)
	}
	if err = validateSigned8Depth2Schedule(schedule, ownedTree); err != nil {
		return nil, err
	}
	conditioner, err := NewScalarSelectorConditionCircuit(selector)
	if err != nil {
		return nil, err
	}

	leftThreshold, rightThreshold := ownedTree.Splits[1].Threshold, ownedTree.Splits[2].Threshold
	leftAt7, err := newSigned8RepeatedWordPlaintext(selector.params, selector.integerEncoder, signed8Depth2ConditionedLevel, leftThreshold)
	if err != nil {
		return nil, fmt.Errorf("homchain: encode depth2 left threshold at L7: %w", err)
	}
	rightAt7, err := newSigned8RepeatedWordPlaintext(selector.params, selector.integerEncoder, signed8Depth2ConditionedLevel, rightThreshold)
	if err != nil {
		return nil, fmt.Errorf("homchain: encode depth2 right threshold at L7: %w", err)
	}
	thresholdDelta := rightAt7.CopyNew()
	selector.params.RingQ().AtLevel(signed8Depth2ConditionedLevel).Sub(rightAt7.Value, leftAt7.Value, thresholdDelta.Value)
	leftAt6, err := newSigned8RepeatedWordPlaintext(selector.params, selector.integerEncoder, signed8Depth2OutputLevel, leftThreshold)
	if err != nil {
		return nil, fmt.Errorf("homchain: encode depth2 left threshold at L6: %w", err)
	}
	leftPayloadDigest, err := signed8PlaintextDigest(leftAt6)
	if err != nil {
		return nil, err
	}
	deltaPayloadDigest, err := signed8PlaintextDigest(thresholdDelta)
	if err != nil {
		return nil, err
	}
	leftSourceDigest := digestString(fmt.Sprintf(
		"signed8-depth2-left-threshold-v1|value=%d|encoding=ArithmeticRootSlots(uint8(value))|level=6",
		leftThreshold,
	))
	deltaSourceDigest := digestString(fmt.Sprintf(
		"signed8-depth2-threshold-delta-v1|left=%d|right=%d|construction=E(right)-E(left)|level=7",
		leftThreshold, rightThreshold,
	))
	parameterDigest, err := signed8ParameterDigest(selector.params)
	if err != nil {
		return nil, err
	}
	defaultScale, err := NewExactScaleSnapshot(selector.params.DefaultScale())
	if err != nil {
		return nil, err
	}
	conditionedScale := conditioner.profile.outputScale
	state := func(stage string, level int, scale ExactScaleSnapshot) Signed8Depth2SourcePrefixState {
		return Signed8Depth2SourcePrefixState{Stage: stage, Level: level, Degree: 1, LogDimensions: selector.params.LogMaxDimensions(), Scale: scale}
	}
	profile := Signed8Depth2SourcePrefixProfile{
		fidelity: Signed8Depth2SourcePrefixFunctionalNotSecure, sourceKind: Signed8Depth2PrefixL6V1,
		logicalSelectionForm:  Signed8Depth2LogicalWidthTwoSourceControl,
		physicalSelectionForm: Signed8Depth2PhysicalLeftPlusSelectorTimesDelta,
		wordBits:              z2n.Word8, words: signed8Words, slots: signed8Slots,
		parameterDigest: parameterDigest, rangeDigest: ranges.digest,
		treeDigest: schedule.Certificate.SourceSHA256, scheduleDigest: schedule.Certificate.StructureSHA256,
		selectorProfileDigest: selector.profile.digest,
		producerPublicDigest:  selector.profile.producerPublicDigest,
		producerOpaqueDigest:  selector.profile.producerOpaqueDigest,
		conditioner:           conditioner.profile, tree: ownedTree, schedule: schedule.Clone(),
		leftThreshold: leftThreshold, rightThreshold: rightThreshold,
		leftThresholdSourceDigest: leftSourceDigest, thresholdDeltaSourceDigest: deltaSourceDigest,
		leftThresholdPayloadDigest: leftPayloadDigest, thresholdDeltaPayloadDigest: deltaPayloadDigest,
		conditionerOutputState: state("conditioned-selector", signed8Depth2ConditionedLevel, conditionedScale),
		featureOutputState:     state("selected-feature", signed8Depth2OutputLevel, defaultScale),
		thresholdOutputState:   state("selected-threshold", signed8Depth2OutputLevel, defaultScale),
		operationCounts: Signed8Depth2SourcePrefixOperationCounts{
			Conditioner: conditioner.profile.operationCounts,
			Feature: Signed8Depth2FeatureSelectionCounts{
				CiphertextCiphertextMultiplications: 1, Relinearizations: 1, Rescales: 1,
				CiphertextSubtractions: 1, CiphertextAdditions: 1, LevelAlignments: 1,
			},
			Threshold: Signed8Depth2ThresholdSelectionCounts{
				CiphertextPlaintextMultiplications: 1, Rescales: 1, PlaintextVectorAdditions: 1,
			},
		},
	}
	profile.digest = digestSigned8Depth2SourcePrefixProfile(profile)
	circuit := &Signed8Depth2SourcePrefixCircuit{
		selector: selector, selectorSeal: selector, conditioner: conditioner,
		params: selector.params, integerEncoder: selector.integerEncoder, ranges: ranges,
		tree: ownedTree, schedule: schedule.Clone(), thresholdLeft: leftAt6,
		thresholdDelta: thresholdDelta, thresholdLeftSeal: leftAt6.CopyNew(),
		thresholdDeltaSeal: thresholdDelta.CopyNew(), profile: profile,
	}
	circuit.graph = signed8Depth2SourcePrefixCircuitGraph{
		circuit: circuit, selector: selector, conditioner: conditioner,
		integerEncoder: circuit.integerEncoder, thresholdLeft: leftAt6, thresholdDelta: thresholdDelta,
		thresholdLeftSeal: circuit.thresholdLeftSeal, thresholdDeltaSeal: circuit.thresholdDeltaSeal,
		profileDigest: profile.digest,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *Signed8Depth2SourcePrefixCircuit) Profile() Signed8Depth2SourcePrefixProfile {
	if c == nil {
		return Signed8Depth2SourcePrefixProfile{}
	}
	return cloneSigned8Depth2Profile(c.profile)
}

// BindSelectorResult turns the selector circuit's opaque result into the
// authenticated, owned conditioner input accepted by EvaluateNew.
func (c *Signed8Depth2SourcePrefixCircuit) BindSelectorResult(
	result SelectorReraiseDecodeResult,
) (ScalarSelectorConditionInput, error) {
	if err := c.validate(); err != nil {
		return ScalarSelectorConditionInput{}, err
	}
	return c.conditioner.BindSelectorResult(result)
}

// BindEvaluator seals the prefix and conditioner to one exact bootstrap
// source and the source's relinearization-key identity.
func (c *Signed8Depth2SourcePrefixCircuit) BindEvaluator(source *bootstrapping.Evaluator) (*Signed8Depth2SourcePrefixEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if source == nil || source.Evaluator == nil || source.MemEvaluationKeySet == nil ||
		!source.ResidualParameters.Equal(&c.params) || !source.BootstrappingParameters.Equal(&c.params) ||
		!c.params.Equal(source.Evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: depth2 source-prefix evaluator source is incomplete or foreign")
	}
	conditioner, err := c.conditioner.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind depth2 selector conditioner: %w", err)
	}
	relinearizationKey, err := source.MemEvaluationKeySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, fmt.Errorf("homchain: depth2 source-prefix relinearization key is missing: %v", err)
	}
	evaluator := &Signed8Depth2SourcePrefixEvaluator{
		circuit: c, source: source, ckks: source.Evaluator, conditioner: conditioner,
		keySet: source.MemEvaluationKeySet, relinearizationKey: relinearizationKey,
	}
	evaluator.graph = signed8Depth2SourcePrefixEvaluatorGraph{
		evaluator: evaluator, circuit: c, source: source, ckks: source.Evaluator,
		conditioner: conditioner, keySet: source.MemEvaluationKeySet,
		relinearizationKey: relinearizationKey, profileDigest: c.profile.digest,
	}
	if err = evaluator.preflight(); err != nil {
		return nil, err
	}
	return evaluator, nil
}

func (e *Signed8Depth2SourcePrefixEvaluator) preflight() error {
	if e == nil || e.circuit == nil || e.source == nil || e.ckks == nil || e.conditioner == nil ||
		e.keySet == nil || e.relinearizationKey == nil {
		return fmt.Errorf("homchain: nil or incomplete depth2 source-prefix evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		return err
	}
	g := e.graph
	if g.evaluator != e || g.circuit != e.circuit || g.source != e.source || g.ckks != e.ckks ||
		g.conditioner != e.conditioner || g.keySet != e.keySet ||
		g.relinearizationKey != e.relinearizationKey || g.profileDigest != e.circuit.profile.digest ||
		e.source.Evaluator != e.ckks || e.source.MemEvaluationKeySet != e.keySet {
		return fmt.Errorf("homchain: depth2 source-prefix evaluator graph changed")
	}
	if err := e.conditioner.preflight(); err != nil {
		return err
	}
	relinearizationKey, err := e.keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil || relinearizationKey != e.relinearizationKey {
		return fmt.Errorf("homchain: depth2 source-prefix relinearization key identity changed")
	}
	return nil
}

// EvaluateNew emits the source-faithful depth-one operands at exact L6/S35.
// All authentication and graph checks finish before the first HE operation.
func (e *Signed8Depth2SourcePrefixEvaluator) EvaluateNew(
	conditionInput ScalarSelectorConditionInput,
	features [2]Signed8FeatureInput,
) (Signed8Depth2Operands, Signed8Depth2SourcePrefixTrace, error) {
	var operands Signed8Depth2Operands
	var trace Signed8Depth2SourcePrefixTrace
	if e == nil || e.circuit == nil {
		return operands, trace, fmt.Errorf("homchain: nil bound depth2 source-prefix evaluator")
	}
	if err := e.preflight(); err != nil {
		return operands, trace, err
	}
	if err := e.circuit.conditioner.validateInput(conditionInput); err != nil {
		return operands, trace, err
	}
	for index := range features {
		if err := e.circuit.selector.producer.validateFeatureHandle(features[index]); err != nil {
			return operands, trace, fmt.Errorf("homchain: depth2 feature candidate %d: %w", index, err)
		}
	}
	conditionInputBefore := conditionInput.selector.CopyNew()
	featureBefore := [2]*rlwe.Ciphertext{features[0].ciphertext.CopyNew(), features[1].ciphertext.CopyNew()}
	leftPlaintextBefore, deltaPlaintextBefore := e.circuit.thresholdLeft.CopyNew(), e.circuit.thresholdDelta.CopyNew()

	conditionedResult, conditionerTrace, err := e.conditioner.EvaluateNew(conditionInput)
	if err != nil {
		return operands, trace, fmt.Errorf("homchain: condition depth2 selector: %w", err)
	}
	if err = e.circuit.conditioner.validateResult(conditionedResult); err != nil {
		return operands, trace, err
	}
	conditioned := conditionedResult.conditioned
	if !conditionInput.selector.Equal(conditionInputBefore) {
		return operands, trace, fmt.Errorf("homchain: depth2 selector conditioning mutated an admitted selector")
	}

	featureDelta, err := e.ckks.SubNew(features[1].ciphertext, features[0].ciphertext)
	if err != nil {
		return operands, trace, fmt.Errorf("homchain: depth2 feature delta: %w", err)
	}
	if err = requireSigned8Depth2State("feature delta", featureDelta, signed8Depth2CandidateLevel, e.circuit.params.DefaultScale(), e.circuit.params); err != nil {
		return operands, trace, err
	}
	featureRaw, err := e.ckks.MulRelinNew(conditioned, featureDelta)
	if err != nil {
		return operands, trace, fmt.Errorf("homchain: depth2 feature selection MulRelin: %w", err)
	}
	featureRawScale := rlwe.NewScale(e.circuit.params.Q()[signed8Depth2ConditionedLevel]).Mul(e.circuit.params.DefaultScale())
	if err = requireSigned8Depth2State("feature raw product", featureRaw, signed8Depth2ConditionedLevel, featureRawScale, e.circuit.params); err != nil {
		return operands, trace, err
	}
	featureRawBefore := featureRaw.CopyNew()
	featureProduct := featureRaw.CopyNew()
	if err = e.ckks.Rescale(featureProduct, featureProduct); err != nil {
		return operands, trace, fmt.Errorf("homchain: depth2 feature selection rescale: %w", err)
	}
	if !featureRaw.Equal(featureRawBefore) {
		return operands, trace, fmt.Errorf("homchain: depth2 feature rescale mutated retained raw product")
	}
	if err = requireSigned8Depth2State("rescaled feature product", featureProduct, signed8Depth2OutputLevel, e.circuit.params.DefaultScale(), e.circuit.params); err != nil {
		return operands, trace, err
	}
	leftAligned := e.ckks.DropLevelNew(features[0].ciphertext, features[0].ciphertext.Level()-signed8Depth2OutputLevel)
	if err = requireSigned8Depth2State("aligned left feature", leftAligned, signed8Depth2OutputLevel, e.circuit.params.DefaultScale(), e.circuit.params); err != nil {
		return operands, trace, err
	}
	featureProductBefore, leftAlignedBefore := featureProduct.CopyNew(), leftAligned.CopyNew()
	selectedFeature, err := e.ckks.AddNew(featureProduct, leftAligned)
	if err != nil {
		return operands, trace, fmt.Errorf("homchain: add depth2 left feature: %w", err)
	}
	if !featureProduct.Equal(featureProductBefore) || !leftAligned.Equal(leftAlignedBefore) {
		return operands, trace, fmt.Errorf("homchain: depth2 feature addition mutated an operand")
	}
	if err = requireSigned8Depth2State("selected feature", selectedFeature, signed8Depth2OutputLevel, e.circuit.params.DefaultScale(), e.circuit.params); err != nil {
		return operands, trace, err
	}

	conditionedBefore := conditioned.CopyNew()
	thresholdRaw, err := e.ckks.MulNew(conditioned, e.circuit.thresholdDelta)
	if err != nil {
		return operands, trace, fmt.Errorf("homchain: depth2 threshold delta multiply: %w", err)
	}
	if !conditioned.Equal(conditionedBefore) {
		return operands, trace, fmt.Errorf("homchain: depth2 threshold multiply mutated conditioned selector")
	}
	if err = requireSigned8Depth2State("threshold raw product", thresholdRaw, signed8Depth2ConditionedLevel, featureRawScale, e.circuit.params); err != nil {
		return operands, trace, err
	}
	thresholdRawBefore := thresholdRaw.CopyNew()
	thresholdProduct := thresholdRaw.CopyNew()
	if err = e.ckks.Rescale(thresholdProduct, thresholdProduct); err != nil {
		return operands, trace, fmt.Errorf("homchain: depth2 threshold selection rescale: %w", err)
	}
	if !thresholdRaw.Equal(thresholdRawBefore) {
		return operands, trace, fmt.Errorf("homchain: depth2 threshold rescale mutated retained raw product")
	}
	if err = requireSigned8Depth2State("rescaled threshold product", thresholdProduct, signed8Depth2OutputLevel, e.circuit.params.DefaultScale(), e.circuit.params); err != nil {
		return operands, trace, err
	}
	thresholdProductBefore := thresholdProduct.CopyNew()
	selectedThreshold, err := e.ckks.AddNew(thresholdProduct, e.circuit.thresholdLeft)
	if err != nil {
		return operands, trace, fmt.Errorf("homchain: add depth2 left threshold: %w", err)
	}
	if !thresholdProduct.Equal(thresholdProductBefore) {
		return operands, trace, fmt.Errorf("homchain: depth2 threshold addition mutated its ciphertext operand")
	}
	if err = requireSigned8Depth2State("selected threshold", selectedThreshold, signed8Depth2OutputLevel, e.circuit.params.DefaultScale(), e.circuit.params); err != nil {
		return operands, trace, err
	}

	if !conditionInput.selector.Equal(conditionInputBefore) ||
		!features[0].ciphertext.Equal(featureBefore[0]) || !features[1].ciphertext.Equal(featureBefore[1]) ||
		!e.circuit.thresholdLeft.Equal(leftPlaintextBefore) || !e.circuit.thresholdDelta.Equal(deltaPlaintextBefore) ||
		!e.circuit.thresholdLeft.Equal(e.circuit.thresholdLeftSeal) || !e.circuit.thresholdDelta.Equal(e.circuit.thresholdDeltaSeal) {
		return operands, trace, fmt.Errorf("homchain: depth2 source prefix mutated an admitted or cached operand")
	}

	featurePayloadDigest, err := signed8CiphertextDigest(selectedFeature)
	if err != nil {
		return operands, trace, err
	}
	thresholdPayloadDigest, err := signed8CiphertextDigest(selectedThreshold)
	if err != nil {
		return operands, trace, err
	}
	conditionedPayloadDigest, err := signed8CiphertextDigest(conditioned)
	if err != nil {
		return operands, trace, err
	}
	operands = Signed8Depth2Operands{
		feature: selectedFeature, threshold: selectedThreshold, conditionedSelector: conditioned.CopyNew(),
		sourceKind: Signed8Depth2PrefixL6V1, profileDigest: e.circuit.profile.digest,
		parameterDigest: e.circuit.profile.parameterDigest, rangeDigest: e.circuit.profile.rangeDigest,
		treeDigest: e.circuit.profile.treeDigest, scheduleDigest: e.circuit.profile.scheduleDigest,
		selectorProfileDigest: conditionInput.selectorProfileDigest, producerProfileDigest: conditionInput.producerProfileDigest,
		conditionerProfileDigest:      e.circuit.conditioner.profile.digest,
		selectorInputProvenanceDigest: conditionInput.provenanceDigest,
		featureInputPayloadDigests:    [2]string{features[0].payloadDigest, features[1].payloadDigest},
		featurePayloadDigest:          featurePayloadDigest, thresholdPayloadDigest: thresholdPayloadDigest,
		conditionedSelectorPayloadDigest: conditionedPayloadDigest,
	}
	operands.provenanceDigest = digestSigned8Depth2Operands(operands)
	if err = e.circuit.validateOperands(operands); err != nil {
		return Signed8Depth2Operands{}, trace, err
	}

	states := make([]Signed8Depth2SourcePrefixState, 0, 9)
	for _, item := range []struct {
		stage      string
		ciphertext *rlwe.Ciphertext
	}{
		{"conditioned-selector", conditioned}, {"feature-delta", featureDelta},
		{"feature-raw-product", featureRaw}, {"feature-rescaled-product", featureProduct},
		{"feature-left-aligned", leftAligned}, {"selected-feature", selectedFeature},
		{"threshold-raw-product", thresholdRaw}, {"threshold-rescaled-product", thresholdProduct},
		{"selected-threshold", selectedThreshold},
	} {
		state, stateErr := snapshotSigned8Depth2State(item.stage, item.ciphertext)
		if stateErr != nil {
			return Signed8Depth2Operands{}, trace, stateErr
		}
		states = append(states, state)
	}
	serializedBytes, err := measureSigned8Depth2SourcePrefixBytes(
		features, conditionInput.selector, conditioned, conditionerTrace.RawProduct(),
		featureDelta, featureRaw, leftAligned, thresholdRaw, selectedFeature, selectedThreshold,
	)
	if err != nil {
		return Signed8Depth2Operands{}, trace, err
	}
	trace = Signed8Depth2SourcePrefixTrace{
		profileDigest: e.circuit.profile.digest, operandsProvenanceDigest: operands.provenanceDigest,
		conditionerTrace: conditionerTrace, states: states,
		operationCounts: e.circuit.profile.operationCounts, serializedBytes: serializedBytes,
		featureDelta: featureDelta.CopyNew(), featureRaw: featureRaw.CopyNew(),
		featureLeftAligned: leftAligned.CopyNew(), thresholdRaw: thresholdRaw.CopyNew(),
	}
	return operands, trace, nil
}

func (c *Signed8Depth2SourcePrefixCircuit) validate() error {
	if c == nil || c.selector == nil || c.selectorSeal == nil || c.conditioner == nil || c.integerEncoder == nil ||
		c.thresholdLeft == nil || c.thresholdDelta == nil || c.thresholdLeftSeal == nil || c.thresholdDeltaSeal == nil {
		return fmt.Errorf("homchain: nil or incomplete depth2 source-prefix circuit")
	}
	if c.selector != c.selectorSeal {
		return fmt.Errorf("homchain: depth2 source-prefix selector identity changed")
	}
	if err := c.selector.validate(); err != nil {
		return err
	}
	if err := c.conditioner.validate(); err != nil {
		return err
	}
	if err := validateSigned8NoOverflowRange(c.ranges); err != nil {
		return err
	}
	if err := validateSigned8Depth2Schedule(c.schedule, c.tree); err != nil {
		return err
	}
	g := c.graph
	if g.circuit != c || g.selector != c.selector || g.conditioner != c.conditioner ||
		g.integerEncoder != c.integerEncoder || g.thresholdLeft != c.thresholdLeft ||
		g.thresholdDelta != c.thresholdDelta || g.thresholdLeftSeal != c.thresholdLeftSeal ||
		g.thresholdDeltaSeal != c.thresholdDeltaSeal || g.profileDigest != c.profile.digest ||
		!c.thresholdLeft.Equal(c.thresholdLeftSeal) || !c.thresholdDelta.Equal(c.thresholdDeltaSeal) {
		return fmt.Errorf("homchain: depth2 source-prefix circuit object graph changed")
	}
	leftDigest, err := signed8PlaintextDigest(c.thresholdLeft)
	if err != nil {
		return err
	}
	deltaDigest, err := signed8PlaintextDigest(c.thresholdDelta)
	if err != nil {
		return err
	}
	if leftDigest != c.profile.leftThresholdPayloadDigest || deltaDigest != c.profile.thresholdDeltaPayloadDigest ||
		c.profile.logicalSelectionForm != Signed8Depth2LogicalWidthTwoSourceControl ||
		c.profile.physicalSelectionForm != Signed8Depth2PhysicalLeftPlusSelectorTimesDelta ||
		c.profile.digest != digestSigned8Depth2SourcePrefixProfile(c.profile) ||
		!reflect.DeepEqual(c.profile.tree, c.tree) || !reflect.DeepEqual(c.profile.schedule, c.schedule) {
		return fmt.Errorf("homchain: depth2 source-prefix profile, tree, schedule, or payload changed")
	}
	return nil
}

func validateSigned8Depth2Schedule(plan treeplan.R0SchedulePlan, tree treeplan.BinaryTree[int8, float64]) error {
	request := treeplan.R0ScheduleRequest{Schedule: treeplan.R0SequentialSourceFaithfulOBO}
	if err := treeplan.VerifyScheduleAgainst(plan, tree, request); err != nil {
		return fmt.Errorf("homchain: depth2 source schedule verification: %w", err)
	}
	if plan.Schedule != treeplan.R0SequentialSourceFaithfulOBO || plan.BinaryDepth != 2 || plan.GroupWidth != 2 || len(plan.Groups) != 1 {
		return fmt.Errorf("homchain: depth2 source schedule shape changed")
	}
	group := plan.Groups[0]
	if group.StartDepth != 0 || group.Height != 2 || group.LogicalComparisons != 2 ||
		!reflect.DeepEqual(group.FeatureSelectorWidths, []int{2}) ||
		!reflect.DeepEqual(group.ThresholdSelectorWidths, []int{2}) ||
		len(group.ComparatorCharges) != 2 ||
		group.ComparatorCharges[0].Provenance != treeplan.ComparatorCTPlaintext || group.ComparatorCharges[0].LogicalComparisons != 1 ||
		group.ComparatorCharges[1].Provenance != treeplan.ComparatorCTCT || group.ComparatorCharges[1].LogicalComparisons != 1 {
		return fmt.Errorf("homchain: depth2 source schedule is not one CT-PT root plus one width-two CT-CT source selection")
	}
	return nil
}

func newSigned8RepeatedWordPlaintext(params ckks.Parameters, encoder *ckks.Encoder, level int, value int8) (*rlwe.Plaintext, error) {
	words := [signed8Words]uint64{}
	for index := range words {
		words[index] = uint64(uint8(value))
	}
	return newSigned8WordPlaintext(params, encoder, signed8IntegerEncoderPrecision, level, words)
}

func cloneSigned8Depth2Tree(tree treeplan.BinaryTree[int8, float64]) treeplan.BinaryTree[int8, float64] {
	return treeplan.BinaryTree[int8, float64]{
		Depth:  tree.Depth,
		Splits: append([]treeplan.BinarySplit[int8](nil), tree.Splits...),
		Leaves: append([]float64(nil), tree.Leaves...),
	}
}

func digestSigned8Depth2SourcePrefixProfile(profile Signed8Depth2SourcePrefixProfile) string {
	var builder strings.Builder
	fmt.Fprintf(&builder,
		"%s|fidelity=%s|source-kind=%d|logical=%s|physical=%s|word=%d|words=%d|slots=%d|params=%s|range=%s|tree=%s|schedule=%s|selector=%s|producer=%s/%s|conditioner=%s|thresholds=%d/%d|left-source=%s|delta-source=%s|left-payload=%s|delta-payload=%s|counts=%+v",
		signed8Depth2SourcePrefixProfileSchema, profile.fidelity, profile.sourceKind,
		profile.logicalSelectionForm, profile.physicalSelectionForm,
		profile.wordBits, profile.words, profile.slots, profile.parameterDigest, profile.rangeDigest,
		profile.treeDigest, profile.scheduleDigest, profile.selectorProfileDigest,
		profile.producerPublicDigest, profile.producerOpaqueDigest, profile.conditioner.digest,
		profile.leftThreshold, profile.rightThreshold, profile.leftThresholdSourceDigest,
		profile.thresholdDeltaSourceDigest, profile.leftThresholdPayloadDigest,
		profile.thresholdDeltaPayloadDigest, profile.operationCounts,
	)
	for _, state := range []Signed8Depth2SourcePrefixState{
		profile.conditionerOutputState, profile.featureOutputState, profile.thresholdOutputState,
	} {
		fmt.Fprintf(&builder, "|state=%s/L%d/D%d/dim=%d,%d/scale={%s}", state.Stage, state.Level,
			state.Degree, state.LogDimensions.Rows, state.LogDimensions.Cols, state.Scale.canonicalString())
	}
	return digestString(builder.String())
}

// validateOperands is the package-private trusted admission seam for the
// subsequent L6 ingress adapter.
func (c *Signed8Depth2SourcePrefixCircuit) validateOperands(operands Signed8Depth2Operands) error {
	if err := c.validate(); err != nil {
		return err
	}
	if operands.sourceKind != Signed8Depth2PrefixL6V1 || operands.feature == nil ||
		operands.threshold == nil || operands.conditionedSelector == nil {
		return fmt.Errorf("homchain: nil or unsupported depth2 operands")
	}
	if err := requireSigned8Depth2State("sealed feature operand", operands.feature, signed8Depth2OutputLevel, c.params.DefaultScale(), c.params); err != nil {
		return err
	}
	if err := requireSigned8Depth2State("sealed threshold operand", operands.threshold, signed8Depth2OutputLevel, c.params.DefaultScale(), c.params); err != nil {
		return err
	}
	conditionedScale, err := c.conditioner.profile.outputScale.Scale()
	if err != nil {
		return err
	}
	if err = requireSigned8Depth2State("sealed conditioned selector", operands.conditionedSelector, signed8Depth2ConditionedLevel, conditionedScale, c.params); err != nil {
		return err
	}
	featureDigest, err := signed8CiphertextDigest(operands.feature)
	if err != nil {
		return err
	}
	thresholdDigest, err := signed8CiphertextDigest(operands.threshold)
	if err != nil {
		return err
	}
	conditionedDigest, err := signed8CiphertextDigest(operands.conditionedSelector)
	if err != nil {
		return err
	}
	producerMode := selectorModeFromProducerDigest(c.selector.producer, operands.producerProfileDigest)
	producer := c.selector.producer.profileForMode(producerMode)
	if producer.digest == "" || operands.profileDigest != c.profile.digest ||
		operands.parameterDigest != c.profile.parameterDigest || operands.rangeDigest != c.profile.rangeDigest ||
		operands.treeDigest != c.profile.treeDigest || operands.scheduleDigest != c.profile.scheduleDigest ||
		operands.selectorProfileDigest != c.selector.profile.digest || operands.producerProfileDigest != producer.digest ||
		operands.conditionerProfileDigest != c.conditioner.profile.digest || operands.selectorInputProvenanceDigest == "" ||
		operands.featureInputPayloadDigests[0] == "" || operands.featureInputPayloadDigests[1] == "" ||
		operands.featurePayloadDigest != featureDigest || operands.thresholdPayloadDigest != thresholdDigest ||
		operands.conditionedSelectorPayloadDigest != conditionedDigest ||
		operands.provenanceDigest != digestSigned8Depth2Operands(operands) {
		return fmt.Errorf("homchain: depth2 operands have foreign source, profile, producer, payload, or provenance")
	}
	return nil
}

func selectorModeFromProducerDigest(producer *Signed8ComparatorCircuit, digest string) Signed8ComparatorOperandMode {
	if producer != nil {
		if digest == producer.publicProfile.digest {
			return Signed8PublicThresholdCTPT
		}
		if digest == producer.opaqueProfile.digest {
			return Signed8OpaqueThresholdCTCT
		}
	}
	return ""
}

func requireSigned8Depth2State(name string, ciphertext *rlwe.Ciphertext, level int, scale rlwe.Scale, params ckks.Parameters) error {
	snapshot, err := NewExactScaleSnapshot(scale)
	if err != nil {
		return err
	}
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level || ciphertext.Degree() != 1 ||
		ciphertext.LogN() != params.LogN() || ciphertext.LogDimensions != params.LogMaxDimensions() ||
		ciphertext.Slots() != signed8Slots || !ciphertext.IsBatched || !ciphertext.IsNTT ||
		!snapshot.EqualScale(ciphertext.Scale) {
		return fmt.Errorf("homchain: depth2 %s is not exact L%d/degree1/full-dense/NTT at the sealed scale", name, level)
	}
	return nil
}

func snapshotSigned8Depth2State(stage string, ciphertext *rlwe.Ciphertext) (Signed8Depth2SourcePrefixState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return Signed8Depth2SourcePrefixState{}, fmt.Errorf("homchain: cannot snapshot nil depth2 %s", stage)
	}
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return Signed8Depth2SourcePrefixState{}, err
	}
	return Signed8Depth2SourcePrefixState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale,
	}, nil
}

func measureSigned8Depth2SourcePrefixBytes(
	features [2]Signed8FeatureInput,
	selectorInput, conditionedSelector, conditionerRaw *rlwe.Ciphertext,
	featureDelta, featureRaw, featureLeftAligned, thresholdRaw *rlwe.Ciphertext,
	featureOutput, thresholdOutput *rlwe.Ciphertext,
) (Signed8Depth2SourcePrefixSerializedBytes, error) {
	items := []struct {
		name       string
		ciphertext *rlwe.Ciphertext
	}{
		{"external left feature", features[0].ciphertext},
		{"external right feature", features[1].ciphertext},
		{"internal selector input", selectorInput},
		{"internal conditioned selector", conditionedSelector},
		{"output feature operand", featureOutput},
		{"output threshold operand", thresholdOutput},
		{"retained conditioner raw product", conditionerRaw},
		{"retained feature delta", featureDelta},
		{"retained feature raw product", featureRaw},
		{"retained aligned left feature", featureLeftAligned},
		{"retained threshold raw product", thresholdRaw},
	}
	sizes := make([]int, len(items))
	for index, item := range items {
		var err error
		if sizes[index], err = marshalCiphertextSize(item.name, item.ciphertext); err != nil {
			return Signed8Depth2SourcePrefixSerializedBytes{}, err
		}
	}
	return Signed8Depth2SourcePrefixSerializedBytes{
		ExternalFeatureLeft: sizes[0], ExternalFeatureRight: sizes[1],
		InternalSelectorInput: sizes[2], InternalConditionedSelector: sizes[3],
		OutputFeature: sizes[4], OutputThreshold: sizes[5], RetainedConditionerRaw: sizes[6],
		RetainedFeatureDelta: sizes[7], RetainedFeatureRaw: sizes[8],
		RetainedFeatureLeftAligned: sizes[9], RetainedThresholdRaw: sizes[10],
	}, nil
}

func digestSigned8Depth2Operands(operands Signed8Depth2Operands) string {
	return digestString(fmt.Sprintf(
		"%s|source-kind=%d|profile=%s|params=%s|range=%s|tree=%s|schedule=%s|selector=%s|producer=%s|conditioner=%s|selector-input=%s|feature-inputs=%s/%s|conditioned=%s|feature=%s|threshold=%s",
		signed8Depth2OperandsSchema, operands.sourceKind, operands.profileDigest, operands.parameterDigest,
		operands.rangeDigest, operands.treeDigest, operands.scheduleDigest, operands.selectorProfileDigest,
		operands.producerProfileDigest, operands.conditionerProfileDigest, operands.selectorInputProvenanceDigest,
		operands.featureInputPayloadDigests[0], operands.featureInputPayloadDigests[1],
		operands.conditionedSelectorPayloadDigest, operands.featurePayloadDigest, operands.thresholdPayloadDigest,
	))
}
