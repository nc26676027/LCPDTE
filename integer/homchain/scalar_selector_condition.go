package homchain

import (
	"encoding/hex"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	scalarSelectorConditionProfileSchema = "scalar-selector-condition-profile-v2"
	scalarSelectorConditionInputSchema   = "scalar-selector-condition-input-v2"
	scalarSelectorConditionResultSchema  = "scalar-selector-condition-result-v2"
	scalarSelectorConditionInputLevel    = 8
	scalarSelectorConditionOutputLevel   = 7
)

// ScalarSelectorConditionOperationCounts records the one exact-scale
// conditioning product and its rescale. Rotations remain an explicit zero.
type ScalarSelectorConditionOperationCounts struct {
	CiphertextPlaintextMultiplications int
	Rescales                           int
	Rotations                          int
}

// ScalarSelectorConditionState is a detached exact ciphertext-state record.
type ScalarSelectorConditionState struct {
	Level         int
	Degree        int
	LogDimensions ring.Dimensions
	Scale         ExactScaleSnapshot
}

// ScalarSelectorConditionSerializedBytes classifies the selector as an
// internal pipeline value. The raw product is retained evidence, not an
// online boundary or communication claim.
type ScalarSelectorConditionSerializedBytes struct {
	InternalSelectorInput int
	RetainedRawProduct    int
	InternalOutput        int
}

// ScalarSelectorConditionProfile seals the exact b:L8/R -> b':L7/q7 map.
type ScalarSelectorConditionProfile struct {
	parameterDigest, rangeDigest                       string
	selectorProfileDigest                              string
	selectorResultSchema                               string
	producerPublicDigest, producerOpaqueDigest         string
	inputLevel, outputLevel                            int
	inputScale, multiplierScale, rawScale, outputScale ExactScaleSnapshot
	multiplierSourceDigest, multiplierPayloadDigest    string
	operationCounts                                    ScalarSelectorConditionOperationCounts
	digest                                             string
}

func (p ScalarSelectorConditionProfile) ParameterDigest() string { return p.parameterDigest }
func (p ScalarSelectorConditionProfile) RangeDigest() string     { return p.rangeDigest }
func (p ScalarSelectorConditionProfile) SelectorProfileDigest() string {
	return p.selectorProfileDigest
}
func (p ScalarSelectorConditionProfile) SelectorResultSchema() string { return p.selectorResultSchema }
func (p ScalarSelectorConditionProfile) ProducerPublicProfileDigest() string {
	return p.producerPublicDigest
}
func (p ScalarSelectorConditionProfile) ProducerOpaqueProfileDigest() string {
	return p.producerOpaqueDigest
}
func (p ScalarSelectorConditionProfile) InputLevel() int                { return p.inputLevel }
func (p ScalarSelectorConditionProfile) OutputLevel() int               { return p.outputLevel }
func (p ScalarSelectorConditionProfile) InputScale() ExactScaleSnapshot { return p.inputScale }
func (p ScalarSelectorConditionProfile) MultiplierScale() ExactScaleSnapshot {
	return p.multiplierScale
}
func (p ScalarSelectorConditionProfile) RawScale() ExactScaleSnapshot    { return p.rawScale }
func (p ScalarSelectorConditionProfile) OutputScale() ExactScaleSnapshot { return p.outputScale }
func (p ScalarSelectorConditionProfile) MultiplierSourceDigest() string {
	return p.multiplierSourceDigest
}
func (p ScalarSelectorConditionProfile) MultiplierPayloadDigest() string {
	return p.multiplierPayloadDigest
}
func (p ScalarSelectorConditionProfile) OperationCounts() ScalarSelectorConditionOperationCounts {
	return p.operationCounts
}
func (p ScalarSelectorConditionProfile) Digest() string { return p.digest }

// ScalarSelectorConditionInput is an owned, authenticated selector result.
// No raw ciphertext admission is exposed.
type ScalarSelectorConditionInput struct {
	selector                             *rlwe.Ciphertext
	profileDigest, selectorProfileDigest string
	producerProfileDigest, rangeDigest   string
	selectorInputProvenanceDigest        string
	selectorResultProvenanceDigest       string
	selectorPath                         SelectorReraiseDecodePath
	operandMode                          Signed8ComparatorOperandMode
	payloadDigest, provenanceDigest      string
}

func (i ScalarSelectorConditionInput) ProvenanceDigest() string { return i.provenanceDigest }

// ScalarSelectorConditionResult owns the conditioned selector and its exact
// producer binding. Ciphertext returns a defensive copy.
type ScalarSelectorConditionResult struct {
	conditioned                          *rlwe.Ciphertext
	profileDigest, selectorProfileDigest string
	producerProfileDigest, rangeDigest   string
	inputProvenanceDigest                string
	operandMode                          Signed8ComparatorOperandMode
	payloadDigest, provenanceDigest      string
}

func (r ScalarSelectorConditionResult) Ciphertext() *rlwe.Ciphertext {
	if r.conditioned == nil {
		return nil
	}
	return r.conditioned.CopyNew()
}
func (r ScalarSelectorConditionResult) ProfileDigest() string    { return r.profileDigest }
func (r ScalarSelectorConditionResult) RangeDigest() string      { return r.rangeDigest }
func (r ScalarSelectorConditionResult) PayloadDigest() string    { return r.payloadDigest }
func (r ScalarSelectorConditionResult) ProvenanceDigest() string { return r.provenanceDigest }

// ScalarSelectorConditionTrace exposes only detached state and byte ledgers.
type ScalarSelectorConditionTrace struct {
	profileDigest, inputProvenanceDigest string
	states                               []ScalarSelectorConditionState
	operationCounts                      ScalarSelectorConditionOperationCounts
	serializedBytes                      ScalarSelectorConditionSerializedBytes
	rawProduct                           *rlwe.Ciphertext
}

func (t ScalarSelectorConditionTrace) ProfileDigest() string { return t.profileDigest }
func (t ScalarSelectorConditionTrace) InputProvenanceDigest() string {
	return t.inputProvenanceDigest
}
func (t ScalarSelectorConditionTrace) States() []ScalarSelectorConditionState {
	return append([]ScalarSelectorConditionState(nil), t.states...)
}
func (t ScalarSelectorConditionTrace) OperationCounts() ScalarSelectorConditionOperationCounts {
	return t.operationCounts
}
func (t ScalarSelectorConditionTrace) SerializedBytes() ScalarSelectorConditionSerializedBytes {
	return t.serializedBytes
}
func (t ScalarSelectorConditionTrace) RawProduct() *rlwe.Ciphertext {
	return copyA2BRefreshCiphertext(t.rawProduct)
}

type ScalarSelectorConditionCircuit struct {
	selector       *SelectorReraiseDecodeCircuit
	params         ckks.Parameters
	encoder        *ckks.Encoder
	multiplier     *rlwe.Plaintext
	multiplierSeal *rlwe.Plaintext
	profile        ScalarSelectorConditionProfile
	graph          scalarSelectorConditionCircuitGraph
}

type scalarSelectorConditionCircuitGraph struct {
	circuit          *ScalarSelectorConditionCircuit
	selector         *SelectorReraiseDecodeCircuit
	encoder          *ckks.Encoder
	multiplier, seal *rlwe.Plaintext
	profileDigest    string
}

type ScalarSelectorConditionEvaluator struct {
	circuit *ScalarSelectorConditionCircuit
	source  *bootstrapping.Evaluator
	ckks    *ckks.Evaluator
	keySet  *rlwe.MemEvaluationKeySet
	graph   scalarSelectorConditionEvaluatorGraph
}

type scalarSelectorConditionEvaluatorGraph struct {
	evaluator     *ScalarSelectorConditionEvaluator
	circuit       *ScalarSelectorConditionCircuit
	source        *bootstrapping.Evaluator
	ckks          *ckks.Evaluator
	keySet        *rlwe.MemEvaluationKeySet
	profileDigest string
}

func NewScalarSelectorConditionCircuit(selector *SelectorReraiseDecodeCircuit) (*ScalarSelectorConditionCircuit, error) {
	if selector == nil {
		return nil, fmt.Errorf("homchain: nil selector reraiser for scalar conditioning")
	}
	if err := selector.validate(); err != nil {
		return nil, fmt.Errorf("homchain: validate selector reraiser for scalar conditioning: %w", err)
	}
	params := selector.params
	periodic := selector.profile.periodic
	if periodic.inputLevel != 17 || periodic.exponentialLevel != 11 || periodic.square0Level != 10 ||
		periodic.rootLevel != 9 || periodic.outputLevel != scalarSelectorConditionInputLevel {
		return nil, fmt.Errorf("homchain: selector periodic schedule is not the accepted L8 conditioning source")
	}

	defaultScale := params.DefaultScale()
	squared := defaultScale.Mul(defaultScale)
	wantInputScale := squared.Mul(squared).
		Div(rlwe.NewScale(params.Q()[11]).Mul(rlwe.NewScale(params.Q()[11])).Mul(rlwe.NewScale(params.Q()[10])))
	if !periodic.outputScale.EqualScale(wantInputScale) {
		return nil, fmt.Errorf("homchain: selector output scale is not exact S^4/(q11^2*q10)")
	}
	multiplierScale := rlwe.NewScale(params.Q()[8]).Mul(rlwe.NewScale(params.Q()[7])).Div(wantInputScale)
	rawScale := wantInputScale.Mul(multiplierScale)
	outputScale := rawScale.Div(rlwe.NewScale(params.Q()[8]))
	if !b2aExactScaleEqual(rawScale, rlwe.NewScale(params.Q()[8]).Mul(rlwe.NewScale(params.Q()[7]))) ||
		!b2aExactScaleEqual(outputScale, rlwe.NewScale(params.Q()[7])) {
		return nil, fmt.Errorf("homchain: exact selector conditioner scale algebra changed")
	}

	multiplier := ckks.NewPlaintext(params, scalarSelectorConditionInputLevel)
	multiplier.LogDimensions = params.LogMaxDimensions()
	multiplier.Scale = multiplierScale
	ones := make([]complex128, signed8Slots)
	for index := range ones {
		ones[index] = 1
	}
	if err := selector.integerEncoder.Encode(ones, multiplier); err != nil {
		return nil, fmt.Errorf("homchain: encode exact selector conditioner: %w", err)
	}
	payloadDigest, err := signed8PlaintextDigest(multiplier)
	if err != nil {
		return nil, err
	}
	parameterDigest, err := signed8ParameterDigest(params)
	if err != nil {
		return nil, err
	}
	snapshots := make([]ExactScaleSnapshot, 4)
	for index, scale := range []rlwe.Scale{wantInputScale, multiplierScale, rawScale, outputScale} {
		if snapshots[index], err = NewExactScaleSnapshot(scale); err != nil {
			return nil, err
		}
	}
	sourceDigest := digestString(fmt.Sprintf(
		"scalar-selector-condition-all-one-v1|slots=%d|level=%d|scale=%s",
		signed8Slots, scalarSelectorConditionInputLevel, snapshots[1].canonicalString(),
	))
	profile := ScalarSelectorConditionProfile{
		parameterDigest: parameterDigest, rangeDigest: selector.profile.rangeDigest,
		selectorProfileDigest: selector.profile.digest,
		selectorResultSchema:  selectorReraiseDecodeResultSchema,
		producerPublicDigest:  selector.profile.producerPublicDigest,
		producerOpaqueDigest:  selector.profile.producerOpaqueDigest,
		inputLevel:            scalarSelectorConditionInputLevel, outputLevel: scalarSelectorConditionOutputLevel,
		inputScale: snapshots[0], multiplierScale: snapshots[1], rawScale: snapshots[2], outputScale: snapshots[3],
		multiplierSourceDigest: sourceDigest, multiplierPayloadDigest: payloadDigest,
		operationCounts: ScalarSelectorConditionOperationCounts{CiphertextPlaintextMultiplications: 1, Rescales: 1},
	}
	profile.digest = digestScalarSelectorConditionProfile(profile)
	circuit := &ScalarSelectorConditionCircuit{
		selector: selector, params: params, encoder: selector.integerEncoder,
		multiplier: multiplier, multiplierSeal: multiplier.CopyNew(), profile: profile,
	}
	circuit.graph = scalarSelectorConditionCircuitGraph{
		circuit: circuit, selector: selector, encoder: circuit.encoder,
		multiplier: multiplier, seal: circuit.multiplierSeal, profileDigest: profile.digest,
	}
	if err = circuit.validate(); err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *ScalarSelectorConditionCircuit) Profile() ScalarSelectorConditionProfile {
	if c == nil {
		return ScalarSelectorConditionProfile{}
	}
	return c.profile
}

func (c *ScalarSelectorConditionCircuit) BindSelectorResult(result SelectorReraiseDecodeResult) (ScalarSelectorConditionInput, error) {
	if err := c.validate(); err != nil {
		return ScalarSelectorConditionInput{}, err
	}
	if err := c.selector.validateResult(result); err != nil {
		return ScalarSelectorConditionInput{}, fmt.Errorf("homchain: authenticate selector result for conditioning: %w", err)
	}
	owned := result.scalar.CopyNew()
	payloadDigest, err := signed8CiphertextDigest(owned)
	if err != nil {
		return ScalarSelectorConditionInput{}, err
	}
	if payloadDigest != result.outputPayloadDigest {
		return ScalarSelectorConditionInput{}, fmt.Errorf("homchain: copied selector result payload differs from its producer seal")
	}
	provenance := digestScalarSelectorConditionInput(c.profile.digest, result, payloadDigest)
	return ScalarSelectorConditionInput{
		selector: owned, profileDigest: c.profile.digest, selectorProfileDigest: result.profileDigest,
		producerProfileDigest: result.producerProfileDigest, rangeDigest: result.rangeDigest,
		selectorInputProvenanceDigest: result.inputProvenanceDigest, operandMode: result.operandMode,
		selectorResultProvenanceDigest: result.provenanceDigest, selectorPath: result.path,
		payloadDigest: payloadDigest, provenanceDigest: provenance,
	}, nil
}

func (c *ScalarSelectorConditionCircuit) BindEvaluator(source *bootstrapping.Evaluator) (*ScalarSelectorConditionEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if source == nil || source.Evaluator == nil || source.MemEvaluationKeySet == nil ||
		!source.ResidualParameters.Equal(&c.params) || !source.BootstrappingParameters.Equal(&c.params) ||
		!c.params.Equal(source.Evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: selector conditioner source is incomplete or foreign")
	}
	evaluator := &ScalarSelectorConditionEvaluator{
		circuit: c, source: source, ckks: source.Evaluator, keySet: source.MemEvaluationKeySet,
	}
	evaluator.graph = scalarSelectorConditionEvaluatorGraph{
		evaluator: evaluator, circuit: c, source: source, ckks: source.Evaluator,
		keySet: source.MemEvaluationKeySet, profileDigest: c.profile.digest,
	}
	if err := evaluator.preflight(); err != nil {
		return nil, err
	}
	return evaluator, nil
}

func (e *ScalarSelectorConditionEvaluator) EvaluateNew(input ScalarSelectorConditionInput) (ScalarSelectorConditionResult, ScalarSelectorConditionTrace, error) {
	var result ScalarSelectorConditionResult
	var trace ScalarSelectorConditionTrace
	if e == nil || e.circuit == nil {
		return result, trace, fmt.Errorf("homchain: nil bound selector conditioner evaluator")
	}
	if err := e.preflight(); err != nil {
		return result, trace, err
	}
	if err := e.circuit.validateInput(input); err != nil {
		return result, trace, err
	}
	inputBefore := input.selector.CopyNew()
	raw, err := e.ckks.MulNew(input.selector, e.circuit.multiplier)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: multiply selector conditioner: %w", err)
	}
	if !input.selector.Equal(inputBefore) {
		return result, trace, fmt.Errorf("homchain: selector conditioner mutated its admitted input")
	}
	if err = requireScalarSelectorConditionState("raw product", raw, e.circuit.profile.inputLevel, e.circuit.profile.rawScale, e.circuit.params); err != nil {
		return result, trace, err
	}
	rawBefore := raw.CopyNew()
	conditioned := raw.CopyNew()
	if err = e.ckks.Rescale(conditioned, conditioned); err != nil {
		return result, trace, fmt.Errorf("homchain: rescale selector conditioner: %w", err)
	}
	if err = requireScalarSelectorConditionState("output", conditioned, e.circuit.profile.outputLevel, e.circuit.profile.outputScale, e.circuit.params); err != nil {
		return result, trace, err
	}
	if !raw.Equal(rawBefore) || !e.circuit.multiplier.Equal(e.circuit.multiplierSeal) {
		return result, trace, fmt.Errorf("homchain: selector conditioner mutated retained evidence or its cached plaintext")
	}
	rawSnapshot, err := snapshotScalarSelectorState(raw)
	if err != nil {
		return result, trace, err
	}
	outputSnapshot, err := snapshotScalarSelectorState(conditioned)
	if err != nil {
		return result, trace, err
	}
	inputBytes, err := marshalCiphertextSize("internal selector input", input.selector)
	if err != nil {
		return result, trace, err
	}
	rawBytes, err := marshalCiphertextSize("retained selector conditioner raw product", raw)
	if err != nil {
		return result, trace, err
	}
	outputBytes, err := marshalCiphertextSize("internal conditioned selector", conditioned)
	if err != nil {
		return result, trace, err
	}
	outputPayloadDigest, err := signed8CiphertextDigest(conditioned)
	if err != nil {
		return result, trace, err
	}
	provenance := digestString(fmt.Sprintf(
		"%s|profile=%s|input=%s|payload=%s",
		scalarSelectorConditionResultSchema, e.circuit.profile.digest, input.provenanceDigest, outputPayloadDigest,
	))
	trace = ScalarSelectorConditionTrace{
		profileDigest: e.circuit.profile.digest, inputProvenanceDigest: input.provenanceDigest,
		states:          []ScalarSelectorConditionState{rawSnapshot, outputSnapshot},
		operationCounts: e.circuit.profile.operationCounts,
		serializedBytes: ScalarSelectorConditionSerializedBytes{
			InternalSelectorInput: inputBytes, RetainedRawProduct: rawBytes, InternalOutput: outputBytes,
		},
		rawProduct: raw.CopyNew(),
	}
	result = ScalarSelectorConditionResult{
		conditioned: conditioned, profileDigest: e.circuit.profile.digest,
		selectorProfileDigest: input.selectorProfileDigest,
		producerProfileDigest: input.producerProfileDigest, rangeDigest: input.rangeDigest,
		inputProvenanceDigest: input.provenanceDigest, operandMode: input.operandMode,
		payloadDigest: outputPayloadDigest, provenanceDigest: provenance,
	}
	return result, trace, nil
}

func (c *ScalarSelectorConditionCircuit) validate() error {
	if c == nil || c.selector == nil || c.encoder == nil || c.multiplier == nil || c.multiplierSeal == nil {
		return fmt.Errorf("homchain: nil or incomplete selector conditioner circuit")
	}
	if err := c.selector.validate(); err != nil {
		return err
	}
	g := c.graph
	if g.circuit != c || g.selector != c.selector || g.encoder != c.encoder || g.multiplier != c.multiplier ||
		g.seal != c.multiplierSeal || g.profileDigest != c.profile.digest ||
		!c.multiplier.Equal(c.multiplierSeal) {
		return fmt.Errorf("homchain: selector conditioner circuit object graph changed")
	}
	payloadDigest, err := signed8PlaintextDigest(c.multiplier)
	if err != nil {
		return err
	}
	if c.profile.selectorResultSchema != selectorReraiseDecodeResultSchema ||
		payloadDigest != c.profile.multiplierPayloadDigest || c.profile.digest != digestScalarSelectorConditionProfile(c.profile) {
		return fmt.Errorf("homchain: selector conditioner profile or plaintext payload changed")
	}
	return nil
}

func (c *ScalarSelectorConditionCircuit) validateInput(input ScalarSelectorConditionInput) error {
	if err := c.validate(); err != nil {
		return err
	}
	if input.selector == nil {
		return fmt.Errorf("homchain: nil selector conditioner input")
	}
	sealedResult := SelectorReraiseDecodeResult{
		scalar: input.selector, profileDigest: input.selectorProfileDigest,
		producerProfileDigest: input.producerProfileDigest, rangeDigest: input.rangeDigest,
		inputProvenanceDigest: input.selectorInputProvenanceDigest, operandMode: input.operandMode,
		path: input.selectorPath, outputPayloadDigest: input.payloadDigest,
		provenanceDigest: input.selectorResultProvenanceDigest,
	}
	if err := c.selector.validateResult(sealedResult); err != nil {
		return fmt.Errorf("homchain: re-authenticate selector result before conditioning: %w", err)
	}
	if err := requireScalarSelectorConditionState("input", input.selector, c.profile.inputLevel, c.profile.inputScale, c.params); err != nil {
		return err
	}
	payloadDigest, err := signed8CiphertextDigest(input.selector)
	if err != nil {
		return err
	}
	if input.profileDigest != c.profile.digest || input.selectorProfileDigest != c.selector.profile.digest ||
		input.producerProfileDigest != c.selector.producer.profileForMode(input.operandMode).digest ||
		input.rangeDigest != c.profile.rangeDigest || !isScalarSelectorSHA256Digest(input.selectorInputProvenanceDigest) ||
		input.selectorPath != SelectorReraiseDecodePeriodicPath ||
		!isScalarSelectorSHA256Digest(input.selectorResultProvenanceDigest) ||
		input.payloadDigest != payloadDigest || input.provenanceDigest != digestScalarSelectorConditionInputFields(input, payloadDigest) {
		return fmt.Errorf("homchain: selector conditioner input has foreign profile, producer, range, payload, or provenance")
	}
	return nil
}

func (c *ScalarSelectorConditionCircuit) validateResult(result ScalarSelectorConditionResult) error {
	if err := c.validate(); err != nil {
		return err
	}
	if result.conditioned == nil {
		return fmt.Errorf("homchain: nil conditioned selector result")
	}
	if err := requireScalarSelectorConditionState("result", result.conditioned, c.profile.outputLevel, c.profile.outputScale, c.params); err != nil {
		return err
	}
	payloadDigest, err := signed8CiphertextDigest(result.conditioned)
	if err != nil {
		return err
	}
	wantProvenance := digestString(fmt.Sprintf(
		"%s|profile=%s|input=%s|payload=%s",
		scalarSelectorConditionResultSchema, c.profile.digest, result.inputProvenanceDigest, payloadDigest,
	))
	producer := c.selector.producer.profileForMode(result.operandMode)
	if producer.digest == "" || result.profileDigest != c.profile.digest ||
		result.selectorProfileDigest != c.selector.profile.digest ||
		result.producerProfileDigest != producer.digest || result.rangeDigest != c.profile.rangeDigest ||
		!isScalarSelectorSHA256Digest(result.inputProvenanceDigest) || result.payloadDigest != payloadDigest ||
		result.provenanceDigest != wantProvenance {
		return fmt.Errorf("homchain: conditioned selector result has foreign profile, producer, payload, or provenance")
	}
	return nil
}

func (e *ScalarSelectorConditionEvaluator) preflight() error {
	if e == nil || e.circuit == nil || e.source == nil || e.ckks == nil || e.keySet == nil {
		return fmt.Errorf("homchain: nil or incomplete selector conditioner evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		return err
	}
	g := e.graph
	if g.evaluator != e || g.circuit != e.circuit || g.source != e.source || g.ckks != e.ckks ||
		g.keySet != e.keySet || g.profileDigest != e.circuit.profile.digest ||
		e.source.Evaluator != e.ckks || e.source.MemEvaluationKeySet != e.keySet {
		return fmt.Errorf("homchain: selector conditioner evaluator graph changed")
	}
	return nil
}

func requireScalarSelectorConditionState(name string, ciphertext *rlwe.Ciphertext, level int, scale ExactScaleSnapshot, params ckks.Parameters) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level || ciphertext.Degree() != 1 ||
		ciphertext.LogN() != params.LogN() || ciphertext.LogDimensions != params.LogMaxDimensions() ||
		ciphertext.Slots() != signed8Slots || !ciphertext.IsBatched || !ciphertext.IsNTT || !scale.EqualScale(ciphertext.Scale) {
		return fmt.Errorf("homchain: selector conditioner %s is not exact L%d/degree1/full-dense/NTT at the sealed scale", name, level)
	}
	return nil
}

func snapshotScalarSelectorState(ciphertext *rlwe.Ciphertext) (ScalarSelectorConditionState, error) {
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return ScalarSelectorConditionState{}, err
	}
	return ScalarSelectorConditionState{
		Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale,
	}, nil
}

func marshalCiphertextSize(name string, ciphertext *rlwe.Ciphertext) (int, error) {
	if ciphertext == nil {
		return 0, fmt.Errorf("homchain: marshal nil %s", name)
	}
	payload, err := ciphertext.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("homchain: marshal %s: %w", name, err)
	}
	return len(payload), nil
}

func digestScalarSelectorConditionProfile(profile ScalarSelectorConditionProfile) string {
	return digestString(fmt.Sprintf(
		"%s|params=%s|range=%s|selector=%s|selector-result-schema=%s|producer=%s/%s|levels=%d/%d|input={%s}|multiplier={%s}|raw={%s}|output={%s}|source=%s|payload=%s|counts=%+v",
		scalarSelectorConditionProfileSchema, profile.parameterDigest, profile.rangeDigest,
		profile.selectorProfileDigest, profile.selectorResultSchema,
		profile.producerPublicDigest, profile.producerOpaqueDigest,
		profile.inputLevel, profile.outputLevel, profile.inputScale.canonicalString(),
		profile.multiplierScale.canonicalString(), profile.rawScale.canonicalString(),
		profile.outputScale.canonicalString(), profile.multiplierSourceDigest,
		profile.multiplierPayloadDigest, profile.operationCounts,
	))
}

func digestScalarSelectorConditionInput(profileDigest string, result SelectorReraiseDecodeResult, payloadDigest string) string {
	return digestString(fmt.Sprintf(
		"%s|profile=%s|selector=%s|producer=%s|range=%s|selector-input=%s|selector-result=%s|mode=%s|path=%s|payload=%s",
		scalarSelectorConditionInputSchema, profileDigest, result.profileDigest, result.producerProfileDigest,
		result.rangeDigest, result.inputProvenanceDigest, result.provenanceDigest,
		result.operandMode, result.path, payloadDigest,
	))
}

func digestScalarSelectorConditionInputFields(input ScalarSelectorConditionInput, payloadDigest string) string {
	return digestString(fmt.Sprintf(
		"%s|profile=%s|selector=%s|producer=%s|range=%s|selector-input=%s|selector-result=%s|mode=%s|path=%s|payload=%s",
		scalarSelectorConditionInputSchema, input.profileDigest, input.selectorProfileDigest,
		input.producerProfileDigest, input.rangeDigest, input.selectorInputProvenanceDigest,
		input.selectorResultProvenanceDigest, input.operandMode, input.selectorPath, payloadDigest,
	))
}

func isScalarSelectorSHA256Digest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == 64 && len(decoded) == 32
}
