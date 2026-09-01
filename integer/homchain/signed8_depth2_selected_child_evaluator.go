package homchain

import (
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Signed8Depth2SelectedChildLinkage is the complete typed-boundary digest
// chain. Arrays use root, left-child, right-child order.
type Signed8Depth2SelectedChildLinkage struct {
	FeaturePayloadDigests              [3]string
	FeatureProvenanceDigests           [3]string
	RootComparatorOutputPayloadDigest  string
	RootSelectorInputProvenanceDigest  string
	RootSelectorResultProvenanceDigest string
	ConditionInputProvenanceDigest     string
	OperandsProvenanceDigest           string
	ChildInputBindingDigest            string
	ChildResultProvenanceDigest        string
	TerminalInputProvenanceDigest      string
	TerminalResultProvenanceDigest     string
	digest                             string
}

func (l Signed8Depth2SelectedChildLinkage) Digest() string { return l.digest }

// Signed8Depth2SelectedChildStageDurations reports wrapper-observed wall time
// for each online module. These values are functional evidence, not a
// benchmark distribution.
type Signed8Depth2SelectedChildStageDurations struct {
	RootComparator  time.Duration
	RootSelector    time.Duration
	SourcePrefix    time.Duration
	ChildComparator time.Duration
	Terminal        time.Duration
}

func (d Signed8Depth2SelectedChildStageDurations) Sum() time.Duration {
	return d.RootComparator + d.RootSelector + d.SourcePrefix + d.ChildComparator + d.Terminal
}

// Signed8Depth2SelectedChildByteLedger preserves the meaning of every nested
// ledger. ModuleReportedSum deliberately retains overlapping boundaries and
// must not be reported as communication or unique-live bytes.
type Signed8Depth2SelectedChildByteLedger struct {
	RootComparator         Signed8ComparatorSerializedBytes
	RootSelector           SelectorReraiseDecodeSerializedBytes
	SourcePrefix           Signed8Depth2SourcePrefixSerializedBytes
	ChildComparator        Signed8Depth2ChildComparatorSerializedBytes
	TerminalLocal          Signed8Depth2TerminalLeafSerializedBytes
	TerminalComposedUnique int
}

func (l Signed8Depth2SelectedChildByteLedger) ModuleReportedSum() int {
	root := l.RootComparator.Feature + l.RootComparator.ThresholdOperand + l.RootComparator.Difference +
		l.RootComparator.HighMSB + l.RootComparator.ArithmeticSign + l.RootComparator.GreaterEqualOutput
	selector := l.RootSelector.OnlineTotal() + l.RootSelector.RetainedTraceTotal()
	prefix := l.SourcePrefix.ExternalInputTotal() + l.SourcePrefix.InternalSelectorTotal() +
		l.SourcePrefix.OutputOperandTotal() + l.SourcePrefix.RetainedEvidenceTotal()
	return root + selector + prefix + l.ChildComparator.TotalBytes() + l.TerminalComposedUnique
}

type signed8Depth2SelectedChildEvaluatorGraph struct {
	evaluator     *Signed8Depth2SelectedChildEvaluator
	circuit       *Signed8Depth2SelectedChildCircuit
	source        *bootstrapping.Evaluator
	keySet        *rlwe.MemEvaluationKeySet
	rootSelector  *SelectorReraiseDecodeEvaluator
	prefix        *Signed8Depth2SourcePrefixEvaluator
	child         *Signed8Depth2ChildComparatorEvaluator
	terminal      *Signed8Depth2TerminalLeafEvaluator
	profileDigest string
}

// Signed8Depth2SelectedChildEvaluator binds every nested evaluator to one
// exact bootstrap source and key set.
type Signed8Depth2SelectedChildEvaluator struct {
	circuit      *Signed8Depth2SelectedChildCircuit
	source       *bootstrapping.Evaluator
	keySet       *rlwe.MemEvaluationKeySet
	rootSelector *SelectorReraiseDecodeEvaluator
	prefix       *Signed8Depth2SourcePrefixEvaluator
	child        *Signed8Depth2ChildComparatorEvaluator
	terminal     *Signed8Depth2TerminalLeafEvaluator
	graph        signed8Depth2SelectedChildEvaluatorGraph
}

// Signed8Depth2SelectedChildResult is the authenticated terminal result plus
// the outer input and linkage seals.
type Signed8Depth2SelectedChildResult struct {
	terminalResult        Signed8Depth2TerminalLeafResult
	profileDigest         string
	inputProvenanceDigest string
	linkageDigest         string
	outputPayloadDigest   string
	provenanceDigest      string
}

func (r Signed8Depth2SelectedChildResult) Ciphertext() *rlwe.Ciphertext {
	return r.terminalResult.Ciphertext()
}
func (r Signed8Depth2SelectedChildResult) ProfileDigest() string { return r.profileDigest }
func (r Signed8Depth2SelectedChildResult) InputProvenanceDigest() string {
	return r.inputProvenanceDigest
}
func (r Signed8Depth2SelectedChildResult) LinkageDigest() string { return r.linkageDigest }
func (r Signed8Depth2SelectedChildResult) OutputPayloadDigest() string {
	return r.outputPayloadDigest
}
func (r Signed8Depth2SelectedChildResult) ProvenanceDigest() string { return r.provenanceDigest }
func (r Signed8Depth2SelectedChildResult) TerminalResult() Signed8Depth2TerminalLeafResult {
	return cloneSigned8Depth2TerminalLeafResult(r.terminalResult)
}

// Signed8Depth2SelectedChildTrace retains the accepted nested evidence and
// private typed tokens required to revalidate the complete cross-stage tuple.
type Signed8Depth2SelectedChildTrace struct {
	profileDigest, inputProvenanceDigest  string
	resultProvenanceDigest, linkageDigest string
	linkage                               Signed8Depth2SelectedChildLinkage
	rootComparator                        Signed8ComparatorTrace
	rootSelector                          SelectorReraiseDecodeTrace
	sourcePrefix                          Signed8Depth2SourcePrefixTrace
	childComparator                       Signed8Depth2ChildComparatorTrace
	terminal                              Signed8Depth2TerminalLeafTrace
	selectorInput                         SelectorReraiseDecodeInput
	selectorResult                        SelectorReraiseDecodeResult
	conditionInput                        ScalarSelectorConditionInput
	operands                              Signed8Depth2Operands
	childInput                            Signed8Depth2ChildComparatorInput
	childResult                           Signed8Depth2ChildComparatorResult
	terminalInput                         Signed8Depth2TerminalLeafInput
	durations                             Signed8Depth2SelectedChildStageDurations
	bytes                                 Signed8Depth2SelectedChildByteLedger
	traceDigest                           string
	wallTime                              time.Duration
}

func (t Signed8Depth2SelectedChildTrace) ProfileDigest() string { return t.profileDigest }
func (t Signed8Depth2SelectedChildTrace) InputProvenanceDigest() string {
	return t.inputProvenanceDigest
}
func (t Signed8Depth2SelectedChildTrace) ResultProvenanceDigest() string {
	return t.resultProvenanceDigest
}
func (t Signed8Depth2SelectedChildTrace) Linkage() Signed8Depth2SelectedChildLinkage {
	return t.linkage
}
func (t Signed8Depth2SelectedChildTrace) RootComparatorTrace() Signed8ComparatorTrace {
	return t.rootComparator
}
func (t Signed8Depth2SelectedChildTrace) RootSelectorTrace() SelectorReraiseDecodeTrace {
	return t.rootSelector
}
func (t Signed8Depth2SelectedChildTrace) SourcePrefixTrace() Signed8Depth2SourcePrefixTrace {
	return t.sourcePrefix
}
func (t Signed8Depth2SelectedChildTrace) ChildComparatorTrace() Signed8Depth2ChildComparatorTrace {
	return t.childComparator
}
func (t Signed8Depth2SelectedChildTrace) TerminalTrace() Signed8Depth2TerminalLeafTrace {
	return cloneSigned8Depth2TerminalLeafTrace(t.terminal)
}
func (t Signed8Depth2SelectedChildTrace) StageDurations() Signed8Depth2SelectedChildStageDurations {
	return t.durations
}
func (t Signed8Depth2SelectedChildTrace) ByteLedger() Signed8Depth2SelectedChildByteLedger {
	return t.bytes
}
func (t Signed8Depth2SelectedChildTrace) Digest() string          { return t.traceDigest }
func (t Signed8Depth2SelectedChildTrace) WallTime() time.Duration { return t.wallTime }

func (c *Signed8Depth2SelectedChildCircuit) bindSelectedChildEvaluator(
	source *bootstrapping.Evaluator,
) (*Signed8Depth2SelectedChildEvaluator, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if source == nil || source.Evaluator == nil || source.EvaluationKeys == nil || source.MemEvaluationKeySet == nil ||
		!source.ResidualParameters.Equal(&c.comparator.params) ||
		!source.BootstrappingParameters.Equal(&c.comparator.params) ||
		!c.comparator.params.Equal(source.Evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: selected-child bootstrap source is nil, incomplete, or foreign")
	}
	rootSelector, err := c.selector.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind selected-child root selector: %w", err)
	}
	prefix, err := c.prefix.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind selected-child source prefix: %w", err)
	}
	child, err := c.child.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind selected-child child comparator: %w", err)
	}
	terminal, err := c.terminal.BindEvaluator(source)
	if err != nil {
		return nil, fmt.Errorf("homchain: bind selected-child terminal: %w", err)
	}
	evaluator := &Signed8Depth2SelectedChildEvaluator{
		circuit: c, source: source, keySet: source.MemEvaluationKeySet,
		rootSelector: rootSelector, prefix: prefix, child: child, terminal: terminal,
	}
	evaluator.graph = signed8Depth2SelectedChildEvaluatorGraph{
		evaluator: evaluator, circuit: c, source: source, keySet: source.MemEvaluationKeySet,
		rootSelector: rootSelector, prefix: prefix, child: child, terminal: terminal,
		profileDigest: c.profile.digest,
	}
	if err = evaluator.preflight(); err != nil {
		return nil, err
	}
	return evaluator, nil
}

func (e *Signed8Depth2SelectedChildEvaluator) preflight() error {
	if e == nil || e.circuit == nil || e.source == nil || e.keySet == nil || e.rootSelector == nil ||
		e.prefix == nil || e.child == nil || e.terminal == nil {
		return fmt.Errorf("homchain: nil or incomplete selected-child evaluator")
	}
	if err := e.circuit.validate(); err != nil {
		return err
	}
	g := e.graph
	if g.evaluator != e || g.circuit != e.circuit || g.source != e.source || g.keySet != e.keySet ||
		g.rootSelector != e.rootSelector || g.prefix != e.prefix || g.child != e.child || g.terminal != e.terminal ||
		g.profileDigest != e.circuit.profile.digest || e.source.MemEvaluationKeySet != e.keySet ||
		e.source.EvaluationKeys == nil || e.source.EvaluationKeys.MemEvaluationKeySet != e.keySet {
		return fmt.Errorf("homchain: selected-child evaluator object graph changed")
	}
	if e.rootSelector.circuit != e.circuit.selector || e.rootSelector.source != e.source ||
		e.rootSelector.keySet != e.keySet || e.rootSelector.producer == nil ||
		e.rootSelector.producer.circuit != e.circuit.comparator || e.rootSelector.producer.source != e.source ||
		e.prefix.circuit != e.circuit.prefix || e.prefix.source != e.source || e.prefix.keySet != e.keySet ||
		e.child.circuit != e.circuit.child || e.child.source != e.source || e.child.sourceKeySet != e.keySet ||
		e.terminal.circuit != e.circuit.terminal || e.terminal.source != e.source || e.terminal.keySet != e.keySet {
		return fmt.Errorf("homchain: selected-child nested evaluator ownership changed")
	}
	if _, err := e.rootSelector.preflight(); err != nil {
		return fmt.Errorf("homchain: selected-child root-selector preflight: %w", err)
	}
	if err := e.prefix.preflight(); err != nil {
		return fmt.Errorf("homchain: selected-child prefix preflight: %w", err)
	}
	if err := e.child.preflight(); err != nil {
		return fmt.Errorf("homchain: selected-child child-comparator preflight: %w", err)
	}
	if _, err := e.terminal.preflight(); err != nil {
		return fmt.Errorf("homchain: selected-child terminal preflight: %w", err)
	}
	return nil
}

// EvaluatePublicNew executes the complete source-faithful depth-2 path. The
// public root threshold is derived from the sealed tree; no threshold argument
// is accepted.
func (e *Signed8Depth2SelectedChildEvaluator) EvaluatePublicNew(
	input Signed8Depth2SelectedChildInput,
) (result Signed8Depth2SelectedChildResult, trace Signed8Depth2SelectedChildTrace, err error) {
	started := time.Now()
	if e == nil || e.circuit == nil {
		return result, trace, fmt.Errorf("homchain: nil selected-child evaluator")
	}
	if err = e.circuit.validateInput(input); err != nil {
		return result, trace, err
	}
	if err = e.preflight(); err != nil {
		return result, trace, err
	}
	inputBefore := cloneSigned8Depth2SelectedChildInput(input)
	defer func() {
		if !equalSigned8Depth2SelectedChildInputs(input, inputBefore) {
			result = Signed8Depth2SelectedChildResult{}
			trace = Signed8Depth2SelectedChildTrace{}
			if err == nil {
				err = fmt.Errorf("homchain: selected-child evaluation mutated its admitted input")
			} else {
				err = fmt.Errorf("homchain: selected-child evaluation mutated its admitted input after: %w", err)
			}
		}
	}()

	rootThreshold := int64(e.circuit.profile.rootThreshold)
	thresholds := [signed8Words]int64{rootThreshold, rootThreshold, rootThreshold, rootThreshold}
	stage := time.Now()
	rootResult, rootTrace, err := e.rootSelector.producer.CompareGEPublicNew(input.root, thresholds)
	rootWall := time.Since(stage)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child root comparison: %w", err)
	}
	if rootTrace.ThresholdOperandDigest() != e.circuit.rootThresholdPayloadDigest ||
		rootTrace.OperandMode() != Signed8PublicThresholdCTPT {
		return result, trace, fmt.Errorf("homchain: selected-child root comparison used a foreign threshold or operand mode")
	}
	selectorInput, err := e.circuit.selector.BindComparatorResult(rootResult)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child bind root comparison: %w", err)
	}
	stage = time.Now()
	selectorResult, selectorTrace, err := e.rootSelector.EvaluateNew(selectorInput)
	selectorWall := time.Since(stage)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child root selector: %w", err)
	}
	conditionInput, err := e.circuit.prefix.BindSelectorResult(selectorResult)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child bind conditioned root selector: %w", err)
	}
	stage = time.Now()
	operands, prefixTrace, err := e.prefix.EvaluateNew(
		conditionInput, [2]Signed8FeatureInput{input.left, input.right},
	)
	prefixWall := time.Since(stage)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child source prefix: %w", err)
	}
	childInput, err := e.circuit.child.BindOperands(operands)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child bind child operands: %w", err)
	}
	stage = time.Now()
	childResult, childTrace, err := e.child.EvaluateNew(childInput)
	childWall := time.Since(stage)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child child comparison: %w", err)
	}
	terminalInput, err := e.circuit.terminal.BindChildResult(childInput, childResult)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child bind terminal: %w", err)
	}
	stage = time.Now()
	terminalResult, terminalTrace, err := e.terminal.EvaluateNew(terminalInput)
	terminalWall := time.Since(stage)
	if err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child terminal: %w", err)
	}
	if err = e.preflight(); err != nil {
		return result, trace, fmt.Errorf("homchain: selected-child post-execution preflight: %w", err)
	}

	linkage := Signed8Depth2SelectedChildLinkage{
		FeaturePayloadDigests:              input.featurePayloadDigests,
		FeatureProvenanceDigests:           input.featureProvenanceDigests,
		RootComparatorOutputPayloadDigest:  selectorInput.payloadDigest,
		RootSelectorInputProvenanceDigest:  selectorInput.provenanceDigest,
		RootSelectorResultProvenanceDigest: selectorResult.provenanceDigest,
		ConditionInputProvenanceDigest:     conditionInput.provenanceDigest,
		OperandsProvenanceDigest:           operands.provenanceDigest,
		ChildInputBindingDigest:            childInput.bindingDigest,
		ChildResultProvenanceDigest:        childResult.provenanceDigest,
		TerminalInputProvenanceDigest:      terminalInput.provenanceDigest,
		TerminalResultProvenanceDigest:     terminalResult.provenanceDigest,
	}
	linkage.digest = digestSigned8Depth2SelectedChildLinkage(linkage)
	result = Signed8Depth2SelectedChildResult{
		terminalResult: cloneSigned8Depth2TerminalLeafResult(terminalResult),
		profileDigest:  e.circuit.profile.digest, inputProvenanceDigest: input.provenanceDigest,
		linkageDigest: linkage.digest, outputPayloadDigest: terminalResult.outputPayloadDigest,
	}
	result.provenanceDigest = digestSigned8Depth2SelectedChildResult(result)
	durations := Signed8Depth2SelectedChildStageDurations{
		RootComparator: rootWall, RootSelector: selectorWall, SourcePrefix: prefixWall,
		ChildComparator: childWall, Terminal: terminalWall,
	}
	bytes := Signed8Depth2SelectedChildByteLedger{
		RootComparator: rootTrace.SerializedBytes(), RootSelector: selectorTrace.SerializedBytes(),
		SourcePrefix: prefixTrace.SerializedBytes(), ChildComparator: childTrace.SerializedBytes(),
		TerminalLocal: terminalTrace.SerializedBytes(), TerminalComposedUnique: terminalTrace.UniqueComposedMeasuredBytes(),
	}
	trace = Signed8Depth2SelectedChildTrace{
		profileDigest: e.circuit.profile.digest, inputProvenanceDigest: input.provenanceDigest,
		resultProvenanceDigest: result.provenanceDigest, linkageDigest: linkage.digest, linkage: linkage,
		rootComparator: rootTrace, rootSelector: selectorTrace, sourcePrefix: prefixTrace,
		childComparator: childTrace, terminal: cloneSigned8Depth2TerminalLeafTrace(terminalTrace),
		selectorInput:  cloneSelectorReraiseDecodeInput(selectorInput),
		selectorResult: cloneSelectorReraiseDecodeResult(selectorResult),
		conditionInput: cloneScalarSelectorConditionInput(conditionInput),
		operands:       cloneSigned8Depth2ChildOperands(operands),
		childInput:     cloneSigned8Depth2ChildComparatorInput(childInput),
		childResult:    cloneSigned8Depth2ChildComparatorResult(childResult),
		terminalInput:  cloneSigned8Depth2TerminalLeafInput(terminalInput),
		durations:      durations, bytes: bytes, wallTime: time.Since(started),
	}
	trace.traceDigest = digestSigned8Depth2SelectedChildTrace(trace)
	if err = e.circuit.validateTrace(input, result, trace); err != nil {
		return Signed8Depth2SelectedChildResult{}, Signed8Depth2SelectedChildTrace{}, err
	}
	return result, trace, nil
}

func (c *Signed8Depth2SelectedChildCircuit) validateResult(result Signed8Depth2SelectedChildResult) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := c.terminal.validateResult(result.terminalResult); err != nil {
		return fmt.Errorf("homchain: selected-child terminal result: %w", err)
	}
	if result.profileDigest != c.profile.digest || result.inputProvenanceDigest == "" || result.linkageDigest == "" ||
		result.outputPayloadDigest != result.terminalResult.outputPayloadDigest ||
		result.provenanceDigest != digestSigned8Depth2SelectedChildResult(result) {
		return fmt.Errorf("homchain: selected-child result profile, linkage, output, or provenance changed")
	}
	return nil
}

func (c *Signed8Depth2SelectedChildCircuit) validateTrace(
	input Signed8Depth2SelectedChildInput,
	result Signed8Depth2SelectedChildResult,
	trace Signed8Depth2SelectedChildTrace,
) error {
	if err := c.validateInput(input); err != nil {
		return err
	}
	if err := c.validateResult(result); err != nil {
		return err
	}
	if trace.profileDigest != c.profile.digest || trace.inputProvenanceDigest != input.provenanceDigest ||
		trace.resultProvenanceDigest != result.provenanceDigest || trace.linkageDigest != result.linkageDigest ||
		trace.linkage.digest != trace.linkageDigest ||
		trace.linkage.digest != digestSigned8Depth2SelectedChildLinkage(trace.linkage) ||
		trace.traceDigest != digestSigned8Depth2SelectedChildTrace(trace) || trace.wallTime <= 0 ||
		trace.durations.RootComparator <= 0 || trace.durations.RootSelector <= 0 || trace.durations.SourcePrefix <= 0 ||
		trace.durations.ChildComparator <= 0 || trace.durations.Terminal <= 0 || trace.durations.Sum() > trace.wallTime {
		return fmt.Errorf("homchain: selected-child outer trace identity or timing changed")
	}
	if trace.linkage.FeaturePayloadDigests != input.featurePayloadDigests ||
		trace.linkage.FeatureProvenanceDigests != input.featureProvenanceDigests ||
		trace.linkage.RootComparatorOutputPayloadDigest != trace.selectorInput.payloadDigest ||
		trace.linkage.RootSelectorInputProvenanceDigest != trace.selectorInput.provenanceDigest ||
		trace.linkage.RootSelectorResultProvenanceDigest != trace.selectorResult.provenanceDigest ||
		trace.linkage.ConditionInputProvenanceDigest != trace.conditionInput.provenanceDigest ||
		trace.linkage.OperandsProvenanceDigest != trace.operands.provenanceDigest ||
		trace.linkage.ChildInputBindingDigest != trace.childInput.bindingDigest ||
		trace.linkage.ChildResultProvenanceDigest != trace.childResult.provenanceDigest ||
		trace.linkage.TerminalInputProvenanceDigest != trace.terminalInput.provenanceDigest ||
		trace.linkage.TerminalResultProvenanceDigest != result.terminalResult.provenanceDigest {
		return fmt.Errorf("homchain: selected-child cross-stage linkage changed")
	}
	if err := validateSigned8RuntimeEvidence(c.comparator.publicProfile, trace.rootComparator); err != nil {
		return fmt.Errorf("homchain: selected-child root evidence: %w", err)
	}
	if trace.rootComparator.ThresholdOperandDigest() != c.rootThresholdPayloadDigest ||
		trace.rootComparator.OperandMode() != Signed8PublicThresholdCTPT {
		return fmt.Errorf("homchain: selected-child root trace changed mode or threshold")
	}
	if err := c.selector.validateInput(trace.selectorInput); err != nil {
		return err
	}
	if err := c.selector.validateResult(trace.selectorResult); err != nil {
		return err
	}
	if err := validateSelectorReraiseDecodeRuntimeEvidence(
		c.selector.profile, trace.selectorInput, trace.rootSelector, trace.selectorResult.scalar,
	); err != nil {
		return fmt.Errorf("homchain: selected-child root-selector evidence: %w", err)
	}
	if err := c.prefix.conditioner.validateInput(trace.conditionInput); err != nil {
		return err
	}
	if err := c.prefix.validateOperands(trace.operands); err != nil {
		return err
	}
	if trace.operands.featureInputPayloadDigests != ([2]string{input.left.payloadDigest, input.right.payloadDigest}) ||
		trace.operands.selectorInputProvenanceDigest != trace.conditionInput.provenanceDigest ||
		trace.operands.producerProfileDigest != c.comparator.publicProfile.digest {
		return fmt.Errorf("homchain: selected-child prefix inputs are not the exact root-selected candidate tuple")
	}
	if trace.sourcePrefix.profileDigest != c.prefix.profile.digest ||
		trace.sourcePrefix.operandsProvenanceDigest != trace.operands.provenanceDigest ||
		trace.sourcePrefix.operationCounts != c.prefix.profile.operationCounts || len(trace.sourcePrefix.states) != 9 ||
		trace.sourcePrefix.conditionerTrace.profileDigest != c.prefix.conditioner.profile.digest ||
		trace.sourcePrefix.conditionerTrace.inputProvenanceDigest != trace.conditionInput.provenanceDigest ||
		trace.sourcePrefix.conditionerTrace.operationCounts != c.prefix.conditioner.profile.operationCounts {
		return fmt.Errorf("homchain: selected-child prefix evidence changed")
	}
	if err := c.child.validateInput(trace.childInput); err != nil {
		return err
	}
	if err := c.child.validateResult(trace.childResult); err != nil {
		return err
	}
	if trace.childComparator.traceDigest != digestSigned8Depth2ChildComparatorTrace(trace.childComparator) ||
		trace.childComparator.profileDigest != c.child.profile.digest ||
		trace.childComparator.inputBindingDigest != trace.childInput.bindingDigest ||
		trace.childComparator.resultProvenanceDigest != trace.childResult.provenanceDigest {
		return fmt.Errorf("homchain: selected-child child-comparator evidence changed")
	}
	if err := c.terminal.validateInput(trace.terminalInput); err != nil {
		return err
	}
	if err := c.terminal.validateTrace(trace.terminalInput, result.terminalResult, trace.terminal); err != nil {
		return fmt.Errorf("homchain: selected-child terminal evidence: %w", err)
	}
	wantBytes := Signed8Depth2SelectedChildByteLedger{
		RootComparator: trace.rootComparator.SerializedBytes(), RootSelector: trace.rootSelector.SerializedBytes(),
		SourcePrefix: trace.sourcePrefix.SerializedBytes(), ChildComparator: trace.childComparator.SerializedBytes(),
		TerminalLocal: trace.terminal.SerializedBytes(), TerminalComposedUnique: trace.terminal.UniqueComposedMeasuredBytes(),
	}
	if trace.bytes != wantBytes || trace.bytes.ModuleReportedSum() <= 0 {
		return fmt.Errorf("homchain: selected-child byte ledger changed")
	}
	return nil
}

func cloneSelectorReraiseDecodeInput(input SelectorReraiseDecodeInput) SelectorReraiseDecodeInput {
	input.branch = copyA2BRefreshCiphertext(input.branch)
	return input
}

func cloneSelectorReraiseDecodeResult(result SelectorReraiseDecodeResult) SelectorReraiseDecodeResult {
	result.scalar = copyA2BRefreshCiphertext(result.scalar)
	return result
}

func cloneScalarSelectorConditionInput(input ScalarSelectorConditionInput) ScalarSelectorConditionInput {
	input.selector = copyA2BRefreshCiphertext(input.selector)
	return input
}

func digestSigned8Depth2SelectedChildLinkage(linkage Signed8Depth2SelectedChildLinkage) string {
	return digestString(fmt.Sprintf(
		"%s|feature-payloads=%s,%s,%s|feature-provenance=%s,%s,%s|root-output=%s|selector-input=%s|selector-result=%s|condition-input=%s|operands=%s|child-input=%s|child-result=%s|terminal-input=%s|terminal-result=%s",
		signed8Depth2SelectedChildLinkageSchema,
		linkage.FeaturePayloadDigests[0], linkage.FeaturePayloadDigests[1], linkage.FeaturePayloadDigests[2],
		linkage.FeatureProvenanceDigests[0], linkage.FeatureProvenanceDigests[1], linkage.FeatureProvenanceDigests[2],
		linkage.RootComparatorOutputPayloadDigest, linkage.RootSelectorInputProvenanceDigest,
		linkage.RootSelectorResultProvenanceDigest, linkage.ConditionInputProvenanceDigest,
		linkage.OperandsProvenanceDigest, linkage.ChildInputBindingDigest,
		linkage.ChildResultProvenanceDigest, linkage.TerminalInputProvenanceDigest,
		linkage.TerminalResultProvenanceDigest,
	))
}

func digestSigned8Depth2SelectedChildResult(result Signed8Depth2SelectedChildResult) string {
	return digestString(fmt.Sprintf(
		"%s|profile=%s|input=%s|linkage=%s|terminal=%s|output=%s",
		signed8Depth2SelectedChildResultSchema, result.profileDigest, result.inputProvenanceDigest,
		result.linkageDigest, result.terminalResult.provenanceDigest, result.outputPayloadDigest,
	))
}

func digestSigned8Depth2SelectedChildTrace(trace Signed8Depth2SelectedChildTrace) string {
	return digestString(fmt.Sprintf(
		"%s|profile=%s|input=%s|result=%s|linkage=%s|root-profile=%s|root-threshold=%s|root-states=%v|root-counts=%+v|selector-result=%s|selector-states=%v|selector-counts=%+v|operands=%s|prefix-states=%v|prefix-counts=%+v|child-trace=%s|terminal-trace=%s|durations=%d,%d,%d,%d,%d|bytes=%+v|wall=%d",
		signed8Depth2SelectedChildTraceSchema, trace.profileDigest, trace.inputProvenanceDigest,
		trace.resultProvenanceDigest, trace.linkageDigest, trace.rootComparator.profileDigest,
		trace.rootComparator.thresholdOperandDigest, trace.rootComparator.states, trace.rootComparator.wrapperCounts,
		trace.rootSelector.resultProvenanceDigest, trace.rootSelector.states, trace.rootSelector.operationCounts,
		trace.sourcePrefix.operandsProvenanceDigest, trace.sourcePrefix.states, trace.sourcePrefix.operationCounts,
		trace.childComparator.traceDigest, trace.terminal.traceDigest,
		trace.durations.RootComparator.Nanoseconds(), trace.durations.RootSelector.Nanoseconds(),
		trace.durations.SourcePrefix.Nanoseconds(), trace.durations.ChildComparator.Nanoseconds(),
		trace.durations.Terminal.Nanoseconds(), trace.bytes, trace.wallTime.Nanoseconds(),
	))
}
