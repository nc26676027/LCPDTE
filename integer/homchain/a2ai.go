package homchain

import (
	"fmt"
	"math"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
)

// A2AIHighOptions bounds the multiplicative scale error introduced by
// Lattigo ScaleDown. The error is measured as |log2(errScale)|, where
// errScale is returned by ScaleDown.
type A2AIHighOptions struct {
	MaxAbsLog2ScaleDownError float64
}

// CiphertextState is the externally auditable level/scale snapshot of one
// A2A-I stage.
type CiphertextState struct {
	Status        A2AIStageStatus
	Level         int
	Scale         ExactScaleSnapshot
	Log2Scale     float64
	LogDimensions ring.Dimensions
}

// A2AIHighTrace records the physical Lattigo path. In particular, callers can
// distinguish the guarded ScaleDown adapter from Gao's fused RLWE.Truncate.
type A2AIHighTrace struct {
	AdaptationLabel          string
	RawScaleSemantics        string
	CircuitDigest            string
	TransformSourceDigest    string
	Admission                A2AIAdmissionTrace
	Input                    CiphertextState
	AfterZToC                CiphertextState
	AfterSlotsToCoeffs       CiphertextState
	AfterScaleDown           CiphertextState
	AfterModUp               CiphertextState
	AfterCoeffsToSlots       CiphertextState
	Output                   CiphertextState
	FullPackingGap           int
	ScaleDownError           ExactScaleSnapshot
	ScaleDownLog2Error       float64
	MaxAbsLog2ScaleDownError float64
	EarlyResize              A2AIEarlyResizeTrace
	RawDFT                   A2AIDFTTrace
	KeyProfile               A2AIKeyProfile
	KeyPreflight             A2AIKeyPreflightTrace
	FailureStage             A2AIStageName
}

const (
	A2AIGuardedLattigoAdaptation = "guarded_lattigo_scaledown_modup_adaptation"
	A2AIRawScaleQ0TimesError     = "q0_times_errScale_not_exact_q0"
)

// A2AIStageStatus distinguishes a legitimate level-zero observation from a
// stage that was never reached or failed before producing an output state.
type A2AIStageStatus uint8

const (
	A2AINotReached A2AIStageStatus = iota
	A2AIReached
	A2AIFailed
)

// A2AIStageName identifies the operation boundary responsible for an error.
type A2AIStageName string

const (
	A2AIStageAdmission     A2AIStageName = "admission"
	A2AIStageKeyPreflight  A2AIStageName = "key-preflight"
	A2AIStageInput         A2AIStageName = "input"
	A2AIStageZToC          A2AIStageName = "z-to-c"
	A2AIStageSlotsToCoeffs A2AIStageName = "slots-to-coeffs"
	A2AIStageScaleDown     A2AIStageName = "guarded-scaledown"
	A2AIStageModUp         A2AIStageName = "modup-trace"
	A2AIStageCoeffsToSlots A2AIStageName = "coeffs-to-slots"
	A2AIStageCToZ          A2AIStageName = "c-to-z"
)

func (t *A2AIHighTrace) fail(stage A2AIStageName) {
	t.FailureStage = stage
	switch stage {
	case A2AIStageInput:
		t.Input.Status = A2AIFailed
	case A2AIStageZToC:
		t.AfterZToC.Status = A2AIFailed
	case A2AIStageSlotsToCoeffs:
		t.AfterSlotsToCoeffs.Status = A2AIFailed
	case A2AIStageScaleDown:
		t.AfterScaleDown.Status = A2AIFailed
	case A2AIStageModUp:
		t.AfterModUp.Status = A2AIFailed
	case A2AIStageCoeffsToSlots:
		t.AfterCoeffsToSlots.Status = A2AIFailed
	case A2AIStageCToZ:
		t.Output.Status = A2AIFailed
	}
}

// A2AIHighEvaluator evaluates the dense/full-slot Gao A2A-I operator graph
// with a guarded Lattigo ScaleDown/ModUp adapter. It can only be obtained by
// binding an A2AIHighCircuit, which rejects sparse packing and
// MessageRatio != 1. The adapter also rejects the ModUp scale-relabel branch;
// under this contract ModUp preserves ScaleDown's q0*errScale metadata (not
// exact q0) and Trace has gap one, so no extra PartialSum or 1/N factor is
// applied.
type A2AIHighEvaluator struct {
	circuit        *A2AIHighCircuit
	bootstrap      *bootstrapping.Evaluator
	triangle       *Evaluator
	rawDFT         RawFullSlotDFT
	options        A2AIHighOptions
	gap            int
	sourceGraph    a2aiEvaluatorGraphIdentity
	executionGraph a2aiEvaluatorGraphIdentity
}

func equalIntSlice(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// A2AIHighNew evaluates
//
//	Z-To-C -> raw Slots-To-Coeffs -> guarded ScaleDown -> ModUp/Trace
//	-> raw Coeffs-To-Slots -> C-To-Z.
//
// The input ciphertext is never mutated. A partially populated trace is
// returned with any stage error.
func (e *A2AIHighEvaluator) A2AIHighNew(input *rlwe.Ciphertext, admission A2AIAdmissionCertificate) (*rlwe.Ciphertext, A2AIHighTrace, error) {
	var trace A2AIHighTrace
	var err error
	if e == nil || e.circuit == nil || e.bootstrap == nil || e.triangle == nil {
		trace.fail(A2AIStageInput)
		return nil, trace, fmt.Errorf("homchain: nil A2A-I evaluator")
	}
	v, u := e.circuit.v, e.circuit.u
	trace.FullPackingGap = e.gap
	trace.MaxAbsLog2ScaleDownError = e.options.MaxAbsLog2ScaleDownError
	trace.AdaptationLabel = A2AIGuardedLattigoAdaptation
	trace.RawScaleSemantics = A2AIRawScaleQ0TimesError
	trace.RawDFT = e.rawDFT.auditTrace()
	trace.CircuitDigest = e.circuit.profile.circuitDigest
	trace.TransformSourceDigest = e.circuit.profile.transformSourceDigest
	if err := admission.validate(); err != nil {
		trace.fail(A2AIStageAdmission)
		return nil, trace, err
	}
	trace.Admission = admission.trace()
	if input == nil {
		trace.fail(A2AIStageInput)
		return nil, trace, fmt.Errorf("homchain: nil A2A-I input")
	}
	if !admission.Delta().EqualScale(input.Scale) {
		trace.fail(A2AIStageAdmission)
		return nil, trace, fmt.Errorf("homchain: A2A-I admission Delta does not match the exact input scale")
	}
	if ratio := e.bootstrap.Mod1Parameters.MessageRatio(); ratio != 1 {
		trace.fail(A2AIStageAdmission)
		return nil, trace, fmt.Errorf("homchain: A2A-I MessageRatio changed to %g, want 1", ratio)
	}
	if input.LogSlots() != e.rawDFT.logSlots {
		trace.fail(A2AIStageInput)
		return nil, trace, fmt.Errorf("homchain: A2A-I input LogSlots=%d, want full LogSlots=%d", input.LogSlots(), e.rawDFT.logSlots)
	}
	if trace.Input, err = ciphertextState(input); err != nil {
		trace.fail(A2AIStageInput)
		return nil, trace, err
	}

	if err := validateCompiledPairAtLevel("V", v, input.Level()); err != nil {
		trace.fail(A2AIStageZToC)
		return nil, trace, err
	}
	if v.Low.LogDimensions != input.LogDimensions {
		trace.fail(A2AIStageZToC)
		return nil, trace, fmt.Errorf(
			"homchain: V dimensions %+v differ from input %+v",
			v.Low.LogDimensions, input.LogDimensions,
		)
	}
	trace.KeyProfile = e.circuit.RequiredKeyProfile()
	keyPreflight, err := e.preflightKeys(trace.KeyProfile)
	trace.KeyPreflight = keyPreflight
	if err != nil {
		trace.fail(A2AIStageKeyPreflight)
		return nil, trace, err
	}
	working := input.CopyNew()
	coefficientHalves, err := e.triangle.ZToCNew(working, v)
	if err != nil {
		trace.fail(A2AIStageZToC)
		return nil, trace, fmt.Errorf("homchain: A2A-I Z-To-C: %w", err)
	}
	if err = validateCiphertextPairState("Z-To-C", coefficientHalves); err != nil {
		trace.fail(A2AIStageZToC)
		return nil, trace, err
	}
	if trace.AfterZToC, err = ciphertextState(coefficientHalves[0]); err != nil {
		trace.fail(A2AIStageZToC)
		return nil, trace, err
	}
	expectedZToCLevel := v.Low.LevelQ - e.rawDFT.params.LevelsConsumedPerRescaling()
	if trace.AfterZToC.Level != expectedZToCLevel {
		trace.fail(A2AIStageZToC)
		return nil, trace, fmt.Errorf("homchain: Z-To-C level=%d, want %d", trace.AfterZToC.Level, expectedZToCLevel)
	}
	if trace.AfterZToC.Level != e.rawDFT.slotsToCoeffs.LevelQ {
		trace.fail(A2AIStageZToC)
		return nil, trace, fmt.Errorf(
			"homchain: Z-To-C level=%d does not match raw Slots-To-Coeffs LevelQ=%d",
			trace.AfterZToC.Level, e.rawDFT.slotsToCoeffs.LevelQ,
		)
	}

	coefficientRLWE, err := e.bootstrap.DFTEvaluator.SlotsToCoeffsNew(
		coefficientHalves[0], coefficientHalves[1], e.rawDFT.slotsToCoeffs,
	)
	if err != nil {
		trace.fail(A2AIStageSlotsToCoeffs)
		return nil, trace, fmt.Errorf("homchain: A2A-I raw Slots-To-Coeffs: %w", err)
	}
	if trace.AfterSlotsToCoeffs, err = ciphertextState(coefficientRLWE); err != nil {
		trace.fail(A2AIStageSlotsToCoeffs)
		return nil, trace, err
	}
	if trace.AfterSlotsToCoeffs.Level != e.rawDFT.stcOutputLevel {
		trace.fail(A2AIStageSlotsToCoeffs)
		return nil, trace, fmt.Errorf(
			"homchain: raw Slots-To-Coeffs level=%d, want %d",
			trace.AfterSlotsToCoeffs.Level, e.rawDFT.stcOutputLevel,
		)
	}
	if !trace.AfterSlotsToCoeffs.Scale.Equal(trace.AfterZToC.Scale) {
		trace.fail(A2AIStageSlotsToCoeffs)
		return nil, trace, fmt.Errorf("homchain: raw Slots-To-Coeffs changed the ciphertext scale")
	}
	trace.EarlyResize, err = e.earlyResizeTrace(coefficientRLWE, admission)
	if err != nil {
		trace.fail(A2AIStageScaleDown)
		return nil, trace, err
	}

	scaledDown, errScale, err := e.bootstrap.ScaleDown(coefficientRLWE)
	if err != nil {
		trace.fail(A2AIStageScaleDown)
		return nil, trace, fmt.Errorf("homchain: A2A-I guarded ScaleDown: %w", err)
	}
	if errScale == nil {
		trace.fail(A2AIStageScaleDown)
		return nil, trace, fmt.Errorf("homchain: A2A-I ScaleDown returned nil errScale")
	}
	if trace.AfterScaleDown, err = ciphertextState(scaledDown); err != nil {
		trace.fail(A2AIStageScaleDown)
		return nil, trace, err
	}
	trace.EarlyResize.ObservedOutputLevel = scaledDown.Level()
	trace.EarlyResize.ObservedOutputLevelKnown = true
	if trace.ScaleDownError, err = NewExactScaleSnapshot(*errScale); err != nil {
		trace.fail(A2AIStageScaleDown)
		return nil, trace, fmt.Errorf("homchain: snapshot ScaleDown errScale: %w", err)
	}
	trace.ScaleDownLog2Error = errScale.Log2()
	if trace.AfterScaleDown.Level != 0 {
		trace.fail(A2AIStageScaleDown)
		return nil, trace, fmt.Errorf("homchain: ScaleDown level=%d, want 0", trace.AfterScaleDown.Level)
	}
	if math.IsNaN(trace.ScaleDownLog2Error) || math.IsInf(trace.ScaleDownLog2Error, 0) ||
		math.Abs(trace.ScaleDownLog2Error) > e.options.MaxAbsLog2ScaleDownError {
		trace.fail(A2AIStageScaleDown)
		return nil, trace, fmt.Errorf(
			"homchain: ScaleDown |log2(errScale)|=%g exceeds %g",
			math.Abs(trace.ScaleDownLog2Error), e.options.MaxAbsLog2ScaleDownError,
		)
	}
	targetScale := rlwe.NewScale(e.rawDFT.params.Q()[0])
	if got := scaledDown.Scale.Div(targetScale); !got.Equal(*errScale) {
		trace.fail(A2AIStageScaleDown)
		return nil, trace, fmt.Errorf("homchain: ScaleDown errScale does not match output.Scale/q0")
	}

	// Lattigo ModUp may enter a branch that multiplies by round(scale) but
	// records the unrounded floating-point ratio in metadata. Even scalar=1
	// then changes the raw scale, unlike Gao ModRaise. Reject that branch.
	requestedScale := e.bootstrap.Mod1Parameters.ScalingFactor().Float64() /
		e.bootstrap.Mod1Parameters.MessageRatio()
	if requestedScale/scaledDown.Scale.Float64() > 1 {
		trace.fail(A2AIStageModUp)
		return nil, trace, fmt.Errorf(
			"homchain: ModUp would relabel raw scale from %.8g toward %.8g",
			scaledDown.Scale.Float64(), requestedScale,
		)
	}
	scaleBeforeModUp, err := NewExactScaleSnapshot(scaledDown.Scale)
	if err != nil {
		trace.fail(A2AIStageModUp)
		return nil, trace, fmt.Errorf("homchain: snapshot pre-ModUp scale: %w", err)
	}
	raised, err := e.bootstrap.ModUp(scaledDown)
	if err != nil {
		trace.fail(A2AIStageModUp)
		return nil, trace, fmt.Errorf("homchain: A2A-I ModUp/Trace: %w", err)
	}
	if trace.AfterModUp, err = ciphertextState(raised); err != nil {
		trace.fail(A2AIStageModUp)
		return nil, trace, err
	}
	if trace.AfterModUp.Level != e.rawDFT.params.MaxLevel() {
		trace.fail(A2AIStageModUp)
		return nil, trace, fmt.Errorf("homchain: ModUp level=%d, want %d", trace.AfterModUp.Level, e.rawDFT.params.MaxLevel())
	}
	if !scaleBeforeModUp.EqualScale(raised.Scale) {
		trace.fail(A2AIStageModUp)
		return nil, trace, fmt.Errorf("homchain: ModUp changed raw scale under the no-relabel contract")
	}
	if raised.Level() < e.rawDFT.coeffsToSlots.LevelQ {
		trace.fail(A2AIStageModUp)
		return nil, trace, fmt.Errorf(
			"homchain: ModUp level=%d below raw Coeffs-To-Slots LevelQ=%d",
			raised.Level(), e.rawDFT.coeffsToSlots.LevelQ,
		)
	}

	recoveredLow, recoveredHigh, err := e.bootstrap.DFTEvaluator.CoeffsToSlotsNew(raised, e.rawDFT.coeffsToSlots)
	if err != nil {
		trace.fail(A2AIStageCoeffsToSlots)
		return nil, trace, fmt.Errorf("homchain: A2A-I raw Coeffs-To-Slots: %w", err)
	}
	recoveredHalves := CiphertextPair{recoveredLow, recoveredHigh}
	if err = validateCiphertextPairState("Coeffs-To-Slots", recoveredHalves); err != nil {
		trace.fail(A2AIStageCoeffsToSlots)
		return nil, trace, err
	}
	if trace.AfterCoeffsToSlots, err = ciphertextState(recoveredHalves[0]); err != nil {
		trace.fail(A2AIStageCoeffsToSlots)
		return nil, trace, err
	}
	if trace.AfterCoeffsToSlots.Level != e.rawDFT.ctsOutputLevel {
		trace.fail(A2AIStageCoeffsToSlots)
		return nil, trace, fmt.Errorf(
			"homchain: raw Coeffs-To-Slots level=%d, want %d",
			trace.AfterCoeffsToSlots.Level, e.rawDFT.ctsOutputLevel,
		)
	}
	if !trace.AfterCoeffsToSlots.Scale.Equal(trace.AfterModUp.Scale) {
		trace.fail(A2AIStageCoeffsToSlots)
		return nil, trace, fmt.Errorf("homchain: raw Coeffs-To-Slots changed the ciphertext scale")
	}
	if err = validateCompiledPairAtLevel("U", u, trace.AfterCoeffsToSlots.Level); err != nil {
		trace.fail(A2AIStageCToZ)
		return nil, trace, err
	}
	if u.Low.LogDimensions != recoveredHalves[0].LogDimensions {
		trace.fail(A2AIStageCToZ)
		return nil, trace, fmt.Errorf(
			"homchain: U dimensions %+v differ from recovered halves %+v",
			u.Low.LogDimensions, recoveredHalves[0].LogDimensions,
		)
	}

	output, err := e.triangle.CToZNew(recoveredHalves, u)
	if err != nil {
		trace.fail(A2AIStageCToZ)
		return nil, trace, fmt.Errorf("homchain: A2A-I C-To-Z: %w", err)
	}
	if trace.Output, err = ciphertextState(output); err != nil {
		trace.fail(A2AIStageCToZ)
		return nil, trace, err
	}
	expectedOutputLevel := u.Low.LevelQ - e.rawDFT.params.LevelsConsumedPerRescaling()
	if trace.Output.Level != expectedOutputLevel {
		trace.fail(A2AIStageCToZ)
		return nil, trace, fmt.Errorf("homchain: C-To-Z output level=%d, want %d", trace.Output.Level, expectedOutputLevel)
	}
	return output, trace, nil
}

func (e *A2AIHighEvaluator) preflightKeys(profile A2AIKeyProfile) (A2AIKeyPreflightTrace, error) {
	result := A2AIKeyPreflightTrace{Checked: true, EvaluatorGraphChecked: true}
	if err := e.sourceGraph.validateTopology(); err != nil {
		result.EvaluatorGraphMismatch = "source graph: " + err.Error()
		return result, fmt.Errorf("homchain: A2A-I evaluator graph preflight failed: %s", result.EvaluatorGraphMismatch)
	}
	if err := e.executionGraph.validateTopology(); err != nil {
		result.EvaluatorGraphMismatch = "sealed execution graph: " + err.Error()
		return result, fmt.Errorf("homchain: A2A-I evaluator graph preflight failed: %s", result.EvaluatorGraphMismatch)
	}
	if e.bootstrap.EvaluationKeys == nil || e.bootstrap.Evaluator == nil || e.bootstrap.Evaluator.EvaluationKeySet == nil {
		return result, fmt.Errorf("homchain: A2A-I evaluation-key set disappeared before preflight")
	}
	keys := e.bootstrap.Evaluator.EvaluationKeySet
	result.SwitchingModeMatched = e.bootstrap.EvkDenseToSparse == nil && e.bootstrap.EvkSparseToDense == nil &&
		profile.SwitchingMode == A2AIDenseNoSwitchLattigoAdaptation
	for _, element := range profile.All {
		key, err := keys.GetGaloisKey(element)
		if err != nil || key == nil {
			result.MissingGaloisElements = append(result.MissingGaloisElements, element)
			continue
		}
		if key.GaloisElement != element || key.LevelQ() < e.circuit.params.MaxLevel() || key.LevelP() != e.circuit.params.MaxLevelP() {
			result.InvalidGaloisElements = append(result.InvalidGaloisElements, element)
		}
	}
	if key, err := keys.GetRelinearizationKey(); err == nil && key != nil {
		result.RelinearizationPresent = true
		result.RelinearizationLevelMatched = key.LevelQ() >= e.circuit.params.MaxLevel() && key.LevelP() == e.circuit.params.MaxLevelP()
	}
	if err := e.sourceGraph.validateKeyIdentities(); err != nil {
		result.EvaluatorGraphMismatch = "source graph: " + err.Error()
	} else if err := e.executionGraph.validateKeyIdentities(); err != nil {
		result.EvaluatorGraphMismatch = "sealed execution graph: " + err.Error()
	} else {
		result.EvaluatorGraphMatched = true
	}
	if !result.SwitchingModeMatched || !result.RelinearizationPresent || !result.RelinearizationLevelMatched ||
		len(result.MissingGaloisElements) != 0 || len(result.InvalidGaloisElements) != 0 || !result.EvaluatorGraphMatched {
		return result, fmt.Errorf(
			"homchain: A2A-I key preflight failed: graph=%q missing-galois=%v invalid-galois=%v relin=%t relin-level=%t switching-mode=%t",
			result.EvaluatorGraphMismatch,
			result.MissingGaloisElements, result.InvalidGaloisElements, result.RelinearizationPresent,
			result.RelinearizationLevelMatched, result.SwitchingModeMatched,
		)
	}
	return result, nil
}

func (e *A2AIHighEvaluator) earlyResizeTrace(ciphertext *rlwe.Ciphertext, admission A2AIAdmissionCertificate) (A2AIEarlyResizeTrace, error) {
	result := A2AIEarlyResizeTrace{
		Source:                              "lattigo-v6.1.1:bootstrapping.ScaleDown/checkMessageRatio",
		InitialLevel:                        ciphertext.Level(),
		ActualEarlyResizeCountKnown:         false,
		AdmissionCertificateDigest:          admission.Digest(),
		CenteredMessageBound:                admission.CenteredMessageBound().String(),
		CenteredBoundUnit:                   admission.CenteredBoundUnit(),
		CenteredBoundDomain:                 admission.CenteredBoundDomain(),
		TopologyConditionInternallyComputed: true,
		MessageBoundInternallyVerified:      false,
	}

	ringQ := e.rawDFT.params.RingQ()
	scale := ciphertext.Scale
	messageRatio := rlwe.NewScale(e.bootstrap.Mod1Parameters.MessageRatio())
	level := ciphertext.Level()
	for level != 0 {
		currentMessageRatio := rlwe.NewScale(ringQ.ModulusAtLevel[level]).Div(scale)
		requiredMessageRatio := rlwe.NewScale(ringQ.SubRings[level].Modulus).Mul(messageRatio)
		if currentMessageRatio.Cmp(requiredMessageRatio) < 0 {
			break
		}
		currentSnapshot, err := NewExactScaleSnapshot(currentMessageRatio)
		if err != nil {
			return A2AIEarlyResizeTrace{}, fmt.Errorf("homchain: snapshot early-Resize current ratio: %w", err)
		}
		requiredSnapshot, err := NewExactScaleSnapshot(requiredMessageRatio)
		if err != nil {
			return A2AIEarlyResizeTrace{}, fmt.Errorf("homchain: snapshot early-Resize required ratio: %w", err)
		}
		result.ExpectedSteps = append(result.ExpectedSteps, A2AIEarlyResizeStep{
			FromLevel:            level,
			ToLevel:              level - 1,
			DroppedModulus:       fmt.Sprint(ringQ.SubRings[level].Modulus),
			CurrentMessageRatio:  currentSnapshot,
			RequiredMessageRatio: requiredSnapshot,
			Condition:            "current_message_ratio >= dropped_modulus * MessageRatio",
		})
		level--
	}
	result.TerminalLevelBeforeRescale = level
	result.ExpectedFinalRescaleToQ0 = level != 0
	return result, nil
}

func ciphertextState(ciphertext *rlwe.Ciphertext) (CiphertextState, error) {
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return CiphertextState{}, fmt.Errorf("homchain: snapshot ciphertext scale: %w", err)
	}
	return CiphertextState{
		Status: A2AIReached, Level: ciphertext.Level(), Scale: scale, Log2Scale: ciphertext.Scale.Log2(),
		LogDimensions: ciphertext.LogDimensions,
	}, nil
}

func validateCompiledPairAtLevel(name string, pair CompiledPair, level int) error {
	if pair.Low.LevelQ != pair.High.LevelQ {
		return fmt.Errorf("homchain: %s halves have different LevelQ values", name)
	}
	if pair.Low.LevelQ != level {
		return fmt.Errorf("homchain: %s LevelQ=%d, input level=%d", name, pair.Low.LevelQ, level)
	}
	if pair.Low.LogDimensions != pair.High.LogDimensions {
		return fmt.Errorf("homchain: %s halves have different dimensions", name)
	}
	equalScale, err := exactScaleEqual(pair.Low.Scale, pair.High.Scale)
	if err != nil {
		return fmt.Errorf("homchain: %s has invalid plaintext scale metadata: %w", name, err)
	}
	if !equalScale {
		return fmt.Errorf("homchain: %s halves have different exact plaintext scales", name)
	}
	return nil
}

func validateCiphertextPairState(name string, pair CiphertextPair) error {
	if pair[0] == nil || pair[1] == nil {
		return fmt.Errorf("homchain: %s did not produce two dense halves", name)
	}
	if pair[0].Level() != pair[1].Level() {
		return fmt.Errorf("homchain: %s halves have different levels", name)
	}
	equalScale, err := exactScaleEqual(pair[0].Scale, pair[1].Scale)
	if err != nil {
		return fmt.Errorf("homchain: %s has invalid ciphertext scale metadata: %w", name, err)
	}
	if !equalScale {
		return fmt.Errorf("homchain: %s halves have different exact scales", name)
	}
	if pair[0].LogDimensions != pair[1].LogDimensions {
		return fmt.Errorf("homchain: %s halves have different dimensions", name)
	}
	return nil
}

func exactScaleEqual(left, right rlwe.Scale) (bool, error) {
	leftSnapshot, err := NewExactScaleSnapshot(left)
	if err != nil {
		return false, fmt.Errorf("left scale: %w", err)
	}
	rightSnapshot, err := NewExactScaleSnapshot(right)
	if err != nil {
		return false, fmt.Errorf("right scale: %w", err)
	}
	return leftSnapshot.Equal(rightSnapshot), nil
}
