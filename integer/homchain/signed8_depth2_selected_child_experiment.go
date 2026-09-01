package homchain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"runtime"
	"time"

	"dt_go/integer/treeplan"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	Signed8Depth2SelectedChildExperimentSchema    = "lcpdte-signed8-depth2-selected-child-experiment-v1"
	Signed8Depth2SelectedChildExperimentTolerance = 1e-3
)

type Signed8Depth2SelectedChildComplexSample struct {
	Real float64 `json:"real"`
	Imag float64 `json:"imag"`
}

type Signed8Depth2SelectedChildTimingReport struct {
	SetupNanoseconds                  int64 `json:"setup_nanoseconds"`
	RootComparatorNanoseconds         int64 `json:"root_comparator_nanoseconds"`
	RootSelectorNanoseconds           int64 `json:"root_selector_nanoseconds"`
	SourcePrefixNanoseconds           int64 `json:"source_prefix_nanoseconds"`
	ChildComparatorNanoseconds        int64 `json:"child_comparator_nanoseconds"`
	TerminalNanoseconds               int64 `json:"terminal_nanoseconds"`
	OnlineNanoseconds                 int64 `json:"online_nanoseconds"`
	PostOnlineVerificationNanoseconds int64 `json:"post_online_verification_nanoseconds"`
	LifecycleNanoseconds              int64 `json:"lifecycle_nanoseconds"`
}

func (r Signed8Depth2SelectedChildTimingReport) StageSum() int64 {
	return r.RootComparatorNanoseconds + r.RootSelectorNanoseconds + r.SourcePrefixNanoseconds +
		r.ChildComparatorNanoseconds + r.TerminalNanoseconds
}

type Signed8Depth2SelectedChildOperationReport struct {
	RootWrapper     Signed8ComparatorWrapperOperationCounts         `json:"root_wrapper"`
	RootSelector    SelectorReraiseDecodeOperationCounts            `json:"root_selector"`
	SourcePrefix    Signed8Depth2SourcePrefixOperationCounts        `json:"source_prefix"`
	ChildComparator Signed8Depth2ChildComparatorOperationCounts     `json:"child_comparator"`
	ChildDecoder    Signed8Depth2ChildSelectorDecodeOperationCounts `json:"child_decoder"`
	TerminalMux     Signed8Depth2TerminalLeafOperationCounts        `json:"terminal_mux"`
}

// Signed8Depth2SelectedChildExperimentResult is a bounded, replayable record
// of one complete functional-profile lifecycle. It intentionally excludes
// secret material and does not carry a security or speedup label.
type Signed8Depth2SelectedChildExperimentResult struct {
	SchemaVersion string `json:"schema_version"`
	Fidelity      string `json:"fidelity"`
	GoVersion     string `json:"go_version"`
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`

	LogN            int `json:"log_n"`
	LogMaxSlots     int `json:"log_max_slots"`
	MaxLevel        int `json:"max_level"`
	LogDefaultScale int `json:"log_default_scale"`

	ParameterDigest        string   `json:"parameter_digest"`
	RangeDigest            string   `json:"range_digest"`
	TreeDigest             string   `json:"tree_digest"`
	ScheduleDigest         string   `json:"schedule_digest"`
	ProfileDigest          string   `json:"profile_digest"`
	KeyProfileDigest       string   `json:"key_profile_digest"`
	RequiredGaloisElements []uint64 `json:"required_galois_elements"`

	Tree               treeplan.BinaryTree[int8, float64]        `json:"tree"`
	FeatureIDs         [3]int                                    `json:"feature_ids"`
	InputWords         [3][4]int64                               `json:"input_words"`
	InputPatternDigest string                                    `json:"input_pattern_digest"`
	ExpectedPaths      [4]int                                    `json:"expected_paths"`
	ExpectedLeaves     [4]float64                                `json:"expected_leaves"`
	DecodedOutput      []Signed8Depth2SelectedChildComplexSample `json:"decoded_output"`

	RootOperandMode     Signed8ComparatorOperandMode `json:"root_operand_mode"`
	ChildOperandKind    string                       `json:"child_operand_kind"`
	ResultDigest        string                       `json:"result_provenance_digest"`
	TraceDigest         string                       `json:"trace_digest"`
	LinkageDigest       string                       `json:"linkage_digest"`
	OutputPayloadDigest string                       `json:"output_payload_digest"`

	Operations            Signed8Depth2SelectedChildOperationReport `json:"operations"`
	Bytes                 Signed8Depth2SelectedChildByteLedger      `json:"bytes"`
	ModuleReportedByteSum int                                       `json:"module_reported_byte_sum"`
	Timing                Signed8Depth2SelectedChildTimingReport    `json:"timing"`

	CertificateTolerance float64 `json:"certificate_tolerance"`
	AcceptanceTolerance  float64 `json:"acceptance_tolerance"`
	MaxRealAbsError      float64 `json:"max_real_abs_error"`
	MaxImaginaryAbs      float64 `json:"max_imaginary_abs"`
	MismatchCount        int     `json:"mismatch_count"`
	Digest               string  `json:"digest"`
}

func (r Signed8Depth2SelectedChildExperimentResult) Validate() error {
	if r.SchemaVersion != Signed8Depth2SelectedChildExperimentSchema ||
		r.Fidelity != string(Signed8Depth2SelectedChildFunctionalNotSecure) ||
		r.GOOS == "" || r.GOARCH == "" || r.GoVersion == "" ||
		r.LogN != 5 || r.LogMaxSlots != 4 || r.MaxLevel != 20 || r.LogDefaultScale != 35 {
		return fmt.Errorf("homchain: selected-child experiment schema, environment, or functional parameter shape changed")
	}
	for name, digest := range map[string]string{
		"parameters": r.ParameterDigest, "range": r.RangeDigest, "tree": r.TreeDigest,
		"schedule": r.ScheduleDigest, "profile": r.ProfileDigest, "keys": r.KeyProfileDigest,
		"input": r.InputPatternDigest, "result": r.ResultDigest, "trace": r.TraceDigest,
		"linkage": r.LinkageDigest, "output": r.OutputPayloadDigest, "record": r.Digest,
	} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 {
			return fmt.Errorf("homchain: selected-child experiment %s digest is not SHA-256", name)
		}
	}
	canonicalTree := signed8Depth2SelectedChildExperimentTree()
	canonicalInputs := signed8Depth2SelectedChildExperimentInputs()
	if !reflectSelectedChildTreesEqual(r.Tree, canonicalTree) || r.FeatureIDs != [3]int{0, 1, 2} ||
		r.InputWords != canonicalInputs || r.InputPatternDigest != digestSigned8Depth2SelectedChildExperimentInput(canonicalTree, canonicalInputs) ||
		r.RootOperandMode != Signed8PublicThresholdCTPT || r.ChildOperandKind != "selected-feature-minus-selected-threshold-ct-ct" ||
		len(r.RequiredGaloisElements) != 7 || !equalSelectedChildUint64Slices(r.RequiredGaloisElements, []uint64{5, 17, 25, 33, 41, 49, 63}) {
		return fmt.Errorf("homchain: selected-child experiment model, input, operand schedule, or key inventory changed")
	}
	if err := r.Tree.Validate(); err != nil {
		return err
	}
	if len(r.DecodedOutput) != signed8Slots || r.AcceptanceTolerance != Signed8Depth2SelectedChildExperimentTolerance ||
		!finiteSelectedChildFloat(r.CertificateTolerance) || r.CertificateTolerance <= 0 ||
		r.CertificateTolerance < r.AcceptanceTolerance {
		return fmt.Errorf("homchain: selected-child experiment output shape or tolerance changed")
	}
	var expectedPaths [4]int
	var expectedLeaves [4]float64
	maxReal, maxImaginary := 0.0, 0.0
	mismatches := 0
	for word := 0; word < signed8Words; word++ {
		features := []int8{int8(r.InputWords[0][word]), int8(r.InputWords[1][word]), int8(r.InputWords[2][word])}
		path, err := r.Tree.Route(features)
		if err != nil {
			return err
		}
		leaf, err := r.Tree.Evaluate(features)
		if err != nil {
			return err
		}
		expectedPaths[word], expectedLeaves[word] = path, leaf
		for slot := 4 * word; slot < 4*(word+1); slot++ {
			sample := r.DecodedOutput[slot]
			if !finiteSelectedChildFloat(sample.Real) || !finiteSelectedChildFloat(sample.Imag) {
				return fmt.Errorf("homchain: selected-child decoded slot %d is non-finite", slot)
			}
			realError := math.Abs(sample.Real - leaf)
			imagError := math.Abs(sample.Imag)
			maxReal = math.Max(maxReal, realError)
			maxImaginary = math.Max(maxImaginary, imagError)
			if realError > r.AcceptanceTolerance || imagError > r.AcceptanceTolerance {
				mismatches++
			}
		}
	}
	if expectedPaths != [4]int{0, 1, 2, 3} || r.ExpectedPaths != expectedPaths || r.ExpectedLeaves != expectedLeaves ||
		r.MaxRealAbsError != maxReal || r.MaxImaginaryAbs != maxImaginary || r.MismatchCount != mismatches ||
		mismatches != 0 || maxReal > r.AcceptanceTolerance || maxImaginary > r.AcceptanceTolerance {
		return fmt.Errorf("homchain: selected-child experiment oracle or accuracy ledger changed")
	}
	if r.Operations.RootWrapper.CiphertextPlaintextSubtractions != 1 ||
		r.Operations.RootWrapper.CiphertextCiphertextSubtractions != 0 ||
		r.Operations.ChildComparator.CiphertextCiphertextSubtractions != 1 ||
		r.Operations.ChildComparator.IngressInvocations != 1 ||
		r.Operations.ChildDecoder.LinearTransformations != 7 ||
		r.Operations.TerminalMux.CiphertextCiphertextMultiplications != 1 {
		return fmt.Errorf("homchain: selected-child experiment operation schedule changed")
	}
	if r.Bytes.TerminalComposedUnique != 106662 || r.ModuleReportedByteSum != r.Bytes.ModuleReportedSum() ||
		r.ModuleReportedByteSum <= 0 || r.Timing.SetupNanoseconds <= 0 || r.Timing.OnlineNanoseconds <= 0 ||
		r.Timing.PostOnlineVerificationNanoseconds <= 0 ||
		r.Timing.LifecycleNanoseconds != r.Timing.SetupNanoseconds+r.Timing.OnlineNanoseconds+
			r.Timing.PostOnlineVerificationNanoseconds ||
		r.Timing.StageSum() <= 0 || r.Timing.StageSum() > r.Timing.OnlineNanoseconds {
		return fmt.Errorf("homchain: selected-child experiment byte or timing ledger changed")
	}
	wantDigest, err := digestSigned8Depth2SelectedChildExperimentResult(r)
	if err != nil || r.Digest != wantDigest {
		return fmt.Errorf("homchain: selected-child experiment record digest changed: %v", err)
	}
	return nil
}

func RunSigned8Depth2SelectedChildExperiment() (result Signed8Depth2SelectedChildExperimentResult, err error) {
	lifecycleStarted := time.Now()
	params, err := GaoA2BKernelFunctionalParameters()
	if err != nil {
		return result, err
	}
	ranges, err := NewSigned8NoOverflowRange(-8, 7, -8, 7)
	if err != nil {
		return result, err
	}
	refreshEncoder := ckks.NewEncoder(params, signed8RefreshEncoderPrecision)
	integerEncoder := ckks.NewEncoder(params, signed8IntegerEncoderPrecision)
	comparator, err := NewSigned8ComparatorCircuit(params, refreshEncoder, integerEncoder, ranges)
	if err != nil {
		return result, err
	}
	tree := signed8Depth2SelectedChildExperimentTree()
	circuit, err := NewSigned8Depth2SelectedChildCircuit(comparator, tree)
	if err != nil {
		return result, err
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	keyProfile := circuit.terminal.RequiredKeyProfile()
	evaluationKeys := &bootstrapping.EvaluationKeys{MemEvaluationKeySet: rlwe.NewMemEvaluationKeySet(
		keyGenerator.GenRelinearizationKeyNew(secretKey),
		keyGenerator.GenGaloisKeysNew(keyProfile.All(), secretKey)...,
	)}
	dftProfile := comparator.a2b.refresh.Profile().DFT()
	bootstrapParameters := bootstrapping.Parameters{
		ResidualParameters: params, BootstrappingParameters: params,
		SlotsToCoeffsParameters: dftProfile.SlotsToCoeffsLiteral(),
		CoeffsToSlotsParameters: dftProfile.CoeffsToSlotsLiteral(),
		Mod1ParametersLiteral: mod1.ParametersLiteral{
			LevelQ: dftProfile.CoeffsToSlotsLiteral().LevelQ - 3, LogScale: params.LogDefaultScale(),
			Mod1Type: mod1.SinContinuous, LogMessageRatio: 15, K: 1, Mod1Degree: 3,
		},
		CircuitOrder: bootstrapping.Custom,
	}
	source, err := bootstrapping.NewEvaluator(bootstrapParameters, evaluationKeys)
	if err != nil {
		return result, err
	}
	evaluator, err := circuit.BindEvaluator(source)
	if err != nil {
		return result, err
	}
	encryptor := ckks.NewEncryptor(params, secretKey)
	decryptor := ckks.NewDecryptor(params, secretKey)
	inputWords := signed8Depth2SelectedChildExperimentInputs()
	ciphertexts := make([]*rlwe.Ciphertext, len(inputWords))
	for feature := range inputWords {
		var residues [signed8Words]uint64
		for word, value := range inputWords[feature] {
			residues[word] = uint64(value) & 0xff
		}
		plaintext, encodeErr := newSigned8WordPlaintext(
			params, refreshEncoder, signed8RefreshEncoderPrecision, signed8InputLevel, residues,
		)
		if encodeErr != nil {
			return result, encodeErr
		}
		ciphertexts[feature], err = encryptor.EncryptNew(plaintext)
		if err != nil {
			return result, err
		}
	}
	input, err := circuit.BindCiphertexts(ciphertexts, params)
	if err != nil {
		return result, err
	}
	setupWall := time.Since(lifecycleStarted)
	selectedResult, trace, err := evaluator.EvaluatePublicNew(input)
	if err != nil {
		return result, err
	}
	if err = circuit.validateTrace(input, selectedResult, trace); err != nil {
		return result, err
	}
	decoded := make([]complex128, signed8Slots)
	if err = integerEncoder.Decode(decryptor.DecryptNew(selectedResult.Ciphertext()), decoded); err != nil {
		return result, err
	}
	samples := make([]Signed8Depth2SelectedChildComplexSample, len(decoded))
	var expectedPaths [4]int
	var expectedLeaves [4]float64
	maxReal, maxImaginary := 0.0, 0.0
	mismatches := 0
	for word := 0; word < signed8Words; word++ {
		features := []int8{int8(inputWords[0][word]), int8(inputWords[1][word]), int8(inputWords[2][word])}
		expectedPaths[word], err = tree.Route(features)
		if err != nil {
			return result, err
		}
		expectedLeaves[word], err = tree.Evaluate(features)
		if err != nil {
			return result, err
		}
		for slot := 4 * word; slot < 4*(word+1); slot++ {
			samples[slot] = Signed8Depth2SelectedChildComplexSample{Real: real(decoded[slot]), Imag: imag(decoded[slot])}
			realError := math.Abs(samples[slot].Real - expectedLeaves[word])
			imagError := math.Abs(samples[slot].Imag)
			maxReal = math.Max(maxReal, realError)
			maxImaginary = math.Max(maxImaginary, imagError)
			if realError > Signed8Depth2SelectedChildExperimentTolerance || imagError > Signed8Depth2SelectedChildExperimentTolerance {
				mismatches++
			}
		}
	}
	stage := trace.StageDurations()
	terminalTrace := trace.TerminalTrace()
	profile := circuit.Profile()
	certificateTolerance := circuit.terminal.Profile().MagnitudeCertificate().OutputToleranceFloat64Up()
	lifecycleWall := time.Since(lifecycleStarted)
	postOnlineVerification := lifecycleWall - setupWall - trace.WallTime()
	result = Signed8Depth2SelectedChildExperimentResult{
		SchemaVersion: Signed8Depth2SelectedChildExperimentSchema,
		Fidelity:      string(profile.Fidelity()), GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		LogN: params.LogN(), LogMaxSlots: params.LogMaxSlots(), MaxLevel: params.MaxLevel(), LogDefaultScale: params.LogDefaultScale(),
		ParameterDigest: profile.ParameterDigest(), RangeDigest: profile.RangeDigest(), TreeDigest: profile.TreeDigest(),
		ScheduleDigest: profile.ScheduleDigest(), ProfileDigest: profile.Digest(), KeyProfileDigest: keyProfile.Digest(),
		RequiredGaloisElements: keyProfile.All(), Tree: profile.Tree(), FeatureIDs: profile.FeatureIDs(),
		InputWords: inputWords, InputPatternDigest: digestSigned8Depth2SelectedChildExperimentInput(tree, inputWords),
		ExpectedPaths: expectedPaths, ExpectedLeaves: expectedLeaves, DecodedOutput: samples,
		RootOperandMode:  trace.RootComparatorTrace().OperandMode(),
		ChildOperandKind: "selected-feature-minus-selected-threshold-ct-ct",
		ResultDigest:     selectedResult.ProvenanceDigest(), TraceDigest: trace.Digest(),
		LinkageDigest: trace.Linkage().Digest(), OutputPayloadDigest: selectedResult.OutputPayloadDigest(),
		Operations: Signed8Depth2SelectedChildOperationReport{
			RootWrapper:  trace.RootComparatorTrace().WrapperOperationCounts(),
			RootSelector: trace.RootSelectorTrace().OperationCounts(), SourcePrefix: trace.SourcePrefixTrace().OperationCounts(),
			ChildComparator: trace.ChildComparatorTrace().OperationCounts(),
			ChildDecoder:    terminalTrace.DecoderTrace().OperationCounts(), TerminalMux: terminalTrace.OperationCounts(),
		},
		Bytes: trace.ByteLedger(), ModuleReportedByteSum: trace.ByteLedger().ModuleReportedSum(),
		Timing: Signed8Depth2SelectedChildTimingReport{
			SetupNanoseconds: setupWall.Nanoseconds(), RootComparatorNanoseconds: stage.RootComparator.Nanoseconds(),
			RootSelectorNanoseconds: stage.RootSelector.Nanoseconds(), SourcePrefixNanoseconds: stage.SourcePrefix.Nanoseconds(),
			ChildComparatorNanoseconds: stage.ChildComparator.Nanoseconds(), TerminalNanoseconds: stage.Terminal.Nanoseconds(),
			OnlineNanoseconds:                 trace.WallTime().Nanoseconds(),
			PostOnlineVerificationNanoseconds: postOnlineVerification.Nanoseconds(),
			LifecycleNanoseconds:              lifecycleWall.Nanoseconds(),
		},
		CertificateTolerance: certificateTolerance,
		AcceptanceTolerance:  Signed8Depth2SelectedChildExperimentTolerance,
		MaxRealAbsError:      maxReal, MaxImaginaryAbs: maxImaginary, MismatchCount: mismatches,
	}
	result.Digest, err = digestSigned8Depth2SelectedChildExperimentResult(result)
	if err != nil {
		return Signed8Depth2SelectedChildExperimentResult{}, err
	}
	if err = result.Validate(); err != nil {
		return Signed8Depth2SelectedChildExperimentResult{}, err
	}
	return result, nil
}

func signed8Depth2SelectedChildExperimentTree() treeplan.BinaryTree[int8, float64] {
	return treeplan.BinaryTree[int8, float64]{
		Depth: 2,
		Splits: []treeplan.BinarySplit[int8]{
			{Feature: 0, Threshold: 0}, {Feature: 1, Threshold: -4}, {Feature: 2, Threshold: 3},
		},
		Leaves: []float64{-1.25, 2.5, -3.75, 5},
	}
}

func signed8Depth2SelectedChildExperimentInputs() [3][4]int64 {
	return [3][4]int64{{-1, -1, 1, 1}, {-5, -4, 0, 0}, {0, 0, 2, 3}}
}

func digestSigned8Depth2SelectedChildExperimentInput(
	tree treeplan.BinaryTree[int8, float64],
	inputs [3][4]int64,
) string {
	return digestString(fmt.Sprintf("selected-child-experiment-input-v1|tree=%v|inputs=%v", tree, inputs))
}

func digestSigned8Depth2SelectedChildExperimentResult(result Signed8Depth2SelectedChildExperimentResult) (string, error) {
	copyResult := result
	copyResult.Digest = ""
	encoded, err := json.Marshal(copyResult)
	if err != nil {
		return "", err
	}
	return digestString(string(encoded)), nil
}

func reflectSelectedChildTreesEqual(left, right treeplan.BinaryTree[int8, float64]) bool {
	if left.Depth != right.Depth || len(left.Splits) != len(right.Splits) || len(left.Leaves) != len(right.Leaves) {
		return false
	}
	for index := range left.Splits {
		if left.Splits[index] != right.Splits[index] {
			return false
		}
	}
	for index := range left.Leaves {
		if left.Leaves[index] != right.Leaves[index] {
			return false
		}
	}
	return true
}

func finiteSelectedChildFloat(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func equalSelectedChildUint64Slices(left, right []uint64) bool {
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
