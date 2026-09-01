package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	routeBSigned8Depth2SelectedChildExperimentInputSchema = "lcpdte-route-b-signed8-depth2-selected-child-input-v1"
	RouteBSigned8Depth2SelectedChildAccuracyTolerance     = 5e-4
	RouteBSigned8Depth2SelectedChildExperimentSchema      = "lcpdte-route-b-signed8-depth2-selected-child-experiment-v1"
)

type RouteBCanonicalSigned8Depth2SelectedChildResult struct {
	SchemaVersion  string                                 `json:"schema_version"`
	BuildSpec      ArtifactBuildSpec                      `json:"build_spec"`
	BuildReceipt   RBDFTBuildReceiptReport                `json:"build_receipt"`
	ReadySpec      ReadySpec                              `json:"ready_spec"`
	FirstOperation RouteBFirstOperationReport             `json:"first_operation"`
	SelectedChild  RouteBSigned8Depth2SelectedChildReport `json:"selected_child"`
	BuildRuntime   RuntimeCapacityEvidenceReport          `json:"build_runtime"`
	ReadyRuntime   RuntimeCapacityEvidenceReport          `json:"ready_runtime"`
	InstallRuntime RuntimeCapacityEvidenceReport          `json:"install_runtime"`

	OverallConstructionDelta   [4]uint64 `json:"overall_construction_delta"`
	PostInstallPeakRSSBytes    uint64    `json:"post_install_peak_rss_bytes"`
	PostEvaluationPeakRSSBytes uint64    `json:"post_evaluation_peak_rss_bytes"`
	SetupWallNanoseconds       uint64    `json:"setup_wall_nanoseconds"`
	OnlineWallNanoseconds      uint64    `json:"online_wall_nanoseconds"`
	PostprocessWallNanoseconds uint64    `json:"postprocess_wall_nanoseconds"`
	TotalWallNanoseconds       uint64    `json:"total_wall_nanoseconds"`

	InputQueries       uint32                `json:"input_queries"`
	RootDistinctWords  uint32                `json:"root_distinct_words"`
	OutputSlots        uint32                `json:"output_slots"`
	InputPatternDigest string                `json:"input_pattern_digest"`
	DecodedOutput      []RouteBComplexSample `json:"decoded_output"`

	AccuracyTolerance          float64   `json:"accuracy_tolerance"`
	MaxAbsError                float64   `json:"max_abs_error"`
	MaxImaginaryAbs            float64   `json:"max_imaginary_abs"`
	PathCounts                 [4]uint32 `json:"path_counts"`
	RootEqualityCount          uint32    `json:"root_equality_count"`
	LeftEqualitySelectedCount  uint32    `json:"left_equality_selected_count"`
	RightEqualitySelectedCount uint32    `json:"right_equality_selected_count"`
	MismatchCount              uint64    `json:"mismatch_count"`

	EncryptedChildSelection  bool `json:"encrypted_child_selection"`
	DecryptionsBeforeOutput  int  `json:"decryptions_before_output"`
	PlaintextBranchDecisions int  `json:"plaintext_branch_decisions"`
}

func (result RouteBCanonicalSigned8Depth2SelectedChildResult) Validate() error {
	if result.SchemaVersion != RouteBSigned8Depth2SelectedChildExperimentSchema {
		return lineagef("canonical selected-child experiment schema changed")
	}
	if err := result.BuildSpec.ValidateFrozenSemantics(); err != nil {
		return err
	}
	if err := validateRBDFTBuildReceipt(result.BuildReceipt); err != nil {
		return err
	}
	if err := result.ReadySpec.ValidateFrozenSemantics(); err != nil {
		return err
	}
	if err := result.FirstOperation.Validate(); err != nil {
		return err
	}
	if err := result.SelectedChild.Validate(); err != nil {
		return err
	}
	for operation, evidence := range map[string]RuntimeCapacityEvidenceReport{
		routeBRuntimeOperationBeginBuild:     result.BuildRuntime,
		routeBRuntimeOperationAuthorizeReady: result.ReadyRuntime,
		routeBRuntimeOperationInstall:        result.InstallRuntime,
	} {
		if err := evidence.Validate(); err != nil || evidence.Operation != operation {
			return lineagef("canonical selected-child runtime evidence %q changed", operation)
		}
	}
	capacityPlanIdentity, err := decodeRBAUTHHexDigest("Route-B selected-child capacity plan", result.SelectedChild.CapacityPlanDigest)
	if err != nil {
		return err
	}
	if result.FirstOperation.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8Depth2SelectedChild ||
		result.FirstOperation.RuntimeCapacity.Capacity.CapacityPlanDigest != capacityPlanIdentity ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 4} ||
		result.BuildReceipt.Payload != result.ReadySpec.ActualPayload ||
		result.BuildReceipt.Payload != result.FirstOperation.ResidentPayload ||
		result.BuildReceipt.ArtifactManifestDigest != result.ReadySpec.ArtifactPairManifestDigest ||
		result.BuildReceipt.ArtifactManifestDigest != result.FirstOperation.ArtifactPairManifestDigest ||
		result.BuildReceipt.BuildPeakRSSBytes == 0 || result.PostInstallPeakRSSBytes == 0 ||
		result.PostEvaluationPeakRSSBytes < result.PostInstallPeakRSSBytes || result.SetupWallNanoseconds == 0 ||
		result.OnlineWallNanoseconds == 0 || result.PostprocessWallNanoseconds == 0 || result.TotalWallNanoseconds == 0 {
		return lineagef("canonical selected-child linkage, construction counter, RSS, or timing ledger changed")
	}
	if result.InputQueries != routeBSigned8RootTreeWords || result.RootDistinctWords != 256 ||
		result.OutputSlots != routeBSigned8RootTreeSlots || len(result.DecodedOutput) != routeBSigned8RootTreeSlots ||
		result.InputPatternDigest != routeBSigned8Depth2SelectedChildInputPatternDigest() ||
		result.AccuracyTolerance != RouteBSigned8Depth2SelectedChildAccuracyTolerance ||
		!result.EncryptedChildSelection || result.DecryptionsBeforeOutput != 0 || result.PlaintextBranchDecisions != 0 {
		return lineagef("canonical selected-child input, output, tolerance, or privacy shape changed")
	}
	model, err := reconstructRouteBSigned8Depth2SelectedChildModelReport(result.SelectedChild.Model)
	if err != nil {
		return err
	}
	var ranges [3]homchain.Signed8NoOverflowRange
	for index, rangeReport := range result.SelectedChild.Ranges {
		ranges[index], err = homchain.NewSigned8NoOverflowRange(
			rangeReport.XMinimum, rangeReport.XMaximum, rangeReport.ThresholdMinimum, rangeReport.ThresholdMaximum,
		)
		if err != nil || ranges[index].Digest() != rangeReport.Digest {
			return lineagef("canonical selected-child range %d changed", index)
		}
	}
	features := routeBSigned8Depth2SelectedChildInputFeatures()
	maxError, maxImaginary := 0.0, 0.0
	var paths [4]uint32
	var rootEquality, leftEquality, rightEquality uint32
	var mismatches uint64
	for query := 0; query < routeBSigned8RootTreeWords; query++ {
		values := map[uint32]int64{
			model.featureIDs[0]: features[0][query], model.featureIDs[1]: features[1][query], model.featureIDs[2]: features[2][query],
		}
		want, path, rootBranch, _, oracleErr := routeBSigned8Depth2SelectedChildOracle(values, ranges, model)
		if oracleErr != nil {
			return oracleErr
		}
		paths[path]++
		if features[0][query] == model.thresholds[0] {
			rootEquality++
		}
		if rootBranch == 0 && features[1][query] == model.thresholds[1] {
			leftEquality++
		}
		if rootBranch == 1 && features[2][query] == model.thresholds[2] {
			rightEquality++
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*query + slot
			got := result.DecodedOutput[index]
			if !routeBFiniteFloat(got.Real) || !routeBFiniteFloat(got.Imag) {
				return lineagef("canonical selected-child decoded slot %d is non-finite", index)
			}
			errorMagnitude := math.Abs(got.Real - want)
			imaginary := math.Abs(got.Imag)
			maxError = math.Max(maxError, errorMagnitude)
			maxImaginary = math.Max(maxImaginary, imaginary)
			if errorMagnitude > result.AccuracyTolerance || imaginary > result.AccuracyTolerance {
				mismatches++
			}
		}
	}
	if result.MaxAbsError != maxError || result.MaxImaginaryAbs != maxImaginary || result.PathCounts != paths ||
		result.RootEqualityCount != rootEquality || result.LeftEqualitySelectedCount != leftEquality ||
		result.RightEqualitySelectedCount != rightEquality || result.MismatchCount != mismatches || mismatches != 0 ||
		rootEquality != 2 || leftEquality == 0 || rightEquality == 0 ||
		paths[0] == 0 || paths[1] == 0 || paths[2] == 0 || paths[3] == 0 ||
		maxError > result.AccuracyTolerance || maxImaginary > result.AccuracyTolerance {
		return lineagef(
			"canonical selected-child decoded accuracy, path, or equality ledger changed or failed: stored-error=%g/%g recomputed=%g/%g stored-paths=%v recomputed-paths=%v stored-equality=%d/%d/%d recomputed=%d/%d/%d stored-mismatches=%d recomputed=%d tolerance=%g",
			result.MaxAbsError, result.MaxImaginaryAbs, maxError, maxImaginary,
			result.PathCounts, paths, result.RootEqualityCount, result.LeftEqualitySelectedCount,
			result.RightEqualitySelectedCount, rootEquality, leftEquality, rightEquality,
			result.MismatchCount, mismatches, result.AccuracyTolerance,
		)
	}
	return nil
}

func RunCanonicalRouteBSigned8Depth2SelectedChild() (result RouteBCanonicalSigned8Depth2SelectedChildResult, err error) {
	started := time.Now()
	before := dft.SnapshotMatrixConstructionCounters()
	authority, err := NewRouteBAuthority()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical selected-child create Authority: %w", err)
	}
	releaseRouteBTransientHeap()
	buildSpec, buildPermit, err := authority.AuthorizeBuild()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical selected-child AuthorizeBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	receipt, artifact, err := authority.BeginBuild(buildPermit)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical selected-child BeginBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	readySpec, readyPermit, err := authority.AuthorizeReady(buildPermit, receipt, artifact)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical selected-child AuthorizeReady: %w", err)
	}
	releaseRouteBTransientHeap()
	raw, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		return result, err
	}
	prepared, _, err := prepareGaoN16RouteBTransportParametersFromRaw(raw)
	raw = bootstrapping.Parameters{}
	if err != nil {
		return result, err
	}
	if err = validateGaoN16RouteBPreparedIdentity(prepared); err != nil {
		return result, err
	}
	parameters := prepared.EffectiveParameters().BootstrappingParameters
	keyGenerator := rlwe.NewKeyGenerator(parameters)
	secretKey := keyGenerator.GenSecretKeyNew()
	keyGenerator = nil
	if secretKey == nil {
		return result, lineagef("canonical selected-child secret-key generation returned nil")
	}
	features := routeBSigned8Depth2SelectedChildInputFeatures()
	model, ranges, err := routeBSigned8Depth2SelectedChildCanonicalModelAndRanges()
	if err != nil {
		return result, err
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8RootTreeEncoderPrecision)
	if err != nil {
		return result, err
	}
	encoder := ckks.NewEncoder(parameters, routeBSigned8RootTreeEncoderPrecision)
	encryptor := ckks.NewEncryptor(parameters, secretKey)
	featureVector := make(map[uint32]*rlwe.Ciphertext, 3)
	for role, featureID := range model.featureIDs {
		slots, slotErr := routeBSigned8Depth2SelectedChildFeatureSlots(ringZ, features[role])
		if slotErr != nil {
			return result, slotErr
		}
		plaintext := ckks.NewPlaintext(parameters, parameters.MaxLevel())
		plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
		if slotErr = encoder.Encode(slots, plaintext); slotErr != nil {
			return result, fmt.Errorf("secureeval: encode canonical selected-child feature %d: %w", role, slotErr)
		}
		featureVector[featureID], slotErr = encryptor.EncryptNew(plaintext)
		if slotErr != nil {
			return result, fmt.Errorf("secureeval: encrypt canonical selected-child feature %d: %w", role, slotErr)
		}
	}
	bound, err := BindRouteBSigned8Depth2SelectedChildFeatures(model, featureVector)
	if err != nil {
		return result, err
	}
	featureVector = nil
	ringZ, encoder, encryptor = nil, nil, nil
	releaseRouteBTransientHeap()
	installed, err := authority.Install(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical selected-child Install: %w", err)
	}
	retired := false
	defer func() {
		if !retired {
			retireRouteBInstalledEvaluator(installed)
		}
	}()
	releaseRouteBTransientHeap()
	postInstallPeak, err := sampleProductionProcessPeakRSS()
	if err != nil {
		return result, err
	}
	setupWall := selectedChildNonzeroWall(started)
	onlineStarted := time.Now()
	treeResult, firstOperation, selectedReport, err := installed.RunSigned8Depth2SelectedChildPublic(bound, ranges, model)
	onlineWall := selectedChildNonzeroWall(onlineStarted)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical Route-B selected-child evaluation: %w", err)
	}
	output := treeResult.Ciphertext()
	if output == nil || treeResult.ReportDigest() != selectedReport.Digest {
		return result, lineagef("canonical selected-child output is nil or has foreign provenance")
	}
	postEvaluationPeak, err := sampleProductionProcessPeakRSS()
	if err != nil {
		return result, err
	}
	installRuntime := installed.InstallRuntimeCapacityEvidence()
	retireRouteBInstalledEvaluator(installed)
	retired = true
	installed = nil
	releaseRouteBTransientHeap()
	postStarted := time.Now()
	decoder := ckks.NewEncoder(parameters, routeBSigned8RootTreeEncoderPrecision)
	decryptor := ckks.NewDecryptor(parameters, secretKey)
	values := make([]complex128, routeBSigned8RootTreeSlots)
	outputPlaintext := decryptor.DecryptNew(output)
	output = nil
	if err = decoder.Decode(outputPlaintext, values); err != nil {
		return result, fmt.Errorf("secureeval: decode canonical selected-child output: %w", err)
	}
	decoded := make([]RouteBComplexSample, routeBSigned8RootTreeSlots)
	maxError, maxImaginary := 0.0, 0.0
	var paths [4]uint32
	var rootEquality, leftEquality, rightEquality uint32
	var mismatches uint64
	for query := 0; query < routeBSigned8RootTreeWords; query++ {
		featureValues := map[uint32]int64{
			model.featureIDs[0]: features[0][query], model.featureIDs[1]: features[1][query], model.featureIDs[2]: features[2][query],
		}
		want, path, rootBranch, _, oracleErr := routeBSigned8Depth2SelectedChildOracle(featureValues, ranges, model)
		if oracleErr != nil {
			return result, oracleErr
		}
		paths[path]++
		if features[0][query] == model.thresholds[0] {
			rootEquality++
		}
		if rootBranch == 0 && features[1][query] == model.thresholds[1] {
			leftEquality++
		}
		if rootBranch == 1 && features[2][query] == model.thresholds[2] {
			rightEquality++
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*query + slot
			value := values[index]
			decoded[index] = RouteBComplexSample{Real: real(value), Imag: imag(value)}
			errorMagnitude := math.Abs(real(value) - want)
			imaginary := math.Abs(imag(value))
			maxError = math.Max(maxError, errorMagnitude)
			maxImaginary = math.Max(maxImaginary, imaginary)
			if errorMagnitude > RouteBSigned8Depth2SelectedChildAccuracyTolerance || imaginary > RouteBSigned8Depth2SelectedChildAccuracyTolerance {
				mismatches++
			}
		}
	}
	postprocessWall := selectedChildNonzeroWall(postStarted)
	secretKey = nil
	prepared = bootstrapping.PreparedParameters{}
	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil {
		return result, err
	}
	result = RouteBCanonicalSigned8Depth2SelectedChildResult{
		SchemaVersion: RouteBSigned8Depth2SelectedChildExperimentSchema,
		BuildSpec:     buildSpec, BuildReceipt: receipt.Report(), ReadySpec: readySpec,
		FirstOperation: firstOperation, SelectedChild: selectedReport,
		BuildRuntime: receipt.RuntimeCapacityEvidence(), ReadyRuntime: readyPermit.RuntimeCapacityEvidence(), InstallRuntime: installRuntime,
		OverallConstructionDelta: [4]uint64{delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming()},
		PostInstallPeakRSSBytes:  postInstallPeak, PostEvaluationPeakRSSBytes: postEvaluationPeak,
		SetupWallNanoseconds: setupWall, OnlineWallNanoseconds: onlineWall,
		PostprocessWallNanoseconds: postprocessWall, TotalWallNanoseconds: selectedChildNonzeroWall(started),
		InputQueries: routeBSigned8RootTreeWords, RootDistinctWords: 256, OutputSlots: routeBSigned8RootTreeSlots,
		InputPatternDigest: routeBSigned8Depth2SelectedChildInputPatternDigest(), DecodedOutput: decoded,
		AccuracyTolerance: RouteBSigned8Depth2SelectedChildAccuracyTolerance,
		MaxAbsError:       maxError, MaxImaginaryAbs: maxImaginary, PathCounts: paths,
		RootEqualityCount: rootEquality, LeftEqualitySelectedCount: leftEquality,
		RightEqualitySelectedCount: rightEquality, MismatchCount: mismatches,
		EncryptedChildSelection: true, DecryptionsBeforeOutput: 0, PlaintextBranchDecisions: 0,
	}
	if err = result.Validate(); err != nil {
		return RouteBCanonicalSigned8Depth2SelectedChildResult{}, err
	}
	return result, nil
}

func routeBSigned8Depth2SelectedChildCanonicalModelAndRanges() (
	RouteBSigned8Depth2SelectedChildModel,
	[3]homchain.Signed8NoOverflowRange,
	error,
) {
	model, err := NewRouteBSigned8Depth2SelectedChildModel(
		[3]uint32{0, 1, 2}, [3]int64{0, -4, 3}, [4]float64{-1.25, 2.5, -3.75, 5},
	)
	if err != nil {
		return RouteBSigned8Depth2SelectedChildModel{}, [3]homchain.Signed8NoOverflowRange{}, err
	}
	tuples := [3][4]int64{{-128, 127, 0, 0}, {-128, 123, -4, -4}, {-125, 127, 3, 3}}
	var ranges [3]homchain.Signed8NoOverflowRange
	for index, tuple := range tuples {
		ranges[index], err = homchain.NewSigned8NoOverflowRange(tuple[0], tuple[1], tuple[2], tuple[3])
		if err != nil {
			return RouteBSigned8Depth2SelectedChildModel{}, [3]homchain.Signed8NoOverflowRange{}, err
		}
	}
	return model, ranges, nil
}

func routeBSigned8Depth2SelectedChildInputFeatures() [3][]int64 {
	result := [3][]int64{
		make([]int64, 0, routeBSigned8RootTreeWords),
		make([]int64, routeBSigned8RootTreeWords),
		make([]int64, routeBSigned8RootTreeWords),
	}
	remaining := make(map[int64]int, 256)
	for value := int64(-128); value <= 127; value++ {
		remaining[value] = 2
	}
	for _, value := range []int64{-1, -1, 0, 0} {
		result[0] = append(result[0], value)
		remaining[value]--
	}
	for value := int64(-128); value <= 127; value++ {
		for count := 0; count < remaining[value]; count++ {
			result[0] = append(result[0], value)
		}
	}
	for query := 0; query < routeBSigned8RootTreeWords; query++ {
		result[1][query] = -128 + int64(query%252)
		result[2][query] = -125 + int64(query%253)
	}
	result[1][0], result[2][0] = -5, 3
	result[1][1], result[2][1] = -4, 2
	result[1][2], result[2][2] = -5, 2
	result[1][3], result[2][3] = -5, 3
	return result
}

func routeBSigned8Depth2SelectedChildFeatureSlots(
	ringZ *z2n.Ring,
	words []int64,
) ([]*bignum.Complex, error) {
	if ringZ == nil || len(words) != routeBSigned8RootTreeWords {
		return nil, lineagef("canonical selected-child feature source shape changed")
	}
	values := make([]*bignum.Complex, 0, routeBSigned8RootTreeSlots)
	for index, value := range words {
		if value < -128 || value > 127 {
			return nil, lineagef("canonical selected-child feature word %d lies outside signed int8", index)
		}
		block, err := ringZ.ToRootSlots(ringZ.ArithmeticEncode(uint64(uint8(value))))
		if err != nil {
			return nil, fmt.Errorf("secureeval: encode canonical selected-child feature word %d: %w", index, err)
		}
		values = append(values, block...)
	}
	return values, nil
}

func routeBSigned8Depth2SelectedChildInputPatternDigest() string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBSigned8Depth2SelectedChildExperimentInputSchema + "\x00"))
	features := routeBSigned8Depth2SelectedChildInputFeatures()
	var record [32]byte
	for query := 0; query < routeBSigned8RootTreeWords; query++ {
		binary.LittleEndian.PutUint64(record[0:8], uint64(query))
		for role := 0; role < 3; role++ {
			binary.LittleEndian.PutUint64(record[8+8*role:16+8*role], uint64(features[role][query]))
		}
		_, _ = hasher.Write(record[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
