package secureeval

import (
	"fmt"
	"math"
	"time"

	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const RouteBSigned8Radix4AccuracyTolerance = 5e-4

type RouteBCanonicalSigned8Radix4Result struct {
	BuildSpec      ArtifactBuildSpec             `json:"build_spec"`
	BuildReceipt   RBDFTBuildReceiptReport       `json:"build_receipt"`
	ReadySpec      ReadySpec                     `json:"ready_spec"`
	FirstOperation RouteBFirstOperationReport    `json:"first_operation"`
	Radix4         RouteBSigned8Radix4Report     `json:"radix4"`
	BuildRuntime   RuntimeCapacityEvidenceReport `json:"build_runtime"`
	ReadyRuntime   RuntimeCapacityEvidenceReport `json:"ready_runtime"`
	InstallRuntime RuntimeCapacityEvidenceReport `json:"install_runtime"`

	OverallConstructionDelta [4]uint64 `json:"overall_construction_delta"`
	PostInstallPeakRSSBytes  uint64    `json:"post_install_peak_rss_bytes"`
	PostRadixPeakRSSBytes    uint64    `json:"post_radix_peak_rss_bytes"`
	TotalWallNanoseconds     uint64    `json:"total_wall_nanoseconds"`

	QueryCount          uint32 `json:"query_count"`
	InputWords          uint32 `json:"input_words"`
	PaddingWords        uint32 `json:"padding_words"`
	OutputSlots         uint32 `json:"output_slots"`
	ActiveOutputSlots   uint32 `json:"active_output_slots"`
	InactiveOutputSlots uint32 `json:"inactive_output_slots"`
	InputPatternDigest  string `json:"input_pattern_digest"`

	ApplicationSecurityProfileDigest string `json:"application_security_profile_digest"`
	SecurityInheritance              string `json:"security_inheritance"`
	DecryptionsBeforeOutput          uint32 `json:"decryptions_before_output"`
	PlaintextBranchDecisions         uint32 `json:"plaintext_branch_decisions"`
	InputCiphertextSerializedBytes   uint64 `json:"input_ciphertext_serialized_bytes,omitempty"`
	OutputCiphertextSerializedBytes  uint64 `json:"output_ciphertext_serialized_bytes,omitempty"`
	EvaluationKeySerializedBytes     uint64 `json:"evaluation_key_serialized_bytes,omitempty"`
	DFTArtifactEncodedBytes          uint64 `json:"dft_artifact_encoded_bytes,omitempty"`

	DecodedOutput []RouteBComplexSample `json:"decoded_output"`

	AccuracyTolerance              float64   `json:"accuracy_tolerance"`
	MaxActiveAbsError              float64   `json:"max_active_abs_error"`
	MaxInactiveAbs                 float64   `json:"max_inactive_abs"`
	MaxImaginaryAbs                float64   `json:"max_imaginary_abs"`
	PathCounts                     [4]uint32 `json:"path_counts"`
	EqualityCounts                 [3]uint32 `json:"equality_counts"`
	ActiveMismatchCount            uint64    `json:"active_mismatch_count"`
	InactiveMismatchCount          uint64    `json:"inactive_mismatch_count"`
	BinaryEquivalenceMismatchCount uint64    `json:"binary_equivalence_mismatch_count"`
}

func (result RouteBCanonicalSigned8Radix4Result) Validate() error {
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
	if err := result.Radix4.Validate(); err != nil {
		return err
	}
	for operation, evidence := range map[string]RuntimeCapacityEvidenceReport{
		routeBRuntimeOperationBeginBuild:     result.BuildRuntime,
		routeBRuntimeOperationAuthorizeReady: result.ReadyRuntime,
		routeBRuntimeOperationInstall:        result.InstallRuntime,
	} {
		if err := evidence.Validate(); err != nil || evidence.Operation != operation {
			return lineagef("canonical signed8 radix-4 runtime evidence %q changed", operation)
		}
	}
	capacityIdentity, err := decodeRBAUTHHexDigest("Route-B signed8 radix-4 capacity plan", result.Radix4.CapacityPlanDigest)
	if err != nil {
		return err
	}
	if result.FirstOperation.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8Radix4Node ||
		result.FirstOperation.RuntimeCapacity.Capacity.CapacityPlanDigest != capacityIdentity ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 3} ||
		result.BuildReceipt.Payload != result.ReadySpec.ActualPayload ||
		result.BuildReceipt.Payload != result.FirstOperation.ResidentPayload ||
		result.BuildReceipt.ArtifactManifestDigest != result.ReadySpec.ArtifactPairManifestDigest ||
		result.BuildReceipt.ArtifactManifestDigest != result.FirstOperation.ArtifactPairManifestDigest ||
		result.BuildReceipt.BuildPeakRSSBytes == 0 || result.PostInstallPeakRSSBytes == 0 ||
		result.PostRadixPeakRSSBytes < result.PostInstallPeakRSSBytes || result.TotalWallNanoseconds == 0 {
		return lineagef("canonical signed8 radix-4 linkage, construction counter, RSS, or wall-time changed")
	}
	if result.QueryCount != routeBSigned8Radix4Queries || result.InputWords != routeBSigned8Radix4Words ||
		result.PaddingWords != routeBSigned8Radix4PaddingWords || result.OutputSlots != routeBSigned8Radix4Slots ||
		result.ActiveOutputSlots != 4*routeBSigned8Radix4Queries ||
		result.InactiveOutputSlots != routeBSigned8Radix4Slots-4*routeBSigned8Radix4Queries ||
		result.InputPatternDigest != routeBSigned8Radix4ExpectedInputDigest ||
		len(result.DecodedOutput) != routeBSigned8Radix4Slots || result.AccuracyTolerance != RouteBSigned8Radix4AccuracyTolerance {
		return lineagef("canonical signed8 radix-4 input, output, or tolerance shape changed")
	}
	if result.ApplicationSecurityProfileDigest != routeBApplicationSecurityProfileDigest ||
		result.SecurityInheritance != "same_parameter_and_41_evaluation_key_schedule;one_fresh_input_sample_is_a_subset_of_C75_three" ||
		result.DecryptionsBeforeOutput != 0 || result.PlaintextBranchDecisions != 0 {
		return lineagef("canonical signed8 radix-4 security binding or no-decryption ledger changed")
	}
	if err := validateRouteBSerializedSizeEvidence(
		result.InputCiphertextSerializedBytes, result.OutputCiphertextSerializedBytes,
		result.EvaluationKeySerializedBytes, result.DFTArtifactEncodedBytes, result.BuildReceipt,
	); err != nil {
		return err
	}
	ranges, model, err := reconstructRouteBSigned8Radix4Inputs(result.Radix4.Ranges, result.Radix4.Model)
	if err != nil {
		return err
	}
	_, _, binaryModel, binaryRanges, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		return err
	}
	values := routeBSigned8Radix4InputValues()
	maxActive, maxInactive, maxImaginary := 0.0, 0.0, 0.0
	var pathCounts [4]uint32
	var equalityCounts [3]uint32
	var activeMismatches, inactiveMismatches, binaryMismatches uint64
	for query, feature := range values {
		want, path, _, oracleErr := routeBSigned8Radix4Oracle(feature, ranges, model)
		if oracleErr != nil {
			return oracleErr
		}
		binaryWant, binaryPath, _, binaryErr := routeBSigned8Depth2NodeBatchOracle(
			[3]int64{feature, feature, feature}, binaryRanges, binaryModel,
		)
		if binaryErr != nil {
			return binaryErr
		}
		if path != binaryPath || math.Float64bits(want) != math.Float64bits(binaryWant) {
			binaryMismatches++
		}
		pathCounts[path]++
		for index, threshold := range model.thresholds {
			if feature == threshold {
				equalityCounts[index]++
			}
		}
		rootWord := routeBSigned8Radix4WordsPerQuery * query
		for slot := 0; slot < 4; slot++ {
			index := 4*rootWord + slot
			got := result.DecodedOutput[index]
			if !routeBFiniteFloat(got.Real) || !routeBFiniteFloat(got.Imag) {
				return lineagef("canonical signed8 radix-4 active slot %d is non-finite", index)
			}
			errorMagnitude := math.Abs(got.Real - want)
			maxActive = math.Max(maxActive, errorMagnitude)
			maxImaginary = math.Max(maxImaginary, math.Abs(got.Imag))
			if errorMagnitude > result.AccuracyTolerance || math.Abs(got.Imag) > result.AccuracyTolerance {
				activeMismatches++
			}
		}
	}
	for word := 0; word < routeBSigned8Radix4Words; word++ {
		if word%3 == 0 && word < 3*routeBSigned8Radix4Queries {
			continue
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*word + slot
			got := result.DecodedOutput[index]
			if !routeBFiniteFloat(got.Real) || !routeBFiniteFloat(got.Imag) {
				return lineagef("canonical signed8 radix-4 inactive slot %d is non-finite", index)
			}
			maxInactive = math.Max(maxInactive, math.Abs(got.Real))
			maxImaginary = math.Max(maxImaginary, math.Abs(got.Imag))
			if math.Abs(got.Real) > result.AccuracyTolerance || math.Abs(got.Imag) > result.AccuracyTolerance {
				inactiveMismatches++
			}
		}
	}
	if pathCounts != [4]uint32{55, 29, 30, 56} || equalityCounts != [3]uint32{2, 2, 2} {
		return lineagef("canonical signed8 radix-4 coverage changed: paths=%v equality=%v", pathCounts, equalityCounts)
	}
	if result.MaxActiveAbsError != maxActive || result.MaxInactiveAbs != maxInactive || result.MaxImaginaryAbs != maxImaginary ||
		result.PathCounts != pathCounts || result.EqualityCounts != equalityCounts ||
		result.ActiveMismatchCount != activeMismatches || result.InactiveMismatchCount != inactiveMismatches ||
		result.BinaryEquivalenceMismatchCount != binaryMismatches || activeMismatches != 0 || inactiveMismatches != 0 || binaryMismatches != 0 ||
		maxActive > result.AccuracyTolerance || maxInactive > result.AccuracyTolerance || maxImaginary > result.AccuracyTolerance {
		return lineagef("canonical signed8 radix-4 decoded accuracy/equivalence ledger changed or failed")
	}
	return nil
}

func RunCanonicalRouteBSigned8Radix4() (result RouteBCanonicalSigned8Radix4Result, err error) {
	started := time.Now()
	before := dft.SnapshotMatrixConstructionCounters()
	authority, err := NewRouteBAuthority()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 radix-4 create Authority: %w", err)
	}
	releaseRouteBTransientHeap()
	buildSpec, buildPermit, err := authority.AuthorizeBuild()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 radix-4 AuthorizeBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	receipt, artifact, err := authority.BeginBuild(buildPermit)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 radix-4 BeginBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	readySpec, readyPermit, err := authority.AuthorizeReady(buildPermit, receipt, artifact)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 radix-4 AuthorizeReady: %w", err)
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
		return result, lineagef("canonical signed8 radix-4 secret-key generation returned nil")
	}

	inputWords := routeBSigned8Radix4InputWords()
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8Radix4EncoderPrecision)
	if err != nil {
		return result, err
	}
	inputSlots := make([]*bignum.Complex, 0, routeBSigned8Radix4Slots)
	for _, value := range inputWords {
		block, blockErr := ringZ.ToRootSlots(ringZ.ArithmeticEncode(uint64(uint8(value))))
		if blockErr != nil {
			return result, fmt.Errorf("secureeval: encode canonical signed8 radix-4 input: %w", blockErr)
		}
		inputSlots = append(inputSlots, block...)
	}
	if len(inputSlots) != routeBSigned8Radix4Slots {
		return result, lineagef("canonical signed8 radix-4 input slot count changed")
	}
	encoder := ckks.NewEncoder(parameters, routeBSigned8Radix4EncoderPrecision)
	plaintext := ckks.NewPlaintext(parameters, parameters.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	if err = encoder.Encode(inputSlots, plaintext); err != nil {
		return result, fmt.Errorf("secureeval: encode canonical signed8 radix-4 input plaintext: %w", err)
	}
	encryptor := ckks.NewEncryptor(parameters, secretKey)
	input, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		return result, fmt.Errorf("secureeval: encrypt canonical signed8 radix-4 input: %w", err)
	}
	inputCiphertextBytes := uint64(input.BinarySize())
	ringZ = nil
	inputSlots = nil
	inputWords = nil
	plaintext = nil
	encoder = nil
	encryptor = nil
	releaseRouteBTransientHeap()

	installed, err := authority.Install(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 radix-4 Install: %w", err)
	}
	evaluationKeyBytes, err := routeBInstalledEvaluationKeyBinarySize(installed)
	if err != nil {
		return result, err
	}
	dftArtifactBytes, err := routeBDFTArtifactEncodedBytes(receipt)
	if err != nil {
		return result, err
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
	model, ranges, _, _, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		return result, err
	}
	radixResult, firstOperation, radixReport, err := installed.RunSigned8Radix4Public(input, ranges, model)
	input = nil
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical Route-B signed8 radix-4: %w", err)
	}
	output := radixResult.Ciphertext()
	if output == nil || radixResult.ReportDigest() != radixReport.Digest {
		return result, lineagef("canonical signed8 radix-4 output is nil or has foreign provenance")
	}
	outputCiphertextBytes := uint64(output.BinarySize())
	postRadixPeak, err := sampleProductionProcessPeakRSS()
	if err != nil {
		return result, err
	}
	installRuntime := installed.InstallRuntimeCapacityEvidence()
	retireRouteBInstalledEvaluator(installed)
	retired = true
	installed = nil
	releaseRouteBTransientHeap()

	decoder := ckks.NewEncoder(parameters, routeBSigned8Radix4EncoderPrecision)
	decryptor := ckks.NewDecryptor(parameters, secretKey)
	values := make([]complex128, routeBSigned8Radix4Slots)
	outputPlaintext := decryptor.DecryptNew(output)
	output = nil
	if err = decoder.Decode(outputPlaintext, values); err != nil {
		return result, fmt.Errorf("secureeval: decode canonical signed8 radix-4 output: %w", err)
	}
	outputPlaintext = nil
	decoder = nil
	decryptor = nil

	decoded := make([]RouteBComplexSample, routeBSigned8Radix4Slots)
	for index, value := range values {
		decoded[index] = RouteBComplexSample{Real: real(value), Imag: imag(value)}
	}
	values = nil
	inputValues := routeBSigned8Radix4InputValues()
	_, _, binaryModel, binaryRanges, err := routeBSigned8Radix4CanonicalModelsAndRanges()
	if err != nil {
		return result, err
	}
	maxActive, maxInactive, maxImaginary := 0.0, 0.0, 0.0
	var pathCounts [4]uint32
	var equalityCounts [3]uint32
	var activeMismatches, inactiveMismatches, binaryMismatches uint64
	for query, feature := range inputValues {
		want, path, _, oracleErr := routeBSigned8Radix4Oracle(feature, ranges, model)
		if oracleErr != nil {
			return result, oracleErr
		}
		binaryWant, binaryPath, _, binaryErr := routeBSigned8Depth2NodeBatchOracle([3]int64{feature, feature, feature}, binaryRanges, binaryModel)
		if binaryErr != nil {
			return result, binaryErr
		}
		if path != binaryPath || math.Float64bits(want) != math.Float64bits(binaryWant) {
			binaryMismatches++
		}
		pathCounts[path]++
		for index, threshold := range model.thresholds {
			if feature == threshold {
				equalityCounts[index]++
			}
		}
		rootWord := routeBSigned8Radix4WordsPerQuery * query
		for slot := 0; slot < 4; slot++ {
			value := decoded[4*rootWord+slot]
			errorMagnitude := math.Abs(value.Real - want)
			maxActive = math.Max(maxActive, errorMagnitude)
			maxImaginary = math.Max(maxImaginary, math.Abs(value.Imag))
			if errorMagnitude > RouteBSigned8Radix4AccuracyTolerance || math.Abs(value.Imag) > RouteBSigned8Radix4AccuracyTolerance {
				activeMismatches++
			}
		}
	}
	for word := 0; word < routeBSigned8Radix4Words; word++ {
		if word%3 == 0 && word < 3*routeBSigned8Radix4Queries {
			continue
		}
		for slot := 0; slot < 4; slot++ {
			value := decoded[4*word+slot]
			maxInactive = math.Max(maxInactive, math.Abs(value.Real))
			maxImaginary = math.Max(maxImaginary, math.Abs(value.Imag))
			if math.Abs(value.Real) > RouteBSigned8Radix4AccuracyTolerance || math.Abs(value.Imag) > RouteBSigned8Radix4AccuracyTolerance {
				inactiveMismatches++
			}
		}
	}
	secretKey = nil
	prepared = bootstrapping.PreparedParameters{}
	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil {
		return result, err
	}
	wall := uint64(time.Since(started).Nanoseconds())
	if wall == 0 {
		wall = 1
	}
	result = RouteBCanonicalSigned8Radix4Result{
		BuildSpec: buildSpec, BuildReceipt: receipt.Report(), ReadySpec: readySpec,
		FirstOperation: firstOperation, Radix4: radixReport,
		BuildRuntime: receipt.RuntimeCapacityEvidence(), ReadyRuntime: readyPermit.RuntimeCapacityEvidence(),
		InstallRuntime: installRuntime, OverallConstructionDelta: [4]uint64{
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(),
		},
		PostInstallPeakRSSBytes: postInstallPeak, PostRadixPeakRSSBytes: postRadixPeak,
		TotalWallNanoseconds: wall, QueryCount: routeBSigned8Radix4Queries,
		InputWords: routeBSigned8Radix4Words, PaddingWords: routeBSigned8Radix4PaddingWords,
		OutputSlots: routeBSigned8Radix4Slots, ActiveOutputSlots: 4 * routeBSigned8Radix4Queries,
		InactiveOutputSlots:              routeBSigned8Radix4Slots - 4*routeBSigned8Radix4Queries,
		InputPatternDigest:               routeBSigned8Radix4ExpectedInputDigest,
		ApplicationSecurityProfileDigest: routeBApplicationSecurityProfileDigest,
		SecurityInheritance:              "same_parameter_and_41_evaluation_key_schedule;one_fresh_input_sample_is_a_subset_of_C75_three",
		DecryptionsBeforeOutput:          0, PlaintextBranchDecisions: 0,
		InputCiphertextSerializedBytes: inputCiphertextBytes, OutputCiphertextSerializedBytes: outputCiphertextBytes,
		EvaluationKeySerializedBytes: evaluationKeyBytes, DFTArtifactEncodedBytes: dftArtifactBytes,
		DecodedOutput: decoded, AccuracyTolerance: RouteBSigned8Radix4AccuracyTolerance,
		MaxActiveAbsError: maxActive, MaxInactiveAbs: maxInactive, MaxImaginaryAbs: maxImaginary,
		PathCounts: pathCounts, EqualityCounts: equalityCounts,
		ActiveMismatchCount: activeMismatches, InactiveMismatchCount: inactiveMismatches,
		BinaryEquivalenceMismatchCount: binaryMismatches,
	}
	if err = result.Validate(); err != nil {
		return RouteBCanonicalSigned8Radix4Result{}, err
	}
	return result, nil
}
