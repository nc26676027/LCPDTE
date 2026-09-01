package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"dt_go/integer/homchain"
	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	routeBSigned8Depth2NodeBatchInputSchema       = "lcpdte-route-b-signed8-depth2-node-batch-input-v1"
	RouteBSigned8Depth2NodeBatchAccuracyTolerance = 5e-4
)

type RouteBCanonicalSigned8Depth2NodeBatchResult struct {
	BuildSpec      ArtifactBuildSpec                  `json:"build_spec"`
	BuildReceipt   RBDFTBuildReceiptReport            `json:"build_receipt"`
	ReadySpec      ReadySpec                          `json:"ready_spec"`
	FirstOperation RouteBFirstOperationReport         `json:"first_operation"`
	Depth2         RouteBSigned8Depth2NodeBatchReport `json:"depth2_node_batch"`
	BuildRuntime   RuntimeCapacityEvidenceReport      `json:"build_runtime"`
	ReadyRuntime   RuntimeCapacityEvidenceReport      `json:"ready_runtime"`
	InstallRuntime RuntimeCapacityEvidenceReport      `json:"install_runtime"`

	OverallConstructionDelta [4]uint64 `json:"overall_construction_delta"`
	PostInstallPeakRSSBytes  uint64    `json:"post_install_peak_rss_bytes"`
	PostDepth2PeakRSSBytes   uint64    `json:"post_depth2_peak_rss_bytes"`
	TotalWallNanoseconds     uint64    `json:"total_wall_nanoseconds"`

	QueryCount          uint32 `json:"query_count"`
	InputWords          uint32 `json:"input_words"`
	PaddingWords        uint32 `json:"padding_words"`
	OutputSlots         uint32 `json:"output_slots"`
	ActiveOutputSlots   uint32 `json:"active_output_slots"`
	InactiveOutputSlots uint32 `json:"inactive_output_slots"`
	InputPatternDigest  string `json:"input_pattern_digest"`

	DecodedOutput []RouteBComplexSample `json:"decoded_output"`

	AccuracyTolerance     float64   `json:"accuracy_tolerance"`
	MaxActiveAbsError     float64   `json:"max_active_abs_error"`
	MaxInactiveAbs        float64   `json:"max_inactive_abs"`
	MaxImaginaryAbs       float64   `json:"max_imaginary_abs"`
	PathCounts            [4]uint32 `json:"path_counts"`
	BranchTripleCounts    [8]uint32 `json:"branch_triple_counts"`
	ActiveMismatchCount   uint64    `json:"active_mismatch_count"`
	InactiveMismatchCount uint64    `json:"inactive_mismatch_count"`
}

func (result RouteBCanonicalSigned8Depth2NodeBatchResult) Validate() error {
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
	if err := result.Depth2.Validate(); err != nil {
		return err
	}
	for operation, evidence := range map[string]RuntimeCapacityEvidenceReport{
		routeBRuntimeOperationBeginBuild:     result.BuildRuntime,
		routeBRuntimeOperationAuthorizeReady: result.ReadyRuntime,
		routeBRuntimeOperationInstall:        result.InstallRuntime,
	} {
		if err := evidence.Validate(); err != nil || evidence.Operation != operation {
			return lineagef("canonical signed8 depth-2 runtime evidence %q changed", operation)
		}
	}
	capacityPlanIdentity, err := decodeRBAUTHHexDigest("Route-B signed8 depth-2 capacity plan", result.Depth2.CapacityPlanDigest)
	if err != nil {
		return err
	}
	if result.FirstOperation.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8Depth2NodeBatch ||
		result.FirstOperation.RuntimeCapacity.Capacity.CapacityPlanDigest != capacityPlanIdentity ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 3} ||
		result.BuildReceipt.Payload != result.ReadySpec.ActualPayload ||
		result.BuildReceipt.Payload != result.FirstOperation.ResidentPayload ||
		result.BuildReceipt.ArtifactManifestDigest != result.ReadySpec.ArtifactPairManifestDigest ||
		result.BuildReceipt.ArtifactManifestDigest != result.FirstOperation.ArtifactPairManifestDigest ||
		result.BuildReceipt.BuildPeakRSSBytes == 0 || result.PostInstallPeakRSSBytes == 0 ||
		result.PostDepth2PeakRSSBytes < result.PostInstallPeakRSSBytes || result.TotalWallNanoseconds == 0 {
		return lineagef("canonical signed8 depth-2 linkage, construction counter, RSS, or wall-time changed")
	}
	if result.QueryCount != routeBSigned8Depth2NodeBatchQueries || result.InputWords != routeBSigned8Depth2NodeBatchWords ||
		result.PaddingWords != routeBSigned8Depth2NodeBatchPaddingWords || result.OutputSlots != routeBSigned8Depth2NodeBatchSlots ||
		result.ActiveOutputSlots != 4*routeBSigned8Depth2NodeBatchQueries ||
		result.InactiveOutputSlots != routeBSigned8Depth2NodeBatchSlots-4*routeBSigned8Depth2NodeBatchQueries ||
		result.InputPatternDigest != routeBSigned8Depth2NodeBatchInputPatternDigest() ||
		len(result.DecodedOutput) != routeBSigned8Depth2NodeBatchSlots ||
		result.AccuracyTolerance != RouteBSigned8Depth2NodeBatchAccuracyTolerance {
		return lineagef("canonical signed8 depth-2 input, output, or tolerance shape changed")
	}
	ranges, model, err := reconstructRouteBSigned8Depth2NodeBatchInputs(result.Depth2.Ranges, result.Depth2.Model)
	if err != nil {
		return err
	}
	queries := routeBSigned8Depth2NodeBatchInputQueries()
	maxActive, maxInactive, maxImaginary := 0.0, 0.0, 0.0
	var pathCounts [4]uint32
	var branchCounts [8]uint32
	var activeMismatches, inactiveMismatches uint64
	for query, features := range queries {
		want, path, branches, oracleErr := routeBSigned8Depth2NodeBatchOracle(features, ranges, model)
		if oracleErr != nil {
			return oracleErr
		}
		pathCounts[path]++
		branchCounts[4*branches[0]+2*branches[1]+branches[2]]++
		rootWord := routeBSigned8Depth2NodeBatchWordsPerQuery * query
		for slot := 0; slot < 4; slot++ {
			index := 4*rootWord + slot
			got := result.DecodedOutput[index]
			if !routeBFiniteFloat(got.Real) || !routeBFiniteFloat(got.Imag) {
				return lineagef("canonical signed8 depth-2 active slot %d is non-finite", index)
			}
			errorMagnitude := math.Abs(got.Real - want)
			maxActive = math.Max(maxActive, errorMagnitude)
			maxImaginary = math.Max(maxImaginary, math.Abs(got.Imag))
			if errorMagnitude > result.AccuracyTolerance || math.Abs(got.Imag) > result.AccuracyTolerance {
				activeMismatches++
			}
		}
	}
	for word := 0; word < routeBSigned8Depth2NodeBatchWords; word++ {
		if word%3 == 0 && word < 3*routeBSigned8Depth2NodeBatchQueries {
			continue
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*word + slot
			got := result.DecodedOutput[index]
			if !routeBFiniteFloat(got.Real) || !routeBFiniteFloat(got.Imag) {
				return lineagef("canonical signed8 depth-2 inactive slot %d is non-finite", index)
			}
			maxInactive = math.Max(maxInactive, math.Abs(got.Real))
			maxImaginary = math.Max(maxImaginary, math.Abs(got.Imag))
			if math.Abs(got.Real) > result.AccuracyTolerance || math.Abs(got.Imag) > result.AccuracyTolerance {
				inactiveMismatches++
			}
		}
	}
	for index, count := range pathCounts {
		if count == 0 {
			return lineagef("canonical signed8 depth-2 path %d was not covered", index)
		}
	}
	for index, count := range branchCounts {
		if count == 0 {
			return lineagef("canonical signed8 depth-2 branch triple %03b was not covered", index)
		}
	}
	if result.MaxActiveAbsError != maxActive || result.MaxInactiveAbs != maxInactive ||
		result.MaxImaginaryAbs != maxImaginary || result.PathCounts != pathCounts ||
		result.BranchTripleCounts != branchCounts || result.ActiveMismatchCount != activeMismatches ||
		result.InactiveMismatchCount != inactiveMismatches || activeMismatches != 0 || inactiveMismatches != 0 ||
		maxActive > result.AccuracyTolerance || maxInactive > result.AccuracyTolerance || maxImaginary > result.AccuracyTolerance {
		return lineagef("canonical signed8 depth-2 decoded accuracy ledger changed or failed")
	}
	return nil
}

func RunCanonicalRouteBSigned8Depth2NodeBatch() (result RouteBCanonicalSigned8Depth2NodeBatchResult, err error) {
	started := time.Now()
	before := dft.SnapshotMatrixConstructionCounters()
	authority, err := NewRouteBAuthority()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 depth-2 create Authority: %w", err)
	}
	releaseRouteBTransientHeap()
	buildSpec, buildPermit, err := authority.AuthorizeBuild()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 depth-2 AuthorizeBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	receipt, artifact, err := authority.BeginBuild(buildPermit)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 depth-2 BeginBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	readySpec, readyPermit, err := authority.AuthorizeReady(buildPermit, receipt, artifact)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 depth-2 AuthorizeReady: %w", err)
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
		return result, lineagef("canonical signed8 depth-2 secret-key generation returned nil")
	}

	inputWords := routeBSigned8Depth2NodeBatchInputWords()
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8Depth2NodeBatchEncoderPrecision)
	if err != nil {
		return result, err
	}
	inputSlots := make([]*bignum.Complex, 0, routeBSigned8Depth2NodeBatchSlots)
	for _, value := range inputWords {
		block, blockErr := ringZ.ToRootSlots(ringZ.ArithmeticEncode(uint64(uint8(value))))
		if blockErr != nil {
			return result, fmt.Errorf("secureeval: encode canonical signed8 depth-2 input: %w", blockErr)
		}
		inputSlots = append(inputSlots, block...)
	}
	if len(inputSlots) != routeBSigned8Depth2NodeBatchSlots {
		return result, lineagef("canonical signed8 depth-2 input slot count changed")
	}
	encoder := ckks.NewEncoder(parameters, routeBSigned8Depth2NodeBatchEncoderPrecision)
	plaintext := ckks.NewPlaintext(parameters, parameters.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	if err = encoder.Encode(inputSlots, plaintext); err != nil {
		return result, fmt.Errorf("secureeval: encode canonical signed8 depth-2 input plaintext: %w", err)
	}
	encryptor := ckks.NewEncryptor(parameters, secretKey)
	input, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		return result, fmt.Errorf("secureeval: encrypt canonical signed8 depth-2 input: %w", err)
	}
	ringZ = nil
	inputSlots = nil
	inputWords = nil
	plaintext = nil
	encoder = nil
	encryptor = nil
	releaseRouteBTransientHeap()

	installed, err := authority.Install(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 depth-2 Install: %w", err)
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
	ranges, err := routeBSigned8Depth2NodeBatchCanonicalRanges()
	if err != nil {
		return result, err
	}
	model, err := NewRouteBSigned8Depth2NodeBatchModel([3]int64{}, [4]float64{-3.25, -0.75, 2.5, 5.125})
	if err != nil {
		return result, err
	}
	depth2Result, firstOperation, depth2Report, err := installed.RunSigned8Depth2NodeBatchPublic(input, ranges, model)
	input = nil
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical Route-B signed8 depth-2 node batch: %w", err)
	}
	output := depth2Result.Ciphertext()
	if output == nil || depth2Result.ReportDigest() != depth2Report.Digest {
		return result, lineagef("canonical signed8 depth-2 output is nil or has foreign provenance")
	}
	postDepth2Peak, err := sampleProductionProcessPeakRSS()
	if err != nil {
		return result, err
	}
	installRuntime := installed.InstallRuntimeCapacityEvidence()
	retireRouteBInstalledEvaluator(installed)
	retired = true
	installed = nil
	releaseRouteBTransientHeap()

	decoder := ckks.NewEncoder(parameters, routeBSigned8Depth2NodeBatchEncoderPrecision)
	decryptor := ckks.NewDecryptor(parameters, secretKey)
	values := make([]complex128, routeBSigned8Depth2NodeBatchSlots)
	outputPlaintext := decryptor.DecryptNew(output)
	output = nil
	if err = decoder.Decode(outputPlaintext, values); err != nil {
		return result, fmt.Errorf("secureeval: decode canonical signed8 depth-2 output: %w", err)
	}
	outputPlaintext = nil
	decoder = nil
	decryptor = nil

	decoded := make([]RouteBComplexSample, routeBSigned8Depth2NodeBatchSlots)
	for index, value := range values {
		decoded[index] = RouteBComplexSample{Real: real(value), Imag: imag(value)}
	}
	values = nil
	queries := routeBSigned8Depth2NodeBatchInputQueries()
	maxActive, maxInactive, maxImaginary := 0.0, 0.0, 0.0
	var pathCounts [4]uint32
	var branchCounts [8]uint32
	var activeMismatches, inactiveMismatches uint64
	for query, features := range queries {
		want, path, branches, oracleErr := routeBSigned8Depth2NodeBatchOracle(features, ranges, model)
		if oracleErr != nil {
			return result, oracleErr
		}
		pathCounts[path]++
		branchCounts[4*branches[0]+2*branches[1]+branches[2]]++
		rootWord := routeBSigned8Depth2NodeBatchWordsPerQuery * query
		for slot := 0; slot < 4; slot++ {
			value := decoded[4*rootWord+slot]
			errorMagnitude := math.Abs(value.Real - want)
			maxActive = math.Max(maxActive, errorMagnitude)
			maxImaginary = math.Max(maxImaginary, math.Abs(value.Imag))
			if errorMagnitude > RouteBSigned8Depth2NodeBatchAccuracyTolerance || math.Abs(value.Imag) > RouteBSigned8Depth2NodeBatchAccuracyTolerance {
				activeMismatches++
			}
		}
	}
	for word := 0; word < routeBSigned8Depth2NodeBatchWords; word++ {
		if word%3 == 0 && word < 3*routeBSigned8Depth2NodeBatchQueries {
			continue
		}
		for slot := 0; slot < 4; slot++ {
			value := decoded[4*word+slot]
			maxInactive = math.Max(maxInactive, math.Abs(value.Real))
			maxImaginary = math.Max(maxImaginary, math.Abs(value.Imag))
			if math.Abs(value.Real) > RouteBSigned8Depth2NodeBatchAccuracyTolerance || math.Abs(value.Imag) > RouteBSigned8Depth2NodeBatchAccuracyTolerance {
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
	result = RouteBCanonicalSigned8Depth2NodeBatchResult{
		BuildSpec: buildSpec, BuildReceipt: receipt.Report(), ReadySpec: readySpec,
		FirstOperation: firstOperation, Depth2: depth2Report,
		BuildRuntime: receipt.RuntimeCapacityEvidence(), ReadyRuntime: readyPermit.RuntimeCapacityEvidence(),
		InstallRuntime:           installRuntime,
		OverallConstructionDelta: [4]uint64{delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming()},
		PostInstallPeakRSSBytes:  postInstallPeak, PostDepth2PeakRSSBytes: postDepth2Peak,
		TotalWallNanoseconds: wall, QueryCount: routeBSigned8Depth2NodeBatchQueries,
		InputWords: routeBSigned8Depth2NodeBatchWords, PaddingWords: routeBSigned8Depth2NodeBatchPaddingWords,
		OutputSlots: routeBSigned8Depth2NodeBatchSlots, ActiveOutputSlots: 4 * routeBSigned8Depth2NodeBatchQueries,
		InactiveOutputSlots: routeBSigned8Depth2NodeBatchSlots - 4*routeBSigned8Depth2NodeBatchQueries,
		InputPatternDigest:  routeBSigned8Depth2NodeBatchInputPatternDigest(), DecodedOutput: decoded,
		AccuracyTolerance: RouteBSigned8Depth2NodeBatchAccuracyTolerance,
		MaxActiveAbsError: maxActive, MaxInactiveAbs: maxInactive, MaxImaginaryAbs: maxImaginary,
		PathCounts: pathCounts, BranchTripleCounts: branchCounts,
		ActiveMismatchCount: activeMismatches, InactiveMismatchCount: inactiveMismatches,
	}
	if err = result.Validate(); err != nil {
		return RouteBCanonicalSigned8Depth2NodeBatchResult{}, err
	}
	return result, nil
}

func routeBSigned8Depth2NodeBatchCanonicalRanges() (result [3]homchain.Signed8NoOverflowRange, err error) {
	for index := range result {
		result[index], err = homchain.NewSigned8NoOverflowRange(-128, 127, 0, 0)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func routeBSigned8Depth2NodeBatchInputQueries() [][3]int64 {
	queries := make([][3]int64, routeBSigned8Depth2NodeBatchQueries)
	branchValue := func(branch int, magnitude int) int64 {
		if branch == 0 {
			return int64(-1 - magnitude)
		}
		return int64(magnitude)
	}
	for query := range queries {
		branches := [3]int{(query >> 2) & 1, (query >> 1) & 1, query & 1}
		queries[query] = [3]int64{
			branchValue(branches[0], (17*query+3)%128),
			branchValue(branches[1], (29*query+5)%128),
			branchValue(branches[2], (43*query+7)%128),
		}
	}
	queries[8] = [3]int64{-128, -128, -128}
	queries[9] = [3]int64{-128, -1, 127}
	queries[10] = [3]int64{-1, 0, -128}
	queries[11] = [3]int64{-1, 0, 0}
	queries[12] = [3]int64{0, -128, -128}
	queries[13] = [3]int64{127, -128, 0}
	queries[14] = [3]int64{0, 0, -128}
	queries[15] = [3]int64{127, 127, 127}
	return queries
}

func routeBSigned8Depth2NodeBatchInputWords() []int64 {
	words := make([]int64, 0, routeBSigned8Depth2NodeBatchWords)
	for _, query := range routeBSigned8Depth2NodeBatchInputQueries() {
		words = append(words, query[:]...)
	}
	for len(words) < routeBSigned8Depth2NodeBatchWords {
		words = append(words, 0)
	}
	return words
}

func routeBSigned8Depth2NodeBatchInputPatternDigest() string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBSigned8Depth2NodeBatchInputSchema + "\x00"))
	var record [16]byte
	for index, value := range routeBSigned8Depth2NodeBatchInputWords() {
		binary.LittleEndian.PutUint64(record[0:8], uint64(index))
		binary.LittleEndian.PutUint64(record[8:16], uint64(value))
		_, _ = hasher.Write(record[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
