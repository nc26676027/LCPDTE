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
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const (
	routeBSigned8RootTreeInputSchema       = "lcpdte-route-b-signed8-root-tree-input-v1"
	RouteBSigned8RootTreeAccuracyTolerance = 5e-4
)

// RouteBCanonicalSigned8RootTreeResult contains one complete Route-B
// lifecycle and every decoded slot for two exhaustive signed-int8 copies.
type RouteBCanonicalSigned8RootTreeResult struct {
	BuildSpec      ArtifactBuildSpec             `json:"build_spec"`
	BuildReceipt   RBDFTBuildReceiptReport       `json:"build_receipt"`
	ReadySpec      ReadySpec                     `json:"ready_spec"`
	FirstOperation RouteBFirstOperationReport    `json:"first_operation"`
	RootTree       RouteBSigned8RootTreeReport   `json:"root_tree"`
	BuildRuntime   RuntimeCapacityEvidenceReport `json:"build_runtime"`
	ReadyRuntime   RuntimeCapacityEvidenceReport `json:"ready_runtime"`
	InstallRuntime RuntimeCapacityEvidenceReport `json:"install_runtime"`

	OverallConstructionDelta [4]uint64 `json:"overall_construction_delta"`
	PostInstallPeakRSSBytes  uint64    `json:"post_install_peak_rss_bytes"`
	PostRootTreePeakRSSBytes uint64    `json:"post_root_tree_peak_rss_bytes"`
	TotalWallNanoseconds     uint64    `json:"total_wall_nanoseconds"`

	InputWords         uint32 `json:"input_words"`
	InputDistinctWords uint32 `json:"input_distinct_words"`
	OutputSlots        uint32 `json:"output_slots"`
	InputPatternDigest string `json:"input_pattern_digest"`

	DecodedOutput []RouteBComplexSample `json:"decoded_output"`

	AccuracyTolerance float64 `json:"accuracy_tolerance"`
	MaxAbsError       float64 `json:"max_abs_error"`
	MaxImaginaryAbs   float64 `json:"max_imaginary_abs"`
	LeftWordCount     uint32  `json:"left_word_count"`
	RightWordCount    uint32  `json:"right_word_count"`
	MismatchCount     uint64  `json:"mismatch_count"`
}

func (result RouteBCanonicalSigned8RootTreeResult) Validate() error {
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
	if err := result.RootTree.Validate(); err != nil {
		return err
	}
	for operation, evidence := range map[string]RuntimeCapacityEvidenceReport{
		routeBRuntimeOperationBeginBuild:     result.BuildRuntime,
		routeBRuntimeOperationAuthorizeReady: result.ReadyRuntime,
		routeBRuntimeOperationInstall:        result.InstallRuntime,
	} {
		if err := evidence.Validate(); err != nil || evidence.Operation != operation {
			return lineagef("canonical signed8 root-tree runtime evidence %q changed", operation)
		}
	}
	capacityPlanIdentity, err := decodeRBAUTHHexDigest("Route-B signed8 root-tree capacity plan", result.RootTree.CapacityPlanDigest)
	if err != nil {
		return err
	}
	if result.FirstOperation.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8RootTree ||
		result.FirstOperation.RuntimeCapacity.Capacity.CapacityPlanDigest != capacityPlanIdentity ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 3} ||
		result.BuildReceipt.Payload != result.ReadySpec.ActualPayload ||
		result.BuildReceipt.Payload != result.FirstOperation.ResidentPayload ||
		result.BuildReceipt.ArtifactManifestDigest != result.ReadySpec.ArtifactPairManifestDigest ||
		result.BuildReceipt.ArtifactManifestDigest != result.FirstOperation.ArtifactPairManifestDigest ||
		result.BuildReceipt.BuildPeakRSSBytes == 0 || result.PostInstallPeakRSSBytes == 0 ||
		result.PostRootTreePeakRSSBytes < result.PostInstallPeakRSSBytes || result.TotalWallNanoseconds == 0 {
		return lineagef("canonical signed8 root-tree linkage, construction counter, RSS, or wall-time changed")
	}
	if result.InputWords != routeBSigned8RootTreeWords || result.InputDistinctWords != 256 ||
		result.OutputSlots != routeBSigned8RootTreeSlots ||
		result.InputPatternDigest != routeBSigned8RootTreeInputPatternDigest() ||
		len(result.DecodedOutput) != routeBSigned8RootTreeSlots ||
		result.AccuracyTolerance != RouteBSigned8RootTreeAccuracyTolerance {
		return lineagef("canonical signed8 root-tree input, output, or tolerance shape changed")
	}
	ranges, model, err := reconstructRouteBSigned8RootTreeInputs(result.RootTree.Range, result.RootTree.Model)
	if err != nil {
		return err
	}
	maxError, maxImaginary := 0.0, 0.0
	leftWords, rightWords := uint32(0), uint32(0)
	var mismatches uint64
	for wordIndex, value := range routeBSigned8RootTreeInputWords() {
		want, branch, oracleErr := routeBSigned8RootTreeOracle(value, ranges, model)
		if oracleErr != nil {
			return oracleErr
		}
		if branch == 0 {
			leftWords++
		} else {
			rightWords++
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*wordIndex + slot
			got := result.DecodedOutput[index]
			if !routeBFiniteFloat(got.Real) || !routeBFiniteFloat(got.Imag) {
				return lineagef("canonical signed8 root-tree decoded slot %d is non-finite", index)
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
	if result.MaxAbsError != maxError || result.MaxImaginaryAbs != maxImaginary ||
		result.LeftWordCount != leftWords || result.RightWordCount != rightWords ||
		result.MismatchCount != mismatches || mismatches != 0 ||
		leftWords != 256 || rightWords != 256 || maxError > result.AccuracyTolerance ||
		maxImaginary > result.AccuracyTolerance {
		return lineagef("canonical signed8 root-tree decoded accuracy ledger changed or failed")
	}
	return nil
}

// RunCanonicalRouteBSigned8RootTree executes the canonical one-process
// lifecycle, one signed-int8 public-root comparison, and real-leaf selection.
func RunCanonicalRouteBSigned8RootTree() (result RouteBCanonicalSigned8RootTreeResult, err error) {
	started := time.Now()
	before := dft.SnapshotMatrixConstructionCounters()
	authority, err := NewRouteBAuthority()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 root create Authority: %w", err)
	}
	releaseRouteBTransientHeap()
	buildSpec, buildPermit, err := authority.AuthorizeBuild()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 root AuthorizeBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	receipt, artifact, err := authority.BeginBuild(buildPermit)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 root BeginBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	readySpec, readyPermit, err := authority.AuthorizeReady(buildPermit, receipt, artifact)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 root AuthorizeReady: %w", err)
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
		return result, lineagef("canonical signed8 root secret-key generation returned nil")
	}

	ringZ, err := z2n.NewWithPrecision(z2n.Word8, 256)
	if err != nil {
		return result, err
	}
	inputSlots := make([]*bignum.Complex, 0, routeBSigned8RootTreeSlots)
	for _, value := range routeBSigned8RootTreeInputWords() {
		block, blockErr := ringZ.ToRootSlots(ringZ.ArithmeticEncode(uint64(uint8(value))))
		if blockErr != nil {
			return result, fmt.Errorf("secureeval: encode canonical signed8 root input: %w", blockErr)
		}
		inputSlots = append(inputSlots, block...)
	}
	if len(inputSlots) != routeBSigned8RootTreeSlots {
		return result, lineagef("canonical signed8 root input slot count changed")
	}
	encoder := ckks.NewEncoder(parameters, 256)
	plaintext := ckks.NewPlaintext(parameters, parameters.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	if err = encoder.Encode(inputSlots, plaintext); err != nil {
		return result, fmt.Errorf("secureeval: encode canonical signed8 root input plaintext: %w", err)
	}
	encryptor := ckks.NewEncryptor(parameters, secretKey)
	input, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		return result, fmt.Errorf("secureeval: encrypt canonical signed8 root input: %w", err)
	}
	ringZ = nil
	inputSlots = nil
	plaintext = nil
	encoder = nil
	encryptor = nil
	releaseRouteBTransientHeap()

	installed, err := authority.Install(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical signed8 root Install: %w", err)
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
	ranges, err := homchain.NewSigned8NoOverflowRange(-128, 127, 0, 0)
	if err != nil {
		return result, err
	}
	model, err := NewRouteBSigned8RootTreeModel(0, -2.25, 3.5)
	if err != nil {
		return result, err
	}
	treeResult, firstOperation, rootReport, err := installed.RunSigned8RootTreePublic(input, ranges, model)
	input = nil
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical Route-B signed8 root tree: %w", err)
	}
	output := treeResult.Ciphertext()
	if output == nil || treeResult.ReportDigest() != rootReport.Digest {
		return result, lineagef("canonical signed8 root-tree output is nil or has foreign provenance")
	}
	postRootPeak, err := sampleProductionProcessPeakRSS()
	if err != nil {
		return result, err
	}
	installRuntime := installed.InstallRuntimeCapacityEvidence()
	retireRouteBInstalledEvaluator(installed)
	retired = true
	installed = nil
	releaseRouteBTransientHeap()

	decoder := ckks.NewEncoder(parameters, 256)
	decryptor := ckks.NewDecryptor(parameters, secretKey)
	values := make([]complex128, routeBSigned8RootTreeSlots)
	outputPlaintext := decryptor.DecryptNew(output)
	output = nil
	if err = decoder.Decode(outputPlaintext, values); err != nil {
		return result, fmt.Errorf("secureeval: decode canonical signed8 root-tree output: %w", err)
	}
	outputPlaintext = nil
	decoder = nil
	decryptor = nil

	decoded := make([]RouteBComplexSample, routeBSigned8RootTreeSlots)
	maxError, maxImaginary := 0.0, 0.0
	leftWords, rightWords := uint32(0), uint32(0)
	var mismatches uint64
	words := routeBSigned8RootTreeInputWords()
	for wordIndex, value := range words {
		want, branch, oracleErr := routeBSigned8RootTreeOracle(value, ranges, model)
		if oracleErr != nil {
			return result, oracleErr
		}
		if branch == 0 {
			leftWords++
		} else {
			rightWords++
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*wordIndex + slot
			value := values[index]
			decoded[index] = RouteBComplexSample{Real: real(value), Imag: imag(value)}
			errorMagnitude := math.Abs(real(value) - want)
			imaginary := math.Abs(imag(value))
			maxError = math.Max(maxError, errorMagnitude)
			maxImaginary = math.Max(maxImaginary, imaginary)
			if errorMagnitude > RouteBSigned8RootTreeAccuracyTolerance || imaginary > RouteBSigned8RootTreeAccuracyTolerance {
				mismatches++
			}
		}
	}
	values = nil
	words = nil
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
	result = RouteBCanonicalSigned8RootTreeResult{
		BuildSpec: buildSpec, BuildReceipt: receipt.Report(), ReadySpec: readySpec,
		FirstOperation: firstOperation, RootTree: rootReport,
		BuildRuntime: receipt.RuntimeCapacityEvidence(), ReadyRuntime: readyPermit.RuntimeCapacityEvidence(),
		InstallRuntime: installRuntime,
		OverallConstructionDelta: [4]uint64{
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(),
		},
		PostInstallPeakRSSBytes: postInstallPeak, PostRootTreePeakRSSBytes: postRootPeak,
		TotalWallNanoseconds: wall,
		InputWords:           routeBSigned8RootTreeWords, InputDistinctWords: 256, OutputSlots: routeBSigned8RootTreeSlots,
		InputPatternDigest: routeBSigned8RootTreeInputPatternDigest(), DecodedOutput: decoded,
		AccuracyTolerance: RouteBSigned8RootTreeAccuracyTolerance,
		MaxAbsError:       maxError, MaxImaginaryAbs: maxImaginary,
		LeftWordCount: leftWords, RightWordCount: rightWords, MismatchCount: mismatches,
	}
	if err = result.Validate(); err != nil {
		return RouteBCanonicalSigned8RootTreeResult{}, err
	}
	return result, nil
}

func routeBSigned8RootTreeInputWords() []int64 {
	words := make([]int64, 0, routeBSigned8RootTreeWords)
	for copyIndex := 0; copyIndex < 2; copyIndex++ {
		for value := int64(-128); value <= 127; value++ {
			words = append(words, value)
		}
	}
	return words
}

func routeBSigned8RootTreeInputPatternDigest() string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBSigned8RootTreeInputSchema + "\x00"))
	var record [16]byte
	for index, value := range routeBSigned8RootTreeInputWords() {
		binary.LittleEndian.PutUint64(record[0:8], uint64(index))
		binary.LittleEndian.PutUint64(record[8:16], uint64(value))
		_, _ = hasher.Write(record[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
