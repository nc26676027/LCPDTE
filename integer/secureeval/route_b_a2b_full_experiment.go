package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	routeBA2BFullInputSchema       = "lcpdte-route-b-a2b-full-input-v1"
	RouteBA2BFullAccuracyTolerance = 5e-4
)

// RouteBCanonicalL11A2BFullResult contains the one-process lifecycle, full
// serial proof, and every decoded low/high Boolean slot for two copies of all
// 256 byte values.
type RouteBCanonicalL11A2BFullResult struct {
	BuildSpec      ArtifactBuildSpec             `json:"build_spec"`
	BuildReceipt   RBDFTBuildReceiptReport       `json:"build_receipt"`
	ReadySpec      ReadySpec                     `json:"ready_spec"`
	FirstOperation RouteBFirstOperationReport    `json:"first_operation"`
	FullA2B        RouteBA2BFullReport           `json:"full_a2b"`
	BuildRuntime   RuntimeCapacityEvidenceReport `json:"build_runtime"`
	ReadyRuntime   RuntimeCapacityEvidenceReport `json:"ready_runtime"`
	InstallRuntime RuntimeCapacityEvidenceReport `json:"install_runtime"`

	OverallConstructionDelta [4]uint64 `json:"overall_construction_delta"`
	PostInstallPeakRSSBytes  uint64    `json:"post_install_peak_rss_bytes"`
	PostFullA2BPeakRSSBytes  uint64    `json:"post_full_a2b_peak_rss_bytes"`
	TotalWallNanoseconds     uint64    `json:"total_wall_nanoseconds"`

	InputWords         uint32 `json:"input_words"`
	InputDistinctWords uint32 `json:"input_distinct_words"`
	OutputSlots        uint32 `json:"output_slots"`
	InputPatternDigest string `json:"input_pattern_digest"`

	DecodedLowMSB  []RouteBComplexSample `json:"decoded_low_msb"`
	DecodedHighMSB []RouteBComplexSample `json:"decoded_high_msb"`

	AccuracyTolerance float64 `json:"accuracy_tolerance"`
	MaxLowAbsError    float64 `json:"max_low_abs_error"`
	MaxHighAbsError   float64 `json:"max_high_abs_error"`
	MaxImaginaryAbs   float64 `json:"max_imaginary_abs"`
	MismatchCount     uint64  `json:"mismatch_count"`
}

func (result RouteBCanonicalL11A2BFullResult) Validate() error {
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
	if err := result.FullA2B.Validate(); err != nil {
		return err
	}
	for operation, evidence := range map[string]RuntimeCapacityEvidenceReport{
		routeBRuntimeOperationBeginBuild:     result.BuildRuntime,
		routeBRuntimeOperationAuthorizeReady: result.ReadyRuntime,
		routeBRuntimeOperationInstall:        result.InstallRuntime,
	} {
		if err := evidence.Validate(); err != nil || evidence.Operation != operation {
			return lineagef("canonical full-A2B runtime evidence %q changed", operation)
		}
	}
	capacityPlanIdentity, err := decodeRBAUTHHexDigest("Route-B full-A2B capacity plan", result.FullA2B.CapacityPlanDigest)
	if err != nil {
		return err
	}
	if result.FirstOperation.RuntimeCapacity.Operation != routeBRuntimeOperationA2BFull ||
		result.FirstOperation.RuntimeCapacity.Capacity.CapacityPlanDigest != capacityPlanIdentity ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 3} ||
		result.BuildReceipt.Payload != result.ReadySpec.ActualPayload ||
		result.BuildReceipt.Payload != result.FirstOperation.ResidentPayload ||
		result.BuildReceipt.ArtifactManifestDigest != result.ReadySpec.ArtifactPairManifestDigest ||
		result.BuildReceipt.ArtifactManifestDigest != result.FirstOperation.ArtifactPairManifestDigest ||
		result.BuildReceipt.BuildPeakRSSBytes == 0 || result.PostInstallPeakRSSBytes == 0 ||
		result.PostFullA2BPeakRSSBytes < result.PostInstallPeakRSSBytes || result.TotalWallNanoseconds == 0 {
		return lineagef("canonical full-A2B linkage, construction counter, RSS, or wall-time changed")
	}
	if result.InputWords != routeBA2BFirstRoundWords || result.InputDistinctWords != 256 ||
		result.OutputSlots != routeBA2BFirstRoundSlots ||
		result.InputPatternDigest != routeBA2BFullInputPatternDigest() ||
		len(result.DecodedLowMSB) != routeBA2BFirstRoundSlots ||
		len(result.DecodedHighMSB) != routeBA2BFirstRoundSlots ||
		result.AccuracyTolerance != RouteBA2BFullAccuracyTolerance {
		return lineagef("canonical full-A2B input, output, or tolerance shape changed")
	}

	maxLowError, maxHighError, maxImaginary := 0.0, 0.0, 0.0
	var mismatches uint64
	for wordIndex, word := range routeBA2BFirstRoundInputWords() {
		lowOracle, highOracle, oracleErr := routeBA2BFullOracle(word)
		if oracleErr != nil {
			return oracleErr
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*wordIndex + slot
			low, high := result.DecodedLowMSB[index], result.DecodedHighMSB[index]
			if !routeBFiniteFloat(low.Real) || !routeBFiniteFloat(low.Imag) ||
				!routeBFiniteFloat(high.Real) || !routeBFiniteFloat(high.Imag) {
				return lineagef("canonical full-A2B decoded slot %d is non-finite", index)
			}
			lowError := math.Abs(low.Real - lowOracle[slot])
			highError := math.Abs(high.Real - highOracle[slot])
			imaginary := math.Max(math.Abs(low.Imag), math.Abs(high.Imag))
			maxLowError = math.Max(maxLowError, lowError)
			maxHighError = math.Max(maxHighError, highError)
			maxImaginary = math.Max(maxImaginary, imaginary)
			if lowError > result.AccuracyTolerance || highError > result.AccuracyTolerance ||
				imaginary > result.AccuracyTolerance {
				mismatches++
			}
		}
	}
	if result.MaxLowAbsError != maxLowError || result.MaxHighAbsError != maxHighError ||
		result.MaxImaginaryAbs != maxImaginary || result.MismatchCount != mismatches || mismatches != 0 ||
		maxLowError > result.AccuracyTolerance || maxHighError > result.AccuracyTolerance ||
		maxImaginary > result.AccuracyTolerance {
		return lineagef("canonical full-A2B decoded accuracy ledger changed or failed")
	}
	return nil
}

// RunCanonicalRouteBL11A2BFull executes one complete one-process Route-B
// lifecycle and the capacity-authorized two-round Gao conversion.
func RunCanonicalRouteBL11A2BFull() (result RouteBCanonicalL11A2BFullResult, err error) {
	started := time.Now()
	before := dft.SnapshotMatrixConstructionCounters()
	authority, err := NewRouteBAuthority()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical full-A2B create Authority: %w", err)
	}
	releaseRouteBTransientHeap()
	buildSpec, buildPermit, err := authority.AuthorizeBuild()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical full-A2B AuthorizeBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	receipt, artifact, err := authority.BeginBuild(buildPermit)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical full-A2B BeginBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	readySpec, readyPermit, err := authority.AuthorizeReady(buildPermit, receipt, artifact)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical full-A2B AuthorizeReady: %w", err)
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
		return result, lineagef("canonical full-A2B secret-key generation returned nil")
	}

	ringZ, err := z2n.NewWithPrecision(z2n.Word8, 256)
	if err != nil {
		return result, err
	}
	inputSlots := make([]*bignum.Complex, 0, routeBA2BFirstRoundSlots)
	for _, word := range routeBA2BFirstRoundInputWords() {
		block, blockErr := ringZ.ToRootSlots(ringZ.ArithmeticEncode(word))
		if blockErr != nil {
			return result, fmt.Errorf("secureeval: encode canonical full-A2B root slots: %w", blockErr)
		}
		inputSlots = append(inputSlots, block...)
	}
	if len(inputSlots) != routeBA2BFirstRoundSlots {
		return result, lineagef("canonical full-A2B input slot count changed")
	}
	encoder := ckks.NewEncoder(parameters, 256)
	plaintext := ckks.NewPlaintext(parameters, parameters.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	if err = encoder.Encode(inputSlots, plaintext); err != nil {
		return result, fmt.Errorf("secureeval: encode canonical full-A2B input: %w", err)
	}
	encryptor := ckks.NewEncryptor(parameters, secretKey)
	input, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		return result, fmt.Errorf("secureeval: encrypt canonical full-A2B input: %w", err)
	}
	ringZ = nil
	inputSlots = nil
	plaintext = nil
	encoder = nil
	encryptor = nil
	releaseRouteBTransientHeap()

	installed, err := authority.Install(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical full-A2B Install: %w", err)
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
	fullResult, firstOperation, fullReport, err := installed.RunFirstSparseA2BFull(input)
	input = nil
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical Route-B full A2B: %w", err)
	}
	lowCiphertext, highCiphertext := fullResult.LowMSB(), fullResult.HighMSB()
	if lowCiphertext == nil || highCiphertext == nil {
		return result, lineagef("canonical full-A2B output ciphertext is nil")
	}
	postFullPeak, err := sampleProductionProcessPeakRSS()
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
	lowValues := make([]complex128, routeBA2BFirstRoundSlots)
	lowPlaintext := decryptor.DecryptNew(lowCiphertext)
	lowCiphertext = nil
	if err = decoder.Decode(lowPlaintext, lowValues); err != nil {
		return result, fmt.Errorf("secureeval: decode canonical full-A2B low MSB: %w", err)
	}
	lowPlaintext = nil
	highValues := make([]complex128, routeBA2BFirstRoundSlots)
	highPlaintext := decryptor.DecryptNew(highCiphertext)
	highCiphertext = nil
	if err = decoder.Decode(highPlaintext, highValues); err != nil {
		return result, fmt.Errorf("secureeval: decode canonical full-A2B high MSB: %w", err)
	}
	highPlaintext = nil
	decoder = nil
	decryptor = nil

	decodedLow := make([]RouteBComplexSample, routeBA2BFirstRoundSlots)
	decodedHigh := make([]RouteBComplexSample, routeBA2BFirstRoundSlots)
	maxLowError, maxHighError, maxImaginary := 0.0, 0.0, 0.0
	var mismatches uint64
	words := routeBA2BFirstRoundInputWords()
	for wordIndex, word := range words {
		lowOracle, highOracle, oracleErr := routeBA2BFullOracle(word)
		if oracleErr != nil {
			return result, oracleErr
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*wordIndex + slot
			lowValue, highValue := lowValues[index], highValues[index]
			decodedLow[index] = RouteBComplexSample{Real: real(lowValue), Imag: imag(lowValue)}
			decodedHigh[index] = RouteBComplexSample{Real: real(highValue), Imag: imag(highValue)}
			lowError := math.Abs(real(lowValue) - lowOracle[slot])
			highError := math.Abs(real(highValue) - highOracle[slot])
			imaginary := math.Max(math.Abs(imag(lowValue)), math.Abs(imag(highValue)))
			maxLowError = math.Max(maxLowError, lowError)
			maxHighError = math.Max(maxHighError, highError)
			maxImaginary = math.Max(maxImaginary, imaginary)
			if lowError > RouteBA2BFullAccuracyTolerance || highError > RouteBA2BFullAccuracyTolerance ||
				imaginary > RouteBA2BFullAccuracyTolerance {
				mismatches++
			}
		}
	}
	lowValues = nil
	highValues = nil
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
	result = RouteBCanonicalL11A2BFullResult{
		BuildSpec: buildSpec, BuildReceipt: receipt.Report(), ReadySpec: readySpec,
		FirstOperation: firstOperation, FullA2B: fullReport,
		BuildRuntime: receipt.RuntimeCapacityEvidence(), ReadyRuntime: readyPermit.RuntimeCapacityEvidence(),
		InstallRuntime: installRuntime,
		OverallConstructionDelta: [4]uint64{
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(),
		},
		PostInstallPeakRSSBytes: postInstallPeak, PostFullA2BPeakRSSBytes: postFullPeak,
		TotalWallNanoseconds: wall,
		InputWords:           routeBA2BFirstRoundWords, InputDistinctWords: 256, OutputSlots: routeBA2BFirstRoundSlots,
		InputPatternDigest: routeBA2BFullInputPatternDigest(),
		DecodedLowMSB:      decodedLow, DecodedHighMSB: decodedHigh,
		AccuracyTolerance: RouteBA2BFullAccuracyTolerance,
		MaxLowAbsError:    maxLowError, MaxHighAbsError: maxHighError,
		MaxImaginaryAbs: maxImaginary, MismatchCount: mismatches,
	}
	if err = result.Validate(); err != nil {
		return RouteBCanonicalL11A2BFullResult{}, err
	}
	return result, nil
}

func routeBA2BFullInputPatternDigest() string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBA2BFullInputSchema + "\x00"))
	var encoded [4]byte
	for index, word := range routeBA2BFirstRoundInputWords() {
		binary.LittleEndian.PutUint16(encoded[:2], uint16(index))
		binary.LittleEndian.PutUint16(encoded[2:], uint16(word))
		_, _ = hasher.Write(encoded[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func routeBA2BFullOracle(word uint64) (low [4]float64, high [4]float64, err error) {
	bits, err := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
	if err != nil {
		return low, high, err
	}
	for bit := 0; bit < 4; bit++ {
		low[bit] = float64(bits.Low[bit])
		high[bit] = float64(bits.High[bit])
	}
	return low, high, nil
}
