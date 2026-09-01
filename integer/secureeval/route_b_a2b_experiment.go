package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

const (
	routeBA2BFirstRoundInputSchema       = "lcpdte-route-b-a2b-first-round-input-v1"
	RouteBA2BFirstRoundAccuracyTolerance = 5e-4
)

// RouteBCanonicalL11A2BFirstRoundResult contains inert lifecycle evidence and
// every decoded ID/MSB slot for the canonical 512-word first-round gate.
// It does not claim the second nibble round or a complete 8-bit A2B.
type RouteBCanonicalL11A2BFirstRoundResult struct {
	BuildSpec      ArtifactBuildSpec             `json:"build_spec"`
	BuildReceipt   RBDFTBuildReceiptReport       `json:"build_receipt"`
	ReadySpec      ReadySpec                     `json:"ready_spec"`
	FirstOperation RouteBFirstOperationReport    `json:"first_operation"`
	FirstRound     RouteBA2BFirstRoundReport     `json:"first_round"`
	BuildRuntime   RuntimeCapacityEvidenceReport `json:"build_runtime"`
	ReadyRuntime   RuntimeCapacityEvidenceReport `json:"ready_runtime"`
	InstallRuntime RuntimeCapacityEvidenceReport `json:"install_runtime"`

	OverallConstructionDelta   [4]uint64 `json:"overall_construction_delta"`
	PostInstallPeakRSSBytes    uint64    `json:"post_install_peak_rss_bytes"`
	PostFirstRoundPeakRSSBytes uint64    `json:"post_first_round_peak_rss_bytes"`
	TotalWallNanoseconds       uint64    `json:"total_wall_nanoseconds"`

	InputWords         uint32 `json:"input_words"`
	InputDistinctWords uint32 `json:"input_distinct_words"`
	OutputSlots        uint32 `json:"output_slots"`
	InputPatternDigest string `json:"input_pattern_digest"`

	DecodedIdentity []RouteBComplexSample `json:"decoded_identity"`
	DecodedMSB      []RouteBComplexSample `json:"decoded_msb"`

	AccuracyTolerance   float64 `json:"accuracy_tolerance"`
	MaxIdentityAbsError float64 `json:"max_identity_abs_error"`
	MaxMSBAbsError      float64 `json:"max_msb_abs_error"`
	MaxImaginaryAbs     float64 `json:"max_imaginary_abs"`
	MismatchCount       uint64  `json:"mismatch_count"`
}

func (result RouteBCanonicalL11A2BFirstRoundResult) Validate() error {
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
	if err := result.FirstRound.Validate(); err != nil {
		return err
	}
	for operation, evidence := range map[string]RuntimeCapacityEvidenceReport{
		routeBRuntimeOperationBeginBuild:     result.BuildRuntime,
		routeBRuntimeOperationAuthorizeReady: result.ReadyRuntime,
		routeBRuntimeOperationInstall:        result.InstallRuntime,
	} {
		if err := evidence.Validate(); err != nil || evidence.Operation != operation {
			return lineagef("canonical first-A2B-round runtime evidence %q changed", operation)
		}
	}
	capacityPlanIdentity, err := decodeRBAUTHHexDigest("Route-B first-A2B-round capacity plan", result.FirstRound.CapacityPlanDigest)
	if err != nil {
		return err
	}
	if result.FirstOperation.RuntimeCapacity.Operation != routeBRuntimeOperationA2BFirstRound ||
		result.FirstOperation.RuntimeCapacity.Capacity.CapacityPlanDigest != capacityPlanIdentity ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 2} ||
		result.BuildReceipt.Payload != result.ReadySpec.ActualPayload ||
		result.BuildReceipt.Payload != result.FirstOperation.ResidentPayload ||
		result.BuildReceipt.ArtifactManifestDigest != result.ReadySpec.ArtifactPairManifestDigest ||
		result.BuildReceipt.ArtifactManifestDigest != result.FirstOperation.ArtifactPairManifestDigest ||
		result.BuildReceipt.BuildPeakRSSBytes == 0 || result.PostInstallPeakRSSBytes == 0 ||
		result.PostFirstRoundPeakRSSBytes < result.PostInstallPeakRSSBytes || result.TotalWallNanoseconds == 0 {
		return lineagef("canonical first-A2B-round linkage, construction counter, RSS, or wall-time changed")
	}
	if result.InputWords != routeBA2BFirstRoundWords || result.InputDistinctWords != 256 ||
		result.OutputSlots != routeBA2BFirstRoundSlots ||
		result.InputPatternDigest != routeBA2BFirstRoundInputPatternDigest() ||
		len(result.DecodedIdentity) != routeBA2BFirstRoundSlots ||
		len(result.DecodedMSB) != routeBA2BFirstRoundSlots ||
		result.AccuracyTolerance != RouteBA2BFirstRoundAccuracyTolerance {
		return lineagef("canonical first-A2B-round input, output, or tolerance shape changed")
	}

	maxIdentityError, maxMSBError, maxImaginary := 0.0, 0.0, 0.0
	var mismatches uint64
	for wordIndex, word := range routeBA2BFirstRoundInputWords() {
		identityOracle, msbOracle, oracleErr := routeBA2BFirstRoundOracle(word)
		if oracleErr != nil {
			return oracleErr
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*wordIndex + slot
			identity := result.DecodedIdentity[index]
			msb := result.DecodedMSB[index]
			if !routeBFiniteFloat(identity.Real) || !routeBFiniteFloat(identity.Imag) ||
				!routeBFiniteFloat(msb.Real) || !routeBFiniteFloat(msb.Imag) {
				return lineagef("canonical first-A2B-round decoded slot %d is non-finite", index)
			}
			identityError := math.Abs(identity.Real - identityOracle[slot])
			msbError := math.Abs(msb.Real - msbOracle[slot])
			imaginary := math.Max(math.Abs(identity.Imag), math.Abs(msb.Imag))
			maxIdentityError = math.Max(maxIdentityError, identityError)
			maxMSBError = math.Max(maxMSBError, msbError)
			maxImaginary = math.Max(maxImaginary, imaginary)
			if identityError > result.AccuracyTolerance || msbError > result.AccuracyTolerance ||
				imaginary > result.AccuracyTolerance {
				mismatches++
			}
		}
	}
	if result.MaxIdentityAbsError != maxIdentityError || result.MaxMSBAbsError != maxMSBError ||
		result.MaxImaginaryAbs != maxImaginary || result.MismatchCount != mismatches || mismatches != 0 ||
		maxIdentityError > result.AccuracyTolerance || maxMSBError > result.AccuracyTolerance ||
		maxImaginary > result.AccuracyTolerance {
		return lineagef("canonical first-A2B-round decoded accuracy ledger changed or failed")
	}
	return nil
}

// RunCanonicalRouteBL11A2BFirstRound executes one complete one-process
// Route-B lifecycle and the capacity-authorized low-nibble Gao A2B round.
func RunCanonicalRouteBL11A2BFirstRound() (result RouteBCanonicalL11A2BFirstRoundResult, err error) {
	started := time.Now()
	before := dft.SnapshotMatrixConstructionCounters()
	authority, err := NewRouteBAuthority()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical first-A2B-round create Authority: %w", err)
	}
	releaseRouteBTransientHeap()
	buildSpec, buildPermit, err := authority.AuthorizeBuild()
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical first-A2B-round AuthorizeBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	receipt, artifact, err := authority.BeginBuild(buildPermit)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical first-A2B-round BeginBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	readySpec, readyPermit, err := authority.AuthorizeReady(buildPermit, receipt, artifact)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical first-A2B-round AuthorizeReady: %w", err)
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
		return result, lineagef("canonical first-A2B-round secret-key generation returned nil")
	}

	ringZ, err := z2n.NewWithPrecision(z2n.Word8, 256)
	if err != nil {
		return result, err
	}
	inputSlots := make([]*bignum.Complex, 0, routeBA2BFirstRoundSlots)
	for _, word := range routeBA2BFirstRoundInputWords() {
		block, blockErr := ringZ.ToRootSlots(ringZ.ArithmeticEncode(word))
		if blockErr != nil {
			return result, fmt.Errorf("secureeval: encode canonical first-A2B-round root slots: %w", blockErr)
		}
		inputSlots = append(inputSlots, block...)
	}
	if len(inputSlots) != routeBA2BFirstRoundSlots {
		return result, lineagef("canonical first-A2B-round input slot count changed")
	}
	encoder := ckks.NewEncoder(parameters, 256)
	plaintext := ckks.NewPlaintext(parameters, parameters.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	if err = encoder.Encode(inputSlots, plaintext); err != nil {
		return result, fmt.Errorf("secureeval: encode canonical first-A2B-round input: %w", err)
	}
	encryptor := ckks.NewEncryptor(parameters, secretKey)
	input, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		return result, fmt.Errorf("secureeval: encrypt canonical first-A2B-round input: %w", err)
	}
	ringZ = nil
	inputSlots = nil
	plaintext = nil
	encoder = nil
	encryptor = nil
	releaseRouteBTransientHeap()

	installed, err := authority.Install(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical first-A2B-round Install: %w", err)
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
	roundResult, firstOperation, firstRound, err := installed.RunFirstSparseA2BFirstRound(input)
	input = nil
	if err != nil {
		return result, fmt.Errorf("secureeval: canonical Route-B first A2B round: %w", err)
	}
	identityCiphertext := roundResult.IDCiphertext()
	msbCiphertext := roundResult.MSBCiphertext()
	if identityCiphertext == nil || msbCiphertext == nil {
		return result, lineagef("canonical first-A2B-round output ciphertext is nil")
	}
	postFirstRoundPeak, err := sampleProductionProcessPeakRSS()
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
	identityValues := make([]complex128, routeBA2BFirstRoundSlots)
	identityPlaintext := decryptor.DecryptNew(identityCiphertext)
	identityCiphertext = nil
	if err = decoder.Decode(identityPlaintext, identityValues); err != nil {
		return result, fmt.Errorf("secureeval: decode canonical first-A2B-round ID: %w", err)
	}
	identityPlaintext = nil
	msbValues := make([]complex128, routeBA2BFirstRoundSlots)
	msbPlaintext := decryptor.DecryptNew(msbCiphertext)
	msbCiphertext = nil
	if err = decoder.Decode(msbPlaintext, msbValues); err != nil {
		return result, fmt.Errorf("secureeval: decode canonical first-A2B-round MSB: %w", err)
	}
	msbPlaintext = nil
	decoder = nil
	decryptor = nil

	decodedIdentity := make([]RouteBComplexSample, routeBA2BFirstRoundSlots)
	decodedMSB := make([]RouteBComplexSample, routeBA2BFirstRoundSlots)
	maxIdentityError, maxMSBError, maxImaginary := 0.0, 0.0, 0.0
	var mismatches uint64
	words := routeBA2BFirstRoundInputWords()
	for wordIndex, word := range words {
		identityOracle, msbOracle, oracleErr := routeBA2BFirstRoundOracle(word)
		if oracleErr != nil {
			return result, oracleErr
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*wordIndex + slot
			identityValue, msbValue := identityValues[index], msbValues[index]
			decodedIdentity[index] = RouteBComplexSample{Real: real(identityValue), Imag: imag(identityValue)}
			decodedMSB[index] = RouteBComplexSample{Real: real(msbValue), Imag: imag(msbValue)}
			identityError := math.Abs(real(identityValue) - identityOracle[slot])
			msbError := math.Abs(real(msbValue) - msbOracle[slot])
			imaginary := math.Max(math.Abs(imag(identityValue)), math.Abs(imag(msbValue)))
			maxIdentityError = math.Max(maxIdentityError, identityError)
			maxMSBError = math.Max(maxMSBError, msbError)
			maxImaginary = math.Max(maxImaginary, imaginary)
			if identityError > RouteBA2BFirstRoundAccuracyTolerance ||
				msbError > RouteBA2BFirstRoundAccuracyTolerance ||
				imaginary > RouteBA2BFirstRoundAccuracyTolerance {
				mismatches++
			}
		}
	}
	identityValues = nil
	msbValues = nil
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
	result = RouteBCanonicalL11A2BFirstRoundResult{
		BuildSpec: buildSpec, BuildReceipt: receipt.Report(), ReadySpec: readySpec,
		FirstOperation: firstOperation, FirstRound: firstRound,
		BuildRuntime: receipt.RuntimeCapacityEvidence(), ReadyRuntime: readyPermit.RuntimeCapacityEvidence(),
		InstallRuntime: installRuntime,
		OverallConstructionDelta: [4]uint64{
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(),
		},
		PostInstallPeakRSSBytes: postInstallPeak, PostFirstRoundPeakRSSBytes: postFirstRoundPeak,
		TotalWallNanoseconds: wall,
		InputWords:           routeBA2BFirstRoundWords, InputDistinctWords: 256, OutputSlots: routeBA2BFirstRoundSlots,
		InputPatternDigest: routeBA2BFirstRoundInputPatternDigest(),
		DecodedIdentity:    decodedIdentity, DecodedMSB: decodedMSB,
		AccuracyTolerance:   RouteBA2BFirstRoundAccuracyTolerance,
		MaxIdentityAbsError: maxIdentityError, MaxMSBAbsError: maxMSBError,
		MaxImaginaryAbs: maxImaginary, MismatchCount: mismatches,
	}
	if err = result.Validate(); err != nil {
		return RouteBCanonicalL11A2BFirstRoundResult{}, err
	}
	return result, nil
}

func routeBA2BFirstRoundInputWords() []uint64 {
	words := make([]uint64, routeBA2BFirstRoundWords)
	for index := range words {
		words[index] = uint64(index & 255)
	}
	return words
}

func routeBA2BFirstRoundInputPatternDigest() string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(routeBA2BFirstRoundInputSchema + "\x00"))
	var encoded [4]byte
	for index, word := range routeBA2BFirstRoundInputWords() {
		binary.LittleEndian.PutUint16(encoded[:2], uint16(index))
		binary.LittleEndian.PutUint16(encoded[2:], uint16(word))
		_, _ = hasher.Write(encoded[:])
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func routeBA2BFirstRoundOracle(word uint64) (identity [4]float64, msb [4]float64, err error) {
	bits, err := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
	if err != nil {
		return identity, msb, err
	}
	for slot := 0; slot < 4; slot++ {
		var prefix uint64
		for offset := 0; offset <= slot; offset++ {
			prefix += uint64(bits.Low[slot-offset]) << uint(3-offset)
		}
		code := (16 - prefix) & 15
		value, lutErr := z2n.A2BTwoLUTOracle(code, 4)
		if lutErr != nil {
			return identity, msb, lutErr
		}
		if value.MSB != bits.Low[slot] {
			return identity, msb, lineagef("first-A2B-round oracle MSB differs from low bit")
		}
		identity[slot], _ = value.ID.Float64()
		msb[slot] = float64(value.MSB)
	}
	return identity, msb, nil
}

func routeBFiniteFloat(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}
