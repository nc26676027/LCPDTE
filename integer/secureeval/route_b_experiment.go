package secureeval

import (
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

// RouteBComplexSample is a JSON-safe decoded complex value.
type RouteBComplexSample struct {
	Real float64 `json:"real"`
	Imag float64 `json:"imag"`
}

// RouteBCanonicalL11MR0Result contains only inert records and measurements
// emitted after the one-process artifact has been retired.
type RouteBCanonicalL11MR0Result struct {
	BuildSpec      ArtifactBuildSpec          `json:"build_spec"`
	BuildReceipt   RBDFTBuildReceiptReport    `json:"build_receipt"`
	ReadySpec      ReadySpec                  `json:"ready_spec"`
	FirstOperation RouteBFirstOperationReport `json:"first_operation"`

	BuildRuntime   RuntimeCapacityEvidenceReport `json:"build_runtime"`
	ReadyRuntime   RuntimeCapacityEvidenceReport `json:"ready_runtime"`
	InstallRuntime RuntimeCapacityEvidenceReport `json:"install_runtime"`

	OverallConstructionDelta [4]uint64 `json:"overall_construction_delta"`
	PostInstallPeakRSSBytes  uint64    `json:"post_install_peak_rss_bytes"`
	PostMR0PeakRSSBytes      uint64    `json:"post_mr0_peak_rss_bytes"`
	TotalWallNanoseconds     uint64    `json:"total_wall_nanoseconds"`

	DecodedZeroSamples [8]RouteBComplexSample `json:"decoded_zero_samples"`
	DecodedZeroMaxAbs  float64                `json:"decoded_zero_max_abs"`
}

func (result RouteBCanonicalL11MR0Result) Validate() error {
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
	for operation, evidence := range map[string]RuntimeCapacityEvidenceReport{
		routeBRuntimeOperationBeginBuild:     result.BuildRuntime,
		routeBRuntimeOperationAuthorizeReady: result.ReadyRuntime,
		routeBRuntimeOperationInstall:        result.InstallRuntime,
	} {
		if err := evidence.Validate(); err != nil || evidence.Operation != operation {
			return lineagef("canonical experiment runtime evidence %q changed", operation)
		}
	}
	if result.OverallConstructionDelta != [4]uint64{0, 0, 0, 2} ||
		result.BuildReceipt.Payload != result.ReadySpec.ActualPayload ||
		result.BuildReceipt.Payload != result.FirstOperation.ResidentPayload ||
		result.BuildReceipt.ArtifactManifestDigest != result.ReadySpec.ArtifactPairManifestDigest ||
		result.BuildReceipt.ArtifactManifestDigest != result.FirstOperation.ArtifactPairManifestDigest ||
		result.BuildReceipt.BuildPeakRSSBytes == 0 || result.PostInstallPeakRSSBytes == 0 ||
		result.PostMR0PeakRSSBytes == 0 || result.TotalWallNanoseconds == 0 ||
		math.IsNaN(result.DecodedZeroMaxAbs) || math.IsInf(result.DecodedZeroMaxAbs, 0) ||
		result.DecodedZeroMaxAbs < 0 {
		return lineagef("canonical experiment counter, linkage, RSS, wall-time, or decoded diagnostic changed")
	}
	return nil
}

// RunCanonicalRouteBL11MR0 executes the complete one-process Route-B lifecycle:
// authorization, 256-bit factorwise build, Ready, input encryption, keygen and
// prebuilt installation, installed-resident preflight, observed sparse MR0,
// evaluator retirement, and only then diagnostic decryption.
func RunCanonicalRouteBL11MR0() (result RouteBCanonicalL11MR0Result, err error) {
	started := time.Now()
	before := dft.SnapshotMatrixConstructionCounters()
	authority, err := NewRouteBAuthority()
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, fmt.Errorf("secureeval: canonical Route-B create Authority: %w", err)
	}
	releaseRouteBTransientHeap()
	buildSpec, buildPermit, err := authority.AuthorizeBuild()
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, fmt.Errorf("secureeval: canonical Route-B AuthorizeBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	receipt, artifact, err := authority.BeginBuild(buildPermit)
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, fmt.Errorf("secureeval: canonical Route-B BeginBuild: %w", err)
	}
	releaseRouteBTransientHeap()
	readySpec, readyPermit, err := authority.AuthorizeReady(buildPermit, receipt, artifact)
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, fmt.Errorf("secureeval: canonical Route-B AuthorizeReady: %w", err)
	}
	releaseRouteBTransientHeap()

	raw, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, err
	}
	prepared, _, err := prepareGaoN16RouteBTransportParametersFromRaw(raw)
	raw = bootstrapping.Parameters{}
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, err
	}
	if err = validateGaoN16RouteBPreparedIdentity(prepared); err != nil {
		return RouteBCanonicalL11MR0Result{}, err
	}
	parameters := prepared.EffectiveParameters().BootstrappingParameters
	keyGenerator := rlwe.NewKeyGenerator(parameters)
	secretKey := keyGenerator.GenSecretKeyNew()
	keyGenerator = nil
	if secretKey == nil {
		return RouteBCanonicalL11MR0Result{}, lineagef("canonical experiment secret-key generation returned nil")
	}

	encoder := ckks.NewEncoder(parameters, 256)
	plaintext := ckks.NewPlaintext(parameters, parameters.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	zeroSlots := make([]complex128, 1<<11)
	if err = encoder.Encode(zeroSlots, plaintext); err != nil {
		return RouteBCanonicalL11MR0Result{}, fmt.Errorf("secureeval: encode canonical sparse zero input: %w", err)
	}
	encryptor := ckks.NewEncryptor(parameters, secretKey)
	input, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, fmt.Errorf("secureeval: encrypt canonical sparse zero input: %w", err)
	}
	zeroSlots = nil
	plaintext = nil
	encoder = nil
	encryptor = nil
	releaseRouteBTransientHeap()

	installed, err := authority.Install(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, fmt.Errorf("secureeval: canonical Route-B Install: %w", err)
	}
	releaseRouteBTransientHeap()
	postInstallPeak, err := sampleProductionProcessPeakRSS()
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, err
	}
	output, firstOperation, err := installed.RunFirstSparseMR0(input)
	input = nil
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, fmt.Errorf("secureeval: canonical Route-B first sparse MR0: %w", err)
	}
	postMR0Peak, err := sampleProductionProcessPeakRSS()
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, err
	}
	installRuntime := installed.InstallRuntimeCapacityEvidence()
	retireRouteBInstalledEvaluator(installed)
	installed = nil
	releaseRouteBTransientHeap()

	decryptor := ckks.NewDecryptor(parameters, secretKey)
	decodedPlaintext := decryptor.DecryptNew(output)
	output = nil
	decoder := ckks.NewEncoder(parameters, 256)
	decoded := make([]complex128, 1<<11)
	if err = decoder.Decode(decodedPlaintext, decoded); err != nil {
		return RouteBCanonicalL11MR0Result{}, fmt.Errorf("secureeval: decode canonical sparse MR0 output: %w", err)
	}
	var samples [8]RouteBComplexSample
	maxAbs := 0.0
	for index, value := range decoded {
		magnitude := math.Hypot(real(value), imag(value))
		if magnitude > maxAbs {
			maxAbs = magnitude
		}
		if index < len(samples) {
			samples[index] = RouteBComplexSample{Real: real(value), Imag: imag(value)}
		}
	}
	decoded = nil
	decodedPlaintext = nil
	decoder = nil
	decryptor = nil
	secretKey = nil
	prepared = bootstrapping.PreparedParameters{}

	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil {
		return RouteBCanonicalL11MR0Result{}, err
	}
	wall := uint64(time.Since(started).Nanoseconds())
	if wall == 0 {
		wall = 1
	}
	result = RouteBCanonicalL11MR0Result{
		BuildSpec: buildSpec, BuildReceipt: receipt.Report(), ReadySpec: readySpec,
		FirstOperation: firstOperation,
		BuildRuntime:   receipt.RuntimeCapacityEvidence(), ReadyRuntime: readyPermit.RuntimeCapacityEvidence(),
		InstallRuntime: installRuntime,
		OverallConstructionDelta: [4]uint64{
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(),
		},
		PostInstallPeakRSSBytes: postInstallPeak, PostMR0PeakRSSBytes: postMR0Peak,
		TotalWallNanoseconds: wall, DecodedZeroSamples: samples, DecodedZeroMaxAbs: maxAbs,
	}
	if err = result.Validate(); err != nil {
		return RouteBCanonicalL11MR0Result{}, err
	}
	return result, nil
}

func retireRouteBInstalledEvaluator(installed *RouteBInstalledEvaluator) {
	if installed == nil || installed.cell == nil {
		return
	}
	installed.cell.operationMu.Lock()
	defer installed.cell.operationMu.Unlock()
	clearRouteBInstalledEvaluatorCell(installed.cell)
}

func releaseRouteBTransientHeap() {
	runtime.GC()
	debug.FreeOSMemory()
}
