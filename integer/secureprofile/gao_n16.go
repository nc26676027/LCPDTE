// Package secureprofile binds an exact CKKS parameter candidate to the static
// level/scale topology required by the secure Gao--Zheng port. A Profile is
// parameter evidence only: it cannot attest circuit correctness or security.
package secureprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"

	"dt_go/integer/securityparams"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// Maturity is deliberately closed to the only status this parameter-only
// module can issue. Later circuit/security promotion belongs to a separate
// verifier that consumes runtime evidence.
type Maturity string

const (
	ParameterCandidateUnverified Maturity = "parameter_candidate_unverified"
	gaoN16WordBits                        = 8
	gaoN16LogMessageRatio                 = 0
)

// ExactRatio records a positive rational without float or pointer aliasing.
type ExactRatio struct {
	NumeratorDecimal   string `json:"numerator_decimal"`
	DenominatorDecimal string `json:"denominator_decimal"`
}

// CircuitTopology is the static level contract to be proved by later
// encrypted gates. Recording it here does not claim that those gates exist.
type CircuitTopology struct {
	RefreshInputLevel              int `json:"refresh_input_level"`
	RefreshOutputLevel             int `json:"refresh_output_level"`
	KernelInputLevel               int `json:"kernel_input_level"`
	KernelOutputLevel              int `json:"kernel_output_level"`
	BooleanToArithmeticOutputLevel int `json:"boolean_to_arithmetic_output_level"`
	SelectOutputLevel              int `json:"select_output_level"`
}

// Profile is immutable to callers: every slice is returned by defensive copy
// and all scalar fields participate in its deterministic digest.
type Profile struct {
	tupleID             string
	manifestDigest      string
	parameterDigest     string
	maturity            Maturity
	logN                int
	slots               int
	wordBits            int
	wordCapacity        int
	logDefaultScale     int
	qCount              int
	pCount              int
	logMessageRatio     int
	scaleDownCorrection ExactRatio
	topology            CircuitTopology
	mainSecretWeight    int
	ephemeralWeight     int
	errorSigma          float64
	errorBound          float64
	missingEvidence     []string
	digest              string
}

type digestRecord struct {
	SchemaVersion       string          `json:"schema_version"`
	TupleID             string          `json:"tuple_id"`
	ManifestDigest      string          `json:"manifest_digest"`
	ParameterDigest     string          `json:"parameter_digest"`
	Maturity            Maturity        `json:"maturity"`
	LogN                int             `json:"log_n"`
	Slots               int             `json:"slots"`
	WordBits            int             `json:"word_bits"`
	WordCapacity        int             `json:"word_capacity"`
	LogDefaultScale     int             `json:"log_default_scale"`
	QCount              int             `json:"q_count"`
	PCount              int             `json:"p_count"`
	LogMessageRatio     int             `json:"log_message_ratio"`
	ScaleDownCorrection ExactRatio      `json:"scale_down_correction"`
	Topology            CircuitTopology `json:"topology"`
	MainSecretWeight    int             `json:"main_secret_weight"`
	EphemeralWeight     int             `json:"ephemeral_weight"`
	ErrorSigma          float64         `json:"error_sigma"`
	ErrorBound          float64         `json:"error_bound"`
	MissingEvidence     []string        `json:"missing_evidence"`
}

// NewGaoN16 admits only the exact deterministic candidate authenticated by
// securityparams. Aggregate-compatible or merely shape-compatible parameters
// are rejected.
func NewGaoN16(params ckks.Parameters) (Profile, error) {
	expected, err := securityparams.GaoCompatibleN16Parameters()
	if err != nil {
		return Profile{}, fmt.Errorf("secureprofile: construct exact Gao-compatible parameters: %w", err)
	}
	if !params.Equal(&expected) {
		return Profile{}, fmt.Errorf("secureprofile: parameters do not equal %s", securityparams.GaoCompatibleTupleID)
	}

	manifest, err := securityparams.GaoCompatibleN16Manifest()
	if err != nil {
		return Profile{}, fmt.Errorf("secureprofile: construct exact parameter manifest: %w", err)
	}
	if manifest.EstimatorEligible || manifest.Status != "PENDING-IMPLEMENTATION/PENDING-ESTIMATOR" || len(manifest.MissingEvidence) == 0 {
		return Profile{}, fmt.Errorf("secureprofile: parameter manifest maturity drifted")
	}
	if manifest.CanonicalJSONSHA256 != securityparams.GaoCompatibleManifestDigest {
		return Profile{}, fmt.Errorf("secureprofile: parameter manifest digest drifted")
	}
	manifestJSON, err := securityparams.CanonicalJSON(manifest)
	if err != nil {
		return Profile{}, fmt.Errorf("secureprofile: authenticate parameter manifest: %w", err)
	}
	manifestFileDigest := sha256.Sum256(manifestJSON)
	if got := hex.EncodeToString(manifestFileDigest[:]); got != "4ca0e01e74271e889b233cfd729b8f45894e37fca2018fbc4cf173a1c4542882" {
		return Profile{}, fmt.Errorf("secureprofile: canonical manifest file digest drifted: %s", got)
	}

	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return Profile{}, fmt.Errorf("secureprofile: marshal exact parameters: %w", err)
	}
	parameterSum := sha256.Sum256(parameterBytes)

	defaultScale := new(big.Int).Lsh(big.NewInt(1), uint(params.LogDefaultScale()))
	q0 := new(big.Int).SetUint64(params.Q()[0])
	profile := Profile{
		tupleID:         manifest.TupleID,
		manifestDigest:  manifest.CanonicalJSONSHA256,
		parameterDigest: hex.EncodeToString(parameterSum[:]),
		maturity:        ParameterCandidateUnverified,
		logN:            params.LogN(),
		slots:           params.MaxSlots(),
		wordBits:        gaoN16WordBits,
		wordCapacity:    params.MaxSlots() / (gaoN16WordBits / 2),
		logDefaultScale: params.LogDefaultScale(),
		qCount:          len(params.Q()),
		pCount:          len(params.P()),
		logMessageRatio: gaoN16LogMessageRatio,
		scaleDownCorrection: ExactRatio{
			NumeratorDecimal: defaultScale.String(), DenominatorDecimal: q0.String(),
		},
		topology: CircuitTopology{
			RefreshInputLevel: params.MaxLevel(), RefreshOutputLevel: 17,
			KernelInputLevel: 17, KernelOutputLevel: 5,
			BooleanToArithmeticOutputLevel: 4, SelectOutputLevel: 3,
		},
		mainSecretWeight: securityparams.GaoCompatibleMainWeight,
		ephemeralWeight:  securityparams.GaoCompatibleEphemeralH,
		errorSigma:       securityparams.GaoCompatibleSigma,
		errorBound:       securityparams.GaoCompatibleBound,
		missingEvidence:  append([]string(nil), manifest.MissingEvidence...),
	}
	if profile.ScaleDownCorrectionAbsLog2() <= 0 || profile.ScaleDownCorrectionAbsLog2() >= 1e-6 {
		return Profile{}, fmt.Errorf("secureprofile: q0/default-scale correction exceeds the MR0 admission bound")
	}
	profile.digest, err = digestProfile(profile)
	if err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func (p Profile) TupleID() string                 { return p.tupleID }
func (p Profile) ManifestDigest() string          { return p.manifestDigest }
func (p Profile) ParameterDigest() string         { return p.parameterDigest }
func (p Profile) Maturity() Maturity              { return p.maturity }
func (p Profile) LogN() int                       { return p.logN }
func (p Profile) Slots() int                      { return p.slots }
func (p Profile) WordBits() int                   { return p.wordBits }
func (p Profile) WordCapacity() int               { return p.wordCapacity }
func (p Profile) LogDefaultScale() int            { return p.logDefaultScale }
func (p Profile) QCount() int                     { return p.qCount }
func (p Profile) PCount() int                     { return p.pCount }
func (p Profile) LogMessageRatio() int            { return p.logMessageRatio }
func (p Profile) ScaleDownCorrection() ExactRatio { return p.scaleDownCorrection }
func (p Profile) Topology() CircuitTopology       { return p.topology }
func (p Profile) Digest() string                  { return p.digest }

// MissingEvidence returns a defensive copy so callers cannot promote or edit
// the parameter-only evidence boundary.
func (p Profile) MissingEvidence() []string {
	return append([]string(nil), p.missingEvidence...)
}

// ScaleDownCorrectionAbsLog2 reports |log2(2^43/q0)| for the exact first Q
// prime. The exact rational, not this diagnostic float, is digested.
func (p Profile) ScaleDownCorrectionAbsLog2() float64 {
	numerator, okNumerator := new(big.Int).SetString(p.scaleDownCorrection.NumeratorDecimal, 10)
	denominator, okDenominator := new(big.Int).SetString(p.scaleDownCorrection.DenominatorDecimal, 10)
	if !okNumerator || !okDenominator || numerator.Sign() <= 0 || denominator.Sign() <= 0 {
		return math.Inf(1)
	}
	numeratorFloat, _ := new(big.Float).SetInt(numerator).Float64()
	denominatorFloat, _ := new(big.Float).SetInt(denominator).Float64()
	return math.Abs(math.Log2(numeratorFloat / denominatorFloat))
}

// ValidateParameters rechecks both the supplied exact candidate and the
// profile's deterministic self-digest.
func (p Profile) ValidateParameters(params ckks.Parameters) error {
	expected, err := NewGaoN16(params)
	if err != nil {
		return err
	}
	if p.digest == "" || p.digest != expected.digest {
		return fmt.Errorf("secureprofile: profile digest or state differs from the exact candidate")
	}
	return nil
}

func digestProfile(profile Profile) (string, error) {
	record := digestRecord{
		SchemaVersion: "secure-n16-parameter-profile-v1",
		TupleID:       profile.tupleID, ManifestDigest: profile.manifestDigest,
		ParameterDigest: profile.parameterDigest, Maturity: profile.maturity,
		LogN: profile.logN, Slots: profile.slots, WordBits: profile.wordBits,
		WordCapacity: profile.wordCapacity, LogDefaultScale: profile.logDefaultScale,
		QCount: profile.qCount, PCount: profile.pCount, LogMessageRatio: profile.logMessageRatio,
		ScaleDownCorrection: profile.scaleDownCorrection, Topology: profile.topology,
		MainSecretWeight: profile.mainSecretWeight, EphemeralWeight: profile.ephemeralWeight,
		ErrorSigma: profile.errorSigma, ErrorBound: profile.errorBound,
		MissingEvidence: append([]string(nil), profile.missingEvidence...),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("secureprofile: marshal profile digest record: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
