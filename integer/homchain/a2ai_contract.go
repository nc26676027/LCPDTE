package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	ckksdft "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

// ExactScaleSnapshot is an immutable audit representation of an rlwe.Scale.
// It stores the floating-point value in exact hexadecimal form together with
// its precision, rounding mode and optional modulus. Accessors reconstruct
// detached big-number values, so copying or inspecting a snapshot cannot
// alias ciphertext metadata.
type ExactScaleSnapshot struct {
	valueHex string
	prec     uint
	mode     big.RoundingMode
	modulus  string
	hasMod   bool
}

// NewExactScaleSnapshot takes a deep, immutable snapshot of a strictly
// positive CKKS/RLWE scale.
func NewExactScaleSnapshot(scale rlwe.Scale) (ExactScaleSnapshot, error) {
	if scale.Value.Prec() == 0 {
		return ExactScaleSnapshot{}, fmt.Errorf("homchain: cannot snapshot an uninitialized scale")
	}
	if scale.Value.IsInf() {
		return ExactScaleSnapshot{}, fmt.Errorf("homchain: cannot snapshot an infinite scale")
	}
	if scale.Value.Sign() <= 0 {
		return ExactScaleSnapshot{}, fmt.Errorf("homchain: cannot snapshot a non-positive scale")
	}
	result := ExactScaleSnapshot{
		valueHex: scale.Value.Text('x', -1),
		prec:     scale.Value.Prec(),
		mode:     scale.Value.Mode(),
	}
	if scale.Mod != nil {
		result.hasMod = true
		result.modulus = scale.Mod.String()
	}
	return result, nil
}

// Scale reconstructs a detached rlwe.Scale with the exact snapshotted
// precision, rounding mode and modulus.
func (s ExactScaleSnapshot) Scale() (rlwe.Scale, error) {
	if s.valueHex == "" || s.prec == 0 {
		return rlwe.Scale{}, fmt.Errorf("homchain: uninitialized exact scale snapshot")
	}
	value, _, err := big.ParseFloat(s.valueHex, 0, s.prec, s.mode)
	if err != nil {
		return rlwe.Scale{}, fmt.Errorf("homchain: parse exact scale snapshot: %w", err)
	}
	result := rlwe.Scale{Value: *value}
	if s.hasMod {
		result.Mod = new(big.Int)
		if _, ok := result.Mod.SetString(s.modulus, 10); !ok {
			return rlwe.Scale{}, fmt.Errorf("homchain: parse exact scale modulus")
		}
	}
	return result, nil
}

// Equal reports whether two immutable snapshots encode identical scale
// metadata and numeric values.
func (s ExactScaleSnapshot) Equal(other ExactScaleSnapshot) bool {
	return s.valueHex == other.valueHex && s.prec == other.prec && s.mode == other.mode &&
		s.hasMod == other.hasMod && s.modulus == other.modulus
}

// EqualScale reports whether scale is exactly represented by this snapshot.
func (s ExactScaleSnapshot) EqualScale(scale rlwe.Scale) bool {
	other, err := NewExactScaleSnapshot(scale)
	return err == nil && s.Equal(other)
}

// Precision returns the snapshotted big.Float precision.
func (s ExactScaleSnapshot) Precision() uint { return s.prec }

// ValueHex returns the exact immutable hexadecimal floating-point value.
func (s ExactScaleSnapshot) ValueHex() string { return s.valueHex }

// RoundingMode returns the snapshotted big.Float rounding mode.
func (s ExactScaleSnapshot) RoundingMode() big.RoundingMode { return s.mode }

// Modulus returns a detached copy of the optional scale modulus.
func (s ExactScaleSnapshot) Modulus() *big.Int {
	if !s.hasMod {
		return nil
	}
	result := new(big.Int)
	result.SetString(s.modulus, 10)
	return result
}

// HasMod reports whether the snapshotted scale has modular semantics.
func (s ExactScaleSnapshot) HasMod() bool { return s.hasMod }

// MarshalJSON exposes a complete immutable audit projection instead of the
// empty object that Go would produce for this type's private storage.
func (s ExactScaleSnapshot) MarshalJSON() ([]byte, error) {
	if s.valueHex == "" && s.prec == 0 {
		return []byte("null"), nil
	}
	if _, err := s.Scale(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ValueHex     string `json:"value_hex"`
		Precision    uint   `json:"precision"`
		RoundingMode uint8  `json:"rounding_mode"`
		HasMod       bool   `json:"has_mod"`
		Modulus      string `json:"modulus,omitempty"`
	}{
		ValueHex: s.valueHex, Precision: s.prec, RoundingMode: uint8(s.mode),
		HasMod: s.hasMod, Modulus: s.modulus,
	})
}

// UnmarshalJSON restores an immutable exact-scale audit projection.
func (s *ExactScaleSnapshot) UnmarshalJSON(data []byte) error {
	if s == nil {
		return fmt.Errorf("homchain: nil exact scale snapshot receiver")
	}
	if string(data) == "null" {
		*s = ExactScaleSnapshot{}
		return nil
	}
	var encoded struct {
		ValueHex     string `json:"value_hex"`
		Precision    uint   `json:"precision"`
		RoundingMode uint8  `json:"rounding_mode"`
		HasMod       bool   `json:"has_mod"`
		Modulus      string `json:"modulus"`
	}
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("homchain: decode exact scale snapshot: %w", err)
	}
	mode := big.RoundingMode(encoded.RoundingMode)
	if !validRoundingMode(mode) {
		return fmt.Errorf("homchain: invalid exact scale rounding mode %d", encoded.RoundingMode)
	}
	candidate := ExactScaleSnapshot{
		valueHex: encoded.ValueHex, prec: encoded.Precision, mode: mode,
		hasMod: encoded.HasMod, modulus: encoded.Modulus,
	}
	reconstructed, err := candidate.Scale()
	if err != nil {
		return err
	}
	if reconstructed.Value.Sign() <= 0 || reconstructed.Value.IsInf() {
		return fmt.Errorf("homchain: invalid exact scale value")
	}
	if encoded.HasMod && (reconstructed.Mod == nil || reconstructed.Mod.Sign() <= 0) {
		return fmt.Errorf("homchain: invalid exact scale modulus")
	}
	*s = candidate
	return nil
}

func validRoundingMode(mode big.RoundingMode) bool {
	switch mode {
	case big.ToNearestEven, big.ToNearestAway, big.ToZero, big.AwayFromZero, big.ToNegativeInf, big.ToPositiveInf:
		return true
	default:
		return false
	}
}

func (s ExactScaleSnapshot) canonicalString() string {
	return fmt.Sprintf("prec=%d;mode=%d;value=%s;has-mod=%t;mod=%s", s.prec, s.mode, s.valueHex, s.hasMod, s.modulus)
}

// A2AIDeltaSemantics identifies what an exact Delta snapshot means. The first
// slice admits only a Gao arithmetic input representative f+I; the certificate
// is checked against the input ciphertext's exact scale before any transform.
type A2AIDeltaSemantics string

const (
	A2AIDeltaGaoArithmeticInput A2AIDeltaSemantics = "gao-arithmetic-input-f-plus-I"
)

// A2AIEvidenceVerificationStatus states what this package knows about the
// centered-message argument. An inline caller artifact is not an attestation:
// until a controlled verifier exists it remains explicitly unverified.
type A2AIEvidenceVerificationStatus string

const (
	A2AIEvidenceExternalUnverified A2AIEvidenceVerificationStatus = "external_unverified"
)

// A2AIEvidenceMaturityStatus records the maturity of the evidence. Caller
// input cannot promote this status beyond the functional, non-secure slice.
type A2AIEvidenceMaturityStatus string

const (
	A2AIEvidenceFunctionalNotSecure A2AIEvidenceMaturityStatus = "functional_not_secure"
)

// A2AICenteredBoundUnit fixes the unit used by CenteredMessageBound.
type A2AICenteredBoundUnit string

const (
	// A2AICenteredCoefficientInfinityNorm means max_i |m_i| for the centered
	// integer coefficients of the coefficient-domain RLWE message.
	A2AICenteredCoefficientInfinityNorm A2AICenteredBoundUnit = "centered_integer_coefficient_linf"
)

// A2AICenteredBoundDomain fixes the exact operation boundary at which the
// centered-message bound is claimed to hold.
type A2AICenteredBoundDomain string

const (
	A2AIBoundBeforeGuardedScaleDown A2AICenteredBoundDomain = "after_slots_to_coeffs_before_guarded_scaledown"
)

// A2AIAdmissionRequest is mutable construction input. The resulting
// A2AIAdmissionCertificate owns immutable copies of every field.
type A2AIAdmissionRequest struct {
	Delta                rlwe.Scale
	DeltaSemantics       A2AIDeltaSemantics
	CenteredMessageBound *big.Int
	CenteredBoundUnit    A2AICenteredBoundUnit
	CenteredBoundDomain  A2AICenteredBoundDomain
	EvidenceArtifact     string
	EvidenceDigest       string
	VerificationStatus   A2AIEvidenceVerificationStatus
	MaturityStatus       A2AIEvidenceMaturityStatus
}

// A2AIAdmissionCertificate binds an exact arithmetic-input Delta and a
// positive centered-message bound to an integrity-checked external artifact.
// It deliberately does not claim that this package verified the mathematical
// range proof contained in that artifact.
type A2AIAdmissionCertificate struct {
	delta               ExactScaleSnapshot
	deltaSemantics      A2AIDeltaSemantics
	centeredBound       string
	centeredBoundUnit   A2AICenteredBoundUnit
	centeredBoundDomain A2AICenteredBoundDomain
	evidenceArtifact    string
	evidenceDigest      string
	verificationStatus  A2AIEvidenceVerificationStatus
	maturityStatus      A2AIEvidenceMaturityStatus
	digest              string
}

// NewA2AIAdmissionCertificate validates and takes immutable ownership of an
// A2A-I admission request.
func NewA2AIAdmissionCertificate(request A2AIAdmissionRequest) (A2AIAdmissionCertificate, error) {
	if request.DeltaSemantics != A2AIDeltaGaoArithmeticInput {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: unsupported A2A-I Delta semantics %q", request.DeltaSemantics)
	}
	if request.Delta.Value.Sign() <= 0 || request.Delta.Value.IsInf() || request.Delta.Mod != nil {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: A2A-I Delta must be a positive finite non-modular CKKS scale")
	}
	delta, err := NewExactScaleSnapshot(request.Delta)
	if err != nil {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: snapshot A2A-I Delta: %w", err)
	}
	if request.CenteredMessageBound == nil || request.CenteredMessageBound.Sign() <= 0 {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: A2A-I centered-message bound must be positive")
	}
	if request.CenteredBoundUnit != A2AICenteredCoefficientInfinityNorm {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: unsupported A2A-I centered-bound unit %q", request.CenteredBoundUnit)
	}
	if request.CenteredBoundDomain != A2AIBoundBeforeGuardedScaleDown {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: unsupported A2A-I centered-bound domain %q", request.CenteredBoundDomain)
	}
	if request.EvidenceArtifact == "" {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: empty A2A-I admission evidence artifact")
	}
	if request.VerificationStatus != A2AIEvidenceExternalUnverified {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: unsupported A2A-I evidence verification status %q", request.VerificationStatus)
	}
	if request.MaturityStatus != A2AIEvidenceFunctionalNotSecure {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: unsupported A2A-I evidence maturity status %q", request.MaturityStatus)
	}
	expectedEvidenceDigest := digestString(request.EvidenceArtifact)
	if request.EvidenceDigest != expectedEvidenceDigest {
		return A2AIAdmissionCertificate{}, fmt.Errorf("homchain: A2A-I evidence digest mismatch")
	}

	result := A2AIAdmissionCertificate{
		delta:               delta,
		deltaSemantics:      request.DeltaSemantics,
		centeredBound:       request.CenteredMessageBound.String(),
		centeredBoundUnit:   request.CenteredBoundUnit,
		centeredBoundDomain: request.CenteredBoundDomain,
		evidenceArtifact:    request.EvidenceArtifact,
		evidenceDigest:      expectedEvidenceDigest,
		verificationStatus:  request.VerificationStatus,
		maturityStatus:      request.MaturityStatus,
	}
	result.digest = digestString(result.canonicalString())
	return result, nil
}

// Delta returns the immutable exact scale snapshot bound by the certificate.
func (c A2AIAdmissionCertificate) Delta() ExactScaleSnapshot { return c.delta }

// DeltaSemantics returns the declared arithmetic representation semantics.
func (c A2AIAdmissionCertificate) DeltaSemantics() A2AIDeltaSemantics {
	return c.deltaSemantics
}

// CenteredMessageBound returns a detached copy of the externally certified
// centered-message bound.
func (c A2AIAdmissionCertificate) CenteredMessageBound() *big.Int {
	result := new(big.Int)
	result.SetString(c.centeredBound, 10)
	return result
}

// CenteredBoundUnit returns the exact norm/unit of CenteredMessageBound.
func (c A2AIAdmissionCertificate) CenteredBoundUnit() A2AICenteredBoundUnit {
	return c.centeredBoundUnit
}

// CenteredBoundDomain returns the operation boundary at which the caller
// claims CenteredMessageBound applies.
func (c A2AIAdmissionCertificate) CenteredBoundDomain() A2AICenteredBoundDomain {
	return c.centeredBoundDomain
}

// EvidenceArtifact returns the immutable external evidence artifact.
func (c A2AIAdmissionCertificate) EvidenceArtifact() string { return c.evidenceArtifact }

// EvidenceDigest returns the SHA-256 digest used to integrity-check the inline
// artifact bytes. It does not verify the artifact's mathematical claim.
func (c A2AIAdmissionCertificate) EvidenceDigest() string { return c.evidenceDigest }

// VerificationStatus returns the artifact's externally asserted status.
func (c A2AIAdmissionCertificate) VerificationStatus() A2AIEvidenceVerificationStatus {
	return c.verificationStatus
}

// MaturityStatus returns the artifact's declared review maturity.
func (c A2AIAdmissionCertificate) MaturityStatus() A2AIEvidenceMaturityStatus {
	return c.maturityStatus
}

// Digest returns the canonical SHA-256 identity of the full certificate.
func (c A2AIAdmissionCertificate) Digest() string { return c.digest }

// MessageBoundInternallyVerified is always false for this guarded adaptation:
// the package verifies certificate shape and artifact integrity, not the
// mathematical centered-message proof.
func (c A2AIAdmissionCertificate) MessageBoundInternallyVerified() bool { return false }

func (c A2AIAdmissionCertificate) validate() error {
	if c.deltaSemantics != A2AIDeltaGaoArithmeticInput || c.centeredBound == "" ||
		c.centeredBoundUnit != A2AICenteredCoefficientInfinityNorm ||
		c.centeredBoundDomain != A2AIBoundBeforeGuardedScaleDown ||
		c.evidenceArtifact == "" || c.verificationStatus != A2AIEvidenceExternalUnverified ||
		c.maturityStatus != A2AIEvidenceFunctionalNotSecure {
		return fmt.Errorf("homchain: invalid or absent A2A-I admission certificate")
	}
	bound := new(big.Int)
	if _, ok := bound.SetString(c.centeredBound, 10); !ok || bound.Sign() <= 0 {
		return fmt.Errorf("homchain: invalid A2A-I centered-message bound")
	}
	if c.evidenceDigest != digestString(c.evidenceArtifact) {
		return fmt.Errorf("homchain: invalid A2A-I evidence digest")
	}
	if c.digest != digestString(c.canonicalString()) {
		return fmt.Errorf("homchain: invalid A2A-I admission certificate digest")
	}
	return nil
}

func (c A2AIAdmissionCertificate) canonicalString() string {
	return fmt.Sprintf(
		"delta={%s};semantics=%s;bound=%s;bound-unit=%s;bound-domain=%s;evidence=%s;verification=%s;maturity=%s",
		c.delta.canonicalString(), c.deltaSemantics, c.centeredBound, c.centeredBoundUnit,
		c.centeredBoundDomain, c.evidenceDigest,
		c.verificationStatus, c.maturityStatus,
	)
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// A2AIAdmissionTrace is the immutable audit projection of the admission
// certificate. IntegrityChecked covers only the inline artifact bytes; it is
// not a mathematical verification of CenteredMessageBound.
type A2AIAdmissionTrace struct {
	CertificateDigest              string
	Delta                          ExactScaleSnapshot
	DeltaSemantics                 A2AIDeltaSemantics
	CenteredMessageBound           string
	CenteredBoundUnit              A2AICenteredBoundUnit
	CenteredBoundDomain            A2AICenteredBoundDomain
	EvidenceDigest                 string
	VerificationStatus             A2AIEvidenceVerificationStatus
	MaturityStatus                 A2AIEvidenceMaturityStatus
	InlineArtifactIntegrityChecked bool
	MessageBoundInternallyVerified bool
}

func (c A2AIAdmissionCertificate) trace() A2AIAdmissionTrace {
	return A2AIAdmissionTrace{
		CertificateDigest:              c.digest,
		Delta:                          c.delta,
		DeltaSemantics:                 c.deltaSemantics,
		CenteredMessageBound:           c.centeredBound,
		CenteredBoundUnit:              c.centeredBoundUnit,
		CenteredBoundDomain:            c.centeredBoundDomain,
		EvidenceDigest:                 c.evidenceDigest,
		VerificationStatus:             c.verificationStatus,
		MaturityStatus:                 c.maturityStatus,
		InlineArtifactIntegrityChecked: true,
		MessageBoundInternallyVerified: false,
	}
}

// A2AIDFTLiteralTrace records both Lattigo's reported moduli depth
// (Depth(true)) and the physical sequential-rescale depth (Depth(false)).
type A2AIDFTLiteralTrace struct {
	Type                 int
	Format               int
	LogSlots             int
	LevelQ               int
	LevelP               int
	Levels               []int
	LogBSGSRatio         int
	ReportedModuliDepth  int
	PhysicalRescaleDepth int
	ScalingHex           string
	ScalingPrecision     uint
}

// A2AIDFTTrace records the dedicated raw DFT literals and the normalization
// convention used by the guarded adaptation.
type A2AIDFTTrace struct {
	SlotsToCoeffs      A2AIDFTLiteralTrace
	CoeffsToSlots      A2AIDFTLiteralTrace
	EncoderPrecision   uint
	GeneratorPrecision uint
	MatrixSourceDigest string
	Normalization      string
	Digest             string
}

const (
	// A2AIDFTNormalizationLattigoFullSplit identifies Scaling=1 raw literals,
	// Lattigo's HomomorphicEncode 1/(2*slots), normalized gap-one Trace, and
	// the absence of an extra PartialSum or 1/N multiplier.
	A2AIDFTNormalizationLattigoFullSplit = "lattigo_full_split_1_over_2slots_gap1_trace_no_extra_partial_sum"
)

func (d RawFullSlotDFT) auditTrace() A2AIDFTTrace {
	result := A2AIDFTTrace{
		SlotsToCoeffs:      dftLiteralTrace(d.slotsToCoeffs.MatrixLiteral),
		CoeffsToSlots:      dftLiteralTrace(d.coeffsToSlots.MatrixLiteral),
		EncoderPrecision:   d.encoderPrecision,
		GeneratorPrecision: d.generatorPrecision,
		MatrixSourceDigest: d.matrixSourceDigest,
		Normalization:      A2AIDFTNormalizationLattigoFullSplit,
	}
	result.Digest = digestString(fmt.Sprintf(
		"raw-dft-trace-v2;stc=%v;cts=%v;encoder-precision=%d;generator-precision=%d;matrix-source=%s;normalization=%s",
		result.SlotsToCoeffs, result.CoeffsToSlots, result.EncoderPrecision,
		result.GeneratorPrecision, result.MatrixSourceDigest, result.Normalization,
	))
	return result
}

func dftLiteralTrace(literal ckksdft.MatrixLiteral) A2AIDFTLiteralTrace {
	result := A2AIDFTLiteralTrace{
		Type:                 int(literal.Type),
		Format:               int(literal.Format),
		LogSlots:             literal.LogSlots,
		LevelQ:               literal.LevelQ,
		LevelP:               literal.LevelP,
		Levels:               append([]int(nil), literal.Levels...),
		LogBSGSRatio:         literal.LogBSGSRatio,
		ReportedModuliDepth:  literal.Depth(true),
		PhysicalRescaleDepth: literal.Depth(false),
	}
	if literal.Scaling != nil {
		result.ScalingHex = literal.Scaling.Text('x', -1)
		result.ScalingPrecision = literal.Scaling.Prec()
	}
	return result
}

// A2AISwitchingMode identifies the ModUp key-switch topology. This slice
// supports only Lattigo's dense, no-switch adaptation; Gao's sparse
// encapsulation path is a distinct future contract.
type A2AISwitchingMode string

const (
	A2AIDenseNoSwitchLattigoAdaptation A2AISwitchingMode = "dense_no_switch_lattigo_adaptation"
)

// A2AIKeyProfile is the exact sorted key contract for one compiled A2A-I
// invocation. Trace is kept as a separate category even when full packing
// makes its required set empty.
type A2AIKeyProfile struct {
	ZToC                    []uint64
	SlotsToCoeffs           []uint64
	Trace                   []uint64
	CoeffsToSlots           []uint64
	CToZ                    []uint64
	Conjugation             []uint64
	All                     []uint64
	RelinearizationRequired bool
	SwitchingMode           A2AISwitchingMode
	Digest                  string
}

// A2AIKeyPreflightTrace records the fail-closed presence check performed
// before any ciphertext transform is evaluated.
type A2AIKeyPreflightTrace struct {
	Checked                     bool
	EvaluatorGraphChecked       bool
	EvaluatorGraphMatched       bool
	EvaluatorGraphMismatch      string
	MissingGaloisElements       []uint64
	InvalidGaloisElements       []uint64
	RelinearizationPresent      bool
	RelinearizationLevelMatched bool
	SwitchingModeMatched        bool
}

// requiredA2AIKeyProfile derives the exact sorted Galois/relinearization/key-
// switch contract for the circuit-owned transforms and raw DFT literals.
// Keeping this helper private prevents caller-supplied CompiledPairs from
// becoming an authoritative source-specific A2A-I seam.
func requiredA2AIKeyProfile(params ckks.Parameters, rawDFT RawFullSlotDFT, v, u CompiledPair) A2AIKeyProfile {
	identity := params.GaloisElement(0)
	filter := func(values []uint64) []uint64 {
		result := make([]uint64, 0, len(values))
		for _, value := range values {
			if value != identity {
				result = append(result, value)
			}
		}
		return uniqueGaloisElements(result)
	}

	result := A2AIKeyProfile{
		ZToC:                    filter(v.GaloisElements(params)),
		SlotsToCoeffs:           filter(rawDFT.slotsToCoeffs.MatrixLiteral.GaloisElements(params)),
		Trace:                   filter(params.GaloisElementsForTrace(rawDFT.logSlots)),
		CoeffsToSlots:           filter(rawDFT.coeffsToSlots.MatrixLiteral.GaloisElements(params)),
		CToZ:                    filter(u.GaloisElements(params)),
		Conjugation:             []uint64{params.GaloisElementForComplexConjugation()},
		RelinearizationRequired: true,
		SwitchingMode:           A2AIDenseNoSwitchLattigoAdaptation,
	}
	result.Conjugation = filter(result.Conjugation)
	result.All = filter(append(append(append(append(append(
		append([]uint64(nil), result.ZToC...), result.SlotsToCoeffs...), result.Trace...),
		result.CoeffsToSlots...), result.CToZ...), result.Conjugation...))
	result.Digest = digestString(fmt.Sprintf(
		"z2c=%v;stc=%v;trace=%v;cts=%v;c2z=%v;conj=%v;relin=%t;switch=%s",
		result.ZToC, result.SlotsToCoeffs, result.Trace, result.CoeffsToSlots,
		result.CToZ, result.Conjugation, result.RelinearizationRequired, result.SwitchingMode,
	))
	return result
}

func cloneA2AIKeyProfile(input A2AIKeyProfile) A2AIKeyProfile {
	result := input
	result.ZToC = append([]uint64(nil), input.ZToC...)
	result.SlotsToCoeffs = append([]uint64(nil), input.SlotsToCoeffs...)
	result.Trace = append([]uint64(nil), input.Trace...)
	result.CoeffsToSlots = append([]uint64(nil), input.CoeffsToSlots...)
	result.CToZ = append([]uint64(nil), input.CToZ...)
	result.Conjugation = append([]uint64(nil), input.Conjugation...)
	result.All = append([]uint64(nil), input.All...)
	return result
}

// A2AIEarlyResizeStep records one exact checkMessageRatio condition that the
// pinned Lattigo v6.1.1 ScaleDown will evaluate before dropping a Q limb.
type A2AIEarlyResizeStep struct {
	FromLevel            int
	ToLevel              int
	DroppedModulus       string
	CurrentMessageRatio  ExactScaleSnapshot
	RequiredMessageRatio ExactScaleSnapshot
	Condition            string
}

// A2AIEarlyResizeTrace separates computable Lattigo branch topology from the
// external, currently unverified mathematical claim that the centered message
// remains safe under every listed limb drop.
type A2AIEarlyResizeTrace struct {
	Source                              string
	InitialLevel                        int
	ExpectedSteps                       []A2AIEarlyResizeStep
	TerminalLevelBeforeRescale          int
	ExpectedFinalRescaleToQ0            bool
	ObservedOutputLevel                 int
	ObservedOutputLevelKnown            bool
	ActualEarlyResizeCountKnown         bool
	AdmissionCertificateDigest          string
	CenteredMessageBound                string
	CenteredBoundUnit                   A2AICenteredBoundUnit
	CenteredBoundDomain                 A2AICenteredBoundDomain
	TopologyConditionInternallyComputed bool
	MessageBoundInternallyVerified      bool
}
