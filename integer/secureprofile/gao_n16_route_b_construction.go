package secureprofile

import (
	"fmt"
	"strings"
)

const (
	// RouteBConstructionContractOnlyUnverified is a pure construction-contract
	// state. It does not assert that a DFT factor, HE key, evaluator, ciphertext,
	// measured RSS result, or application-security result exists.
	RouteBConstructionContractOnlyUnverified Maturity = "route_b_construction_contract_only_unverified"

	gaoN16RouteBTransformDigestSchema       = "gao-n16-route-b-transform-digests-v1"
	gaoN16RouteBArtifactDigestSchema        = "gao-n16-route-b-artifact-digests-v1"
	gaoN16RouteBPeakContractSchema          = "gao-n16-route-b-peak-contract-v1"
	gaoN16RouteBConstructionSemanticsSchema = "gao-n16-route-b-construction-semantics-v1"
	gaoN16RouteBArtifactManifestSchema      = "gao-n16-route-b-private-artifact-manifest-v1"
	gaoN16RouteBConstructionSpecSchema      = "gao-n16-route-b-precision-construction-spec-v1"
	gaoN16RouteBSnapshotDigestSchema        = "gao-n16-route-b-capacity-snapshot-v1"
	gaoN16RouteBConstructionPermitSchema    = "gao-n16-route-b-precision-construction-permit-v1"

	gaoN16RouteBConstructionEvidenceScope = "precision_construction_contract_only"
	gaoN16RouteBC2SRole                   = "c2s"
	gaoN16RouteBS2CRole                   = "s2c"

	gaoN16RouteBBuilderID            = "lattigo-route-b-prebuilt-dft-streaming-builder-v1"
	gaoN16RouteBDigestAlgorithmID    = "sha256-canonical-streaming-binary-v1"
	gaoN16RouteBAllocationScheduleID = "route-b-l11-factor-at-a-time-no-default-v1"
	gaoN16RouteBReleaseScheduleID    = "route-b-l11-release-factor-scratch-before-next-v1"
	gaoN16RouteBOwnershipModelID     = "route-b-private-exclusive-transfer-no-alias-v1"
)

// ErrGaoN16RouteBConstructionBlocked is the fail-closed error for the pure
// precision/construction authorization boundary. It wraps capacity failures
// but never promotes them to HE execution or security evidence.
type ErrGaoN16RouteBConstructionBlocked struct {
	reason string
	cause  error
}

func (e *ErrGaoN16RouteBConstructionBlocked) Error() string {
	if e == nil {
		return "secureprofile: Gao N16 Route-B construction blocked"
	}
	if e.cause != nil {
		return fmt.Sprintf("secureprofile: Gao N16 Route-B construction blocked: %s: %v", e.reason, e.cause)
	}
	return "secureprofile: Gao N16 Route-B construction blocked: " + e.reason
}

func (e *ErrGaoN16RouteBConstructionBlocked) Unwrap() error { return e.cause }
func (e *ErrGaoN16RouteBConstructionBlocked) Reason() string {
	if e == nil {
		return ""
	}
	return e.reason
}

func routeBConstructionBlocked(reason string, cause error) error {
	return &ErrGaoN16RouteBConstructionBlocked{reason: reason, cause: cause}
}

// GaoN16RouteBTransformDigests is a value-only, role-tagged identity for one
// raw and post-bootstrap-preparation DFT literal. The four digests are kept
// separate so a raw/effective literal or scaling swap changes the identity.
type GaoN16RouteBTransformDigests struct {
	schema                                   string
	role                                     string
	rawLiteralDigest, effectiveLiteralDigest string
	rawScalingDigest, effectiveScalingDigest string
	digest                                   string
}

func NewGaoN16RouteBC2SDigests(rawLiteral, effectiveLiteral, rawScaling, effectiveScaling string) (GaoN16RouteBTransformDigests, error) {
	return newGaoN16RouteBTransformDigests(gaoN16RouteBC2SRole, rawLiteral, effectiveLiteral, rawScaling, effectiveScaling)
}

func NewGaoN16RouteBS2CDigests(rawLiteral, effectiveLiteral, rawScaling, effectiveScaling string) (GaoN16RouteBTransformDigests, error) {
	return newGaoN16RouteBTransformDigests(gaoN16RouteBS2CRole, rawLiteral, effectiveLiteral, rawScaling, effectiveScaling)
}

func newGaoN16RouteBTransformDigests(role, rawLiteral, effectiveLiteral, rawScaling, effectiveScaling string) (GaoN16RouteBTransformDigests, error) {
	result := GaoN16RouteBTransformDigests{
		schema:           gaoN16RouteBTransformDigestSchema,
		role:             role,
		rawLiteralDigest: rawLiteral, effectiveLiteralDigest: effectiveLiteral,
		rawScalingDigest: rawScaling, effectiveScalingDigest: effectiveScaling,
	}
	if err := validateGaoN16RouteBTransformDigestFields(result); err != nil {
		return GaoN16RouteBTransformDigests{}, err
	}
	var err error
	result.digest, err = digestGaoN16RouteBTransformDigests(result)
	if err != nil {
		return GaoN16RouteBTransformDigests{}, err
	}
	return result, nil
}

func (d GaoN16RouteBTransformDigests) IsZero() bool             { return d == (GaoN16RouteBTransformDigests{}) }
func (d GaoN16RouteBTransformDigests) Role() string             { return d.role }
func (d GaoN16RouteBTransformDigests) RawLiteralDigest() string { return d.rawLiteralDigest }
func (d GaoN16RouteBTransformDigests) EffectiveLiteralDigest() string {
	return d.effectiveLiteralDigest
}
func (d GaoN16RouteBTransformDigests) RawScalingDigest() string { return d.rawScalingDigest }
func (d GaoN16RouteBTransformDigests) EffectiveScalingDigest() string {
	return d.effectiveScalingDigest
}
func (d GaoN16RouteBTransformDigests) Digest() string { return d.digest }

type gaoN16RouteBTransformDigestRecord struct {
	SchemaVersion, Role                      string
	RawLiteralDigest, EffectiveLiteralDigest string
	RawScalingDigest, EffectiveScalingDigest string
}

func digestGaoN16RouteBTransformDigests(value GaoN16RouteBTransformDigests) (string, error) {
	return digestGaoN16RouteBRecord(gaoN16RouteBTransformDigestRecord{
		SchemaVersion: value.schema, Role: value.role,
		RawLiteralDigest: value.rawLiteralDigest, EffectiveLiteralDigest: value.effectiveLiteralDigest,
		RawScalingDigest: value.rawScalingDigest, EffectiveScalingDigest: value.effectiveScalingDigest,
	}, "transform digests")
}

func validateGaoN16RouteBTransformDigestFields(value GaoN16RouteBTransformDigests) error {
	if value.schema != gaoN16RouteBTransformDigestSchema ||
		(value.role != gaoN16RouteBC2SRole && value.role != gaoN16RouteBS2CRole) ||
		!isCanonicalGaoN16RouteBDigest(value.rawLiteralDigest) ||
		!isCanonicalGaoN16RouteBDigest(value.effectiveLiteralDigest) ||
		!isCanonicalGaoN16RouteBDigest(value.rawScalingDigest) ||
		!isCanonicalGaoN16RouteBDigest(value.effectiveScalingDigest) {
		return routeBConstructionBlocked("transform literal or scaling identity is zero, malformed, or untyped", nil)
	}
	return nil
}

func validateGaoN16RouteBTransformDigests(value GaoN16RouteBTransformDigests, role string) error {
	if err := validateGaoN16RouteBTransformDigestFields(value); err != nil {
		return err
	}
	digest, err := digestGaoN16RouteBTransformDigests(value)
	if err != nil {
		return err
	}
	if value.role != role || value.digest == "" || value.digest != digest {
		return routeBConstructionBlocked("transform digest role or seal changed", nil)
	}
	return nil
}

// GaoN16RouteBArtifactDigests carries only canonical digests. It has no DFT
// matrix, plaintext, key, evaluator, ciphertext, or externally writable slice.
type GaoN16RouteBArtifactDigests struct {
	schema                                     string
	c2s, s2c                                   GaoN16RouteBTransformDigests
	numericPayloadDigest, encodedPayloadDigest string
	digest                                     string
}

func NewGaoN16RouteBArtifactDigests(
	c2s, s2c GaoN16RouteBTransformDigests,
	numericPayloadDigest, encodedPayloadDigest string,
) (GaoN16RouteBArtifactDigests, error) {
	value := GaoN16RouteBArtifactDigests{
		schema: gaoN16RouteBArtifactDigestSchema,
		c2s:    c2s, s2c: s2c,
		numericPayloadDigest: numericPayloadDigest,
		encodedPayloadDigest: encodedPayloadDigest,
	}
	if err := validateGaoN16RouteBArtifactDigestFields(value); err != nil {
		return GaoN16RouteBArtifactDigests{}, err
	}
	var err error
	value.digest, err = digestGaoN16RouteBArtifactDigests(value)
	if err != nil {
		return GaoN16RouteBArtifactDigests{}, err
	}
	return value, nil
}

func (d GaoN16RouteBArtifactDigests) IsZero() bool                      { return d == (GaoN16RouteBArtifactDigests{}) }
func (d GaoN16RouteBArtifactDigests) C2S() GaoN16RouteBTransformDigests { return d.c2s }
func (d GaoN16RouteBArtifactDigests) S2C() GaoN16RouteBTransformDigests { return d.s2c }
func (d GaoN16RouteBArtifactDigests) NumericPayloadDigest() string      { return d.numericPayloadDigest }
func (d GaoN16RouteBArtifactDigests) EncodedPayloadDigest() string      { return d.encodedPayloadDigest }
func (d GaoN16RouteBArtifactDigests) Digest() string                    { return d.digest }

type gaoN16RouteBArtifactDigestRecord struct {
	SchemaVersion        string
	C2S, S2C             gaoN16RouteBTransformDigestRecord
	C2SDigest, S2CDigest string
	NumericPayloadDigest string
	EncodedPayloadDigest string
}

func gaoN16RouteBTransformRecord(value GaoN16RouteBTransformDigests) gaoN16RouteBTransformDigestRecord {
	return gaoN16RouteBTransformDigestRecord{
		SchemaVersion: value.schema, Role: value.role,
		RawLiteralDigest: value.rawLiteralDigest, EffectiveLiteralDigest: value.effectiveLiteralDigest,
		RawScalingDigest: value.rawScalingDigest, EffectiveScalingDigest: value.effectiveScalingDigest,
	}
}

func digestGaoN16RouteBArtifactDigests(value GaoN16RouteBArtifactDigests) (string, error) {
	return digestGaoN16RouteBRecord(gaoN16RouteBArtifactDigestRecord{
		SchemaVersion: value.schema,
		C2S:           gaoN16RouteBTransformRecord(value.c2s), S2C: gaoN16RouteBTransformRecord(value.s2c),
		C2SDigest: value.c2s.digest, S2CDigest: value.s2c.digest,
		NumericPayloadDigest: value.numericPayloadDigest,
		EncodedPayloadDigest: value.encodedPayloadDigest,
	}, "artifact digests")
}

func validateGaoN16RouteBArtifactDigestFields(value GaoN16RouteBArtifactDigests) error {
	if value.schema != gaoN16RouteBArtifactDigestSchema {
		return routeBConstructionBlocked("artifact digest schema changed", nil)
	}
	if err := validateGaoN16RouteBTransformDigests(value.c2s, gaoN16RouteBC2SRole); err != nil {
		return err
	}
	if err := validateGaoN16RouteBTransformDigests(value.s2c, gaoN16RouteBS2CRole); err != nil {
		return err
	}
	if !isCanonicalGaoN16RouteBDigest(value.numericPayloadDigest) ||
		!isCanonicalGaoN16RouteBDigest(value.encodedPayloadDigest) {
		return routeBConstructionBlocked("numeric or encoded payload digest is zero or malformed", nil)
	}
	return nil
}

func validateGaoN16RouteBArtifactDigests(value GaoN16RouteBArtifactDigests) error {
	if err := validateGaoN16RouteBArtifactDigestFields(value); err != nil {
		return err
	}
	digest, err := digestGaoN16RouteBArtifactDigests(value)
	if err != nil {
		return err
	}
	if value.digest == "" || value.digest != digest {
		return routeBConstructionBlocked("artifact digest seal changed", nil)
	}
	return nil
}

// GaoN16RouteBPeakContract freezes the accepted L11 derived byte ledger. The
// values are bounds, not measured RSS.
type GaoN16RouteBPeakContract struct {
	schema                                                        string
	fullArtifactPeakBytes, preGuardIncrementalPeakBytes           uint64
	guardedRequirementBytes, remainingBelowLimitBytes             uint64
	forbiddenDuplicateDefaultBytes, forbiddenDuplicateExcessBytes uint64
}

func DefaultGaoN16RouteBPeakContract() GaoN16RouteBPeakContract {
	return GaoN16RouteBPeakContract{
		schema:                         gaoN16RouteBPeakContractSchema,
		fullArtifactPeakBytes:          2968063744,
		preGuardIncrementalPeakBytes:   7129861888,
		guardedRequirementBytes:        7842848076,
		remainingBelowLimitBytes:       2585547267,
		forbiddenDuplicateDefaultBytes: 2641362944,
		forbiddenDuplicateExcessBytes:  55815677,
	}
}

func (p GaoN16RouteBPeakContract) IsZero() bool                  { return p == (GaoN16RouteBPeakContract{}) }
func (p GaoN16RouteBPeakContract) FullArtifactPeakBytes() uint64 { return p.fullArtifactPeakBytes }
func (p GaoN16RouteBPeakContract) PreGuardIncrementalPeakBytes() uint64 {
	return p.preGuardIncrementalPeakBytes
}
func (p GaoN16RouteBPeakContract) GuardedRequirementBytes() uint64 { return p.guardedRequirementBytes }
func (p GaoN16RouteBPeakContract) RemainingBelowLimitBytes() uint64 {
	return p.remainingBelowLimitBytes
}
func (p GaoN16RouteBPeakContract) ForbiddenDuplicateDefaultBytes() uint64 {
	return p.forbiddenDuplicateDefaultBytes
}
func (p GaoN16RouteBPeakContract) ForbiddenDuplicateExcessBytes() uint64 {
	return p.forbiddenDuplicateExcessBytes
}

func validateGaoN16RouteBPeakContract(value GaoN16RouteBPeakContract) error {
	expected := DefaultGaoN16RouteBPeakContract()
	if value != expected {
		return routeBConstructionBlocked("Route-B peak contract drifted", nil)
	}
	guard, err := checkedUint64Sum(value.preGuardIncrementalPeakBytes / 10)
	if err != nil {
		return routeBConstructionBlocked("relative guard overflow", err)
	}
	guarded, err := checkedUint64Sum(value.preGuardIncrementalPeakBytes, guard)
	if err != nil {
		return routeBConstructionBlocked("guarded requirement overflow", err)
	}
	if guarded != value.guardedRequirementBytes ||
		value.forbiddenDuplicateDefaultBytes <= value.remainingBelowLimitBytes ||
		value.forbiddenDuplicateDefaultBytes-value.remainingBelowLimitBytes != value.forbiddenDuplicateExcessBytes {
		return routeBConstructionBlocked("Route-B peak arithmetic changed", nil)
	}
	return nil
}

// GaoN16RouteBConstructionSemantics seals the only admitted precision,
// builder, digest, ownership and allocation/release schedule. In particular,
// the stock default DFT constructor count is fixed at zero.
type GaoN16RouteBConstructionSemantics struct {
	schema                                                    string
	generatorPrecisionBits, encoderPrecisionBits              uint64
	builderID, digestAlgorithmID                              string
	allocationScheduleID, releaseScheduleID, ownershipModelID string
	defaultConstructorCalls                                   uint64
	peak                                                      GaoN16RouteBPeakContract
	digest                                                    string
}

func DefaultGaoN16RouteBConstructionSemantics() GaoN16RouteBConstructionSemantics {
	value := GaoN16RouteBConstructionSemantics{
		schema:                 gaoN16RouteBConstructionSemanticsSchema,
		generatorPrecisionBits: 256, encoderPrecisionBits: 256,
		builderID: gaoN16RouteBBuilderID, digestAlgorithmID: gaoN16RouteBDigestAlgorithmID,
		allocationScheduleID:    gaoN16RouteBAllocationScheduleID,
		releaseScheduleID:       gaoN16RouteBReleaseScheduleID,
		ownershipModelID:        gaoN16RouteBOwnershipModelID,
		defaultConstructorCalls: 0,
		peak:                    DefaultGaoN16RouteBPeakContract(),
	}
	value.digest, _ = digestGaoN16RouteBConstructionSemantics(value)
	return value
}

func (s GaoN16RouteBConstructionSemantics) IsZero() bool {
	return s == (GaoN16RouteBConstructionSemantics{})
}
func (s GaoN16RouteBConstructionSemantics) GeneratorPrecisionBits() uint64 {
	return s.generatorPrecisionBits
}
func (s GaoN16RouteBConstructionSemantics) EncoderPrecisionBits() uint64 {
	return s.encoderPrecisionBits
}
func (s GaoN16RouteBConstructionSemantics) BuilderID() string         { return s.builderID }
func (s GaoN16RouteBConstructionSemantics) DigestAlgorithmID() string { return s.digestAlgorithmID }
func (s GaoN16RouteBConstructionSemantics) AllocationScheduleID() string {
	return s.allocationScheduleID
}
func (s GaoN16RouteBConstructionSemantics) ReleaseScheduleID() string { return s.releaseScheduleID }
func (s GaoN16RouteBConstructionSemantics) OwnershipModelID() string  { return s.ownershipModelID }
func (s GaoN16RouteBConstructionSemantics) DefaultConstructorCalls() uint64 {
	return s.defaultConstructorCalls
}
func (s GaoN16RouteBConstructionSemantics) PeakContract() GaoN16RouteBPeakContract { return s.peak }
func (s GaoN16RouteBConstructionSemantics) Digest() string                         { return s.digest }

type gaoN16RouteBPeakContractRecord struct {
	SchemaVersion                                                 string
	FullArtifactPeakBytes, PreGuardIncrementalPeakBytes           uint64
	GuardedRequirementBytes, RemainingBelowLimitBytes             uint64
	ForbiddenDuplicateDefaultBytes, ForbiddenDuplicateExcessBytes uint64
}

func gaoN16RouteBPeakRecord(value GaoN16RouteBPeakContract) gaoN16RouteBPeakContractRecord {
	return gaoN16RouteBPeakContractRecord{
		SchemaVersion:                  value.schema,
		FullArtifactPeakBytes:          value.fullArtifactPeakBytes,
		PreGuardIncrementalPeakBytes:   value.preGuardIncrementalPeakBytes,
		GuardedRequirementBytes:        value.guardedRequirementBytes,
		RemainingBelowLimitBytes:       value.remainingBelowLimitBytes,
		ForbiddenDuplicateDefaultBytes: value.forbiddenDuplicateDefaultBytes,
		ForbiddenDuplicateExcessBytes:  value.forbiddenDuplicateExcessBytes,
	}
}

type gaoN16RouteBConstructionSemanticsRecord struct {
	SchemaVersion                                string
	GeneratorPrecisionBits, EncoderPrecisionBits uint64
	BuilderID, DigestAlgorithmID                 string
	AllocationScheduleID, ReleaseScheduleID      string
	OwnershipModelID                             string
	DefaultConstructorCalls                      uint64
	Peak                                         gaoN16RouteBPeakContractRecord
}

func gaoN16RouteBSemanticsRecord(value GaoN16RouteBConstructionSemantics) gaoN16RouteBConstructionSemanticsRecord {
	return gaoN16RouteBConstructionSemanticsRecord{
		SchemaVersion:          value.schema,
		GeneratorPrecisionBits: value.generatorPrecisionBits,
		EncoderPrecisionBits:   value.encoderPrecisionBits,
		BuilderID:              value.builderID, DigestAlgorithmID: value.digestAlgorithmID,
		AllocationScheduleID: value.allocationScheduleID, ReleaseScheduleID: value.releaseScheduleID,
		OwnershipModelID:        value.ownershipModelID,
		DefaultConstructorCalls: value.defaultConstructorCalls,
		Peak:                    gaoN16RouteBPeakRecord(value.peak),
	}
}

func digestGaoN16RouteBConstructionSemantics(value GaoN16RouteBConstructionSemantics) (string, error) {
	return digestGaoN16RouteBRecord(gaoN16RouteBSemanticsRecord(value), "construction semantics")
}

func validateGaoN16RouteBConstructionSemantics(value GaoN16RouteBConstructionSemantics) error {
	if err := validateGaoN16RouteBPeakContract(value.peak); err != nil {
		return err
	}
	digest, err := digestGaoN16RouteBConstructionSemantics(value)
	if err != nil {
		return err
	}
	expected := DefaultGaoN16RouteBConstructionSemantics()
	if value != expected || value.digest == "" || value.digest != digest ||
		value.generatorPrecisionBits != value.encoderPrecisionBits || value.defaultConstructorCalls != 0 {
		return routeBConstructionBlocked("precision, builder, digest, ownership, or schedule semantics drifted", nil)
	}
	return nil
}

// GaoN16RouteBArtifactManifest is a private-identity value. Its digest covers
// the capacity identities, all raw/effective and payload digests, precision,
// construction versions, ownership model, schedule and peak contract.
type GaoN16RouteBArtifactManifest struct {
	schema                                                     string
	capacityPlanDigest, parameterDigest, profileDigest         string
	shapeDigest, policyDigest, artifactDigest, semanticsDigest string
	digest                                                     string
}

func (m GaoN16RouteBArtifactManifest) IsZero() bool               { return m == (GaoN16RouteBArtifactManifest{}) }
func (m GaoN16RouteBArtifactManifest) CapacityPlanDigest() string { return m.capacityPlanDigest }
func (m GaoN16RouteBArtifactManifest) ParameterDigest() string    { return m.parameterDigest }
func (m GaoN16RouteBArtifactManifest) ProfileDigest() string      { return m.profileDigest }
func (m GaoN16RouteBArtifactManifest) ShapeDigest() string        { return m.shapeDigest }
func (m GaoN16RouteBArtifactManifest) PolicyDigest() string       { return m.policyDigest }
func (m GaoN16RouteBArtifactManifest) ArtifactDigest() string     { return m.artifactDigest }
func (m GaoN16RouteBArtifactManifest) SemanticsDigest() string    { return m.semanticsDigest }
func (m GaoN16RouteBArtifactManifest) Digest() string             { return m.digest }

type gaoN16RouteBArtifactManifestDigestRecord struct {
	SchemaVersion                                      string
	CapacityPlanDigest, ParameterDigest, ProfileDigest string
	ShapeDigest, PolicyDigest                          string
	Artifacts                                          gaoN16RouteBArtifactDigestRecord
	ArtifactDigest                                     string
	Semantics                                          gaoN16RouteBConstructionSemanticsRecord
	SemanticsDigest                                    string
}

func buildGaoN16RouteBArtifactManifest(
	plan GaoN16PackingL11CapacityPlan,
	artifacts GaoN16RouteBArtifactDigests,
	semantics GaoN16RouteBConstructionSemantics,
) (GaoN16RouteBArtifactManifest, error) {
	manifest := GaoN16RouteBArtifactManifest{
		schema:             gaoN16RouteBArtifactManifestSchema,
		capacityPlanDigest: plan.Digest(), parameterDigest: plan.ParameterDigest(),
		profileDigest: plan.ProfileDigest(), shapeDigest: plan.ShapeDigest(), policyDigest: plan.PolicyDigest(),
		artifactDigest: artifacts.digest, semanticsDigest: semantics.digest,
	}
	record := gaoN16RouteBArtifactManifestDigestRecord{
		SchemaVersion:      manifest.schema,
		CapacityPlanDigest: manifest.capacityPlanDigest, ParameterDigest: manifest.parameterDigest,
		ProfileDigest: manifest.profileDigest, ShapeDigest: manifest.shapeDigest, PolicyDigest: manifest.policyDigest,
		Artifacts: gaoN16RouteBArtifactDigestRecord{
			SchemaVersion: artifacts.schema,
			C2S:           gaoN16RouteBTransformRecord(artifacts.c2s), S2C: gaoN16RouteBTransformRecord(artifacts.s2c),
			C2SDigest: artifacts.c2s.digest, S2CDigest: artifacts.s2c.digest,
			NumericPayloadDigest: artifacts.numericPayloadDigest,
			EncodedPayloadDigest: artifacts.encodedPayloadDigest,
		},
		ArtifactDigest: artifacts.digest,
		Semantics:      gaoN16RouteBSemanticsRecord(semantics), SemanticsDigest: semantics.digest,
	}
	var err error
	manifest.digest, err = digestGaoN16RouteBRecord(record, "private artifact manifest")
	if err != nil {
		return GaoN16RouteBArtifactManifest{}, err
	}
	return manifest, nil
}

// GaoN16RouteBConstructionSpec is the immutable, zero-HE-object bridge from
// the accepted capacity plan to one exact private artifact identity.
type GaoN16RouteBConstructionSpec struct {
	schema, adaptationLabel, evidenceScope             string
	maturity                                           Maturity
	sourceFaithful, fullPacked                         bool
	capacityPlanDigest, parameterDigest, profileDigest string
	shapeDigest, policyDigest                          string
	capacityPlan                                       GaoN16PackingL11CapacityPlan
	artifacts                                          GaoN16RouteBArtifactDigests
	semantics                                          GaoN16RouteBConstructionSemantics
	manifest                                           GaoN16RouteBArtifactManifest
	digest                                             string
}

func NewGaoN16RouteBConstructionSpec(
	capacityPlan GaoN16PackingL11CapacityPlan,
	artifacts GaoN16RouteBArtifactDigests,
	semantics GaoN16RouteBConstructionSemantics,
) (GaoN16RouteBConstructionSpec, error) {
	if err := capacityPlan.validate(); err != nil {
		return GaoN16RouteBConstructionSpec{}, routeBConstructionBlocked("capacity plan is not the accepted L11 plan", err)
	}
	if err := validateGaoN16RouteBArtifactDigests(artifacts); err != nil {
		return GaoN16RouteBConstructionSpec{}, err
	}
	if err := validateGaoN16RouteBConstructionSemantics(semantics); err != nil {
		return GaoN16RouteBConstructionSpec{}, err
	}
	ownedPlan, err := NewGaoN16PackingL11CapacityPlan(capacityPlan.profile, capacityPlan.shape, capacityPlan.policy)
	if err != nil {
		return GaoN16RouteBConstructionSpec{}, routeBConstructionBlocked("cannot rebuild owned capacity plan", err)
	}
	if ownedPlan.Digest() != capacityPlan.Digest() {
		return GaoN16RouteBConstructionSpec{}, routeBConstructionBlocked("capacity plan changed while being copied", nil)
	}
	manifest, err := buildGaoN16RouteBArtifactManifest(ownedPlan, artifacts, semantics)
	if err != nil {
		return GaoN16RouteBConstructionSpec{}, err
	}
	spec := GaoN16RouteBConstructionSpec{
		schema:          gaoN16RouteBConstructionSpecSchema,
		adaptationLabel: gaoN16PackingL11AdaptationLabel,
		evidenceScope:   gaoN16RouteBConstructionEvidenceScope,
		maturity:        RouteBConstructionContractOnlyUnverified,
		sourceFaithful:  false, fullPacked: false,
		capacityPlanDigest: ownedPlan.Digest(), parameterDigest: ownedPlan.ParameterDigest(),
		profileDigest: ownedPlan.ProfileDigest(), shapeDigest: ownedPlan.ShapeDigest(), policyDigest: ownedPlan.PolicyDigest(),
		capacityPlan: ownedPlan, artifacts: artifacts, semantics: semantics, manifest: manifest,
	}
	spec.digest, err = digestGaoN16RouteBConstructionSpec(spec)
	if err != nil {
		return GaoN16RouteBConstructionSpec{}, err
	}
	return spec, nil
}

func (s GaoN16RouteBConstructionSpec) IsZero() bool {
	return s.schema == "" && s.digest == "" && s.capacityPlan.digest == "" &&
		s.artifacts.IsZero() && s.semantics.IsZero() && s.manifest.IsZero()
}
func (s GaoN16RouteBConstructionSpec) SchemaVersion() string                  { return s.schema }
func (s GaoN16RouteBConstructionSpec) AdaptationLabel() string                { return s.adaptationLabel }
func (s GaoN16RouteBConstructionSpec) EvidenceScope() string                  { return s.evidenceScope }
func (s GaoN16RouteBConstructionSpec) Maturity() Maturity                     { return s.maturity }
func (s GaoN16RouteBConstructionSpec) IsSourceFaithful() bool                 { return s.sourceFaithful }
func (s GaoN16RouteBConstructionSpec) IsFullPacked() bool                     { return s.fullPacked }
func (s GaoN16RouteBConstructionSpec) CapacityPlanDigest() string             { return s.capacityPlanDigest }
func (s GaoN16RouteBConstructionSpec) ParameterDigest() string                { return s.parameterDigest }
func (s GaoN16RouteBConstructionSpec) ProfileDigest() string                  { return s.profileDigest }
func (s GaoN16RouteBConstructionSpec) ShapeDigest() string                    { return s.shapeDigest }
func (s GaoN16RouteBConstructionSpec) PolicyDigest() string                   { return s.policyDigest }
func (s GaoN16RouteBConstructionSpec) Artifacts() GaoN16RouteBArtifactDigests { return s.artifacts }
func (s GaoN16RouteBConstructionSpec) Semantics() GaoN16RouteBConstructionSemantics {
	return s.semantics
}
func (s GaoN16RouteBConstructionSpec) PeakContract() GaoN16RouteBPeakContract {
	return s.semantics.peak
}
func (s GaoN16RouteBConstructionSpec) ArtifactManifest() GaoN16RouteBArtifactManifest {
	return s.manifest
}
func (s GaoN16RouteBConstructionSpec) ArtifactManifestDigest() string { return s.manifest.digest }
func (s GaoN16RouteBConstructionSpec) GeneratorPrecisionBits() uint64 {
	return s.semantics.generatorPrecisionBits
}
func (s GaoN16RouteBConstructionSpec) EncoderPrecisionBits() uint64 {
	return s.semantics.encoderPrecisionBits
}
func (s GaoN16RouteBConstructionSpec) BuilderID() string { return s.semantics.builderID }
func (s GaoN16RouteBConstructionSpec) DigestAlgorithmID() string {
	return s.semantics.digestAlgorithmID
}
func (s GaoN16RouteBConstructionSpec) AllocationScheduleID() string {
	return s.semantics.allocationScheduleID
}
func (s GaoN16RouteBConstructionSpec) ReleaseScheduleID() string {
	return s.semantics.releaseScheduleID
}
func (s GaoN16RouteBConstructionSpec) OwnershipModelID() string { return s.semantics.ownershipModelID }
func (s GaoN16RouteBConstructionSpec) DefaultConstructorCalls() uint64 {
	return s.semantics.defaultConstructorCalls
}
func (s GaoN16RouteBConstructionSpec) RawC2SLiteralDigest() string {
	return s.artifacts.c2s.rawLiteralDigest
}
func (s GaoN16RouteBConstructionSpec) EffectiveC2SLiteralDigest() string {
	return s.artifacts.c2s.effectiveLiteralDigest
}
func (s GaoN16RouteBConstructionSpec) RawC2SScalingDigest() string {
	return s.artifacts.c2s.rawScalingDigest
}
func (s GaoN16RouteBConstructionSpec) EffectiveC2SScalingDigest() string {
	return s.artifacts.c2s.effectiveScalingDigest
}
func (s GaoN16RouteBConstructionSpec) RawS2CLiteralDigest() string {
	return s.artifacts.s2c.rawLiteralDigest
}
func (s GaoN16RouteBConstructionSpec) EffectiveS2CLiteralDigest() string {
	return s.artifacts.s2c.effectiveLiteralDigest
}
func (s GaoN16RouteBConstructionSpec) RawS2CScalingDigest() string {
	return s.artifacts.s2c.rawScalingDigest
}
func (s GaoN16RouteBConstructionSpec) EffectiveS2CScalingDigest() string {
	return s.artifacts.s2c.effectiveScalingDigest
}
func (s GaoN16RouteBConstructionSpec) NumericPayloadDigest() string {
	return s.artifacts.numericPayloadDigest
}
func (s GaoN16RouteBConstructionSpec) EncodedPayloadDigest() string {
	return s.artifacts.encodedPayloadDigest
}
func (s GaoN16RouteBConstructionSpec) Digest() string { return s.digest }

type gaoN16RouteBConstructionSpecDigestRecord struct {
	SchemaVersion, AdaptationLabel, EvidenceScope      string
	Maturity                                           Maturity
	SourceFaithful, FullPacked                         bool
	CapacityPlanDigest, ParameterDigest, ProfileDigest string
	ShapeDigest, PolicyDigest                          string
	Artifacts                                          gaoN16RouteBArtifactDigestRecord
	ArtifactDigest                                     string
	Semantics                                          gaoN16RouteBConstructionSemanticsRecord
	SemanticsDigest, ArtifactManifestDigest            string
}

func gaoN16RouteBArtifactRecord(value GaoN16RouteBArtifactDigests) gaoN16RouteBArtifactDigestRecord {
	return gaoN16RouteBArtifactDigestRecord{
		SchemaVersion: value.schema,
		C2S:           gaoN16RouteBTransformRecord(value.c2s), S2C: gaoN16RouteBTransformRecord(value.s2c),
		C2SDigest: value.c2s.digest, S2CDigest: value.s2c.digest,
		NumericPayloadDigest: value.numericPayloadDigest,
		EncodedPayloadDigest: value.encodedPayloadDigest,
	}
}

func digestGaoN16RouteBConstructionSpec(value GaoN16RouteBConstructionSpec) (string, error) {
	return digestGaoN16RouteBRecord(gaoN16RouteBConstructionSpecDigestRecord{
		SchemaVersion: value.schema, AdaptationLabel: value.adaptationLabel, EvidenceScope: value.evidenceScope,
		Maturity: value.maturity, SourceFaithful: value.sourceFaithful, FullPacked: value.fullPacked,
		CapacityPlanDigest: value.capacityPlanDigest, ParameterDigest: value.parameterDigest,
		ProfileDigest: value.profileDigest, ShapeDigest: value.shapeDigest, PolicyDigest: value.policyDigest,
		Artifacts: gaoN16RouteBArtifactRecord(value.artifacts), ArtifactDigest: value.artifacts.digest,
		Semantics: gaoN16RouteBSemanticsRecord(value.semantics), SemanticsDigest: value.semantics.digest,
		ArtifactManifestDigest: value.manifest.digest,
	}, "construction spec")
}

func (s GaoN16RouteBConstructionSpec) validate() error {
	if err := s.capacityPlan.validate(); err != nil {
		return routeBConstructionBlocked("embedded capacity plan changed", err)
	}
	if err := validateGaoN16RouteBArtifactDigests(s.artifacts); err != nil {
		return err
	}
	if err := validateGaoN16RouteBConstructionSemantics(s.semantics); err != nil {
		return err
	}
	manifest, err := buildGaoN16RouteBArtifactManifest(s.capacityPlan, s.artifacts, s.semantics)
	if err != nil {
		return err
	}
	digest, err := digestGaoN16RouteBConstructionSpec(s)
	if err != nil {
		return err
	}
	if s.schema != gaoN16RouteBConstructionSpecSchema ||
		s.adaptationLabel != gaoN16PackingL11AdaptationLabel ||
		s.evidenceScope != gaoN16RouteBConstructionEvidenceScope ||
		s.maturity != RouteBConstructionContractOnlyUnverified ||
		s.sourceFaithful || s.fullPacked ||
		s.capacityPlanDigest != s.capacityPlan.Digest() ||
		s.parameterDigest != s.capacityPlan.ParameterDigest() ||
		s.profileDigest != s.capacityPlan.ProfileDigest() ||
		s.shapeDigest != s.capacityPlan.ShapeDigest() || s.policyDigest != s.capacityPlan.PolicyDigest() ||
		s.manifest != manifest || s.digest == "" || s.digest != digest {
		return routeBConstructionBlocked("construction spec is zero, stale, foreign, tampered, or promoted", nil)
	}
	return nil
}

// GaoN16RouteBConstructionPermit is minted only after the current capacity
// report and permit are independently rebuilt. It binds that exact snapshot,
// report and permit to the complete construction spec.
type GaoN16RouteBConstructionPermit struct {
	schema, adaptationLabel, evidenceScope                    string
	maturity                                                  Maturity
	decision                                                  CapacityDecision
	sourceFaithful, fullPacked                                bool
	specDigest                                                string
	capacityPlanDigest, capacityProbeDigest                   string
	capacityReportDigest, capacityPermitDigest                string
	parameterDigest, profileDigest, shapeDigest, policyDigest string
	snapshot                                                  PhysicalMemorySnapshot
	snapshotDigest                                            string
	artifacts                                                 GaoN16RouteBArtifactDigests
	semantics                                                 GaoN16RouteBConstructionSemantics
	manifest                                                  GaoN16RouteBArtifactManifest
	manifestDigest                                            string
	sealDigest                                                string
}

func (p GaoN16RouteBConstructionPermit) IsZero() bool                           { return p == (GaoN16RouteBConstructionPermit{}) }
func (p GaoN16RouteBConstructionPermit) SchemaVersion() string                  { return p.schema }
func (p GaoN16RouteBConstructionPermit) AdaptationLabel() string                { return p.adaptationLabel }
func (p GaoN16RouteBConstructionPermit) EvidenceScope() string                  { return p.evidenceScope }
func (p GaoN16RouteBConstructionPermit) Maturity() Maturity                     { return p.maturity }
func (p GaoN16RouteBConstructionPermit) Decision() CapacityDecision             { return p.decision }
func (p GaoN16RouteBConstructionPermit) IsSourceFaithful() bool                 { return p.sourceFaithful }
func (p GaoN16RouteBConstructionPermit) IsFullPacked() bool                     { return p.fullPacked }
func (p GaoN16RouteBConstructionPermit) SpecDigest() string                     { return p.specDigest }
func (p GaoN16RouteBConstructionPermit) CapacityPlanDigest() string             { return p.capacityPlanDigest }
func (p GaoN16RouteBConstructionPermit) CapacityProbeDigest() string            { return p.capacityProbeDigest }
func (p GaoN16RouteBConstructionPermit) CapacityReportDigest() string           { return p.capacityReportDigest }
func (p GaoN16RouteBConstructionPermit) CapacityPermitDigest() string           { return p.capacityPermitDigest }
func (p GaoN16RouteBConstructionPermit) ParameterDigest() string                { return p.parameterDigest }
func (p GaoN16RouteBConstructionPermit) ProfileDigest() string                  { return p.profileDigest }
func (p GaoN16RouteBConstructionPermit) ShapeDigest() string                    { return p.shapeDigest }
func (p GaoN16RouteBConstructionPermit) PolicyDigest() string                   { return p.policyDigest }
func (p GaoN16RouteBConstructionPermit) Snapshot() PhysicalMemorySnapshot       { return p.snapshot }
func (p GaoN16RouteBConstructionPermit) SnapshotDigest() string                 { return p.snapshotDigest }
func (p GaoN16RouteBConstructionPermit) Artifacts() GaoN16RouteBArtifactDigests { return p.artifacts }
func (p GaoN16RouteBConstructionPermit) Semantics() GaoN16RouteBConstructionSemantics {
	return p.semantics
}
func (p GaoN16RouteBConstructionPermit) PeakContract() GaoN16RouteBPeakContract {
	return p.semantics.peak
}
func (p GaoN16RouteBConstructionPermit) ArtifactManifest() GaoN16RouteBArtifactManifest {
	return p.manifest
}
func (p GaoN16RouteBConstructionPermit) ArtifactManifestDigest() string { return p.manifestDigest }
func (p GaoN16RouteBConstructionPermit) Digest() string                 { return p.sealDigest }

type gaoN16RouteBSnapshotDigestRecord struct {
	SchemaVersion                              string
	SnapshotID                                 string
	TotalPhysicalBytes, AvailablePhysicalBytes uint64
}

func digestGaoN16RouteBSnapshot(snapshot PhysicalMemorySnapshot) (string, error) {
	return digestGaoN16RouteBRecord(gaoN16RouteBSnapshotDigestRecord{
		SchemaVersion:          gaoN16RouteBSnapshotDigestSchema,
		SnapshotID:             snapshot.SnapshotID,
		TotalPhysicalBytes:     snapshot.TotalPhysicalBytes,
		AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes,
	}, "capacity snapshot")
}

type gaoN16RouteBConstructionPermitDigestRecord struct {
	SchemaVersion, AdaptationLabel, EvidenceScope             string
	Maturity                                                  Maturity
	Decision                                                  CapacityDecision
	SourceFaithful, FullPacked                                bool
	SpecDigest                                                string
	CapacityPlanDigest, CapacityProbeDigest                   string
	CapacityReportDigest, CapacityPermitDigest                string
	ParameterDigest, ProfileDigest, ShapeDigest, PolicyDigest string
	Snapshot                                                  PhysicalMemorySnapshot
	SnapshotDigest                                            string
	Artifacts                                                 gaoN16RouteBArtifactDigestRecord
	ArtifactDigest                                            string
	Semantics                                                 gaoN16RouteBConstructionSemanticsRecord
	SemanticsDigest                                           string
	ArtifactManifestDigest                                    string
}

func digestGaoN16RouteBConstructionPermit(value GaoN16RouteBConstructionPermit) (string, error) {
	return digestGaoN16RouteBRecord(gaoN16RouteBConstructionPermitDigestRecord{
		SchemaVersion: value.schema, AdaptationLabel: value.adaptationLabel, EvidenceScope: value.evidenceScope,
		Maturity: value.maturity, Decision: value.decision,
		SourceFaithful: value.sourceFaithful, FullPacked: value.fullPacked,
		SpecDigest:         value.specDigest,
		CapacityPlanDigest: value.capacityPlanDigest, CapacityProbeDigest: value.capacityProbeDigest,
		CapacityReportDigest: value.capacityReportDigest, CapacityPermitDigest: value.capacityPermitDigest,
		ParameterDigest: value.parameterDigest, ProfileDigest: value.profileDigest,
		ShapeDigest: value.shapeDigest, PolicyDigest: value.policyDigest,
		Snapshot: value.snapshot, SnapshotDigest: value.snapshotDigest,
		Artifacts: gaoN16RouteBArtifactRecord(value.artifacts), ArtifactDigest: value.artifacts.digest,
		Semantics: gaoN16RouteBSemanticsRecord(value.semantics), SemanticsDigest: value.semantics.digest,
		ArtifactManifestDigest: value.manifestDigest,
	}, "construction permit")
}

// Evaluate re-evaluates the current capacity inputs and mints the only permit
// for this spec, snapshot, capacity report and capacity permit combination.
func (s GaoN16RouteBConstructionSpec) Evaluate(
	snapshot PhysicalMemorySnapshot,
	capacityPermit GaoN16PackingL11CapacityPermit,
) (GaoN16RouteBConstructionPermit, error) {
	if err := s.validate(); err != nil {
		return GaoN16RouteBConstructionPermit{}, err
	}
	report, expectedCapacityPermit, err := s.capacityPlan.Evaluate(snapshot)
	if err != nil {
		return GaoN16RouteBConstructionPermit{}, routeBConstructionBlocked("current capacity evidence is not admitted", err)
	}
	if err = s.capacityPlan.ValidatePermit(snapshot, capacityPermit); err != nil {
		return GaoN16RouteBConstructionPermit{}, routeBConstructionBlocked("capacity permit did not revalidate", err)
	}
	if capacityPermit != expectedCapacityPermit {
		return GaoN16RouteBConstructionPermit{}, routeBConstructionBlocked("capacity permit is stale, foreign, tampered, or resealed", nil)
	}
	if err = s.validatePeakAgainstCapacity(report); err != nil {
		return GaoN16RouteBConstructionPermit{}, err
	}
	snapshotDigest, err := digestGaoN16RouteBSnapshot(snapshot)
	if err != nil {
		return GaoN16RouteBConstructionPermit{}, err
	}
	permit := GaoN16RouteBConstructionPermit{
		schema:          gaoN16RouteBConstructionPermitSchema,
		adaptationLabel: s.adaptationLabel, evidenceScope: s.evidenceScope,
		maturity: s.maturity, decision: Admitted,
		sourceFaithful: false, fullPacked: false,
		specDigest:          s.digest,
		capacityPlanDigest:  s.capacityPlanDigest,
		capacityProbeDigest: report.ProbeDigest(), capacityReportDigest: report.Digest(),
		capacityPermitDigest: capacityPermit.Digest(),
		parameterDigest:      s.parameterDigest, profileDigest: s.profileDigest,
		shapeDigest: s.shapeDigest, policyDigest: s.policyDigest,
		snapshot: snapshot, snapshotDigest: snapshotDigest,
		artifacts: s.artifacts, semantics: s.semantics, manifest: s.manifest,
		manifestDigest: s.manifest.digest,
	}
	permit.sealDigest, err = digestGaoN16RouteBConstructionPermit(permit)
	if err != nil {
		return GaoN16RouteBConstructionPermit{}, err
	}
	return permit, nil
}

func (s GaoN16RouteBConstructionSpec) validatePeakAgainstCapacity(report GaoN16PackingL11CapacityReport) error {
	peak := s.semantics.peak
	if s.capacityPlan.FullArtifactPeakBytes() != peak.fullArtifactPeakBytes ||
		s.capacityPlan.ProjectedIncrementalPeakBytes() != peak.preGuardIncrementalPeakBytes ||
		report.ProjectedIncrementalPeakBytes() != peak.preGuardIncrementalPeakBytes ||
		report.GuardedRequirementBytes() != peak.guardedRequirementBytes ||
		report.RemainingBelowLimitBytes() != peak.remainingBelowLimitBytes {
		return routeBConstructionBlocked("current capacity report differs from the exact Route-B peak contract", nil)
	}
	duplicateProjected, err := checkedUint64Sum(report.ProjectedSystemUsedBytes(), peak.forbiddenDuplicateDefaultBytes)
	if err != nil {
		return routeBConstructionBlocked("duplicate-default projected use overflow", err)
	}
	if duplicateProjected <= report.CapacityLimitBytes() ||
		peak.forbiddenDuplicateDefaultBytes-peak.remainingBelowLimitBytes != peak.forbiddenDuplicateExcessBytes {
		return routeBConstructionBlocked("duplicate-default schedule is not the frozen capacity contradiction", nil)
	}
	return nil
}

// ValidatePermit independently repeats Evaluate and compares the complete
// opaque value. Recomputing a seal after changing any field cannot authorize a
// different construction.
func (s GaoN16RouteBConstructionSpec) ValidatePermit(
	snapshot PhysicalMemorySnapshot,
	capacityPermit GaoN16PackingL11CapacityPermit,
	permit GaoN16RouteBConstructionPermit,
) error {
	expected, err := s.Evaluate(snapshot, capacityPermit)
	if err != nil {
		return err
	}
	digest, err := digestGaoN16RouteBConstructionPermit(permit)
	if err != nil {
		return err
	}
	if permit != expected || permit.sealDigest == "" || permit.sealDigest != digest ||
		!isCanonicalGaoN16RouteBDigest(permit.sealDigest) {
		return routeBConstructionBlocked("construction permit is zero, stale, foreign, tampered, resealed, or promoted", nil)
	}
	return nil
}

// GaoN16RouteBConstructionStage is deliberately HE-agnostic. The secure
// constructor may map its provider, builder and encoder stages here; none is
// invoked until both permits and all current capacity inputs revalidate.
type GaoN16RouteBConstructionStage func(GaoN16RouteBConstructionPermit) error

// RunAfterValidation supplies a narrow counter/test seam and an integration
// boundary for the later secure constructor. It contains no default
// constructor hook: the admitted schedule fixes that call count at zero.
func (s GaoN16RouteBConstructionSpec) RunAfterValidation(
	snapshot PhysicalMemorySnapshot,
	capacityPermit GaoN16PackingL11CapacityPermit,
	constructionPermit GaoN16RouteBConstructionPermit,
	provider, builder, encoder GaoN16RouteBConstructionStage,
) error {
	if err := s.ValidatePermit(snapshot, capacityPermit, constructionPermit); err != nil {
		return err
	}
	if provider == nil || builder == nil || encoder == nil {
		return routeBConstructionBlocked("provider, builder and encoder stages must all be present", nil)
	}
	for _, stage := range []struct {
		name string
		call GaoN16RouteBConstructionStage
	}{
		{name: "provider", call: provider},
		{name: "builder", call: builder},
		{name: "encoder", call: encoder},
	} {
		if err := stage.call(constructionPermit); err != nil {
			return routeBConstructionBlocked(stage.name+" stage failed", err)
		}
	}
	return nil
}

func isCanonicalGaoN16RouteBDigest(value string) bool {
	return isArtifactCapacityDigest(value) && value == strings.ToLower(value)
}

func digestGaoN16RouteBRecord(record any, label string) (string, error) {
	digest, err := digestCapacityRecord(record, "Route-B "+label)
	if err != nil {
		return "", routeBConstructionBlocked("cannot digest "+label, err)
	}
	return digest, nil
}
