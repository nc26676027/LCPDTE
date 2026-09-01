package secureprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

const (
	ArtifactCapacityOnlyUnverified Maturity = "artifact_capacity_only_unverified"

	gaoN16ArtifactShapeSchema     = "gao-n16-artifact-capacity-shape-estimate-v1"
	artifactCapacityPolicySchema  = "gao-n16-artifact-capacity-policy-estimate-v1"
	gaoN16CapacityPlanSchema      = "gao-n16-artifact-capacity-plan-estimate-v1"
	artifactCapacityProbeSchema   = "gao-n16-artifact-capacity-probe-estimate-v1"
	artifactCapacityReportSchema  = "gao-n16-artifact-capacity-report-estimate-v1"
	artifactCapacityPermitSchema  = "gao-n16-artifact-capacity-permit-estimate-v1"
	gaoN16ExpectedParameterDigest = "c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816"
	gaoN16ExpectedProfileDigest   = "7e4f9308cfd099e9474f496412eb79da5e3a0c1f56625d37a687d067e5e99b89"
)

type CapacityDecision string

const (
	ResourceBlocked CapacityDecision = "RESOURCE_BLOCKED"
	Admitted        CapacityDecision = "ADMITTED"
)

// ErrArtifactCapacityBlocked is returned for every fail-closed capacity
// decision. It denotes resource admission only, never circuit correctness or
// security.
type ErrArtifactCapacityBlocked struct {
	reason string
	cause  error
}

func (e *ErrArtifactCapacityBlocked) Error() string {
	if e == nil {
		return "secureprofile: artifact capacity blocked"
	}
	if e.cause != nil {
		return fmt.Sprintf("secureprofile: artifact capacity blocked: %s: %v", e.reason, e.cause)
	}
	return "secureprofile: artifact capacity blocked: " + e.reason
}

func (e *ErrArtifactCapacityBlocked) Unwrap() error { return e.cause }
func (e *ErrArtifactCapacityBlocked) Reason() string {
	if e == nil {
		return ""
	}
	return e.reason
}

func artifactCapacityBlocked(reason string, cause error) error {
	return &ErrArtifactCapacityBlocked{reason: reason, cause: cause}
}

// GaoN16ArtifactShape is an immutable description of the exact dry-run
// artifact formulas. It contains estimates and bounds, not measured memory.
type GaoN16ArtifactShape struct {
	formulaVersion                   string
	logN, ringDegree, slots          uint64
	wordCapacity, qCount, pCount     uint64
	coefficientBytes                 uint64
	complexEntryBoundBytes           uint64
	textComplexBoundBytes            uint64
	textCopies                       uint64
	specificationTransformCount      uint64
	specificationVectorsPerTransform uint64
	compiledPairPolynomialCount      uint64
	stcFactorDiagonalCounts          []uint64
	ctsFactorDiagonalCounts          []uint64
	stcLevelQ, stcLevelP             int
	ctsLevelQ, ctsLevelP             int
	maskCount, maskLevelQ            uint64
	polynomialMappingCount           uint64
	polynomialCoefficientCount       uint64
}

func DefaultGaoN16ArtifactShape() GaoN16ArtifactShape {
	return GaoN16ArtifactShape{
		formulaVersion:                   gaoN16ArtifactShapeSchema,
		logN:                             16,
		ringDegree:                       65536,
		slots:                            32768,
		wordCapacity:                     8192,
		qCount:                           21,
		pCount:                           7,
		coefficientBytes:                 8,
		complexEntryBoundBytes:           256,
		textComplexBoundBytes:            192,
		textCopies:                       2,
		specificationTransformCount:      9,
		specificationVectorsPerTransform: 4,
		compiledPairPolynomialCount:      14,
		stcFactorDiagonalCounts:          []uint64{255, 256},
		ctsFactorDiagonalCounts:          []uint64{32, 63, 63},
		stcLevelQ:                        18,
		stcLevelP:                        6,
		ctsLevelQ:                        20,
		ctsLevelP:                        6,
		maskCount:                        2,
		maskLevelQ:                       19,
		polynomialMappingCount:           3,
		polynomialCoefficientCount:       79,
	}
}

func (s GaoN16ArtifactShape) LogN() uint64         { return s.logN }
func (s GaoN16ArtifactShape) RingDegree() uint64   { return s.ringDegree }
func (s GaoN16ArtifactShape) Slots() uint64        { return s.slots }
func (s GaoN16ArtifactShape) WordCapacity() uint64 { return s.wordCapacity }
func (s GaoN16ArtifactShape) QCount() uint64       { return s.qCount }
func (s GaoN16ArtifactShape) PCount() uint64       { return s.pCount }
func (s GaoN16ArtifactShape) STCLevelQ() int       { return s.stcLevelQ }
func (s GaoN16ArtifactShape) STCLevelP() int       { return s.stcLevelP }
func (s GaoN16ArtifactShape) CTSLevelQ() int       { return s.ctsLevelQ }
func (s GaoN16ArtifactShape) CTSLevelP() int       { return s.ctsLevelP }
func (s GaoN16ArtifactShape) MaskLevelQ() uint64   { return s.maskLevelQ }
func (s GaoN16ArtifactShape) STCFactorDiagonalCounts() []uint64 {
	return append([]uint64(nil), s.stcFactorDiagonalCounts...)
}
func (s GaoN16ArtifactShape) CTSFactorDiagonalCounts() []uint64 {
	return append([]uint64(nil), s.ctsFactorDiagonalCounts...)
}

func cloneGaoN16ArtifactShape(s GaoN16ArtifactShape) GaoN16ArtifactShape {
	s.stcFactorDiagonalCounts = append([]uint64(nil), s.stcFactorDiagonalCounts...)
	s.ctsFactorDiagonalCounts = append([]uint64(nil), s.ctsFactorDiagonalCounts...)
	return s
}

// CapacityPolicy is the sealed preregistered 80% policy with a conservative
// guard of max(512 MiB, projectedIncrementalPeak/10).
type CapacityPolicy struct {
	schema                   string
	limitNumerator           uint64
	limitDenominator         uint64
	minimumGuardBytes        uint64
	relativeGuardNumerator   uint64
	relativeGuardDenominator uint64
	digest                   string
}

func DefaultArtifactCapacityPolicy() CapacityPolicy {
	policy := CapacityPolicy{
		schema:         artifactCapacityPolicySchema,
		limitNumerator: 4, limitDenominator: 5,
		minimumGuardBytes:      536870912,
		relativeGuardNumerator: 1, relativeGuardDenominator: 10,
	}
	policy.digest = digestCapacityPolicy(policy)
	return policy
}

func (p CapacityPolicy) LimitNumerator() uint64           { return p.limitNumerator }
func (p CapacityPolicy) LimitDenominator() uint64         { return p.limitDenominator }
func (p CapacityPolicy) MinimumGuardBytes() uint64        { return p.minimumGuardBytes }
func (p CapacityPolicy) RelativeGuardNumerator() uint64   { return p.relativeGuardNumerator }
func (p CapacityPolicy) RelativeGuardDenominator() uint64 { return p.relativeGuardDenominator }
func (p CapacityPolicy) Digest() string                   { return p.digest }

type ArtifactCapacityEstimate struct {
	name                       string
	formula                    string
	residentBytes              uint64
	constructionTransientBytes uint64
	levelQ, levelP             int
	factorDiagonalCounts       []uint64
}

func (e ArtifactCapacityEstimate) Name() string          { return e.name }
func (e ArtifactCapacityEstimate) Formula() string       { return e.formula }
func (e ArtifactCapacityEstimate) ResidentBytes() uint64 { return e.residentBytes }
func (e ArtifactCapacityEstimate) ConstructionTransientBytes() uint64 {
	return e.constructionTransientBytes
}
func (e ArtifactCapacityEstimate) LevelQ() int { return e.levelQ }
func (e ArtifactCapacityEstimate) LevelP() int { return e.levelP }
func (e ArtifactCapacityEstimate) FactorDiagonalCounts() []uint64 {
	return append([]uint64(nil), e.factorDiagonalCounts...)
}

func cloneArtifactCapacityEstimate(e ArtifactCapacityEstimate) ArtifactCapacityEstimate {
	e.factorDiagonalCounts = append([]uint64(nil), e.factorDiagonalCounts...)
	return e
}

type ArtifactCapacityStageEstimate struct {
	name                      string
	formula                   string
	projectedIncrementalBytes uint64
}

func (s ArtifactCapacityStageEstimate) Name() string    { return s.name }
func (s ArtifactCapacityStageEstimate) Formula() string { return s.formula }
func (s ArtifactCapacityStageEstimate) ProjectedIncrementalBytes() uint64 {
	return s.projectedIncrementalBytes
}

// CapacityPlan seals the exact profile, deterministic shape and every
// conservative estimate. All fields are private and all aggregate accessors
// return detached copies.
type CapacityPlan struct {
	maturity                                    Maturity
	parameterDigest, profileDigest, shapeDigest string
	policyDigest, digest                        string
	shape                                       GaoN16ArtifactShape
	policy                                      CapacityPolicy
	artifactEstimates                           []ArtifactCapacityEstimate
	stageEstimates                              []ArtifactCapacityStageEstimate
	residentArtifactBytes                       uint64
	projectedIncrementalPeakBytes               uint64
}

func (p CapacityPlan) Maturity() Maturity            { return p.maturity }
func (p CapacityPlan) ParameterDigest() string       { return p.parameterDigest }
func (p CapacityPlan) ProfileDigest() string         { return p.profileDigest }
func (p CapacityPlan) ShapeDigest() string           { return p.shapeDigest }
func (p CapacityPlan) PolicyDigest() string          { return p.policyDigest }
func (p CapacityPlan) Digest() string                { return p.digest }
func (p CapacityPlan) ResidentArtifactBytes() uint64 { return p.residentArtifactBytes }
func (p CapacityPlan) ProjectedIncrementalPeakBytes() uint64 {
	return p.projectedIncrementalPeakBytes
}
func (p CapacityPlan) Shape() GaoN16ArtifactShape { return cloneGaoN16ArtifactShape(p.shape) }
func (p CapacityPlan) Policy() CapacityPolicy     { return p.policy }
func (p CapacityPlan) ArtifactEstimates() []ArtifactCapacityEstimate {
	result := make([]ArtifactCapacityEstimate, len(p.artifactEstimates))
	for i := range p.artifactEstimates {
		result[i] = cloneArtifactCapacityEstimate(p.artifactEstimates[i])
	}
	return result
}
func (p CapacityPlan) StageEstimates() []ArtifactCapacityStageEstimate {
	return append([]ArtifactCapacityStageEstimate(nil), p.stageEstimates...)
}

// PhysicalMemorySnapshot is always supplied explicitly by the caller. The
// dry-run never probes the operating system. SnapshotID is an opaque caller
// identity used to reject stale permits even when byte counts happen to match.
type PhysicalMemorySnapshot struct {
	SnapshotID             string
	TotalPhysicalBytes     uint64
	AvailablePhysicalBytes uint64
}

// CapacityReport is a sealed projection of one explicit snapshot. A blocked
// report is returned with a typed error so callers can retain the evidence,
// but it never carries a permit.
type CapacityReport struct {
	maturity                                                Maturity
	decision                                                CapacityDecision
	planDigest, parameterDigest, profileDigest, shapeDigest string
	policyDigest, probeDigest, digest                       string
	snapshot                                                PhysicalMemorySnapshot
	currentSystemUsedBytes, capacityLimitBytes              uint64
	residentArtifactBytes                                   uint64
	projectedIncrementalPeakBytes, guardBytes               uint64
	projectedSystemUsedBytes, remainingBytes                uint64
}

func (r CapacityReport) Maturity() Maturity               { return r.maturity }
func (r CapacityReport) Decision() CapacityDecision       { return r.decision }
func (r CapacityReport) PlanDigest() string               { return r.planDigest }
func (r CapacityReport) ParameterDigest() string          { return r.parameterDigest }
func (r CapacityReport) ProfileDigest() string            { return r.profileDigest }
func (r CapacityReport) ShapeDigest() string              { return r.shapeDigest }
func (r CapacityReport) PolicyDigest() string             { return r.policyDigest }
func (r CapacityReport) ProbeDigest() string              { return r.probeDigest }
func (r CapacityReport) Digest() string                   { return r.digest }
func (r CapacityReport) Snapshot() PhysicalMemorySnapshot { return r.snapshot }
func (r CapacityReport) CurrentSystemUsedBytes() uint64   { return r.currentSystemUsedBytes }
func (r CapacityReport) CapacityLimitBytes() uint64       { return r.capacityLimitBytes }
func (r CapacityReport) ResidentArtifactBytes() uint64    { return r.residentArtifactBytes }
func (r CapacityReport) ProjectedIncrementalPeakBytes() uint64 {
	return r.projectedIncrementalPeakBytes
}
func (r CapacityReport) GuardBytes() uint64               { return r.guardBytes }
func (r CapacityReport) ProjectedSystemUsedBytes() uint64 { return r.projectedSystemUsedBytes }
func (r CapacityReport) RemainingBelowLimitBytes() uint64 { return r.remainingBytes }

// CapacityPermit is deliberately opaque. Only an admitted, authenticated
// report can mint a non-zero permit.
type CapacityPermit struct {
	schema                                                  string
	maturity                                                Maturity
	decision                                                CapacityDecision
	planDigest, parameterDigest, profileDigest, shapeDigest string
	policyDigest, probeDigest, reportDigest, sealDigest     string
}

func (p CapacityPermit) IsZero() bool {
	return p.schema == "" && p.maturity == "" && p.decision == "" && p.planDigest == "" &&
		p.parameterDigest == "" && p.profileDigest == "" && p.shapeDigest == "" && p.policyDigest == "" &&
		p.probeDigest == "" && p.reportDigest == "" && p.sealDigest == ""
}
func (p CapacityPermit) Maturity() Maturity         { return p.maturity }
func (p CapacityPermit) Decision() CapacityDecision { return p.decision }
func (p CapacityPermit) ParameterDigest() string    { return p.parameterDigest }
func (p CapacityPermit) ProbeDigest() string        { return p.probeDigest }
func (p CapacityPermit) Digest() string             { return p.sealDigest }

// Evaluate applies the strict preregistered boundary to an explicit snapshot.
// Equality with the 80% limit is blocked. The method performs arithmetic only.
func (p CapacityPlan) Evaluate(snapshot PhysicalMemorySnapshot) (CapacityReport, CapacityPermit, error) {
	report, err := p.evaluateReport(snapshot)
	if err != nil {
		return report, CapacityPermit{}, err
	}
	permit := CapacityPermit{
		schema:   artifactCapacityPermitSchema,
		maturity: report.maturity, decision: report.decision,
		planDigest: report.planDigest, parameterDigest: report.parameterDigest,
		profileDigest: report.profileDigest,
		shapeDigest:   report.shapeDigest, policyDigest: report.policyDigest,
		probeDigest: report.probeDigest, reportDigest: report.digest,
	}
	permit.sealDigest, err = digestCapacityPermit(permit)
	if err != nil {
		return CapacityReport{}, CapacityPermit{}, err
	}
	return report, permit, nil
}

// ValidateReport authenticates a detached report against the exact plan and
// the caller's explicit snapshot.
func (p CapacityPlan) ValidateReport(snapshot PhysicalMemorySnapshot, report CapacityReport) error {
	expected, evaluationErr := p.evaluateReport(snapshot)
	if report.digest == "" || report.digest != expected.digest {
		return artifactCapacityBlocked("capacity report is zero, stale, foreign, or tampered", nil)
	}
	recomputed, err := digestCapacityReport(report)
	if err != nil {
		return err
	}
	if recomputed != report.digest {
		return artifactCapacityBlocked("capacity report seal changed", nil)
	}
	if evaluationErr != nil {
		var blocked *ErrArtifactCapacityBlocked
		if !errors.As(evaluationErr, &blocked) {
			return evaluationErr
		}
	}
	return nil
}

// ValidatePermit rejects zero, blocked, stale, foreign or modified permits.
// A caller may invoke its own artifact constructor only after this returns nil.
func (p CapacityPlan) ValidatePermit(snapshot PhysicalMemorySnapshot, permit CapacityPermit) error {
	expectedReport, err := p.evaluateReport(snapshot)
	if err != nil {
		// A blocked or arithmetically invalid snapshot can never authenticate an
		// admitted permit, even when the caller recomputes every public digest.
		return err
	}
	if expectedReport.decision != Admitted {
		return artifactCapacityBlocked("capacity report is not admitted", nil)
	}
	expected := CapacityPermit{
		schema: artifactCapacityPermitSchema, maturity: expectedReport.maturity,
		decision: expectedReport.decision, planDigest: expectedReport.planDigest,
		parameterDigest: expectedReport.parameterDigest, profileDigest: expectedReport.profileDigest,
		shapeDigest: expectedReport.shapeDigest, policyDigest: expectedReport.policyDigest,
		probeDigest: expectedReport.probeDigest, reportDigest: expectedReport.digest,
	}
	expected.sealDigest, err = digestCapacityPermit(expected)
	if err != nil {
		return err
	}
	if permit != expected || !isArtifactCapacityDigest(permit.reportDigest) ||
		!isArtifactCapacityDigest(permit.sealDigest) {
		return artifactCapacityBlocked("capacity permit is zero, blocked, stale, foreign, or tampered", nil)
	}
	return nil
}

func (p CapacityPlan) evaluateReport(snapshot PhysicalMemorySnapshot) (CapacityReport, error) {
	if err := p.validate(); err != nil {
		return CapacityReport{}, err
	}
	if err := validatePhysicalMemorySnapshot(snapshot); err != nil {
		return CapacityReport{}, err
	}
	probeDigest, err := digestArtifactCapacityProbe(p.policyDigest, snapshot)
	if err != nil {
		return CapacityReport{}, err
	}
	currentUsed := snapshot.TotalPhysicalBytes - snapshot.AvailablePhysicalBytes
	limitProduct, err := checkedUint64Product(snapshot.TotalPhysicalBytes, p.policy.limitNumerator)
	if err != nil {
		return CapacityReport{}, artifactCapacityBlocked("capacity limit overflow", err)
	}
	capacityLimit := limitProduct / p.policy.limitDenominator
	relativeGuardProduct, err := checkedUint64Product(p.projectedIncrementalPeakBytes, p.policy.relativeGuardNumerator)
	if err != nil {
		return CapacityReport{}, artifactCapacityBlocked("relative guard overflow", err)
	}
	// The versioned policy defines the relative guard with integer floor
	// division. The final admission boundary remains strict: projected use must
	// be strictly less than floor(totalPhysical*4/5).
	guard := relativeGuardProduct / p.policy.relativeGuardDenominator
	if guard < p.policy.minimumGuardBytes {
		guard = p.policy.minimumGuardBytes
	}
	projectedUsed, err := checkedUint64Sum(currentUsed, p.projectedIncrementalPeakBytes, guard)
	if err != nil {
		return CapacityReport{}, artifactCapacityBlocked("projected system use overflow", err)
	}
	decision := Admitted
	var remaining uint64
	if projectedUsed >= capacityLimit {
		decision = ResourceBlocked
	} else {
		remaining = capacityLimit - projectedUsed
	}
	report := CapacityReport{
		maturity: ArtifactCapacityOnlyUnverified, decision: decision,
		planDigest: p.digest, parameterDigest: p.parameterDigest,
		profileDigest: p.profileDigest, shapeDigest: p.shapeDigest,
		policyDigest: p.policyDigest, probeDigest: probeDigest, snapshot: snapshot,
		currentSystemUsedBytes: currentUsed, capacityLimitBytes: capacityLimit,
		residentArtifactBytes:         p.residentArtifactBytes,
		projectedIncrementalPeakBytes: p.projectedIncrementalPeakBytes,
		guardBytes:                    guard, projectedSystemUsedBytes: projectedUsed, remainingBytes: remaining,
	}
	report.digest, err = digestCapacityReport(report)
	if err != nil {
		return CapacityReport{}, err
	}
	if decision == ResourceBlocked {
		return report, artifactCapacityBlocked("projected use is at or over the strict 80% boundary", nil)
	}
	return report, nil
}

func validatePhysicalMemorySnapshot(snapshot PhysicalMemorySnapshot) error {
	if strings.TrimSpace(snapshot.SnapshotID) == "" || snapshot.TotalPhysicalBytes == 0 ||
		snapshot.AvailablePhysicalBytes > snapshot.TotalPhysicalBytes {
		return artifactCapacityBlocked("physical memory snapshot is invalid", nil)
	}
	return nil
}

func (p CapacityPlan) validate() error {
	if p.maturity != ArtifactCapacityOnlyUnverified || p.parameterDigest != gaoN16ExpectedParameterDigest ||
		p.profileDigest != gaoN16ExpectedProfileDigest {
		return artifactCapacityBlocked("capacity plan profile or maturity changed", nil)
	}
	shapeDigest, err := digestGaoN16ArtifactShape(p.shape)
	if err != nil {
		return err
	}
	expectedShapeDigest, err := digestGaoN16ArtifactShape(DefaultGaoN16ArtifactShape())
	if err != nil {
		return err
	}
	if shapeDigest != expectedShapeDigest || p.shapeDigest != shapeDigest {
		return artifactCapacityBlocked("capacity plan shape changed", nil)
	}
	if err = validateArtifactCapacityPolicy(p.policy); err != nil || p.policyDigest != p.policy.digest {
		return artifactCapacityBlocked("capacity plan policy changed", err)
	}
	estimates, stages, resident, peak, err := deriveGaoN16ArtifactEstimates(p.shape)
	if err != nil {
		return err
	}
	actualDigest, err := digestCapacityPlan(p)
	if err != nil {
		return err
	}
	if p.digest == "" || p.digest != actualDigest {
		return artifactCapacityBlocked("capacity plan artifact or stage seal changed", nil)
	}
	expected := p
	expected.artifactEstimates = estimates
	expected.stageEstimates = stages
	expected.residentArtifactBytes = resident
	expected.projectedIncrementalPeakBytes = peak
	expected.digest = ""
	expectedDigest, err := digestCapacityPlan(expected)
	if err != nil {
		return err
	}
	if p.residentArtifactBytes != resident || p.projectedIncrementalPeakBytes != peak || p.digest != expectedDigest {
		return artifactCapacityBlocked("capacity plan estimates or seal changed", nil)
	}
	return nil
}

// NewGaoN16ArtifactCapacityPlan is a deterministic dry-run. It does not probe
// the host and does not create an encoder, transform, key, evaluator or
// ciphertext.
func NewGaoN16ArtifactCapacityPlan(profile Profile, shape GaoN16ArtifactShape, policy CapacityPolicy) (CapacityPlan, error) {
	if err := validateGaoN16CapacityProfile(profile); err != nil {
		return CapacityPlan{}, err
	}
	shape = cloneGaoN16ArtifactShape(shape)
	shapeDigest, err := digestGaoN16ArtifactShape(shape)
	if err != nil {
		return CapacityPlan{}, err
	}
	if err = validateArtifactCapacityPolicy(policy); err != nil {
		return CapacityPlan{}, err
	}
	estimates, stages, resident, peak, err := deriveGaoN16ArtifactEstimates(shape)
	if err != nil {
		return CapacityPlan{}, err
	}
	expectedShapeDigest, err := digestGaoN16ArtifactShape(DefaultGaoN16ArtifactShape())
	if err != nil {
		return CapacityPlan{}, err
	}
	if shapeDigest != expectedShapeDigest || shape.logN != uint64(profile.logN) ||
		shape.slots != uint64(profile.slots) || shape.wordCapacity != uint64(profile.wordCapacity) ||
		shape.qCount != uint64(profile.qCount) || shape.pCount != uint64(profile.pCount) {
		return CapacityPlan{}, artifactCapacityBlocked("artifact shape or parameter profile drifted", nil)
	}
	plan := CapacityPlan{
		maturity:        ArtifactCapacityOnlyUnverified,
		parameterDigest: profile.parameterDigest, profileDigest: profile.digest, shapeDigest: shapeDigest,
		policyDigest: policy.digest, shape: shape, policy: policy,
		artifactEstimates: estimates, stageEstimates: stages,
		residentArtifactBytes: resident, projectedIncrementalPeakBytes: peak,
	}
	plan.digest, err = digestCapacityPlan(plan)
	if err != nil {
		return CapacityPlan{}, err
	}
	return plan, nil
}

func validateGaoN16CapacityProfile(profile Profile) error {
	digest, err := digestProfile(profile)
	if err != nil {
		return artifactCapacityBlocked("cannot authenticate parameter profile", err)
	}
	if profile.digest != digest || profile.parameterDigest != gaoN16ExpectedParameterDigest ||
		profile.digest != gaoN16ExpectedProfileDigest ||
		profile.maturity != ParameterCandidateUnverified || profile.logN != 16 || profile.slots != 32768 ||
		profile.wordCapacity != 8192 || profile.qCount != 21 || profile.pCount != 7 {
		return artifactCapacityBlocked("parameter profile is not the exact Gao N16 candidate", nil)
	}
	return nil
}

func validateArtifactCapacityPolicy(policy CapacityPolicy) error {
	expected := DefaultArtifactCapacityPolicy()
	if policy.schema != expected.schema || policy.limitNumerator != expected.limitNumerator ||
		policy.limitDenominator != expected.limitDenominator || policy.minimumGuardBytes != expected.minimumGuardBytes ||
		policy.relativeGuardNumerator != expected.relativeGuardNumerator ||
		policy.relativeGuardDenominator != expected.relativeGuardDenominator ||
		policy.digest != digestCapacityPolicy(policy) || policy.digest != expected.digest {
		return artifactCapacityBlocked("capacity policy drifted", nil)
	}
	return nil
}

func deriveGaoN16ArtifactEstimates(shape GaoN16ArtifactShape) (
	[]ArtifactCapacityEstimate,
	[]ArtifactCapacityStageEstimate,
	uint64,
	uint64,
	error,
) {
	stcDiagonals, err := checkedUint64Sum(shape.stcFactorDiagonalCounts...)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("STC diagonal count overflow", err)
	}
	ctsDiagonals, err := checkedUint64Sum(shape.ctsFactorDiagonalCounts...)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("CTS diagonal count overflow", err)
	}
	stcQCount, err := checkedLevelCount(shape.stcLevelQ)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("invalid STC Q level", err)
	}
	stcPCount, err := checkedLevelCount(shape.stcLevelP)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("invalid STC P level", err)
	}
	stcLimbs, err := checkedUint64Sum(stcQCount, stcPCount)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("STC limb count overflow", err)
	}
	ctsQCount, err := checkedLevelCount(shape.ctsLevelQ)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("invalid CTS Q level", err)
	}
	ctsPCount, err := checkedLevelCount(shape.ctsLevelP)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("invalid CTS P level", err)
	}
	ctsLimbs, err := checkedUint64Sum(ctsQCount, ctsPCount)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("CTS limb count overflow", err)
	}
	compiledPairLimbs, err := checkedUint64Sum(shape.qCount, shape.pCount)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("compiled pair limb count overflow", err)
	}

	specifications, err := checkedUint64Product(
		shape.specificationTransformCount, shape.specificationVectorsPerTransform,
		shape.slots, shape.complexEntryBoundBytes,
	)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("transform specification estimate overflow", err)
	}
	compiledPair, err := checkedUint64Product(
		shape.compiledPairPolynomialCount, shape.ringDegree, shape.coefficientBytes,
		compiledPairLimbs,
	)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("compiled transform pair estimate overflow", err)
	}
	stcEncoded, err := checkedUint64Product(stcDiagonals, shape.ringDegree, shape.coefficientBytes, stcLimbs)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("encoded STC estimate overflow", err)
	}
	ctsEncoded, err := checkedUint64Product(ctsDiagonals, shape.ringDegree, shape.coefficientBytes, ctsLimbs)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("encoded CTS estimate overflow", err)
	}
	maskQCount, err := checkedUint64Sum(shape.maskLevelQ, 1)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("mask level count overflow", err)
	}
	masks, err := checkedUint64Product(shape.maskCount, shape.ringDegree, shape.coefficientBytes, maskQCount)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("mask estimate overflow", err)
	}
	polynomialMappings, err := checkedUint64Product(shape.polynomialMappingCount, shape.slots, shape.coefficientBytes)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("polynomial mapping estimate overflow", err)
	}
	polynomialCoefficients, err := checkedUint64Product(shape.polynomialCoefficientCount, shape.complexEntryBoundBytes)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("polynomial coefficient estimate overflow", err)
	}
	polynomials, err := checkedUint64Sum(polynomialMappings, polynomialCoefficients)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("polynomial artifact estimate overflow", err)
	}
	stcHighPrecision, err := checkedUint64Product(stcDiagonals, shape.slots, shape.complexEntryBoundBytes)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("STC high-precision estimate overflow", err)
	}
	ctsHighPrecision, err := checkedUint64Product(ctsDiagonals, shape.slots, shape.complexEntryBoundBytes)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("CTS high-precision estimate overflow", err)
	}
	stcText, err := checkedUint64Product(stcDiagonals, shape.slots, shape.textComplexBoundBytes, shape.textCopies)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("STC textual digest estimate overflow", err)
	}
	ctsText, err := checkedUint64Product(ctsDiagonals, shape.slots, shape.textComplexBoundBytes, shape.textCopies)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("CTS textual digest estimate overflow", err)
	}

	estimates := []ArtifactCapacityEstimate{
		{name: "transform_specifications_bound", formula: "9*4*slots*256B", residentBytes: specifications, levelQ: -1, levelP: -1},
		{name: "compiled_transform_pair_bound", formula: "14*N*8B*(Q+P)", residentBytes: compiledPair, levelQ: -1, levelP: -1},
		{name: "encoded_stc_qp_exact", formula: "sum(255,256)*N*8B*((LQ18+1)+(LP6+1))", residentBytes: stcEncoded, levelQ: shape.stcLevelQ, levelP: shape.stcLevelP, factorDiagonalCounts: shape.STCFactorDiagonalCounts()},
		{name: "encoded_cts_qp_exact", formula: "sum(32,63,63)*N*8B*((LQ20+1)+(LP6+1))", residentBytes: ctsEncoded, levelQ: shape.ctsLevelQ, levelP: shape.ctsLevelP, factorDiagonalCounts: shape.CTSFactorDiagonalCounts()},
		{name: "q_only_masks_bound", formula: "2*N*8B*(LQ19+1)", residentBytes: masks, levelQ: int(shape.maskLevelQ), levelP: -1},
		{name: "polynomial_operands_bound", formula: "3*slots*8B+79*256B", residentBytes: polynomials, constructionTransientBytes: polynomials, levelQ: -1, levelP: -1},
		{name: "stc_high_precision_bound", formula: "sum(255,256)*slots*256B", constructionTransientBytes: stcHighPrecision, levelQ: shape.stcLevelQ, levelP: shape.stcLevelP, factorDiagonalCounts: shape.STCFactorDiagonalCounts()},
		{name: "cts_high_precision_bound", formula: "sum(32,63,63)*slots*256B", constructionTransientBytes: ctsHighPrecision, levelQ: shape.ctsLevelQ, levelP: shape.ctsLevelP, factorDiagonalCounts: shape.CTSFactorDiagonalCounts()},
		{name: "stc_text_digest_bound", formula: "sum(255,256)*slots*192B*2copies", constructionTransientBytes: stcText, levelQ: shape.stcLevelQ, levelP: shape.stcLevelP, factorDiagonalCounts: shape.STCFactorDiagonalCounts()},
		{name: "cts_text_digest_bound", formula: "sum(32,63,63)*slots*192B*2copies", constructionTransientBytes: ctsText, levelQ: shape.ctsLevelQ, levelP: shape.ctsLevelP, factorDiagonalCounts: shape.CTSFactorDiagonalCounts()},
	}
	resident, err := checkedUint64Sum(specifications, compiledPair, stcEncoded, ctsEncoded, masks, polynomials)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("resident artifact estimate overflow", err)
	}
	base, err := checkedUint64Sum(specifications, compiledPair, masks, polynomials)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("base resident estimate overflow", err)
	}
	stcStage, err := checkedUint64Sum(base, stcEncoded, stcHighPrecision, stcText)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("STC construction peak overflow", err)
	}
	ctsStage, err := checkedUint64Sum(base, stcEncoded, ctsEncoded, ctsHighPrecision, ctsText)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("CTS construction peak overflow", err)
	}
	polynomialCloneStage, err := checkedUint64Sum(resident, polynomials)
	if err != nil {
		return nil, nil, 0, 0, artifactCapacityBlocked("polynomial clone peak overflow", err)
	}
	stages := []ArtifactCapacityStageEstimate{
		{name: "stc_non_streaming_digest_bound", formula: "base-resident+encoded-STC+STC-high-precision+STC-text-and-copy", projectedIncrementalBytes: stcStage},
		{name: "cts_non_streaming_digest_bound", formula: "base-resident+encoded-STC+encoded-CTS+CTS-high-precision+CTS-text-and-copy", projectedIncrementalBytes: ctsStage},
		{name: "polynomial_clone_bound", formula: "final-resident+polynomial-clone", projectedIncrementalBytes: polynomialCloneStage},
	}
	peak := stcStage
	if ctsStage > peak {
		peak = ctsStage
	}
	if polynomialCloneStage > peak {
		peak = polynomialCloneStage
	}
	return estimates, stages, resident, peak, nil
}

type gaoN16ArtifactShapeDigestRecord struct {
	SchemaVersion, FormulaVersion                                 string
	LogN, RingDegree, Slots, WordCapacity, QCount, PCount         uint64
	CoefficientBytes, ComplexEntryBoundBytes                      uint64
	TextComplexBoundBytes, TextCopies                             uint64
	SpecificationTransformCount, SpecificationVectorsPerTransform uint64
	CompiledPairPolynomialCount                                   uint64
	STCFactorDiagonalCounts, CTSFactorDiagonalCounts              []uint64
	STCLevelQ, STCLevelP, CTSLevelQ, CTSLevelP                    int
	MaskCount, MaskLevelQ                                         uint64
	PolynomialMappingCount, PolynomialCoefficientCount            uint64
}

func digestGaoN16ArtifactShape(shape GaoN16ArtifactShape) (string, error) {
	record := gaoN16ArtifactShapeDigestRecord{
		SchemaVersion: gaoN16ArtifactShapeSchema, FormulaVersion: shape.formulaVersion,
		LogN: shape.logN, RingDegree: shape.ringDegree, Slots: shape.slots,
		WordCapacity: shape.wordCapacity, QCount: shape.qCount, PCount: shape.pCount,
		CoefficientBytes: shape.coefficientBytes, ComplexEntryBoundBytes: shape.complexEntryBoundBytes,
		TextComplexBoundBytes: shape.textComplexBoundBytes, TextCopies: shape.textCopies,
		SpecificationTransformCount:      shape.specificationTransformCount,
		SpecificationVectorsPerTransform: shape.specificationVectorsPerTransform,
		CompiledPairPolynomialCount:      shape.compiledPairPolynomialCount,
		STCFactorDiagonalCounts:          shape.STCFactorDiagonalCounts(), CTSFactorDiagonalCounts: shape.CTSFactorDiagonalCounts(),
		STCLevelQ: shape.stcLevelQ, STCLevelP: shape.stcLevelP,
		CTSLevelQ: shape.ctsLevelQ, CTSLevelP: shape.ctsLevelP,
		MaskCount: shape.maskCount, MaskLevelQ: shape.maskLevelQ,
		PolynomialMappingCount:     shape.polynomialMappingCount,
		PolynomialCoefficientCount: shape.polynomialCoefficientCount,
	}
	return digestCapacityRecord(record, "artifact shape")
}

type capacityPolicyDigestRecord struct {
	SchemaVersion                                    string
	LimitNumerator, LimitDenominator                 uint64
	MinimumGuardBytes                                uint64
	RelativeGuardNumerator, RelativeGuardDenominator uint64
	BoundaryRule                                     string
}

func digestCapacityPolicy(policy CapacityPolicy) string {
	record := capacityPolicyDigestRecord{
		SchemaVersion:  policy.schema,
		LimitNumerator: policy.limitNumerator, LimitDenominator: policy.limitDenominator,
		MinimumGuardBytes:        policy.minimumGuardBytes,
		RelativeGuardNumerator:   policy.relativeGuardNumerator,
		RelativeGuardDenominator: policy.relativeGuardDenominator,
		BoundaryRule:             "projected-used-strictly-less-than-floor-limit",
	}
	digest, err := digestCapacityRecord(record, "capacity policy")
	if err != nil {
		return ""
	}
	return digest
}

type capacityPlanDigestRecord struct {
	SchemaVersion                                             string
	Maturity                                                  Maturity
	ParameterDigest, ProfileDigest, ShapeDigest, PolicyDigest string
	ArtifactEstimates                                         []artifactCapacityEstimateDigestRecord
	StageEstimates                                            []artifactCapacityStageDigestRecord
	ResidentArtifactBytes, ProjectedIncrementalPeakBytes      uint64
}

type artifactCapacityEstimateDigestRecord struct {
	Name, Formula                             string
	ResidentBytes, ConstructionTransientBytes uint64
	LevelQ, LevelP                            int
	FactorDiagonalCounts                      []uint64
}

type artifactCapacityStageDigestRecord struct {
	Name, Formula             string
	ProjectedIncrementalBytes uint64
}

func digestCapacityPlan(plan CapacityPlan) (string, error) {
	artifacts := make([]artifactCapacityEstimateDigestRecord, len(plan.artifactEstimates))
	for i, estimate := range plan.artifactEstimates {
		artifacts[i] = artifactCapacityEstimateDigestRecord{
			Name: estimate.name, Formula: estimate.formula,
			ResidentBytes:              estimate.residentBytes,
			ConstructionTransientBytes: estimate.constructionTransientBytes,
			LevelQ:                     estimate.levelQ, LevelP: estimate.levelP,
			FactorDiagonalCounts: estimate.FactorDiagonalCounts(),
		}
	}
	stages := make([]artifactCapacityStageDigestRecord, len(plan.stageEstimates))
	for i, stage := range plan.stageEstimates {
		stages[i] = artifactCapacityStageDigestRecord{
			Name: stage.name, Formula: stage.formula,
			ProjectedIncrementalBytes: stage.projectedIncrementalBytes,
		}
	}
	record := capacityPlanDigestRecord{
		SchemaVersion: gaoN16CapacityPlanSchema, Maturity: plan.maturity,
		ParameterDigest: plan.parameterDigest, ProfileDigest: plan.profileDigest,
		ShapeDigest: plan.shapeDigest, PolicyDigest: plan.policyDigest,
		ArtifactEstimates: artifacts, StageEstimates: stages,
		ResidentArtifactBytes:         plan.residentArtifactBytes,
		ProjectedIncrementalPeakBytes: plan.projectedIncrementalPeakBytes,
	}
	return digestCapacityRecord(record, "capacity plan")
}

type artifactCapacityProbeDigestRecord struct {
	SchemaVersion                              string
	PolicyDigest                               string
	SnapshotID                                 string
	TotalPhysicalBytes, AvailablePhysicalBytes uint64
}

func digestArtifactCapacityProbe(policyDigest string, snapshot PhysicalMemorySnapshot) (string, error) {
	return digestCapacityRecord(artifactCapacityProbeDigestRecord{
		SchemaVersion: artifactCapacityProbeSchema, PolicyDigest: policyDigest,
		SnapshotID: snapshot.SnapshotID, TotalPhysicalBytes: snapshot.TotalPhysicalBytes,
		AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes,
	}, "capacity probe")
}

type capacityReportDigestRecord struct {
	SchemaVersion                                                                      string
	Maturity                                                                           Maturity
	Decision                                                                           CapacityDecision
	PlanDigest, ParameterDigest, ProfileDigest, ShapeDigest, PolicyDigest, ProbeDigest string
	Snapshot                                                                           PhysicalMemorySnapshot
	CurrentSystemUsedBytes, CapacityLimitBytes                                         uint64
	ResidentArtifactBytes, ProjectedIncrementalPeakBytes                               uint64
	GuardBytes, ProjectedSystemUsedBytes, RemainingBytes                               uint64
}

func digestCapacityReport(report CapacityReport) (string, error) {
	return digestCapacityRecord(capacityReportDigestRecord{
		SchemaVersion: artifactCapacityReportSchema, Maturity: report.maturity, Decision: report.decision,
		PlanDigest: report.planDigest, ParameterDigest: report.parameterDigest,
		ProfileDigest: report.profileDigest,
		ShapeDigest:   report.shapeDigest, PolicyDigest: report.policyDigest, ProbeDigest: report.probeDigest,
		Snapshot: report.snapshot, CurrentSystemUsedBytes: report.currentSystemUsedBytes,
		CapacityLimitBytes: report.capacityLimitBytes, ResidentArtifactBytes: report.residentArtifactBytes,
		ProjectedIncrementalPeakBytes: report.projectedIncrementalPeakBytes,
		GuardBytes:                    report.guardBytes, ProjectedSystemUsedBytes: report.projectedSystemUsedBytes,
		RemainingBytes: report.remainingBytes,
	}, "capacity report")
}

type capacityPermitDigestRecord struct {
	SchemaVersion                                                         string
	Maturity                                                              Maturity
	Decision                                                              CapacityDecision
	PlanDigest, ParameterDigest, ProfileDigest, ShapeDigest, PolicyDigest string
	ProbeDigest, ReportDigest                                             string
}

func digestCapacityPermit(permit CapacityPermit) (string, error) {
	return digestCapacityRecord(capacityPermitDigestRecord{
		SchemaVersion: permit.schema, Maturity: permit.maturity, Decision: permit.decision,
		PlanDigest: permit.planDigest, ParameterDigest: permit.parameterDigest,
		ProfileDigest: permit.profileDigest,
		ShapeDigest:   permit.shapeDigest, PolicyDigest: permit.policyDigest,
		ProbeDigest: permit.probeDigest, ReportDigest: permit.reportDigest,
	}, "capacity permit")
}

func isArtifactCapacityDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func digestCapacityRecord(record any, label string) (string, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", artifactCapacityBlocked("cannot encode "+label+" digest", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func checkedUint64Product(values ...uint64) (uint64, error) {
	result := uint64(1)
	for _, value := range values {
		if value != 0 && result > math.MaxUint64/value {
			return 0, errors.New("uint64 multiplication overflow")
		}
		result *= value
	}
	return result, nil
}

func checkedUint64Sum(values ...uint64) (uint64, error) {
	var result uint64
	for _, value := range values {
		if result > math.MaxUint64-value {
			return 0, errors.New("uint64 addition overflow")
		}
		result += value
	}
	return result, nil
}

func checkedLevelCount(level int) (uint64, error) {
	if level < 0 {
		return 0, errors.New("negative level")
	}
	return checkedUint64Sum(uint64(level), 1)
}
