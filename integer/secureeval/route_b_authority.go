package secureeval

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dt_go/integer/secureprofile"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
)

const routeBCapacitySnapshotDomain = "RBAUTH-capacity-snapshot-v1"

type routeBLineageState uint32

const (
	routeBLineageZero routeBLineageState = iota
	routeBLineageAuthorized
	routeBLineageBuilding
	routeBLineagePrivateUninstalled
	routeBLineageReadying
	routeBLineageReady
	routeBLineageInstalling
	routeBLineageInstalledUnverified
	routeBLineagePreflighting
	routeBLineageOperational
	routeBLineageFailed
)

type routeBAuthorityOwner struct{ marker byte }

type routeBLineageCell struct {
	owner *routeBAuthorityOwner
	state atomic.Uint32

	mintGeneration         uint64
	lastConsumedGeneration atomic.Uint64
	mintSampleTime         time.Time

	buildSpecIdentity                 RBAUTHDigest
	buildPermitIdentity               RBAUTHDigest
	mintCapacityReportIdentity        RBAUTHDigest
	mintCapacityPermitIdentity        RBAUTHDigest
	buildUseCapacityEvidenceIdentity  RBAUTHDigest
	buildReceiptIdentity              RBAUTHDigest
	artifactPairManifestIdentity      RBAUTHDigest
	actualPayload                     RBAUTHActualPayload
	readyUseCapacityEvidenceIdentity  RBAUTHDigest
	readySpecIdentity                 RBAUTHDigest
	readyPermitIdentity               RBAUTHDigest
	installCapacityEvidenceIdentity   RBAUTHDigest
	preflightCapacityEvidenceIdentity RBAUTHDigest
}

// ArtifactBuildPermit is the live, owner-bound build capability. Its report is
// serializable; its lineage is process-local and has no parser or constructor.
type ArtifactBuildPermit struct {
	report  ArtifactBuildPermitReport
	lineage *routeBLineageCell
}

func (permit ArtifactBuildPermit) IsZero() bool {
	return permit.lineage == nil || permit.report == (ArtifactBuildPermitReport{})
}

func (permit ArtifactBuildPermit) Report() ArtifactBuildPermitReport {
	return permit.report
}

func (permit ArtifactBuildPermit) MarshalBinary() ([]byte, error) {
	if permit.IsZero() {
		return nil, lineagef("build permit is zero")
	}
	return permit.report.MarshalBinary()
}

// RouteBAuthority is an opaque handle. Copies share one private cell, owner,
// sampler, raw parameter value, mutexes and global generation counter.
type RouteBAuthority struct {
	cell *routeBAuthorityCell
}

type routeBAuthorityCell struct {
	sampleMu  sync.Mutex
	prepareMu sync.Mutex

	owner       *routeBAuthorityOwner
	ownerSecret [sha256.Size]byte
	generation  uint64
	sampler     physicalMemorySampler
	raw         bootstrapping.Parameters

	sampleCalls             atomic.Uint64
	capacityEvaluationCalls atomic.Uint64
	prepareCalls            atomic.Uint64
}

type routeBCapabilityCell struct {
	owner      *routeBAuthorityOwner
	generation uint64
	consumed   atomic.Bool
}

type routeBCapacityCapability struct {
	cell       *routeBCapabilityCell
	generation uint64
	sampledAt  time.Time
	totals     physicalMemoryTotals
	snapshotID string
}

type routeBCapacityEvidence struct {
	generation uint64
	sampledAt  time.Time
	gate       routeBCapacityGate
	binding    RBAUTHCapacityBinding
	peak       RBAUTHPeakContract
}

type routeBCapacityGate uint8

const (
	routeBCapacityGateAuthorizeBuild routeBCapacityGate = iota + 1
	routeBCapacityGateBeginBuild
	routeBCapacityGateAuthorizeReady
	routeBCapacityGateInstall
	routeBCapacityGatePreflight
	routeBCapacityGateA2BFirstRound
	routeBCapacityGateA2BFull
	routeBCapacityGateSigned8RootTree
	routeBCapacityGateSigned8Depth2NodeBatch
	routeBCapacityGateSigned8Depth2SelectedChild
	routeBCapacityGateSigned8Radix4Node
)

type routeBCapacityPlan interface {
	Digest() string
	ParameterDigest() string
	ProfileDigest() string
	ShapeDigest() string
	PolicyDigest() string
	FullArtifactPeakBytes() uint64
	ProjectedIncrementalPeakBytes() uint64
	Evaluate(secureprofile.PhysicalMemorySnapshot) (secureprofile.GaoN16PackingL11CapacityReport, secureprofile.GaoN16PackingL11CapacityPermit, error)
	ValidateReport(secureprofile.PhysicalMemorySnapshot, secureprofile.GaoN16PackingL11CapacityReport) error
	ValidatePermit(secureprofile.PhysicalMemorySnapshot, secureprofile.GaoN16PackingL11CapacityPermit) error
}

// NewRouteBAuthority creates the sole production Authority surface. Capacity
// inputs and sampler injection are deliberately absent.
func NewRouteBAuthority() (*RouteBAuthority, error) {
	return newRouteBAuthorityWithSampler(productionPhysicalMemorySampler{})
}

func newRouteBAuthorityWithSampler(sampler physicalMemorySampler) (*RouteBAuthority, error) {
	if isNilPhysicalMemorySampler(sampler) {
		return nil, lineagef("physical-memory sampler is nil")
	}
	raw, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		return nil, fmt.Errorf("secureeval: construct stored Route-B parameters: %w", err)
	}
	cell := &routeBAuthorityCell{
		owner: &routeBAuthorityOwner{marker: 1}, sampler: sampler, raw: raw,
	}
	if _, err = rand.Read(cell.ownerSecret[:]); err != nil {
		return nil, fmt.Errorf("secureeval: generate Route-B Authority owner secret: %w", err)
	}
	if cell.ownerSecret == ([sha256.Size]byte{}) {
		return nil, errors.New("secureeval: generated an all-zero Route-B Authority owner secret")
	}
	return &RouteBAuthority{cell: cell}, nil
}

func isNilPhysicalMemorySampler(sampler physicalMemorySampler) bool {
	if sampler == nil {
		return true
	}
	value := reflect.ValueOf(sampler)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// AuthorizeBuild obtains trusted live capacity first, then prepares the stored
// canonical raw value, creates the unique payload-free records, and finally
// publishes a new owner-bound authorized lineage.
func (authority *RouteBAuthority) AuthorizeBuild() (ArtifactBuildSpec, ArtifactBuildPermit, error) {
	if authority == nil || authority.cell == nil || authority.cell.owner == nil || authority.cell.sampler == nil {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, lineagef("Authority is nil or uninitialized")
	}
	evidence, err := authority.cell.sampleAndEvaluateCapacity(routeBCapacityGateAuthorizeBuild)
	if err != nil {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, err
	}
	preparedDigest, transforms, err := authority.cell.prepareStoredParameters()
	if err != nil {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, blockedCause("prepare stored Route-B parameters", err)
	}
	return authority.cell.mintArtifactBuildPermit(evidence, preparedDigest, transforms)
}

func (cell *routeBAuthorityCell) sampleAndEvaluateCapacity(gate routeBCapacityGate) (routeBCapacityEvidence, error) {
	if err := validateRouteBCapacityGate(gate); err != nil {
		return routeBCapacityEvidence{}, err
	}
	cell.sampleMu.Lock()
	defer cell.sampleMu.Unlock()

	if cell.owner == nil || cell.sampler == nil {
		return routeBCapacityEvidence{}, lineagef("Authority capacity owner or sampler is nil")
	}
	if cell.generation == math.MaxUint64 {
		return routeBCapacityEvidence{}, blockedf("Authority capacity generation is exhausted")
	}
	cell.generation++
	generation := cell.generation
	cell.sampleCalls.Add(1)
	totals, err := cell.sampler.samplePhysicalMemory()
	if err != nil {
		return routeBCapacityEvidence{}, blockedCause("sample physical memory", err)
	}
	if err = totals.validate(); err != nil {
		return routeBCapacityEvidence{}, blockedCause("validate physical-memory sample", err)
	}

	capability := routeBCapacityCapability{
		cell:       &routeBCapabilityCell{owner: cell.owner, generation: generation},
		generation: generation,
		sampledAt:  time.Now().UTC(),
		totals:     totals,
		snapshotID: routeBCapacitySnapshotID(cell.ownerSecret, generation, totals),
	}
	snapshot, sampledAt, err := cell.consumeCapacityCapability(capability)
	capability = routeBCapacityCapability{}
	if err != nil {
		return routeBCapacityEvidence{}, err
	}

	cell.capacityEvaluationCalls.Add(1)
	plan, err := canonicalRouteBCapacityPlan(gate)
	if err != nil {
		return routeBCapacityEvidence{}, blockedCause("construct L11 gate capacity plan", err)
	}
	report, permit, err := plan.Evaluate(snapshot)
	if err != nil {
		return routeBCapacityEvidence{}, blockedCause(fmt.Sprintf(
			"evaluate L11 capacity (total=%d available=%d current-used=%d guarded=%d projected=%d strict-limit=%d)",
			snapshot.TotalPhysicalBytes, snapshot.AvailablePhysicalBytes,
			report.CurrentSystemUsedBytes(), report.GuardedRequirementBytes(),
			report.ProjectedSystemUsedBytes(), report.CapacityLimitBytes(),
		), err)
	}
	if err = plan.ValidateReport(snapshot, report); err != nil {
		return routeBCapacityEvidence{}, blockedCause("validate L11 capacity report", err)
	}
	if err = plan.ValidatePermit(snapshot, permit); err != nil {
		return routeBCapacityEvidence{}, blockedCause("validate L11 capacity permit", err)
	}
	peak, err := rbauthPeakContractForRequirement(
		totals.total, totals.available, plan.ProjectedIncrementalPeakBytes(),
	)
	if err != nil {
		return routeBCapacityEvidence{}, err
	}
	if plan.FullArtifactPeakBytes() != peak.FullArtifactPeakBytes ||
		plan.ProjectedIncrementalPeakBytes() != peak.PreGuardIncrementalPeakBytes ||
		report.GuardedRequirementBytes() != peak.GuardedRequirementBytes ||
		report.RemainingBelowLimitBytes() != peak.RemainingBelowLimitBytes {
		return routeBCapacityEvidence{}, blockedf("capacity plan/report and RBAUTH peak ledger disagree")
	}
	binding, err := rbauthCapacityBinding(plan, report, permit)
	if err != nil {
		return routeBCapacityEvidence{}, err
	}
	return routeBCapacityEvidence{
		generation: generation, sampledAt: sampledAt, gate: gate, binding: binding, peak: peak,
	}, nil
}

func validateRouteBCapacityGate(gate routeBCapacityGate) error {
	switch gate {
	case routeBCapacityGateAuthorizeBuild, routeBCapacityGateBeginBuild,
		routeBCapacityGateAuthorizeReady, routeBCapacityGateInstall,
		routeBCapacityGatePreflight, routeBCapacityGateA2BFirstRound,
		routeBCapacityGateA2BFull, routeBCapacityGateSigned8RootTree,
		routeBCapacityGateSigned8Depth2NodeBatch, routeBCapacityGateSigned8Depth2SelectedChild,
		routeBCapacityGateSigned8Radix4Node:
		return nil
	default:
		return lineagef("Route-B capacity gate is invalid")
	}
}

func canonicalRouteBCapacityPlan(gate routeBCapacityGate) (routeBCapacityPlan, error) {
	if err := validateRouteBCapacityGate(gate); err != nil {
		return nil, err
	}
	profile, err := secureprofile.NewGaoN16PackingL11Profile()
	if err != nil {
		return nil, err
	}
	shape := secureprofile.DefaultGaoN16PackingL11CapacityShape()
	policy := secureprofile.DefaultArtifactCapacityPolicy()
	if gate == routeBCapacityGateAuthorizeBuild {
		return secureprofile.NewGaoN16PackingL11CapacityPlan(profile, shape, policy)
	}
	var phase secureprofile.GaoN16PackingL11CapacityPhase
	switch gate {
	case routeBCapacityGateBeginBuild:
		phase = secureprofile.GaoN16PackingL11PhaseBeginBuild
	case routeBCapacityGateAuthorizeReady:
		phase = secureprofile.GaoN16PackingL11PhaseAuthorizeReady
	case routeBCapacityGateInstall:
		phase = secureprofile.GaoN16PackingL11PhaseInstall
	case routeBCapacityGatePreflight:
		phase = secureprofile.GaoN16PackingL11PhasePreflight
	case routeBCapacityGateA2BFirstRound:
		phase = secureprofile.GaoN16PackingL11PhaseA2BFirstRound
	case routeBCapacityGateA2BFull:
		phase = secureprofile.GaoN16PackingL11PhaseA2BFull
	case routeBCapacityGateSigned8RootTree:
		phase = secureprofile.GaoN16PackingL11PhaseSigned8RootTree
	case routeBCapacityGateSigned8Depth2NodeBatch:
		phase = secureprofile.GaoN16PackingL11PhaseSigned8Depth2NodeBatch
	case routeBCapacityGateSigned8Depth2SelectedChild:
		phase = secureprofile.GaoN16PackingL11PhaseSigned8Depth2SelectedChild
	case routeBCapacityGateSigned8Radix4Node:
		phase = secureprofile.GaoN16PackingL11PhaseSigned8Radix4Node
	}
	return secureprofile.NewGaoN16PackingL11PhaseCapacityPlan(profile, shape, policy, phase)
}

func (cell *routeBAuthorityCell) consumeCapacityCapability(capability routeBCapacityCapability) (
	secureprofile.PhysicalMemorySnapshot,
	time.Time,
	error,
) {
	if capability.cell == nil || capability.cell.owner == nil || capability.cell.owner != cell.owner ||
		capability.cell.generation != capability.generation || capability.generation != cell.generation {
		return secureprofile.PhysicalMemorySnapshot{}, time.Time{}, lineagef("capacity capability owner or generation is foreign")
	}
	if !capability.cell.consumed.CompareAndSwap(false, true) {
		return secureprofile.PhysicalMemorySnapshot{}, time.Time{}, lineagef("capacity capability was already consumed")
	}
	if err := capability.totals.validate(); err != nil {
		return secureprofile.PhysicalMemorySnapshot{}, time.Time{}, blockedCause("capacity capability totals", err)
	}
	wantID := routeBCapacitySnapshotID(cell.ownerSecret, capability.generation, capability.totals)
	if capability.snapshotID == "" || capability.snapshotID != wantID || capability.sampledAt.IsZero() {
		return secureprofile.PhysicalMemorySnapshot{}, time.Time{}, lineagef("capacity capability identity or sample time changed")
	}
	return secureprofile.PhysicalMemorySnapshot{
		SnapshotID: capability.snapshotID, TotalPhysicalBytes: capability.totals.total,
		AvailablePhysicalBytes: capability.totals.available,
	}, capability.sampledAt, nil
}

func (cell *routeBAuthorityCell) prepareStoredParameters() (RBAUTHDigest, RBAUTHTransformDigests, error) {
	_, digest, transforms, err := cell.prepareStoredParametersValue()
	return digest, transforms, err
}

func (cell *routeBAuthorityCell) prepareStoredParametersValue() (
	bootstrapping.PreparedParameters,
	RBAUTHDigest,
	RBAUTHTransformDigests,
	error,
) {
	cell.prepareMu.Lock()
	defer cell.prepareMu.Unlock()
	cell.prepareCalls.Add(1)
	prepared, transforms, err := prepareGaoN16RouteBTransportParametersFromRaw(cell.raw)
	if err != nil {
		return bootstrapping.PreparedParameters{}, RBAUTHDigest{}, RBAUTHTransformDigests{}, err
	}
	digest := RBAUTHDigest(prepared.Digest())
	return prepared, digest, transforms, nil
}

func (cell *routeBAuthorityCell) mintArtifactBuildPermit(
	evidence routeBCapacityEvidence,
	preparedDigest RBAUTHDigest,
	transforms RBAUTHTransformDigests,
) (ArtifactBuildSpec, ArtifactBuildPermit, error) {
	if cell.owner == nil || evidence.generation == 0 || evidence.sampledAt.IsZero() ||
		isZeroDigest(preparedDigest) {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, lineagef("build authorization inputs are empty")
	}
	spec := ArtifactBuildSpec{
		Classification: RBAUTHClassification{
			AdaptationLabel: RBAUTHAdaptationLabel, EvidenceScope: RBAUTHBuildEvidenceScope, Maturity: RBAUTHMaturity,
		},
		Capacity: evidence.binding, PreparedParameterDigest: preparedDigest, Transforms: transforms,
		GeneratorPrecisionBits: 256, EncoderPrecisionBits: 256,
		BuilderID: RBAUTHBuilderID, DigestID: RBAUTHDigestID, AllocationID: RBAUTHAllocationID,
		ReleaseID: RBAUTHReleaseID, OwnershipID: RBAUTHOwnershipID,
		ConstructionOrder: RBAUTHConstructionOrderSTCDropCTS,
		STCFactorCount:    2, STCDiagonalCounts: [2]uint32{63, 64},
		CTSFactorCount: 3, CTSDiagonalCounts: [3]uint32{16, 31, 15},
		ExpectedObservedStreamingDelta: 2,
		Scratch:                        defaultRBAUTHScratchLedger(), Peak: evidence.peak,
	}
	if err := spec.ValidateFrozenSemantics(); err != nil {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, err
	}
	specRecord, err := spec.MarshalBinary()
	if err != nil {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, err
	}
	specIdentity, err := RBAUTHRecordIdentity(specRecord)
	if err != nil {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, err
	}
	report := ArtifactBuildPermitReport{BuildSpecDigest: specIdentity, Spec: spec}
	if err = report.ValidateFrozenSemantics(); err != nil {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, err
	}
	permitRecord, err := report.MarshalBinary()
	if err != nil {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, err
	}
	permitIdentity, err := RBAUTHRecordIdentity(permitRecord)
	if err != nil {
		return ArtifactBuildSpec{}, ArtifactBuildPermit{}, err
	}
	lineage := &routeBLineageCell{
		owner: cell.owner, mintGeneration: evidence.generation, mintSampleTime: evidence.sampledAt,
		buildSpecIdentity: specIdentity, buildPermitIdentity: permitIdentity,
		mintCapacityReportIdentity: evidence.binding.CapacityReportDigest,
		mintCapacityPermitIdentity: evidence.binding.CapacityPermitDigest,
	}
	lineage.lastConsumedGeneration.Store(evidence.generation)
	lineage.state.Store(uint32(routeBLineageAuthorized))
	return spec, ArtifactBuildPermit{report: report, lineage: lineage}, nil
}

func rbauthCapacityBinding(
	plan interface{ Digest() string },
	report secureprofile.GaoN16PackingL11CapacityReport,
	permit secureprofile.GaoN16PackingL11CapacityPermit,
) (RBAUTHCapacityBinding, error) {
	snapshot := report.Snapshot()
	values := []struct {
		name, encoded string
		target        *RBAUTHDigest
	}{
		{name: "capacity plan", encoded: plan.Digest()},
		{name: "capacity probe", encoded: report.ProbeDigest()},
		{name: "capacity report", encoded: report.Digest()},
		{name: "capacity permit", encoded: permit.Digest()},
		{name: "parameter", encoded: report.ParameterDigest()},
		{name: "profile", encoded: report.ProfileDigest()},
		{name: "shape", encoded: report.ShapeDigest()},
		{name: "policy", encoded: report.PolicyDigest()},
	}
	result := RBAUTHCapacityBinding{
		SnapshotID: snapshot.SnapshotID, TotalPhysicalBytes: snapshot.TotalPhysicalBytes,
		AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes,
	}
	targets := []*RBAUTHDigest{
		&result.CapacityPlanDigest, &result.CapacityProbeDigest, &result.CapacityReportDigest,
		&result.CapacityPermitDigest, &result.ParameterDigest, &result.ProfileDigest,
		&result.ShapeDigest, &result.PolicyDigest,
	}
	for index := range values {
		values[index].target = targets[index]
		digest, err := decodeRBAUTHHexDigest(values[index].name, values[index].encoded)
		if err != nil {
			return RBAUTHCapacityBinding{}, err
		}
		*values[index].target = digest
	}
	if err := validateCapacity(result); err != nil {
		return RBAUTHCapacityBinding{}, err
	}
	return result, nil
}

func decodeRBAUTHHexDigest(name, encoded string) (RBAUTHDigest, error) {
	if len(encoded) != 2*sha256.Size || strings.ToLower(encoded) != encoded {
		return RBAUTHDigest{}, blockedf("%s digest is not canonical lowercase SHA-256", name)
	}
	payload, err := hex.DecodeString(encoded)
	if err != nil || len(payload) != sha256.Size {
		return RBAUTHDigest{}, blockedCause("decode "+name+" digest", err)
	}
	var digest RBAUTHDigest
	copy(digest[:], payload)
	if isZeroDigest(digest) {
		return RBAUTHDigest{}, blockedf("%s digest is zero", name)
	}
	return digest, nil
}

func routeBCapacitySnapshotID(secret [sha256.Size]byte, generation uint64, totals physicalMemoryTotals) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(routeBCapacitySnapshotDomain))
	_, _ = hash.Write(secret[:])
	var integers [3 * 8]byte
	binary.LittleEndian.PutUint64(integers[0:8], generation)
	binary.LittleEndian.PutUint64(integers[8:16], totals.total)
	binary.LittleEndian.PutUint64(integers[16:24], totals.available)
	_, _ = hash.Write(integers[:])
	return hex.EncodeToString(hash.Sum(nil))
}

func blockedCause(context string, cause error) error {
	if cause == nil {
		return blockedf("%s", context)
	}
	return fmt.Errorf("%w: %s: %w", ErrRBAUTHBlocked, context, cause)
}

func lineagef(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrRBAUTHLineage, fmt.Sprintf(format, values...))
}
