package secureeval

import (
	"crypto/sha256"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureprofile"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
)

const (
	routeBRuntimeCapacityDomain                      = "RBAUTH-runtime-capacity-v1"
	routeBRuntimeOperationBeginBuild                 = "begin-build"
	routeBRuntimeOperationAuthorizeReady             = "authorize-ready"
	routeBRuntimeOperationInstall                    = "install"
	routeBRuntimeOperationPreflight                  = "preflight"
	routeBRuntimeOperationA2BFirstRound              = "a2b-first-round"
	routeBRuntimeOperationA2BFull                    = "a2b-full"
	routeBRuntimeOperationSigned8RootTree            = "signed8-root-tree"
	routeBRuntimeOperationSigned8Depth2NodeBatch     = "signed8-depth2-node-batch"
	routeBRuntimeOperationSigned8Depth2SelectedChild = "signed8-depth2-selected-child"
	routeBRuntimeOperationSigned8Radix4Node          = "signed8-radix4-node"
)

// RuntimeCapacityEvidenceReport is inert audit evidence for one live gate.
// No live method accepts it as input or converts it back into a capability.
type RuntimeCapacityEvidenceReport struct {
	Operation       string
	Generation      uint64
	SampledAt       time.Time
	Capacity        RBAUTHCapacityBinding
	Peak            RBAUTHPeakContract
	LineageIdentity RBAUTHDigest
	Digest          RBAUTHDigest
}

func (value RuntimeCapacityEvidenceReport) Validate() error {
	switch value.Operation {
	case routeBRuntimeOperationBeginBuild, routeBRuntimeOperationAuthorizeReady,
		routeBRuntimeOperationInstall, routeBRuntimeOperationPreflight,
		routeBRuntimeOperationA2BFirstRound, routeBRuntimeOperationA2BFull,
		routeBRuntimeOperationSigned8RootTree, routeBRuntimeOperationSigned8Depth2NodeBatch,
		routeBRuntimeOperationSigned8Depth2SelectedChild, routeBRuntimeOperationSigned8Radix4Node:
	default:
		return lineagef("runtime-capacity evidence operation is invalid")
	}
	if value.Generation == 0 || value.SampledAt.IsZero() || value.SampledAt.UnixNano() <= 0 ||
		isZeroDigest(value.LineageIdentity) {
		return lineagef("runtime-capacity evidence operation, generation, time, or lineage is empty")
	}
	if err := validateCapacity(value.Capacity); err != nil {
		return err
	}
	gate, err := routeBCapacityGateForRuntimeOperation(value.Operation)
	if err != nil {
		return err
	}
	plan, err := canonicalRouteBCapacityPlan(gate)
	if err != nil {
		return lineagef("cannot reconstruct runtime-capacity phase plan: %v", err)
	}
	snapshot := secureprofile.PhysicalMemorySnapshot{
		SnapshotID: value.Capacity.SnapshotID, TotalPhysicalBytes: value.Capacity.TotalPhysicalBytes,
		AvailablePhysicalBytes: value.Capacity.AvailablePhysicalBytes,
	}
	report, permit, err := plan.Evaluate(snapshot)
	if err != nil {
		return lineagef("runtime-capacity phase is not canonically admitted: %v", err)
	}
	expectedBinding, err := rbauthCapacityBinding(plan, report, permit)
	if err != nil {
		return err
	}
	expectedPeak, err := rbauthPeakContractForRequirement(
		value.Capacity.TotalPhysicalBytes, value.Capacity.AvailablePhysicalBytes,
		plan.ProjectedIncrementalPeakBytes(),
	)
	if err != nil {
		return err
	}
	if value.Capacity != expectedBinding || value.Peak != expectedPeak ||
		value.Digest != digestRuntimeCapacityEvidence(value) {
		return lineagef("runtime-capacity phase binding, peak, or identity changed")
	}
	return nil
}

func routeBCapacityGateForRuntimeOperation(operation string) (routeBCapacityGate, error) {
	switch operation {
	case routeBRuntimeOperationBeginBuild:
		return routeBCapacityGateBeginBuild, nil
	case routeBRuntimeOperationAuthorizeReady:
		return routeBCapacityGateAuthorizeReady, nil
	case routeBRuntimeOperationInstall:
		return routeBCapacityGateInstall, nil
	case routeBRuntimeOperationPreflight:
		return routeBCapacityGatePreflight, nil
	case routeBRuntimeOperationA2BFirstRound:
		return routeBCapacityGateA2BFirstRound, nil
	case routeBRuntimeOperationA2BFull:
		return routeBCapacityGateA2BFull, nil
	case routeBRuntimeOperationSigned8RootTree:
		return routeBCapacityGateSigned8RootTree, nil
	case routeBRuntimeOperationSigned8Depth2NodeBatch:
		return routeBCapacityGateSigned8Depth2NodeBatch, nil
	case routeBRuntimeOperationSigned8Depth2SelectedChild:
		return routeBCapacityGateSigned8Depth2SelectedChild, nil
	case routeBRuntimeOperationSigned8Radix4Node:
		return routeBCapacityGateSigned8Radix4Node, nil
	default:
		return 0, lineagef("runtime-capacity evidence operation is invalid")
	}
}

// ArtifactBuildReceipt is the live owner-bound receipt. Its report and record
// copies are inert; only the private lineage makes this value live.
type ArtifactBuildReceipt struct {
	report  RBDFTBuildReceiptReport
	records RBDFTBuildRecordSet
	runtime RuntimeCapacityEvidenceReport
	lineage *routeBLineageCell
}

func (receipt ArtifactBuildReceipt) IsZero() bool {
	return receipt.lineage == nil || receipt.report == (RBDFTBuildReceiptReport{}) ||
		len(receipt.records.BuildReceipt) == 0 || receipt.runtime.Digest == (RBAUTHDigest{})
}

func (receipt ArtifactBuildReceipt) Report() RBDFTBuildReceiptReport { return receipt.report }

func (receipt ArtifactBuildReceipt) Records() RBDFTBuildRecordSet {
	return cloneRBDFTBuildRecordSet(receipt.records)
}

func (receipt ArtifactBuildReceipt) RuntimeCapacityEvidence() RuntimeCapacityEvidenceReport {
	return receipt.runtime
}

func (receipt ArtifactBuildReceipt) MarshalBinary() ([]byte, error) {
	if receipt.IsZero() || receipt.lineage.owner == nil {
		return nil, lineagef("build receipt is zero or unowned")
	}
	if err := receipt.runtime.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateRBDFTBuildRecordLinks(
		receipt.records, receipt.lineage.buildPermitIdentity, receipt.report.PreparedParameterDigest,
	); err != nil {
		return nil, err
	}
	identity := RBAUTHDigest(sha256.Sum256(receipt.records.BuildReceipt))
	pairIdentity := RBAUTHDigest(sha256.Sum256(receipt.records.ArtifactPair))
	parsed, err := ParseRBDFTBuildReceipt(receipt.records.BuildReceipt)
	if err != nil {
		return nil, err
	}
	if parsed != receipt.report || identity != receipt.lineage.buildReceiptIdentity ||
		pairIdentity != receipt.lineage.artifactPairManifestIdentity ||
		receipt.report.Payload != receipt.lineage.actualPayload ||
		receipt.runtime.Digest != receipt.lineage.buildUseCapacityEvidenceIdentity {
		return nil, lineagef("build receipt differs from its private anchors")
	}
	return append([]byte(nil), receipt.records.BuildReceipt...), nil
}

// RouteBArtifact is an opaque handle to the private, uninstalled matrix pair.
// Copies share the same cell and cannot duplicate the consuming right.
type RouteBArtifact struct {
	cell *routeBArtifactCell
}

type routeBArtifactCell struct {
	lineage   *routeBLineageCell
	available atomic.Bool
	stc       dft.Matrix
	cts       dft.Matrix
	records   RBDFTBuildRecordSet
}

func (artifact RouteBArtifact) IsZero() bool {
	return artifact.cell == nil || artifact.cell.lineage == nil || !artifact.cell.available.Load()
}

type routeBArtifactBuilder func(
	bootstrapping.PreparedParameters,
	RBAUTHDigest,
) (routeBArtifactBuildProduct, error)

type routeBArtifactProductValidator func(
	routeBArtifactBuildProduct,
	bootstrapping.PreparedParameters,
) error

type routeBBuildPermitUse struct {
	lineage        *routeBLineageCell
	spec           ArtifactBuildSpec
	permitIdentity RBAUTHDigest
}

// BeginBuild consumes a live authorized lineage after a fresh trusted capacity
// gate and constructs the canonical private Route-B factor artifact.
func (authority *RouteBAuthority) BeginBuild(permit ArtifactBuildPermit) (
	ArtifactBuildReceipt,
	RouteBArtifact,
	error,
) {
	return authority.beginBuildWithBuilder(permit, buildCanonicalRouteBArtifact, validateCanonicalRouteBArtifactProduct)
}

func (authority *RouteBAuthority) beginBuildWithBuilder(
	permit ArtifactBuildPermit,
	builder routeBArtifactBuilder,
	validator routeBArtifactProductValidator,
) (
	receipt ArtifactBuildReceipt,
	artifact RouteBArtifact,
	err error,
) {
	if builder == nil || validator == nil {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, lineagef("artifact builder or validator is nil")
	}
	use, err := authority.validateBuildPermitBeforeUse(permit)
	if err != nil {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, err
	}

	evidence, err := authority.cell.sampleAndEvaluateCapacity(routeBCapacityGateBeginBuild)
	if err != nil {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, err
	}
	prepared, preparedIdentity, transforms, err := authority.cell.prepareStoredParametersValue()
	if err != nil {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, blockedCause("prepare stored Route-B parameters for build", err)
	}
	if preparedIdentity != use.spec.PreparedParameterDigest || transforms != use.spec.Transforms {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, lineagef("build-use preparation differs from the authorized specification")
	}
	if _, err = authority.validateBuildPermitBeforeUse(permit); err != nil {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, err
	}
	if evidence.generation <= use.lineage.lastConsumedGeneration.Load() {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, lineagef("build-use capacity generation is not newer than the lineage")
	}
	runtimeEvidence := newRuntimeCapacityEvidence(
		routeBRuntimeOperationBeginBuild, evidence, use.permitIdentity,
	)
	if err = runtimeEvidence.Validate(); err != nil {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, err
	}
	if !use.lineage.state.CompareAndSwap(uint32(routeBLineageAuthorized), uint32(routeBLineageBuilding)) {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, lineagef("build lineage is no longer authorized")
	}
	wonTransition := true
	published := false
	use.lineage.lastConsumedGeneration.Store(evidence.generation)
	use.lineage.buildUseCapacityEvidenceIdentity = runtimeEvidence.Digest
	defer func() {
		prepared = bootstrapping.PreparedParameters{}
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("secureeval: Route-B BeginBuild panicked: %v", recovered)
		}
		if wonTransition && !published {
			use.lineage.state.Store(uint32(routeBLineageFailed))
			receipt = ArtifactBuildReceipt{}
			artifact = RouteBArtifact{}
		}
	}()

	product, err := builder(prepared, use.permitIdentity)
	if err != nil {
		return ArtifactBuildReceipt{}, RouteBArtifact{}, fmt.Errorf("secureeval: build private Route-B artifact: %w", err)
	}
	if err = validateRouteBArtifactBuildProduct(
		product, prepared, use.permitIdentity, preparedIdentity, validator,
	); err != nil {
		product = routeBArtifactBuildProduct{}
		return ArtifactBuildReceipt{}, RouteBArtifact{}, err
	}

	buildReceiptIdentity := RBAUTHDigest(sha256.Sum256(product.records.BuildReceipt))
	pairIdentity := RBAUTHDigest(sha256.Sum256(product.records.ArtifactPair))
	artifactCell := &routeBArtifactCell{
		lineage: use.lineage, stc: product.stc, cts: product.cts,
		records: cloneRBDFTBuildRecordSet(product.records),
	}
	artifactCell.available.Store(true)
	product.stc = dft.Matrix{}
	product.cts = dft.Matrix{}
	receiptRecords := cloneRBDFTBuildRecordSet(product.records)

	use.lineage.buildReceiptIdentity = buildReceiptIdentity
	use.lineage.artifactPairManifestIdentity = pairIdentity
	use.lineage.actualPayload = product.payload
	receipt = ArtifactBuildReceipt{
		report: product.receipt, records: receiptRecords, runtime: runtimeEvidence, lineage: use.lineage,
	}
	artifact = RouteBArtifact{cell: artifactCell}
	product = routeBArtifactBuildProduct{}
	use.lineage.state.Store(uint32(routeBLineagePrivateUninstalled))
	published = true
	return receipt, artifact, nil
}

func (authority *RouteBAuthority) validateBuildPermitBeforeUse(permit ArtifactBuildPermit) (routeBBuildPermitUse, error) {
	use, err := authority.validateBuildPermitCanonical(permit)
	if err != nil {
		return routeBBuildPermitUse{}, err
	}
	if use.lineage.state.Load() != uint32(routeBLineageAuthorized) ||
		use.lineage.lastConsumedGeneration.Load() != use.lineage.mintGeneration {
		return routeBBuildPermitUse{}, lineagef("build lineage is not in its mint-time authorized state")
	}
	return use, nil
}

func (authority *RouteBAuthority) validateBuildPermitCanonical(permit ArtifactBuildPermit) (routeBBuildPermitUse, error) {
	if authority == nil || authority.cell == nil || authority.cell.owner == nil || isNilPhysicalMemorySampler(authority.cell.sampler) {
		return routeBBuildPermitUse{}, lineagef("Authority is nil or uninitialized")
	}
	if permit.IsZero() || permit.lineage.owner == nil || permit.lineage.owner != authority.cell.owner {
		return routeBBuildPermitUse{}, lineagef("build permit is zero or belongs to a foreign Authority")
	}
	if err := permit.report.ValidateFrozenSemantics(); err != nil {
		return routeBBuildPermitUse{}, err
	}
	specRecord, err := permit.report.Spec.MarshalBinary()
	if err != nil {
		return routeBBuildPermitUse{}, err
	}
	permitRecord, err := permit.report.MarshalBinary()
	if err != nil {
		return routeBBuildPermitUse{}, err
	}
	specIdentity, err := RBAUTHRecordIdentity(specRecord)
	if err != nil {
		return routeBBuildPermitUse{}, err
	}
	permitIdentity, err := RBAUTHRecordIdentity(permitRecord)
	if err != nil {
		return routeBBuildPermitUse{}, err
	}
	lineage := permit.lineage
	if permit.report.BuildSpecDigest != specIdentity || lineage.buildSpecIdentity != specIdentity ||
		lineage.buildPermitIdentity != permitIdentity ||
		lineage.mintCapacityReportIdentity != permit.report.Spec.Capacity.CapacityReportDigest ||
		lineage.mintCapacityPermitIdentity != permit.report.Spec.Capacity.CapacityPermitDigest ||
		lineage.mintGeneration == 0 || lineage.mintSampleTime.IsZero() {
		return routeBBuildPermitUse{}, lineagef("build permit differs from its mint-time private anchors")
	}
	return routeBBuildPermitUse{lineage: lineage, spec: permit.report.Spec, permitIdentity: permitIdentity}, nil
}

func buildCanonicalRouteBArtifact(
	prepared bootstrapping.PreparedParameters,
	buildPermitIdentity RBAUTHDigest,
) (routeBArtifactBuildProduct, error) {
	if err := prepared.Verify(); err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: verify prepared Route-B parameters before artifact build: %w", err)
	}
	if err := validateGaoN16RouteBPreparedIdentity(prepared); err != nil {
		return routeBArtifactBuildProduct{}, err
	}
	effective := prepared.EffectiveParameters()
	stcProfile, err := rbdftCanonicalL11FactorProfile(dft.ObservedSlotsToCoeffs)
	if err != nil {
		return routeBArtifactBuildProduct{}, err
	}
	ctsProfile, err := rbdftCanonicalL11FactorProfile(dft.ObservedCoeffsToSlots)
	if err != nil {
		return routeBArtifactBuildProduct{}, err
	}
	return buildRouteBArtifactFromPlan(routeBArtifactBuildPlan{
		params:     effective.BootstrappingParameters,
		stcLiteral: effective.SlotsToCoeffsParameters, ctsLiteral: effective.CoeffsToSlotsParameters,
		stcProfile: stcProfile, ctsProfile: ctsProfile,
		buildPermitIdentity:       buildPermitIdentity,
		preparedParameterIdentity: RBAUTHDigest(prepared.Digest()),
		peakRSS:                   sampleProductionProcessPeakRSS,
	})
}

func validateCanonicalRouteBArtifactProduct(
	product routeBArtifactBuildProduct,
	prepared bootstrapping.PreparedParameters,
) error {
	effective := prepared.EffectiveParameters()
	if err := product.stc.ValidateAgainst(effective.BootstrappingParameters, effective.SlotsToCoeffsParameters); err != nil {
		return fmt.Errorf("secureeval: validate canonical Route-B STC artifact: %w", err)
	}
	if err := product.cts.ValidateAgainst(effective.BootstrappingParameters, effective.CoeffsToSlotsParameters); err != nil {
		return fmt.Errorf("secureeval: validate canonical Route-B CTS artifact: %w", err)
	}
	return nil
}

func validateRouteBArtifactBuildProduct(
	product routeBArtifactBuildProduct,
	prepared bootstrapping.PreparedParameters,
	buildPermitIdentity, preparedIdentity RBAUTHDigest,
	validator routeBArtifactProductValidator,
) error {
	if product.isZero() || validator == nil {
		return lineagef("private Route-B artifact build product is empty")
	}
	if err := validator(product, prepared); err != nil {
		return err
	}
	if err := ValidateRBDFTBuildRecordLinks(product.records, buildPermitIdentity, preparedIdentity); err != nil {
		return err
	}
	parsed, err := ParseRBDFTBuildReceipt(product.records.BuildReceipt)
	if err != nil {
		return err
	}
	pairIdentity := RBAUTHDigest(sha256.Sum256(product.records.ArtifactPair))
	if parsed != product.receipt || parsed.Payload != product.payload ||
		parsed.BuildPermitDigest != buildPermitIdentity || parsed.PreparedParameterDigest != preparedIdentity ||
		parsed.ArtifactManifestDigest != pairIdentity {
		return lineagef("private Route-B artifact product differs from its linked receipt")
	}
	return nil
}

func newRuntimeCapacityEvidence(
	operation string,
	evidence routeBCapacityEvidence,
	lineageIdentity RBAUTHDigest,
) RuntimeCapacityEvidenceReport {
	value := RuntimeCapacityEvidenceReport{
		Operation: operation, Generation: evidence.generation, SampledAt: evidence.sampledAt.UTC(),
		Capacity: evidence.binding, Peak: evidence.peak, LineageIdentity: lineageIdentity,
	}
	value.Digest = digestRuntimeCapacityEvidence(value)
	return value
}

func digestRuntimeCapacityEvidence(value RuntimeCapacityEvidenceReport) RBAUTHDigest {
	var writer wireWriter
	writer.stringUnchecked(routeBRuntimeCapacityDomain)
	writer.stringUnchecked(value.Operation)
	writer.u64(value.Generation)
	writer.u64(uint64(value.SampledAt.UnixNano()))
	writeCapacity(&writer, value.Capacity)
	writePeakFields(&writer, value.Peak)
	writer.digest(value.Peak.Digest)
	writer.digest(value.LineageIdentity)
	return RBAUTHDigest(sha256.Sum256(writer.buffer))
}
