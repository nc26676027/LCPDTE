package secureeval

import (
	"crypto/sha256"
	"fmt"

	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
)

// ReadyPermit is the live, owner-bound post-build capability. Its report and
// runtime evidence are inert copies; only the private lineage can authorize a
// later installation.
type ReadyPermit struct {
	report  ReadyPermitReport
	runtime RuntimeCapacityEvidenceReport
	lineage *routeBLineageCell
}

func (permit ReadyPermit) IsZero() bool {
	return permit.lineage == nil || permit.report == (ReadyPermitReport{}) ||
		permit.runtime.Digest == (RBAUTHDigest{})
}

func (permit ReadyPermit) Report() ReadyPermitReport { return permit.report }

func (permit ReadyPermit) RuntimeCapacityEvidence() RuntimeCapacityEvidenceReport {
	return permit.runtime
}

func (permit ReadyPermit) MarshalBinary() ([]byte, error) {
	if permit.IsZero() || permit.lineage.owner == nil {
		return nil, lineagef("ready permit is zero or unowned")
	}
	if err := permit.runtime.Validate(); err != nil {
		return nil, err
	}
	if err := permit.report.ValidateFrozenSemantics(); err != nil {
		return nil, err
	}
	specRecord, err := permit.report.Spec.MarshalBinary()
	if err != nil {
		return nil, err
	}
	specIdentity, err := RBAUTHRecordIdentity(specRecord)
	if err != nil {
		return nil, err
	}
	record, err := permit.report.MarshalBinary()
	if err != nil {
		return nil, err
	}
	permitIdentity, err := RBAUTHRecordIdentity(record)
	if err != nil {
		return nil, err
	}
	lineage := permit.lineage
	spec := permit.report.Spec
	if permit.report.ReadySpecDigest != specIdentity ||
		specIdentity != lineage.readySpecIdentity ||
		permitIdentity != lineage.readyPermitIdentity ||
		permit.runtime.Digest != lineage.readyUseCapacityEvidenceIdentity ||
		permit.runtime.LineageIdentity != lineage.buildPermitIdentity ||
		spec.BuildSpecDigest != lineage.buildSpecIdentity ||
		spec.BuildPermitDigest != lineage.buildPermitIdentity ||
		spec.BuildReceiptDigest != lineage.buildReceiptIdentity ||
		spec.ArtifactPairManifestDigest != lineage.artifactPairManifestIdentity ||
		spec.ActualPayload != lineage.actualPayload {
		return nil, lineagef("ready permit differs from its private anchors")
	}
	return append([]byte(nil), record...), nil
}

type routeBResidentArtifactValidator func(
	*routeBArtifactCell,
	ArtifactBuildReceipt,
	bootstrapping.PreparedParameters,
) (RBAUTHActualPayload, RBAUTHDigest, error)

// AuthorizeReady admits a freshly sampled host, re-prepares the canonical
// parameters and, only after winning the exclusive readying transition,
// rehashes the resident private artifact into a receipt-bound ReadyPermit.
func (authority *RouteBAuthority) AuthorizeReady(
	buildPermit ArtifactBuildPermit,
	receipt ArtifactBuildReceipt,
	artifact RouteBArtifact,
) (ReadySpec, ReadyPermit, error) {
	return authority.authorizeReadyWithValidator(
		buildPermit, receipt, artifact, validateCanonicalRouteBResidentArtifact,
	)
}

func (authority *RouteBAuthority) authorizeReadyWithValidator(
	buildPermit ArtifactBuildPermit,
	receipt ArtifactBuildReceipt,
	artifact RouteBArtifact,
	validator routeBResidentArtifactValidator,
) (
	spec ReadySpec,
	readyPermit ReadyPermit,
	err error,
) {
	if validator == nil {
		return ReadySpec{}, ReadyPermit{}, lineagef("resident artifact validator is nil")
	}
	use, err := authority.validateReadyInputsBeforeUse(buildPermit, receipt, artifact)
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}

	evidence, err := authority.cell.sampleAndEvaluateCapacity(routeBCapacityGateAuthorizeReady)
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	prepared, preparedIdentity, transforms, err := authority.cell.prepareStoredParametersValue()
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, blockedCause("prepare stored Route-B parameters for Ready", err)
	}
	if preparedIdentity != use.spec.PreparedParameterDigest || transforms != use.spec.Transforms {
		return ReadySpec{}, ReadyPermit{}, lineagef("ready-use preparation differs from the authorized specification")
	}
	if _, err = authority.validateReadyInputsBeforeUse(buildPermit, receipt, artifact); err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	if evidence.generation <= use.lineage.lastConsumedGeneration.Load() {
		return ReadySpec{}, ReadyPermit{}, lineagef("ready-use capacity generation is not newer than the lineage")
	}
	runtimeEvidence := newRuntimeCapacityEvidence(
		routeBRuntimeOperationAuthorizeReady, evidence, use.permitIdentity,
	)
	if err = runtimeEvidence.Validate(); err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	if !use.lineage.state.CompareAndSwap(
		uint32(routeBLineagePrivateUninstalled), uint32(routeBLineageReadying),
	) {
		return ReadySpec{}, ReadyPermit{}, lineagef("build lineage is no longer private-uninstalled")
	}
	published := false
	use.lineage.lastConsumedGeneration.Store(evidence.generation)
	use.lineage.readyUseCapacityEvidenceIdentity = runtimeEvidence.Digest
	defer func() {
		prepared = bootstrapping.PreparedParameters{}
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("secureeval: Route-B AuthorizeReady panicked: %v", recovered)
		}
		if !published {
			use.lineage.state.Store(uint32(routeBLineageFailed))
			if artifact.cell != nil {
				artifact.cell.available.Store(false)
				artifact.cell.stc = dft.Matrix{}
				artifact.cell.cts = dft.Matrix{}
				artifact.cell.records = RBDFTBuildRecordSet{}
			}
			spec = ReadySpec{}
			readyPermit = ReadyPermit{}
		}
	}()

	receiptRecord, err := receipt.MarshalBinary()
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	payload, pairIdentity, err := validator(artifact.cell, receipt, prepared)
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, fmt.Errorf("secureeval: validate resident Route-B artifact for Ready: %w", err)
	}
	if payload != use.lineage.actualPayload || pairIdentity != use.lineage.artifactPairManifestIdentity ||
		receipt.report.Payload != payload || receipt.report.ArtifactManifestDigest != pairIdentity {
		return ReadySpec{}, ReadyPermit{}, lineagef("resident Route-B artifact differs from its private anchors")
	}

	buildSpecRecord, err := use.spec.MarshalBinary()
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	buildPermitRecord, err := buildPermit.report.MarshalBinary()
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	buildReceiptIdentity := RBAUTHDigest(sha256.Sum256(receiptRecord))
	if buildReceiptIdentity != use.lineage.buildReceiptIdentity {
		return ReadySpec{}, ReadyPermit{}, lineagef("Ready build-receipt identity differs from its private anchor")
	}
	spec = ReadySpec{
		Classification: RBAUTHClassification{
			AdaptationLabel: RBAUTHAdaptationLabel,
			EvidenceScope:   RBAUTHReadyEvidenceScope,
			Maturity:        RBAUTHMaturity,
		},
		Capacity:                   evidence.binding,
		PreparedParameterDigest:    preparedIdentity,
		BuildSpecDigest:            use.lineage.buildSpecIdentity,
		BuildPermitDigest:          use.permitIdentity,
		BuildReceiptDigest:         buildReceiptIdentity,
		ArtifactPairManifestDigest: pairIdentity,
		ActualPayload:              payload,
		ArtifactState:              RBAUTHPrivateUninstalledState,
	}
	if err = spec.ValidateFrozenSemantics(); err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	if err = spec.ValidateLinks(
		buildSpecRecord, buildPermitRecord, receiptRecord, receipt.records.ArtifactPair,
	); err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	specRecord, err := spec.MarshalBinary()
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	specIdentity, err := RBAUTHRecordIdentity(specRecord)
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	report := ReadyPermitReport{ReadySpecDigest: specIdentity, Spec: spec}
	if err = report.ValidateFrozenSemantics(); err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	readyRecord, err := report.MarshalBinary()
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}
	readyIdentity, err := RBAUTHRecordIdentity(readyRecord)
	if err != nil {
		return ReadySpec{}, ReadyPermit{}, err
	}

	use.lineage.readySpecIdentity = specIdentity
	use.lineage.readyPermitIdentity = readyIdentity
	readyPermit = ReadyPermit{report: report, runtime: runtimeEvidence, lineage: use.lineage}
	use.lineage.state.Store(uint32(routeBLineageReady))
	published = true
	return spec, readyPermit, nil
}

func (authority *RouteBAuthority) validateReadyInputsBeforeUse(
	buildPermit ArtifactBuildPermit,
	receipt ArtifactBuildReceipt,
	artifact RouteBArtifact,
) (routeBBuildPermitUse, error) {
	use, err := authority.validateBuildPermitCanonical(buildPermit)
	if err != nil {
		return routeBBuildPermitUse{}, err
	}
	if receipt.IsZero() || artifact.IsZero() || artifact.cell == nil ||
		receipt.lineage != use.lineage || artifact.cell.lineage != use.lineage {
		return routeBBuildPermitUse{}, lineagef("Ready inputs are zero or belong to different lineages")
	}
	lineage := use.lineage
	if lineage.state.Load() != uint32(routeBLineagePrivateUninstalled) {
		return routeBBuildPermitUse{}, lineagef("build lineage is not private-uninstalled")
	}
	if lineage.lastConsumedGeneration.Load() <= lineage.mintGeneration ||
		isZeroDigest(lineage.buildUseCapacityEvidenceIdentity) ||
		isZeroDigest(lineage.buildReceiptIdentity) ||
		isZeroDigest(lineage.artifactPairManifestIdentity) ||
		lineage.actualPayload == (RBAUTHActualPayload{}) {
		return routeBBuildPermitUse{}, lineagef("build lineage has incomplete post-build anchors")
	}
	if receipt.report.BuildPermitDigest != use.permitIdentity ||
		receipt.report.PreparedParameterDigest != use.spec.PreparedParameterDigest ||
		receipt.report.Payload != lineage.actualPayload ||
		receipt.report.ArtifactManifestDigest != lineage.artifactPairManifestIdentity ||
		receipt.runtime.Operation != routeBRuntimeOperationBeginBuild ||
		receipt.runtime.LineageIdentity != use.permitIdentity ||
		receipt.runtime.Digest != lineage.buildUseCapacityEvidenceIdentity {
		return routeBBuildPermitUse{}, lineagef("live build receipt differs from the post-build anchors")
	}
	return use, nil
}

func validateCanonicalRouteBResidentArtifact(
	cell *routeBArtifactCell,
	receipt ArtifactBuildReceipt,
	prepared bootstrapping.PreparedParameters,
) (RBAUTHActualPayload, RBAUTHDigest, error) {
	if cell == nil || !cell.available.Load() {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, lineagef("private Route-B artifact is unavailable")
	}
	if err := prepared.Verify(); err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, fmt.Errorf("secureeval: verify prepared Route-B parameters before resident validation: %w", err)
	}
	if err := validateGaoN16RouteBPreparedIdentity(prepared); err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	effective := prepared.EffectiveParameters()
	stcProfile, err := rbdftCanonicalL11FactorProfile(dft.ObservedSlotsToCoeffs)
	if err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	ctsProfile, err := rbdftCanonicalL11FactorProfile(dft.ObservedCoeffsToSlots)
	if err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	return validateRouteBResidentArtifactWithPlan(
		cell.stc, cell.cts, cell.records, receipt.report,
		routeBResidentArtifactPlan{
			params:     effective.BootstrappingParameters,
			stcLiteral: effective.SlotsToCoeffsParameters,
			ctsLiteral: effective.CoeffsToSlotsParameters,
			stcProfile: stcProfile,
			ctsProfile: ctsProfile,
		},
	)
}
