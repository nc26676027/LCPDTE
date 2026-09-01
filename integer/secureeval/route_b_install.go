package secureeval

import (
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/nc26676027/LCPDTE/integer/secureprofile"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// RouteBInstalledEvaluator is the sole opaque owner of a prebuilt Route-B
// evaluator after installation. It deliberately exposes no vendor evaluator,
// matrix, key, or mutable record accessor.
type RouteBInstalledEvaluator struct {
	cell *routeBInstalledEvaluatorCell
}

type routeBInstalledEvaluatorCell struct {
	authority *routeBAuthorityCell
	lineage   *routeBLineageCell
	available atomic.Bool

	evaluator      *bootstrapping.Evaluator
	receipt        RBDFTBuildReceiptReport
	records        RBDFTBuildRecordSet
	ready          ReadyPermitReport
	install        RuntimeCapacityEvidenceReport
	firstOperation RouteBFirstOperationReport
}

func (installed *RouteBInstalledEvaluator) IsZero() bool {
	return installed == nil || installed.cell == nil || installed.cell.lineage == nil ||
		installed.cell.evaluator == nil || !installed.cell.available.Load()
}

func (installed *RouteBInstalledEvaluator) InstallRuntimeCapacityEvidence() RuntimeCapacityEvidenceReport {
	if installed == nil || installed.cell == nil {
		return RuntimeCapacityEvidenceReport{}
	}
	return installed.cell.install
}

type routeBEvaluationKeyGenerator func(
	bootstrapping.PreparedParameters,
	*rlwe.SecretKey,
) (*bootstrapping.EvaluationKeys, error)

type routeBPrebuiltEvaluatorAssembler func(
	bootstrapping.PreparedParameters,
	*routeBArtifactCell,
	**bootstrapping.EvaluationKeys,
) (*bootstrapping.Evaluator, error)

type routeBInstalledEvaluatorValidator func(
	*bootstrapping.Evaluator,
	bootstrapping.PreparedParameters,
) error

// Install consumes a ready artifact after a fresh host-capacity and canonical
// preparation gate, generates the admitted keys and moves the matrices into a
// prebuilt Lattigo evaluator. No caller-supplied capacity evidence is accepted.
func (authority *RouteBAuthority) Install(
	readyPermit ReadyPermit,
	receipt ArtifactBuildReceipt,
	artifact RouteBArtifact,
	secretKey *rlwe.SecretKey,
) (*RouteBInstalledEvaluator, error) {
	return authority.installWithHooks(
		readyPermit, receipt, artifact, secretKey,
		validateCanonicalRouteBResidentArtifact,
		generateCanonicalRouteBEvaluationKeys,
		assembleCanonicalRouteBPrebuiltEvaluator,
		validateCanonicalRouteBInstalledEvaluator,
	)
}

func (authority *RouteBAuthority) installWithHooks(
	readyPermit ReadyPermit,
	receipt ArtifactBuildReceipt,
	artifact RouteBArtifact,
	secretKey *rlwe.SecretKey,
	residentValidator routeBResidentArtifactValidator,
	keyGenerator routeBEvaluationKeyGenerator,
	assembler routeBPrebuiltEvaluatorAssembler,
	installedValidator routeBInstalledEvaluatorValidator,
) (
	installed *RouteBInstalledEvaluator,
	err error,
) {
	if residentValidator == nil || keyGenerator == nil || assembler == nil || installedValidator == nil {
		return nil, lineagef("Install validator, key generator, or assembler is nil")
	}
	lineage, err := authority.validateInstallInputsBeforeUse(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return nil, err
	}

	evidence, err := authority.cell.sampleAndEvaluateCapacity(routeBCapacityGateInstall)
	if err != nil {
		return nil, err
	}
	prepared, preparedIdentity, transforms, err := authority.cell.prepareStoredParametersValue()
	if err != nil {
		return nil, blockedCause("prepare stored Route-B parameters for Install", err)
	}
	readySpec := readyPermit.report.Spec
	if preparedIdentity != readySpec.PreparedParameterDigest ||
		preparedIdentity != receipt.report.PreparedParameterDigest {
		return nil, lineagef("install-use preparation differs from the ready lineage")
	}
	if err = validateGaoN16RouteBTransformIdentitySet(transforms); err != nil {
		return nil, err
	}
	if _, err = authority.validateInstallInputsBeforeUse(readyPermit, receipt, artifact, secretKey); err != nil {
		return nil, err
	}
	if evidence.generation <= lineage.lastConsumedGeneration.Load() {
		return nil, lineagef("install-use capacity generation is not newer than the lineage")
	}
	runtimeEvidence := newRuntimeCapacityEvidence(
		routeBRuntimeOperationInstall, evidence, lineage.readyPermitIdentity,
	)
	if err = runtimeEvidence.Validate(); err != nil {
		return nil, err
	}
	if !lineage.state.CompareAndSwap(uint32(routeBLineageReady), uint32(routeBLineageInstalling)) {
		return nil, lineagef("Route-B lineage is no longer ready")
	}
	lineage.lastConsumedGeneration.Store(evidence.generation)
	lineage.installCapacityEvidenceIdentity = runtimeEvidence.Digest
	published := false
	var evaluator *bootstrapping.Evaluator
	var keyDonor *bootstrapping.EvaluationKeys
	var constructorBefore dft.MatrixConstructionCounters
	constructorGuardActive := false
	defer func() {
		prepared = bootstrapping.PreparedParameters{}
		keyDonor = nil
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("secureeval: Route-B Install panicked: %v", recovered)
		}
		if constructorGuardActive {
			after := dft.SnapshotMatrixConstructionCounters()
			delta, deltaErr := after.Delta(constructorBefore)
			if deltaErr != nil {
				err = errors.Join(err, deltaErr)
				published = false
			} else if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 ||
				delta.RawNumeric() != 0 || delta.ObservedStreaming() != 0 {
				err = errors.Join(err, blockedRBDFT(
					"Route-B install construction delta is %d/%d/%d/%d, want 0/0/0/0",
					delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(),
				))
				published = false
			}
		}
		if !published {
			lineage.state.Store(uint32(routeBLineageFailed))
			clearRouteBArtifactCell(artifact.cell)
			clearRouteBInstalledVendorEvaluator(evaluator)
			installed = nil
		}
	}()

	if _, err = receipt.MarshalBinary(); err != nil {
		return nil, err
	}
	payload, pairIdentity, err := residentValidator(artifact.cell, receipt, prepared)
	if err != nil {
		return nil, fmt.Errorf("secureeval: validate resident Route-B artifact for Install: %w", err)
	}
	if payload != lineage.actualPayload || payload != readySpec.ActualPayload ||
		pairIdentity != lineage.artifactPairManifestIdentity ||
		pairIdentity != readySpec.ArtifactPairManifestDigest {
		return nil, lineagef("install-time resident artifact differs from the Ready anchors")
	}

	constructorBefore = dft.SnapshotMatrixConstructionCounters()
	constructorGuardActive = true
	keyDonor, err = keyGenerator(prepared, secretKey)
	if err != nil {
		return nil, fmt.Errorf("secureeval: generate Route-B evaluation keys: %w", err)
	}
	if keyDonor == nil {
		return nil, lineagef("Route-B evaluation-key generator returned nil")
	}
	evaluator, err = assembler(prepared, artifact.cell, &keyDonor)
	if keyDonor != nil {
		keyDonor = nil
		if err == nil {
			err = lineagef("prebuilt evaluator assembler did not consume its key donor")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("secureeval: assemble prebuilt Route-B evaluator: %w", err)
	}
	if evaluator == nil {
		return nil, lineagef("prebuilt Route-B assembler returned a nil evaluator")
	}
	if len(artifact.cell.stc.Matrices) != 0 || len(artifact.cell.cts.Matrices) != 0 {
		return nil, lineagef("prebuilt Route-B assembler retained a matrix donor")
	}
	if err = installedValidator(evaluator, prepared); err != nil {
		return nil, fmt.Errorf("secureeval: validate installed Route-B evaluator: %w", err)
	}
	installedCell := &routeBInstalledEvaluatorCell{
		authority: authority.cell, lineage: lineage, evaluator: evaluator, receipt: receipt.report,
		records: cloneRBDFTBuildRecordSet(receipt.records), ready: readyPermit.report,
		install: runtimeEvidence,
	}
	installedCell.available.Store(true)
	artifact.cell.available.Store(false)
	artifact.cell.records = RBDFTBuildRecordSet{}
	installed = &RouteBInstalledEvaluator{cell: installedCell}
	evaluator = nil
	lineage.state.Store(uint32(routeBLineageInstalledUnverified))
	published = true
	return installed, nil
}

func (authority *RouteBAuthority) validateInstallInputsBeforeUse(
	readyPermit ReadyPermit,
	receipt ArtifactBuildReceipt,
	artifact RouteBArtifact,
	secretKey *rlwe.SecretKey,
) (*routeBLineageCell, error) {
	if authority == nil || authority.cell == nil || authority.cell.owner == nil ||
		isNilPhysicalMemorySampler(authority.cell.sampler) {
		return nil, lineagef("Authority is nil or uninitialized")
	}
	if secretKey == nil || readyPermit.IsZero() || receipt.IsZero() || artifact.IsZero() ||
		artifact.cell == nil || readyPermit.lineage == nil {
		return nil, lineagef("Install secret key or live input is empty")
	}
	lineage := readyPermit.lineage
	if lineage.owner == nil || lineage.owner != authority.cell.owner || receipt.lineage != lineage ||
		artifact.cell.lineage != lineage {
		return nil, lineagef("Install inputs belong to a foreign Authority or lineage")
	}
	if lineage.state.Load() != uint32(routeBLineageReady) {
		return nil, lineagef("Route-B lineage is not ready")
	}
	if _, err := readyPermit.MarshalBinary(); err != nil {
		return nil, err
	}
	if readyPermit.runtime.Operation != routeBRuntimeOperationAuthorizeReady ||
		readyPermit.runtime.Generation != lineage.lastConsumedGeneration.Load() ||
		readyPermit.report.Spec.BuildReceiptDigest != lineage.buildReceiptIdentity ||
		readyPermit.report.Spec.ArtifactPairManifestDigest != lineage.artifactPairManifestIdentity ||
		readyPermit.report.Spec.ActualPayload != lineage.actualPayload ||
		receipt.report.Payload != lineage.actualPayload ||
		receipt.report.ArtifactManifestDigest != lineage.artifactPairManifestIdentity {
		return nil, lineagef("Install inputs differ from their Ready anchors")
	}
	return lineage, nil
}

func generateCanonicalRouteBEvaluationKeys(
	prepared bootstrapping.PreparedParameters,
	secretKey *rlwe.SecretKey,
) (*bootstrapping.EvaluationKeys, error) {
	if secretKey == nil {
		return nil, lineagef("Route-B secret key is nil")
	}
	if err := prepared.Verify(); err != nil {
		return nil, err
	}
	parameters := prepared.EffectiveParameters()
	evaluationKeys, _, err := parameters.GenEvaluationKeys(secretKey)
	if err != nil {
		return nil, err
	}
	return evaluationKeys, nil
}

func assembleCanonicalRouteBPrebuiltEvaluator(
	prepared bootstrapping.PreparedParameters,
	artifact *routeBArtifactCell,
	evaluationKeys **bootstrapping.EvaluationKeys,
) (*bootstrapping.Evaluator, error) {
	if artifact == nil {
		return nil, lineagef("Route-B artifact cell is nil")
	}
	carrier, err := bootstrapping.NewPrebuiltDFTMatrixCarrier(&artifact.cts, &artifact.stc)
	if err != nil {
		return nil, err
	}
	return bootstrapping.NewEvaluatorFromPrebuiltMatrices(prepared, carrier, evaluationKeys)
}

func validateCanonicalRouteBInstalledEvaluator(
	evaluator *bootstrapping.Evaluator,
	prepared bootstrapping.PreparedParameters,
) error {
	if evaluator == nil || evaluator.Evaluator == nil || evaluator.DFTEvaluator == nil ||
		evaluator.Mod1Evaluator == nil || evaluator.EvaluationKeys == nil ||
		evaluator.MemEvaluationKeySet == nil {
		return lineagef("installed Route-B evaluator graph or keys are incomplete")
	}
	if err := prepared.Verify(); err != nil {
		return err
	}
	if err := validateGaoN16RouteBPreparedIdentity(prepared); err != nil {
		return err
	}
	effective := prepared.EffectiveParameters()
	if !evaluator.ResidualParameters.Equal(&effective.ResidualParameters) ||
		!evaluator.BootstrappingParameters.Equal(&effective.BootstrappingParameters) {
		return lineagef("installed Route-B evaluator parameters changed")
	}
	if err := evaluator.S2CDFTMatrix.ValidateAgainst(
		effective.BootstrappingParameters, effective.SlotsToCoeffsParameters,
	); err != nil {
		return err
	}
	if err := evaluator.C2SDFTMatrix.ValidateAgainst(
		effective.BootstrappingParameters, effective.CoeffsToSlotsParameters,
	); err != nil {
		return err
	}
	if _, err := evaluator.GetRelinearizationKey(); err != nil {
		return err
	}
	actualGalois := evaluator.GetGaloisKeysList()
	slices.Sort(actualGalois)
	expectedGalois := secureprofile.DefaultGaoN16PackingL11CapacityShape().EvaluationGaloisElements()
	if !slices.Equal(actualGalois, expectedGalois) {
		return lineagef("installed Route-B Galois-key inventory changed")
	}
	if evaluator.EvkDenseToSparse == nil || evaluator.EvkSparseToDense == nil ||
		evaluator.EvkN1ToN2 != nil || evaluator.EvkN2ToN1 != nil ||
		evaluator.EvkRealToCmplx != nil || evaluator.EvkCmplxToReal != nil {
		return lineagef("installed Route-B fixed evaluation-key inventory changed")
	}
	return nil
}

func clearRouteBArtifactCell(cell *routeBArtifactCell) {
	if cell == nil {
		return
	}
	cell.available.Store(false)
	cell.stc = dft.Matrix{}
	cell.cts = dft.Matrix{}
	cell.records = RBDFTBuildRecordSet{}
}

func clearRouteBInstalledVendorEvaluator(evaluator *bootstrapping.Evaluator) {
	if evaluator == nil {
		return
	}
	evaluator.S2CDFTMatrix = dft.Matrix{}
	evaluator.C2SDFTMatrix = dft.Matrix{}
	evaluator.EvaluationKeys = nil
	evaluator.Evaluator = nil
	evaluator.DFTEvaluator = nil
	evaluator.Mod1Evaluator = nil
}
