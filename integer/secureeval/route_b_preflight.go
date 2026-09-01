package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"slices"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureprofile"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

const (
	routeBTraceDispatchCount       = 4
	routeBEvaluationGaloisKeyCount = 38
	routeBPackingLayoutRecordBytes = 81_967
	routeBExpectedPackingLayoutHex = "8a4f785eaaba8d1dd9ec453dc1d3fcb34ad8c1fd9b3b9bb03cf1ad8d756607b0"
)

var (
	routeBExpectedTraceRotationExponents = [routeBTraceDispatchCount]uint64{2048, 4096, 8192, 16384}
	routeBExpectedTraceGaloisElements    = [routeBTraceDispatchCount]uint64{122881, 114689, 98305, 65537}
)

// RouteBFirstOperationReport is inert evidence for the installed-resident
// preflight and the first sparse ModUp/C2S prefix. It carries fixed-size values
// only and cannot authorize another operation.
type RouteBFirstOperationReport struct {
	RuntimeCapacity RuntimeCapacityEvidenceReport

	PreparedParameterDigest    RBAUTHDigest
	ResidentPayload            RBAUTHActualPayload
	ArtifactPairManifestDigest RBAUTHDigest

	LogN, LogSlots                 uint32
	ExpectedTraceGap               uint32
	ObservedTraceGap               uint32
	ExpectedTraceRotationExponents [routeBTraceDispatchCount]uint64
	ObservedTraceRotationExponents [routeBTraceDispatchCount]uint64
	ExpectedTraceGaloisElements    [routeBTraceDispatchCount]uint64
	ObservedTraceGaloisElements    [routeBTraceDispatchCount]uint64
	TraceDispatchDigest            RBAUTHDigest
	ModUpInputOutputAliased        bool

	ExpectedCTImagNil bool
	ObservedCTImagNil bool

	PackingSlots, WordBits, WordCapacity uint32
	ExpectedPackingLayoutDigest          RBAUTHDigest
	ObservedPackingLayoutDigest          RBAUTHDigest
	ExpectedEvaluationGaloisKeys         [routeBEvaluationGaloisKeyCount]uint64
	ObservedEvaluationGaloisKeys         [routeBEvaluationGaloisKeyCount]uint64

	RaisedLevel, OutputLevel int32
	WallNanoseconds          uint64
}

func (report RouteBFirstOperationReport) Validate() error {
	if err := report.RuntimeCapacity.Validate(); err != nil {
		return err
	}
	if (report.RuntimeCapacity.Operation != routeBRuntimeOperationPreflight &&
		report.RuntimeCapacity.Operation != routeBRuntimeOperationA2BFirstRound &&
		report.RuntimeCapacity.Operation != routeBRuntimeOperationA2BFull &&
		report.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8RootTree &&
		report.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8Depth2NodeBatch &&
		report.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8Depth2SelectedChild &&
		report.RuntimeCapacity.Operation != routeBRuntimeOperationSigned8Radix4Node) ||
		isZeroDigest(report.PreparedParameterDigest) || isZeroDigest(report.ArtifactPairManifestDigest) ||
		report.ResidentPayload == (RBAUTHActualPayload{}) || isZeroDigest(report.TraceDispatchDigest) {
		return lineagef("first-operation runtime, parameter, payload, pair, or Trace evidence is empty")
	}
	profile, err := secureprofile.NewGaoN16PackingL11Profile()
	if err != nil {
		return err
	}
	if report.LogN != uint32(profile.LogN()) || report.LogSlots != uint32(profile.LogSlots()) {
		return lineagef("first-operation dimensions are LogN=%d/LogSlots=%d, want %d/%d",
			report.LogN, report.LogSlots, profile.LogN(), profile.LogSlots())
	}
	if report.ExpectedTraceGap != uint32(profile.SparseDenseGap()) ||
		report.ObservedTraceGap != report.ExpectedTraceGap {
		return lineagef("first-operation Trace gap is expected=%d/observed=%d, want %d",
			report.ExpectedTraceGap, report.ObservedTraceGap, profile.SparseDenseGap())
	}
	if report.ExpectedTraceRotationExponents != routeBExpectedTraceRotationExponents ||
		report.ObservedTraceRotationExponents != report.ExpectedTraceRotationExponents {
		return lineagef("first-operation Trace rotations are expected=%v/observed=%v, want %v",
			report.ExpectedTraceRotationExponents, report.ObservedTraceRotationExponents,
			routeBExpectedTraceRotationExponents)
	}
	if report.ExpectedTraceGaloisElements != routeBExpectedTraceGaloisElements ||
		report.ObservedTraceGaloisElements != report.ExpectedTraceGaloisElements {
		return lineagef("first-operation Trace Galois sequence is expected=%v/observed=%v, want %v",
			report.ExpectedTraceGaloisElements, report.ObservedTraceGaloisElements,
			routeBExpectedTraceGaloisElements)
	}
	if !report.ModUpInputOutputAliased || !report.ExpectedCTImagNil || !report.ObservedCTImagNil {
		return lineagef("first-operation alias/C2S evidence is alias=%t expected-imag-nil=%t observed-imag-nil=%t",
			report.ModUpInputOutputAliased, report.ExpectedCTImagNil, report.ObservedCTImagNil)
	}
	if report.PackingSlots != uint32(profile.Slots()) || report.WordBits != uint32(profile.WordBits()) ||
		report.WordCapacity != uint32(profile.WordCapacity()) {
		return lineagef("first-operation packing is slots=%d/word-bits=%d/words=%d, want %d/%d/%d",
			report.PackingSlots, report.WordBits, report.WordCapacity,
			profile.Slots(), profile.WordBits(), profile.WordCapacity())
	}
	if report.RaisedLevel != 20 || report.OutputLevel != 17 || report.WallNanoseconds == 0 {
		return lineagef("first-operation levels/wall are raised=%d/output=%d/wall-ns=%d, want 20/17/nonzero",
			report.RaisedLevel, report.OutputLevel, report.WallNanoseconds)
	}
	expectedLayout, err := routeBExpectedPackingLayoutIdentity()
	if err != nil {
		return err
	}
	if report.ExpectedPackingLayoutDigest != expectedLayout ||
		report.ObservedPackingLayoutDigest != expectedLayout {
		return lineagef("first-operation packing-layout identity changed")
	}
	expectedKeys, err := routeBExpectedEvaluationGaloisKeys()
	if err != nil {
		return err
	}
	if report.ExpectedEvaluationGaloisKeys != expectedKeys ||
		report.ObservedEvaluationGaloisKeys != expectedKeys {
		return lineagef("first-operation evaluation-key inventory changed")
	}
	return nil
}

type routeBFirstOperationObservation struct {
	logN, logSlots int
	traceGap       uint32

	traceRotationExponents  [routeBTraceDispatchCount]uint64
	traceGaloisElements     [routeBTraceDispatchCount]uint64
	traceDigest             RBAUTHDigest
	modUpInputOutputAliased bool
	ctImagNil               bool
	packingLayoutDigest     RBAUTHDigest
	evaluationGaloisKeys    [routeBEvaluationGaloisKeyCount]uint64
	raisedLevel             int
	outputLevel             int
	wallNanoseconds         uint64
}

type routeBInstalledResidentValidator func(
	*routeBInstalledEvaluatorCell,
	bootstrapping.PreparedParameters,
) (RBAUTHActualPayload, RBAUTHDigest, error)

type routeBFirstOperationRunner func(
	*bootstrapping.Evaluator,
	*rlwe.Ciphertext,
) (*rlwe.Ciphertext, routeBFirstOperationObservation, error)

// RunFirstSparseMR0 performs the mandatory installed-resident preflight and
// then exactly one observed sparse ModUp/C2S prefix. A caller cannot separate
// the preflight from the first HE dispatch.
func (installed *RouteBInstalledEvaluator) RunFirstSparseMR0(
	input *rlwe.Ciphertext,
) (*rlwe.Ciphertext, RouteBFirstOperationReport, error) {
	return installed.runFirstSparseMR0WithHooks(
		input,
		validateCanonicalRouteBInstalledResident,
		validateCanonicalRouteBInstalledEvaluator,
		runCanonicalRouteBFirstSparseMR0,
	)
}

func (installed *RouteBInstalledEvaluator) runFirstSparseMR0WithHooks(
	input *rlwe.Ciphertext,
	residentValidator routeBInstalledResidentValidator,
	installedValidator routeBInstalledEvaluatorValidator,
	runner routeBFirstOperationRunner,
) (*rlwe.Ciphertext, RouteBFirstOperationReport, error) {
	return installed.runFirstOperationWithHooks(
		input, routeBCapacityGatePreflight, routeBRuntimeOperationPreflight,
		residentValidator, installedValidator, runner,
	)
}

func (installed *RouteBInstalledEvaluator) runFirstOperationWithHooks(
	input *rlwe.Ciphertext,
	capacityGate routeBCapacityGate,
	runtimeOperation string,
	residentValidator routeBInstalledResidentValidator,
	installedValidator routeBInstalledEvaluatorValidator,
	runner routeBFirstOperationRunner,
) (
	output *rlwe.Ciphertext,
	report RouteBFirstOperationReport,
	err error,
) {
	if residentValidator == nil || installedValidator == nil || runner == nil {
		return nil, RouteBFirstOperationReport{}, lineagef("first-operation validator or runner is nil")
	}
	expectedGate, err := routeBCapacityGateForRuntimeOperation(runtimeOperation)
	if err != nil || expectedGate != capacityGate ||
		(runtimeOperation != routeBRuntimeOperationPreflight &&
			runtimeOperation != routeBRuntimeOperationA2BFirstRound &&
			runtimeOperation != routeBRuntimeOperationA2BFull &&
			runtimeOperation != routeBRuntimeOperationSigned8RootTree &&
			runtimeOperation != routeBRuntimeOperationSigned8Depth2NodeBatch &&
			runtimeOperation != routeBRuntimeOperationSigned8Depth2SelectedChild &&
			runtimeOperation != routeBRuntimeOperationSigned8Radix4Node) {
		return nil, RouteBFirstOperationReport{}, lineagef("first-operation capacity gate and runtime operation disagree")
	}
	cell, err := validateRouteBFirstOperationInputs(installed, input)
	if err != nil {
		return nil, RouteBFirstOperationReport{}, err
	}

	evidence, err := cell.authority.sampleAndEvaluateCapacity(capacityGate)
	if err != nil {
		return nil, RouteBFirstOperationReport{}, err
	}
	prepared, preparedIdentity, transforms, err := cell.authority.prepareStoredParametersValue()
	if err != nil {
		return nil, RouteBFirstOperationReport{}, blockedCause("prepare stored Route-B parameters for first operation", err)
	}
	if preparedIdentity != cell.ready.Spec.PreparedParameterDigest ||
		preparedIdentity != cell.receipt.PreparedParameterDigest {
		return nil, RouteBFirstOperationReport{}, lineagef("first-operation preparation differs from the installed lineage")
	}
	if err = validateGaoN16RouteBTransformIdentitySet(transforms); err != nil {
		return nil, RouteBFirstOperationReport{}, err
	}
	if _, err = validateRouteBFirstOperationInputs(installed, input); err != nil {
		return nil, RouteBFirstOperationReport{}, err
	}
	lineage := cell.lineage
	if evidence.generation <= lineage.lastConsumedGeneration.Load() {
		return nil, RouteBFirstOperationReport{}, lineagef("preflight capacity generation is not newer than the lineage")
	}
	runtimeEvidence := newRuntimeCapacityEvidence(
		runtimeOperation, evidence, lineage.readyPermitIdentity,
	)
	if err = runtimeEvidence.Validate(); err != nil {
		return nil, RouteBFirstOperationReport{}, err
	}
	if !lineage.state.CompareAndSwap(
		uint32(routeBLineageInstalledUnverified), uint32(routeBLineagePreflighting),
	) {
		return nil, RouteBFirstOperationReport{}, lineagef("Route-B lineage is no longer installed-unverified")
	}
	lineage.lastConsumedGeneration.Store(evidence.generation)
	lineage.preflightCapacityEvidenceIdentity = runtimeEvidence.Digest
	published := false
	defer func() {
		prepared = bootstrapping.PreparedParameters{}
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("secureeval: Route-B first sparse MR0 panicked: %v", recovered)
		}
		if !published {
			lineage.state.Store(uint32(routeBLineageFailed))
			cell.available.Store(false)
			clearRouteBInstalledVendorEvaluator(cell.evaluator)
			cell.evaluator = nil
			cell.records = RBDFTBuildRecordSet{}
			cell.firstOperation = RouteBFirstOperationReport{}
			output = nil
			report = RouteBFirstOperationReport{}
		}
	}()

	payload, pairIdentity, err := residentValidator(cell, prepared)
	if err != nil {
		return nil, RouteBFirstOperationReport{}, fmt.Errorf("secureeval: preflight installed Route-B artifact: %w", err)
	}
	if payload != lineage.actualPayload || payload != cell.ready.Spec.ActualPayload ||
		pairIdentity != lineage.artifactPairManifestIdentity ||
		pairIdentity != cell.ready.Spec.ArtifactPairManifestDigest {
		return nil, RouteBFirstOperationReport{}, lineagef("installed-resident artifact differs from the Ready anchors")
	}
	if err = installedValidator(cell.evaluator, prepared); err != nil {
		return nil, RouteBFirstOperationReport{}, fmt.Errorf("secureeval: validate installed evaluator before first HE: %w", err)
	}
	observationOutput, observation, err := runner(cell.evaluator, input)
	if err != nil {
		return nil, RouteBFirstOperationReport{}, fmt.Errorf("secureeval: execute first sparse MR0: %w", err)
	}
	if observationOutput == nil {
		return nil, RouteBFirstOperationReport{}, lineagef("first sparse MR0 returned nil output")
	}
	report, err = newRouteBFirstOperationReport(
		runtimeEvidence, preparedIdentity, payload, pairIdentity, observation,
	)
	if err != nil {
		return nil, RouteBFirstOperationReport{}, err
	}
	cell.firstOperation = report
	output = observationOutput
	lineage.state.Store(uint32(routeBLineageOperational))
	published = true
	return output, report, nil
}

func validateRouteBFirstOperationInputs(
	installed *RouteBInstalledEvaluator,
	input *rlwe.Ciphertext,
) (*routeBInstalledEvaluatorCell, error) {
	if input == nil || installed == nil || installed.cell == nil || installed.IsZero() {
		return nil, lineagef("first-operation input or installed evaluator is empty")
	}
	cell := installed.cell
	if cell.authority == nil || cell.authority.owner == nil || cell.lineage == nil ||
		cell.lineage.owner != cell.authority.owner || cell.evaluator == nil {
		return nil, lineagef("installed evaluator Authority or owner is invalid")
	}
	lineage := cell.lineage
	if lineage.state.Load() != uint32(routeBLineageInstalledUnverified) {
		return nil, lineagef("Route-B lineage is not installed-unverified")
	}
	if err := cell.install.Validate(); err != nil {
		return nil, err
	}
	if err := cell.ready.ValidateFrozenSemantics(); err != nil {
		return nil, err
	}
	readyRecord, err := cell.ready.MarshalBinary()
	if err != nil {
		return nil, err
	}
	readyIdentity, err := RBAUTHRecordIdentity(readyRecord)
	if err != nil {
		return nil, err
	}
	if cell.install.Operation != routeBRuntimeOperationInstall ||
		cell.install.Generation != lineage.lastConsumedGeneration.Load() ||
		cell.install.Digest != lineage.installCapacityEvidenceIdentity ||
		cell.install.LineageIdentity != lineage.readyPermitIdentity ||
		readyIdentity != lineage.readyPermitIdentity ||
		cell.ready.Spec.BuildReceiptDigest != lineage.buildReceiptIdentity ||
		cell.ready.Spec.ArtifactPairManifestDigest != lineage.artifactPairManifestIdentity ||
		cell.ready.Spec.ActualPayload != lineage.actualPayload ||
		cell.receipt.Payload != lineage.actualPayload ||
		cell.receipt.ArtifactManifestDigest != lineage.artifactPairManifestIdentity {
		return nil, lineagef("installed evaluator differs from its private anchors")
	}
	return cell, nil
}

func validateCanonicalRouteBInstalledResident(
	cell *routeBInstalledEvaluatorCell,
	prepared bootstrapping.PreparedParameters,
) (RBAUTHActualPayload, RBAUTHDigest, error) {
	if cell == nil || cell.evaluator == nil || !cell.available.Load() {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, lineagef("installed Route-B evaluator is unavailable")
	}
	if err := prepared.Verify(); err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
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
		cell.evaluator.S2CDFTMatrix, cell.evaluator.C2SDFTMatrix,
		cell.records, cell.receipt,
		routeBResidentArtifactPlan{
			params:     effective.BootstrappingParameters,
			stcLiteral: effective.SlotsToCoeffsParameters,
			ctsLiteral: effective.CoeffsToSlotsParameters,
			stcProfile: stcProfile,
			ctsProfile: ctsProfile,
		},
	)
}

func runCanonicalRouteBFirstSparseMR0(
	evaluator *bootstrapping.Evaluator,
	input *rlwe.Ciphertext,
) (*rlwe.Ciphertext, routeBFirstOperationObservation, error) {
	if evaluator == nil || evaluator.Evaluator == nil || input == nil {
		return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse MR0 evaluator or input is nil")
	}
	if evaluator.BootstrappingParameters.LogN() != 16 || input.Level() < 0 ||
		input.Level() > evaluator.BootstrappingParameters.MaxLevel() || input.Degree() != 1 ||
		input.LogSlots() != 11 || input.Value[0].N() != 1<<16 ||
		input.Value[1].N() != 1<<16 {
		return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse MR0 input shape, level, or packing changed")
	}
	start := time.Now()
	scaled, _, err := evaluator.ScaleDown(input)
	if err != nil {
		return nil, routeBFirstOperationObservation{}, err
	}
	if scaled != input || scaled.Level() != 0 {
		return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse MR0 ScaleDown output changed")
	}
	before, err := evaluator.Evaluator.Evaluator.RuntimeIdentitySnapshot()
	if err != nil {
		return nil, routeBFirstOperationObservation{}, err
	}
	raised, modUpReport, err := evaluator.ModUpObserved(input)
	if err != nil {
		return nil, routeBFirstOperationObservation{}, err
	}
	if err = modUpReport.Validate(); err != nil || modUpReport.Status() != bootstrapping.ModUpTraceSuccess ||
		!modUpReport.TraceStarted() || raised != input {
		return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse MR0 ModUp evidence changed")
	}
	trace := modUpReport.TraceReport()
	if err = trace.Validate(); err != nil || trace.Status() != rlwe.TraceDispatchSuccess ||
		trace.RingLogN() != 16 || trace.RingType() != ring.Standard || trace.RequestedLogN() != 11 ||
		!trace.InputOutputAliased() || trace.AttemptedDispatches() != routeBTraceDispatchCount ||
		trace.CompletedDispatches() != routeBTraceDispatchCount {
		return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse MR0 Trace evidence changed")
	}
	events := trace.Events()
	if len(events) != routeBTraceDispatchCount {
		return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse MR0 Trace event count changed")
	}
	var rotations, galois [routeBTraceDispatchCount]uint64
	for index, event := range events {
		if event.Sequence() != uint32(index) || event.Kind() != rlwe.TraceDispatchAutomorphism ||
			!event.HasOrdinaryExponent() || !event.Completed() {
			return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse MR0 Trace event changed")
		}
		rotations[index] = event.OrdinaryExponent()
		galois[index] = event.GaloisElement()
	}
	after, err := evaluator.Evaluator.Evaluator.RuntimeIdentitySnapshot()
	if err != nil || !before.Equal(after) {
		return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse MR0 evaluator topology changed")
	}
	realOutput, imaginaryOutput, err := evaluator.CoeffsToSlots(raised)
	if err != nil {
		return nil, routeBFirstOperationObservation{}, err
	}
	if realOutput == nil || imaginaryOutput != nil {
		return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse C2S did not return real-only output")
	}
	layout, _, err := deriveRouteBPackingLayoutIdentity()
	if err != nil {
		return nil, routeBFirstOperationObservation{}, err
	}
	keys := evaluator.GetGaloisKeysList()
	slices.Sort(keys)
	if len(keys) != routeBEvaluationGaloisKeyCount {
		return nil, routeBFirstOperationObservation{}, lineagef("canonical sparse MR0 key inventory length changed")
	}
	var keyInventory [routeBEvaluationGaloisKeyCount]uint64
	copy(keyInventory[:], keys)
	wall := uint64(time.Since(start).Nanoseconds())
	if wall == 0 {
		wall = 1
	}
	traceDigest := trace.Digest()
	return realOutput, routeBFirstOperationObservation{
		logN: evaluator.BootstrappingParameters.LogN(), logSlots: trace.RequestedLogN(),
		traceGap:               uint32(1 << (trace.RingLogN() - trace.RequestedLogN() - 1)),
		traceRotationExponents: rotations, traceGaloisElements: galois,
		traceDigest: RBAUTHDigest(traceDigest), modUpInputOutputAliased: raised == input,
		ctImagNil: imaginaryOutput == nil, packingLayoutDigest: layout,
		evaluationGaloisKeys: keyInventory, raisedLevel: raised.Level(), outputLevel: realOutput.Level(),
		wallNanoseconds: wall,
	}, nil
}

func newRouteBFirstOperationReport(
	runtimeEvidence RuntimeCapacityEvidenceReport,
	preparedIdentity RBAUTHDigest,
	payload RBAUTHActualPayload,
	pairIdentity RBAUTHDigest,
	observation routeBFirstOperationObservation,
) (RouteBFirstOperationReport, error) {
	expectedLayout, err := routeBExpectedPackingLayoutIdentity()
	if err != nil {
		return RouteBFirstOperationReport{}, err
	}
	expectedKeys, err := routeBExpectedEvaluationGaloisKeys()
	if err != nil {
		return RouteBFirstOperationReport{}, err
	}
	report := RouteBFirstOperationReport{
		RuntimeCapacity:         runtimeEvidence,
		PreparedParameterDigest: preparedIdentity, ResidentPayload: payload,
		ArtifactPairManifestDigest: pairIdentity,
		LogN:                       uint32(observation.logN), LogSlots: uint32(observation.logSlots),
		ExpectedTraceGap: 16, ObservedTraceGap: observation.traceGap,
		ExpectedTraceRotationExponents: routeBExpectedTraceRotationExponents,
		ObservedTraceRotationExponents: observation.traceRotationExponents,
		ExpectedTraceGaloisElements:    routeBExpectedTraceGaloisElements,
		ObservedTraceGaloisElements:    observation.traceGaloisElements,
		TraceDispatchDigest:            observation.traceDigest,
		ModUpInputOutputAliased:        observation.modUpInputOutputAliased,
		ExpectedCTImagNil:              true, ObservedCTImagNil: observation.ctImagNil,
		PackingSlots: 2048, WordBits: 8, WordCapacity: 512,
		ExpectedPackingLayoutDigest:  expectedLayout,
		ObservedPackingLayoutDigest:  observation.packingLayoutDigest,
		ExpectedEvaluationGaloisKeys: expectedKeys,
		ObservedEvaluationGaloisKeys: observation.evaluationGaloisKeys,
		RaisedLevel:                  int32(observation.raisedLevel), OutputLevel: int32(observation.outputLevel),
		WallNanoseconds: observation.wallNanoseconds,
	}
	if err = report.Validate(); err != nil {
		return RouteBFirstOperationReport{}, err
	}
	return report, nil
}

func routeBExpectedEvaluationGaloisKeys() ([routeBEvaluationGaloisKeyCount]uint64, error) {
	values := secureprofile.DefaultGaoN16PackingL11CapacityShape().EvaluationGaloisElements()
	if len(values) != routeBEvaluationGaloisKeyCount {
		return [routeBEvaluationGaloisKeyCount]uint64{}, lineagef("expected Route-B key inventory length changed")
	}
	var result [routeBEvaluationGaloisKeyCount]uint64
	copy(result[:], values)
	return result, nil
}

func routeBExpectedPackingLayoutIdentity() (RBAUTHDigest, error) {
	return decodeRBAUTHHexDigest("Route-B packing layout", routeBExpectedPackingLayoutHex)
}

func deriveRouteBPackingLayoutIdentity() (RBAUTHDigest, uint64, error) {
	hasher := sha256.New()
	var written uint64
	write := func(payload []byte) {
		_, _ = hasher.Write(payload)
		written += uint64(len(payload))
	}
	write([]byte("LCPDTE-RBLAYOUT-v1\x00"))
	for _, value := range []uint32{16, 11, 2048, 8, 512, 2, 4} {
		writeRouteBPackingUint32(hasher, &written, value)
	}
	for word := uint32(0); word < 512; word++ {
		for bit := uint32(0); bit < 4; bit++ {
			slot := 4*word + bit
			for _, field := range []uint32{word, bit, 0, slot, 0} {
				writeRouteBPackingUint32(hasher, &written, field)
			}
			for _, field := range []uint32{word, bit + 4, 1, slot, 0} {
				writeRouteBPackingUint32(hasher, &written, field)
			}
		}
	}
	var result RBAUTHDigest
	copy(result[:], hasher.Sum(nil))
	if written != routeBPackingLayoutRecordBytes {
		return RBAUTHDigest{}, written, lineagef("Route-B packing layout byte count is %d, want %d", written, routeBPackingLayoutRecordBytes)
	}
	return result, written, nil
}

func writeRouteBPackingUint32(hasher hash.Hash, written *uint64, value uint32) {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	_, _ = hasher.Write(encoded[:])
	*written += uint64(len(encoded))
}
