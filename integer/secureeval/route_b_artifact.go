package secureeval

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type routeBArtifactBuildPlan struct {
	params                    ckks.Parameters
	stcLiteral                dft.MatrixLiteral
	ctsLiteral                dft.MatrixLiteral
	stcProfile                rbdftFactorProfile
	ctsProfile                rbdftFactorProfile
	buildPermitIdentity       RBAUTHDigest
	preparedParameterIdentity RBAUTHDigest
	peakRSS                   func() (uint64, error)
}

type routeBArtifactBuildProduct struct {
	stc     dft.Matrix
	cts     dft.Matrix
	records RBDFTBuildRecordSet
	receipt RBDFTBuildReceiptReport
	payload RBAUTHActualPayload
}

type routeBResidentArtifactPlan struct {
	params                 ckks.Parameters
	stcLiteral, ctsLiteral dft.MatrixLiteral
	stcProfile, ctsProfile rbdftFactorProfile
}

func (product routeBArtifactBuildProduct) isZero() bool {
	return len(product.stc.Matrices) == 0 && len(product.cts.Matrices) == 0 &&
		len(product.records.STCNumericAggregate) == 0 && len(product.records.STCEncodedAggregate) == 0 &&
		len(product.records.CTSNumericAggregate) == 0 && len(product.records.CTSEncodedAggregate) == 0 &&
		len(product.records.ArtifactPair) == 0 && len(product.records.Lifecycle) == 0 &&
		len(product.records.BuildReceipt) == 0 && product.receipt == (RBDFTBuildReceiptReport{}) &&
		product.payload == (RBAUTHActualPayload{})
}

func buildRouteBArtifactFromPlan(plan routeBArtifactBuildPlan) (
	product routeBArtifactBuildProduct,
	err error,
) {
	if err = validateRouteBArtifactBuildPlan(plan); err != nil {
		return routeBArtifactBuildProduct{}, err
	}

	started := time.Now()
	before := dft.SnapshotMatrixConstructionCounters()
	var encoder *ckks.Encoder
	var stcConsumer, ctsConsumer *routeBRBDFTFactorConsumer
	var stc, cts dft.Matrix
	defer func() {
		if stcConsumer != nil {
			stcConsumer.dropEncoderReference()
		}
		if ctsConsumer != nil {
			ctsConsumer.dropEncoderReference()
		}
		encoder = nil
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("secureeval: Route-B artifact builder panicked: %v", recovered)
		}
		if err != nil {
			stc = dft.Matrix{}
			cts = dft.Matrix{}
			product = routeBArtifactBuildProduct{}
		}
	}()

	encoder = ckks.NewEncoder(plan.params, rbdftGeneratorPrecision)
	stcConsumer, err = newRouteBRBDFTFactorConsumer(plan.params, encoder, plan.stcLiteral, plan.stcProfile)
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: create Route-B STC factor consumer: %w", err)
	}
	var stcTrace dft.ObservedStreamingTrace
	stc, stcTrace, err = dft.NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		plan.params, dft.ObservedSlotsToCoeffs, plan.stcLiteral,
		encoder, rbdftGeneratorPrecision, stcConsumer,
	)
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: build observed Route-B STC matrix: %w", err)
	}
	stcEvidence, err := stcConsumer.promote(stc, stcTrace)
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: promote observed Route-B STC evidence: %w", err)
	}

	ctsConsumer, err = newRouteBRBDFTFactorConsumer(plan.params, encoder, plan.ctsLiteral, plan.ctsProfile)
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: create Route-B CTS factor consumer: %w", err)
	}
	var ctsTrace dft.ObservedStreamingTrace
	cts, ctsTrace, err = dft.NewMatrixFromLiteralWithGeneratorPrecisionObserved(
		plan.params, dft.ObservedCoeffsToSlots, plan.ctsLiteral,
		encoder, rbdftGeneratorPrecision, ctsConsumer,
	)
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: build observed Route-B CTS matrix: %w", err)
	}
	ctsEvidence, err := ctsConsumer.promote(cts, ctsTrace)
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: promote observed Route-B CTS evidence: %w", err)
	}

	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: Route-B DFT construction counters: %w", err)
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 ||
		delta.ObservedStreaming() != 2 {
		return routeBArtifactBuildProduct{}, blockedRBDFT(
			"artifact build construction delta is %d/%d/%d/%d, want 0/0/0/2",
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(),
		)
	}

	records, payload, pairIdentity, err := buildRouteBArtifactPayloadRecords(
		plan.buildPermitIdentity, stcEvidence, ctsEvidence,
	)
	if err != nil {
		return routeBArtifactBuildProduct{}, err
	}
	stcConsumer.dropEncoderReference()
	ctsConsumer.dropEncoderReference()
	encoder = nil
	lifecycle, err := buildRouteBSuccessLifecycle(stcTrace, ctsTrace, pairIdentity)
	if err != nil {
		return routeBArtifactBuildProduct{}, err
	}
	records.Lifecycle, err = marshalRBDFTLifecycle(lifecycle)
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: marshal Route-B lifecycle: %w", err)
	}
	lifecycleIdentity := RBAUTHDigest(sha256.Sum256(records.Lifecycle))

	peakRSSBytes, err := plan.peakRSS()
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: measure Route-B build peak RSS: %w", err)
	}
	if peakRSSBytes == 0 {
		return routeBArtifactBuildProduct{}, blockedRBDFT("measured Route-B build peak RSS is zero")
	}
	wallNanoseconds := uint64(time.Since(started).Nanoseconds())
	if wallNanoseconds == 0 {
		wallNanoseconds = 1
	}
	receipt := RBDFTBuildReceiptReport{
		BuildPermitDigest: plan.buildPermitIdentity, PreparedParameterDigest: plan.preparedParameterIdentity,
		BuilderID: RBDFTBuilderID, DigestID: RBDFTDigestID, AllocationID: RBDFTAllocationID,
		ReleaseID: RBDFTReleaseID, OwnershipID: RBDFTOwnershipID,
		GeneratorPrecisionBits: 256, EncoderPrecisionBits: 256,
		DefaultCounterDelta: delta.DefaultWhole(), ExplicitWholeCounterDelta: delta.ExplicitWhole(),
		RawNumericCounterDelta: delta.RawNumeric(), ObservedStreamingCounterDelta: delta.ObservedStreaming(),
		LifecycleDigest: lifecycleIdentity, MaxLiveNumeric: 1,
		STCFactorCount: uint32(stcEvidence.count), CTSFactorCount: uint32(ctsEvidence.count),
		Payload: payload, BuildWallNanoseconds: wallNanoseconds, BuildPeakRSSBytes: peakRSSBytes,
		ArtifactState: RBDFTPrivateUninstalledState, ArtifactManifestDigest: pairIdentity,
	}
	records.BuildReceipt, err = marshalRBDFTBuildReceipt(receipt)
	if err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: marshal Route-B build receipt: %w", err)
	}
	if err = ValidateRBDFTBuildRecordLinks(records, plan.buildPermitIdentity, plan.preparedParameterIdentity); err != nil {
		return routeBArtifactBuildProduct{}, fmt.Errorf("secureeval: validate minted Route-B build records: %w", err)
	}

	product = routeBArtifactBuildProduct{
		stc: stc, cts: cts, records: cloneRBDFTBuildRecordSet(records), receipt: receipt, payload: payload,
	}
	stc = dft.Matrix{}
	cts = dft.Matrix{}
	return product, nil
}

func validateRouteBArtifactBuildPlan(plan routeBArtifactBuildPlan) error {
	if len(plan.params.Q()) == 0 || isZeroDigest(plan.buildPermitIdentity) ||
		isZeroDigest(plan.preparedParameterIdentity) || plan.peakRSS == nil {
		return malformedRBDFT("artifact build plan parameters, identities, or RSS sampler are empty")
	}
	if plan.stcProfile.role != dft.ObservedSlotsToCoeffs || plan.stcProfile.wireRole != RBDFTRoleSTC ||
		plan.ctsProfile.role != dft.ObservedCoeffsToSlots || plan.ctsProfile.wireRole != RBDFTRoleCTS {
		return malformedRBDFT("artifact build plan roles are not STC then CTS")
	}
	if err := plan.stcProfile.validate(); err != nil {
		return err
	}
	if err := plan.ctsProfile.validate(); err != nil {
		return err
	}
	if err := rbdftValidateEffectiveLiteral(plan.params, plan.stcProfile, plan.stcLiteral); err != nil {
		return err
	}
	if err := rbdftValidateEffectiveLiteral(plan.params, plan.ctsProfile, plan.ctsLiteral); err != nil {
		return err
	}
	return nil
}

func buildRouteBArtifactPayloadRecords(
	buildPermitIdentity RBAUTHDigest,
	stcEvidence, ctsEvidence rbdftPromotedFactorEvidence,
) (RBDFTBuildRecordSet, RBAUTHActualPayload, RBAUTHDigest, error) {
	stcNumeric, stcNumericReport, err := buildRBDFTTransformAggregate(RBDFTNumericAggregateType, stcEvidence)
	if err != nil {
		return RBDFTBuildRecordSet{}, RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	stcEncoded, stcEncodedReport, err := buildRBDFTTransformAggregate(RBDFTEncodedAggregateType, stcEvidence)
	if err != nil {
		return RBDFTBuildRecordSet{}, RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	ctsNumeric, ctsNumericReport, err := buildRBDFTTransformAggregate(RBDFTNumericAggregateType, ctsEvidence)
	if err != nil {
		return RBDFTBuildRecordSet{}, RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	ctsEncoded, ctsEncodedReport, err := buildRBDFTTransformAggregate(RBDFTEncodedAggregateType, ctsEvidence)
	if err != nil {
		return RBDFTBuildRecordSet{}, RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	records := RBDFTBuildRecordSet{
		STCNumericAggregate: stcNumeric, STCEncodedAggregate: stcEncoded,
		CTSNumericAggregate: ctsNumeric, CTSEncodedAggregate: ctsEncoded,
	}
	payload := RBAUTHActualPayload{
		STCNumeric: rbdftAggregateTuple(stcNumeric, stcNumericReport),
		STCEncoded: rbdftAggregateTuple(stcEncoded, stcEncodedReport),
		CTSNumeric: rbdftAggregateTuple(ctsNumeric, ctsNumericReport),
		CTSEncoded: rbdftAggregateTuple(ctsEncoded, ctsEncodedReport),
	}
	records.ArtifactPair, err = marshalRBDFTArtifactPairAggregate(RBDFTArtifactPairReport{
		BuildPermitDigest: buildPermitIdentity, Payload: payload,
	})
	if err != nil {
		return RBDFTBuildRecordSet{}, RBAUTHActualPayload{}, RBAUTHDigest{}, fmt.Errorf("secureeval: marshal Route-B artifact pair: %w", err)
	}
	pairIdentity := RBAUTHDigest(sha256.Sum256(records.ArtifactPair))
	return records, payload, pairIdentity, nil
}

func buildRBDFTTransformAggregate(
	recordType byte,
	evidence rbdftPromotedFactorEvidence,
) ([]byte, RBDFTTransformAggregateReport, error) {
	if evidence.count == 0 || uint32(evidence.count) > uint32(len(evidence.factors)) {
		return nil, RBDFTTransformAggregateReport{}, malformedRBDFT("promoted aggregate evidence count is invalid")
	}
	wireRole := byte(0)
	switch evidence.role {
	case dft.ObservedSlotsToCoeffs:
		wireRole = RBDFTRoleSTC
	case dft.ObservedCoeffsToSlots:
		wireRole = RBDFTRoleCTS
	default:
		return nil, RBDFTTransformAggregateReport{}, malformedRBDFT("promoted aggregate evidence role is invalid")
	}
	report := RBDFTTransformAggregateReport{
		RecordType: recordType, Role: wireRole, FactorCount: uint32(evidence.count),
	}
	total := uint64(rbdftAggregateFixedBytes) + uint64(report.FactorCount)*rbdftFactorReferenceBytes
	for index := uint32(0); index < report.FactorCount; index++ {
		factor := evidence.factors[index]
		identity := factor.numeric
		if recordType == RBDFTEncodedAggregateType {
			identity = factor.encoded
		} else if recordType != RBDFTNumericAggregateType {
			return nil, RBDFTTransformAggregateReport{}, malformedRBDFT("aggregate record type is invalid")
		}
		if factor.index != index || isZeroDigest(RBAUTHDigest(identity.digest)) || identity.bytes == 0 {
			return nil, RBDFTTransformAggregateReport{}, malformedRBDFT("promoted factor evidence is empty or non-contiguous")
		}
		report.Factors[index] = RBDFTFactorRecordRef{
			Index: index, Digest: RBAUTHDigest(identity.digest), RecordBytes: identity.bytes,
		}
		var ok bool
		if total, ok = checkedAddRBDFTUint64(total, identity.bytes); !ok {
			return nil, RBDFTTransformAggregateReport{}, malformedRBDFT("aggregate byte ledger overflowed")
		}
	}
	report.AggregateRecordBytes = total
	encoded, err := marshalRBDFTTransformAggregate(report)
	if err != nil {
		return nil, RBDFTTransformAggregateReport{}, fmt.Errorf("secureeval: marshal Route-B transform aggregate: %w", err)
	}
	return encoded, report, nil
}

func buildRouteBSuccessLifecycle(
	stcTrace, ctsTrace dft.ObservedStreamingTrace,
	pairIdentity RBAUTHDigest,
) (RBDFTLifecycleReport, error) {
	if isZeroDigest(pairIdentity) {
		return RBDFTLifecycleReport{}, malformedRBDFT("artifact pair identity is zero")
	}
	value := RBDFTLifecycleReport{
		TerminalStatus: RBDFTLifecycleSuccess, CompletedEventCount: RBDFTLifecycleSuccessEventCount,
		AttemptedEventLowerBound: RBDFTLifecycleSuccessEventCount, FailureStage: RBDFTFailureNone,
	}
	position := uint32(0)
	appendEvent := func(event RBDFTLifecycleEvent) error {
		if position >= RBDFTLifecycleSuccessEventCount {
			return malformedRBDFT("lifecycle event count overflowed")
		}
		event.Sequence = position
		value.events[position] = event
		position++
		return nil
	}
	if err := appendEvent(RBDFTLifecycleEvent{
		Source: RBDFTSourceSecureEval, Code: RBDFTEventPrepareComplete,
		Role: RBDFTRoleNone, FactorIndex: -1, PayloadKind: RBDFTPayloadNone,
	}); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	if err := appendEvent(RBDFTLifecycleEvent{
		Source: RBDFTSourceSecureEval, Code: RBDFTEventEncoderCreated,
		Role: RBDFTRoleNone, FactorIndex: -1, PayloadKind: RBDFTPayloadPrecision, Value: 256,
	}); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	for _, trace := range []dft.ObservedStreamingTrace{stcTrace, ctsTrace} {
		if err := trace.Validate(); err != nil || trace.Status() != dft.ObservedStreamingSuccess ||
			len(trace.CleanupEvents()) != 0 {
			return RBDFTLifecycleReport{}, malformedRBDFT("observed transform trace is not a clean success")
		}
		for _, source := range trace.Events() {
			event, err := routeBWireLifecycleEvent(source)
			if err != nil {
				return RBDFTLifecycleReport{}, err
			}
			if err = appendEvent(event); err != nil {
				return RBDFTLifecycleReport{}, err
			}
		}
	}
	if err := appendEvent(RBDFTLifecycleEvent{
		Source: RBDFTSourceSecureEval, Code: RBDFTEventArtifactSealed,
		Role: RBDFTRoleNone, FactorIndex: -1, PayloadKind: RBDFTPayloadArtifactPair,
		PayloadDigest: pairIdentity, Value: uint64(RBDFTArtifactPairRecordBytes),
	}); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	if err := appendEvent(RBDFTLifecycleEvent{
		Source: RBDFTSourceSecureEval, Code: RBDFTEventEncoderDropped,
		Role: RBDFTRoleNone, FactorIndex: -1, PayloadKind: RBDFTPayloadNone,
	}); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	if position != RBDFTLifecycleSuccessEventCount {
		return RBDFTLifecycleReport{}, malformedRBDFT("lifecycle event count is %d, want %d", position, RBDFTLifecycleSuccessEventCount)
	}
	if err := validateRBDFTLifecycle(value); err != nil {
		return RBDFTLifecycleReport{}, err
	}
	return value, nil
}

func routeBWireLifecycleEvent(source dft.ObservedStreamingEvent) (RBDFTLifecycleEvent, error) {
	wireRole := byte(0)
	switch source.Role() {
	case dft.ObservedSlotsToCoeffs:
		wireRole = RBDFTRoleSTC
	case dft.ObservedCoeffsToSlots:
		wireRole = RBDFTRoleCTS
	default:
		return RBDFTLifecycleEvent{}, malformedRBDFT("observed lifecycle role is invalid")
	}
	code := byte(source.Code())
	switch source.Code() {
	case dft.ObservedStreamingTransformStart, dft.ObservedStreamingFactorGenerated,
		dft.ObservedStreamingNumericDigested, dft.ObservedStreamingFactorEncoded,
		dft.ObservedStreamingEncodedDigested, dft.ObservedStreamingNumericReferenceDropped,
		dft.ObservedStreamingTransformEnd, dft.ObservedStreamingGeneratorReturned:
	default:
		return RBDFTLifecycleEvent{}, malformedRBDFT("observed lifecycle event code is invalid")
	}
	kind := byte(source.PayloadKind())
	switch source.PayloadKind() {
	case dft.ObservedStreamingPayloadNone, dft.ObservedStreamingPayloadNumericFactor,
		dft.ObservedStreamingPayloadEncodedFactor:
	default:
		return RBDFTLifecycleEvent{}, malformedRBDFT("observed lifecycle payload kind is invalid")
	}
	return RBDFTLifecycleEvent{
		Source: RBDFTSourceVendor, Code: code, Role: wireRole,
		FactorIndex: int32(source.FactorIndex()), PayloadKind: kind,
		PayloadDigest: RBAUTHDigest(source.PayloadDigest()), Value: source.PayloadBytes(),
	}, nil
}

func cloneRBDFTBuildRecordSet(value RBDFTBuildRecordSet) RBDFTBuildRecordSet {
	return RBDFTBuildRecordSet{
		STCNumericAggregate: append([]byte(nil), value.STCNumericAggregate...),
		STCEncodedAggregate: append([]byte(nil), value.STCEncodedAggregate...),
		CTSNumericAggregate: append([]byte(nil), value.CTSNumericAggregate...),
		CTSEncodedAggregate: append([]byte(nil), value.CTSEncodedAggregate...),
		ArtifactPair:        append([]byte(nil), value.ArtifactPair...),
		Lifecycle:           append([]byte(nil), value.Lifecycle...),
		BuildReceipt:        append([]byte(nil), value.BuildReceipt...),
	}
}

func validateRouteBResidentArtifactWithPlan(
	stc, cts dft.Matrix,
	records RBDFTBuildRecordSet,
	receipt RBDFTBuildReceiptReport,
	plan routeBResidentArtifactPlan,
) (RBAUTHActualPayload, RBAUTHDigest, error) {
	if err := validateRouteBResidentArtifactPlan(plan); err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	if err := validateRBDFTBuildReceipt(receipt); err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	if err := ValidateRBDFTBuildRecordLinks(records, receipt.BuildPermitDigest, receipt.PreparedParameterDigest); err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	parsedReceipt, err := ParseRBDFTBuildReceipt(records.BuildReceipt)
	if err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	if parsedReceipt != receipt {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, blockedRBDFT("resident build receipt differs from the supplied live receipt")
	}
	if err := stc.ValidateAgainst(plan.params, plan.stcLiteral); err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, fmt.Errorf("secureeval: validate resident Route-B STC matrix: %w", err)
	}
	if err := cts.ValidateAgainst(plan.params, plan.ctsLiteral); err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, fmt.Errorf("secureeval: validate resident Route-B CTS matrix: %w", err)
	}

	before := dft.SnapshotMatrixConstructionCounters()
	stcEncoded, stcEncodedReport, err := rehashRouteBResidentEncodedAggregate(
		plan.params, plan.stcLiteral, plan.stcProfile, stc,
	)
	if err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	ctsEncoded, ctsEncodedReport, err := rehashRouteBResidentEncodedAggregate(
		plan.params, plan.ctsLiteral, plan.ctsProfile, cts,
	)
	if err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	after := dft.SnapshotMatrixConstructionCounters()
	delta, err := after.Delta(before)
	if err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	if delta.DefaultWhole() != 0 || delta.ExplicitWhole() != 0 || delta.RawNumeric() != 0 ||
		delta.ObservedStreaming() != 0 {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, blockedRBDFT(
			"resident rehash construction delta is %d/%d/%d/%d, want 0/0/0/0",
			delta.DefaultWhole(), delta.ExplicitWhole(), delta.RawNumeric(), delta.ObservedStreaming(),
		)
	}
	payload := receipt.Payload
	payload.STCEncoded = rbdftAggregateTuple(stcEncoded, stcEncodedReport)
	payload.CTSEncoded = rbdftAggregateTuple(ctsEncoded, ctsEncodedReport)
	if payload != receipt.Payload || !bytes.Equal(stcEncoded, records.STCEncodedAggregate) ||
		!bytes.Equal(ctsEncoded, records.CTSEncodedAggregate) {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, blockedRBDFT("resident encoded aggregate differs from the build receipt")
	}
	pair, err := marshalRBDFTArtifactPairAggregate(RBDFTArtifactPairReport{
		BuildPermitDigest: receipt.BuildPermitDigest, Payload: payload,
	})
	if err != nil {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, err
	}
	pairIdentity := RBAUTHDigest(sha256.Sum256(pair))
	if pairIdentity != receipt.ArtifactManifestDigest || !bytes.Equal(pair, records.ArtifactPair) {
		return RBAUTHActualPayload{}, RBAUTHDigest{}, blockedRBDFT("resident artifact pair differs from the build receipt")
	}
	return payload, pairIdentity, nil
}

func validateRouteBResidentArtifactPlan(plan routeBResidentArtifactPlan) error {
	if len(plan.params.Q()) == 0 || plan.stcProfile.role != dft.ObservedSlotsToCoeffs ||
		plan.stcProfile.wireRole != RBDFTRoleSTC || plan.ctsProfile.role != dft.ObservedCoeffsToSlots ||
		plan.ctsProfile.wireRole != RBDFTRoleCTS {
		return malformedRBDFT("resident artifact plan parameters or roles are invalid")
	}
	if err := plan.stcProfile.validate(); err != nil {
		return err
	}
	if err := plan.ctsProfile.validate(); err != nil {
		return err
	}
	if err := rbdftValidateEffectiveLiteral(plan.params, plan.stcProfile, plan.stcLiteral); err != nil {
		return err
	}
	return rbdftValidateEffectiveLiteral(plan.params, plan.ctsProfile, plan.ctsLiteral)
}

func rehashRouteBResidentEncodedAggregate(
	params ckks.Parameters,
	literal dft.MatrixLiteral,
	profile rbdftFactorProfile,
	matrix dft.Matrix,
) ([]byte, RBDFTTransformAggregateReport, error) {
	if len(matrix.Matrices) != int(profile.factorCount) {
		return nil, RBDFTTransformAggregateReport{}, malformedRBDFT("resident matrix factor count changed")
	}
	evidence := rbdftPromotedFactorEvidence{role: profile.role, count: profile.factorCount}
	for index := range matrix.Matrices {
		transformation := matrix.Matrices[index]
		keys := make([]int, 0, len(transformation.Vec))
		for key := range transformation.Vec {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		identity, err := rbdftDigestEncodedFactor(
			params, profile, dft.ObservedFactorIndex(index), rbdftGeneratorPrecision,
			literal, keys, transformation,
		)
		if err != nil {
			return nil, RBDFTTransformAggregateReport{}, fmt.Errorf("secureeval: rehash resident encoded factor %d: %w", index, err)
		}
		evidence.factors[index] = rbdftFactorEvidencePair{index: uint32(index), encoded: identity}
	}
	return buildRBDFTTransformAggregate(RBDFTEncodedAggregateType, evidence)
}
