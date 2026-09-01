package rlwe

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/tuneinsight/lattigo/v6/ring"
)

const traceDispatchReportVersion uint8 = 1

// TraceDispatchStatus is the terminal status of one observed Trace invocation.
type TraceDispatchStatus uint8

const (
	TraceDispatchStatusUnset TraceDispatchStatus = iota
	TraceDispatchSuccess
	TraceDispatchFailure
)

// TraceDispatchFailureKind distinguishes ordinary errors from recovered panics.
type TraceDispatchFailureKind uint8

const (
	TraceDispatchFailureNone TraceDispatchFailureKind = iota
	TraceDispatchFailureError
	TraceDispatchFailurePanic
)

// TraceDispatchFailureStage identifies the Trace phase in which an invocation failed.
type TraceDispatchFailureStage uint8

const (
	TraceDispatchStageNone TraceDispatchFailureStage = iota
	TraceDispatchStageValidation
	TraceDispatchStagePreparation
	TraceDispatchStageDispatch
	TraceDispatchStageAdd
	TraceDispatchStageFinalize
)

// TraceDispatchEventKind distinguishes the ordinary <5>-subgroup path from
// the standard-ring order-two automorphism.
type TraceDispatchEventKind uint8

const (
	TraceDispatchEventUnset TraceDispatchEventKind = iota
	TraceDispatchAutomorphism
	TraceDispatchOrderTwoAutomorphism
)

// TraceDispatchEvent describes one actual Automorphism attempt made by Trace.
// Its fields are private so callers cannot manufacture an accepted report.
type TraceDispatchEvent struct {
	sequence            uint32
	kind                TraceDispatchEventKind
	hasOrdinaryExponent bool
	ordinaryExponent    uint64
	galoisElement       uint64
	completed           bool
}

func (event TraceDispatchEvent) Sequence() uint32             { return event.sequence }
func (event TraceDispatchEvent) Kind() TraceDispatchEventKind { return event.kind }
func (event TraceDispatchEvent) HasOrdinaryExponent() bool    { return event.hasOrdinaryExponent }
func (event TraceDispatchEvent) OrdinaryExponent() uint64     { return event.ordinaryExponent }
func (event TraceDispatchEvent) GaloisElement() uint64        { return event.galoisElement }
func (event TraceDispatchEvent) Completed() bool              { return event.completed }

// TraceDispatchReport is invocation-local structural evidence for the real
// Automorphism calls made by Trace. Its digest is structural only: it does not
// authenticate keys or ciphertext contents.
type TraceDispatchReport struct {
	version             uint8
	status              TraceDispatchStatus
	failureKind         TraceDispatchFailureKind
	failureStage        TraceDispatchFailureStage
	ringLogN            int
	ringType            ring.Type
	requestedLogN       int
	inputOutputAliased  bool
	attemptedDispatches uint32
	completedDispatches uint32
	events              []TraceDispatchEvent
	digest              [sha256.Size]byte
}

func (report TraceDispatchReport) Version() uint8                        { return report.version }
func (report TraceDispatchReport) Status() TraceDispatchStatus           { return report.status }
func (report TraceDispatchReport) FailureKind() TraceDispatchFailureKind { return report.failureKind }
func (report TraceDispatchReport) FailureStage() TraceDispatchFailureStage {
	return report.failureStage
}
func (report TraceDispatchReport) RingLogN() int               { return report.ringLogN }
func (report TraceDispatchReport) RingType() ring.Type         { return report.ringType }
func (report TraceDispatchReport) RequestedLogN() int          { return report.requestedLogN }
func (report TraceDispatchReport) InputOutputAliased() bool    { return report.inputOutputAliased }
func (report TraceDispatchReport) AttemptedDispatches() uint32 { return report.attemptedDispatches }
func (report TraceDispatchReport) CompletedDispatches() uint32 { return report.completedDispatches }
func (report TraceDispatchReport) Digest() [sha256.Size]byte   { return report.digest }
func (report TraceDispatchReport) Events() []TraceDispatchEvent {
	return append([]TraceDispatchEvent(nil), report.events...)
}

// IsZero reports whether this value is the absent nested-report value.
func (report TraceDispatchReport) IsZero() bool {
	return report.version == 0 && report.status == TraceDispatchStatusUnset &&
		report.failureKind == TraceDispatchFailureNone && report.failureStage == TraceDispatchStageNone &&
		report.ringLogN == 0 && report.ringType == ring.Standard && report.requestedLogN == 0 &&
		!report.inputOutputAliased && report.attemptedDispatches == 0 && report.completedDispatches == 0 &&
		len(report.events) == 0 && report.digest == ([sha256.Size]byte{})
}

// Validate verifies the report digest, terminal ledger and source-order event shape.
func (report TraceDispatchReport) Validate() error {
	if report.IsZero() {
		return fmt.Errorf("rlwe: zero Trace dispatch report")
	}
	if report.version != traceDispatchReportVersion {
		return fmt.Errorf("rlwe: Trace dispatch report version changed")
	}
	if report.digest == ([sha256.Size]byte{}) || report.digest != digestTraceDispatchReport(report) {
		return fmt.Errorf("rlwe: Trace dispatch report digest changed")
	}
	if report.ringLogN < MinLogN || report.ringLogN > MaxLogN {
		return fmt.Errorf("rlwe: Trace dispatch ring degree changed")
	}
	if report.ringType != ring.Standard && report.ringType != ring.ConjugateInvariant {
		return fmt.Errorf("rlwe: Trace dispatch ring type changed")
	}
	if report.attemptedDispatches != uint32(len(report.events)) {
		return fmt.Errorf("rlwe: Trace attempted count changed")
	}

	var completed uint32
	for sequence, event := range report.events {
		if event.sequence != uint32(sequence) {
			return fmt.Errorf("rlwe: Trace dispatch sequence changed")
		}
		if event.completed {
			completed++
		} else if sequence != len(report.events)-1 {
			return fmt.Errorf("rlwe: incomplete Trace dispatch is not last")
		}
	}
	if report.completedDispatches != completed || report.completedDispatches > report.attemptedDispatches {
		return fmt.Errorf("rlwe: Trace completed count changed")
	}

	switch report.status {
	case TraceDispatchSuccess:
		if report.failureKind != TraceDispatchFailureNone || report.failureStage != TraceDispatchStageNone ||
			report.completedDispatches != report.attemptedDispatches {
			return fmt.Errorf("rlwe: Trace success ledger changed")
		}
		if err := report.validateEventPrefix(true); err != nil {
			return err
		}
	case TraceDispatchFailure:
		if report.failureKind != TraceDispatchFailureError && report.failureKind != TraceDispatchFailurePanic {
			return fmt.Errorf("rlwe: Trace failure kind changed")
		}
		if report.failureStage == TraceDispatchStageNone || report.failureStage > TraceDispatchStageFinalize {
			return fmt.Errorf("rlwe: Trace failure stage changed")
		}
		if err := report.validateFailureLedger(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("rlwe: Trace dispatch status changed")
	}

	return nil
}

func (report TraceDispatchReport) validateFailureLedger() error {
	switch report.failureStage {
	case TraceDispatchStageValidation:
		if report.attemptedDispatches != 0 {
			return fmt.Errorf("rlwe: Trace validation failure ledger changed")
		}
	case TraceDispatchStagePreparation:
		if report.failureKind != TraceDispatchFailurePanic || report.attemptedDispatches != 0 {
			return fmt.Errorf("rlwe: Trace preparation failure ledger changed")
		}
	case TraceDispatchStageDispatch:
		if report.attemptedDispatches == 0 || report.completedDispatches != report.attemptedDispatches-1 ||
			report.events[len(report.events)-1].completed {
			return fmt.Errorf("rlwe: Trace dispatch failure prefix changed")
		}
		if err := report.validateEventPrefix(false); err != nil {
			return err
		}
	case TraceDispatchStageAdd:
		if report.failureKind != TraceDispatchFailurePanic || report.attemptedDispatches == 0 ||
			report.completedDispatches != report.attemptedDispatches {
			return fmt.Errorf("rlwe: Trace add failure ledger changed")
		}
		if err := report.validateEventPrefix(false); err != nil {
			return err
		}
	case TraceDispatchStageFinalize:
		if report.failureKind != TraceDispatchFailurePanic || report.completedDispatches != report.attemptedDispatches {
			return fmt.Errorf("rlwe: Trace finalize failure ledger changed")
		}
		if err := report.validateEventPrefix(true); err != nil {
			return err
		}
	default:
		return fmt.Errorf("rlwe: Trace failure stage changed")
	}
	return nil
}

func (report TraceDispatchReport) validateEventPrefix(requireComplete bool) error {
	expected, err := expectedTraceDispatchEvents(report.ringLogN, report.ringType, report.requestedLogN)
	if err != nil {
		return err
	}
	if len(report.events) > len(expected) || (requireComplete && len(report.events) != len(expected)) {
		return fmt.Errorf("rlwe: Trace dispatch count differs from source order")
	}
	for index, event := range report.events {
		want := expected[index]
		if event.kind != want.kind || event.hasOrdinaryExponent != want.hasOrdinaryExponent ||
			event.ordinaryExponent != want.ordinaryExponent || event.galoisElement != want.galoisElement {
			return fmt.Errorf("rlwe: Trace dispatch event %d differs from source order", index)
		}
	}
	return nil
}

func expectedTraceDispatchEvents(ringLogN int, ringType ring.Type, requestedLogN int) ([]TraceDispatchEvent, error) {
	if requestedLogN < 0 || requestedLogN > ringLogN-1 {
		return nil, fmt.Errorf("rlwe: Trace requested logN is outside the successful range")
	}
	if ringType != ring.Standard && ringType != ring.ConjugateInvariant {
		return nil, fmt.Errorf("rlwe: Trace ring type changed")
	}

	gap := 1 << (ringLogN - requestedLogN - 1)
	if requestedLogN == 0 {
		gap <<= 1
	}
	if gap <= 1 {
		return nil, nil
	}

	logNthRoot := ringLogN + 1
	if ringType == ring.ConjugateInvariant {
		logNthRoot++
	}
	nthRoot := uint64(1) << logNthRoot
	events := make([]TraceDispatchEvent, 0, ringLogN-requestedLogN)
	for i := requestedLogN; i < ringLogN-1; i++ {
		exponent := uint64(1) << i
		events = append(events, TraceDispatchEvent{
			sequence:            uint32(len(events)),
			kind:                TraceDispatchAutomorphism,
			hasOrdinaryExponent: true,
			ordinaryExponent:    exponent,
			galoisElement:       ring.ModExp(GaloisGen, exponent&(nthRoot-1), nthRoot),
			completed:           true,
		})
	}
	if requestedLogN == 0 && ringType == ring.Standard {
		events = append(events, TraceDispatchEvent{
			sequence:      uint32(len(events)),
			kind:          TraceDispatchOrderTwoAutomorphism,
			galoisElement: nthRoot - 1,
			completed:     true,
		})
	}
	return events, nil
}

func digestTraceDispatchReport(report TraceDispatchReport) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lattigo/rlwe/trace-dispatch-report/v1\x00"))
	writeTraceDigestByte(h, report.version)
	writeTraceDigestByte(h, uint8(report.status))
	writeTraceDigestByte(h, uint8(report.failureKind))
	writeTraceDigestByte(h, uint8(report.failureStage))
	writeTraceDigestUint64(h, uint64(int64(report.ringLogN)))
	writeTraceDigestUint64(h, uint64(int64(report.ringType)))
	writeTraceDigestUint64(h, uint64(int64(report.requestedLogN)))
	writeTraceDigestBool(h, report.inputOutputAliased)
	writeTraceDigestUint32(h, report.attemptedDispatches)
	writeTraceDigestUint32(h, report.completedDispatches)
	writeTraceDigestUint32(h, uint32(len(report.events)))
	for _, event := range report.events {
		writeTraceDigestUint32(h, event.sequence)
		writeTraceDigestByte(h, uint8(event.kind))
		writeTraceDigestBool(h, event.hasOrdinaryExponent)
		writeTraceDigestUint64(h, event.ordinaryExponent)
		writeTraceDigestUint64(h, event.galoisElement)
		writeTraceDigestBool(h, event.completed)
	}
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

func writeTraceDigestByte(h hash.Hash, value uint8) {
	_, _ = h.Write([]byte{value})
}

func writeTraceDigestBool(h hash.Hash, value bool) {
	if value {
		writeTraceDigestByte(h, 1)
	} else {
		writeTraceDigestByte(h, 0)
	}
}

func writeTraceDigestUint32(h hash.Hash, value uint32) {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

func writeTraceDigestUint64(h hash.Hash, value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

type traceDispatchRecorder struct {
	report TraceDispatchReport
	stage  TraceDispatchFailureStage
}

func newTraceDispatchRecorder(params *Parameters, requestedLogN int, aliased bool) *traceDispatchRecorder {
	return &traceDispatchRecorder{
		report: TraceDispatchReport{
			version:            traceDispatchReportVersion,
			ringLogN:           params.LogN(),
			ringType:           params.RingType(),
			requestedLogN:      requestedLogN,
			inputOutputAliased: aliased,
		},
		stage: TraceDispatchStageValidation,
	}
}

func (recorder *traceDispatchRecorder) setStage(stage TraceDispatchFailureStage) {
	if recorder != nil {
		recorder.stage = stage
	}
}

func (recorder *traceDispatchRecorder) begin(kind TraceDispatchEventKind, hasExponent bool, exponent, galEl uint64) {
	if recorder == nil {
		return
	}
	recorder.stage = TraceDispatchStageDispatch
	recorder.report.events = append(recorder.report.events, TraceDispatchEvent{
		sequence:            uint32(len(recorder.report.events)),
		kind:                kind,
		hasOrdinaryExponent: hasExponent,
		ordinaryExponent:    exponent,
		galoisElement:       galEl,
	})
	recorder.report.attemptedDispatches++
}

func (recorder *traceDispatchRecorder) complete() {
	if recorder == nil {
		return
	}
	index := len(recorder.report.events) - 1
	recorder.report.events[index].completed = true
	recorder.report.completedDispatches++
}

func (recorder *traceDispatchRecorder) succeed() {
	recorder.report.status = TraceDispatchSuccess
	recorder.report.failureKind = TraceDispatchFailureNone
	recorder.report.failureStage = TraceDispatchStageNone
}

func (recorder *traceDispatchRecorder) fail(kind TraceDispatchFailureKind) {
	recorder.report.status = TraceDispatchFailure
	recorder.report.failureKind = kind
	recorder.report.failureStage = recorder.stage
}

func (recorder *traceDispatchRecorder) seal() TraceDispatchReport {
	recorder.report.digest = digestTraceDispatchReport(recorder.report)
	return recorder.report
}
