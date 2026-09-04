// Modified by the LCPDTE project for local module integration and, where applicable,
// runtime instrumentation. See lattigo/NOTICE for attribution and modification details.

package bootstrapping

import (
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
)

const modUpTraceReportVersion uint8 = 1

// ModUpTraceStatus is the terminal status of one observed ModUp invocation.
type ModUpTraceStatus uint8

const (
	ModUpTraceStatusUnset ModUpTraceStatus = iota
	ModUpTraceSuccess
	ModUpTraceFailure
)

// ModUpTraceFailureKind distinguishes ordinary errors from recovered panics.
type ModUpTraceFailureKind uint8

const (
	ModUpTraceFailureNone ModUpTraceFailureKind = iota
	ModUpTraceFailureError
	ModUpTraceFailurePanic
)

// ModUpTraceFailureStage identifies the ModUp phase in which an invocation
// failed. A successful report always uses ModUpTraceStageNone.
type ModUpTraceFailureStage uint8

const (
	ModUpTraceStageNone ModUpTraceFailureStage = iota
	ModUpTraceStageDenseToSparse
	ModUpTraceStageCoefficientLift
	ModUpTraceStageSparseToDense
	ModUpTraceStageScale
	ModUpTraceStageTrace
	ModUpTraceStageFinalize
)

// ModUpTraceReport is invocation-local structural evidence that ModUp entered
// one observed Trace invocation. Its digest authenticates neither keys nor
// ciphertext contents.
type ModUpTraceReport struct {
	version      uint8
	status       ModUpTraceStatus
	failureKind  ModUpTraceFailureKind
	failureStage ModUpTraceFailureStage
	traceStarted bool
	traceReport  rlwe.TraceDispatchReport
	digest       [sha256.Size]byte
}

func (report ModUpTraceReport) Version() uint8                       { return report.version }
func (report ModUpTraceReport) Status() ModUpTraceStatus             { return report.status }
func (report ModUpTraceReport) FailureKind() ModUpTraceFailureKind   { return report.failureKind }
func (report ModUpTraceReport) FailureStage() ModUpTraceFailureStage { return report.failureStage }
func (report ModUpTraceReport) TraceStarted() bool                   { return report.traceStarted }
func (report ModUpTraceReport) TraceReport() rlwe.TraceDispatchReport {
	return report.traceReport
}
func (report ModUpTraceReport) Digest() [sha256.Size]byte { return report.digest }

// IsZero reports whether this value is the absent report value.
func (report ModUpTraceReport) IsZero() bool {
	return report.version == 0 && report.status == ModUpTraceStatusUnset &&
		report.failureKind == ModUpTraceFailureNone && report.failureStage == ModUpTraceStageNone &&
		!report.traceStarted && report.traceReport.IsZero() && report.digest == ([sha256.Size]byte{})
}

// Validate verifies the report seal and its terminal/nested-Trace invariants.
func (report ModUpTraceReport) Validate() error {
	if report.IsZero() {
		return fmt.Errorf("bootstrapping: zero ModUp Trace report")
	}
	if report.version != modUpTraceReportVersion {
		return fmt.Errorf("bootstrapping: ModUp Trace report version changed")
	}
	if report.digest == ([sha256.Size]byte{}) || report.digest != digestModUpTraceReport(report) {
		return fmt.Errorf("bootstrapping: ModUp Trace report digest changed")
	}
	if report.traceStarted {
		if report.traceReport.IsZero() {
			return fmt.Errorf("bootstrapping: ModUp Trace report lost its nested Trace report")
		}
		if err := report.traceReport.Validate(); err != nil {
			return fmt.Errorf("bootstrapping: invalid nested Trace report: %w", err)
		}
		if !report.traceReport.InputOutputAliased() {
			return fmt.Errorf("bootstrapping: ModUp nested Trace was not in-place")
		}
	} else if !report.traceReport.IsZero() {
		return fmt.Errorf("bootstrapping: ModUp has a nested Trace report without starting Trace")
	}

	switch report.status {
	case ModUpTraceSuccess:
		if report.failureKind != ModUpTraceFailureNone || report.failureStage != ModUpTraceStageNone ||
			!report.traceStarted || report.traceReport.Status() != rlwe.TraceDispatchSuccess {
			return fmt.Errorf("bootstrapping: ModUp success ledger changed")
		}
	case ModUpTraceFailure:
		if report.failureKind != ModUpTraceFailureError && report.failureKind != ModUpTraceFailurePanic {
			return fmt.Errorf("bootstrapping: ModUp failure kind changed")
		}
		if report.failureStage == ModUpTraceStageNone || report.failureStage > ModUpTraceStageFinalize {
			return fmt.Errorf("bootstrapping: ModUp failure stage changed")
		}
		switch report.failureStage {
		case ModUpTraceStageTrace:
			if !report.traceStarted {
				if report.failureKind != ModUpTraceFailurePanic || !report.traceReport.IsZero() {
					return fmt.Errorf("bootstrapping: ModUp Trace-entry panic ledger changed")
				}
				break
			}
			if report.traceReport.Status() != rlwe.TraceDispatchFailure {
				return fmt.Errorf("bootstrapping: ModUp Trace failure ledger changed")
			}
			if (report.failureKind == ModUpTraceFailurePanic) != (report.traceReport.FailureKind() == rlwe.TraceDispatchFailurePanic) ||
				(report.failureKind == ModUpTraceFailureError) != (report.traceReport.FailureKind() == rlwe.TraceDispatchFailureError) {
				return fmt.Errorf("bootstrapping: ModUp and nested Trace failure kinds differ")
			}
		case ModUpTraceStageFinalize:
			if !report.traceStarted || report.traceReport.Status() != rlwe.TraceDispatchSuccess {
				return fmt.Errorf("bootstrapping: ModUp finalize failure ledger changed")
			}
		default:
			if report.traceStarted || !report.traceReport.IsZero() {
				return fmt.Errorf("bootstrapping: pre-Trace ModUp failure contains Trace evidence")
			}
		}
	default:
		return fmt.Errorf("bootstrapping: ModUp Trace status changed")
	}

	return nil
}

func digestModUpTraceReport(report ModUpTraceReport) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lattigo/ckks/bootstrapping/modup-trace-report/v1\x00"))
	writeModUpTraceByte(h, report.version)
	writeModUpTraceByte(h, uint8(report.status))
	writeModUpTraceByte(h, uint8(report.failureKind))
	writeModUpTraceByte(h, uint8(report.failureStage))
	writeModUpTraceBool(h, report.traceStarted)
	nestedDigest := report.traceReport.Digest()
	_, _ = h.Write(nestedDigest[:])
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

func writeModUpTraceByte(h hash.Hash, value uint8) {
	_, _ = h.Write([]byte{value})
}

func writeModUpTraceBool(h hash.Hash, value bool) {
	if value {
		writeModUpTraceByte(h, 1)
	} else {
		writeModUpTraceByte(h, 0)
	}
}

type modUpTraceRecorder struct {
	stage        ModUpTraceFailureStage
	traceStarted bool
	traceReport  rlwe.TraceDispatchReport
}

func (recorder *modUpTraceRecorder) setStage(stage ModUpTraceFailureStage) {
	if recorder != nil {
		recorder.stage = stage
	}
}

func (recorder *modUpTraceRecorder) beginTrace() {
	if recorder != nil {
		recorder.stage = ModUpTraceStageTrace
		recorder.traceStarted = true
	}
}

func (recorder *modUpTraceRecorder) setTraceReport(report rlwe.TraceDispatchReport) {
	if recorder != nil {
		recorder.traceReport = report
	}
}

func (recorder *modUpTraceRecorder) seal(status ModUpTraceStatus, kind ModUpTraceFailureKind) ModUpTraceReport {
	stage := recorder.stage
	if status == ModUpTraceSuccess {
		stage = ModUpTraceStageNone
	}
	report := ModUpTraceReport{
		version:      modUpTraceReportVersion,
		status:       status,
		failureKind:  kind,
		failureStage: stage,
		traceStarted: recorder.traceStarted,
		traceReport:  recorder.traceReport,
	}
	report.digest = digestModUpTraceReport(report)
	return report
}

// ModUpObserved executes the stock ModUp algorithm once and returns the exact
// nested report from its final in-place TraceObserved call. Only this observed
// entry recovers panics; callers must discard all partially modified inputs
// after an error.
func (eval Evaluator) ModUpObserved(ctIn *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext, report ModUpTraceReport, err error) {
	recorder := new(modUpTraceRecorder)
	defer func() {
		if recovered := recover(); recovered != nil {
			// TraceObserved can panic while its receiver is being resolved,
			// before it can return a nested report. The stage records that
			// transition, while traceStarted remains false without evidence.
			if recorder.traceStarted && recorder.traceReport.IsZero() {
				recorder.traceStarted = false
			}
			ctOut = nil
			report = recorder.seal(ModUpTraceFailure, ModUpTraceFailurePanic)
			err = fmt.Errorf("bootstrapping: ModUpObserved recovered panic at stage %d: %v", recorder.stage, recovered)
		}
	}()

	ctOut, err = eval.modUpCore(ctIn, recorder)
	if err != nil {
		kind := ModUpTraceFailureError
		if recorder.traceStarted && recorder.traceReport.FailureKind() == rlwe.TraceDispatchFailurePanic {
			kind = ModUpTraceFailurePanic
			ctOut = nil
		}
		report = recorder.seal(ModUpTraceFailure, kind)
		return
	}

	recorder.setStage(ModUpTraceStageFinalize)
	report = recorder.seal(ModUpTraceSuccess, ModUpTraceFailureNone)
	return
}
