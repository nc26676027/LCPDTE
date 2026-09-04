package dft

import (
	"fmt"
	"sync/atomic"
)

// MatrixConstructionCounters is an immutable value snapshot of every public
// DFT matrix or numeric-factor construction entry. Its fields are private so
// external callers cannot set arbitrary non-zero values. Admission code must
// derive deltas from live snapshots and must not accept a caller-supplied value.
type MatrixConstructionCounters struct {
	defaultWhole      uint64
	explicitWhole     uint64
	rawNumeric        uint64
	observedStreaming uint64
}

var matrixConstructionCounters struct {
	defaultWhole      atomic.Uint64
	explicitWhole     atomic.Uint64
	rawNumeric        atomic.Uint64
	observedStreaming atomic.Uint64
}

const maxMatrixConstructionCounter = ^uint64(0)

// SnapshotMatrixConstructionCounters returns a monotonic, process-wide value
// snapshot. Each public construction entry increments exactly one field before
// validation and then calls a private construction core.
func SnapshotMatrixConstructionCounters() MatrixConstructionCounters {
	return MatrixConstructionCounters{
		defaultWhole:      matrixConstructionCounters.defaultWhole.Load(),
		explicitWhole:     matrixConstructionCounters.explicitWhole.Load(),
		rawNumeric:        matrixConstructionCounters.rawNumeric.Load(),
		observedStreaming: matrixConstructionCounters.observedStreaming.Load(),
	}
}

// DefaultWhole returns calls to NewMatrixFromLiteral.
func (c MatrixConstructionCounters) DefaultWhole() uint64 { return c.defaultWhole }

// ExplicitWhole returns calls to explicit-precision constructors that return
// an ordinary whole Matrix.
func (c MatrixConstructionCounters) ExplicitWhole() uint64 { return c.explicitWhole }

// RawNumeric returns calls to the public raw-factor iteration and all-at-once
// numeric generation entries.
func (c MatrixConstructionCounters) RawNumeric() uint64 { return c.rawNumeric }

// ObservedStreaming returns calls to the receipt-producing observed streaming
// constructor.
func (c MatrixConstructionCounters) ObservedStreaming() uint64 { return c.observedStreaming }

// Delta subtracts an earlier snapshot and rejects a non-monotonic pair.
func (c MatrixConstructionCounters) Delta(before MatrixConstructionCounters) (MatrixConstructionCounters, error) {
	if c.defaultWhole == maxMatrixConstructionCounter ||
		c.explicitWhole == maxMatrixConstructionCounter ||
		c.rawNumeric == maxMatrixConstructionCounter ||
		c.observedStreaming == maxMatrixConstructionCounter ||
		before.defaultWhole == maxMatrixConstructionCounter ||
		before.explicitWhole == maxMatrixConstructionCounter ||
		before.rawNumeric == maxMatrixConstructionCounter ||
		before.observedStreaming == maxMatrixConstructionCounter {
		return MatrixConstructionCounters{}, fmt.Errorf("dft: construction counter saturated")
	}
	if c.defaultWhole < before.defaultWhole ||
		c.explicitWhole < before.explicitWhole ||
		c.rawNumeric < before.rawNumeric ||
		c.observedStreaming < before.observedStreaming {
		return MatrixConstructionCounters{}, fmt.Errorf("dft: construction counter snapshot is non-monotonic")
	}
	return MatrixConstructionCounters{
		defaultWhole:      c.defaultWhole - before.defaultWhole,
		explicitWhole:     c.explicitWhole - before.explicitWhole,
		rawNumeric:        c.rawNumeric - before.rawNumeric,
		observedStreaming: c.observedStreaming - before.observedStreaming,
	}, nil
}

func noteDefaultWholeConstruction() {
	incrementMatrixConstructionCounter(&matrixConstructionCounters.defaultWhole)
}

func noteExplicitWholeConstruction() {
	incrementMatrixConstructionCounter(&matrixConstructionCounters.explicitWhole)
}

func noteRawNumericConstruction() {
	incrementMatrixConstructionCounter(&matrixConstructionCounters.rawNumeric)
}

func noteObservedStreamingConstruction() {
	incrementMatrixConstructionCounter(&matrixConstructionCounters.observedStreaming)
}

func incrementMatrixConstructionCounter(counter *atomic.Uint64) {
	for {
		before := counter.Load()
		if before == maxMatrixConstructionCounter {
			return
		}
		if counter.CompareAndSwap(before, before+1) {
			return
		}
	}
}
