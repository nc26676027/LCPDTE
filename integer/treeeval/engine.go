package treeeval

import "fmt"

type countedBackend[V any] struct {
	backend Backend[V]
	counts  OperationCounts
}

func (e *countedBackend[V]) kind(value V, where string) (ValueKind, error) {
	kind := e.backend.Kind(value)
	if kind != ValuePublic && kind != ValueOpaque {
		return ValueInvalid, fmt.Errorf("%w: %s has kind %s", ErrInvalidValue, where, kind)
	}
	return kind, nil
}

func joinedKind(left, right ValueKind) ValueKind {
	if left == ValueOpaque || right == ValueOpaque {
		return ValueOpaque
	}
	return ValuePublic
}

func (e *countedBackend[V]) requireResult(value V, want ValueKind, operation string) (V, error) {
	got := e.backend.Kind(value)
	if got != want {
		var zero V
		return zero, fmt.Errorf("%w: %s returned %s, want %s", ErrBackendProvenance, operation, got, want)
	}
	return value, nil
}

func (e *countedBackend[V]) public(value PublicScalar) (V, error) {
	result, err := e.backend.PublicConstant(value)
	if err != nil {
		var zero V
		return zero, fmt.Errorf("%w: PublicConstant(%+v): %v", ErrBackendOperation, value, err)
	}
	e.counts.PublicConstants++
	return e.requireResult(result, ValuePublic, "PublicConstant")
}

func (e *countedBackend[V]) add(left, right V) (V, error) {
	lk, err := e.kind(left, "Add left operand")
	if err != nil {
		var zero V
		return zero, err
	}
	rk, err := e.kind(right, "Add right operand")
	if err != nil {
		var zero V
		return zero, err
	}
	result, err := e.backend.Add(left, right)
	if err != nil {
		var zero V
		return zero, fmt.Errorf("%w: Add: %v", ErrBackendOperation, err)
	}
	e.counts.Additions++
	return e.requireResult(result, joinedKind(lk, rk), "Add")
}

func (e *countedBackend[V]) sub(left, right V) (V, error) {
	lk, err := e.kind(left, "Sub left operand")
	if err != nil {
		var zero V
		return zero, err
	}
	rk, err := e.kind(right, "Sub right operand")
	if err != nil {
		var zero V
		return zero, err
	}
	result, err := e.backend.Sub(left, right)
	if err != nil {
		var zero V
		return zero, fmt.Errorf("%w: Sub: %v", ErrBackendOperation, err)
	}
	e.counts.Subtractions++
	return e.requireResult(result, joinedKind(lk, rk), "Sub")
}

func (e *countedBackend[V]) mul(left, right V) (V, error) {
	lk, err := e.kind(left, "Mul left operand")
	if err != nil {
		var zero V
		return zero, err
	}
	rk, err := e.kind(right, "Mul right operand")
	if err != nil {
		var zero V
		return zero, err
	}
	result, err := e.backend.Mul(left, right)
	if err != nil {
		var zero V
		return zero, fmt.Errorf("%w: Mul: %v", ErrBackendOperation, err)
	}
	switch {
	case lk == ValueOpaque && rk == ValueOpaque:
		e.counts.CTCTMultiplications++
	case lk == ValueOpaque || rk == ValueOpaque:
		e.counts.CTPublicMultiplications++
	default:
		e.counts.PublicPublicMultiplications++
	}
	return e.requireResult(result, joinedKind(lk, rk), "Mul")
}

func (e *countedBackend[V]) compareGE(left, right V, policy ComparisonPolicy) (V, error) {
	lk, err := e.kind(left, "CompareGE left operand")
	if err != nil {
		var zero V
		return zero, err
	}
	rk, err := e.kind(right, "CompareGE right operand")
	if err != nil {
		var zero V
		return zero, err
	}
	result, err := e.backend.CompareGE(left, right, policy)
	if err != nil {
		var zero V
		return zero, fmt.Errorf("%w: CompareGE: %v", ErrBackendOperation, err)
	}
	e.counts.Comparisons++
	switch {
	case lk == ValueOpaque && rk == ValueOpaque:
		e.counts.CTCTComparisons++
	case lk == ValueOpaque || rk == ValueOpaque:
		e.counts.CTPublicComparisons++
	default:
		e.counts.PublicPublicComparisons++
	}
	return e.requireResult(result, joinedKind(lk, rk), "CompareGE")
}

func (e *countedBackend[V]) observeLive(pathStates, comparisonStates int) {
	if pathStates > e.counts.PeakLivePathStates {
		e.counts.PeakLivePathStates = pathStates
	}
	if comparisonStates > e.counts.PeakLiveComparisonStates {
		e.counts.PeakLiveComparisonStates = comparisonStates
	}
	if total := pathStates + comparisonStates; total > e.counts.PeakLiveStates {
		e.counts.PeakLiveStates = total
	}
}
