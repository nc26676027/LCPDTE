package treeeval

import (
	"fmt"
	"reflect"

	"github.com/nc26676027/LCPDTE/integer/treeplan"
)

func nilBackend[V any](backend Backend[V]) bool {
	if backend == nil {
		return true
	}
	value := reflect.ValueOf(backend)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func validateInputs[T treeplan.Ordered, L treeplan.Ordered, V any](backend Backend[V], tree treeplan.BinaryTree[T, L], features []V, opaqueOne V, policy ComparisonPolicy) error {
	if nilBackend(backend) {
		return ErrInvalidBackend
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidComparisonPolicy, err)
	}
	if err := tree.Validate(); err != nil {
		return fmt.Errorf("invalid tree: %w", err)
	}
	if backend.Kind(opaqueOne) != ValueOpaque {
		return fmt.Errorf("%w: initial one-hot weight must be opaque", ErrInvalidValue)
	}
	for i, feature := range features {
		if backend.Kind(feature) != ValueOpaque {
			return fmt.Errorf("%w: feature %d must be opaque", ErrInvalidValue, i)
		}
	}
	for i, split := range tree.Splits {
		if split.Feature >= len(features) {
			return fmt.Errorf("%w: split %d requires feature %d, input has %d", ErrInvalidValue, i, split.Feature, len(features))
		}
		threshold, err := exactPublicScalar(split.Threshold)
		if err != nil {
			return err
		}
		if err := policy.validateOperand(threshold, false); err != nil {
			return fmt.Errorf("%w: split %d threshold: %v", ErrInvalidComparisonPolicy, i, err)
		}
	}
	return nil
}

func exactPublicScalar[N treeplan.Ordered](value N) (PublicScalar, error) {
	scalar, err := publicScalarFromOrdered(value)
	if err != nil {
		return PublicScalar{}, fmt.Errorf("%w: %v: %v", ErrInvalidValue, value, err)
	}
	return scalar, nil
}

func sumValues[V any](engine *countedBackend[V], values []V) (V, error) {
	if len(values) == 0 {
		var zero V
		return zero, fmt.Errorf("%w: cannot sum an empty value set", ErrInvalidValue)
	}
	sum := values[0]
	for i := 1; i < len(values); i++ {
		var err error
		sum, err = engine.add(sum, values[i])
		if err != nil {
			var zero V
			return zero, err
		}
	}
	return sum, nil
}

func selectFeatures[T treeplan.Ordered, V any](engine *countedBackend[V], weights []V, splits []treeplan.BinarySplit[T], features []V) (V, error) {
	terms := make([]V, len(weights))
	for i := range weights {
		term, err := engine.mul(weights[i], features[splits[i].Feature])
		if err != nil {
			var zero V
			return zero, err
		}
		terms[i] = term
	}
	return sumValues(engine, terms)
}

func selectThresholds[T treeplan.Ordered, V any](engine *countedBackend[V], weights []V, splits []treeplan.BinarySplit[T]) (V, error) {
	terms := make([]V, len(weights))
	for i := range weights {
		scalar, err := exactPublicScalar(splits[i].Threshold)
		if err != nil {
			var zero V
			return zero, err
		}
		threshold, err := engine.public(scalar)
		if err != nil {
			var zero V
			return zero, err
		}
		term, err := engine.mul(weights[i], threshold)
		if err != nil {
			var zero V
			return zero, err
		}
		terms[i] = term
	}
	return sumValues(engine, terms)
}

func updatePathWeights[V any](engine *countedBackend[V], weights []V, branches []V) ([]V, error) {
	if len(weights) != len(branches) {
		return nil, fmt.Errorf("%w: path/branch lengths %d/%d", ErrInvalidValue, len(weights), len(branches))
	}
	next := make([]V, 2*len(weights))
	for i := range weights {
		right, err := engine.mul(weights[i], branches[i])
		if err != nil {
			return nil, err
		}
		left, err := engine.sub(weights[i], right)
		if err != nil {
			return nil, err
		}
		next[2*i] = left
		next[2*i+1] = right
	}
	return next, nil
}

func selectLeaves[L treeplan.Ordered, V any](engine *countedBackend[V], weights []V, leaves []L) (V, error) {
	if len(weights) != len(leaves) {
		var zero V
		return zero, fmt.Errorf("%w: path/leaf lengths %d/%d", ErrInvalidValue, len(weights), len(leaves))
	}
	terms := make([]V, len(leaves))
	for i, leaf := range leaves {
		scalar, err := exactPublicScalar(leaf)
		if err != nil {
			var zero V
			return zero, err
		}
		constant, err := engine.public(scalar)
		if err != nil {
			var zero V
			return zero, err
		}
		term, err := engine.mul(weights[i], constant)
		if err != nil {
			var zero V
			return zero, err
		}
		terms[i] = term
	}
	return sumValues(engine, terms)
}

// EvaluateOBO performs model-private one-branch-only evaluation. At each depth
// opaque path weights select both the encrypted feature value and the public
// model threshold. The selected threshold is therefore opaque, and CompareGE is
// CT-CT at every level, including the root because opaqueOne is supplied as an
// encryption/opaque representation of scalar one.
func EvaluateOBO[T treeplan.Ordered, L treeplan.Ordered, V any](backend Backend[V], tree treeplan.BinaryTree[T, L], features []V, opaqueOne V, policy ComparisonPolicy) (Result[V], error) {
	if err := validateInputs(backend, tree, features, opaqueOne, policy); err != nil {
		return Result[V]{}, err
	}
	engine := &countedBackend[V]{backend: backend}
	weights := []V{opaqueOne}
	engine.observeLive(1, 0)

	for depth := 0; depth < tree.Depth; depth++ {
		width := 1 << depth
		base := width - 1
		splits := tree.Splits[base : base+width]

		selectedFeature, err := selectFeatures(engine, weights, splits, features)
		if err != nil {
			return Result[V]{Counts: engine.counts}, err
		}
		selectedThreshold, err := selectThresholds(engine, weights, splits)
		if err != nil {
			return Result[V]{Counts: engine.counts}, err
		}
		branch, err := engine.compareGE(selectedFeature, selectedThreshold, policy)
		if err != nil {
			return Result[V]{Counts: engine.counts}, err
		}
		engine.observeLive(len(weights), 1)

		// OBO has one selected branch bit. Apply it to every opaque path
		// weight; inactive weights remain zero under multiplication.
		branches := make([]V, width)
		for i := range branches {
			branches[i] = branch
		}
		weights, err = updatePathWeights(engine, weights, branches)
		if err != nil {
			return Result[V]{Counts: engine.counts}, err
		}
		engine.observeLive(len(weights), 0)
	}

	value, err := selectLeaves(engine, weights, tree.Leaves)
	if err != nil {
		return Result[V]{Counts: engine.counts}, err
	}
	if backend.Kind(value) != ValueOpaque {
		return Result[V]{Counts: engine.counts}, fmt.Errorf("%w: final leaf selection is not opaque", ErrBackendProvenance)
	}
	engine.counts.FinalLiveStates = len(weights)
	return Result[V]{Value: value, Counts: engine.counts}, nil
}

// EvaluateFullLevel evaluates every public threshold at every level, then
// obliviously updates path weights. It uses 2^D-1 CT-public comparisons but
// never encrypts/selects a threshold for a single OBO comparison.
func EvaluateFullLevel[T treeplan.Ordered, L treeplan.Ordered, V any](backend Backend[V], tree treeplan.BinaryTree[T, L], features []V, opaqueOne V, policy ComparisonPolicy) (Result[V], error) {
	if err := validateInputs(backend, tree, features, opaqueOne, policy); err != nil {
		return Result[V]{}, err
	}
	engine := &countedBackend[V]{backend: backend}
	weights := []V{opaqueOne}
	engine.observeLive(1, 0)

	for depth := 0; depth < tree.Depth; depth++ {
		width := 1 << depth
		base := width - 1
		branches := make([]V, width)
		for i := 0; i < width; i++ {
			split := tree.Splits[base+i]
			scalar, err := exactPublicScalar(split.Threshold)
			if err != nil {
				return Result[V]{Counts: engine.counts}, err
			}
			threshold, err := engine.public(scalar)
			if err != nil {
				return Result[V]{Counts: engine.counts}, err
			}
			branch, err := engine.compareGE(features[split.Feature], threshold, policy)
			if err != nil {
				return Result[V]{Counts: engine.counts}, err
			}
			branches[i] = branch
		}
		engine.observeLive(len(weights), len(branches))
		var err error
		weights, err = updatePathWeights(engine, weights, branches)
		if err != nil {
			return Result[V]{Counts: engine.counts}, err
		}
		engine.observeLive(len(weights), 0)
	}

	value, err := selectLeaves(engine, weights, tree.Leaves)
	if err != nil {
		return Result[V]{Counts: engine.counts}, err
	}
	if backend.Kind(value) != ValueOpaque {
		return Result[V]{Counts: engine.counts}, fmt.Errorf("%w: final leaf selection is not opaque", ErrBackendProvenance)
	}
	engine.counts.FinalLiveStates = len(weights)
	return Result[V]{Value: value, Counts: engine.counts}, nil
}
