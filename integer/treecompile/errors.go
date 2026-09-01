package treecompile

import "errors"

var (
	ErrMalformedTree    = errors.New("malformed raw tree")
	ErrCategoricalSplit = errors.New("categorical splits are unsupported")
	ErrDefaultLeft      = errors.New("default-left missing-value routing is unsupported")
	ErrMissingValue     = errors.New("missing feature values are unsupported")
	ErrNonFiniteValue   = errors.New("non-finite numeric values are unsupported")
	ErrModelSemantics   = errors.New("model semantics must be explicit")
	ErrOutputGroup      = errors.New("multi-output tree aggregation is unsupported")
)
