// Package treecompile is the fail-closed adapter from the repository's parsed
// XGBoost arenas to treeplan's explicit plaintext semantics.
//
// It currently supports finite numerical splits, finite inputs, single-output
// additive forests, and explicit base-score/output interpretation. Categorical
// splits, missing values, default-left routing, and multi-output aggregation are
// rejected rather than silently approximated.
package treecompile
