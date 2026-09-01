// Package treeeval defines backend-neutral oblivious decision-tree evaluation.
// It keeps public/opaque provenance explicit so implementations cannot hide a
// CT-CT comparison behind a generic numeric API. Integer constants retain exact
// bits, width, and signedness, and every comparison requires a range/overflow
// policy.
package treeeval
