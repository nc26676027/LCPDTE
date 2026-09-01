// Package treeplan defines plaintext decision-tree semantics and HE-oriented
// structural plans. It deliberately contains no encryption code.
//
// BinaryTree is the reference full-binary model. CompileR0 groups g consecutive
// binary levels into radix-2^g supernodes without changing any split, branch
// convention, leaf index, or leaf value. MultiwayTree instead represents an
// explicit interval model and is classified as R1 (model-changing).
//
// Route decisions use the convention value < threshold -> left/lower interval;
// equality therefore enters the right/upper interval. Inputs and thresholds are
// expected to be ordinary finite numeric values. Missing-value policy belongs in
// the caller's model adapter, where it can be made explicit.
package treeplan
