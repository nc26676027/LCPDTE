// Package ckksint provides packed modular-integer operations over CKKS.
//
// Context is the ordinary arithmetic entry point. It owns the parameters,
// encoder, encryption/decryption keys, and evaluation keys needed to encrypt,
// add, subtract, negate, and multiply packed Z/(2^n) words. Values are opaque
// and bound to the Context that created them; a detached Lattigo ciphertext is
// available only through the explicit interoperability method.
//
// Functional8 is the compact conversion/tree profile. The canonical Route-B
// entry point returns a split client/server session for one encrypted depth-2
// batch: the client owns encryption and decryption state, while the server owns
// the installed evaluator.
//
// The Demo constructors use deliberately small functional parameters.
// Applications that supply their own parameter tuple label its boundary
// explicitly.
package ckksint
