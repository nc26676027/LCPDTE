// Package ckksint provides packed modular-integer operations over CKKS.
//
// Context is the ordinary arithmetic entry point. It owns the parameters,
// encoder, encryption/decryption keys, and evaluation keys needed to encrypt,
// add, subtract, negate, and multiply packed Z/(2^n) words. Values are opaque
// and bound to the Context that created them; a detached Lattigo ciphertext is
// available only through the explicit interoperability method.
//
// The Demo constructors use deliberately small functional parameters and make
// no security claim. Applications that supply their own parameter tuple must
// label its security boundary explicitly.
package ckksint
