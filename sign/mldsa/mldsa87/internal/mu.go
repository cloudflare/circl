// Code generated from mu.templ.go. DO NOT EDIT.

package internal

import "io"

// MPrime writes M′ = 0x00 ‖ len(ctx) ‖ ctx ‖ msg, the message signed by the
// pure variant of ML-DSA-87. ctx must be at most 255 bytes.
func MPrime(msg, ctx []byte) func(io.Writer) {
	return func(w io.Writer) {
		_, _ = w.Write([]byte{0, byte(len(ctx))})
		_, _ = w.Write(ctx)
		_, _ = w.Write(msg)
	}
}

// ComputeMu writes the message representative μ of the message msg with the
// optional context string ctx into mu. ctx must be at most 255 bytes.
func (pk *PublicKey) ComputeMu(msg, ctx []byte, mu *[64]byte) {
	computeMu(&pk.tr, MPrime(msg, ctx), mu)
}

// ComputeMu writes the message representative μ of the message msg with the
// optional context string ctx into mu. ctx must be at most 255 bytes.
func (sk *PrivateKey) ComputeMu(msg, ctx []byte, mu *[64]byte) {
	computeMu(&sk.tr, MPrime(msg, ctx), mu)
}
