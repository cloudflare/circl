// Package blindsign provides a blind signature protocol.
//
// A blind signature protocol is a two-party protocol for computing
// a digital signature. One party (the server) holds the signing key,
// and the other (the client) holds the message input. Blindness
// ensures that the server does not learn anything about the client's
// input during the BlindSign step.
package blindsign

import "io"

// A Verifier represents a specific instance of a blind signature verifier.
type Verifier interface {
	// Blind produces an encoded protocol message and VerifierState based on
	// the input message and Signer's public key.
	Blind(random io.Reader, message []byte) ([]byte, VerifierState, error)

	// Verify verifies a (message, signature) pair over and produces an error
	// if the signature is invalid.
	Verify(message, signature []byte) error
}

// A VerifierState represents the protocol state used to run and complete a
// specific blind signature protocol.
type VerifierState interface {
	// Finalize completes the blind signature protocol and produces a signature
	// over the corresponding Verifier-provided message.
	Finalize(data []byte) ([]byte, error)

	// CopyBlind returns an encoding of the blind value used in the protocol.
	CopyBlind() []byte

	// CopySalt returns an encoding of the per-message salt used in the protocol.
	CopySalt() []byte
}

// A Signer represents a specific instance of a blind signature signer.
type Signer interface {
	// Blindly signs the input message using the Signer's private key
	// and produces an encoded blind signature protocol message as output.
	BlindSign(data []byte) ([]byte, error)
}
