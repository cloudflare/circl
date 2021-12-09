// Package blindsign provides a blind signature protocol.
//
// A blind signature protocol is a two-party protocol for computing
// a digital signature. One party (the server) holds the signing key,
// and the other (the client) holds the message input. Blindness
// ensures that the server does not learn anything about the client's
// input during the BlindSign step.
package blindsign

// A Verifier represents a specific instance of a blind signature verifier.
type Verifier interface {
	// Blind produces an encoded protocol message and VerifierState based on
	// the input message and Signer's public key.
	Blind(message []byte) ([]byte, VerifierState, error)
}

// A VerifierState represents the protocol state used to run and complete a
// specific blind signature protocol.
type VerifierState interface {
	// Finalize completes the blind signature protocol and produces a signature
	// over the corresponding Verifier-provided message.
	Finalize(data []byte) ([]byte, error)
}

// A Signer represents a specific instance of a blind signature signer.
type Signer interface {
	// Blindly signs the input message using the Signer's private key
	// and produces an encoded blind signature protocol message as output.
	BlindSign(data []byte) ([]byte, error)
}
