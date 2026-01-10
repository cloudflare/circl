// Package bbs provides an implementation of the BBS signature scheme.
//
// # Signing
//
// Unlike other signature schemes, BBS allows to sign multiple messages at once.
// Verification works as usual but it is sensitive to the order in which
// the messages are signed.
//
// # Proof of Knowledge of a Signature
//
// Anyone with a valid signature (over a set of messages) can generate a proof
// that attests knowledge of the signature.
// Proof verification works as usual but it is sensitive to the order in which
// the messages are processed.
//
// # Message Disclosure
//
// The prover can conceal some of the messages, while disclosing the others.
// For verification, only the disclosed messages are necessary to validate
// the proof.
//
// # Specification
//
// This package is compliant with draft-irtf-cfrg-bbs-signatures [v08].
//
// [v08] https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-08
package bbs
