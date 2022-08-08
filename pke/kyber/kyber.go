//go:generate go run gen.go

// Package kyber implements the CRYSTALS-Kyber.CPAPKE public key encrpyption
// as submitted to round 3 of the NIST PQC competition and described in
//
//	https://pq-crystals.org/kyber/data/kyber-specification-round3.pdf
//
// The related key encapsulation mechanism (KEM) CRYSTALS-Kyber.CCAKEM can
// be found in the package github.com/cloudflare/circl/kem/kyber.
package kyber
