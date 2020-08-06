//go:generate go run gen.go

// Package kyber implements the CRYSTALS-Kyber.CPAPKE public key encrpyption
// as submitted to round 2 of the NIST PQC competition and described in
//
// 	https://pq-crystals.org/kyber/data/kyber-specification-round2.pdf
//
// The related key encapsulation mechanism (KEM) CRYSTALS-Kyber.CCAKEM can
// be found in the package github.com/cloudflare/circl/kem/kyber.
package kyber
