//go:generate go run gen.go

// Package kyber implements the CRYSTALS-Kyber.CCAKEM IND-CCA2 secure
// key encapsulation mechanism (KEM) as submitted to round 3 of the NIST PQC
// competition and described in
//
//	https://pq-crystals.org/kyber/data/kyber-specification-round3.pdf
//
// The related public key encryption scheme CRYSTALS-Kyber.CPAPKE can be
// found in the package github.com/cloudflare/circl/pke/kyber.
package kyber
