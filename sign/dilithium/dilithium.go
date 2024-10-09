//go:generate go run gen.go

// Deprecated. This package implements Dilithium, an early proposal
// for what is now ML-DSA (FIPS 204). An implementation of ML-DSA
// can be found in sign/mldsa.
//
// Dilithium implements the CRYSTALS-Dilithium signature schemes
// as submitted to round3 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
//
// Each of the three different modes of Dilithium is implemented by a
// subpackage.  For instance, Dilithium2 (the recommended mode)
// can be found in
//
//	github.com/cloudflare/circl/sign/dilithium/mode2
//
// If your choice for mode is fixed compile-time, use the subpackages.
// To choose a scheme at runtime, use the generic signatures API under
//
//	github.com/cloudflare/circl/sign/schemes
//
// The packages
//
//	github.com/cloudflare/circl/sign/eddilithium2
//	github.com/cloudflare/circl/sign/eddilithium3
//
// implement hybrids of Dilithium2 with Ed25519 respectively and
// Dilithium3 with Ed448.  These packages are a drop in replacements for the
// mode subpackages of this package.
package dilithium
