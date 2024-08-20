//go:generate go run gen.go

// dilithium implements the CRYSTALS-Dilithium signature schemes
// as submitted to round3 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
//
// Each of the eight different modes of Dilithium is implemented by a
// subpackage.  For instance, Dilithium2 (the recommended mode)
// can be found in
//
//	github.com/cloudflare/circl/sign/dilithium/mode2
//
// If your choice for mode is fixed compile-time, use the subpackages.
// This package provides a convenient wrapper around all of the subpackages
// so one can be chosen at runtime.
//
// The authors of Dilithium recommend to combine it with a "pre-quantum"
// signature scheme.  The packages
//
//	github.com/cloudflare/circl/sign/eddilithium2
//	github.com/cloudflare/circl/sign/eddilithium3
//
// implement such hybrids of Dilithium2 with Ed25519 respectively and
// Dilithium3 with Ed448.  These packages are a drop in replacements for the
// mode subpackages of this package.
package dilithium
