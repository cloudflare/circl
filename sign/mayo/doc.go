//go:generate go run gen.go

// Package mayo implements the MAYO signature scheme
// as submitted to round1 of the NIST PQC competition of Additional Signature Scehemes and described in
//
//	https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/mayo-spec-web.pdf
//
// This implemented the nibble-sliced version as proposed in
//
//	https://eprint.iacr.org/2023/1683
package mayo
