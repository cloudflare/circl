//go:generate go run gen.go

// Package sike is deprecated, it contains the SIKE key encapsulation mechanism.
//
// # DEPRECATION NOTICE
//
// SIDH and SIKE are deprecated as were shown vulnerable to a key recovery
// attack by Castryck-Decru's paper (https://eprint.iacr.org/2022/975). New
// systems should not rely on this package. This package is frozen.
package sike
