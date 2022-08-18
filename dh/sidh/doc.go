// Package sidh is deprecated, it provides SIDH and SIKE key encapsulation
// mechanisms.
//
// # DEPRECATION NOTICE
//
// SIDH and SIKE are deprecated as were shown vulnerable to a key recovery
// attack by Castryck-Decru's paper (https://eprint.iacr.org/2022/975). New
// systems should not rely on this package. This package is frozen.
//
// # SIDH and SIKE
//
// This package provides implementation of experimental post-quantum
// Supersingular Isogeny Diffie-Hellman (SIDH) as well as Supersingular
// Isogeny Key Encapsulation (SIKE).
//
// It comes with implementations of three different field arithmetic
// implementations sidh.Fp434, sidh.Fp503, and sidh.Fp751.
//
//	| Algorithm | Public Key Size | Shared Secret Size | Ciphertext Size |
//	|-----------|-----------------|--------------------|-----------------|
//	| SIDH/p434 |          330    |        110         |       N/A       |
//	| SIDH/p503 |          378    |        126         |       N/A       |
//	| SIDH/p751 |          564    |        188         |       N/A       |
//	| SIKE/p434 |          330    |         16         |       346       |
//	| SIKE/p503 |          378    |         24         |       402       |
//	| SIKE/p751 |          564    |         32         |       596       |
//
// In order to instantiate SIKE/p751 KEM one needs to create a KEM object
// and allocate internal structures. This can be done with NewSike751 helper.
// After that, the kem variable can be used multiple times.
//
//	var kem = sike.NewSike751(rand.Reader)
//	kem.Encapsulate(ciphertext, sharedSecret, publicBob)
//	kem.Decapsulate(sharedSecret, privateBob, publicBob, ciphertext)
//
// Code is optimized for AMD64 and aarch64. Generic implementation
// is provided for other architectures.
//
// References:
//
//   - [SIDH] https://eprint.iacr.org/2011/506
//   - [SIKE] http://www.sike.org/files/SIDH-spec.pdf
package sidh
