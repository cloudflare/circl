// Package classicmceliece implements the Classic McEliece key encapsulation
// mechanism (KEM), a conservative, code-based IND-CCA2 KEM built on binary
// Goppa codes.
//
// This is a pure Go port of the Round 4 submission to the NIST Post-Quantum
// Cryptography standardization process, dated 2022-10-23, and is validated
// against the reference implementation and the official Known Answer Test
// (KAT) vectors from that submission:
//
//  https://classic.mceliece.org/
//  Round-4 reference
//  https://classic.mceliece.org/nist/mceliece-20221023.tar.gz
//  https://classic.mceliece.org/nist/mceliece-kat-20221023.tar.gz
//
// The ten parameter sets defined by the submission are provided, each in its
// own sub-package registered with kem/schemes:
//
//	mceliece348864   mceliece348864f
//	mceliece460896   mceliece460896f
//	mceliece6688128  mceliece6688128f
//	mceliece6960119  mceliece6960119f
//	mceliece8192128  mceliece8192128f
//
// The "f" variants use the faster ("fast") key-generation procedure from the
// specification; both variants of a parameter set are interoperable and share
// the same key, ciphertext and shared-secret sizes.
//
// Secret-dependent operations are implemented to run in constant time, and
// invalid ciphertexts are handled by implicit rejection as required by the
// specification rather than by returning an error. Key generation is the
// dominant cost; on amd64 its inner bit-matrix elimination is accelerated with
// AVX-512 or AVX2 (see the internal/matops package), with a constant-time
// pure Go fallback used elsewhere and under the purego build tag.
package classicmceliece
