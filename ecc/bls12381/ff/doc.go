// Package ff provides finite fields and groups useful for the BLS12-381 curve.
//
// # Fp
//
// Fp are elements of the prime field GF(p), where
//
//	p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
//
// The binary representation takes FpSize = 48 bytes encoded in big-endian form.
//
// # Fp2
//
// Fp2 are elements of the finite field GF(p^2) = Fp[u]/(u^2+1) represented as
//
//	(a[1]u + a[0]) in Fp2, where a[0],a[1] in Fp
//
// The binary representation takes Fp2Size = 96 bytes encoded as a[1] || a[0]
// all in big-endian form.
//
// # Fp4
//
// Fp4 is GF(p^4)=Fp2[t]/(t^2-(u+1)). We use the repesentation  a[1]v+a[0].
// There is no fixed external form.
//
// # Fp6
//
// Fp6 are elements of the finite field GF(p^6) = Fp2[v]/(v^3-u-1) represented as
//
//	(a[2]v^2 + a[1]v + a[0]) in Fp6, where a[0],a[1],a[2] in Fp2
//
// The binary representation takes Fp6Size = 288 bytes encoded as a[2] || a[1] || a[0]
// all in big-endian form.
//
// # Fp12
//
// Fp12 are elements of the finite field GF(p^12) = Fp6[w]/(w^2-v) represented as
//
//	(a[1]w + a[0]) in Fp12, where a[0],a[1] in Fp6
//
// The binary representation takes Fp12Size = 576 bytes encoded as a[1] || a[0]
// all in big-endian form.
//
// We can also represent this field via Fp4[w]/(w^3-t). This is the struct Fp12alt,
// used to accelerate the pairing calculation.
//
// # Scalar
//
// Scalar are elements of the prime field GF(r), where
//
//	r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
//
// The binary representation takes ScalarSize = 32 bytes encoded in big-endian form.
//
// # Groups
//
// Cyclo6 are elements of the 6th cyclotomic group contained in Fp12.
// For efficient arithmetic see Granger-Scott "Faster Squaring in the Cyclotomic Subgroup of Sixth
// Degree Extensions" (https://eprint.iacr.org/2009/565).
//
// URoot are elements of the r-roots of unity group contained in Fp12.
package ff
