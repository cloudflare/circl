// Package csidh implements commutative supersingular isogeny-based Diffie-Hellman
// key exchange algorithm (CSIDH) resulting from the group action. Implementation
// uses prime field of a size 512-bits.
// This implementation is highly experimental work and currently it is not suitable
// for securing systems.
//
// References:
//   - cSIDH:        ia.cr/2018/383
//   - Faster cSIDH: ia.cr/2018/782
package csidh
