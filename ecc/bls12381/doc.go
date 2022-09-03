// Package bls12381 provides bilinear pairings using the BLS12-381 curve.
//
// A pairing system consists of three groups G1 and G2 (adiitive notation) and
// Gt (multiplicative notation) of the same order.
// Scalars can be used interchangeably between groups.
//
// These groups have the same order equal to:
//
//	Order = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
//
// # Serialization Format
//
// Elements of G1 and G2 can be encoded in uncompressed form (the x-coordinate
// followed by the y-coordinate) or in compressed form (just the x-coordinate).
// G1 elements occupy 96 bytes in uncompressed form, and 48 bytes in compressed
// form. G2 elements occupy 192 bytes in uncompressed form, and 96 bytes in
// compressed form.
//
// The most-significant three bits of a G1 or G2 encoding should be masked away
// before the coordinates are interpreted. These bits are used to unambiguously
// represent the underlying element:
//
// * The most significant bit, when set, indicates that the point is in
// compressed form. Otherwise, the point is in uncompressed form.
//
// * The second-most significant bit indicates that the point is at infinity.
// If this bit is set, the remaining bits of the group element's encoding
// should be set to zero.
//
// * The third-most significant bit is set if (and only if) this point is in
// compressed form AND it is not the point at infinity AND its y-coordinate
// is the lexicographically largest of the two associated with the encoded
// x-coordinate.
//
//	|----------------------------------------------------|
//	|                Serialization Format                |
//	|-----|-------|-------|---------------|--------------|
//	| MSB | MSB-1 | MSB-2 |  Description  | Encoding     |
//	|-----|-------|-------|---------------|--------------|
//	|  0  |   X   |   X   | Uncompressed  |  e || x || y |
//	|  1  |   X   |   X   | Compressed    |  e || x      |
//	|-----|-------|-------|---------------|--------------|
//	|  X  |   0   |   X   | Non-Infinity  |  e || x || y |
//	|  X  |   1   |   X   | Infinity      |  e || 0 || 0 |
//	|-----|-------|-------|---------------|--------------|
//	|     |       |       | Compressed,   |              |
//	|  1  |   0   |   1   | Non-Infinity, |  e || x      |
//	|     |       |       | Big y-coord   |              |
//	|-----|-------|-------|---------------|--------------|
//	|     |       |       | Compressed,   |              |
//	|  1  |   0   |   0   | Non-Infinity, |  e || x      |
//	|     |       |       | Small y-coord |              |
//	|----------------------------------------------------|
package bls12381
