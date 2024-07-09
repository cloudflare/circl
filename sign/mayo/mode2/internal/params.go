// Code generated from params.templ.go. DO NOT EDIT.

package internal

const (
	Mode = "MAYO_2"

	N = 78
	M = 64
	O = 18
	K = 4

	KeySeedSize = 24
	DigestSize  = 32
)

var Tail = [5]uint8{8, 0, 2, 8, 0}

const (
	V = N - O

	// The division by 2 converts the number of nibbles to bytes (when packed together).
	// We don't explicitly round up beause given parameters ensure this will not happen.
	OSize  = V * O / 2                 // O is a V*O matrix of GF(16)
	P1Size = (V * (V + 1) / 2) * M / 2 // P1 consists of M V*V triangular matrices
	P2Size = V * O * M / 2
	P3Size = (O * (O + 1) / 2) * M / 2 // P3 consists of M O*O triangular matrices

	VSize = (V + 1) / 2 // +1 to round up

	SignatureSize = (K*N+1)/2 + SaltSize

	PublicKeySeedSize = 16

	PrivateKeySize = KeySeedSize
	PublicKeySize  = PublicKeySeedSize + P3Size

	SaltSize = KeySeedSize

	// P denotes the number of uint64 words required to fit M GF16 elements
	P = M / 16
)
