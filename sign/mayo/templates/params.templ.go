// +build ignore
// The previous line (and this one up to the warning below) is removed by the
// template generator.

// Code generated from params.templ.go. DO NOT EDIT.

package internal

const (
	Mode = "{{.Name}}"

	N = {{.N}}
	M = {{.M}}
	O = {{.O}}
	K = {{.K}}

	KeySeedSize = {{.KeySeedSize}}
	DigestSize  = {{.DigestSize}}
)

var Tail = [5]uint8{ {{index .Tail 0}}, {{index .Tail 1}}, {{index .Tail 2}}, {{index .Tail 3}}, {{index .Tail 4}} }

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
