package hpke

// Shim to use generic KEM (kem.Scheme) as HPKE KEM.

import (
	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/kem"
)

type otherKEM struct {
	kem  kem.Scheme
	name string
}

func (h otherKEM) PrivateKeySize() int        { return h.kem.PrivateKeySize() }
func (h otherKEM) SeedSize() int              { return h.kem.SeedSize() }
func (h otherKEM) CiphertextSize() int        { return h.kem.CiphertextSize() }
func (h otherKEM) PublicKeySize() int         { return h.kem.PublicKeySize() }
func (h otherKEM) EncapsulationSeedSize() int { return h.kem.EncapsulationSeedSize() }
func (h otherKEM) SharedKeySize() int         { return h.kem.SharedKeySize() }
func (h otherKEM) Name() string               { return h.name }

func (h otherKEM) AuthDecapsulate(skR kem.PrivateKey,
	ct []byte,
	pkS kem.PublicKey,
) ([]byte, error) {
	panic("AuthDecapsulate is not supported for this KEM")
}

func (h otherKEM) AuthEncapsulate(pkr kem.PublicKey, sks kem.PrivateKey) (
	ct []byte, ss []byte, err error,
) {
	panic("AuthEncapsulate is not supported for this KEM")
}

func (h otherKEM) AuthEncapsulateDeterministically(pkr kem.PublicKey, sks kem.PrivateKey, seed []byte) (ct, ss []byte, err error) {
	panic("AuthEncapsulateDeterministically is not supported for this KEM")
}

func (h otherKEM) Encapsulate(pkr kem.PublicKey) (
	ct []byte, ss []byte, err error,
) {
	return h.kem.Encapsulate(pkr)
}

func (h otherKEM) Decapsulate(skr kem.PrivateKey, ct []byte) ([]byte, error) {
	return h.kem.Decapsulate(skr, ct)
}

func (h otherKEM) EncapsulateDeterministically(
	pkr kem.PublicKey, seed []byte,
) (ct, ss []byte, err error) {
	return h.kem.EncapsulateDeterministically(pkr, seed)
}

// HPKE requires DeriveKeyPair() to take any seed larger than the private key
// size, whereas typical KEMs expect a specific seed size. We'll just use
// SHAKE256 to hash it to the right size as in X-Wing.
func (h otherKEM) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	seed2 := make([]byte, h.kem.SeedSize())
	hh := sha3.NewShake256()
	_, _ = hh.Write(seed)
	_, _ = hh.Read(seed2)
	return h.kem.DeriveKeyPair(seed2)
}

func (h otherKEM) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	return h.kem.GenerateKeyPair()
}

func (h otherKEM) UnmarshalBinaryPrivateKey(data []byte) (kem.PrivateKey, error) {
	return h.kem.UnmarshalBinaryPrivateKey(data)
}

func (h otherKEM) UnmarshalBinaryPublicKey(data []byte) (kem.PublicKey, error) {
	return h.kem.UnmarshalBinaryPublicKey(data)
}
