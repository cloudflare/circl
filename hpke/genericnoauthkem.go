package hpke

// Shim to use generic KEM (kem.Scheme) as HPKE KEM.

import (
	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/kem"
)

// genericNoAuthKEM wraps a generic KEM (kem.Scheme) to be used as a HPKE KEM.
type genericNoAuthKEM struct {
	kem  kem.Scheme
	name string
}

func (h genericNoAuthKEM) PrivateKeySize() int        { return h.kem.PrivateKeySize() }
func (h genericNoAuthKEM) SeedSize() int              { return h.kem.SeedSize() }
func (h genericNoAuthKEM) CiphertextSize() int        { return h.kem.CiphertextSize() }
func (h genericNoAuthKEM) PublicKeySize() int         { return h.kem.PublicKeySize() }
func (h genericNoAuthKEM) EncapsulationSeedSize() int { return h.kem.EncapsulationSeedSize() }
func (h genericNoAuthKEM) SharedKeySize() int         { return h.kem.SharedKeySize() }
func (h genericNoAuthKEM) Name() string               { return h.name }

func (h genericNoAuthKEM) AuthDecapsulate(skR kem.PrivateKey,
	ct []byte,
	pkS kem.PublicKey,
) ([]byte, error) {
	panic("AuthDecapsulate is not supported for this KEM")
}

func (h genericNoAuthKEM) AuthEncapsulate(pkr kem.PublicKey, sks kem.PrivateKey) (
	ct []byte, ss []byte, err error,
) {
	panic("AuthEncapsulate is not supported for this KEM")
}

func (h genericNoAuthKEM) AuthEncapsulateDeterministically(pkr kem.PublicKey, sks kem.PrivateKey, seed []byte) (ct, ss []byte, err error) {
	panic("AuthEncapsulateDeterministically is not supported for this KEM")
}

func (h genericNoAuthKEM) Encapsulate(pkr kem.PublicKey) (
	ct []byte, ss []byte, err error,
) {
	return h.kem.Encapsulate(pkr)
}

func (h genericNoAuthKEM) Decapsulate(skr kem.PrivateKey, ct []byte) ([]byte, error) {
	return h.kem.Decapsulate(skr, ct)
}

func (h genericNoAuthKEM) EncapsulateDeterministically(
	pkr kem.PublicKey, seed []byte,
) (ct, ss []byte, err error) {
	return h.kem.EncapsulateDeterministically(pkr, seed)
}

// HPKE requires DeriveKeyPair() to take any seed larger than the private key
// size, whereas typical KEMs expect a specific seed size. We'll just use
// SHAKE256 to hash it to the right size as in X-Wing.
func (h genericNoAuthKEM) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	seed2 := make([]byte, h.kem.SeedSize())
	hh := sha3.NewShake256()
	_, _ = hh.Write(seed)
	_, _ = hh.Read(seed2)
	return h.kem.DeriveKeyPair(seed2)
}

func (h genericNoAuthKEM) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	return h.kem.GenerateKeyPair()
}

func (h genericNoAuthKEM) UnmarshalBinaryPrivateKey(data []byte) (kem.PrivateKey, error) {
	return h.kem.UnmarshalBinaryPrivateKey(data)
}

func (h genericNoAuthKEM) UnmarshalBinaryPublicKey(data []byte) (kem.PublicKey, error) {
	return h.kem.UnmarshalBinaryPublicKey(data)
}
