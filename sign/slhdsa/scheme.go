package slhdsa

import (
	"crypto/rand"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/sign"
)

type scheme struct{ ParamID }

func (id ParamID) Scheme() sign.Scheme { return scheme{id} }

// GenerateKey is similar to [GenerateKey] function, except it always reads
// random bytes from [rand.Reader].
func (s scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(rand.Reader, s.ParamID)
}

// [ParamID.Sign] returns a randomized signature of the message with the
// specified options.
// This function never pre-hashes the message and uses the context provided
// in options. If options is nil, an empty context is used.
// It returns an empty slice if it fails reading from the random source.
//
// Panics if the key is not a [PrivateKey] or mismatches with the ParamID.
func (s scheme) Sign(
	key sign.PrivateKey, message []byte, options *sign.SignatureOpts,
) []byte {
	var sigOps Options
	if options != nil {
		sigOps.Context = []byte(options.Context)
	}

	signature, err := key.Sign(rand.Reader, message, sigOps)
	if err != nil {
		return nil
	}

	return signature
}

// [Verify] returns true if the signature of the message with the specified
// context is valid.
// This function never pre-hashes the message and uses the context provided
// in options. If options is nil, an empty context is used.
//
// Panics if the key is not a [*PublicKey] or mismatches with the ParamID.
func (s scheme) Verify(
	key sign.PublicKey, message, signature []byte, options *sign.SignatureOpts,
) bool {
	k, ok := key.(PublicKey)
	if !ok || s.ParamID != k.ParamID {
		panic(sign.ErrTypeMismatch)
	}

	var sigOps Options
	if options != nil {
		sigOps.Context = []byte(options.Context)
	}

	msg := NewMessage(message)
	return Verify(&k, &msg, signature, &sigOps)
}

// Deterministically derives a pair of keys from a seed. If you're unsure,
// you're better off using [GenerateKey] function.
//
// Panics if seed is not of length [ParamID.SeedSize].
func (s scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	params := s.ParamID.params()
	if len(seed) != s.SeedSize() {
		panic(sign.ErrSeedSize)
	}

	n := params.n
	buf := make([]byte, 3*n)
	if params.isSHA2 {
		params.mgf1(buf, seed, 3*n)
	} else {
		sha3.ShakeSum256(buf, seed)
	}

	c := cursor(buf)
	skSeed := c.Next(n)
	skPrf := c.Next(n)
	pkSeed := c.Next(n)

	return slhKeyGenInternal(params, skSeed, skPrf, pkSeed)
}

func (s scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	k := PublicKey{ParamID: s.ParamID}
	err := k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (s scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	k := PrivateKey{ParamID: s.ParamID}
	err := k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (s scheme) Name() string          { return s.String() }
func (s scheme) PublicKeySize() int    { return int(s.params().PublicKeySize()) }
func (s scheme) PrivateKeySize() int   { return int(s.params().PrivateKeySize()) }
func (s scheme) SignatureSize() int    { return int(s.params().SignatureSize()) }
func (s scheme) SeedSize() int         { return s.PrivateKeySize() }
func (s scheme) SupportsContext() bool { return true }
