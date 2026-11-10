// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package slhdsa

import (
	"crypto/rand"
	"encoding/asn1"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/sign"
)

func (id ID) Scheme() sign.Scheme { return scheme{id.params()} }

type scheme struct{ *params }

func (s scheme) Name() string          { return s.name }
func (s scheme) SeedSize() int         { return s.PrivateKeySize() }
func (s scheme) SupportsContext() bool { return true }

// GenerateKey is similar to [GenerateKey] function, except it always reads
// random bytes from [rand.Reader].
func (s scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(rand.Reader, s.ID)
}

// Sign returns a randomized pure signature of the message with the context
// given.
// If options is nil, an empty context is used.
// It returns an empty slice if the signature generation fails.
//
// Panics if the key is not a [PrivateKey] or when the [ID] mismatches.
func (s scheme) Sign(
	priv sign.PrivateKey, message []byte, options *sign.SignatureOpts,
) []byte {
	k, ok := priv.(PrivateKey)
	if !ok || s.ID != k.ID {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if options != nil {
		context = []byte(options.Context)
	}

	sig, err := SignRandomized(&k, rand.Reader, NewMessage(message), context)
	if err != nil {
		return nil
	}

	return sig
}

// Verify returns true if the signature of the message with the specified
// context is valid.
// If options is nil, an empty context is used.
//
// Panics if the key is not a [PublicKey] or when the [ID] mismatches.
func (s scheme) Verify(
	pub sign.PublicKey, message, signature []byte, options *sign.SignatureOpts,
) bool {
	k, ok := pub.(PublicKey)
	if !ok || s.ID != k.ID {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if options != nil {
		context = []byte(options.Context)
	}

	return Verify(&k, NewMessage(message), signature, context)
}

// DeriveKey deterministically generates a pair of keys from a seed.
//
// Panics if seed is not of length [sign.Scheme.SeedSize].
func (s scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != s.SeedSize() {
		panic(sign.ErrSeedSize)
	}

	n := s.n
	buf := make([]byte, 3*n)
	if s.isSHA2 {
		s.mgf1(buf, seed, 3*n)
	} else {
		sha3.ShakeSum256(buf, seed)
	}

	c := cursor(buf)
	skSeed := c.Next(n)
	skPrf := c.Next(n)
	pkSeed := c.Next(n)

	return slhKeyGenInternal(s.params, skSeed, skPrf, pkSeed)
}

func (s scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	k := PublicKey{ID: s.ID}
	err := k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}

	return k, nil
}

func (s scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	k := PrivateKey{ID: s.ID}
	err := k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}

	return k, nil
}

func (s scheme) Oid() asn1.ObjectIdentifier {
	// https://datatracker.ietf.org/doc/html/rfc9814
	// base OID for sigAlgs (2.16.840.1.101.3.4.3)
	baseOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3}

	// clone the base OID and append a parameter-specific digit
	oid := make(asn1.ObjectIdentifier, len(baseOID)+1)
	copy(oid, baseOID)

	// add the parameter-specific digit based on the ID
	switch s.ID {
	case SHA2_128s:
		oid[len(baseOID)] = 20 // 2.16.840.1.101.3.4.3.20
	case SHA2_128f:
		oid[len(baseOID)] = 21 // 2.16.840.1.101.3.4.3.21
	case SHA2_192s:
		oid[len(baseOID)] = 22 // 2.16.840.1.101.3.4.3.22
	case SHA2_192f:
		oid[len(baseOID)] = 23 // 2.16.840.1.101.3.4.3.23
	case SHA2_256s:
		oid[len(baseOID)] = 24 // 2.16.840.1.101.3.4.3.24
	case SHA2_256f:
		oid[len(baseOID)] = 25 // 2.16.840.1.101.3.4.3.25
	case SHAKE_128s:
		oid[len(baseOID)] = 26 // 2.16.840.1.101.3.4.3.26
	case SHAKE_128f:
		oid[len(baseOID)] = 27 // 2.16.840.1.101.3.4.3.27
	case SHAKE_192s:
		oid[len(baseOID)] = 28 // 2.16.840.1.101.3.4.3.28
	case SHAKE_192f:
		oid[len(baseOID)] = 29 // 2.16.840.1.101.3.4.3.29
	case SHAKE_256s:
		oid[len(baseOID)] = 30 // 2.16.840.1.101.3.4.3.30
	case SHAKE_256f:
		oid[len(baseOID)] = 31 // 2.16.840.1.101.3.4.3.31
	default:
		// for invalid schemes, return the base sigAlgs
		return baseOID
	}

	return oid
}
