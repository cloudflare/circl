// Copyright (c) 2026 OmniTrust Security LLC. All rights reserved.
// OmniTrust Security LLC's additions and modifications are licensed under the
// Apache License, Version 2.0 (see LICENSE-APACHE).
// Existing third-party code remains under its original terms (see LICENSE).

package pki_test

import (
	"crypto"
	"io"
	"strings"
	"testing"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// Embedding only sign.Scheme deliberately hides the underlying scheme's Oid method.
type schemeWithoutOID struct{ sign.Scheme }

type publicKeyWithoutOID struct{ sign.PublicKey }

type privateKeyWithoutOID struct{ sign.PrivateKey }

func (k publicKeyWithoutOID) Scheme() sign.Scheme  { return schemeWithoutOID{k.PublicKey.Scheme()} }
func (k privateKeyWithoutOID) Scheme() sign.Scheme { return schemeWithoutOID{k.PrivateKey.Scheme()} }

func (s schemeWithoutOID) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	pk, sk, err := s.Scheme.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return publicKeyWithoutOID{pk}, privateKeyWithoutOID{sk}, nil
}

// Schemes without an object identifier must get an error rather than a panic.
func TestMarshalSchemeWithoutOid(t *testing.T) {
	n := 0
	for _, scheme := range append(schemes.All(), schemeWithoutOID{schemes.ByName("ML-DSA-44")}) {
		if _, ok := scheme.(pki.CertificateScheme); ok {
			continue
		}
		n++
		t.Run(scheme.Name(), func(t *testing.T) {
			pk, sk, err := scheme.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			for name, call := range map[string]func() ([]byte, error){
				"MarshalPKIXPublicKey":  func() ([]byte, error) { return pki.MarshalPKIXPublicKey(pk) },
				"MarshalPEMPublicKey":   func() ([]byte, error) { return pki.MarshalPEMPublicKey(pk) },
				"MarshalPKIXPrivateKey": func() ([]byte, error) { return pki.MarshalPKIXPrivateKey(sk) },
				"MarshalPEMPrivateKey":  func() ([]byte, error) { return pki.MarshalPEMPrivateKey(sk) },
			} {
				out, err := call()
				if err == nil {
					t.Fatalf("%s: got no error and %d bytes, want an error", name, len(out))
				}
				if !strings.Contains(err.Error(), "object identifier") {
					t.Fatalf("%s: got error %q, want it to name the missing object identifier", name, err)
				}
			}
		})
	}
	if n == 0 {
		t.Fatal("no registered scheme lacks an object identifier; this test covers nothing")
	}
}

// unseededKey reports an ML-DSA scheme but does not implement sign.Seeded.
type unseededKey struct{ scheme sign.Scheme }

func (k unseededKey) Scheme() sign.Scheme            { return k.scheme }
func (k unseededKey) Equal(crypto.PrivateKey) bool   { return false }
func (k unseededKey) Public() crypto.PublicKey       { return nil }
func (k unseededKey) MarshalBinary() ([]byte, error) { return []byte{0}, nil }
func (k unseededKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestMarshalMLDSAPrivateKeyWithoutSeed(t *testing.T) {
	scheme := schemes.ByName("ML-DSA-44")
	if scheme == nil {
		t.Fatal("ML-DSA-44 is not registered")
	}
	if _, err := pki.MarshalPKIXPrivateKey(unseededKey{scheme}); err == nil {
		t.Fatal("got no error for an ML-DSA private key that carries no seed")
	}
}
