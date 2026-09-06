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

// Schemes without an object identifier, such as Dilithium and SLH-DSA, must
// get an error from the marshal functions rather than a panic.
func TestMarshalSchemeWithoutOid(t *testing.T) {
	n := 0
	for _, scheme := range schemes.All() {
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
