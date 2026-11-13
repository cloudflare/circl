package pki_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/schemes"
)

// Example id-slh-dsa-sha2-128s keys from RFC 9909, Appendix C.1 and C.2.
const (
	rfc9909PublicKey = `-----BEGIN PUBLIC KEY-----
MDAwCwYJYIZIAWUDBAMUAyEAK4EJ7Hd8qk4fAkzPz5SX2ZGAUJKA9CVq8rB6+AKJ
tJQ=
-----END PUBLIC KEY-----
`
	rfc9909PrivateKey = `-----BEGIN PRIVATE KEY-----
MFICAQAwCwYJYIZIAWUDBAMUBECiJjvKRYYINlIxYASVI9YhZ3+tkNUetgZ6Mn4N
HmSlASuBCex3fKpOHwJMz8+Ul9mRgFCSgPQlavKwevgCibSU
-----END PRIVATE KEY-----
`
)

func TestSLHDSAOid(t *testing.T) {
	// RFC 9909, Section 3.
	for name, want := range map[string]string{
		"SLH-DSA-SHA2-128s":  "2.16.840.1.101.3.4.3.20",
		"SLH-DSA-SHA2-128f":  "2.16.840.1.101.3.4.3.21",
		"SLH-DSA-SHA2-192s":  "2.16.840.1.101.3.4.3.22",
		"SLH-DSA-SHA2-192f":  "2.16.840.1.101.3.4.3.23",
		"SLH-DSA-SHA2-256s":  "2.16.840.1.101.3.4.3.24",
		"SLH-DSA-SHA2-256f":  "2.16.840.1.101.3.4.3.25",
		"SLH-DSA-SHAKE-128s": "2.16.840.1.101.3.4.3.26",
		"SLH-DSA-SHAKE-128f": "2.16.840.1.101.3.4.3.27",
		"SLH-DSA-SHAKE-192s": "2.16.840.1.101.3.4.3.28",
		"SLH-DSA-SHAKE-192f": "2.16.840.1.101.3.4.3.29",
		"SLH-DSA-SHAKE-256s": "2.16.840.1.101.3.4.3.30",
		"SLH-DSA-SHAKE-256f": "2.16.840.1.101.3.4.3.31",
	} {
		t.Run(name, func(t *testing.T) {
			scheme := schemes.ByName(name)
			if scheme == nil {
				t.Fatalf("%s is not registered", name)
			}
			cert, ok := scheme.(pki.CertificateScheme)
			if !ok {
				t.Fatalf("%s has no object identifier", name)
			}
			oid := cert.Oid()
			if oid.String() != want {
				t.Fatalf("got OID %s, want %s", oid, want)
			}
			if got := pki.SchemeByOid(oid); got == nil || got.Name() != name {
				t.Fatalf("SchemeByOid(%s) did not return %s", oid, name)
			}

			pk, sk, err := scheme.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}

			// The parameters must be absent (Sections 3 and 5) and the
			// subjectPublicKey is the raw public key.
			spki, err := pki.MarshalPKIXPublicKey(pk)
			if err != nil {
				t.Fatal(err)
			}
			var pub struct {
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}
			if _, err = asn1.Unmarshal(spki, &pub); err != nil {
				t.Fatal(err)
			}
			if !pub.Algorithm.Algorithm.Equal(oid) {
				t.Fatalf("got algorithm %s, want %s", pub.Algorithm.Algorithm, oid)
			}
			if len(pub.Algorithm.Parameters.FullBytes) != 0 {
				t.Fatal("public key has algorithm parameters")
			}
			rawPk, err := pk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pub.PublicKey.RightAlign(), rawPk) {
				t.Fatal("subjectPublicKey is not the raw public key")
			}

			// The privateKey OCTET STRING holds the raw private key,
			// with no further wrapping (Section 7).
			p8, err := pki.MarshalPKIXPrivateKey(sk)
			if err != nil {
				t.Fatal(err)
			}
			var priv struct {
				Version    int
				Algorithm  pkix.AlgorithmIdentifier
				PrivateKey []byte
			}
			if _, err = asn1.Unmarshal(p8, &priv); err != nil {
				t.Fatal(err)
			}
			if len(priv.Algorithm.Parameters.FullBytes) != 0 {
				t.Fatal("private key has algorithm parameters")
			}
			rawSk, err := sk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(priv.PrivateKey, rawSk) {
				t.Fatal("privateKey is not the raw private key")
			}
			sk2, err := pki.UnmarshalPKIXPrivateKey(p8)
			if err != nil {
				t.Fatal(err)
			}
			if !sk.Equal(sk2) {
				t.Fatal("private key does not round-trip")
			}
		})
	}
}

func TestSLHDSARFC9909Example(t *testing.T) {
	pk, err := pki.UnmarshalPEMPublicKey([]byte(rfc9909PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sk, err := pki.UnmarshalPEMPrivateKey([]byte(rfc9909PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	scheme := pk.Scheme()
	if scheme.Name() != "SLH-DSA-SHA2-128s" {
		t.Fatalf("got scheme %s, want SLH-DSA-SHA2-128s", scheme.Name())
	}
	if !pk.Equal(sk.Public()) {
		t.Fatal("public key does not match the private key")
	}

	// Marshalling must reproduce the RFC encodings byte for byte.
	spki, err := pki.MarshalPKIXPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode([]byte(rfc9909PublicKey)); !bytes.Equal(spki, block.Bytes) {
		t.Fatalf("public key encoding differs from RFC 9909, Appendix C.1:\n%x", spki)
	}
	p8, err := pki.MarshalPKIXPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode([]byte(rfc9909PrivateKey)); !bytes.Equal(p8, block.Bytes) {
		t.Fatalf("private key encoding differs from RFC 9909, Appendix C.2:\n%x", p8)
	}

	msg := []byte("RFC 9909")
	sig := scheme.Sign(sk, msg, nil)
	if !scheme.Verify(pk, msg, sig, nil) {
		t.Fatal("signature by the example private key does not verify")
	}
}
