package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	allSchemesByOID map[string]sign.Scheme
	allSchemesByTLS map[uint]sign.Scheme
)

type pkixPrivKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func init() {
	allSchemesByOID = make(map[string]sign.Scheme)
	allSchemesByTLS = make(map[uint]sign.Scheme)
	for _, scheme := range schemes.All() {
		if cert, ok := scheme.(CertificateScheme); ok {
			allSchemesByOID[cert.Oid().String()] = scheme
		}
		if tlsScheme, ok := scheme.(TLSScheme); ok {
			allSchemesByTLS[tlsScheme.TLSIdentifier()] = scheme
		}
	}
}

func SchemeByOid(oid asn1.ObjectIdentifier) sign.Scheme { return allSchemesByOID[oid.String()] }

func SchemeByTLSID(id uint) sign.Scheme { return allSchemesByTLS[id] }

// Additional methods when the signature scheme is supported in X509.
type CertificateScheme interface {
	// Return the appropriate OIDs for this instance.  It is implicitly
	// assumed that the encoding is simple: e.g. uses the same OID for
	// signature and public key like Ed25519.
	Oid() asn1.ObjectIdentifier
}

// Additional methods when the signature scheme is supported in TLS.
type TLSScheme interface {
	TLSIdentifier() uint
}

func UnmarshalPEMPublicKey(data []byte) (sign.PublicKey, error) {
	block, rest := pem.Decode(data)
	if len(rest) != 0 {
		return nil, errors.New("trailing data")
	}
	if !strings.HasSuffix(block.Type, "PUBLIC KEY") {
		return nil, errors.New("pem block type is not public key")
	}

	return UnmarshalPKIXPublicKey(block.Bytes)
}

func UnmarshalPKIXPublicKey(data []byte) (sign.PublicKey, error) {
	var pkix struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(data, &pkix); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("trailing data")
	}
	scheme := SchemeByOid(pkix.Algorithm.Algorithm)
	if scheme == nil {
		return nil, errors.New("unsupported public key algorithm")
	}
	return scheme.UnmarshalBinaryPublicKey(pkix.PublicKey.RightAlign())
}

func UnmarshalPEMPrivateKey(data []byte) (sign.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if len(rest) != 0 {
		return nil, errors.New("trailing")
	}
	if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errors.New("pem block type is not private key")
	}

	return UnmarshalPKIXPrivateKey(block.Bytes)
}

func isMLDSA(scheme sign.Scheme) bool {
	name := scheme.Name()
	return name == "ML-DSA-44" || name == "ML-DSA-65" || name == "ML-DSA-87"
}

func UnmarshalPKIXPrivateKey(data []byte) (sign.PrivateKey, error) {
	var pkix pkixPrivKey
	if rest, err := asn1.Unmarshal(data, &pkix); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("trailing data")
	}
	scheme := SchemeByOid(pkix.Algorithm.Algorithm)
	if scheme == nil {
		return nil, errors.New("unsupported public key algorithm")
	}

	// ML-DSA unfortunately has a complex private key format, which we
	// handle here separately. If future schemes require custom parsing
	// as well, we can introduce an interface for that.
	if isMLDSA(scheme) {
		// Handle case of seed-only private key
		ss := cryptobyte.String(pkix.PrivateKey)
		tag := casn1.Tag(0).ContextSpecific()
		if ss.PeekASN1Tag(tag) {
			var ss2 cryptobyte.String
			if !ss.ReadASN1(&ss2, tag) {
				return nil, errors.New("truncated seed")
			}
			if !ss.Empty() {
				return nil, errors.New("trailing data")
			}
			if len(ss2) != scheme.SeedSize() {
				return nil, errors.New("incorrect seed size")
			}
			_, sk := scheme.DeriveKey(ss2)
			return sk, nil
		}

		// We don't support expanded-only private keys, so the only remaining
		// option is a SEQUENCE of both seed and expanded private key.
		if ss.PeekASN1Tag(casn1.OCTET_STRING) {
			return nil, errors.New("require seed in private key")
		}

		var both struct {
			Seed     []byte
			Expanded []byte
		}
		if rest, err := asn1.Unmarshal(pkix.PrivateKey, &both); err != nil {
			return nil, err
		} else if len(rest) > 0 {
			return nil, errors.New("trailing data")
		}
		if len(both.Seed) != scheme.SeedSize() {
			return nil, errors.New("incorrect seed size")
		}
		_, sk := scheme.DeriveKey(both.Seed)
		sk2, err := scheme.UnmarshalBinaryPrivateKey(both.Expanded)
		if err != nil {
			return nil, err
		}
		if !sk2.Equal(sk) {
			return nil, errors.New("mismatching seed and expanded private key")
		}
		return sk, nil
	}

	var sk []byte
	if rest, err := asn1.Unmarshal(pkix.PrivateKey, &sk); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("trailing data")
	}
	return scheme.UnmarshalBinaryPrivateKey(sk)
}

func MarshalPEMPublicKey(pk sign.PublicKey) ([]byte, error) {
	data, err := MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	str := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	})
	return str, nil
}

func MarshalPKIXPublicKey(pk sign.PublicKey) ([]byte, error) {
	data, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	scheme := pk.Scheme()
	return asn1.Marshal(struct {
		pkix.AlgorithmIdentifier
		asn1.BitString
	}{
		pkix.AlgorithmIdentifier{
			Algorithm: scheme.(CertificateScheme).Oid(),
		},
		asn1.BitString{
			Bytes:     data,
			BitLength: len(data) * 8,
		},
	})
}

func MarshalPEMPrivateKey(sk sign.PrivateKey) ([]byte, error) {
	data, err := MarshalPKIXPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	str := pem.EncodeToMemory(&pem.Block{
		Type:  sk.Scheme().Name() + " PRIVATE KEY",
		Bytes: data,
	},
	)
	return str, nil
}

func MarshalPKIXPrivateKey(sk sign.PrivateKey) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	scheme := sk.Scheme()

	// ML-DSA is special. See comment in UnmarshalPKIXPrivateKey().
	if isMLDSA(scheme) {
		seed := sk.(sign.Seeded).Seed()
		if seed == nil {
			return nil, errors.New("seed not retained in ML-DSA private key")
		}
		var b cryptobyte.Builder
		b.AddASN1(casn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes(seed)
		})
		data, err = b.Bytes()
		if err != nil {
			return nil, err
		}
	} else {
		data, err = sk.MarshalBinary()
		if err != nil {
			return nil, err
		}

		data, err = asn1.Marshal(data)
		if err != nil {
			return nil, err
		}
	}

	return asn1.Marshal(pkixPrivKey{
		0,
		pkix.AlgorithmIdentifier{
			Algorithm: scheme.(CertificateScheme).Oid(),
		},
		data,
	})
}
