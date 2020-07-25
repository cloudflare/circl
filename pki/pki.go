package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/api"
)

var allSchemesByOID map[string]sign.Scheme
var allSchemesByTLS map[uint]sign.Scheme

func init() {
	allSchemesByOID = make(map[string]sign.Scheme)
	for _, scheme := range api.AllSchemes() {
		if cert, ok := scheme.(CertificateScheme); ok {
			allSchemesByOID[cert.Oid().String()] = scheme
		}
	}

	allSchemesByTLS = make(map[uint]sign.Scheme)
	for _, scheme := range api.AllSchemes() {
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
		return nil, errors.New("trailing")
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

	return UnmarshalPKIXPrivateKey(block.Bytes)
}

func UnmarshalPKIXPrivateKey(data []byte) (sign.PrivateKey, error) {
	var pkix struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
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
		Type:  fmt.Sprintf("%s PUBLIC KEY", pk.Scheme().Name()),
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
		Type:  fmt.Sprintf("%s PRIVATE KEY", sk.Scheme().Name()),
		Bytes: data,
	},
	)
	return str, nil
}

func MarshalPKIXPrivateKey(sk sign.PrivateKey) ([]byte, error) {
	data, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	data, err = asn1.Marshal(data)
	if err != nil {
		return nil, err
	}

	scheme := sk.Scheme()
	return asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		0,
		pkix.AlgorithmIdentifier{
			Algorithm: scheme.(CertificateScheme).Oid(),
		},
		data,
	})
}
