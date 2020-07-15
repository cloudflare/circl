// package sign provides a unified interface to all signature schemes
// supported by Circl.
package sign

import (
	"bytes"
	"crypto"
	"encoding"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"crypto/x509/pkix"
)

var schemes = [...]Scheme{
	EdDilithium3,
}

type SignatureOpts struct {
	// If non-empty, includes the given context in the signature if supported
	// and will cause an error during signing otherwise.
	Context string
}

// A public key is used to verify a signature set by the corresponding private
// key.
type PublicKey interface {
	// Returns the signature scheme for this public key.
	Scheme() Scheme

	encoding.BinaryMarshaler
}

// A private key allows one to create signatures.
type PrivateKey interface {
	// Returns the signature scheme for this private key.
	Scheme() Scheme

	// For compatibility with Go standard library
	crypto.Signer

	encoding.BinaryMarshaler
}

// A Scheme represents a specific instance of a signature scheme.
type Scheme interface {
	// GenerateKey creates a new key-pair.
	GenerateKey() (PublicKey, PrivateKey, error)

	// Creates a signature using the PrivateKey on the given message and
	// returns the signature. opts are additional options which can be nil.
	Sign(sk PrivateKey, message []byte, opts *SignatureOpts) []byte

	// Checks whether the given signature is a valid signature set by
	// the private key corresponding to the given public key on the
	// given message. opts are additional options which can be nil.
	Verify(pk PublicKey, message []byte, signature []byte, opts *SignatureOpts) bool

	// Deterministically derives a keypair from a seed.  If you're unsure,
	// you're better off using GenerateKey().
	//
	// Panics if seed is not of length SeedSize().
	DeriveKey(seed []byte) (PublicKey, PrivateKey)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)

	// Size of binary marshalled public keys
	PublicKeySize() uint

	// Size of binary marshalled public keys
	PrivateKeySize() uint

	// Name of the scheme
	Name() string

	// Size of signatures
	SignatureSize() uint

	// Size of seeds
	SeedSize() uint
}

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

// SchemeByName returns the scheme with the given name and nil if it is not
// supported.  Use ListSchemes() to list supported schemes.
// Names are case insensitive.
func SchemeByName(name string) Scheme {
	// XXX add a (compile time?) lookup table
	name = strings.ToLower(name)
	for _, scheme := range schemes {
		if strings.ToLower(scheme.Name()) == name {
			return scheme
		}
	}
	return nil
}

// ListSchemeNames returns the names of all schemes supported.
func ListSchemeNames() []string {
	ret := []string{}
	for _, scheme := range schemes {
		ret = append(ret, scheme.Name())
	}
	return ret
}

func SchemeByOid(oid asn1.ObjectIdentifier) Scheme {
	// XXX add a (compile time?) lookup table
	for _, scheme := range schemes {
		certScheme, ok := scheme.(CertificateScheme)
		if !ok {
			continue
		}
		if certScheme.Oid().Equal(oid) {
			return scheme
		}
	}
	return nil
}

func SchemeByTLSIdentifier(id uint) Scheme {
	// XXX add a (compile time?) lookup table
	for _, scheme := range schemes {
		tlsScheme, ok := scheme.(TLSScheme)
		if !ok {
			continue
		}
		if tlsScheme.TLSIdentifier() == id {
			return scheme
		}
	}
	return nil
}

func UnmarshalPEMPublicKey(data []byte) (PublicKey, error) {
	block, rest := pem.Decode(data)
	if len(rest) != 0 {
		return nil, errors.New("trailing")
	}

	pk, err := UnmarshalPKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func MarshalPEMPublicKey(pk PublicKey) ([]byte, error) {
	data, err := MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	str := pem.EncodeToMemory(
		&pem.Block{
			Type:  fmt.Sprintf("%s PUBLIC KEY", pk.Scheme().Name()),
			Bytes: data,
		},
	)
	return str, nil
}

func UnmarshalPKIXPublicKey(data []byte) (PublicKey, error) {
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

func MarshalPKIXPublicKey(pk PublicKey) ([]byte, error) {
	scheme := pk.Scheme()
	certScheme, ok := scheme.(CertificateScheme)
	if !ok {
		return nil, errors.New("only supported for CertificateScheme")
	}

	data, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	pkix := struct {
		pkix.AlgorithmIdentifier
		asn1.BitString
	}{
		pkix.AlgorithmIdentifier{
			Algorithm: certScheme.Oid(),
		},
		asn1.BitString{
			Bytes:     data,
			BitLength: len(data) * 8,
		},
	}

	return asn1.Marshal(pkix)
}

func UnmarshalPEMPrivateKey(data []byte) (PrivateKey, error) {
	block, rest := pem.Decode(data)
	if len(rest) != 0 {
		return nil, errors.New("trailing")
	}

	sk, err := UnmarshalPKIXPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return sk, nil
}

func MarshalPEMPrivateKey(sk PrivateKey) ([]byte, error) {
	data, err := MarshalPKIXPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	str := pem.EncodeToMemory(
		&pem.Block{
			Type:  fmt.Sprintf("%s PRIVATE KEY", sk.Scheme().Name()),
			Bytes: data,
		},
	)
	return str, nil
}

func UnmarshalPKIXPrivateKey(data []byte) (PrivateKey, error) {
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

func MarshalPKIXPrivateKey(sk PrivateKey) ([]byte, error) {
	scheme := sk.Scheme()
	certScheme, ok := scheme.(CertificateScheme)
	if !ok {
		return nil, errors.New("only supported for CertificateScheme")
	}

	data, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	data, err = asn1.Marshal(data)
	if err != nil {
		return nil, err
	}

	pkix := struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		0,
		pkix.AlgorithmIdentifier{
			Algorithm: certScheme.Oid(),
		},
		data,
	}

	return asn1.Marshal(pkix)
}

// Go1.15 adds {PublicKey,PrivateKey}.Equal(). Until then, we can use that
// we use this.

func PublicKeysEqual(a, b PublicKey) bool {
	if a.Scheme() != b.Scheme() {
		return false
	}
	ap, err := a.MarshalBinary()
	if err != nil {
		return false
	}
	bp, err := b.MarshalBinary()
	if err != nil {
		return false
	}
	return bytes.Equal(ap, bp)
}

func PrivateKeysEqual(a, b PrivateKey) bool {
	if a.Scheme() != b.Scheme() {
		return false
	}
	ap, err := a.MarshalBinary()
	if err != nil {
		return false
	}
	bp, err := b.MarshalBinary()
	if err != nil {
		return false
	}
	return bytes.Equal(ap, bp)
}

// We would like the following from our signatures API:
//
// 1) Have the main types such as Scheme, PublicKey and PrivateKey
//    defined in circl/sign.
// 2) Have all built-in signature schemes available without having to import
//    secondary modules.
// 3) Get the Scheme from a Public/PrivateKey using the Scheme() memberfunction.
//
// Because of this we cannot use the Private/PublicKey types of the original
// package, because that original package needs to import the circl/sign
// package for the definition of Scheme (because of 3 and 1).  Conversely,
// because of 2, the circl/sign package needs to import the original package.
// We fix this by simply wrapping the Public/PrivateKeys together with the
// appropriate scheme.

func wrapPublicKey(pk schemelessPublicKey, scheme Scheme) PublicKey {
	return &wrappedPublicKey{pk, scheme}
}

func wrapPrivateKey(sk schemelessPrivateKey, scheme Scheme) PrivateKey {
	return &wrappedPrivateKey{sk, scheme}
}

// PublicKey minus Scheme()
type schemelessPublicKey interface {
	encoding.BinaryMarshaler
}

// PrivateKey minus Scheme()
type schemelessPrivateKey interface {
	crypto.Signer
	encoding.BinaryMarshaler
}

type wrappedPublicKey struct {
	wrappee schemelessPublicKey
	scheme  Scheme
}

func (pk *wrappedPublicKey) Scheme() Scheme {
	return pk.scheme
}

func (pk *wrappedPublicKey) MarshalBinary() ([]byte, error) {
	return pk.wrappee.MarshalBinary()
}

type wrappedPrivateKey struct {
	wrappee schemelessPrivateKey
	scheme  Scheme
}

func (sk *wrappedPrivateKey) Scheme() Scheme {
	return sk.scheme
}

func (sk *wrappedPrivateKey) Sign(rand io.Reader, msg []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {
	return sk.wrappee.Sign(rand, msg, opts)
}

func (sk *wrappedPrivateKey) Public() crypto.PublicKey {
	return wrapPublicKey(sk.wrappee.Public().(schemelessPublicKey), sk.scheme)
}

func (sk *wrappedPrivateKey) MarshalBinary() ([]byte, error) {
	return sk.wrappee.MarshalBinary()
}
