package hybrid

import (
	"crypto/ecdh"
	cryptoRand "crypto/rand"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/xof"
)

type cPublicKey struct {
	scheme cScheme
	key    *ecdh.PublicKey
}
type cPrivateKey struct {
	scheme cScheme
	key    *ecdh.PrivateKey
}
type cScheme struct {
	curve ecdh.Curve
}

var p256Kem = &cScheme{ecdh.P256()}

func (sch cScheme) Name() string {
	switch sch.curve {
	case ecdh.P256():
		return "P-256"
	case ecdh.P384():
		return "P-384"
	case ecdh.P521():
		return "P-521"
	default:
		panic("unsupported curve")
	}
}

func (sch cScheme) PublicKeySize() int {
	switch sch.curve {
	case ecdh.P256():
		return 65
	case ecdh.P384():
		return 97
	case ecdh.P521():
		return 133
	default:
		panic("unsupported curve")
	}
}

func (sch cScheme) PrivateKeySize() int {
	switch sch.curve {
	case ecdh.P256():
		return 32
	case ecdh.P384():
		return 48
	case ecdh.P521():
		return 66
	default:
		panic("unsupported curve")
	}
}

func (sch cScheme) SeedSize() int {
	return sch.PrivateKeySize()
}

func (sch cScheme) SharedKeySize() int {
	return sch.PrivateKeySize()
}

func (sch cScheme) CiphertextSize() int {
	return sch.PublicKeySize()
}

func (sch cScheme) EncapsulationSeedSize() int {
	return sch.SeedSize()
}

func (sk *cPrivateKey) Scheme() kem.Scheme { return sk.scheme }
func (pk *cPublicKey) Scheme() kem.Scheme  { return pk.scheme }

func (sk *cPrivateKey) MarshalBinary() ([]byte, error) {
	return sk.key.Bytes(), nil
}

func (sk *cPrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*cPrivateKey)
	if !ok {
		return false
	}
	if oth.scheme != sk.scheme {
		return false
	}
	return oth.key.Equal(sk.key)
}

func (sk *cPrivateKey) Public() kem.PublicKey {
	pk := sk.key.PublicKey()
	return &cPublicKey{scheme: sk.scheme, key: pk}
}

func (pk *cPublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*cPublicKey)
	if !ok {
		return false
	}
	if oth.scheme != pk.scheme {
		return false
	}
	return oth.key.Equal(pk.key)
}

func (pk *cPublicKey) MarshalBinary() ([]byte, error) {
	return pk.key.Bytes(), nil
}

func (sch cScheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	seed := make([]byte, sch.SeedSize())
	_, err := cryptoRand.Read(seed)
	if err != nil {
		return nil, nil, err
	}
	pk, sk := sch.DeriveKeyPair(seed)
	return pk, sk, nil
}

func (sch cScheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != sch.SeedSize() {
		panic(kem.ErrSeedSize)
	}
	h := xof.SHAKE256.New()
	_, _ = h.Write(seed)
	privKey, err := sch.curve.GenerateKey(h)
	if err != nil {
		panic(err)
	}
	pubKey := privKey.PublicKey()

	sk := cPrivateKey{scheme: sch, key: privKey}
	pk := cPublicKey{scheme: sch, key: pubKey}

	return &pk, &sk
}

func (sch cScheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	seed := make([]byte, sch.EncapsulationSeedSize())
	_, err = cryptoRand.Read(seed)
	if err != nil {
		return
	}
	return sch.EncapsulateDeterministically(pk, seed)
}

func (pk *cPublicKey) X(sk *cPrivateKey) []byte {
	if pk.scheme != sk.scheme {
		panic(kem.ErrTypeMismatch)
	}

	sharedKey, err := sk.key.ECDH(pk.key)
	if err != nil {
		// ECDH cannot fail for NIST curves as NewPublicKey rejects
		// invalid points and the point in infinity, and NewPrivateKey
		// rejects invalid scalars and the zero value.
		panic(err)
	}
	return sharedKey
}

func (sch cScheme) EncapsulateDeterministically(
	pk kem.PublicKey, seed []byte,
) (ct, ss []byte, err error) {
	if len(seed) != sch.EncapsulationSeedSize() {
		return nil, nil, kem.ErrSeedSize
	}
	pub, ok := pk.(*cPublicKey)
	if !ok || pub.scheme != sch {
		return nil, nil, kem.ErrTypeMismatch
	}

	pk2, sk2 := sch.DeriveKeyPair(seed)
	ss = pub.X(sk2.(*cPrivateKey))
	ct, _ = pk2.MarshalBinary()
	return
}

func (sch cScheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != sch.CiphertextSize() {
		return nil, kem.ErrCiphertextSize
	}

	priv, ok := sk.(*cPrivateKey)
	if !ok || priv.scheme != sch {
		return nil, kem.ErrTypeMismatch
	}

	pk, err := sch.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		return nil, err
	}

	ss := pk.(*cPublicKey).X(priv)
	return ss, nil
}

func (sch cScheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != sch.PublicKeySize() {
		return nil, kem.ErrPubKeySize
	}
	key, err := sch.curve.NewPublicKey(buf)
	if err != nil {
		return nil, err
	}
	return &cPublicKey{sch, key}, nil
}

func (sch cScheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != sch.PrivateKeySize() {
		return nil, kem.ErrPrivKeySize
	}
	key, err := sch.curve.NewPrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return &cPrivateKey{sch, key}, nil
}
