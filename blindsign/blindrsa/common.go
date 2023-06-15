package blindrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa/internal/keys"
)

// ConvertHashFunction converts a crypto.Hash function to an equivalent hash.Hash type.
func ConvertHashFunction(hash crypto.Hash) hash.Hash {
	switch hash {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return hash.New()
	default:
		panic(errUnsupportedHashFunction)
	}
}

// EncodeMessageEMSAPSS hashes the input message and then encodes it using PSS encoding.
func EncodeMessageEMSAPSS(message []byte, N *big.Int, hash hash.Hash, salt []byte) ([]byte, error) {
	hash.Reset() // Ensure the hash state is cleared
	hash.Write(message)
	digest := hash.Sum(nil)
	hash.Reset()
	emBits := N.BitLen() - 1
	encodedMsg, err := emsaPSSEncode(digest[:], emBits, salt, hash)
	return encodedMsg, err
}

// GenerateBlindingFactor generates a blinding factor and its multiplicative inverse
// to use for RSA blinding.
func GenerateBlindingFactor(random io.Reader, N *big.Int) (*big.Int, *big.Int, error) {
	randReader := random
	if randReader == nil {
		randReader = rand.Reader
	}
	r, err := rand.Int(randReader, N)
	if err != nil {
		return nil, nil, err
	}

	if r.Sign() == 0 {
		r = bigOne
	}
	rInv := new(big.Int).ModInverse(r, N)
	if rInv == nil {
		return nil, nil, ErrInvalidBlind
	}

	return r, rInv, nil
}

// VerifyMessageSignature verifies the input message signature against the expected public key
func VerifyMessageSignature(message, signature []byte, saltLength int, pk *keys.BigPublicKey, hash crypto.Hash) error {
	h := ConvertHashFunction(hash)
	h.Write(message)
	digest := h.Sum(nil)

	err := verifyPSS(pk, hash, digest, signature, &rsa.PSSOptions{
		Hash:       hash,
		SaltLength: saltLength,
	})
	return err
}

// DecryptAndCheck checks that the private key operation is consistent (fault attack detection).
func DecryptAndCheck(random io.Reader, priv *keys.BigPrivateKey, c *big.Int) (m *big.Int, err error) {
	m, err = decrypt(random, priv, c)
	if err != nil {
		return nil, err
	}

	// In order to defend against errors in the CRT computation, m^e is
	// calculated, which should match the original ciphertext.
	check := encrypt(new(big.Int), priv.Pk.N, priv.Pk.E, m)
	if c.Cmp(check) != 0 {
		return nil, errors.New("rsa: internal error")
	}
	return m, nil
}

// VerifyBlindSignature verifies the signature of the hashed and encoded message against the input public key.
func VerifyBlindSignature(pub *keys.BigPublicKey, hashed, sig []byte) error {
	m := new(big.Int).SetBytes(hashed)
	bigSig := new(big.Int).SetBytes(sig)

	c := encrypt(new(big.Int), pub.N, pub.E, bigSig)
	if subtle.ConstantTimeCompare(m.Bytes(), c.Bytes()) == 1 {
		return nil
	} else {
		return rsa.ErrVerification
	}
}

func verifyPSS(pub *keys.BigPublicKey, hash crypto.Hash, digest []byte, sig []byte, opts *rsa.PSSOptions) error {
	if len(sig) != pub.Size() {
		return rsa.ErrVerification
	}
	s := new(big.Int).SetBytes(sig)
	m := encrypt(new(big.Int), pub.N, pub.E, s)
	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	if m.BitLen() > emLen*8 {
		return rsa.ErrVerification
	}
	em := m.FillBytes(make([]byte, emLen))
	return emsaPSSVerify(digest, em, emBits, saltLength(opts), hash.New())
}
