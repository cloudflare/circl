package rsa

import (
	"crypto"
	"crypto/rsa"
	"io"

	"github.com/cloudflare/circl/tss/rsa/internal"
	pss2 "github.com/cloudflare/circl/tss/rsa/internal/pss"
)

type Padder interface {
	Pad(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte) ([]byte, error)
}

type PKCS1v15Padder struct{}

func (PKCS1v15Padder) Pad(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
	return internal.PadPKCS1v15(pub, hash, hashed)
}

// PSSPadder is a padder for RSA Probabilistic Padding Scheme (RSA-PSS) used in TLS 1.3
//
// Note: If the salt length is non-zero, PSS padding is not deterministic.
// TLS 1.3 mandates that the salt length is the same as the hash output length. As such, each player cannot
// pad the message individually, otherwise they will produce unique messages and the signature will not be valid.
// Instead, one party should generate a random saltLen byte string. When requesting signatures from the rest of the
// parties they should send along the same random string to be used as `rand` here.
//
// For TLS, rsa.PSSOptions.SaltLength should be PSSSaltLengthEqualsHash.
type PSSPadder struct {
	Rand io.Reader
	Opts *rsa.PSSOptions
}

func (pss *PSSPadder) Pad(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
	return pss2.PadPSS(pss.Rand, pub, hash, hashed, pss.Opts)
}
