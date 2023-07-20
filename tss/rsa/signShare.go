package rsa

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/zk/qndleq"
	"golang.org/x/crypto/cryptobyte"
)

// SignShare represents a portion of a signature. It is generated when a message is signed by a KeyShare. t SignShare's are then combined by calling CombineSignShares, where t is the Threshold.
type SignShare struct {
	share

	xi *big.Int

	// It stores a DLEQ proof attesting that the signature
	// share was computed using the signer's key share.
	// If it's nil, signature share is not verifiable.
	// This field is present only if the RSA private key is
	// composed of two safe primes.
	proof *qndleq.Proof
}

func (s SignShare) String() string {
	return fmt.Sprintf("%v xi: 0x%v proof: {%v}", s.share, s.xi.Text(16), s.proof)
}

// IsVerifiable returns true if the signature share contains
// a DLEQ proof for verification.
func (s *SignShare) IsVerifiable() bool { return s.proof != nil }

// Verify returns nil if the signature share is verifiable and validates
// the DLEQ proof. This indicates the signature share of the message was
// produced using the signer's key share. The signer must provide its
// verification keys. If proof verification does not pass, returns
// an ErrSignShareInvalid error.
//
// Before calling this function, ensure the signature share is verifiable
// by calling the method IsVerifiable. If the signature share is not
// verifiable, this function returns an ErrSignShareNonVerifiable error.
func (s *SignShare) Verify(pub *rsa.PublicKey, vk *VerifyKeys, digest []byte) error {
	if !s.IsVerifiable() {
		return ErrSignShareNonVerifiable
	}

	x := new(big.Int).SetBytes(digest)
	fourDelta := calculateDelta(int64(s.Players))
	fourDelta.Lsh(fourDelta, 2)
	x4Delta := new(big.Int).Exp(x, fourDelta, pub.N)
	xiSqr := new(big.Int).Mul(s.xi, s.xi)
	xiSqr.Mod(xiSqr, pub.N)

	const SecParam = 128
	if !s.proof.Verify(vk.GroupKey, vk.VerifyKey, x4Delta, xiSqr, pub.N, SecParam) {
		return ErrSignShareInvalid
	}

	return nil
}

func (s *SignShare) Marshal(b *cryptobyte.Builder) error {
	buf := make([]byte, (s.ModulusLength+7)/8)
	b.AddValue(&s.share)
	b.AddBytes(s.xi.FillBytes(buf))

	isVerifiable := s.IsVerifiable()
	var flag uint8
	if isVerifiable {
		flag = 0x01
	}
	b.AddUint8(flag)

	if isVerifiable {
		b.AddValue(s.proof)
	}

	return nil
}

func (s *SignShare) ReadValue(r *cryptobyte.String) bool {
	var sh share
	ok := sh.ReadValue(r)
	if !ok {
		return false
	}

	mlen := int((sh.ModulusLength + 7) / 8)
	var xiBytes []byte
	ok = r.ReadBytes(&xiBytes, mlen)
	if !ok {
		return false
	}

	var isVerifiable uint8
	ok = r.ReadUint8(&isVerifiable)
	if !ok {
		return false
	}

	var proof *qndleq.Proof
	switch isVerifiable {
	case 0:
		proof = nil
	case 1:
		proof = new(qndleq.Proof)
		ok = proof.ReadValue(r)
		if !ok {
			return false
		}

	default:
		return false
	}

	s.share = sh
	s.xi = new(big.Int).SetBytes(xiBytes)
	s.proof = proof

	return true
}

func (s *SignShare) MarshalBinary() ([]byte, error) { return conv.MarshalBinary(s) }
func (s *SignShare) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(s, b) }

var (
	ErrKeyShareNonVerifiable  = errors.New("key share has no verification keys")
	ErrSignShareNonVerifiable = errors.New("signature share is not verifiable")
	ErrSignShareInvalid       = errors.New("signature share is invalid")
)
