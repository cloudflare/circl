package rsa

import (
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/cloudflare/circl/zk/qndleq"
)

// SignShare represents a portion of a signature. It is generated when a message is signed by a KeyShare. t SignShare's are then combined by calling CombineSignShares, where t is the Threshold.
type SignShare struct {
	xi *big.Int

	Index uint

	Players   uint
	Threshold uint

	// It stores a DLEQ proof attesting that the signature
	// share was computed using the signer's key share.
	// If it's nil, signature share is not verifiable.
	// This field is present only if the RSA private key is
	// composed of two safe primes.
	proof *qndleq.Proof
}

func (s SignShare) String() string {
	return fmt.Sprintf("(t,n): (%v,%v) index: %v xi: 0x%v",
		s.Threshold, s.Players, s.Index, s.xi.Text(16))
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

	if !s.proof.Verify(vk.GroupKey, vk.VerifyKey, x4Delta, xiSqr, pub.N) {
		return ErrSignShareInvalid
	}

	return nil
}

// MarshalBinary encodes SignShare into a byte array in a format readable by UnmarshalBinary.
// Note: Only Index's up to math.MaxUint16 are supported
func (s *SignShare) MarshalBinary() ([]byte, error) {
	// | Players: uint16 | Threshold: uint16 | Index: uint16 | xiLen: uint16 | xi: []byte |

	if s.Players > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: Players is too big to fit in a uint16")
	}

	if s.Threshold > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: Threshold is too big to fit in a uint16")
	}

	if s.Index > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: Index is too big to fit in a uint16")
	}

	players := uint16(s.Players)
	threshold := uint16(s.Threshold)
	index := uint16(s.Index)

	xiBytes := s.xi.Bytes()
	xiLen := len(xiBytes)

	if xiLen > math.MaxInt16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: xiBytes is too big to fit it's length in a uint16")
	}

	if xiLen == 0 {
		xiLen = 1
		xiBytes = []byte{0}
	}

	blen := 2 + 2 + 2 + 2 + xiLen
	out := make([]byte, blen)

	binary.BigEndian.PutUint16(out[0:2], players)
	binary.BigEndian.PutUint16(out[2:4], threshold)
	binary.BigEndian.PutUint16(out[4:6], index)

	binary.BigEndian.PutUint16(out[6:8], uint16(xiLen))

	copy(out[8:8+xiLen], xiBytes)

	return out, nil
}

// UnmarshalBinary converts a byte array outputted from Marshall into a SignShare or returns an error if the value is invalid
func (s *SignShare) UnmarshalBinary(data []byte) error {
	// | Players: uint16 | Threshold: uint16 | Index: uint16 | xiLen: uint16 | xi: []byte |
	if len(data) < 8 {
		return fmt.Errorf("rsa_threshold: signshare unmarshalKeyShareTest failed: data length was too short for reading Players, Threshold, Index, and xiLen")
	}

	players := binary.BigEndian.Uint16(data[0:2])
	threshold := binary.BigEndian.Uint16(data[2:4])
	index := binary.BigEndian.Uint16(data[4:6])
	xiLen := binary.BigEndian.Uint16(data[6:8])

	if xiLen == 0 {
		return fmt.Errorf("rsa_threshold: signshare unmarshalKeyShareTest failed: xi is a required field but xiLen was 0")
	}

	if uint16(len(data[8:])) < xiLen {
		return fmt.Errorf("rsa_threshold: signshare unmarshalKeyShareTest failed: data length was too short for reading xi, needed: %d found: %d", xiLen, len(data[6:]))
	}

	xi := big.Int{}
	bytes := make([]byte, xiLen)
	copy(bytes, data[8:8+xiLen])
	xi.SetBytes(bytes)

	s.Players = uint(players)
	s.Threshold = uint(threshold)
	s.Index = uint(index)
	s.xi = &xi

	return nil
}

var (
	ErrSignShareNonVerifiable = errors.New("signature share is not verifiable")
	ErrSignShareInvalid       = errors.New("signature share is invalid")
)
