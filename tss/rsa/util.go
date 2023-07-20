package rsa

import (
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
)

func calculateDelta(l int64) *big.Int {
	// ∆ = l!
	delta := big.Int{}
	delta.MulRange(1, l)
	return &delta
}

type share struct {
	ModulusLength uint // Size of RSA modulus in bits.
	Threshold     uint // Minimum number of shares to produce a signature.
	Players       uint // Total number of signers.
	Index         uint // Non-zero identifier of the signer.
}

func (s share) String() string {
	return fmt.Sprintf("(t=%v,n=%v)-RSA-%v index: %v", s.Threshold, s.Players, s.ModulusLength, s.Index)
}

func (s *share) Marshal(b *cryptobyte.Builder) error {
	b.AddUint16(uint16(s.ModulusLength))
	b.AddUint16(uint16(s.Threshold))
	b.AddUint16(uint16(s.Players))
	b.AddUint16(uint16(s.Index))
	return nil
}

func (s *share) ReadValue(r *cryptobyte.String) bool {
	var ModulusLength, Index, Threshold, Players uint16
	ok := r.ReadUint16(&ModulusLength) &&
		r.ReadUint16(&Threshold) &&
		r.ReadUint16(&Players) &&
		r.ReadUint16(&Index)
	if !ok {
		return false
	}

	err := validateParams(uint(Players), uint(Threshold))
	if err != nil {
		panic(err)
	}

	if Index == 0 {
		panic("index cannot be zero")
	}

	s.ModulusLength = uint(ModulusLength)
	s.Threshold = uint(Threshold)
	s.Players = uint(Players)
	s.Index = uint(Index)

	return true
}
