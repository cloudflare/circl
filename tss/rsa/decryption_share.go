package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"filippo.io/bigmod"
)

const decryptionShareHeader = 3*2 + sha256.Size

// DecryptionShare is one player's contribution to decrypting one ciphertext.
type DecryptionShare struct {
	Index, Players, Threshold uint
	ciphertextHash            [sha256.Size]byte
	value, inverse            []byte
}

// MarshalBinary encodes the share's metadata and its two fixed-width RSA values.
func (share DecryptionShare) MarshalBinary() ([]byte, error) {
	if !share.validMetadata() || len(share.value) < minOAEPKeyBits/8 || len(share.value) != len(share.inverse) {
		return nil, rsa.ErrDecryption
	}
	encoded := make([]byte, decryptionShareHeader, decryptionShareHeader+2*len(share.value))
	binary.BigEndian.PutUint16(encoded[0:2], uint16(share.Index))
	binary.BigEndian.PutUint16(encoded[2:4], uint16(share.Players))
	binary.BigEndian.PutUint16(encoded[4:6], uint16(share.Threshold))
	copy(encoded[6:], share.ciphertextHash[:])
	encoded = append(encoded, share.value...)
	return append(encoded, share.inverse...), nil
}

// UnmarshalBinary decodes a share. CombineDecryptionSharesOAEP checks the
// encoded values against the trusted modulus and ciphertext.
func (share *DecryptionShare) UnmarshalBinary(data []byte) error {
	if share == nil || len(data) < decryptionShareHeader+2*(minOAEPKeyBits/8) || (len(data)-decryptionShareHeader)%2 != 0 {
		return rsa.ErrDecryption
	}
	prepared := DecryptionShare{
		Index:     uint(binary.BigEndian.Uint16(data[0:2])),
		Players:   uint(binary.BigEndian.Uint16(data[2:4])),
		Threshold: uint(binary.BigEndian.Uint16(data[4:6])),
	}
	if !prepared.validMetadata() {
		return rsa.ErrDecryption
	}
	copy(prepared.ciphertextHash[:], data[6:decryptionShareHeader])
	values := data[decryptionShareHeader:]
	half := len(values) / 2
	prepared.value = bytes.Clone(values[:half])
	prepared.inverse = bytes.Clone(values[half:])
	*share = prepared
	return nil
}

func (share DecryptionShare) validMetadata() bool {
	return share.Index > 0 && share.Index <= share.Players && share.Players <= math.MaxUint16 &&
		share.Threshold >= 2 && share.Threshold <= share.Players
}

func (share DecryptionShare) baseForExponent(modulus *bigmod.Modulus, negative bool) (*bigmod.Nat, error) {
	if len(share.value) != modulus.Size() || len(share.inverse) != modulus.Size() {
		return nil, rsa.ErrDecryption
	}
	value, err := bigmod.NewNat().SetBytes(share.value, modulus)
	if err != nil {
		return nil, rsa.ErrDecryption
	}
	inverse, err := bigmod.NewNat().SetBytes(share.inverse, modulus)
	if err != nil || bigmod.NewNat().SetUint(1).ExpandFor(modulus).Mul(value, modulus).Mul(inverse, modulus).IsOne() != 1 {
		return nil, rsa.ErrDecryption
	}
	if negative {
		return inverse, nil
	}
	return value, nil
}
