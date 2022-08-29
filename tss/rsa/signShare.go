package rsa

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

// SignShare represents a portion of a signature. It is generated when a message is signed by a KeyShare. t SignShare's are then combined by calling CombineSignShares, where t is the threshold.
type SignShare struct {
	xi *big.Int

	Index uint
}

// MarshalBinary encodes SignShare into a byte array in a format readable by UnmarshalBinary.
// Note: Only Index's up to math.MaxUint16 are supported
func (s *SignShare) MarshalBinary() ([]byte, error) {
	// | Index: uint16 | xiLen: uint16 | xi: []byte |

	if s.Index > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: Index is too big to fit in a uint16")
	}

	index := uint16(s.Index)

	xiBytes := s.xi.Bytes()
	if len(xiBytes) > math.MaxInt16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: xiBytes is too big to fit it's length in a uint16")
	}
	xiLen := len(xiBytes)
	if xiLen == 0 { // same as above
		xiLen = 1
	}

	blen := 2 + 2 + xiLen
	out := make([]byte, blen)

	binary.BigEndian.PutUint16(out[0:2], index)

	binary.BigEndian.PutUint16(out[2:4], uint16(xiLen))

	copy(out[4:4+xiLen], xiBytes)

	return out, nil
}

// UnmarshalBinary converts a byte array outputted from Marshall into a SignShare or returns an error if the value is invalid
func (s *SignShare) UnmarshalBinary(data []byte) error {
	// | Index: uint16 | xiLen: uint16 | xi: []byte |
	if len(data) < 2 {
		return fmt.Errorf("rsa_threshold: signshare unmarshal failed: data length was too short for reading Index")
	}

	i := binary.BigEndian.Uint16(data[0:2])

	if len(data[2:]) < 2 {
		return fmt.Errorf("rsa_threshold: signshare unmarshal failed: data length was too short for reading xiLen length")
	}

	xiLen := binary.BigEndian.Uint16(data[2:4])

	if xiLen == 0 {
		return fmt.Errorf("rsa_threshold: signshare unmarshal failed: xi is a required field but xiLen was 0")
	}

	if uint16(len(data[4:])) < xiLen {
		return fmt.Errorf("rsa_threshold: signshare unmarshal failed: data length was too short for reading xi, needed: %d found: %d", xiLen, len(data[3:]))
	}

	xi := big.Int{}
	bytes := make([]byte, xiLen)
	copy(bytes, data[4:4+xiLen])
	xi.SetBytes(bytes)

	s.Index = uint(i)
	s.xi = &xi

	return nil
}
