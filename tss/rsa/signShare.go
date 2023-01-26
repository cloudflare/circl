package rsa

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

// SignShare represents a portion of a signature. It is generated when a message is signed by a KeyShare. t SignShare's are then combined by calling CombineSignShares, where t is the Threshold.
type SignShare struct {
	xi *big.Int

	Index uint

	Players   uint
	Threshold uint
}

func (s SignShare) String() string {
	return fmt.Sprintf("(t,n): (%v,%v) index: %v xi: 0x%v",
		s.Threshold, s.Players, s.Index, s.xi.Text(16))
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
