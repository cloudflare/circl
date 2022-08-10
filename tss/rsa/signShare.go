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

	Index uint8
}

// MarshalBinary marshalizes SignShare into a byte array in a format readable by Unmarshal. The format itself should not be
// depended on but for now it is | Index: uint8 | xiLen: uint16 | xi: []byte | with all values in big endian.
func (s *SignShare) MarshalBinary() ([]byte, error) {
	// | Index: uint8 | xiLen: uint16 | xi: []byte |

	xiBytes := s.xi.Bytes()
	if len(xiBytes) > math.MaxInt16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: xiBytes is too big to fit it's length in a uint16")
	}
	xiLen := len(xiBytes)
	if xiLen == 0 { // same as above
		xiLen = 1
	}

	blen := 1 + 2 + xiLen
	out := make([]byte, blen)

	out[0] = s.Index

	binary.BigEndian.PutUint16(out[1:3], uint16(xiLen))

	copy(out[3:3+xiLen], xiBytes)

	return out, nil
}

// UnmarshalBinary converts a byte array outputted from Marshall into a SignShare or returns an error if the value is invalid
func (s *SignShare) UnmarshalBinary(data []byte) error {
	// | Index: uint8 | xiLen: uint16 | xi: []byte |
	if len(data) < 1 {
		return fmt.Errorf("rsa_threshold: signshare unmarshal failed: data length was too short for reading Index")
	}
	i := data[0]

	if len(data[1:]) < 2 {
		return fmt.Errorf("rsa_threshold: signshare unmarshal failed: data length was too short for reading xiLen length")
	}

	xiLen := binary.BigEndian.Uint16(data[1:3])

	if xiLen == 0 {
		return fmt.Errorf("rsa_threshold: signshare unmarshal failed: xi is a required field but xiLen was 0")
	}

	if uint16(len(data[3:])) < xiLen {
		return fmt.Errorf("rsa_threshold: signshare unmarshal failed: data length was too short for reading xi, needed: %d found: %d", xiLen, len(data[3:]))
	}

	xi := big.Int{}
	bytes := make([]byte, xiLen)
	copy(bytes, data[3:3+xiLen])
	xi.SetBytes(bytes)

	s.Index = i
	s.xi = &xi

	return nil
}
