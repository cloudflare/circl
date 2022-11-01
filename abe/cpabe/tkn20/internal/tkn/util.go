package tkn

import (
	"encoding/binary"
	"errors"
	"fmt"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/blake2b"
)

var gtBaseVal *pairing.Gt

func init() {
	// This should really be a constant, but what can I do?
	g1 := pairing.G1Generator()
	g2 := pairing.G2Generator()
	gtBaseVal = pairing.Pair(g1, g2)
}

func ToScalar(n int) *pairing.Scalar {
	ret := &pairing.Scalar{}
	ret.SetUint64(uint64(n))
	return ret
}

func HashStringToScalar(key []byte, value string) *pairing.Scalar {
	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, key)
	if err != nil {
		return nil
	}
	xof.Reset()
	_, err = xof.Write([]byte(value))
	if err != nil {
		return nil
	}
	s := &pairing.Scalar{}
	err = s.Random(xof)
	if err != nil {
		return nil
	}
	return s
}

func appendLenPrefixed(a []byte, b []byte) []byte {
	a = append(a, 0, 0)
	binary.LittleEndian.PutUint16(a[len(a)-2:], uint16(len(b)))
	a = append(a, b...)
	return a
}

func removeLenPrefixed(data []byte) (next []byte, remainder []byte, err error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("data too short")
	}
	itemLen := int(binary.LittleEndian.Uint16(data))
	if (2 + itemLen) > len(data) {
		return nil, nil, fmt.Errorf("data too short")
	}
	return data[2 : 2+itemLen], data[2+itemLen:], nil
}

var (
	errBadMatrixSize       = errors.New("matrix inputs do not conform")
	errMatrixNonInvertible = errors.New("matrix has no inverse")
)
