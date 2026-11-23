package tkn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/cryptobyte"
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

// The tkn20 on-the-wire format uses little-endian length prefixes, but
// cryptobyte works in big-endian
//
// leUint16/leUint32 use cryptobyte.Builder as a bounds-checker but write the
// little-endian "by hand" and centralize the over/underflow check
type leUint16 int

func (v leUint16) Marshal(b *cryptobyte.Builder) error {
	if v < 0 || v > math.MaxUint16 {
		return fmt.Errorf("data too long")
	}
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], uint16(v))
	b.AddBytes(buf[:])
	return nil
}

type leUint32 int

func (v leUint32) Marshal(b *cryptobyte.Builder) error {
	if v < 0 || v > math.MaxUint32 {
		return fmt.Errorf("data too long")
	}
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(v))
	b.AddBytes(buf[:])
	return nil
}

type lenPrefixed16 []byte

func (v lenPrefixed16) Marshal(b *cryptobyte.Builder) error {
	if err := leUint16(len(v)).Marshal(b); err != nil {
		return err
	}
	b.AddBytes(v)
	return nil
}

type lenPrefixed32 []byte

func (v lenPrefixed32) Marshal(b *cryptobyte.Builder) error {
	if err := leUint32(len(v)).Marshal(b); err != nil {
		return err
	}
	b.AddBytes(v)
	return nil
}

// readLEUint16 and readLEUint32 read a little-endian length field which is
// bounds-checked by cryptobyte.String
func readLEUint16(s *cryptobyte.String) (uint16, bool) {
	var raw []byte
	if !s.ReadBytes(&raw, 2) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(raw), true
}

func readLEUint32(s *cryptobyte.String) (uint32, bool) {
	var raw []byte
	if !s.ReadBytes(&raw, 4) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(raw), true
}

func appendLen16Prefixed(a []byte, b []byte) ([]byte, error) {
	bld := cryptobyte.NewBuilder(a)
	bld.AddValue(lenPrefixed16(b))
	return bld.Bytes()
}

// removeLen16Prefixed reads a little-endian uint16 length prefix from data
// via cryptobyte.String (ReadBytes rejects both short input and a negative
// length)
func removeLen16Prefixed(data []byte) (next []byte, remainder []byte, err error) {
	s := cryptobyte.String(data)
	n, ok := readLEUint16(&s)
	if !ok {
		return nil, nil, fmt.Errorf("data too short")
	}
	var item []byte
	if !s.ReadBytes(&item, int(n)) {
		return nil, nil, fmt.Errorf("data too short")
	}
	return item, s, nil
}

var (
	appendLenPrefixed = appendLen16Prefixed
	removeLenPrefixed = removeLen16Prefixed
)

func appendLen32Prefixed(a []byte, b []byte) ([]byte, error) {
	bld := cryptobyte.NewBuilder(a)
	bld.AddValue(lenPrefixed32(b))
	return bld.Bytes()
}

func removeLen32Prefixed(data []byte) (next []byte, remainder []byte, err error) {
	s := cryptobyte.String(data)
	n, ok := readLEUint32(&s)
	if !ok {
		return nil, nil, fmt.Errorf("data too short")
	}
	var item []byte
	if !s.ReadBytes(&item, int(n)) {
		return nil, nil, fmt.Errorf("data too short")
	}
	return item, s, nil
}

func marshalBinarySortedMapMatrixG1(m map[string]*matrixG1) ([]byte, error) {
	sortedKeys := make([]string, 0, len(m))
	for key := range m {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	ret := []byte{}
	for _, key := range sortedKeys {
		b, err := m[key].marshalBinary()
		if err != nil {
			return nil, err
		}

		ret, err = appendLenPrefixed(ret, []byte(key))
		if err != nil {
			return nil, err
		}
		ret, err = appendLenPrefixed(ret, b)
		if err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func marshalBinarySortedMapAttribute(m map[string]Attribute) ([]byte, error) {
	sortedKeys := make([]string, 0, len(m))
	for key := range m {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	ret := []byte{}
	for _, key := range sortedKeys {
		a := m[key]
		b, err := a.marshalBinary()
		if err != nil {
			return nil, err
		}

		ret, err = appendLenPrefixed(ret, []byte(key))
		if err != nil {
			return nil, err
		}
		ret = append(ret, b...)
	}

	return ret, nil
}

var (
	errBadMatrixSize       = errors.New("matrix inputs do not conform")
	errMatrixNonInvertible = errors.New("matrix has no inverse")
)
