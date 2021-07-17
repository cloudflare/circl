// Package ff provides finite fields of characteristic P381.
package ff

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/cloudflare/circl/internal/conv"
)

func errSum(e ...error) error {
	for i := range e {
		if e != nil {
			return e[i]
		}
	}
	return nil
}

func setString(out []uint64, in string, order []byte) error {
	inBig, ok := new(big.Int).SetString(in, 0)
	if !ok {
		return errors.New("invalid string")
	}
	inBytes := make([]byte, len(order))
	conv.BigInt2BytesLe(inBytes, inBig)
	return setBytes(out, inBytes, order)
}

func setBytes(out []uint64, in []byte, order []byte) error {
	if len(in) != len(order) {
		return errors.New("input length incorrect")
	}
	if !isLessThan(in, order) {
		return errors.New("value out of [0,order)")
	}

	for i := range out {
		out[i] = binary.LittleEndian.Uint64(in[i*8:])
	}
	return nil
}

// isLessThan returns true if 0 <= x < y, and assumes that slices have the same length.
func isLessThan(x, y []byte) bool {
	i := len(x) - 1
	for i > 0 && x[i] == y[i] {
		i--
	}
	return x[i] < y[i]
}

func randomInt(out []uint64, rnd io.Reader, order []byte) error {
	r, err := rand.Int(rnd, conv.BytesLe2BigInt(order))
	if err == nil {
		conv.BigInt2Uint64Le(out, r)
	}
	return err
}

// ctUint64Eq returns 1 if the two slices have equal contents and 0 otherwise.
func ctUint64Eq(x, y []uint64) int {
	if len(x) != len(y) {
		return 0
	}
	l := len(x)
	var v uint64
	for i := 0; i < l; i++ {
		v |= x[i] ^ y[i]
	}

	v8 := byte(v) | byte(v>>8) | byte(v>>16) | byte(v>>24) |
		byte(v>>32) | byte(v>>40) | byte(v>>48) | byte(v>>56)

	return subtle.ConstantTimeByteEq(v8, 0)
}
