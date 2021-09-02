package ff

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"

	"github.com/cloudflare/circl/internal/conv"
)

func errFirst(e ...error) error {
	n := len(e)
	for i := 0; i < n; i++ {
		if e[i] != nil {
			return e[i]
		}
	}
	return nil
}

func setString(in string, order []byte) ([]uint64, error) {
	inBig, ok := new(big.Int).SetString(in, 0)
	if !ok {
		return nil, errors.New("invalid string")
	}
	if inBig.Sign() < 0 || inBig.Cmp(new(big.Int).SetBytes(order)) >= 0 {
		return nil, errors.New("value out of range [0,order)")
	}
	inBytes := inBig.FillBytes(make([]byte, len(order)))
	return setBytes(inBytes, order)
}

func setBytes(in []byte, order []byte) ([]uint64, error) {
	if !isLessThan(in, order) {
		return nil, errors.New("value out of range [0,order)")
	}
	return conv.BytesBe2Uint64Le(in), nil
}

// isLessThan returns true if 0 <= x < y, and assumes that slices have the same length.
func isLessThan(x, y []byte) bool {
	n := len(x)
	i := 0
	for i < n-1 && x[i] == y[i] {
		i++
	}
	return x[i] < y[i]
}

func randomInt(out []uint64, rnd io.Reader, order []byte) error {
	r, err := rand.Int(rnd, new(big.Int).SetBytes(order))
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
