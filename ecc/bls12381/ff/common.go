// Package ff provides finite fields of characteristic P381.
package ff

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"

	"github.com/cloudflare/circl/internal/conv"
)

var (
	errInputLength = errors.New("incorrect input length")
	errInputRange  = errors.New("value out of range [0,order)")
	errInputString = errors.New("invalid string")
)

func errFirst(e ...error) (err error) {
	for i := 0; i < len(e); i++ {
		if e[i] != nil {
			return e[i]
		}
	}
	return
}

func setString(in string, order []byte) ([]uint64, error) {
	inBig, ok := new(big.Int).SetString(in, 0)
	if !ok {
		return nil, errInputString
	}
	if inBig.Sign() < 0 || inBig.Cmp(new(big.Int).SetBytes(order)) >= 0 {
		return nil, errInputRange
	}
	inBytes := inBig.FillBytes(make([]byte, len(order)))
	return setBytesBounded(inBytes, order)
}

func setBytesBounded(in []byte, order []byte) ([]uint64, error) {
	if isLessThan(in, order) == 0 {
		return nil, errInputRange
	}
	return conv.BytesBe2Uint64Le(in), nil
}

func setBytesUnbounded(in []byte, order []byte) []uint64 {
	inBig := new(big.Int).SetBytes(in)
	inBig.Mod(inBig, new(big.Int).SetBytes(order))
	inBytes := inBig.FillBytes(make([]byte, len(order)))
	return conv.BytesBe2Uint64Le(inBytes)
}

// isLessThan returns 1 if 0 <= x < y, otherwise 0. Assumes that slices have the same length.
func isLessThan(x, y []byte) int {
	i := 0
	for i < len(x)-1 && x[i] == y[i] {
		i++
	}
	return 1 - subtle.ConstantTimeLessOrEq(int(y[i]), int(x[i]))
}

func randomInt(out []uint64, rnd io.Reader, order []byte) error {
	r, err := rand.Int(rnd, new(big.Int).SetBytes(order))
	if err == nil {
		conv.BigInt2Uint64Le(out, r)
	}
	return err
}

// ctUint64Eq returns 1 if the two slices have equal contents and 0 otherwise.
func ctUint64Eq(x, y []uint64) (b int) {
	if len(x) == len(y) {
		var v uint64
		for i := 0; i < len(x); i++ {
			v |= x[i] ^ y[i]
		}
		return subtle.ConstantTimeEq(int32(v>>32), 0) & subtle.ConstantTimeEq(int32(v), 0)
	}
	return
}

func cselectU64(z *uint64, b, x, y uint64) { *z = (x &^ (-b)) | (y & (-b)) }
