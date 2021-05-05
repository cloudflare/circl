package group

import (
	"crypto"
	"math/big"
)

// HashToField generates a set of elements {u1,..., uN} = Hash(b) where each
// u in GF(p) and L is the security parameter.
func HashToField(u []big.Int, b []byte, e Expander, p *big.Int, L uint) {
	count := uint(len(u))
	bytes := e.Expand(b, count*L)
	for i := range u {
		j := uint(i) * L
		u[i].Mod(u[i].SetBytes(bytes[j:j+L]), p)
	}
}

const maxDSTLength = 255

var longDSTPrefix = [17]byte{'H', '2', 'C', '-', 'O', 'V', 'E', 'R', 'S', 'I', 'Z', 'E', '-', 'D', 'S', 'T', '-'}

type Expander interface {
	// Expand generates a pseudo-random byte string of a determined length by
	// expanding an input string.
	Expand(in []byte, length uint) (pseudo []byte)
}

type expanderXMD struct {
	h   crypto.Hash
	dst []byte
}

// NewExpanderMD returns a hash function based on a Merkle-Damgård hash function.
func NewExpanderMD(h crypto.Hash, dst []byte) Expander {
	var dstPrime []byte
	if l := len(dst); l > maxDSTLength {
		H := h.New()
		_, _ = H.Write(longDSTPrefix[:])
		_, _ = H.Write(dst)
		dstPrime = H.Sum(nil)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, dst)
	}
	dstPrime = append(dstPrime, byte(len(dstPrime)))
	return expanderXMD{h, dstPrime}
}

func (e expanderXMD) Expand(in []byte, n uint) []byte {
	H := e.h.New()
	bLen := uint(H.Size())
	ell := (n + (bLen - 1)) / bLen
	if ell > 255 {
		panic("too big")
	}

	zPad := make([]byte, H.BlockSize())
	libStr := []byte{0, 0}
	libStr[0] = byte((n >> 8) & 0xFF)
	libStr[1] = byte(n & 0xFF)

	H.Reset()
	_, _ = H.Write(zPad)
	_, _ = H.Write(in)
	_, _ = H.Write(libStr)
	_, _ = H.Write([]byte{0})
	_, _ = H.Write(e.dst)
	b0 := H.Sum(nil)

	H.Reset()
	_, _ = H.Write(b0)
	_, _ = H.Write([]byte{1})
	_, _ = H.Write(e.dst)
	bi := H.Sum(nil)
	pseudo := append([]byte{}, bi...)
	for i := uint(2); i <= ell; i++ {
		H.Reset()
		for i := range b0 {
			bi[i] ^= b0[i]
		}
		_, _ = H.Write(bi)
		_, _ = H.Write([]byte{byte(i)})
		_, _ = H.Write(e.dst)
		bi = H.Sum(nil)
		pseudo = append(pseudo, bi...)
	}
	return pseudo[0:n]
}
