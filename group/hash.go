package group

import (
	"crypto"
	"math/big"
)

// GFHasher is
type GFHasher interface {
	GFHash(u []big.Int, b []byte)
}

type expanderXMD struct {
	h   crypto.Hash
	p   *big.Int
	L   uint
	dst []byte
}

// NewExpanderMD returns a hash function based on a Merkle-Damgård hash function.
func NewExpanderMD(h crypto.Hash, p *big.Int, L uint, dst []byte) GFHasher {
	const maxDSTLength = 255
	var dstPrime []byte
	if l := len(dst); l > maxDSTLength {
		H := h.New()
		_, _ = H.Write([]byte("H2C-OVERSIZE-DST-"))
		_, _ = H.Write(dst)
		dstPrime = H.Sum(nil)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, dst)
	}
	dstPrime = append(dstPrime, byte(len(dstPrime)))
	return expanderXMD{h, p, L, dstPrime}
}

func (e expanderXMD) GFHash(u []big.Int, b []byte) {
	count := uint(len(u))
	bytes := e.expand(b, count*e.L)
	for i := range u {
		j := uint(i) * e.L
		u[i].Mod(u[i].SetBytes(bytes[j:j+e.L]), e.p)
	}
}

func (e expanderXMD) expand(msg []byte, n uint) []byte {
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
	_, _ = H.Write(msg)
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
		_, _ = H.Write(xor(bi, b0))
		_, _ = H.Write([]byte{byte(i)})
		_, _ = H.Write(e.dst)
		bi = H.Sum(nil)
		pseudo = append(pseudo, bi...)
	}
	return pseudo[0:n]
}

func xor(x, y []byte) []byte {
	for i := range x {
		x[i] ^= y[i]
	}
	return x
}
