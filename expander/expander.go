// Package expander generates arbitrary bytes from an XOF or Hash function.
package expander

import (
	"crypto"
	"encoding/binary"
	"errors"
	"io"

	"github.com/cloudflare/circl/xof"
)

type Expander interface {
	// Expand generates a pseudo-random byte string of a determined length by
	// expanding an input string.
	Expand(in []byte, length uint) (pseudo []byte)
}

type expanderMD struct {
	h   crypto.Hash
	dst []byte
}

// NewExpanderMD returns a hash function based on a Merkle-Damgård hash function.
func NewExpanderMD(h crypto.Hash, dst []byte) *expanderMD {
	return &expanderMD{h, dst}
}

func (e *expanderMD) calcDSTPrime() []byte {
	var dstPrime []byte
	if l := len(e.dst); l > maxDSTLength {
		H := e.h.New()
		mustWrite(H, longDSTPrefix[:])
		mustWrite(H, e.dst)
		dstPrime = H.Sum(nil)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, e.dst)
	}
	return append(dstPrime, byte(len(dstPrime)))
}

func (e *expanderMD) Expand(in []byte, n uint) []byte {
	H := e.h.New()
	bLen := uint(H.Size())
	ell := (n + (bLen - 1)) / bLen
	if ell > 255 {
		panic(errorLongOutput)
	}

	zPad := make([]byte, H.BlockSize())
	libStr := []byte{0, 0}
	libStr[0] = byte((n >> 8) & 0xFF)
	libStr[1] = byte(n & 0xFF)
	dstPrime := e.calcDSTPrime()

	mustWrite(H, zPad)
	mustWrite(H, in)
	mustWrite(H, libStr)
	mustWrite(H, []byte{0})
	mustWrite(H, dstPrime)
	b0 := H.Sum(nil)

	H.Reset()
	mustWrite(H, b0)
	mustWrite(H, []byte{1})
	mustWrite(H, dstPrime)
	bi := H.Sum(nil)
	pseudo := append([]byte{}, bi...)
	for i := uint(2); i <= ell; i++ {
		H.Reset()
		for i := range b0 {
			bi[i] ^= b0[i]
		}
		mustWrite(H, bi)
		mustWrite(H, []byte{byte(i)})
		mustWrite(H, dstPrime)
		bi = H.Sum(nil)
		pseudo = append(pseudo, bi...)
	}
	return pseudo[0:n]
}

// expanderXOF is based on an extendable output function.
type expanderXOF struct {
	id        xof.ID
	kSecLevel uint
	dst       []byte
}

// NewExpanderXOF returns an Expander based on an extendable output function.
// The kSecLevel parameter is the target security level in bits, and dst is
// a domain separation string.
func NewExpanderXOF(id xof.ID, kSecLevel uint, dst []byte) *expanderXOF {
	return &expanderXOF{id, kSecLevel, dst}
}

// Expand panics if output's length is longer than 2^16 bytes.
func (e *expanderXOF) Expand(in []byte, n uint) []byte {
	bLen := []byte{0, 0}
	binary.BigEndian.PutUint16(bLen, uint16(n))
	pseudo := make([]byte, n)
	dstPrime := e.calcDSTPrime()

	H := e.id.New()
	mustWrite(H, in)
	mustWrite(H, bLen)
	mustWrite(H, dstPrime)
	mustReadFull(H, pseudo)
	return pseudo
}

func (e *expanderXOF) calcDSTPrime() []byte {
	var dstPrime []byte
	if l := len(e.dst); l > maxDSTLength {
		H := e.id.New()
		mustWrite(H, longDSTPrefix[:])
		mustWrite(H, e.dst)
		max := ((2 * e.kSecLevel) + 7) / 8
		dstPrime = make([]byte, max, max+1)
		mustReadFull(H, dstPrime)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, e.dst)
	}
	return append(dstPrime, byte(len(dstPrime)))
}

func mustWrite(w io.Writer, b []byte) {
	if n, err := w.Write(b); err != nil || n != len(b) {
		panic(err)
	}
}

func mustReadFull(r io.Reader, b []byte) {
	if n, err := io.ReadFull(r, b); err != nil || n != len(b) {
		panic(err)
	}
}

const maxDSTLength = 255

var (
	longDSTPrefix = [17]byte{'H', '2', 'C', '-', 'O', 'V', 'E', 'R', 'S', 'I', 'Z', 'E', '-', 'D', 'S', 'T', '-'}

	errorLongOutput = errors.New("requested too many bytes")
)
