// Package ascon provides a light-weight AEAD cipher.
//
// This package implements Ascon128 and Ascon128a two AEAD ciphers as specified
// in ASCON v1.2 by C. Dobraunig, M. Eichlseder, F. Mendel, M. Schläffer.
// https://ascon.iaik.tugraz.at/index.html
package ascon

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	KeySize   = 16
	NonceSize = 16
	TagSize   = KeySize
)

type Mode int

func (m Mode) String() string {
	switch m {
	case Ascon128:
		return "Ascon128"
	case Ascon128a:
		return "Ascon128a"
	default:
		panic(ErrMode)
	}
}

const (
	Ascon128 Mode = iota + 1
	Ascon128a
)

const (
	permA     = 12
	permB     = 6 // 6 for Ascon128, or  8 for Ascon128a
	blockSize = 8 // 8 for Ascon128, or 16 for Ascon128a
	ivSize    = 8
	stateSize = ivSize + KeySize + NonceSize
)

type Cipher struct {
	s    [5]uint64
	key  [2]uint64
	mode Mode
}

// New returns a Cipher struct implementing the cipher.AEAD interface. Mode is
// one of Ascon128 or Ascon128a.
func New(key []byte, m Mode) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	if !(m == Ascon128 || m == Ascon128a) {
		return nil, ErrMode
	}
	c := new(Cipher)
	c.mode = m
	c.key[0] = binary.BigEndian.Uint64(key[0:8])
	c.key[1] = binary.BigEndian.Uint64(key[8:16])

	return c, nil
}

// NonceSize returns the size of the nonce that must be passed to Seal
// and Open.
func (a *Cipher) NonceSize() int { return NonceSize }

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (a *Cipher) Overhead() int { return TagSize }

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
func (a *Cipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic(ErrNonceSize)
	}

	ptLen := len(plaintext)
	output := make([]byte, ptLen+TagSize)
	ciphertext, tag := output[:ptLen], output[ptLen:]

	a.initialize(nonce)
	a.assocData(additionalData)
	a.procText(plaintext, ciphertext, true)
	a.finalize(tag)

	return output
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (a *Cipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic(ErrNonceSize)
	}
	if len(ciphertext) < TagSize {
		return nil, ErrDecryption
	}

	ptLen := len(ciphertext) - TagSize
	plaintext := make([]byte, ptLen)
	ciphertext, tag0 := ciphertext[:ptLen], ciphertext[ptLen:]
	tag1 := (&[TagSize]byte{})[:]

	a.initialize(nonce)
	a.assocData(additionalData)
	a.procText(ciphertext, plaintext, false)
	a.finalize(tag1)

	if subtle.ConstantTimeCompare(tag0, tag1) == 0 {
		return nil, ErrDecryption
	}

	return plaintext, nil
}

func (a *Cipher) initialize(nonce []byte) {
	bcs := blockSize * uint64(a.mode)
	pB := permB + 2*(uint64(a.mode)-1)
	a.s[0] = ((KeySize * 8) << 56) | ((bcs * 8) << 48) | (permA << 40) | (pB << 32)
	a.s[1] = a.key[0]
	a.s[2] = a.key[1]
	a.s[3] = binary.BigEndian.Uint64(nonce[0:8])
	a.s[4] = binary.BigEndian.Uint64(nonce[8:16])
	a.perm(permA)
	a.s[3] ^= a.key[0]
	a.s[4] ^= a.key[1]
}

func (a *Cipher) assocData(add []byte) {
	bcs := blockSize * int(a.mode)
	pB := permB + 2*(int(a.mode)-1)
	if len(add) > 0 {
		for ; len(add) >= bcs; add = add[bcs:] {
			for i := 0; i < bcs; i += 8 {
				a.s[i/8] ^= binary.BigEndian.Uint64(add[i : i+8])
			}
			a.perm(pB)
		}
		for i := 0; i < len(add); i++ {
			a.s[i/8] ^= uint64(add[i]) << (56 - 8*(i%8))
		}
		a.s[len(add)/8] ^= uint64(0x80) << (56 - 8*(len(add)%8))
		a.perm(pB)
	}
	a.s[4] ^= 0x01
}

func (a *Cipher) procText(in, out []byte, enc bool) {
	bcs := blockSize * int(a.mode)
	pB := permB + 2*(int(a.mode)-1)
	mask := uint64(0)
	if enc {
		mask -= 1
	}

	for ; len(in) >= bcs; in, out = in[bcs:], out[bcs:] {
		for i := 0; i < bcs; i += 8 {
			inW := binary.BigEndian.Uint64(in[i : i+8])
			outW := a.s[i/8] ^ inW
			binary.BigEndian.PutUint64(out[i:i+8], outW)

			a.s[i/8] = (inW &^ mask) | (outW & mask)
		}
		a.perm(pB)
	}

	mask8 := byte(mask & 0xFF)
	for i := 0; i < len(in); i++ {
		off := 56 - (8 * (i % 8))
		si := byte((a.s[i/8] >> off) & 0xFF)
		out[i] = si ^ in[i]
		ss := (in[i] &^ mask8) | (out[i] & mask8)
		a.s[i/8] = (a.s[i/8] &^ (0xFF << off)) | uint64(ss)<<off
	}
	a.s[len(in)/8] ^= uint64(0x80) << (56 - 8*(len(in)%8))
}

func (a *Cipher) finalize(tag []byte) {
	bcs := blockSize * int(a.mode)
	a.s[bcs/8+0] ^= a.key[0]
	a.s[bcs/8+1] ^= a.key[1]
	a.perm(permA)
	binary.BigEndian.PutUint64(tag[0:8], a.s[3]^a.key[0])
	binary.BigEndian.PutUint64(tag[8:16], a.s[4]^a.key[1])
}

var roundConst = [12]uint64{0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}

func (a *Cipher) perm(n int) {
	ri := 0
	if n != permA {
		ri = permA - n
	}

	x0, x1, x2, x3, x4 := a.s[0], a.s[1], a.s[2], a.s[3], a.s[4]
	for i := 0; i < n; i++ {
		// pC -- addition of constants
		x2 ^= roundConst[ri+i]

		// pS -- substitution layer
		// Figure 6 from Spec [DHVV18,Dae18]
		// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
		x0 ^= x4
		x4 ^= x3
		x2 ^= x1
		t0 := x0 & (^x4)
		t1 := x2 & (^x1)
		x0 ^= t1
		t1 = x4 & (^x3)
		x2 ^= t1
		t1 = x1 & (^x0)
		x4 ^= t1
		t1 = x3 & (^x2)
		x1 ^= t1
		x3 ^= t0
		x1 ^= x0
		x3 ^= x2
		x0 ^= x4
		x2 = ^x2

		// pL -- linear diffusion layer
		x0 ^= bits.RotateLeft64(x0, -19) ^ bits.RotateLeft64(x0, -28)
		x1 ^= bits.RotateLeft64(x1, -61) ^ bits.RotateLeft64(x1, -39)
		x2 ^= bits.RotateLeft64(x2, -1) ^ bits.RotateLeft64(x2, -6)
		x3 ^= bits.RotateLeft64(x3, -10) ^ bits.RotateLeft64(x3, -17)
		x4 ^= bits.RotateLeft64(x4, -7) ^ bits.RotateLeft64(x4, -41)
	}
	a.s[0], a.s[1], a.s[2], a.s[3], a.s[4] = x0, x1, x2, x3, x4
}

var (
	ErrKeySize    = errors.New("ascon: bad key size")
	ErrNonceSize  = errors.New("ascon: bad nonce size")
	ErrDecryption = errors.New("ascon: invalid ciphertext")
	ErrMode       = errors.New("ascon: invalid cipher mode")
)
