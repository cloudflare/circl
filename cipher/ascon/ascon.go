// Package ascon provides a light-weight AEAD cipher.
//
// This packges implements the AEAD ciphers Ascon128 and Ascon128a as specified
// in https://ascon.iaik.tugraz.at/index.html
package ascon

import (
	"bytes"
	"crypto/cipher"
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

const (
	Ascon128 Mode = iota + 1
	Ascon128a
)

const (
	permA     = 12
	permB     = 6 // 6 for Ascon128, or 8 for Ascon128a
	blockSize = 8 // 8 for Ascon128, or 16 for Ascon128a
	ivSize    = 8
	stateSize = ivSize + KeySize + NonceSize
)

var (
	roundConst = [12]uint64{0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b}
	subs       = [32]int{
		0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02,
		0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
		0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,
		0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17,
	}
)

type Cipher struct {
	state [stateSize]byte
	key   [KeySize]byte
	mode  Mode
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
	copy(c.key[:], key)
	var _ cipher.AEAD = c
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

	ptLen := len(ciphertext) - TagSize
	plaintext := make([]byte, ptLen)
	ciphertext, tag0 := ciphertext[:ptLen], ciphertext[ptLen:]
	tag1 := (&[TagSize]byte{})[:]

	a.initialize(nonce)
	a.assocData(additionalData)
	a.procText(ciphertext, plaintext, false)
	a.finalize(tag1)

	if !bytes.Equal(tag0, tag1) {
		return nil, ErrDecryption
	}

	return plaintext, nil
}

func (a *Cipher) initialize(nonce []byte) {
	bcs := blockSize * byte(a.mode)
	pB := permB + 2*(byte(a.mode)-1)
	a.state[0] = KeySize * 8
	a.state[1] = bcs * 8
	a.state[2] = permA
	a.state[3] = pB
	a.state[4] = 0
	a.state[5] = 0
	a.state[6] = 0
	a.state[7] = 0
	copy(a.state[ivSize:ivSize+KeySize], a.key[:])
	copy(a.state[ivSize+KeySize:ivSize+KeySize+NonceSize], nonce)
	a.perm(permA)

	for i := 0; i < KeySize; i++ {
		a.state[stateSize-KeySize+i] ^= a.key[i]
	}
}

func (a *Cipher) assocData(add []byte) {
	bcs := blockSize * int(a.mode)
	pB := permB + 2*(int(a.mode)-1)
	if len(add) > 0 {
		for ; len(add) >= bcs; add = add[bcs:] {
			for i := 0; i < bcs; i++ {
				a.state[i] ^= add[i]
			}
			a.perm(pB)
		}
		if len(add) >= 0 {
			for i := 0; i < len(add); i++ {
				a.state[i] ^= add[i]
			}
			a.state[len(add)] ^= 0x80
			a.perm(pB)
		}
	}
	a.state[stateSize-1] ^= 0x01
}

func (a *Cipher) procText(in, out []byte, enc bool) {
	bcs := blockSize * int(a.mode)
	pB := permB + 2*(int(a.mode)-1)
	cc := in
	if enc {
		cc = out
	}
	for ; len(in) >= bcs; in, out, cc = in[bcs:], out[bcs:], cc[bcs:] {
		for i := 0; i < bcs; i++ {
			out[i] = a.state[i] ^ in[i]
			a.state[i] = cc[i]
		}
		a.perm(pB)
	}
	if len(in) >= 0 {
		for i := 0; i < len(in); i++ {
			out[i] = a.state[i] ^ in[i]
			a.state[i] = cc[i]
		}
		a.state[len(in)] ^= 0x80
	}
}

func (a *Cipher) finalize(tag []byte) {
	bcs := blockSize * int(a.mode)
	for i := 0; i < KeySize; i++ {
		a.state[bcs+i] ^= a.key[i]
	}
	a.perm(permA)
	for i := 0; i < KeySize; i++ {
		tag[i] = a.state[stateSize-KeySize+i] ^ a.key[i]
	}
}

func (a *Cipher) perm(n int) {
	x := [5]uint64{}
	x[0] = binary.BigEndian.Uint64(a.state[0:8])
	x[1] = binary.BigEndian.Uint64(a.state[8:16])
	x[2] = binary.BigEndian.Uint64(a.state[16:24])
	x[3] = binary.BigEndian.Uint64(a.state[24:32])
	x[4] = binary.BigEndian.Uint64(a.state[32:40])

	for i := 0; i < n; i++ {
		// pC -- addition of constants
		ri := i
		if n != permA {
			ri = i + permA - n
		}
		x[2] ^= roundConst[ri]

		// pS -- substitution layer
		for j := 0; j < 64; j++ {
			sx := subs[0|
				(((x[0]>>j)&0x1)<<4)|
				(((x[1]>>j)&0x1)<<3)|
				(((x[2]>>j)&0x1)<<2)|
				(((x[3]>>j)&0x1)<<1)|
				(((x[4]>>j)&0x1)<<0)]
			mask := uint64(1) << j
			x[0] = (x[0] &^ mask) | uint64((sx>>4)&0x1)<<j
			x[1] = (x[1] &^ mask) | uint64((sx>>3)&0x1)<<j
			x[2] = (x[2] &^ mask) | uint64((sx>>2)&0x1)<<j
			x[3] = (x[3] &^ mask) | uint64((sx>>1)&0x1)<<j
			x[4] = (x[4] &^ mask) | uint64((sx>>0)&0x1)<<j
		}

		// pL -- linear diffusion layer
		x[0] ^= bits.RotateLeft64(x[0], -19) ^ bits.RotateLeft64(x[0], -28)
		x[1] ^= bits.RotateLeft64(x[1], -61) ^ bits.RotateLeft64(x[1], -39)
		x[2] ^= bits.RotateLeft64(x[2], -1) ^ bits.RotateLeft64(x[2], -6)
		x[3] ^= bits.RotateLeft64(x[3], -10) ^ bits.RotateLeft64(x[3], -17)
		x[4] ^= bits.RotateLeft64(x[4], -7) ^ bits.RotateLeft64(x[4], -41)
	}

	binary.BigEndian.PutUint64(a.state[0:8], x[0])
	binary.BigEndian.PutUint64(a.state[8:16], x[1])
	binary.BigEndian.PutUint64(a.state[16:24], x[2])
	binary.BigEndian.PutUint64(a.state[24:32], x[3])
	binary.BigEndian.PutUint64(a.state[32:40], x[4])
}

var (
	ErrKeySize    = errors.New("ascon: bad key size")
	ErrNonceSize  = errors.New("ascon: bad nonce size")
	ErrDecryption = errors.New("ascon: invalid ciphertext")
	ErrMode       = errors.New("ascon: invalid cipher mode")
)
