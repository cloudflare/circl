// Package ascon provides ASCON family of light-weight AEAD ciphers.
//
// This package implements Ascon128 and Ascon128a two AEAD ciphers as specified
// in ASCON v1.2 by C. Dobraunig, M. Eichlseder, F. Mendel, M. Schläffer.
// https://ascon.iaik.tugraz.at/index.html
//
// It also implements Ascon-80pq, which has an increased key-size to provide
// more resistance against a quantum adversary using Grover’s algorithm for
// key search. Since Ascon-128 and Ascon-80pq share the same building blocks
// and same parameters except the size of the key, it is claimed the same
// security for Ascon-80pq against classical attacks as for Ascon-128.
package ascon

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	KeySize     = 16 // For Ascon128 and Ascon128a.
	KeySize80pq = 20 // Only for Ascon80pq.
	NonceSize   = 16
	TagSize     = 16
)

type Mode int

// KeySize is 16 for Ascon128 and Ascon128a, or 20 for Ascon80pq.
func (m Mode) KeySize() int {
	switch m {
	case Ascon128, Ascon128a, Ascon80pq:
		v := int(m) >> 2
		return KeySize&^v | KeySize80pq&v
	default:
		panic(ErrMode)
	}
}

func (m Mode) String() string {
	switch m {
	case Ascon128:
		return "Ascon128"
	case Ascon128a:
		return "Ascon128a"
	case Ascon80pq:
		return "Ascon80pq"
	default:
		panic(ErrMode)
	}
}

const (
	Ascon128  Mode = 1
	Ascon128a Mode = 2
	Ascon80pq Mode = -1
)

const permA = 12

type Cipher struct {
	key  [3]uint64
	mode Mode
}

// New returns a Cipher struct implementing the crypto/cipher.AEAD interface.
// The key must be Mode.KeySize() bytes long, and the mode is one of Ascon128,
// Ascon128a or Ascon80pq.
func New(key []byte, m Mode) (*Cipher, error) {
	if (m == Ascon128 || m == Ascon128a) && len(key) != KeySize {
		return nil, ErrKeySize
	}
	if m == Ascon80pq && len(key) != KeySize80pq {
		return nil, ErrKeySize
	}
	if !(m == Ascon128 || m == Ascon128a || m == Ascon80pq) {
		return nil, ErrMode
	}
	c := new(Cipher)
	c.mode = m
	if m == Ascon80pq {
		c.key[0] = uint64(binary.BigEndian.Uint32(key[0:4]))
		c.key[1] = binary.BigEndian.Uint64(key[4:12])
		c.key[2] = binary.BigEndian.Uint64(key[12:20])
	} else {
		c.key[0] = 0
		c.key[1] = binary.BigEndian.Uint64(key[0:8])
		c.key[2] = binary.BigEndian.Uint64(key[8:16])
	}

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
	ret, out := sliceForAppend(dst, ptLen+TagSize)
	ciphertext, tag := out[:ptLen], out[ptLen:]

	var s [5]uint64
	a.initialize(nonce, &s)
	a.assocData(additionalData, &s)
	a.procText(plaintext, ciphertext, true, &s)
	a.finalize(tag, &s)

	return ret
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
	ret, out := sliceForAppend(dst, ptLen)
	plaintext := out[:ptLen]
	ciphertext, tag0 := ciphertext[:ptLen], ciphertext[ptLen:]
	tag1 := (&[TagSize]byte{})[:]

	var s [5]uint64
	a.initialize(nonce, &s)
	a.assocData(additionalData, &s)
	a.procText(ciphertext, plaintext, false, &s)
	a.finalize(tag1, &s)

	if subtle.ConstantTimeCompare(tag0, tag1) == 0 {
		return nil, ErrDecryption
	}

	return ret, nil
}

func abs(x int) int { m := uint(x >> (bits.UintSize - 1)); return int((uint(x) + m) ^ m) }

// blockSize = 8 for Ascon128 and Ascon80pq, or 16 for Ascon128a.
func (a *Cipher) blockSize() int { return abs(int(a.mode)) << 3 }

// permB = 6 for Ascon128 and Ascon80pq, or 8 for Ascon128a.
func (a *Cipher) permB() int { return (abs(int(a.mode)) + 2) << 1 }

func (a *Cipher) initialize(nonce []byte, s *[5]uint64) {
	bcs := uint64(a.blockSize())
	pB := uint64(a.permB())
	kS := uint64(a.mode.KeySize())

	s[0] = ((kS * 8) << 56) | ((bcs * 8) << 48) | (permA << 40) | (pB << 32) | a.key[0]
	s[1] = a.key[1]
	s[2] = a.key[2]
	s[3] = binary.BigEndian.Uint64(nonce[0:8])
	s[4] = binary.BigEndian.Uint64(nonce[8:16])

	perm(permA, s)

	s[2] ^= a.key[0]
	s[3] ^= a.key[1]
	s[4] ^= a.key[2]
}

func (a *Cipher) assocData(add []byte, s *[5]uint64) {
	bcs := a.blockSize()
	pB := a.permB()
	if len(add) > 0 {
		for ; len(add) >= bcs; add = add[bcs:] {
			for i := 0; i < bcs; i += 8 {
				s[i/8] ^= binary.BigEndian.Uint64(add[i : i+8])
			}
			perm(pB, s)
		}
		for i := 0; i < len(add); i++ {
			s[i/8] ^= uint64(add[i]) << (56 - 8*(i%8))
		}
		s[len(add)/8] ^= uint64(0x80) << (56 - 8*(len(add)%8))
		perm(pB, s)
	}
	s[4] ^= 0x01
}

func (a *Cipher) procText(in, out []byte, enc bool, s *[5]uint64) {
	bcs := a.blockSize()
	pB := a.permB()
	mask := uint64(0)
	if enc {
		mask -= 1
	}

	for ; len(in) >= bcs; in, out = in[bcs:], out[bcs:] {
		for i := 0; i < bcs; i += 8 {
			inW := binary.BigEndian.Uint64(in[i : i+8])
			outW := s[i/8] ^ inW
			binary.BigEndian.PutUint64(out[i:i+8], outW)

			s[i/8] = (inW &^ mask) | (outW & mask)
		}
		perm(pB, s)
	}

	mask8 := byte(mask & 0xFF)
	for i := 0; i < len(in); i++ {
		off := 56 - (8 * (i % 8))
		si := byte((s[i/8] >> off) & 0xFF)
		inB := in[i]
		outB := si ^ inB
		out[i] = outB
		ss := inB&^mask8 | outB&mask8
		s[i/8] = (s[i/8] &^ (0xFF << off)) | uint64(ss)<<off
	}
	s[len(in)/8] ^= uint64(0x80) << (56 - 8*(len(in)%8))
}

func (a *Cipher) finalize(tag []byte, s *[5]uint64) {
	bcs := a.blockSize()
	if a.mode == Ascon80pq {
		s[bcs/8+0] ^= a.key[0]<<32 | a.key[1]>>32
		s[bcs/8+1] ^= a.key[1]<<32 | a.key[2]>>32
		s[bcs/8+2] ^= a.key[2] << 32
	} else {
		s[bcs/8+0] ^= a.key[1]
		s[bcs/8+1] ^= a.key[2]
	}

	perm(permA, s)
	binary.BigEndian.PutUint64(tag[0:8], s[3]^a.key[1])
	binary.BigEndian.PutUint64(tag[8:16], s[4]^a.key[2])
}

func perm(n int, s *[5]uint64) {
	x0, x1, x2, x3, x4 := s[0], s[1], s[2], s[3], s[4]
	for i := permA - n; i < permA; i++ {
		// pC -- addition of constants
		x2 ^= uint64((0xF-i)<<4 | i)

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
	s[0], s[1], s[2], s[3], s[4] = x0, x1, x2, x3, x4
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

var (
	ErrKeySize    = errors.New("ascon: bad key size")
	ErrNonceSize  = errors.New("ascon: bad nonce size")
	ErrDecryption = errors.New("ascon: invalid ciphertext")
	ErrMode       = errors.New("ascon: invalid cipher mode")
)
