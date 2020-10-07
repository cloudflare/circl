// Package nist implements helpers to generate NIST's Known Answer Tests (KATs).
package nist

import (
	"crypto/aes"
)

// See NIST's PQCgenKAT.c.
type DRBG struct {
	key [32]byte
	v   [16]byte
}

func (g *DRBG) incV() {
	for j := 15; j >= 0; j-- {
		if g.v[j] == 255 {
			g.v[j] = 0
		} else {
			g.v[j]++
			break
		}
	}
}

// AES256_CTR_DRBG_Update(pd, &g.key, &g.v).
func (g *DRBG) update(pd *[48]byte) {
	var buf [48]byte
	b, _ := aes.NewCipher(g.key[:])
	for i := 0; i < 3; i++ {
		g.incV()
		b.Encrypt(buf[i*16:(i+1)*16], g.v[:])
	}
	if pd != nil {
		for i := 0; i < 48; i++ {
			buf[i] ^= pd[i]
		}
	}
	copy(g.key[:], buf[:32])
	copy(g.v[:], buf[32:])
}

// randombyte_init(seed, NULL, 256).
func NewDRBG(seed *[48]byte) (g DRBG) {
	g.update(seed)
	return
}

// randombytes.
func (g *DRBG) Fill(x []byte) {
	var block [16]byte

	b, _ := aes.NewCipher(g.key[:])
	for len(x) > 0 {
		g.incV()
		b.Encrypt(block[:], g.v[:])
		if len(x) < 16 {
			copy(x[:], block[:len(x)])
			break
		}
		copy(x[:], block[:])
		x = x[16:]
	}
	g.update(nil)
}
