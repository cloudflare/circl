package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

type encdecCxt struct {
	cipher.AEAD
	s              Suite
	baseNonce      []byte
	seq            []byte
	exporterSecret []byte
}
type sealCxt struct{ *encdecCxt }
type openCxt struct{ *encdecCxt }

func (s Suite) aeadCtx(key, baseNonce, exporter []byte) (*encdecCxt, error) {
	l := aeadParams[s.AeadID].Nn
	if len(baseNonce) < int(l) {
		return nil, errors.New("wrong nonce size")
	}

	var aead cipher.AEAD
	var err error

	switch s.AeadID {
	case AeadAES128GCM, AeadAES256GCM:
		var block cipher.Block
		if block, err = aes.NewCipher(key); err == nil {
			aead, err = cipher.NewGCM(block)
		}
	case AeadCC20P1305:
		aead, err = chacha20poly1305.New(key)
	default:
		err = errors.New("wrong AeadID")
	}
	if err != nil {
		return nil, err
	}
	return &encdecCxt{aead, s, baseNonce, make([]byte, l), exporter}, nil
}

func (c *encdecCxt) Export(expCtx []byte, len uint16) []byte {
	return c.s.labeledExpand(c.exporterSecret, []byte("sec"), expCtx, len)
}

func (c *encdecCxt) calcNonce() []byte {
	out := make([]byte, len(c.seq))
	for i := range c.baseNonce {
		out[i] = c.baseNonce[i] ^ c.seq[i]
	}
	return out
}

func (c *encdecCxt) inc() error {
	max := byte(0xFF)
	of := max
	for i := range c.seq {
		of &= c.seq[i]
	}

	carry := uint(1)
	for i := len(c.seq) - 1; i >= 0; i-- {
		w := uint(c.seq[i]) + carry
		carry = w >> 8
		c.seq[i] = byte(w & 0xFF)
	}
	if of == max || carry != 0 {
		return errors.New("seq overflow")
	}
	return nil
}

func (c *sealCxt) Seal(pt, aad []byte) ([]byte, error) {
	ct := c.AEAD.Seal(nil, c.calcNonce(), pt, aad)
	err := c.inc()
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func (c *openCxt) Open(ct, aad []byte) ([]byte, error) {
	pt, err := c.AEAD.Open(nil, c.calcNonce(), ct, aad)
	if err != nil {
		return nil, err
	}
	err = c.inc()
	if err != nil {
		return nil, err
	}
	return pt, nil
}
