package hpke

import (
	"crypto/cipher"
	"errors"
)

type encdecCtx struct {
	cipher.AEAD
	Suite
	baseNonce      []byte
	seq            []byte
	exporterSecret []byte
}

type sealCtx struct{ *encdecCtx }
type openCtx struct{ *encdecCtx }

func (c *encdecCtx) Export(expCtx []byte, len uint16) []byte {
	return c.labeledExpand(c.exporterSecret, []byte("sec"), expCtx, len)
}

func (c *encdecCtx) calcNonce() []byte {
	out := make([]byte, len(c.seq))
	for i := range c.baseNonce {
		out[i] = c.baseNonce[i] ^ c.seq[i]
	}
	return out
}

func (c *encdecCtx) inc() error {
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
		return errors.New("sequence number overflow")
	}
	return nil
}

func (c *sealCtx) Seal(pt, aad []byte) ([]byte, error) {
	ct := c.AEAD.Seal(nil, c.calcNonce(), pt, aad)
	err := c.inc()
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func (c *openCtx) Open(ct, aad []byte) ([]byte, error) {
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
