package hpke

import (
	"crypto/cipher"
	"errors"
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
