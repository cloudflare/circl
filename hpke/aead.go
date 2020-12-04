package hpke

import (
	"crypto/cipher"
	"errors"
	"fmt"
)

type encdecCtx struct {
	Suite
	cipher.AEAD
	baseNonce      []byte
	seq            []byte
	exporterSecret []byte
}

type sealCtx struct{ *encdecCtx }
type openCtx struct{ *encdecCtx }

func (c *encdecCtx) Export(expCtx []byte, length uint) []byte {
	maxLength := uint(255 * c.KdfID.Hash().Size())
	if length > maxLength {
		panic(fmt.Errorf("size greater than %v", maxLength))
	}
	return c.labeledExpand(c.exporterSecret, []byte("sec"), expCtx, uint16(length))
}

func (c *encdecCtx) calcNonce() []byte {
	nonce := (&[12]byte{})[:]
	if len := c.NonceSize(); len != 12 {
		nonce = make([]byte, len)
	}
	for i := range c.baseNonce {
		nonce[i] = c.baseNonce[i] ^ c.seq[i]
	}
	return nonce
}

func (c *encdecCtx) inc() error {
	max := byte(0xFF)
	of := max
	for i := range c.seq {
		of &= c.seq[i]
	}
	if of == max {
		return errors.New("sequence number overflow")
	}

	carry := uint(1)
	for i := len(c.seq) - 1; i >= 0; i-- {
		w := uint(c.seq[i]) + carry
		carry = w >> 8
		c.seq[i] = byte(w & 0xFF)
	}
	if carry != 0 {
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
