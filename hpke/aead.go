package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/bits"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncContext is
type EncContext interface {
	Seal(aad, pt []byte) (ct []byte, err error)
	Export(expCtx []byte, len uint16) []byte
}

// DecContext is
type DecContext interface {
	Open(aad, ct []byte) (pt []byte, err error)
}

type encdecCxt struct {
	cipher.AEAD
	m              Mode
	baseNonce      []byte
	seq            []byte
	exporterSecret []byte
}

func (m Mode) aeadCtx(id AeadID, key, baseNonce, exporter []byte) (*encdecCxt, error) {
	l := aeadParams[id].Nn
	if len(baseNonce) < int(l) {
		return nil, errors.New("wrong nonce size")
	}

	var aead cipher.AEAD
	var err error

	switch id {
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
	return &encdecCxt{aead, m, baseNonce, make([]byte, l), exporter}, nil
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
	l32 := len(c.seq) / 4
	carry := uint32(0)
	word := uint32(1)
	for i := l32 - 1; i >= 0; i-- {
		si := binary.BigEndian.Uint32(c.seq[4*i : 4*(i+1)])
		si, carry = bits.Add32(si, word, carry)
		binary.BigEndian.PutUint32(c.seq[4*i:4*(i+1)], si)
		word = 0
	}
	l8 := len(c.seq) % 4
	for i := l8 - 1; i >= 0; i-- {
		w := uint32(c.seq[i]) + carry
		carry = w >> 8
		c.seq[i] = byte(w & 0xFF)
	}
	if of == max || carry != 0 {
		return errors.New("seq overflow")
	}
	return nil
}

func (c *encdecCxt) Seal(pt, aad []byte) ([]byte, error) {
	ct := c.AEAD.Seal(nil, c.calcNonce(), pt, aad)
	err := c.inc()
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func (c *encdecCxt) Open(ct, aad []byte) ([]byte, error) {
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

func (c *encdecCxt) Export(expCtx []byte, len uint16) []byte {
	return c.m.labeledExpand(c.exporterSecret, []byte("sec"), expCtx, len)
}
