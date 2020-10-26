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
}

// DecContext is
type DecContext interface {
	Open(aad, ct []byte) (pt []byte, err error)
}

type encdecCxt struct {
	alg            aeadInfo
	aead           cipher.AEAD
	baseNonce      []byte
	seq            []byte
	exporterSecret []byte
}

func (ai aeadInfo) newCtx(key, baseNonce, exporter []byte) (*encdecCxt, error) {
	var aead cipher.AEAD
	var err error

	switch ai.ID {
	case AeadAES128GCM, AeadAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case AeadCC20P1305:
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("wrong AeadID")
	}
	return &encdecCxt{ai, aead, baseNonce, make([]byte, ai.Nn), exporter}, nil
}

func (c *encdecCxt) calcNonce() []byte {
	if len(c.baseNonce) != len(c.seq) {
		panic("wrong sizes")
	}
	out := make([]byte, len(c.seq))
	for i := range c.seq {
		out[i] = c.baseNonce[i] ^ c.seq[i]
	}
	return out
}

func (c *encdecCxt) inc() error {
	const max = uint32(0xFFFFFFFF)
	s0 := binary.BigEndian.Uint32(c.seq[8:12])
	s1 := binary.BigEndian.Uint32(c.seq[4:8])
	s2 := binary.BigEndian.Uint32(c.seq[0:4])
	if s0 == max && s1 == max && s2 == max {
		return errors.New("seq overflow")
	}
	r0, c0 := bits.Add32(s0, 1, 0)
	r1, c1 := bits.Add32(s1, 0, c0)
	r2, _ := bits.Add32(s2, 0, c1)
	binary.BigEndian.PutUint32(c.seq[8:12], r0)
	binary.BigEndian.PutUint32(c.seq[4:8], r1)
	binary.BigEndian.PutUint32(c.seq[0:4], r2)
	return nil
}

func (c *encdecCxt) Seal(aad, pt []byte) ([]byte, error) {
	ct := c.aead.Seal(nil, c.calcNonce(), pt, aad)
	err := c.inc()
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func (c *encdecCxt) Open(aad, ct []byte) ([]byte, error) {
	pt, err := c.aead.Open(nil, c.calcNonce(), ct, aad)
	if err != nil {
		return nil, err
	}
	err = c.inc()
	if err != nil {
		return nil, err
	}
	return pt, nil
}
