package hpke

import (
	"crypto/cipher"
)

type encdecContext struct {
	// Serialized parameters
	expContext
	key            []byte
	baseNonce      []byte
	sequenceNumber []byte

	// Operational parameters
	cipher.AEAD
	nonce []byte
}

type sealContext struct{ *encdecContext }
type openContext struct{ *encdecContext }

func (c *encdecContext) calcNonce() []byte {
	for i := range c.baseNonce {
		c.nonce[i] = c.baseNonce[i] ^ c.sequenceNumber[i]
	}
	return c.nonce
}

func (c *encdecContext) increment() error {
	// tests whether the sequence number is all-ones, which prevents an
	// overflow after the increment.
	allOnes := byte(0xFF)
	for i := range c.sequenceNumber {
		allOnes &= c.sequenceNumber[i]
	}
	if allOnes == byte(0xFF) {
		return errAEADSeqOverflows
	}

	// performs an increment by 1 and verifies whether the sequence overflows.
	carry := uint(1)
	for i := len(c.sequenceNumber) - 1; i >= 0; i-- {
		sum := uint(c.sequenceNumber[i]) + carry
		carry = sum >> 8
		c.sequenceNumber[i] = byte(sum & 0xFF)
	}
	if carry != 0 {
		return errAEADSeqOverflows
	}
	return nil
}

func (c *sealContext) Seal(pt, aad []byte) ([]byte, error) {
	ct := c.AEAD.Seal(nil, c.calcNonce(), pt, aad)
	err := c.increment()
	if err != nil {
		for i := range ct {
			ct[i] = 0
		}
		return nil, err
	}
	return ct, nil
}

func (c *openContext) Open(ct, aad []byte) ([]byte, error) {
	pt, err := c.AEAD.Open(nil, c.calcNonce(), ct, aad)
	if err != nil {
		return nil, err
	}
	err = c.increment()
	if err != nil {
		for i := range pt {
			pt[i] = 0
		}
		return nil, err
	}
	return pt, nil
}
