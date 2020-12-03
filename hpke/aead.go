package hpke

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

type encdecCtx struct {
	raw []byte

	// parsed from raw
	suite          Suite
	exporterSecret []byte
	key            []byte
	baseNonce      []byte
	seq            []byte

	// operational parameters
	cipher.AEAD
}

type sealCtx struct {
	raw []byte
	*encdecCtx
}

type openCtx struct {
	raw []byte
	*encdecCtx
}

func (c *encdecCtx) Export(expCtx []byte, length uint) []byte {
	maxLength := uint(255 * c.suite.KdfID.Hash().Size())
	if length > maxLength {
		panic(fmt.Errorf("size greater than %v", maxLength))
	}
	return c.suite.labeledExpand(c.exporterSecret, []byte("sec"), expCtx, uint16(length))
}

func (c *encdecCtx) Suite() Suite {
	return c.suite
}

// marshal serializes an HPKE context.
func (c *encdecCtx) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(c.suite.KemID))
	b.AddUint16(uint16(c.suite.KdfID))
	b.AddUint16(uint16(c.suite.AeadID))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.exporterSecret)
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.key)
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.baseNonce)
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.seq)
	})
	return b.Bytes()
}

// unmarshalContext parses an HPKE context.
func unmarshalContext(raw []byte) (*encdecCtx, error) {
	var (
		err                  error
		kemID, kdfID, aeadID uint16
		t                    cryptobyte.String
	)

	c := new(encdecCtx)
	s := cryptobyte.String(raw)
	if !s.ReadUint16(&kemID) ||
		!s.ReadUint16(&kdfID) ||
		!s.ReadUint16(&aeadID) ||
		!s.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&c.exporterSecret, len(t)) ||
		!s.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&c.key, len(t)) ||
		!s.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&c.baseNonce, len(t)) ||
		!s.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&c.seq, len(t)) {
		return nil, errors.New("failed to parse context")
	}

	c.suite.KemID = KemID(kemID)
	c.suite.KdfID = KdfID(kdfID)
	c.suite.AeadID = AeadID(aeadID)
	if !c.suite.isValid() {
		return nil, errors.New("invalid suite")
	}

	Nh := c.suite.KdfID.Hash().Size()
	if len(c.exporterSecret) != Nh {
		return nil, errors.New("invalid exporter secret")
	}

	Nk := int(c.suite.AeadID.KeySize())
	if len(c.key) != Nk {
		return nil, errors.New("invalid key")
	}

	c.AEAD, err = c.suite.AeadID.New(c.key)
	if err != nil {
		return nil, err
	}

	Nn := c.AEAD.NonceSize()
	if len(c.baseNonce) != Nn {
		return nil, errors.New("invalid base nonce")
	}
	if len(c.seq) != Nn {
		return nil, errors.New("invalid sequence number")
	}

	return c, nil
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

// Marshal serializes an HPKE sealer according to the format specified below.
// (expressed in TLS syntax). Note that this format is not defined by the HPKE
// standard.
//
// enum { sealer(0), opener(1) } HpkeRole;
//
// struct {
//     HpkeKemId kem_id;   // draft-irtf-cfrg-hpke-06
//     HpkeKdfId kdf_id;   // draft-irtf-cfrg-hpke-06
//     HpkeAeadId aead_id; // draft-irtf-cfrg-hpke-06
//     opaque exporter_secret<0..255>;
//     opaque key<0..255>;
//     opaque base_nonce<0..255>;
//     opaque seq<0..255>;
// } HpkeContext;
//
// struct {
//   HpkeRole role = 0; // sealer
//   HpkeContext context;
// } HpkeSealer;
func (c *sealCtx) Marshal() ([]byte, error) {
	rawCtx, err := c.encdecCtx.marshal()
	if err != nil {
		return nil, err
	}
	c.raw = append([]byte{0}, rawCtx...)
	return c.raw, nil
}

// UnmarshalSealer parses an HPKE sealer.
func UnmarshalSealer(raw []byte) (Sealer, error) {
	if raw[0] != 0 {
		return nil, errors.New("incorrect role")
	}
	ctx, err := unmarshalContext(raw[1:])
	if err != nil {
		return nil, err
	}
	return &sealCtx{raw, ctx}, nil
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

// Marshal serializes an HPKE opener according to the format specified below
// (expressed in TLS syntax). Note that this format is not defined by the HPKE
// standard.
//
// struct {
//   HpkeRole role = 1; // opener
//   HpkeContext context;
// } HpkeOpener;
func (c *openCtx) Marshal() ([]byte, error) {
	rawCtx, err := c.encdecCtx.marshal()
	if err != nil {
		return nil, err
	}
	c.raw = append([]byte{1}, rawCtx...)
	return c.raw, nil
}

// UnmarshalOpener parses a serialized HPKE opener and returns the corresponding
// Opener.
func UnmarshalOpener(raw []byte) (Opener, error) {
	if raw[0] != 1 {
		return nil, errors.New("incorrect role")
	}
	ctx, err := unmarshalContext(raw[1:])
	if err != nil {
		return nil, err
	}
	return &openCtx{raw, ctx}, nil
}
