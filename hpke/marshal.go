package hpke

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// marshal serializes an HPKE context.
func (c *encdecContext) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(c.suite.KemID.uint16)
	b.AddUint16(c.suite.KdfID.uint16)
	b.AddUint16(c.suite.AeadID.uint16)
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
		b.AddBytes(c.sequenceNumber)
	})
	return b.Bytes()
}

// unmarshalContext parses an HPKE context.
func unmarshalContext(raw []byte) (*encdecContext, error) {
	var (
		err                  error
		kemID, kdfID, aeadID uint16
		t                    cryptobyte.String
	)

	c := new(encdecContext)
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
		!t.ReadBytes(&c.sequenceNumber, len(t)) {
		return nil, errors.New("failed to parse context")
	}

	kem, err := KEM.Parse(int(kemID))
	if err != nil {
		return nil, errInvalidKEM
	}

	kdf, err := KDF.Parse(int(kdfID))
	if err != nil {
		return nil, errInvalidKDF
	}

	aead, err := AEAD.Parse(int(aeadID))
	if err != nil {
		return nil, errInvalidAEAD
	}

	c.suite = Suite{*kem, *kdf, *aead}

	Nh := c.suite.KdfID.Hash().Size()
	if len(c.exporterSecret) != Nh {
		return nil, errors.New("invalid exporter secret length")
	}

	Nk := int(c.suite.AeadID.KeySize())
	if len(c.key) != Nk {
		return nil, errors.New("invalid key length")
	}

	c.AEAD, err = c.suite.AeadID.New(c.key)
	if err != nil {
		return nil, err
	}

	Nn := c.AEAD.NonceSize()
	if len(c.baseNonce) != Nn {
		return nil, errors.New("invalid base nonce length")
	}
	if len(c.sequenceNumber) != Nn {
		return nil, errors.New("invalid sequence number length")
	}

	return c, nil
}

// MarshalBinary serializes an HPKE sealer according to the format specified
// below. (Expressed in TLS syntax.) Note that this format is not defined by
// the HPKE standard.
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
func (c *sealContext) MarshalBinary() ([]byte, error) {
	rawContext, err := c.encdecContext.marshal()
	if err != nil {
		return nil, err
	}
	return append([]byte{0}, rawContext...), nil
}

// UnmarshalSealer parses an HPKE sealer.
func UnmarshalSealer(raw []byte) (Sealer, error) {
	if raw[0] != 0 {
		return nil, errors.New("incorrect role")
	}
	context, err := unmarshalContext(raw[1:])
	if err != nil {
		return nil, err
	}
	return &sealContext{context}, nil
}

// MarshalBinary serializes an HPKE opener according to the format specified
// below. (Expressed in TLS syntax.) Note that this format is not defined by the
// HPKE standard.
//
// struct {
//   HpkeRole role = 1; // opener
//   HpkeContext context;
// } HpkeOpener;
func (c *openContext) MarshalBinary() ([]byte, error) {
	rawContext, err := c.encdecContext.marshal()
	if err != nil {
		return nil, err
	}
	return append([]byte{1}, rawContext...), nil
}

// UnmarshalOpener parses a serialized HPKE opener and returns the corresponding
// Opener.
func UnmarshalOpener(raw []byte) (Opener, error) {
	if raw[0] != 1 {
		return nil, errors.New("incorrect role")
	}
	context, err := unmarshalContext(raw[1:])
	if err != nil {
		return nil, err
	}
	return &openContext{context}, nil
}
