package group

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// https://tools.ietf.org/html/draft-irtf-cfrg-ristretto255-decaf448-00#appendix-A.1
func TestGeneratorMultiples(t *testing.T) {
	encVec := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
		"6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
		"94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
		"da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
		"e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
		"f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
		"44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
		"903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
		"02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
		"20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
		"bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
		"e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
		"aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
		"46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
		"e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
	}

	g := Ristretto255
	base := g.NewElement()
	encBase, err := hex.DecodeString(encVec[0])
	if err != nil {
		t.Fatal("DecodeString")
	}
	err = base.UnmarshalBinary(encBase)
	if err != nil {
		t.Fatal("UnmarshalBinary")
	}
	if !base.IsIdentity() {
		t.Fatal("Base element is not identity")
	}

	for i := 1; i < len(encVec); i++ {
		base.Add(base, g.Generator())
		baseEnc, err := base.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary %d", i)
		}
		if hex.EncodeToString(baseEnc) != encVec[i] {
			t.Fatalf("Multiple %d mismatch", i)
		}
	}
}

// https://tools.ietf.org/html/draft-irtf-cfrg-ristretto255-decaf448-00#appendix-A.2
func TestInvalidEncodings(t *testing.T) {
	encVec := []string{
		// Non-canonical field encodings.
		"00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// The internal ristretto255 implementation ignores the MSB, so the following two encodings fail.
		// "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// Negative field elements.
		"0100000000000000000000000000000000000000000000000000000000000000",
		"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20",
		"c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
		"c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
		"47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
		"f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
		"87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
		// Non-square x^2.
		"26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
		"4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
		"de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
		"bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
		"2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
		"f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
		"8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
		"2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
		// Negative xy value.
		"3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
		"a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
		"d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e",
		"8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
		"32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b",
		"227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
		"5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e",
		"445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",
		// s = -1, which causes y = 0.
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}

	for i, enc := range encVec {
		raw, err := hex.DecodeString(enc)
		if err != nil {
			t.Fatal("DecodeString")
		}
		err = Ristretto255.NewElement().UnmarshalBinary(raw)
		if err == nil {
			t.Fatalf("Decode succeeded for vector %d: %v", i, enc)
		}
	}
}

// TestRistrettoScalarNonCanonical checks that scalar decoding rejects
// non-canonical encodings, i.e. any 32-byte string that is not the canonical
// little-endian encoding of an integer in the range [0, l). Previously the
// decoding delegated to go-ristretto Scalar.SetBytes, which masked bits
// 253-255 and reduced modulo l, silently accepting many distinct encodings of
// the same scalar (proof/key byte malleability). See RFC 9496 §4.4 and
// RFC 9497 §4.1.
func TestRistrettoScalarNonCanonical(t *testing.T) {
	// canonical encodings that MUST be accepted.
	valid := []string{
		// 0
		"0000000000000000000000000000000000000000000000000000000000000000",
		// 1
		"0100000000000000000000000000000000000000000000000000000000000000",
		// l-1, the largest canonical scalar.
		"ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
	}

	// non-canonical encodings that MUST be rejected.
	invalid := []string{
		// l, the group order (out of range: valid range is [0, l)).
		"edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
		// l+1.
		"eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
		// All ones: a value far larger than l with the top three bits set.
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// Scalar 1 with bit 255 set: the old masking behavior reduced this
		// to 1; it MUST now be rejected as non-canonical.
		"0100000000000000000000000000000000000000000000000000000000000080",
		// l-1 with the top three bits set (bits 253-255): masked to l-1 by
		// the old code; MUST now be rejected.
		"ecd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000f0",
	}

	for i, enc := range valid {
		raw, err := hex.DecodeString(enc)
		if err != nil {
			t.Fatal("DecodeString")
		}

		s := Ristretto255.NewScalar()
		if err = s.UnmarshalBinary(raw); err != nil {
			t.Errorf("UnmarshalBinary rejected canonical vector %d (%v): %v", i, enc, err)
		}

		// re-encoding a canonical scalar must yield the same bytes.
		out, err := s.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary %d", i)
		}
		if !bytes.Equal(out, raw) {
			t.Errorf("round-trip mismatch for vector %d: got %x want %s", i, out, enc)
		}

		// the cryptobyte path must also accept it.
		str := cryptobyte.String(raw)
		if ok := Ristretto255.NewScalar().(interface {
			Unmarshal(*cryptobyte.String) bool
		}).Unmarshal(&str); !ok {
			t.Errorf("Unmarshal rejected canonical vector %d (%v)", i, enc)
		}
	}

	for i, enc := range invalid {
		raw, err := hex.DecodeString(enc)
		if err != nil {
			t.Fatal("DecodeString")
		}

		if err = Ristretto255.NewScalar().UnmarshalBinary(raw); err == nil {
			t.Errorf("UnmarshalBinary accepted non-canonical vector %d (%v)", i, enc)
		}

		str := cryptobyte.String(raw)
		if ok := Ristretto255.NewScalar().(interface {
			Unmarshal(*cryptobyte.String) bool
		}).Unmarshal(&str); ok {
			t.Errorf("Unmarshal accepted non-canonical vector %d (%v)", i, enc)
		}
	}
}

func TestRistrettoElGamal(t *testing.T) {
	g := Ristretto255
	pk := g.NewElement()
	sk := g.RandomScalar(rand.Reader)
	pk.MulGen(sk)

	// El'Gamal encrypt a random element p into a ciphertext-pair (c1,c2)
	p := g.RandomElement(rand.Reader)
	r := g.RandomScalar(rand.Reader)
	c2 := g.NewElement()
	c1 := g.NewElement()
	c2.MulGen(r)
	c1.Mul(pk, r)
	c1.Add(c1, p)

	// Decrypt (c1,c2) back to p
	b := g.NewElement()
	p2 := g.NewElement()
	b.Mul(c2, sk)
	p2.Add(c1, b.Neg(b))

	if !p.IsEqual(p2) {
		t.Fatal("Encryption/decryption failed")
	}

	pEnc, err := p.MarshalBinary()
	if err != nil {
		t.Fatal("MarshalBinary")
	}
	p2Enc, err := p2.MarshalBinary()
	if err != nil {
		t.Fatal("MarshalBinary")
	}
	if !bytes.Equal(pEnc, p2Enc) {
		t.Fatal("Unequal encodings")
	}
}
