package hybrid

import (
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/kem"
)

func mustDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// patchHybridWithLowOrderX25519 replaces the last half of the given ciphertext
// or public key by a 32-byte Curve25519 public key with a point of low order.
func patchHybridWithLowOrderX25519(hybridKey []byte) {
	// order 8
	xPub := mustDecodeString("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
	copy(hybridKey[len(hybridKey)-len(xPub):], xPub)
}

func patchHybridPublicKeyWithLowOrderX25519(pub kem.PublicKey) (kem.PublicKey, error) {
	packed, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	patchHybridWithLowOrderX25519(packed)
	return pub.Scheme().UnmarshalBinaryPublicKey(packed)
}

func TestLowOrderX25519PointEncapsulate(t *testing.T) {
	scheme := X25519MLKEM768()
	pk, _, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("X25519MLKEM768 keygen: %s", err)
	}
	badPk, err := patchHybridPublicKeyWithLowOrderX25519(pk)
	if err != nil {
		t.Fatalf("patching X25519 key failed: %s", err)
	}
	_, _, err = scheme.Encapsulate(badPk)
	want := kem.ErrPubKey
	if err != want {
		t.Fatalf("Encapsulate error: expected %v; got %v", want, err)
	}
}

func TestLowOrderX25519PointDecapsulate(t *testing.T) {
	scheme := X25519MLKEM768()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("X25519MLKEM768 keygen: %s", err)
	}
	ct, _, err := scheme.Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate failed: %s", err)
	}
	patchHybridWithLowOrderX25519(ct)
	_, err = scheme.Decapsulate(sk, ct)
	want := kem.ErrPubKey
	if err != want {
		t.Fatalf("Decapsulate error: expected %v; got %v", want, err)
	}
}
