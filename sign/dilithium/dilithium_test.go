package dilithium

import (
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
)

func hexHash(in []byte) string {
	var ret [16]byte
	h := sha3.NewShake256()
	_, _ = h.Write(in[:])
	_, _ = h.Read(ret[:])
	return hex.EncodeToString(ret[:])
}

func testNewKeyFromSeed(t *testing.T, name, esk, epk string) {
	mode := ModeByName(name)
	if mode == nil {
		t.Fatal()
	}
	var seed [96]byte
	h := sha3.NewShake128()
	_, _ = h.Write(make([]byte, mode.SeedSize()))
	_, _ = h.Read(seed[:])
	pk, sk := mode.NewKeyFromExpandedSeed(&seed)
	pkh := hexHash(pk.Bytes())
	skh := hexHash(sk.Bytes())
	if pkh != epk {
		t.Fatalf("%s expected pk %s, got %s", name, epk, pkh)
	}
	if skh != esk {
		t.Fatalf("%s expected pk %s, got %s", name, esk, skh)
	}
}

func TestNewKeyFromSeed(t *testing.T) {
	// Test vectors generated from reference implementation
	testNewKeyFromSeed(t, "Dilithium1",
		"af470e12a57d00c04c4a2b5998f41c71", "83616951b98312a97ea10e12b7b69675")
	testNewKeyFromSeed(t, "Dilithium2",
		"48dec3d688330dfc68f9bf4277fb92e1", "38e7339d00e64348cb2f965ecf9ee38b")
	testNewKeyFromSeed(t, "Dilithium3",
		"a44fcf1f43d124865c63cbf381a3b7eb", "b725d31fb709664f8587e2fb6a60fe80")
	testNewKeyFromSeed(t, "Dilithium4",
		"e054319bbabd2e156c56e8ee923c2a8e", "e7997fc71a6796056d4633a40769c495")
	testNewKeyFromSeed(t, "Dilithium1-AES",
		"be55853ce1d2c1113fc96f1295928789", "7782ac146d9e636221329cfe64647112")
	testNewKeyFromSeed(t, "Dilithium2-AES",
		"2abfd0d294ce1b2bab5b860482c4bbc1", "23c4e9516662394e88e559cf2874d7a4")
	testNewKeyFromSeed(t, "Dilithium3-AES",
		"ba72ed309182aa509e595013b3ad9089", "887baaf3a98d0aa6b95c8c1a6867e609")
	testNewKeyFromSeed(t, "Dilithium4-AES",
		"7c1c8b5df63fd096901da43c00fa71e8", "f7f850c1d8ff82c868ab2f188ac624b3")
}
