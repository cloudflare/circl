package dilithium

import (
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/sign/schemes"

	"github.com/cloudflare/circl/internal/sha3"
)

func hexHash(in []byte) string {
	var ret [16]byte
	h := sha3.NewShake256()
	_, _ = h.Write(in[:])
	_, _ = h.Read(ret[:])
	return hex.EncodeToString(ret[:])
}

func TestNewKeyFromSeed(t *testing.T) {
	// Test vectors generated from reference implementation
	for _, tc := range []struct {
		name string
		esk  string
		epk  string
	}{
		{
			"Dilithium2", "afe2e91f5f5899354230744c18410498",
			"7522162619f3329b5312322d3ee45b87",
		},
		{
			"Dilithium3", "8ad3142e08b718b33f7c2668cd9d053c",
			"3562fc184dce1a10aad099051705b5d3",
		},
		{
			"Dilithium5", "3956d812a7961af6e5dad16af15c736c",
			"665388291aa01e12e7f94bdc7769db18",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := schemes.ByName(tc.name)
			if mode == nil {
				t.Fatal()
			}
			var seed [32]byte
			pk, sk := mode.DeriveKey(seed[:])

			ppk, err := pk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			psk, err := sk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			pkh := hexHash(ppk)
			skh := hexHash(psk)
			if pkh != tc.epk {
				t.Fatalf("%s expected pk %s, got %s", tc.name, tc.epk, pkh)
			}
			if skh != tc.esk {
				t.Fatalf("%s expected pk %s, got %s", tc.name, tc.esk, skh)
			}
		})
	}
}
