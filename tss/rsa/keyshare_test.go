package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestKeyShare_Sign(t *testing.T) {
	// delta = 3! = 6
	// n = 253
	// players = 3
	// kshare = { si: 15, Index: 1 }
	// x = { 150 }
	// x_i = x^{2∆kshare.si} = 150^{2 * 6 * 15} = 150^180 = 243

	players := 3
	kshare := KeyShare{
		si:    big.NewInt(15),
		Index: 1,
	}
	pub := rsa.PublicKey{N: big.NewInt(253)}
	share, err := kshare.Sign(nil, int64(players), &pub, []byte{150}, false)
	if err != nil {
		t.Fatal(err)
	}
	if share.xi.Cmp(big.NewInt(243)) != 0 {
		t.Fatalf("share.xi should be 243 but was %d", share.xi)
	}
}

func testSignBlind(parallel bool, t *testing.T) {
	// delta = 3! = 6
	// n = 253
	// players = 3
	// kshare = { si: 15, i: 1 }
	// x = { 150 }
	// x_i = x^{2∆kshare.si} = 150^{2 * 6 * 15} = 150^180 = 243

	players := 3
	kshare := KeyShare{
		si:    big.NewInt(15),
		Index: 1,
	}
	pub := rsa.PublicKey{N: big.NewInt(253)}
	share, err := kshare.Sign(rand.Reader, int64(players), &pub, []byte{150}, parallel)
	if err != nil {
		t.Fatal(err)
	}
	if share.xi.Cmp(big.NewInt(243)) != 0 {
		t.Fatalf("share.xi should be 243 but was %d", share.xi)
	}
}

func TestKeyShare_SignBlind(t *testing.T) {
	testSignBlind(false, t)
}

func TestKeyShare_SignBlindParallel(t *testing.T) {
	testSignBlind(true, t)
}

func marshalTestKeyShare(share KeyShare, t *testing.T) {
	marshall, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	share2 := KeyShare{}
	err = share2.UnmarshalBinary(marshall)
	if err != nil {
		t.Fatal(err)
	}

	if share.Index != share2.Index {
		t.Fatalf("Index did not match, expected %d, found %d", share.Index, share2.Index)
	}

	if (share.twoDeltaSi == nil || share2.twoDeltaSi == nil) && share.twoDeltaSi != share2.twoDeltaSi {
		t.Fatalf("twoDeltaSi did not match, expected %v, found %v", share.twoDeltaSi, share2.twoDeltaSi)
	}

	if !(share.twoDeltaSi == nil && share2.twoDeltaSi == nil) && share.twoDeltaSi.Cmp(share2.twoDeltaSi) != 0 {
		t.Fatalf("twoDeltaSi did not match, expected %v, found %v", share.twoDeltaSi.Bytes(), share2.twoDeltaSi.Bytes())
	}

	if share.si.Cmp(share2.si) != 0 {
		t.Fatalf("si did not match, expected %v, found %v", share.si.Bytes(), share2.si.Bytes())
	}
}

func TestMarshallKeyShare(t *testing.T) {
	marshalTestKeyShare(KeyShare{
		si:         big.NewInt(10),
		twoDeltaSi: big.NewInt(20),
		Index:      30,
	}, t)

	marshalTestKeyShare(KeyShare{
		si:         big.NewInt(10),
		twoDeltaSi: nil,
		Index:      30,
	}, t)

	marshalTestKeyShare(KeyShare{
		si:         big.NewInt(0),
		twoDeltaSi: big.NewInt(0),
		Index:      0,
	}, t)

	// | Index: uint8 | siLen: uint16 | si: []byte | twoDeltaSi: []byte |
	share := KeyShare{}
	err := share.UnmarshalBinary([]byte{})
	if err == nil {
		t.Fatalf("unmarshall succeeded when it shouldn't have")
	}

	share = KeyShare{}
	err = share.UnmarshalBinary([]byte{1, 0, 1})
	if err == nil {
		t.Fatalf("unmarshall succeeded when it shouldn't have")
	}
}

func TestMarshallKeyShareFull(t *testing.T) {
	const players = 3
	const threshold = 2
	const bits = 4096

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := Deal(rand.Reader, players, threshold, key, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, share := range keys {
		marshalTestKeyShare(share, t)
	}
}
