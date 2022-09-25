package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func marshalTestSignShare(share SignShare, t *testing.T) {
	marshall, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	share2 := SignShare{}
	err = share2.UnmarshalBinary(marshall)
	if err != nil {
		t.Fatal(err)
	}

	if share.Players != share2.Players {
		t.Fatalf("Players did not match, expected %d, found %d", share.Players, share2.Players)
	}

	if share.Threshold != share2.Threshold {
		t.Fatalf("Threshold did not match, expected %d, found %d", share.Threshold, share2.Threshold)
	}

	if share.Index != share2.Index {
		t.Fatalf("Index did not match, expected %d, found %d", share.Index, share2.Index)
	}

	if share.xi.Cmp(share2.xi) != 0 {
		t.Fatalf("si did not match, expected %v, found %v", share.xi.Bytes(), share2.xi.Bytes())
	}
}

func unmarshalSignShareTest(t *testing.T, input []byte) {
	share := SignShare{}
	err := share.UnmarshalBinary(input)
	if err == nil {
		t.Fatalf("unmarshall succeeded when it shouldn't have")
	}
}

func TestMarshallSignShare(t *testing.T) {
	marshalTestSignShare(SignShare{
		xi:        big.NewInt(10),
		Index:     30,
		Players:   16,
		Threshold: 18,
	}, t)

	marshalTestSignShare(SignShare{
		xi:        big.NewInt(0),
		Index:     0,
		Players:   0,
		Threshold: 0,
	}, t)

	unmarshalSignShareTest(t, []byte{})
	unmarshalSignShareTest(t, []byte{0, 0, 0})
	unmarshalSignShareTest(t, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	unmarshalSignShareTest(t, []byte{0, 0, 0, 0, 0, 0, 0, 1})
	unmarshalSignShareTest(t, []byte{0, 0, 0, 0, 0, 0, 0, 2, 1})
}

func TestMarshallFullSignShare(t *testing.T) {
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
		keyshare, err := share.Sign(rand.Reader, &key.PublicKey, []byte("Cloudflare!"), true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = keyshare.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
	}
}
