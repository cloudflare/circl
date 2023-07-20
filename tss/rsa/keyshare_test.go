package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestProtocol(t *testing.T) {
	const (
		bits      = 512
		Players   = 10
		Threshold = 5
	)

	priv, err := GenerateKey(rand.Reader, bits)
	pub := &priv.PublicKey
	test.CheckNoErr(t, err, fmt.Sprintf("cannot generate keys: %v", err))

	msg := []byte("Cloudflare!")
	hash := crypto.SHA256
	padded, err := PadHash(new(PKCS1v15Padder), hash, pub, msg)
	test.CheckNoErr(t, err, fmt.Sprintf("cannot pad message: %v", err))

	keyShares, err := Deal(rand.Reader, Players, Threshold, priv)
	test.CheckNoErr(t, err, fmt.Sprintf("cannot deal key shares: %v", err))

	test.CheckMarshal(t, &keyShares[0], new(KeyShare))

	signShares := make([]*SignShare, len(keyShares))
	for i := range keyShares {
		signShares[i], err = keyShares[i].Sign(rand.Reader, pub, padded, true)
		test.CheckNoErr(t, err, fmt.Sprintf("cannot create signature share: %v", err))

		err = signShares[i].Verify(pub, keyShares[i].VerifyKeys(), padded)
		test.CheckNoErr(t, err, fmt.Sprintf("signature share does not verify: %v", err))
	}

	test.CheckMarshal(t, signShares[0], new(SignShare))

	signature, err := CombineSignShares(pub, signShares, padded)
	test.CheckNoErr(t, err, fmt.Sprintf("cannot create RSA signature: %v", err))

	hasher := hash.New()
	hasher.Write(msg)
	hashed := hasher.Sum(nil)

	err = rsa.VerifyPKCS1v15(pub, hash, hashed, signature)
	test.CheckNoErr(t, err, fmt.Sprintf("RSA signature does not verify: %v", err))
}

func TestKeyShare_Sign(t *testing.T) {
	// delta = 3! = 6
	// n = 253
	// Players = 3
	// kshare = { si: 15, Index: 1 }
	// x = { 150 }
	// x_i = x^{2∆kshare.si} = 150^{2 * 6 * 15} = 150^180 = 243

	kshare := KeyShare{
		share: share{
			ModulusLength: 256,
			Threshold:     1,
			Players:       3,
			Index:         1,
		},
		si:         big.NewInt(15),
		twoDeltaSi: big.NewInt(180),
	}
	pub := rsa.PublicKey{N: big.NewInt(253)}
	share, err := kshare.Sign(nil, &pub, []byte{150}, false)
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
	// Players = 3
	// kshare = { si: 15, i: 1 }
	// x = { 150 }
	// x_i = x^{2∆kshare.si} = 150^{2 * 6 * 15} = 150^180 = 243

	kshare := KeyShare{
		share: share{
			ModulusLength: 256,
			Threshold:     1,
			Players:       3,
			Index:         1,
		},
		si:         big.NewInt(15),
		twoDeltaSi: big.NewInt(180),
	}
	pub := rsa.PublicKey{N: big.NewInt(253)}
	share, err := kshare.Sign(rand.Reader, &pub, []byte{150}, parallel)
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
