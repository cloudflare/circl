package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"strconv"
	"testing"
)

func TestThresholdDecryptOAEP(t *testing.T) {
	for _, bits := range []int{2048, 3072, 4096} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			testThresholdDecryptOAEP(t, bits)
		})
	}
}

func testThresholdDecryptOAEP(t *testing.T, bits int) {
	t.Helper()
	key, keyErr := rsa.GenerateKey(rand.Reader, bits)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	public := &key.PublicKey
	keyShares, dealErr := Deal(rand.Reader, 3, 2, key, false)
	if dealErr != nil {
		t.Fatal(dealErr)
	}
	if _, err := NewOAEPDecrypter(&rsa.PublicKey{N: public.N, E: 3}, &keyShares[0]); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("public exponent sharing a factor with 3! returned %v", err)
	}
	message, label := []byte("threshold RSA decryption"), []byte("test label")
	ciphertext, encryptErr := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, message, label)
	if encryptErr != nil {
		t.Fatal(encryptErr)
	}
	aboveModulus := new(big.Int).Add(public.N, big.NewInt(1))
	disallowedCiphertexts := [][]byte{
		ciphertext[1:], make([]byte, key.Size()), public.N.Bytes(),
		aboveModulus.Bytes(), key.Primes[0].FillBytes(make([]byte, key.Size())),
	}
	var parts [3]DecryptionShare
	for i := range keyShares {
		decrypter := restoreOAEPDecrypter(t, public, &keyShares[i])
		for _, invalid := range disallowedCiphertexts {
			if _, err := decrypter.DecryptShare(invalid); !errors.Is(err, rsa.ErrDecryption) {
				t.Errorf("invalid ciphertext returned %v", err)
			}
		}
		parts[i] = transferDecryptionShare(t, decrypter, ciphertext)
	}
	for _, pair := range [][2]int{{0, 1}, {2, 0}, {1, 2}} {
		pairParts := []DecryptionShare{parts[pair[0]], parts[pair[1]]}
		plaintext, err := CombineDecryptionSharesOAEP(public, 3, 2, pairParts, ciphertext, label)
		if err != nil || !bytes.Equal(plaintext, message) {
			t.Errorf("pair %v could not decrypt: %v", pair, err)
		}
	}
	if got, err := CombineDecryptionSharesOAEP(public, 3, 2, parts[:], ciphertext, label); err != nil || !bytes.Equal(got, message) {
		t.Errorf("three shares could not decrypt: %v", err)
	}
	bad := parts[1]
	bad.value = make([]byte, key.Size())
	bad.value[key.Size()-1] = 1
	bad.inverse = bytes.Clone(bad.value)
	if _, err := CombineDecryptionSharesOAEP(public, 3, 2, []DecryptionShare{parts[0], bad}, ciphertext, label); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("invalid share with a matching inverse returned %v", err)
	}
	bad = parts[1]
	bad.inverse = make([]byte, key.Size())
	if _, err := CombineDecryptionSharesOAEP(public, 3, 2, []DecryptionShare{parts[0], bad}, ciphertext, label); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("invalid inverse returned %v", err)
	}
	bad = parts[1]
	bad.value = append(bytes.Clone(bad.value), 0)
	bad.inverse = append(bytes.Clone(bad.inverse), 0)
	if _, err := CombineDecryptionSharesOAEP(public, 3, 2, []DecryptionShare{parts[0], bad}, ciphertext, label); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("shares with a different modulus width returned %v", err)
	}
	if _, err := CombineDecryptionSharesOAEP(public, 3, 2, parts[:1], ciphertext, label); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("insufficient shares returned %v", err)
	}
	if _, err := CombineDecryptionSharesOAEP(public, 3, 2, []DecryptionShare{parts[0], parts[0]}, ciphertext, label); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("duplicate shares returned %v", err)
	}
	if _, err := CombineDecryptionSharesOAEP(public, 3, 2, parts[:2], ciphertext, nil); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("incorrect OAEP label returned %v", err)
	}
	other, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, message, label)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CombineDecryptionSharesOAEP(public, 3, 2, parts[:2], other, label); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("shares for another ciphertext returned %v", err)
	}
}

func TestThresholdDecryptOAEPUnorderedShares(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// For e=65537, rosters of five and ten exercise opposite signs of the
	// ciphertext exponent in the Bézout relation.
	for _, players := range []int{5, 10} {
		t.Run(strconv.Itoa(players), func(t *testing.T) {
			testThresholdDecryptOAEPUnorderedShares(t, key, players)
		})
	}
}

func testThresholdDecryptOAEPUnorderedShares(t *testing.T, key *rsa.PrivateKey, players int) {
	t.Helper()
	public := &key.PublicKey
	shares, err := Deal(rand.Reader, uint(players), 3, key, true)
	if err != nil {
		t.Fatal(err)
	}
	var decrypters [3]*OAEPDecrypter
	for i, index := range [3]int{4, 0, 2} {
		decrypters[i] = restoreOAEPDecrypter(t, public, &shares[index])
	}
	for _, size := range []int{0, key.Size() - 2*sha256.Size - 2} {
		message := bytes.Repeat([]byte{0x42}, size)
		ciphertext, encryptErr := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, message, nil)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		var parts [3]DecryptionShare
		for i, decrypter := range decrypters {
			parts[i] = transferDecryptionShare(t, decrypter, ciphertext)
		}
		if _, combineErr := CombineDecryptionSharesOAEP(public, uint(players), 3, parts[:2], ciphertext, nil); !errors.Is(combineErr, rsa.ErrDecryption) {
			t.Errorf("two of %d shares returned %v", players, combineErr)
		}
		got, combineErr := CombineDecryptionSharesOAEP(public, uint(players), 3, parts[:], ciphertext, nil)
		if combineErr != nil || !bytes.Equal(got, message) {
			t.Errorf("three of %d shares could not decrypt %d bytes: %v", players, size, combineErr)
		}
	}
}

func restoreOAEPDecrypter(t *testing.T, public *rsa.PublicKey, share *KeyShare) *OAEPDecrypter {
	t.Helper()
	stored, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var restored KeyShare
	if unmarshalErr := restored.UnmarshalBinary(stored); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	decrypter, err := NewOAEPDecrypter(public, &restored)
	if err != nil {
		t.Fatal(err)
	}
	return decrypter
}

func transferDecryptionShare(t *testing.T, decrypter *OAEPDecrypter, ciphertext []byte) DecryptionShare {
	t.Helper()
	part, err := decrypter.DecryptShare(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := part.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var received DecryptionShare
	if err := received.UnmarshalBinary(encoded[:len(encoded)-1]); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("truncated share returned %v", err)
	}
	zeroIndex := bytes.Clone(encoded)
	clear(zeroIndex[:2])
	if err := received.UnmarshalBinary(zeroIndex); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("zero index in a serialized share returned %v", err)
	}
	part.Index = 0
	if _, err := part.MarshalBinary(); !errors.Is(err, rsa.ErrDecryption) {
		t.Errorf("marshaling a share with zero index returned %v", err)
	}
	if err := received.UnmarshalBinary(encoded); err != nil {
		t.Fatal(err)
	}
	return received
}
