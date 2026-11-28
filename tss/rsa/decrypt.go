package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"math"
	"math/big"

	"filippo.io/bigmod"
	"github.com/cloudflare/circl/tss/rsa/internal"
)

const minOAEPKeyBits = 2048

// OAEPDecrypter uses one trusted key share to produce partial RSA-OAEP
// decryptions. It is safe for concurrent use after successful construction.
// The key pair must be dedicated to encryption.
type OAEPDecrypter struct {
	n         *big.Int
	modulus   *bigmod.Modulus
	factor    []byte
	exponent  []byte
	index     uint
	players   uint
	threshold uint
}

// NewOAEPDecrypter prepares a trusted key share for RSA-OAEP decryption.
// The public key must match the private key passed to Deal and come from
// trusted key provisioning. An attacker-controlled modulus can disclose the
// long-term key share. Use a key pair dedicated to encryption.
// The modulus must be at least 2048 bits and the public exponent must be
// coprime to the factorial of the player count.
// Key-share validation and encoding during setup use variable-time math/big
// operations on the secret share. Construct the decrypter in a trusted setup
// path before handling requests, then reuse it. DecryptShare uses fixed-width
// exponentiation for the secret share.
func NewOAEPDecrypter(pub *rsa.PublicKey, share *KeyShare) (*OAEPDecrypter, error) {
	if share == nil || share.si == nil || share.Index == 0 || share.Index > share.Players {
		return nil, rsa.ErrDecryption
	}
	modulus, delta, err := decryptionModulus(pub, share.Players, share.Threshold)
	if err != nil || share.si.Sign() < 0 || share.si.BitLen() > modulus.BitLen() {
		return nil, rsa.ErrDecryption
	}
	return &OAEPDecrypter{
		n: new(big.Int).Set(pub.N), modulus: modulus, factor: delta.Lsh(delta, 1).Bytes(),
		exponent: share.si.FillBytes(make([]byte, modulus.Size())),
		index:    share.Index, players: share.Players, threshold: share.Threshold,
	}, nil
}

// DecryptShare calculates a partial RSA-OAEP decryption of ciphertext. The
// ciphertext must be exactly the modulus size in bytes and represent a value
// less than and coprime to the modulus. The result must be sent only to the
// intended combiner over a protected channel.
func (d *OAEPDecrypter) DecryptShare(ciphertext []byte) (DecryptionShare, error) {
	if d == nil || d.modulus == nil {
		return DecryptionShare{}, rsa.ErrDecryption
	}
	value, inverse, err := ciphertextRepresentatives(d.n, d.modulus, ciphertext)
	if err != nil {
		return DecryptionShare{}, err
	}
	return DecryptionShare{
		Index: d.index, Players: d.players, Threshold: d.threshold,
		ciphertextHash: sha256.Sum256(ciphertext),
		value:          d.exponentiate(value),
		inverse:        d.exponentiate(inverse),
	}, nil
}

func (d *OAEPDecrypter) exponentiate(base *bigmod.Nat) []byte {
	// The factor 2Δ and the base are public. The second exponentiation uses
	// the fixed-width secret share to compute (representative^2Δ)^s_i.
	power := bigmod.NewNat().Exp(base, d.factor, d.modulus)
	return bigmod.NewNat().Exp(power, d.exponent, d.modulus).Bytes(d.modulus)
}

// CombineDecryptionSharesOAEP recovers plaintext using SHA-256 for both OAEP
// and MGF1. The public key, player count and threshold must be trusted and the
// caller must authenticate each share's participant. The ciphertext and label
// must be identical to those used during encryption. The ciphertext must meet
// the same requirements as in DecryptShare. The final RSA result is checked
// before decoding. Malformed ciphertexts and shares return rsa.ErrDecryption.
func CombineDecryptionSharesOAEP(pub *rsa.PublicKey, players, threshold uint, shares []DecryptionShare, ciphertext, label []byte) ([]byte, error) {
	if uint(len(shares)) < threshold || uint(len(shares)) > players {
		return nil, rsa.ErrDecryption
	}
	modulus, delta, err := decryptionModulus(pub, players, threshold)
	if err != nil {
		return nil, err
	}
	encoded, err := combineDecryptionBlock(pub, modulus, delta, players, threshold, shares, ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	plaintext, err := internal.DecodeOAEP(encoded, label)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(plaintext), nil
}

func decryptionModulus(pub *rsa.PublicKey, players, threshold uint) (*bigmod.Modulus, *big.Int, error) {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.N.BitLen() < minOAEPKeyBits || pub.N.Bit(0) == 0 ||
		pub.E < 3 || pub.E > math.MaxInt32 || pub.E%2 == 0 || players > math.MaxUint16 || threshold < 2 || threshold > players {
		return nil, nil, rsa.ErrDecryption
	}
	modulus, err := bigmod.NewModulus(pub.N.Bytes())
	if err != nil {
		return nil, nil, rsa.ErrDecryption
	}
	delta := calculateDelta(int64(players))
	if new(big.Int).GCD(nil, nil, delta, big.NewInt(int64(pub.E))).Cmp(big.NewInt(1)) != 0 {
		return nil, nil, rsa.ErrDecryption
	}
	return modulus, delta, nil
}

func ciphertextRepresentatives(n *big.Int, modulus *bigmod.Modulus, ciphertext []byte) (value, inverse *bigmod.Nat, err error) {
	if len(ciphertext) != modulus.Size() {
		return nil, nil, rsa.ErrDecryption
	}
	value, err = bigmod.NewNat().SetBytes(ciphertext, modulus)
	if err != nil {
		return nil, nil, rsa.ErrDecryption
	}
	// Only the public ciphertext is inverted here. Negative interpolation
	// exponents use separately computed inverse shares during combination.
	inv := new(big.Int).ModInverse(new(big.Int).SetBytes(ciphertext), n)
	if inv == nil {
		return nil, nil, rsa.ErrDecryption
	}
	inverse, err = bigmod.NewNat().SetBytes(inv.Bytes(), modulus)
	if err != nil {
		return nil, nil, rsa.ErrDecryption
	}
	return value, inverse, nil
}

func combineDecryptionBlock(pub *rsa.PublicKey, modulus *bigmod.Modulus, delta *big.Int, players, threshold uint, shares []DecryptionShare, ciphertext []byte) ([]byte, error) {
	expected, inverse, err := ciphertextRepresentatives(pub.N, modulus, ciphertext)
	if err != nil {
		return nil, err
	}
	indices, err := decryptionIndices(shares, players, threshold, sha256.Sum256(ciphertext))
	if err != nil {
		return nil, err
	}
	// Find a and b such that 4Δ²a + eb = 1, as in Shoup's Protocol 1.
	var a, b big.Int
	e := big.NewInt(int64(pub.E))
	fourDeltaSquared := new(big.Int).Mul(delta, delta)
	fourDeltaSquared.Lsh(fourDeltaSquared, 2)
	// decryptionModulus verifies that e is odd and coprime to Δ.
	new(big.Int).GCD(&a, &b, fourDeltaSquared, e)
	base := expected
	if b.Sign() < 0 {
		base = inverse
	}
	result := bigmod.NewNat().Exp(base, b.Bytes(), modulus)
	for _, share := range shares {
		lambda, interpolationErr := computeLambda(delta, indices, 0, int64(share.Index), int64(players))
		if interpolationErr != nil {
			return nil, rsa.ErrDecryption
		}
		power := lambda.Mul(lambda, &a).Lsh(lambda, 1)
		part, shareErr := share.baseForExponent(modulus, power.Sign() < 0)
		if shareErr != nil {
			return nil, shareErr
		}
		result.Mul(bigmod.NewNat().Exp(part, power.Bytes(), modulus), modulus)
	}
	if bigmod.NewNat().Exp(result, e.Bytes(), modulus).Equal(expected) != 1 {
		return nil, rsa.ErrDecryption
	}
	return result.Bytes(modulus), nil
}

func decryptionIndices(shares []DecryptionShare, players, threshold uint, ciphertextHash [sha256.Size]byte) ([]SignShare, error) {
	indices := make([]SignShare, len(shares))
	seen := make(map[uint]bool, len(shares))
	for i, share := range shares {
		if share.Index == 0 || share.Index > players || share.Players != players || share.Threshold != threshold ||
			seen[share.Index] || share.ciphertextHash != ciphertextHash {
			return nil, rsa.ErrDecryption
		}
		seen[share.Index] = true
		// computeLambda reads only the participant index.
		indices[i].Index = share.Index
	}
	return indices, nil
}
