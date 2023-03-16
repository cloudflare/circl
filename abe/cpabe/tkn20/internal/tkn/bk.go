package tkn

import (
	"crypto/subtle"
	"fmt"
	"io"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/blake2b"
)

// This file is based on the techniques in
// https://www.iacr.org/archive/pkc2011/65710074/65710074.pdf that
// apply the Boneh-Katz transform to Attribute based encryption.

// Seed size is chosen based on the proof for BK transform
// (https://eprint.iacr.org/2004/261.pdf - page 12, theorem 2) to maintain the
// statistical hiding property. Their input is 448 bits -> 128 bits,
// whereas we require a seed size of 576 bits to ensure a 2^(-65) statistical difference
// for our output size of 256 bits.
const macKeySeedSize = 72

func blakeEncrypt(key []byte, msg []byte) ([]byte, error) {
	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, key)
	if err != nil {
		return nil, err
	}
	keystream := make([]byte, len(msg))
	_, err = io.ReadFull(xof, keystream)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(msg); i++ {
		keystream[i] ^= msg[i]
	}
	return keystream, nil
}

func blakeDecrypt(key []byte, msg []byte) ([]byte, error) {
	return blakeEncrypt(key, msg)
}

func blakeMac(key []byte, msg []byte) (tag []byte, err error) {
	mac, err := blake2b.New256(key)
	if err != nil {
		return nil, err
	}
	mac.Write(msg)
	tag = mac.Sum(nil)
	return
}

func expandSeed(seed []byte) (id []byte, macKey []byte, err error) {
	h1, err := blake2b.New256(nil)
	if err != nil {
		return nil, nil, err
	}
	h1.Write([]byte("id computation hash"))

	h2, err := blake2b.New256(nil)
	if err != nil {
		return nil, nil, err
	}
	h2.Write([]byte("key computation hash"))

	h1.Write(seed)
	h2.Write(seed)
	id = h1.Sum(nil)
	macKey = h2.Sum(nil)
	return
}

func DeriveAttributeKeysCCA(rand io.Reader, sp *SecretParams, attrs *Attributes) (*AttributesKey, error) {
	realAttrs := transformAttrsBK(attrs)
	return deriveAttributeKeys(rand, sp, realAttrs)
}

func EncryptCCA(rand io.Reader, public *PublicParams, policy *Policy, msg []byte) ([]byte, error) {
	seed := make([]byte, macKeySeedSize)
	_, err := io.ReadFull(rand, seed)
	if err != nil {
		return nil, err
	}
	id, macKey, err := expandSeed(seed)
	if err != nil {
		return nil, err
	}

	numid := &pairing.Scalar{}
	numid.SetBytes(id)

	encPolicy := policy.transformBK(numid)

	header, encPoint, err := encapsulate(rand, public, encPolicy)
	if err != nil {
		return nil, err
	}
	// Send the policy that was not enhanced. The receiver will recover with the ID.
	// This avoids a bug where we omit the check that the ID is correct
	header.p = policy
	C1, err := header.marshalBinary()
	if err != nil {
		return nil, err
	}
	env := make([]byte, len(seed)+len(msg))
	copy(env[0:len(seed)], seed)
	copy(env[len(seed):], msg)

	encKey, err := encPoint.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hashedEncKey := blake2b.Sum256(encKey)

	env, err = blakeEncrypt(hashedEncKey[:], env)
	if err != nil {
		return nil, err
	}
	macData := appendLenPrefixed(nil, C1)
	macData = appendLenPrefixed(macData, env)

	tag, err := blakeMac(macKey, macData)
	if err != nil {
		return nil, err
	}

	ret := appendLenPrefixed(nil, id)
	ret = appendLenPrefixed(ret, macData)
	ret = appendLenPrefixed(ret, tag)

	return ret, nil
}

func DecryptCCA(ciphertext []byte, key *AttributesKey) ([]byte, error) {
	id, rest, err := removeLenPrefixed(ciphertext)
	if err != nil {
		return nil, err
	}
	macData, rest, err := removeLenPrefixed(rest)
	if err != nil {
		return nil, err
	}
	tag, _, err := removeLenPrefixed(rest)
	if err != nil {
		return nil, err
	}
	C1, envRaw, err := removeLenPrefixed(macData)
	if err != nil {
		return nil, err
	}
	env, _, err := removeLenPrefixed(envRaw)
	if err != nil {
		return nil, err
	}

	header := &ciphertextHeader{}
	err = header.unmarshalBinary(C1)
	if err != nil {
		return nil, err
	}

	numid := &pairing.Scalar{}
	numid.SetBytes(id)

	header.p = header.p.transformBK(numid)

	encPoint, err := decapsulate(header, key)
	if err != nil {
		return nil, fmt.Errorf("error in decryption: %w", err)
	}
	encKey, err := encPoint.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hashedEncKey := blake2b.Sum256(encKey)

	// Decrypt the envelope
	decEnv, err := blakeDecrypt(hashedEncKey[:], env)
	if err != nil {
		return nil, err
	}
	if len(decEnv) < macKeySeedSize {
		return nil, fmt.Errorf("envelope too short")
	}

	seed := decEnv[0:macKeySeedSize]
	ptx := make([]byte, len(decEnv)-macKeySeedSize)
	compID, macKey, err := expandSeed(seed)
	if err != nil {
		return nil, err
	}
	compTag, err := blakeMac(macKey, macData)
	if err != nil {
		return nil, err
	}

	// Now check that compTag = tag and compID = id
	// We don't want to distinguish which fails.
	tagMatch := subtle.ConstantTimeCompare(compTag, tag)
	idMatch := subtle.ConstantTimeCompare(compID, id)
	check := tagMatch & idMatch
	if check == 1 {
		copy(ptx, decEnv[macKeySeedSize:])
		return ptx, nil
	}
	return nil, fmt.Errorf("failure of decryption")
}

func CouldDecrypt(ciphertext []byte, a *Attributes) bool {
	id, rest, err := removeLenPrefixed(ciphertext)
	if err != nil {
		return false
	}
	macData, _, err := removeLenPrefixed(rest)
	if err != nil {
		return false
	}
	C1, _, err := removeLenPrefixed(macData)
	if err != nil {
		return false
	}

	header := &ciphertextHeader{}
	err = header.unmarshalBinary(C1)
	if err != nil {
		return false
	}

	numid := &pairing.Scalar{}
	numid.SetBytes(id)

	header.p = header.p.transformBK(numid)
	realAttrs := transformAttrsBK(a)
	_, err = header.p.Satisfaction(realAttrs)
	return err == nil
}

func (p *Policy) ExtractFromCiphertext(ct []byte) error {
	_, rest, err := removeLenPrefixed(ct)
	if err != nil {
		return fmt.Errorf("invalid ciphertext")
	}
	macData, _, err := removeLenPrefixed(rest)
	if err != nil {
		return fmt.Errorf("invalid ciphetext")
	}
	C1, _, err := removeLenPrefixed(macData)
	if err != nil {
		return fmt.Errorf("invalid ciphertext")
	}

	header := &ciphertextHeader{}
	err = header.unmarshalBinary(C1)
	if err != nil {
		return fmt.Errorf("invalid ciphertext")
	}
	*p = *header.p
	return nil
}
