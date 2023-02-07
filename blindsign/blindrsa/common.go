package blindrsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"math/big"
)

func encodeMessageMetadata(message, metadata []byte) []byte {
	lenBuffer := []byte{'m', 's', 'g', 0, 0, 0, 0}

	binary.BigEndian.PutUint32(lenBuffer[3:], uint32(len(metadata)))
	framedMetadata := append(lenBuffer, metadata...)
	return append(framedMetadata, message...)
}

func verifyPSS(pub *BigPublicKey, hash crypto.Hash, digest []byte, sig []byte, opts *rsa.PSSOptions) error {
	if len(sig) != pub.Size() {
		return rsa.ErrVerification
	}
	s := new(big.Int).SetBytes(sig)
	m := encrypt(new(big.Int), pub.N, pub.e, s)
	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	if m.BitLen() > emLen*8 {
		return rsa.ErrVerification
	}
	em := m.FillBytes(make([]byte, emLen))
	return emsaPSSVerify(digest, em, emBits, saltLength(opts), hash.New())
}

func verifyMessageSignature(message, signature []byte, saltLength int, pk *BigPublicKey, hash crypto.Hash) error {
	h := convertHashFunction(hash)
	h.Write(message)
	digest := h.Sum(nil)

	err := verifyPSS(pk, hash, digest, signature, &rsa.PSSOptions{
		Hash:       hash,
		SaltLength: saltLength,
	})
	return err
}

func verifyBlindSignature(pub *BigPublicKey, hashed, sig []byte) error {
	m := new(big.Int).SetBytes(hashed)
	bigSig := new(big.Int).SetBytes(sig)

	c := encrypt(new(big.Int), pub.N, pub.e, bigSig)
	if subtle.ConstantTimeCompare(m.Bytes(), c.Bytes()) == 1 {
		return nil
	} else {
		return rsa.ErrVerification
	}
}
