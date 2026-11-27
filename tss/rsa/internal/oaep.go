package internal

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
)

// DecodeOAEP decodes an RSAES-OAEP block using SHA-256 for the hash and MGF1.
// It unmasks encoded in place and returns a slice of that buffer on success.
func DecodeOAEP(encoded, label []byte) ([]byte, error) {
	if len(encoded) < 2*sha256.Size+2 {
		return nil, rsa.ErrDecryption
	}

	// RFC 8017, Section 7.1.2, Step 3.
	firstByteOK := subtle.ConstantTimeByteEq(encoded[0], 0)
	seed := encoded[1 : 1+sha256.Size]
	database := encoded[1+sha256.Size:]
	hasher := sha256.New()
	MGF1XOR(seed, hasher, database)
	MGF1XOR(database, hasher, seed)
	labelHash := sha256.Sum256(label)
	labelOK := subtle.ConstantTimeCompare(database[:sha256.Size], labelHash[:])

	// Scan the full block to locate the separator without exposing padding errors.
	message := database[sha256.Size:]
	looking, separator, invalid := 1, 0, 0
	for i, value := range message {
		isZero := subtle.ConstantTimeByteEq(value, 0)
		isOne := subtle.ConstantTimeByteEq(value, 1)
		separator = subtle.ConstantTimeSelect(looking&isOne, i, separator)
		looking &= 1 - isOne
		invalid |= looking & (1 - isZero)
	}
	if firstByteOK&labelOK&(1-looking)&(1-invalid) != 1 {
		return nil, rsa.ErrDecryption
	}
	return message[separator+1:], nil
}
