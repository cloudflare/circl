// Code generated from operations_6960119.templ.go. DO NOT EDIT.

package mceliece6960119

import "fmt"

// This function determines (in a constant-time manner) whether the padding bits of `pk` are all zero.
func checkPkPadding(pk *[PublicKeySize]byte) byte {
	b := byte(0)
	for i := 0; i < pkNRows; i++ {
		b |= pk[i*pkRowBytes+pkRowBytes-1]
	}
	b >>= pkNCols % 8
	b -= 1
	b >>= 7
	return b - 1
}

// This function determines (in a constant-time manner) whether the padding bits of `c` are all zero.
func checkCPadding(c []byte) byte {
	b := c[syndBytes-1] >> (pkNRows % 8)
	b -= 1
	b >>= 7
	return b - 1
}

// input: public key pk, error vector e
// output: syndrome s
func syndrome(s []byte, pk []byte, e []byte) {
	row := [sysN / 8]byte{}
	pkSegment := pk
	tail := pkNRows % 8
	for i := 0; i < syndBytes; i++ {
		s[i] = 0
	}
	for i := 0; i < pkNRows; i++ {
		for j := 0; j < sysN/8; j++ {
			row[j] = 0
		}
		for j := 0; j < pkRowBytes; j++ {
			row[sysN/8-pkRowBytes+j] = pkSegment[j]
		}
		for j := sysN/8 - 1; j >= sysN/8-pkRowBytes; j-- {
			row[j] = (row[j] << tail) | (row[j-1] >> (8 - tail))
		}
		row[i/8] |= 1 << (i % 8)

		b := byte(0)
		for j := 0; j < sysN/8; j++ {
			b ^= row[j] & e[j]
		}

		b ^= b >> 4
		b ^= b >> 2
		b ^= b >> 1
		b &= 1

		s[i/8] |= b << (i % 8)

		pkSegment = pkSegment[pkRowBytes:]
	}
}

// KEM Encapsulation.
//
// Given a public key `pk`, sample a shared key.
// This shared key is returned through parameter `key` whereas
// the ciphertext (meant to be used for decapsulation) is returned as `c`.
func kemEncapsulate(c *[CiphertextSize]byte, key *[SharedKeySize]byte, pk *[PublicKeySize]byte, rand randFunc) error {
	twoE := [1 + sysN/8]byte{2}
	oneEC := [1 + sysN/8 + (syndBytes + 32)]byte{1}
	paddingOk := checkPkPadding(pk)
	err := encrypt(c[:], pk[:], twoE[1:1+sysN/8], rand)
	if err != nil {
		return err
	}
	err = shake256(c[syndBytes:syndBytes+32], twoE[:])
	if err != nil {
		return err
	}
	copy(oneEC[1:1+(sysN/8)], twoE[1:(sysN/8)+1])
	copy(oneEC[1+(sysN/8):1+(sysN/8)+syndBytes+32], c[0:syndBytes+32])
	err = shake256(key[0:32], oneEC[:])
	if err != nil {
		return err
	}

	mask := paddingOk ^ 0xFF
	for i := 0; i < syndBytes+32; i++ {
		c[i] &= mask
	}
	for i := 0; i < 32; i++ {
		key[i] &= mask
	}

	if paddingOk == 0 {
		return nil
	}
	return fmt.Errorf("public key padding error %d", paddingOk)
}

// KEM Encapsulation.
//
// Given a public key `pk`, sample a shared key.
// This shared key is returned through parameter `key` whereas
// the ciphertext (meant to be used for decapsulation) is returned as `c`.
func kemDecapsulate(key *[SharedKeySize]byte, c *[CiphertextSize]byte, sk *[PrivateKeySize]byte) error {
	conf := [32]byte{}
	twoE := [1 + sysN/8]byte{2}
	e := twoE[1:]
	preimage := [1 + sysN/8 + (syndBytes + 32)]byte{}
	s := sk[40+irrBytes+condBytes:]

	paddingOk := checkCPadding(c[:])
	retDecrypt := decrypt((*[sysN / 8]byte)(e[:sysN/8]), sk[40:], (*[syndBytes]byte)(c[:syndBytes]))
	err := shake256(conf[0:32], twoE[:])
	if err != nil {
		return err
	}

	var retConfirm byte
	for i := 0; i < 32; i++ {
		retConfirm |= conf[i] ^ c[syndBytes+i]
	}

	m := retDecrypt | uint16(retConfirm)
	m -= 1
	m >>= 8

	preimage[0] = byte(m & 1)
	for i := 0; i < sysN/8; i++ {
		preimage[1+i] = (byte(^m) & s[i]) | (byte(m) & twoE[1+i])
	}
	copy(preimage[1+(sysN/8):][0:syndBytes+32], c[0:syndBytes+32])
	err = shake256(key[0:32], preimage[:])
	if err != nil {
		return err
	}

	mask := paddingOk
	for i := 0; i < 32; i++ {
		key[i] |= mask
	}

	if paddingOk == 0 {
		return nil
	}
	return fmt.Errorf("public key padding error %d", paddingOk)
}
