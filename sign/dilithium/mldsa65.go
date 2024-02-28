// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	common "github.com/cloudflare/circl/sign/internal/dilithium"
)

// implMLDSA65 implements the mode.Mode interface for ML-DSA-65.
type implMLDSA65 struct{}

// MLDSA65 is ML-DSA-65.
var MLDSA65 Mode = &implMLDSA65{}

func (m *implMLDSA65) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mldsa65.GenerateKey(rand)
}

func (m *implMLDSA65) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mldsa65.NewKeyFromSeed(&seedBuf)
}

func (m *implMLDSA65) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mldsa65.PrivateKey)
	ret := [mldsa65.SignatureSize]byte{}
	mldsa65.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMLDSA65) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mldsa65.PublicKey)
	return mldsa65.Verify(ipk, msg, signature)
}

func (m *implMLDSA65) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mldsa65.PublicKey
	if len(data) != mldsa65.PublicKeySize {
		panic("packed public key must be of mldsa65.PublicKeySize bytes")
	}
	var buf [mldsa65.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMLDSA65) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mldsa65.PrivateKey
	if len(data) != mldsa65.PrivateKeySize {
		panic("packed private key must be of mldsa65.PrivateKeySize bytes")
	}
	var buf [mldsa65.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMLDSA65) SeedSize() int {
	return common.SeedSize
}

func (m *implMLDSA65) PublicKeySize() int {
	return mldsa65.PublicKeySize
}

func (m *implMLDSA65) PrivateKeySize() int {
	return mldsa65.PrivateKeySize
}

func (m *implMLDSA65) SignatureSize() int {
	return mldsa65.SignatureSize
}

func (m *implMLDSA65) Name() string {
	return "ML-DSA-65"
}

func init() {
	modes["ML-DSA-65"] = MLDSA65
}
