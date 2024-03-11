// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	common "github.com/cloudflare/circl/sign/internal/dilithium"
)

// implMLDSA44 implements the mode.Mode interface for ML-DSA-44.
type implMLDSA44 struct{}

// MLDSA44 is ML-DSA-44.
var MLDSA44 Mode = &implMLDSA44{}

func (m *implMLDSA44) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mldsa44.GenerateKey(rand)
}

func (m *implMLDSA44) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mldsa44.NewKeyFromSeed(&seedBuf)
}

func (m *implMLDSA44) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mldsa44.PrivateKey)
	ret := [mldsa44.SignatureSize]byte{}
	mldsa44.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMLDSA44) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mldsa44.PublicKey)
	return mldsa44.Verify(ipk, msg, signature)
}

func (m *implMLDSA44) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mldsa44.PublicKey
	if len(data) != mldsa44.PublicKeySize {
		panic("packed public key must be of mldsa44.PublicKeySize bytes")
	}
	var buf [mldsa44.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMLDSA44) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mldsa44.PrivateKey
	if len(data) != mldsa44.PrivateKeySize {
		panic("packed private key must be of mldsa44.PrivateKeySize bytes")
	}
	var buf [mldsa44.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMLDSA44) SeedSize() int {
	return common.SeedSize
}

func (m *implMLDSA44) PublicKeySize() int {
	return mldsa44.PublicKeySize
}

func (m *implMLDSA44) PrivateKeySize() int {
	return mldsa44.PrivateKeySize
}

func (m *implMLDSA44) SignatureSize() int {
	return mldsa44.SignatureSize
}

func (m *implMLDSA44) Name() string {
	return "ML-DSA-44"
}

func init() {
	modes["ML-DSA-44"] = MLDSA44
}
