// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	common "github.com/cloudflare/circl/sign/internal/dilithium"
)

// implMLDSA87 implements the mode.Mode interface for ML-DSA-87.
type implMLDSA87 struct{}

// MLDSA87 is ML-DSA-87.
var MLDSA87 Mode = &implMLDSA87{}

func (m *implMLDSA87) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mldsa87.GenerateKey(rand)
}

func (m *implMLDSA87) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mldsa87.NewKeyFromSeed(&seedBuf)
}

func (m *implMLDSA87) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mldsa87.PrivateKey)
	ret := [mldsa87.SignatureSize]byte{}
	mldsa87.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMLDSA87) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mldsa87.PublicKey)
	return mldsa87.Verify(ipk, msg, signature)
}

func (m *implMLDSA87) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mldsa87.PublicKey
	if len(data) != mldsa87.PublicKeySize {
		panic("packed public key must be of mldsa87.PublicKeySize bytes")
	}
	var buf [mldsa87.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMLDSA87) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mldsa87.PrivateKey
	if len(data) != mldsa87.PrivateKeySize {
		panic("packed public key must be of mldsa87.PrivateKeySize bytes")
	}
	var buf [mldsa87.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMLDSA87) SeedSize() int {
	return common.SeedSize
}

func (m *implMLDSA87) PublicKeySize() int {
	return mldsa87.PublicKeySize
}

func (m *implMLDSA87) PrivateKeySize() int {
	return mldsa87.PrivateKeySize
}

func (m *implMLDSA87) SignatureSize() int {
	return mldsa87.SignatureSize
}

func (m *implMLDSA87) Name() string {
	return "ML-DSA-87"
}

func init() {
	modes["ML-DSA-87"] = MLDSA87
}
