// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// implMode3 implements the mode.Mode interface for Dilithium3.
type implMode3 struct{}

// Mode3 is Dilithium in mode "Dilithium3".
var Mode3 Mode = &implMode3{}

func (m *implMode3) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode3.GenerateKey(rand)
}

func (m *implMode3) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode3.NewKeyFromSeed(&seedBuf)
}

func (m *implMode3) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode3.PrivateKey)
	ret := [mode3.SignatureSize]byte{}
	mode3.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode3) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode3.PublicKey)
	return mode3.Verify(ipk, msg, signature)
}

func (m *implMode3) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode3.PublicKey
	if len(data) != mode3.PublicKeySize {
		panic("packed public key must be of mode3.PublicKeySize bytes")
	}
	var buf [mode3.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode3) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode3.PrivateKey
	if len(data) != mode3.PrivateKeySize {
		panic("packed public key must be of mode3.PrivateKeySize bytes")
	}
	var buf [mode3.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode3) SeedSize() int {
	return common.SeedSize
}

func (m *implMode3) PublicKeySize() int {
	return mode3.PublicKeySize
}

func (m *implMode3) PrivateKeySize() int {
	return mode3.PrivateKeySize
}

func (m *implMode3) SignatureSize() int {
	return mode3.SignatureSize
}

func (m *implMode3) Name() string {
	return "Dilithium3"
}

func init() {
	modes["Dilithium3"] = Mode3
}
