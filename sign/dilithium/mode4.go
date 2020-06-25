// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/mode4"
)

// implMode4 implements the mode.Mode interface for Dilithium4.
type implMode4 struct{}

// Mode4 is Dilithium in mode "Dilithium4".
var Mode4 Mode = &implMode4{}

func (m *implMode4) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode4.GenerateKey(rand)
}

func (m *implMode4) NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey,
	PrivateKey) {
	return mode4.NewKeyFromExpandedSeed(seed)
}

func (m *implMode4) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode4.NewKeyFromSeed(&seedBuf)
}

func (m *implMode4) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode4.PrivateKey)
	ret := [mode4.SignatureSize]byte{}
	mode4.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode4) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode4.PublicKey)
	return mode4.Verify(ipk, msg, signature)
}

func (m *implMode4) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode4.PublicKey
	if len(data) != mode4.PublicKeySize {
		panic("packed public key must be of mode4.PublicKeySize bytes")
	}
	var buf [mode4.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode4) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode4.PrivateKey
	if len(data) != mode4.PrivateKeySize {
		panic("packed public key must be of mode4.PrivateKeySize bytes")
	}
	var buf [mode4.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode4) SeedSize() int {
	return common.SeedSize
}

func (m *implMode4) PublicKeySize() int {
	return mode4.PublicKeySize
}

func (m *implMode4) PrivateKeySize() int {
	return mode4.PrivateKeySize
}

func (m *implMode4) SignatureSize() int {
	return mode4.SignatureSize
}

func (m *implMode4) Name() string {
	return "Dilithium4"
}

func init() {
	modes["Dilithium4"] = Mode4
}
