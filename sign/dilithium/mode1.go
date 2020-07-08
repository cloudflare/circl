// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/mode1"
)

// implMode1 implements the mode.Mode interface for Dilithium1.
type implMode1 struct{}

// Mode1 is Dilithium in mode "Dilithium1".
var Mode1 Mode = &implMode1{}

func (m *implMode1) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode1.GenerateKey(rand)
}

func (m *implMode1) NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey,
	PrivateKey) {
	return mode1.NewKeyFromExpandedSeed(seed)
}

func (m *implMode1) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode1.NewKeyFromSeed(&seedBuf)
}

func (m *implMode1) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode1.PrivateKey)
	ret := [mode1.SignatureSize]byte{}
	mode1.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode1) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode1.PublicKey)
	return mode1.Verify(ipk, msg, signature)
}

func (m *implMode1) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode1.PublicKey
	if len(data) != mode1.PublicKeySize {
		panic("packed public key must be of mode1.PublicKeySize bytes")
	}
	var buf [mode1.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode1) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode1.PrivateKey
	if len(data) != mode1.PrivateKeySize {
		panic("packed public key must be of mode1.PrivateKeySize bytes")
	}
	var buf [mode1.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode1) SeedSize() int {
	return common.SeedSize
}

func (m *implMode1) PublicKeySize() int {
	return mode1.PublicKeySize
}

func (m *implMode1) PrivateKeySize() int {
	return mode1.PrivateKeySize
}

func (m *implMode1) SignatureSize() int {
	return mode1.SignatureSize
}

func (m *implMode1) Name() string {
	return "Dilithium1"
}

func init() {
	modes["Dilithium1"] = Mode1
}
