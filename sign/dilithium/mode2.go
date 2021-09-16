// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

// implMode2 implements the mode.Mode interface for Dilithium2.
type implMode2 struct{}

// Mode2 is Dilithium in mode "Dilithium2".
var Mode2 Mode = &implMode2{}

func (m *implMode2) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode2.GenerateKey(rand)
}

func (m *implMode2) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode2.NewKeyFromSeed(&seedBuf)
}

func (m *implMode2) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode2.PrivateKey)
	ret := [mode2.SignatureSize]byte{}
	mode2.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode2) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode2.PublicKey)
	return mode2.Verify(ipk, msg, signature)
}

func (m *implMode2) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode2.PublicKey
	if len(data) != mode2.PublicKeySize {
		panic("packed public key must be of mode2.PublicKeySize bytes")
	}
	var buf [mode2.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode2) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode2.PrivateKey
	if len(data) != mode2.PrivateKeySize {
		panic("packed public key must be of mode2.PrivateKeySize bytes")
	}
	var buf [mode2.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode2) SeedSize() int {
	return common.SeedSize
}

func (m *implMode2) PublicKeySize() int {
	return mode2.PublicKeySize
}

func (m *implMode2) PrivateKeySize() int {
	return mode2.PrivateKeySize
}

func (m *implMode2) SignatureSize() int {
	return mode2.SignatureSize
}

func (m *implMode2) Name() string {
	return "Dilithium2"
}

func init() {
	modes["Dilithium2"] = Mode2
}
