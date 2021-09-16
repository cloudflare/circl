// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

// implMode5 implements the mode.Mode interface for Dilithium5.
type implMode5 struct{}

// Mode5 is Dilithium in mode "Dilithium5".
var Mode5 Mode = &implMode5{}

func (m *implMode5) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode5.GenerateKey(rand)
}

func (m *implMode5) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode5.NewKeyFromSeed(&seedBuf)
}

func (m *implMode5) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode5.PrivateKey)
	ret := [mode5.SignatureSize]byte{}
	mode5.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode5) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode5.PublicKey)
	return mode5.Verify(ipk, msg, signature)
}

func (m *implMode5) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode5.PublicKey
	if len(data) != mode5.PublicKeySize {
		panic("packed public key must be of mode5.PublicKeySize bytes")
	}
	var buf [mode5.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode5) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode5.PrivateKey
	if len(data) != mode5.PrivateKeySize {
		panic("packed public key must be of mode5.PrivateKeySize bytes")
	}
	var buf [mode5.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode5) SeedSize() int {
	return common.SeedSize
}

func (m *implMode5) PublicKeySize() int {
	return mode5.PublicKeySize
}

func (m *implMode5) PrivateKeySize() int {
	return mode5.PrivateKeySize
}

func (m *implMode5) SignatureSize() int {
	return mode5.SignatureSize
}

func (m *implMode5) Name() string {
	return "Dilithium5"
}

func init() {
	modes["Dilithium5"] = Mode5
}
