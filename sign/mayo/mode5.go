// Code generated from mode.templ.go. DO NOT EDIT.

package mayo

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mayo/mode5"
)

// implMode5 implements the mode.Mode interface for MAYO_5.
type implMode5 struct{}

// Mode5 is MAYO in mode "MAYO_5".
var Mode5 Mode = &implMode5{}

func (m *implMode5) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode5.GenerateKey(rand)
}

func (m *implMode5) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != mode5.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", mode5.SeedSize))
	}
	seedBuf := [mode5.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode5.NewKeyFromSeed(&seedBuf)
}

func (m *implMode5) Sign(sk PrivateKey, msg []byte, rand io.Reader) ([]byte, error) {
	isk := sk.(*mode5.PrivateKey)
	return mode5.Sign(isk, msg, rand)
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
	return mode5.SeedSize
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
	return "MAYO_5"
}

func init() {
	modes["MAYO_5"] = Mode5
}
