// Code generated from mode.templ.go. DO NOT EDIT.

package mayo

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mayo/mode3"
)

// implMode3 implements the mode.Mode interface for MAYO_3.
type implMode3 struct{}

// Mode3 is MAYO in mode "MAYO_3".
var Mode3 Mode = &implMode3{}

func (m *implMode3) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode3.GenerateKey(rand)
}

func (m *implMode3) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != mode3.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", mode3.SeedSize))
	}
	seedBuf := [mode3.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode3.NewKeyFromSeed(&seedBuf)
}

func (m *implMode3) Sign(sk PrivateKey, msg []byte, rand io.Reader) ([]byte, error) {
	isk := sk.(*mode3.PrivateKey)
	return mode3.Sign(isk, msg, rand)
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
	return mode3.SeedSize
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
	return "MAYO_3"
}

func init() {
	modes["MAYO_3"] = Mode3
}
