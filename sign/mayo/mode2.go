// Code generated from mode.templ.go. DO NOT EDIT.

package mayo

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mayo/mode2"
)

// implMode2 implements the mode.Mode interface for MAYO_2.
type implMode2 struct{}

// Mode2 is MAYO in mode "MAYO_2".
var Mode2 Mode = &implMode2{}

func (m *implMode2) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode2.GenerateKey(rand)
}

func (m *implMode2) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != mode2.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", mode2.SeedSize))
	}
	seedBuf := [mode2.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode2.NewKeyFromSeed(&seedBuf)
}

func (m *implMode2) Sign(sk PrivateKey, msg []byte, rand io.Reader) ([]byte, error) {
	isk := sk.(*mode2.PrivateKey)
	return mode2.Sign(isk, msg, rand)
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
	return mode2.SeedSize
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
	return "MAYO_2"
}

func init() {
	modes["MAYO_2"] = Mode2
}
