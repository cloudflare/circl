// Code generated from mode.templ.go. DO NOT EDIT.

package mayo

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mayo/mode1"
)

// implMode1 implements the mode.Mode interface for MAYO_1.
type implMode1 struct{}

// Mode1 is MAYO in mode "MAYO_1".
var Mode1 Mode = &implMode1{}

func (m *implMode1) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode1.GenerateKey(rand)
}

func (m *implMode1) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != mode1.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", mode1.SeedSize))
	}
	seedBuf := [mode1.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode1.NewKeyFromSeed(&seedBuf)
}

func (m *implMode1) Sign(sk PrivateKey, msg []byte, rand io.Reader) ([]byte, error) {
	isk := sk.(*mode1.PrivateKey)
	return mode1.Sign(isk, msg, rand)
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
	return mode1.SeedSize
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
	return "MAYO_1"
}

func init() {
	modes["MAYO_1"] = Mode1
}
