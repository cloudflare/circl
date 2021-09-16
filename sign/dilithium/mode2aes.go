// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/mode2aes"
)

// implMode2AES implements the mode.Mode interface for Dilithium2-AES.
type implMode2AES struct{}

// Mode2AES is Dilithium in mode "Dilithium2-AES".
var Mode2AES Mode = &implMode2AES{}

func (m *implMode2AES) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode2aes.GenerateKey(rand)
}

func (m *implMode2AES) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode2aes.NewKeyFromSeed(&seedBuf)
}

func (m *implMode2AES) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode2aes.PrivateKey)
	ret := [mode2aes.SignatureSize]byte{}
	mode2aes.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode2AES) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode2aes.PublicKey)
	return mode2aes.Verify(ipk, msg, signature)
}

func (m *implMode2AES) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode2aes.PublicKey
	if len(data) != mode2aes.PublicKeySize {
		panic("packed public key must be of mode2aes.PublicKeySize bytes")
	}
	var buf [mode2aes.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode2AES) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode2aes.PrivateKey
	if len(data) != mode2aes.PrivateKeySize {
		panic("packed public key must be of mode2aes.PrivateKeySize bytes")
	}
	var buf [mode2aes.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode2AES) SeedSize() int {
	return common.SeedSize
}

func (m *implMode2AES) PublicKeySize() int {
	return mode2aes.PublicKeySize
}

func (m *implMode2AES) PrivateKeySize() int {
	return mode2aes.PrivateKeySize
}

func (m *implMode2AES) SignatureSize() int {
	return mode2aes.SignatureSize
}

func (m *implMode2AES) Name() string {
	return "Dilithium2-AES"
}

func init() {
	modes["Dilithium2-AES"] = Mode2AES
}
