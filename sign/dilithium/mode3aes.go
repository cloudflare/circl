// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/mode3aes"
)

// implMode3AES implements the mode.Mode interface for Dilithium3-AES.
type implMode3AES struct{}

// Mode3AES is Dilithium in mode "Dilithium3-AES".
var Mode3AES Mode = &implMode3AES{}

func (m *implMode3AES) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode3aes.GenerateKey(rand)
}

func (m *implMode3AES) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode3aes.NewKeyFromSeed(&seedBuf)
}

func (m *implMode3AES) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode3aes.PrivateKey)
	ret := [mode3aes.SignatureSize]byte{}
	mode3aes.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode3AES) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode3aes.PublicKey)
	return mode3aes.Verify(ipk, msg, signature)
}

func (m *implMode3AES) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode3aes.PublicKey
	if len(data) != mode3aes.PublicKeySize {
		panic("packed public key must be of mode3aes.PublicKeySize bytes")
	}
	var buf [mode3aes.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode3AES) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode3aes.PrivateKey
	if len(data) != mode3aes.PrivateKeySize {
		panic("packed public key must be of mode3aes.PrivateKeySize bytes")
	}
	var buf [mode3aes.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode3AES) SeedSize() int {
	return common.SeedSize
}

func (m *implMode3AES) PublicKeySize() int {
	return mode3aes.PublicKeySize
}

func (m *implMode3AES) PrivateKeySize() int {
	return mode3aes.PrivateKeySize
}

func (m *implMode3AES) SignatureSize() int {
	return mode3aes.SignatureSize
}

func (m *implMode3AES) Name() string {
	return "Dilithium3-AES"
}

func init() {
	modes["Dilithium3-AES"] = Mode3AES
}
