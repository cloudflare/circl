// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/mode5aes"
)

// implMode5AES implements the mode.Mode interface for Dilithium5-AES.
type implMode5AES struct{}

// Mode5AES is Dilithium in mode "Dilithium5-AES".
var Mode5AES Mode = &implMode5AES{}

func (m *implMode5AES) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return mode5aes.GenerateKey(rand)
}

func (m *implMode5AES) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode5aes.NewKeyFromSeed(&seedBuf)
}

func (m *implMode5AES) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode5aes.PrivateKey)
	ret := [mode5aes.SignatureSize]byte{}
	mode5aes.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode5AES) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode5aes.PublicKey)
	return mode5aes.Verify(ipk, msg, signature)
}

func (m *implMode5AES) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode5aes.PublicKey
	if len(data) != mode5aes.PublicKeySize {
		panic("packed public key must be of mode5aes.PublicKeySize bytes")
	}
	var buf [mode5aes.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode5AES) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode5aes.PrivateKey
	if len(data) != mode5aes.PrivateKeySize {
		panic("packed public key must be of mode5aes.PrivateKeySize bytes")
	}
	var buf [mode5aes.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode5AES) SeedSize() int {
	return common.SeedSize
}

func (m *implMode5AES) PublicKeySize() int {
	return mode5aes.PublicKeySize
}

func (m *implMode5AES) PrivateKeySize() int {
	return mode5aes.PrivateKeySize
}

func (m *implMode5AES) SignatureSize() int {
	return mode5aes.SignatureSize
}

func (m *implMode5AES) Name() string {
	return "Dilithium5-AES"
}

func init() {
	modes["Dilithium5-AES"] = Mode5AES
}
