// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"errors"
	"fmt"
	"io"

	common "github.com/cloudflare/circl/sign/dilithium/internal"
	"github.com/cloudflare/circl/sign/dilithium/mode4aes"
)

// implMode4AES implements the mode.Mode interface for Dilithium4-AES.
type implMode4AES struct{}

// Mode4AES is Dilithium in mode "Dilithium4-AES".
var Mode4AES Mode = &implMode4AES{}

func (m *implMode4AES) GenerateKey(rand io.Reader) (PublicKey,
	PrivateKey, error) {
	return mode4aes.GenerateKey(rand)
}

func (m *implMode4AES) NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey,
	PrivateKey) {
	return mode4aes.NewKeyFromExpandedSeed(seed)
}

func (m *implMode4AES) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode4aes.NewKeyFromSeed(&seedBuf)
}

func (m *implMode4AES) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode4aes.PrivateKey)
	ret := [mode4aes.SignatureSize]byte{}
	mode4aes.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode4AES) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode4aes.PublicKey)
	return mode4aes.Verify(ipk, msg, signature)
}

func (m *implMode4AES) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode4aes.PublicKey
	if len(data) != mode4aes.PublicKeySize {
		panic(errors.New("packed public key must be of mode4aes.PublicKeySize bytes"))
	}
	var buf [mode4aes.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode4AES) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode4aes.PrivateKey
	if len(data) != mode4aes.PrivateKeySize {
		panic(errors.New("packed public key must be of mode4aes.PrivateKeySize bytes"))
	}
	var buf [mode4aes.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode4AES) SeedSize() int {
	return common.SeedSize
}

func (m *implMode4AES) PublicKeySize() int {
	return mode4aes.PublicKeySize
}

func (m *implMode4AES) PrivateKeySize() int {
	return mode4aes.PrivateKeySize
}

func (m *implMode4AES) SignatureSize() int {
	return mode4aes.SignatureSize
}

func (m *implMode4AES) Name() string {
	return "Dilithium4-AES"
}

func init() {
	modes["Dilithium4-AES"] = Mode4AES
}
