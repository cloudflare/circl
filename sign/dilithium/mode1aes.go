// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/mode1aes"
)

// implMode1AES implements the mode.Mode interface for Dilithium1-AES.
type implMode1AES struct{}

// Mode1AES is Dilithium in mode "Dilithium1-AES".
var Mode1AES Mode = &implMode1AES{}

func (m *implMode1AES) GenerateKey(rand io.Reader) (PublicKey,
	PrivateKey, error) {
	return mode1aes.GenerateKey(rand)
}

func (m *implMode1AES) NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey,
	PrivateKey) {
	return mode1aes.NewKeyFromExpandedSeed(seed)
}

func (m *implMode1AES) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return mode1aes.NewKeyFromSeed(&seedBuf)
}

func (m *implMode1AES) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*mode1aes.PrivateKey)
	ret := [mode1aes.SignatureSize]byte{}
	mode1aes.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode1AES) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*mode1aes.PublicKey)
	return mode1aes.Verify(ipk, msg, signature)
}

func (m *implMode1AES) PublicKeyFromBytes(data []byte) PublicKey {
	var ret mode1aes.PublicKey
	if len(data) != mode1aes.PublicKeySize {
		panic(errors.New("packed public key must be of mode1aes.PublicKeySize bytes"))
	}
	var buf [mode1aes.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode1AES) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret mode1aes.PrivateKey
	if len(data) != mode1aes.PrivateKeySize {
		panic(errors.New("packed public key must be of mode1aes.PrivateKeySize bytes"))
	}
	var buf [mode1aes.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *implMode1AES) SeedSize() int {
	return common.SeedSize
}

func (m *implMode1AES) PublicKeySize() int {
	return mode1aes.PublicKeySize
}

func (m *implMode1AES) PrivateKeySize() int {
	return mode1aes.PrivateKeySize
}

func (m *implMode1AES) SignatureSize() int {
	return mode1aes.SignatureSize
}

func (m *implMode1AES) Name() string {
	return "Dilithium1-AES"
}

func init() {
	modes["Dilithium1-AES"] = Mode1AES
}
