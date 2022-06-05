// +build ignore
// The previous line (and this one up to the warning below) is removed by the
// template generator.

// Code generated from mode.templ.go. DO NOT EDIT.

package dilithium

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal/common"
	"github.com/cloudflare/circl/sign/dilithium/{{.Pkg}}"
)

// {{.Impl}} implements the mode.Mode interface for {{.Name}}.
type {{.Impl}} struct{}

// {{.Mode}} is Dilithium in mode "{{.Name}}".
var {{.Mode}} Mode = &{{.Impl}}{}

func (m *{{.Impl}}) GenerateKey(rand io.Reader) (
	PublicKey, PrivateKey, error) {
	return {{.Pkg}}.GenerateKey(rand)
}

func (m *{{.Impl}}) NewKeyFromSeed(seed []byte) (PublicKey,
	PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return {{.Pkg}}.NewKeyFromSeed(&seedBuf)
}

func (m *{{.Impl}}) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*{{.Pkg}}.PrivateKey)
	ret := [{{.Pkg}}.SignatureSize]byte{}
	{{.Pkg}}.SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *{{.Impl}}) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*{{.Pkg}}.PublicKey)
	return {{.Pkg}}.Verify(ipk, msg, signature)
}

func (m *{{.Impl}}) PublicKeyFromBytes(data []byte) PublicKey {
	var ret {{.Pkg}}.PublicKey
	if len(data) != {{.Pkg}}.PublicKeySize {
		panic("packed public key must be of {{.Pkg}}.PublicKeySize bytes")
	}
	var buf [{{.Pkg}}.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *{{.Impl}}) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret {{.Pkg}}.PrivateKey
	if len(data) != {{.Pkg}}.PrivateKeySize {
		panic("packed public key must be of {{.Pkg}}.PrivateKeySize bytes")
	}
	var buf [{{.Pkg}}.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}

func (m *{{.Impl}}) SeedSize() int {
	return common.SeedSize
}

func (m *{{.Impl}}) PublicKeySize() int {
	return {{.Pkg}}.PublicKeySize
}

func (m *{{.Impl}}) PrivateKeySize() int {
	return {{.Pkg}}.PrivateKeySize
}

func (m *{{.Impl}}) SignatureSize() int {
	return {{.Pkg}}.SignatureSize
}

func (m *{{.Impl}}) Name() string {
	return "{{.Name}}"
}

func init() {
	modes["{{.Name}}"] = {{.Mode}}
}
