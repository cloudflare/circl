// @author Armando Faz

// +build amd64

// Package x25519 implements the Diffie-Hellman function X25519.
package x25519

import (
	Fp "github.com/cloudflare/circl/ecc/fp25519"
	cpu "github.com/cloudflare/circl/utils"
)

// SizeKey is the size in bytes of a X25519 key.
const SizeKey = 32

// xCoordinateX25519 is the x-coordinate of the generator
// point of Curve25519.
const xCoordinateX25519 = 9

// Key is the alias of a X25519 key.
type Key = [SizeKey]byte

//go:noescape
func ladderStepX64(work *[7 * Fp.SizeElement]byte, buffer *[4 * Fp.SizeElement]byte, move uint)

//go:noescape
func ladderStepBmi2Adx(work *[7 * Fp.SizeElement]byte, buffer *[4 * Fp.SizeElement]byte, move uint)

//go:noescape
func mixAdditionX64(work *[4 * Fp.SizeElement]byte, buffer *[4 * Fp.SizeElement]byte, mu *[Fp.SizeElement]byte, swap uint)

//go:noescape
func mixAdditionBmi2Adx(work *[4 * Fp.SizeElement]byte, buffer *[4 * Fp.SizeElement]byte, mu *[Fp.SizeElement]byte, swap uint)

//go:noescape
func doublingBmi2Adx(work *[4 * Fp.SizeElement]byte, buffer *[4 * Fp.SizeElement]byte)

//go:noescape
func doublingX64(work *[4 * Fp.SizeElement]byte, buffer *[4 * Fp.SizeElement]byte)

// XCoordBase returns the x-coordinate of the point generator of Curve25519
func XCoordBase() int {
	return xCoordinateX25519
}

// GetBase returns a field element with the x-coordinate of the point generator of Curve25519
func GetBase() Fp.Element {
	var base Fp.Element
	base[0] = xCoordinateX25519
	return base
}

func ladderJoye(xkP *Fp.Element, k *[SizeKey]byte) {
	var buffer [4 * Fp.SizeElement]byte
	var work [4 * Fp.SizeElement]byte // = [x1|z1|x2|z2]
	var pointGMinusS = Fp.Element{0xbd, 0xaa, 0x2f, 0xc8, 0xfe, 0xe1, 0x94, 0x7e, 0xf8, 0xed, 0xb2, 0x14, 0xae, 0x95, 0xf0, 0xbb, 0xe2, 0x48, 0x5d, 0x23, 0xb9, 0xa0, 0xc7, 0xad, 0x34, 0xab, 0x7c, 0xe2, 0xee, 0xcd, 0xae, 0x1e}

	const (
		x1 = iota * Fp.SizeElement
		z1
		x2
		z2
	)
	work[x1] = 1
	work[z1] = 1
	copy(work[x2:x2+Fp.SizeElement], pointGMinusS[:])
	work[z2] = 1

	swap := uint(1)
	if cpu.X86.HasBMI2 && cpu.X86.HasADX {
		for s := 0; s < 252; s++ {
			i := (s + 3) / 8
			j := (s + 3) % 8
			bit := uint(((*k)[i] >> uint(j)) & 1)
			mixAdditionBmi2Adx(&work, &buffer, &tableBasePoint25519[s], swap^bit)
			swap = bit
		}
		doublingBmi2Adx(&work, &buffer)
		doublingBmi2Adx(&work, &buffer)
		doublingBmi2Adx(&work, &buffer)
	} else {
		for s := 0; s < 252; s++ {
			i := (s + 3) / 8
			j := (s + 3) % 8
			bit := uint(((*k)[i] >> uint(j)) & 1)
			mixAdditionX64(&work, &buffer, &tableBasePoint25519[s], swap^bit)
			swap = bit
		}
		doublingX64(&work, &buffer)
		doublingX64(&work, &buffer)
		doublingX64(&work, &buffer)
	}

	var x, z Fp.Element
	copy(x[:], work[x1:x1+Fp.SizeElement])
	copy(z[:], work[z1:z1+Fp.SizeElement])
	Fp.Div(xkP, &x, &z)
	Fp.ModuloP(xkP)
}

func ladderMontgomery(xkP, xP *Fp.Element, k *[SizeKey]byte) {
	var buffer [4 * Fp.SizeElement]byte
	var work [7 * Fp.SizeElement]byte // = [x2|z2|x3|z3|t0|t1|x1]

	const (
		x2 = iota * Fp.SizeElement
		z2
		x3
		z3
		_
		_
		x1
	)
	copy(work[x1:x1+Fp.SizeElement], (*xP)[:])
	copy(work[x3:x3+Fp.SizeElement], (*xP)[:])
	work[x2] = 1
	work[z3] = 1

	move := uint(0)
	if cpu.X86.HasBMI2 && cpu.X86.HasADX {
		for s := 254; s >= 0; s-- {
			i := s / 8
			j := s % 8
			bit := uint(((*k)[i] >> uint(j)) & 1)
			ladderStepBmi2Adx(&work, &buffer, move^bit)
			move = bit
		}
	} else {
		for s := 254; s >= 0; s-- {
			i := s / 8
			j := s % 8
			bit := uint(((*k)[i] >> uint(j)) & 1)
			ladderStepX64(&work, &buffer, move^bit)
			move = bit
		}
	}

	var x, z Fp.Element
	copy(x[:], work[x2:x2+Fp.SizeElement])
	copy(z[:], work[z2:z2+Fp.SizeElement])
	Fp.Div(xkP, &x, &z)
	Fp.ModuloP(xkP)
}

func x25519(out, in, base *[SizeKey]byte) {
	var xP Fp.Element

	k := *in
	k[0] &= 248
	k[SizeKey-1] &= 127
	k[SizeKey-1] |= 64

	// [RFC-7748] When receiving such an array, implementations
	// of X25519 (but not X448) MUST mask the most significant
	// bit in the final byte.
	xP = *base
	xP[SizeKey-1] &= (1 << (255 % 8)) - 1

	ladderMontgomery(out, &xP, &k)
}

func x25519Base(out, in *[SizeKey]byte) {
	k := *in
	k[0] &= 248
	k[SizeKey-1] &= 127
	k[SizeKey-1] |= 64

	ladderJoye(out, &k)
}

// ScalarMult calculates a X25519 shared secret.
func ScalarMult(dst, in, base *[SizeKey]byte) {
	x25519(dst, in, base)
}

// ScalarBaseMult calculates a public/ephemeral key using Diffie-Hellman
// function X25519.
func ScalarBaseMult(dst, in *[SizeKey]byte) {
	x25519Base(dst, in)
}
