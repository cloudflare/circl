// @author Armando Faz

// +build amd64

// Package x448 implements the Diffie-Hellman function X448.
package x448

import (
	Fp "github.com/cloudflare/circl/ecc/fp448"
	cpu "github.com/cloudflare/circl/utils"
)

// SizeKey is the size in bytes of a X448 key.
const SizeKey = 56

// xCoordinateX448 is the x-coordinate of the generator
// point of Curve448.
const xCoordinateX448 = 5

// Key is the alias of a X448 key.
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

// XCoordBase returns the x-coordinate of the point generator of Curve448
func XCoordBase() int {
	return xCoordinateX448
}

// GetBase returns a field element with the x-coordinate of the point generator of Curve448
func GetBase() Fp.Element {
	var base Fp.Element
	base[0] = xCoordinateX448
	return base
}

func ladderJoye(xkP *Fp.Element, k *[SizeKey]byte) {
	var buffer [4 * Fp.SizeElement]byte
	var work [4 * Fp.SizeElement]byte // = [x1|z1|x2|z2]
	var pointS = Fp.Element{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	var pointGMinusS = Fp.Element{0x20, 0x27, 0x9d, 0xc9, 0x7d, 0x19, 0xb1, 0xac, 0xf8, 0xba, 0x69, 0x1c, 0xff, 0x33, 0xac, 0x23, 0x51, 0x1b, 0xce, 0x3a, 0x64, 0x65, 0xbd, 0xf1, 0x23, 0xf8, 0xc1, 0x84, 0x9d, 0x45, 0x54, 0x29, 0x67, 0xb9, 0x81, 0x1c, 0x3, 0xd1, 0xcd, 0xda, 0x7b, 0xeb, 0xff, 0x1a, 0x88, 0x3, 0xcf, 0x3a, 0x42, 0x44, 0x32, 0x1, 0x25, 0xb7, 0xfa, 0xf0}

	const (
		x1 = iota * Fp.SizeElement
		z1
		x2
		z2
	)
	copy(work[x1:x1+Fp.SizeElement], pointS[:])
	work[z1] = 1
	copy(work[x2:x2+Fp.SizeElement], pointGMinusS[:])
	work[z2] = 1

	swap := uint(1)
	if cpu.X86.HasBMI2 && cpu.X86.HasADX {
		for s := 0; s < 446; s++ {
			i := (s + 2) / 8
			j := (s + 2) % 8
			bit := uint(((*k)[i] >> uint(j)) & 1)
			mixAdditionBmi2Adx(&work, &buffer, &tableBasePoint448[s], swap^bit)
			swap = bit
		}
		doublingBmi2Adx(&work, &buffer)
		doublingBmi2Adx(&work, &buffer)
	} else {
		for s := 0; s < 446; s++ {
			i := (s + 2) / 8
			j := (s + 2) % 8
			bit := uint(((*k)[i] >> uint(j)) & 1)
			mixAdditionX64(&work, &buffer, &tableBasePoint448[s], swap^bit)
			swap = bit
		}
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
		for s := 447; s >= 0; s-- {
			i := s / 8
			j := s % 8
			bit := uint(((*k)[i] >> uint(j)) & 1)
			ladderStepBmi2Adx(&work, &buffer, move^bit)
			move = bit
		}
	} else {
		for s := 447; s >= 0; s-- {
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

func x448(out, in, base *[SizeKey]byte) {
	k := *in
	k[0] &= 252
	k[SizeKey-1] |= 128

	ladderMontgomery(out, base, &k)
}

func x448Base(out, in *[SizeKey]byte) {
	k := *in
	k[0] &= 252
	k[SizeKey-1] |= 128

	ladderJoye(out, &k)
}

// ScalarMult calculates a X448 shared secret.
func ScalarMult(dst, in, base *[SizeKey]byte) {
	x448(dst, in, base)
}

// ScalarBaseMult calculates a public/ephemeral key using Diffie-Hellman
// function X448.
func ScalarBaseMult(dst, in *[SizeKey]byte) {
	x448Base(dst, in)
}
