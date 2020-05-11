// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package shake

// This file defines the Shake struct, and provides
// functions for creating SHAKE and cSHAKE instances, as well as utility
// functions for hashing bytes to arbitrary-length output.
//
//
// SHAKE implementation is based on FIPS PUB 202 [1]
//
// [1] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

// Consts for configuring initial SHA-3 state
const (
	dsbyteShake = 0x1f
	rate256     = 136
	rate128     = 168
)

// RC stores the round constants for use in the ι step.
var RC = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

// NewShake256 creates a new SHAKE256 variable-output-length Shake.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() Shake {
	return Shake{rate: rate256, dsbyte: dsbyteShake}
}

// NewShake128 creates a new SHAKE128 variable-output-length Shake.
// Its generic security strength is 128 bits against all attacks if
// at least 32 bytes of its output are used.
func NewShake128() Shake {
	return Shake{rate: rate128, dsbyte: dsbyteShake}
}

func (d *Shake) Init128() {
	d.rate = rate128
	d.dsbyte = dsbyteShake
}
