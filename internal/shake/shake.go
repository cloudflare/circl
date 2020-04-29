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
