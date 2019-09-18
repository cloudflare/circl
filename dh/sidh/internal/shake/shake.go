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

// cSHAKE specific context
type Shake struct {
	state // SHA-3 state context and Read/Write operations
}

// Consts for configuring initial SHA-3 state
const (
	dsbyteShake = 0x1f
	rate256     = 136
)

// Reset resets the hash to initial state.
func (c *Shake) Reset() {
	c.state.Reset()
}

// Clone returns copy of a cSHAKE context within its current state.
func (c *Shake) Clone() Shake {
	var ret Shake
	c.clone(&ret.state)
	return ret
}

// NewShake256 creates a new SHAKE256 variable-output-length Shake.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() *Shake {
	return &Shake{state{rate: rate256, dsbyte: dsbyteShake}}
}
