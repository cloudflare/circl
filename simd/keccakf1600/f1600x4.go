// Package keccakf1600 provides a four-way Keccak-f[1600] permutation in parallel.
//
// Keccak-f[1600] is the permutation underlying several algorithms such as
// Keccak, SHA3 and SHAKE. Running four permutations in parallel is useful in
// some scenarios like in hash-based signatures.
//
// Limitations
//
// Note that not all the architectures support SIMD instructions. This package
// uses AVX2 instructions that are available in some AMD64 architectures.
//
// For those systems not supporting AVX2, the package still provides the
// expected functionality by means of a generic and slow implementation.
// The recommendation is to beforehand verify IsEnabledX4() to determine if
// the current system supports the SIMD implementation.
package keccakf1600

import (
	"unsafe"

	"github.com/cloudflare/circl/internal/shake"
	"golang.org/x/sys/cpu"
)

// StateX4 contains state for the four-way permutation including the four
// interleaved [25]uint64 buffers. Call Initialize() before use to initialize
// and get a pointer to the interleaved buffer.
type StateX4 struct {
	// Go guarantees a to be aligned on 8 bytes, whereas we need it to be
	// aligned on 32 bytes for bet performance.  Thus we leave some headroom
	// to be able to move the start of the state.

	// 4 x 25 uint64s for the interleaved states and three uint64s headroom
	// to fix alignment.
	a [103]uint64

	// Offset into a that is 32 byte aligned.
	offset int
}

// IsEnabledX4 returns true if the architecture supports a four-way SIMD
// implementation provided in this package.
func IsEnabledX4() bool { return cpu.X86.HasAVX2 }

// Initialize the state and returns the buffer on which the four permutations
// will act: a uint64 slice of length 100.  The first permutation will act
// on {a[0], a[4], ..., a[96]}, the second on {a[1], a[5], ..., a[97]}, etc.
func (s *StateX4) Initialize() []uint64 {
	rp := unsafe.Pointer(&s.a[0])

	// uint64s are always aligned by a multiple of 8.  Compute the remainder
	// of the address modulo 32 divided by 8.
	rem := (int(uintptr(rp)&31) >> 3)

	if rem != 0 {
		s.offset = 4 - rem
	}

	// The slice we return will be aligned on 32 byte boundary.
	return s.a[s.offset : s.offset+100]
}

// Permute performs the four parallel Keccak-f[1600]s interleaved on the slice
// returned from Initialize().
func (s *StateX4) Permute() {
	if IsEnabledX4() {
		permuteSIMD(s.a[s.offset:])
	} else {
		permuteScalar(s.a[s.offset:]) // A slower generic implementation.
	}
}

func permuteScalar(a []uint64) {
	var buf [25]uint64
	for i := 0; i < 4; i++ {
		for j := 0; j < 25; j++ {
			buf[j] = a[4*j+i]
		}
		shake.KeccakF1600(&buf)
		for j := 0; j < 25; j++ {
			a[4*j+i] = buf[j]
		}
	}
}
