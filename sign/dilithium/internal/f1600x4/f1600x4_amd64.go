package f1600x4

import (
	"github.com/cloudflare/circl/internal/shake"

	"golang.org/x/sys/cpu"

	"unsafe"
)

// Available is true when this system supports a fast fourway KeccaK-f[1600].
var Available = cpu.X86.HasAVX2

// Contains state for the fourway permutation including the four
// interleaved [25]uint64 buffers.  Call Initialize() before use to initialize
// and get a pointer to the interleaved buffer.
type State struct {
	// Go guarantees a to be aligned on 8 bytes, whereas we need it to be
	// aligned on 32 bytes for bet performance.  Thus we leave some headroom
	// to be able to move the start of the state.

	// 4 x 25 uint64s for the interleaved states and three uint64s headroom
	// to fix allignment.
	a [103]uint64

	// Offset into a that is 32 byte aligned.
	offset int
}

// Initialize the state and returns the buffer on which the four permutations
// will act: a uint64 slice of length 100.  The first permutation will act
// on {a[0], a[4], ..., a[96]}, the second on {a[1], a[5], ..., a[97]}, etc.
func (s *State) Initialize() []uint64 {
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

// Perform the four parallel KeccaK-f[1600]s interleaved on the slice returned
// from Initialize().
func (s *State) Permute() {
	f1600x4(&s.a[s.offset], &shake.RC)
}
