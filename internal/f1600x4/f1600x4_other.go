// +build !amd64

package f1600x4

// Available is true when this system supports a fast fourway KeccaK-f[1600].
var Available = false

// Contains state for the fourway permutation including the four
// interleaved [25]uint64 buffers.  Call Initialize() before use to initialize
// and get a pointer to the interleaved buffer.
type State struct{}

// Initialize the state and returns the buffer on which the four permutations
// will act: a uint64 slice of length 100.  The first permutation will act
// on {a[0], a[4], ..., a[96]}, the second on {a[1], a[5], ..., a[97]}, etc.
func (s *State) Initialize() []uint64 {
	panic("Not available")
}

// Perform the four parallel KeccaK-f[1600]s interleaved on the slice returned
// from Initialize().
func (s *State) Permute() {
	panic("Not available")
}
