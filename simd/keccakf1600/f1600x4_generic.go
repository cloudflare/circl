// +build !amd64

package keccakf1600

// AvailableX4 is true when this system supports a fast fourway Keccak-f[1600].
var AvailableX4 = false

// Contains state for the fourway permutation including the four
// interleaved [25]uint64 buffers.  Call Initialize() before use to initialize
// and get a pointer to the interleaved buffer.
type StateX4 [100]uint64

// Initialize the state and returns the buffer on which the four permutations
// will act: a uint64 slice of length 100.  The first permutation will act
// on {a[0], a[4], ..., a[96]}, the second on {a[1], a[5], ..., a[97]}, etc.
func (s *StateX4) Initialize() []uint64 {
	return s[:]
}

// Perform the four parallel Keccak-f[1600]s interleaved on the slice returned
// from Initialize().
func (s *StateX4) Permute() {
	// This function should not have been called if AvailableX4 is false.
	// We could panic(), but use a slower generic implementation.
	// We don't guarantee that this function won't panic in the future!
	genericF1600x4(s[:])
}
