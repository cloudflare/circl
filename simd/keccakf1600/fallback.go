// +build !amd64

package keccakf1600

func permuteSIMD(state []uint64) { permuteScalar(state) }
