//go:build arm64 && !purego
// +build arm64,!purego

package dilithium

import (
	"testing"
	"unsafe"
)

func TestAssemblyImplementationAssumptions(t *testing.T) {
	var p Poly

	if len(p) != 256 {
		t.Fatal("length of p must be 256. (assumption of the arm64 implementations)")
	}

	if unsafe.Sizeof(p) != 1024 {
		t.Fatal("sizeof p be must be 1024 bytes. (assumption of the arm64 implementations)")
	}
}
