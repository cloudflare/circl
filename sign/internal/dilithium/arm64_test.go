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

func BenchmarkExceedsThreshold(b *testing.B) {
	var p Poly

	for i := range uint32(N) {
		p[i] = i
	}

	b.SetParallelism(1)
	b.Run(
		"ARM64", func(b *testing.B) {
			b.SetParallelism(1)

			b.Run(
				"1stElementExceeds", func(b *testing.B) {
					b.SetBytes(N * 4)

					for b.Loop() {
						p.Exceeds(0)
					}
				},
			)
			// on my machine (M1 Max), this is the threshold in which the arm64 version outperforms the generic version.
			b.Run(
				"4thElementExceeds", func(b *testing.B) {
					b.SetBytes(N * 4)

					for b.Loop() {
						p.Exceeds(3)
					}
				},
			)
			b.Run(
				"NoElementExceeds", func(b *testing.B) {
					b.SetBytes(N * 4)

					for b.Loop() {
						p.Exceeds(256)
					}
				},
			)
		},
	)
	b.Run(
		"Generic", func(b *testing.B) {
			b.SetParallelism(1)

			b.Run(
				"1stElementExceeds", func(b *testing.B) {
					b.SetBytes(N * 4)

					for b.Loop() {
						p.exceedsGeneric(0)
					}
				},
			)
			b.Run(
				"4thElementExceeds", func(b *testing.B) {
					b.SetBytes(N * 4)

					for b.Loop() {
						p.exceedsGeneric(3)
					}
				},
			)
			b.Run(
				"NoElementExceeds", func(b *testing.B) {
					b.SetBytes(N * 4)

					for b.Loop() {
						p.exceedsGeneric(256)
					}
				},
			)
		},
	)
}
