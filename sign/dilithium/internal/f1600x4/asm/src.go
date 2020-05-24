//go:generate go run src.go -out ../f1600x4_amd64.s -stubs ../f1600x4stubs_amd64.go -pkg f1600x4

// AVX2 fourway parallelized KeccaK-f[1600].

package main

import (
	. "github.com/mmcloughlin/avo/build"   // nolint:stylecheck,golint
	. "github.com/mmcloughlin/avo/operand" // nolint:stylecheck,golint
)

// nolint:funlen
func main() {
	ConstraintExpr("amd64")

	// Must be called on 32 byte aligned memory.
	TEXT("f1600x4", NOSPLIT, "func(state *uint64, rc *[24]uint64)")

	Pragma("noescape")

	statePtr := Load(Param("state"), GP64())
	state := func(offset int) Op {
		return Mem{Base: statePtr, Disp: 32 * offset}
	}

	rcPtr := Load(Param("rc"), GP64())

	// We use the same approach as the normal KeccaK-f[1600] implementation
	// (in the internal/shake package): we group four rounds together into a
	// super round.  Thus we have six super rounds.
	superRound := GP64()
	MOVQ(U64(6), superRound) // count down.

	// XXX Because our AVX2 is signficantly larger, it might better not
	//     to group four rounds together, but simply loop over the rounds
	//     themselves.

	Label("loop")

	for r := 0; r < 4; r++ {
		// Compute parities: p[i] = a[i] ^ a[i + 5] ^ ... ^ a[i + 20].
		p := []Op{YMM(), YMM(), YMM(), YMM(), YMM()}
		for i := 0; i < 5; i++ {
			VMOVDQA(state(i), p[i])
		}
		for j := 1; j < 5; j++ {
			for i := 0; i < 5; i++ {
				VPXOR(state(5*j+i), p[i], p[i])
			}
		}

		// Rotate and xor parities: d[i] = rotate_left(p[i+1], 1) ^ p[i-1]
		t := []Op{YMM(), YMM(), YMM(), YMM(), YMM()}
		d := []Op{YMM(), YMM(), YMM(), YMM(), YMM()}
		for i := 0; i < 5; i++ {
			VPSLLQ(U8(1), p[(i+1)%5], t[i])
		}
		for i := 0; i < 5; i++ {
			VPSRLQ(U8(63), p[(i+1)%5], d[i])
		}
		for i := 0; i < 5; i++ {
			VPOR(t[i], d[i], d[i])
		}
		for i := 0; i < 5; i++ {
			VPXOR(d[i], p[(i+4)%5], d[i])
		}

		// Rotation to use
		rot := func(i, g int) int {
			table := [][]int{{0, 24, 18, 6, 12},
				{7, 23, 2, 9, 22},
				{1, 3, 17, 16, 20},
				{13, 8, 4, 5, 15},
				{19, 10, 21, 14, 11}}
			t := table[g][i]
			return ((t + 1) * t / 2) % 64 // t'th triangle number
		}

		// Index into d to use
		di := func(i, g int) int {
			return (3*g + i) % 5
		}

		// Index into state to use
		si := func(i, g, r int) int {
			n := []int{6, 16, 11, 1}[r]
			m := []int{10, 20, 15, 5}[r]
			return (i*n + m*g) % 25
		}

		for g := 0; g < 5; g++ {
			s := []Op{YMM(), YMM(), YMM(), YMM(), YMM()}

			// Load the right five words from the state and XOR d into them.
			for i := 0; i < 5; i++ {
				VPXOR(state(si(di(i, g), g, r)), d[di(i, g)], s[i])
			}

			// Rotate each s[i] by the appropriate amount
			for i := 0; i < 5; i++ {
				if rot(i, g) != 0 {
					VPSLLQ(U8(rot(i, g)), s[i], t[i])
				}
			}
			for i := 0; i < 5; i++ {
				if rot(i, g) != 0 {
					VPSRLQ(U8(64-rot(i, g)), s[i], s[i])
				}
			}
			for i := 0; i < 5; i++ {
				if rot(i, g) != 0 {
					VPOR(t[i], s[i], s[i])
				}
			}

			// Compute the new words s[i] ^ (s[i+2] & ~s[i+1])
			for i := 0; i < 5; i++ {
				VPANDN(s[(i+2)%5], s[(i+1)%5], t[i])
			}
			for i := 0; i < 5; i++ {
				VPXOR(s[i], t[i], t[i])
			}

			// Round constant
			if g == 0 {
				// Note that we move rcPtr by 8*4 bytes after each superround.
				rc := YMM()
				VPBROADCASTQ(Mem{Base: rcPtr, Disp: r * 8}, rc)
				VPXOR(rc, t[0], t[0])
			}

			// Store back into state
			for i := 0; i < 5; i++ {
				VMOVDQA(t[i], state(si(i, g, r)))
			}
		}
	}

	ADDQ(Imm(8*4), rcPtr)
	SUBQ(U32(1), superRound)
	JNZ(LabelRef("loop"))

	RET()

	Generate()
}
