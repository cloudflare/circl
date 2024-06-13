// Code generated from benes_other.templ.go. DO NOT EDIT.

package mceliece8192128

// Layers of the Beneš network. The required size of `data` and `bits` depends on the value `lgs`.
func layerIn(data *[2][64]uint64, bits *[64]uint64, lgs int) {
	s := 1 << lgs
	index := 0
	for i := 0; i < 64; i += s * 2 {
		for j := i; j < i+s; j++ {
			d := data[0][j+0] ^ data[0][j+s]
			d &= bits[index]
			data[0][j+0] ^= d
			data[0][j+s] ^= d
			index += 1

			d = data[1][j+0] ^ data[1][j+s]
			d &= bits[index]
			data[1][j+0] ^= d
			data[1][j+s] ^= d
			index += 1
		}
	}
}

// Exterior layers of the Beneš network. The length of `bits` depends on the value of `lgs`.
// Note that this implementation is quite different from the C implementation.
// However, it does make sense. Whereas the C implementation uses pointer arithmetic to access
// the entire array `data`, this implementation always considers `data` as two-dimensional array.
// The C implementation uses 128 as upper bound (because the array contains 128 elements),
// but this implementation has 64 elements per subarray and needs case distinctions at different places.
func layerEx(data *[2][64]uint64, bits *[64]uint64, lgs int) {
	data0Idx := 0
	data1Idx := 32
	s := 1 << lgs
	if s == 64 {
		for j := 0; j < 64; j++ {
			d := data[0][j+0] ^ data[1][j]
			d &= bits[data0Idx]
			data0Idx += 1
			data[0][j+0] ^= d
			data[1][j] ^= d
		}
	} else {
		for i := 0; i < 64; i += s * 2 {
			for j := i; j < i+s; j++ {
				d := data[0][j+0] ^ data[0][j+s]
				d &= bits[data0Idx]
				data0Idx += 1

				data[0][j+0] ^= d
				data[0][j+s] ^= d

				// data[1] computations
				d = data[1][j+0] ^ data[1][j+s]
				d &= bits[data1Idx]
				data1Idx += 1

				data[1][j+0] ^= d
				data[1][j+s] ^= d
			}
		}
	}
}

// Apply Beneš network in-place to array `r` based on configuration `bits`.
// Here, `r` is a sequence of bits to be permuted.
// `bits` defines the condition bits configuring the Beneš network and
// Note that this differs from the C implementation, missing the `rev` parameter.
// This is because `rev` is not used throughout the entire codebase.
func applyBenes(r *[1024]byte, bits *[condBytes]byte) {
	rIntV := [2][64]uint64{}
	rIntH := [2][64]uint64{}
	bIntV := [64]uint64{}
	bIntH := [64]uint64{}
	bitsPtr := bits[:]

	for i := 0; i < 64; i++ {
		rIntV[0][i] = load8(r[i*16:])
		rIntV[1][i] = load8(r[i*16+8:])
	}

	transpose64x64(&rIntH[0], &rIntV[0])
	transpose64x64(&rIntH[1], &rIntV[1])

	for iter := 0; iter <= 6; iter++ {
		for i := 0; i < 64; i++ {
			bIntV[i] = load8(bitsPtr)
			bitsPtr = bitsPtr[8:]
		}
		transpose64x64(&bIntH, &bIntV)
		layerEx(&rIntH, &bIntH, iter)
	}

	transpose64x64(&rIntV[0], &rIntH[0])
	transpose64x64(&rIntV[1], &rIntH[1])

	for iter := 0; iter <= 5; iter++ {
		for i := 0; i < 64; i++ {
			bIntV[i] = load8(bitsPtr)
			bitsPtr = bitsPtr[8:]
		}
		layerIn(&rIntV, &bIntV, iter)
	}

	for iter := 4; iter >= 0; iter-- {
		for i := 0; i < 64; i++ {
			bIntV[i] = load8(bitsPtr)
			bitsPtr = bitsPtr[8:]
		}
		layerIn(&rIntV, &bIntV, iter)
	}

	transpose64x64(&rIntH[0], &rIntV[0])
	transpose64x64(&rIntH[1], &rIntV[1])

	for iter := 6; iter >= 0; iter-- {
		for i := 0; i < 64; i++ {
			bIntV[i] = load8(bitsPtr)
			bitsPtr = bitsPtr[8:]
		}
		transpose64x64(&bIntH, &bIntV)
		layerEx(&rIntH, &bIntH, iter)
	}

	transpose64x64(&rIntV[0], &rIntH[0])
	transpose64x64(&rIntV[1], &rIntH[1])

	for i := 0; i < 64; i++ {
		store8(r[i*16+0:], rIntV[0][i])
		store8(r[i*16+8:], rIntV[1][i])
	}
}
