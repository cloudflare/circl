// Code generated from benes_other.templ.go. DO NOT EDIT.

package mceliece460896f

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
