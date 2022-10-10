// Code generated from benes_348864.templ.go. DO NOT EDIT.

package mceliece348864f

func layer(data, bits []uint64, lgs int) {
	index := 0
	s := 1 << lgs
	for i := 0; i < 64; i += s * 2 {
		for j := i; j < i+s; j++ {
			d := data[j] ^ data[j+s]
			d &= bits[index]
			index++
			data[j] ^= d
			data[j+s] ^= d
		}
	}
}

func applyBenes(r *[512]byte, bits *[condBytes]byte) {
	bs := [64]uint64{}
	cond := [64]uint64{}
	for i := 0; i < 64; i++ {
		bs[i] = load8(r[i*8:])
	}

	transpose64x64(&bs, &bs)

	for low := 0; low <= 5; low++ {
		for i := 0; i < 64; i++ {
			cond[i] = uint64(load4(bits[low*256+i*4:]))
		}
		transpose64x64(&cond, &cond)
		layer(bs[:], cond[:], low)
	}

	transpose64x64(&bs, &bs)

	for low := 0; low <= 5; low++ {
		for i := 0; i < 32; i++ {
			cond[i] = load8(bits[(low+6)*256+i*8:])
		}
		layer(bs[:], cond[:], low)
	}
	for low := 4; low >= 0; low-- {
		for i := 0; i < 32; i++ {
			cond[i] = load8(bits[(4-low+6+6)*256+i*8:])
		}
		layer(bs[:], cond[:], low)
	}

	transpose64x64(&bs, &bs)

	for low := 5; low >= 0; low-- {
		for i := 0; i < 64; i++ {
			cond[i] = uint64(load4(bits[(5-low+6+6+5)*256+i*4:]))
		}
		transpose64x64(&cond, &cond)
		layer(bs[:], cond[:], low)
	}
	transpose64x64(&bs, &bs)

	for i := 0; i < 64; i++ {
		store8(r[i*8:], bs[i])
	}
}
