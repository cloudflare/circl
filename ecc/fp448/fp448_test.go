// @author Armando Faz

package fp448_test

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	fp448 "github.com/cloudflare/circl/ecc/fp448"
)

// getFixedSizeBytes returns an array of numBytes bytes containing
// the big number stored in x.
// if the size of x (in bytes) is greater than numBytes, then
// it returns the first numBytes bytes of x
func getFixedSizeBytes(x *big.Int, numBytes int) []byte {
	bytesX := x.Bytes()
	if len(bytesX) > numBytes {
		return bytesX[len(bytesX)-numBytes:]
	}
	if len(bytesX) < numBytes {
		buf := make([]byte, numBytes)
		copy(buf[numBytes-len(bytesX):], bytesX)
		bytesX = buf
	}
	return bytesX
}

// setFromBigInt returns the little endian version of num for a fixed size.
// if num is greater than size bytes, it returns the first num bytes
// if num is lesser than size bytes, it pads zeros.
func setFromBigInt(num *big.Int, size int) (out []byte) {
	out = make([]byte, size)
	bytesBigEndian := getFixedSizeBytes(num, size)
	for i := 0; i < size; i++ {
		out[i] = bytesBigEndian[size-1-i]
	}
	return out
}

func Test(t *testing.T) {
	numTests := 1000
	seed := time.Now().UnixNano()
	r := rand.New(rand.NewSource(seed))

	var bigPrime, bigOne, twoTo448, twoTo896 big.Int
	bigOne.SetUint64(1)
	bigPrime.Lsh(&bigOne, 224)
	bigPrime.Sub(&bigPrime, &bigOne)
	bigPrime.Lsh(&bigPrime, 224)
	bigPrime.Sub(&bigPrime, &bigOne)
	twoTo448.SetUint64(1)
	twoTo448.Lsh(&twoTo448, 448)
	twoTo896.SetUint64(1)
	twoTo896.Lsh(&twoTo896, 896)

	var bigX, bigY, bigZ big.Int

	t.Run("select", func(t *testing.T) {
		var y, got, want fp448.Element
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo448)
			bigY.Rand(r, &twoTo448)
			bigZ.Rand(r, &twoTo448)
			b := int(bigZ.Bit(0))
			if b == 0 {
				copy(want[:], setFromBigInt(&bigX, fp448.SizeElement))
			} else {
				copy(want[:], setFromBigInt(&bigY, fp448.SizeElement))
			}

			copy(got[:], setFromBigInt(&bigX, fp448.SizeElement))
			copy(y[:], setFromBigInt(&bigY, fp448.SizeElement))
			fp448.CSelect(&got, &y, b)

			if got != want {
				t.Errorf("[Error in %v] got %v, want %v", t.Name(), got, want)
			}
		}
	})

	t.Run("swap", func(t *testing.T) {
		var got0, got1, want0, want1 fp448.Element
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo448)
			bigY.Rand(r, &twoTo448)
			bigZ.Rand(r, &twoTo448)
			b := int(bigZ.Bit(0))
			if b == 0 {
				copy(want0[:], setFromBigInt(&bigX, fp448.SizeElement))
				copy(want1[:], setFromBigInt(&bigY, fp448.SizeElement))
			} else {
				copy(want0[:], setFromBigInt(&bigY, fp448.SizeElement))
				copy(want1[:], setFromBigInt(&bigX, fp448.SizeElement))
			}

			copy(got0[:], setFromBigInt(&bigX, fp448.SizeElement))
			copy(got1[:], setFromBigInt(&bigY, fp448.SizeElement))
			fp448.CSwap(&got0, &got1, b)

			if got0 != want0 || got1 != want1 {
				t.Errorf("[Error in %v] got %v, want %v", t.Name(), got0, want0)
			}
		}
	})

	t.Run("prime", func(t *testing.T) {
		var got, want fp448.Element

		copy(want[:], setFromBigInt(&bigPrime, fp448.SizeElement))
		got = fp448.Prime()

		if got != want {
			t.Errorf("[Error in %v] got %v, want %v", t.Name(), got, want)
		}
	})

	t.Run("add", func(t *testing.T) {
		var x, y, got, want fp448.Element
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo448)
			bigY.Rand(r, &twoTo448)
			bigZ.Add(&bigX, &bigY)
			bigZ.Mod(&bigZ, &bigPrime)
			copy(want[:], setFromBigInt(&bigZ, fp448.SizeElement))

			// fp448.Element
			copy(x[:], setFromBigInt(&bigX, fp448.SizeElement))
			copy(y[:], setFromBigInt(&bigY, fp448.SizeElement))
			fp448.Add(&got, &x, &y)
			fp448.ModuloP(&got)

			if got != want {
				t.Errorf("[Error in %v] seed:%x i:%d got %v, want %v", t.Name(), seed, testID, got, want)
			}
		}
	})

	t.Run("sub", func(t *testing.T) {
		var x, y, got, want fp448.Element
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo448)
			bigY.Rand(r, &twoTo448)
			bigZ.Sub(&bigX, &bigY)
			bigZ.Mod(&bigZ, &bigPrime)

			copy(want[:], setFromBigInt(&bigZ, fp448.SizeElement))

			// fp448.Element
			copy(x[:], setFromBigInt(&bigX, fp448.SizeElement))
			copy(y[:], setFromBigInt(&bigY, fp448.SizeElement))
			fp448.Sub(&got, &x, &y)
			fp448.ModuloP(&got)

			if got != want {
				t.Errorf("[Error in %v] seed:%x i:%d got %v, want %v", t.Name(), seed, testID, got, want)
			}
		}
	})

	t.Run("addsub", func(t *testing.T) {
		var gotX, gotY, wantX, wantY fp448.Element
		var bigAdd, bigSub big.Int
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo448)
			bigY.Rand(r, &twoTo448)
			bigAdd.Add(&bigX, &bigY)
			bigSub.Sub(&bigX, &bigY)
			bigAdd.Mod(&bigAdd, &bigPrime)
			bigSub.Mod(&bigSub, &bigPrime)

			copy(wantX[:], setFromBigInt(&bigAdd, fp448.SizeElement))
			copy(wantY[:], setFromBigInt(&bigSub, fp448.SizeElement))

			// fp448.Element
			copy(gotX[:], setFromBigInt(&bigX, fp448.SizeElement))
			copy(gotY[:], setFromBigInt(&bigY, fp448.SizeElement))
			fp448.AddSub(&gotX, &gotY)
			fp448.ModuloP(&gotX)
			fp448.ModuloP(&gotY)

			if gotX != wantX {
				t.Errorf("[Error in %v] seed:%x i:%d got %v, want %v", t.Name(), seed, testID, gotX, wantX)
			}
			if gotY != wantY {
				t.Errorf("[Error in %v] seed:%x i:%d got %v, want %v", t.Name(), seed, testID, gotY, wantY)
			}
		}
	})

	t.Run("imul", func(t *testing.T) {
		var x, y fp448.Element
		var got, want [2 * fp448.SizeElement]byte
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo448)
			bigY.Rand(r, &twoTo448)
			bigZ.Mul(&bigX, &bigY)
			copy(want[:], setFromBigInt(&bigZ, 2*fp448.SizeElement))

			// fp448.Element
			copy(x[:], setFromBigInt(&bigX, fp448.SizeElement))
			copy(y[:], setFromBigInt(&bigY, fp448.SizeElement))
			fp448.IntMul(&got, &x, &y)

			if got != want {
				t.Errorf("[Error in %v] seed:%x i:%d got %v, want %v", t.Name(), seed, testID, got, want)
			}
		}
	})

	t.Run("isqr", func(t *testing.T) {
		var x fp448.Element
		var got, want [2 * fp448.SizeElement]byte
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo448)
			bigZ.Mul(&bigX, &bigX)
			copy(want[:], setFromBigInt(&bigZ, 2*fp448.SizeElement))

			// fp448.Element
			copy(x[:], setFromBigInt(&bigX, fp448.SizeElement))
			fp448.IntSqr(&got, &x)

			if got != want {
				t.Errorf("[Error in %v] seed:%x i:%d got %v, want %v", t.Name(), seed, testID, got, want)
			}
		}
	})

	t.Run("ired", func(t *testing.T) {
		var x [2 * fp448.SizeElement]byte
		var got, want fp448.Element
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo896)
			bigZ.Mod(&bigX, &bigPrime)
			copy(want[:], setFromBigInt(&bigZ, fp448.SizeElement))

			// fp448.Element
			copy(x[:], setFromBigInt(&bigX, 2*fp448.SizeElement))
			fp448.Reduce(&got, &x)
			fp448.ModuloP(&got)

			if got != want {
				t.Errorf("[Error in %v] seed:%x i:%d got %v, want %v", t.Name(), seed, testID, got, want)
			}
		}
	})

	t.Run("div", func(t *testing.T) {
		var x, y, got, want fp448.Element
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo448)
			bigY.Rand(r, &twoTo448)
			bigZ.ModInverse(&bigY, &bigPrime)
			bigZ.Mul(&bigZ, &bigX)
			bigZ.Mod(&bigZ, &bigPrime)
			copy(want[:], setFromBigInt(&bigZ, fp448.SizeElement))

			// fp448.Element
			copy(x[:], setFromBigInt(&bigX, fp448.SizeElement))
			copy(y[:], setFromBigInt(&bigY, fp448.SizeElement))
			fp448.Div(&got, &x, &y)
			fp448.ModuloP(&got)

			if got != want {
				t.Errorf("[Error in %v] seed:%x i:%d got %v, want %v", t.Name(), seed, testID, got, want)
			}
		}
	})

	t.Run("mulw", func(t *testing.T) {
		_A24 := uint64(39082)
		var bigW big.Int
		var x, got, want fp448.Element
		for testID := 0; testID < numTests; testID++ {
			// Big Int
			bigX.Rand(r, &twoTo448)
			bigW.SetUint64(_A24)
			bigZ.Mul(&bigX, &bigW)
			bigZ.Mod(&bigZ, &bigPrime)
			copy(want[:], setFromBigInt(&bigZ, fp448.SizeElement))

			// fp448.Element
			copy(x[:], setFromBigInt(&bigX, fp448.SizeElement))
			fp448.MulA24(&got, &x)
			fp448.ModuloP(&got)

			if got != want {
				t.Errorf("[Error in %v] seed:%x i:%d got %v, want %v", t.Name(), seed, testID, got, want)
			}
		}
	})
}

func BenchmarkCSelect(b *testing.B) {
	var x, y fp448.Element
	for i := 0; i < b.N; i++ {
		fp448.CSelect(&x, &y, i)
	}
}

func BenchmarkCSwap(b *testing.B) {
	var x, y fp448.Element
	for i := 0; i < b.N; i++ {
		fp448.CSwap(&x, &y, i)
	}
}

func BenchmarkAdd(b *testing.B) {
	var x, y, z fp448.Element
	for i := 0; i < b.N; i++ {
		fp448.Add(&z, &x, &y)
	}
}

func BenchmarkSub(b *testing.B) {
	var x, y, z fp448.Element
	for i := 0; i < b.N; i++ {
		fp448.Sub(&z, &x, &y)
	}
}

func BenchmarkAddSub(b *testing.B) {
	var x, y fp448.Element
	for i := 0; i < b.N; i++ {
		fp448.AddSub(&x, &y)
	}
}

func BenchmarkIntMul(b *testing.B) {
	var x, y fp448.Element
	var buffer [2 * fp448.SizeElement]byte
	for i := 0; i < b.N; i++ {
		fp448.IntMul(&buffer, &x, &y)
	}
}

func BenchmarkIntSqr(b *testing.B) {
	var x fp448.Element
	var buffer [2 * fp448.SizeElement]byte
	for i := 0; i < b.N; i++ {
		fp448.IntSqr(&buffer, &x)
	}
}

func BenchmarkReduce(b *testing.B) {
	var z fp448.Element
	var buffer [2 * fp448.SizeElement]byte
	for i := 0; i < b.N; i++ {
		fp448.Reduce(&z, &buffer)
	}
}

func BenchmarkSqrn(b *testing.B) {
	var z fp448.Element
	var buffer [2 * fp448.SizeElement]byte
	for i := 0; i < b.N; i++ {
		fp448.Sqrn(&z, &buffer, 10)
	}
}

func BenchmarkDiv(b *testing.B) {
	var x, y, z fp448.Element
	for i := 0; i < b.N; i++ {
		fp448.Div(&z, &x, &y)
	}
}
