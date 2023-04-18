package k12

import (
	"encoding/hex"
	"testing"
)

// See draft-irtf-cfrg-kangarootwelve-10 §4.
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/10/
func ptn(n int) []byte {
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = byte(i % 0xfb)
	}
	return buf
}

func testK12(t *testing.T, msg []byte, c []byte, l int, want string) {
	do := func(lanes byte, writeSize int) {
		h := newDraft10(c, lanes)
		msg2 := msg
		for len(msg2) > 0 {
			to := writeSize
			if len(msg2) < to {
				to = len(msg2)
			}
			_, _ = h.Write(msg2[:to])
			msg2 = msg2[to:]
		}
		buf := make([]byte, l)
		_, _ = h.Read(buf)
		got := hex.EncodeToString(buf)
		if want != got {
			t.Fatalf("%s != %s (lanes=%d, writeSize=%d )", want, got, lanes, writeSize)
		}
	}

	for _, lanes := range []byte{1, 2, 4} {
		for _, writeSize := range []int{7919, 1024, 8 * 1024} {
			do(lanes, writeSize)
		}
	}
}

func TestK12(t *testing.T) {
	// I-D test vectors
	testK12(t, []byte{}, []byte{}, 32, "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5")
	i := 17
	testK12(t, ptn(i), []byte{}, 32, "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888")
	i *= 17
	testK12(t, ptn(i), []byte{}, 32, "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c")
	i *= 17
	testK12(t, ptn(i), []byte{}, 32, "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0")
	i *= 17
	testK12(t, ptn(i), []byte{}, 32, "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe")
	i *= 17
	testK12(t, ptn(i), []byte{}, 32, "844d610933b1b9963cbdeb5ae3b6b05cc7cbd67ceedf883eb678a0a8e0371682")
	i *= 17
	testK12(t, ptn(i), []byte{}, 32, "3c390782a8a4e89fa6367f72feaaf13255c8d95878481d3cd8ce85f58e880af8")
	testK12(t, []byte{}, ptn(1), 32, "fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583")
	testK12(t, []byte{0xff}, ptn(41), 32, "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4")
	testK12(t, []byte{0xff, 0xff, 0xff}, ptn(41*41), 32, "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74")
	testK12(t, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ptn(41*41*41), 32, "75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf")

	// Cornercases
	testK12(t, ptn(chunkSize), []byte{}, 16, "48f256f6772f9edfb6a8b661ec92dc93")
	testK12(t, ptn(chunkSize+1), []byte{}, 16, "bb66fe72eaea5179418d5295ee134485")
	testK12(t, ptn(2*chunkSize), []byte{}, 16, "82778f7f7234c83352e76837b721fbdb")
	testK12(t, ptn(2*chunkSize+1), []byte{}, 16, "5f8d2b943922b451842b4e82740d0236")
	testK12(t, ptn(3*chunkSize), []byte{}, 16, "f4082a8fe7d1635aa042cd1da63bf235")
	testK12(t, ptn(3*chunkSize+1), []byte{}, 16, "38cb940999aca742d69dd79298c6051c")
}

func BenchmarkK12_100B(b *testing.B) { benchmarkK12(b, 100, 1) }
func BenchmarkK12_10K(b *testing.B)  { benchmarkK12(b, 10000, 1) }
func BenchmarkK12_100K(b *testing.B) { benchmarkK12(b, 10000, 10) }
func BenchmarkK12_1M(b *testing.B)   { benchmarkK12(b, 10000, 100) }
func BenchmarkK12_10M(b *testing.B)  { benchmarkK12(b, 10000, 1000) }

func benchmarkK12(b *testing.B, size, num int) {
	b.StopTimer()
	h := NewDraft10([]byte{})
	data := make([]byte, size)
	d := make([]byte, 32)

	b.SetBytes(int64(size * num))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		h.Reset()
		for j := 0; j < num; j++ {
			_, _ = h.Write(data)
		}
		_, _ = h.Read(d)
	}
}
