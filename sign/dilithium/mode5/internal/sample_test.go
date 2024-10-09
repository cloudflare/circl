// Code generated from mode3/internal/sample_test.go by gen.go

package internal

import (
	"encoding/binary"
	"testing"

	common "github.com/cloudflare/circl/sign/internal/dilithium"
)

func TestVectorDeriveUniform(t *testing.T) {
	var p, p2 common.Poly
	var seed [32]byte
	p2 = common.Poly{
		2901364, 562527, 5258502, 3885002, 4190126, 4460268, 6884052,
		3514511, 5383040, 213206, 2155865, 5179607, 3551954, 2312357,
		6066350, 8126097, 1179080, 4787182, 6552182, 6713644,
		1561067, 7626063, 7859743, 5052321, 7032876, 7815031, 157938,
		1865184, 490802, 5717642, 3451902, 7000218, 3743250, 1677431,
		1875427, 5596150, 671623, 3819041, 6247594, 1014875, 4933545,
		7122446, 6682963, 3388398, 3335295, 943002, 1145083, 3113071,
		105967, 1916675, 7474561, 1107006, 700548, 2147909, 1603855,
		5049181, 437882, 6118899, 5656914, 6731065, 3066622, 865453,
		5427634, 981549, 4650873, 861291, 4003872, 5104220, 6171453,
		3723302, 7426315, 6137283, 4874820, 6052561, 53441, 5032874,
		5614778, 2248550, 1756499, 8280764, 8263880, 7600081,
		5118374, 795344, 7543392, 6869925, 1841187, 4181568, 584562,
		7483939, 4938664, 6863397, 5126354, 5218129, 6236086,
		4149293, 379169, 4368487, 7490569, 3409215, 1580463, 3081737,
		1278732, 7109719, 7371700, 2097931, 399836, 1700274, 7188595,
		6830029, 1548850, 6593138, 6849097, 1518037, 2859442,
		7772265, 7325153, 3281191, 7856131, 4995056, 4684325,
		1351194, 8223904, 6817307, 2484146, 131782, 397032, 7436778,
		7973479, 3171829, 5624626, 3540123, 7150120, 8313283,
		3604714, 1043574, 117692, 7797783, 7909392, 903315, 7335342,
		7501562, 5826142, 2709813, 8245473, 2369045, 2782257,
		5762833, 6474114, 6862031, 424522, 594248, 2626630, 7659983,
		5642869, 4075194, 1592129, 245547, 5271031, 3205046, 982375,
		267873, 1286496, 7230481, 3208972, 7485411, 676111, 4944500,
		2959742, 5934456, 1414847, 6067948, 1709895, 4648315, 126008,
		8258986, 2183134, 2302072, 4674924, 4306056, 7465311,
		6500270, 4247428, 4016815, 4973426, 294287, 2456847, 3289700,
		2732169, 1159447, 5569724, 140001, 3237977, 8007761, 5874533,
		255652, 3119586, 2102434, 6248250, 8152822, 8006066, 7708625,
		6997719, 6260212, 6186962, 6636650, 7836834, 7998017,
		2061516, 1197591, 1706544, 733027, 2392907, 2700000, 8254598,
		4488002, 160495, 2985325, 2036837, 2703633, 6406550, 3579947,
		6195178, 5552390, 6804584, 6305468, 5731980, 6095195,
		3323409, 1322661, 6690942, 3374630, 5615167, 479044, 3136054,
		4380418, 2833144, 7829577, 1770522, 6056687, 240415, 14780,
		3740517, 5224226, 3547288, 2083124, 4699398, 3654239,
		5624978, 585593, 3655369, 2281739, 3338565, 1908093, 7784706,
		4352830,
	}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}
	PolyDeriveUniform(&p, &seed, 30000)
	if p != p2 {
		t.Fatalf("%v != %v", p, p2)
	}
}

func TestDeriveUniform(t *testing.T) {
	var p common.Poly
	var seed [32]byte
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		PolyDeriveUniform(&p, &seed, uint16(i))
		if !PolyNormalized(&p) {
			t.Fatal()
		}
	}
}

func TestDeriveUniformLeqEta(t *testing.T) {
	var p common.Poly
	var seed [64]byte
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		PolyDeriveUniformLeqEta(&p, &seed, uint16(i))
		for j := 0; j < common.N; j++ {
			if p[j] < common.Q-Eta || p[j] > common.Q+Eta {
				t.Fatal()
			}
		}
	}
}

func TestDeriveUniformLeGamma1(t *testing.T) {
	var p common.Poly
	var seed [64]byte
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		PolyDeriveUniformLeGamma1(&p, &seed, uint16(i))
		for j := 0; j < common.N; j++ {
			if (p[j] > Gamma1 && p[j] <= common.Q-Gamma1) || p[j] >= common.Q {
				t.Fatal()
			}
		}
	}
}

func TestDeriveUniformBall(t *testing.T) {
	var p common.Poly
	var seed [CTildeSize]byte
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		PolyDeriveUniformBall(&p, seed[:])
		nonzero := 0
		for j := 0; j < common.N; j++ {
			if p[j] != 0 {
				if p[j] != 1 && p[j] != common.Q-1 {
					t.Fatal()
				}
				nonzero++
			}
		}
		if nonzero != Tau {
			t.Fatal()
		}
	}
}

func TestDeriveUniformX4(t *testing.T) {
	if !DeriveX4Available {
		t.SkipNow()
	}
	var ps [4]common.Poly
	var p common.Poly
	var seed [32]byte
	nonces := [4]uint16{12345, 54321, 13532, 37377}

	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i)
	}

	PolyDeriveUniformX4([4]*common.Poly{&ps[0], &ps[1], &ps[2], &ps[3]}, &seed,
		nonces)
	for i := 0; i < 4; i++ {
		PolyDeriveUniform(&p, &seed, nonces[i])
		if ps[i] != p {
			t.Fatal()
		}
	}
}

func TestDeriveUniformBallX4(t *testing.T) {
	if !DeriveX4Available {
		t.SkipNow()
	}
	var ps [4]common.Poly
	var p common.Poly
	var seed [CTildeSize]byte
	PolyDeriveUniformBallX4(
		[4]*common.Poly{&ps[0], &ps[1], &ps[2], &ps[3]},
		seed[:],
	)
	for j := 0; j < 4; j++ {
		PolyDeriveUniformBall(&p, seed[:])
		if ps[j] != p {
			t.Fatalf("%d\n%v\n%v", j, ps[j], p)
		}
	}
}

func BenchmarkPolyDeriveUniformBall(b *testing.B) {
	var seed [32]byte
	var p common.Poly
	var w1 VecK
	for i := 0; i < b.N; i++ {
		w1[0][0] = uint32(i)
		PolyDeriveUniformBall(&p, seed[:])
	}
}

func BenchmarkPolyDeriveUniformBallX4(b *testing.B) {
	var seed [32]byte
	var p common.Poly
	var w1 VecK
	for i := 0; i < b.N; i++ {
		w1[0][0] = uint32(i)
		PolyDeriveUniformBallX4(
			[4]*common.Poly{&p, &p, &p, &p},
			seed[:],
		)
	}
}

func BenchmarkPolyDeriveUniform(b *testing.B) {
	var seed [32]byte
	var p common.Poly
	for i := 0; i < b.N; i++ {
		PolyDeriveUniform(&p, &seed, uint16(i))
	}
}

func BenchmarkPolyDeriveUniformX4(b *testing.B) {
	if !DeriveX4Available {
		b.SkipNow()
	}
	var seed [32]byte
	var p [4]common.Poly
	for i := 0; i < b.N; i++ {
		nonce := uint16(4 * i)
		PolyDeriveUniformX4([4]*common.Poly{&p[0], &p[1], &p[2], &p[3]},
			&seed, [4]uint16{nonce, nonce + 1, nonce + 2, nonce + 3})
	}
}

func BenchmarkPolyDeriveUniformLeGamma1(b *testing.B) {
	var seed [64]byte
	var p common.Poly
	for i := 0; i < b.N; i++ {
		PolyDeriveUniformLeGamma1(&p, &seed, uint16(i))
	}
}
