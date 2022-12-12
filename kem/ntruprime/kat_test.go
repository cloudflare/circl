package ntruprime

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/nist"
	"github.com/cloudflare/circl/kem/schemes"
	sntrupSchemes "github.com/cloudflare/circl/pke/ntruprime/kem/schemes/sntrup"
)

func TestPQCgenStreamlinedKATKem(t *testing.T) {
	kats := []struct {
		name string
		want string
	}{
		// Computed from reference implementation
		{"sntrup653", "82249a46c1bc538e980a2335764c81f70701e6374eed3e1d0457e18c57ec2cee64280dcc75504c2648eb3e37ab3eee37955c1114d851f755a28cc997aba781c8"},
		{"sntrup761", "1a687f42261c47fe4421b35c5d9faf035433fcb2101458680c66c8d54caafec5fb767ea7725d6681ab100912ef06c38d88862a5d2d86786af2989b7dad33813a"},
		{"sntrup857", "79473d6c709dbbc99528886bf2c1d033c409dab1755299154f33232bc57ba1fbe91322fcb741df5252d575a77aa5ca000d52a44c17f1ab64a299884d0f101519"},
		{"sntrup953", "6fe0cf3b8cb62a3011c1870ec9eb3cd8825c06993a213e01ecd0f21f5dee670838fe1c89dd120086a09e8227496a00e22188c8f947618a35764c5a24726ce16c"},
		{"sntrup1013", "195a38eb843fdda53241f65b641ab925f61fb1cf5b0fffcb5891115da121a85174a796d69c75b86c4e92193453155aef9d27ce53aa268076617be55ee6f5da4f"},
		{"sntrup1277", "ada8a0cbe6b077dc563874fd372f60779bbee1524f576c2931cf9c804163b9632163610d6e380f889170cdf4d9928de0782368a43413f2b6976897ba0e19a828"},
	}

	for _, kat := range kats {
		kat := kat
		t.Run(kat.name, func(t *testing.T) {
			testPQCgenStreamlinedKATKem(t, kat.name, kat.want)
		})
	}
}

func TestPQCgenLPRKATKem(t *testing.T) {
	kats := []struct {
		name string
		want string
		p    int
	}{
		// Computed from reference implementation
		{"ntrulpr653", "30b750e9bcf5a14d0dc10a1a4f0ff4269f7ff7a5b8b835fe7d50d45de3653bbb33c3943fc50759175ba7fef92fd601ac705d7658d3f15a8a7610973ef098e849", 653},
		{"ntrulpr761", "35f9b8191aef509766019015b7af11dd2afaadf7fca827a9b0a80f7318b7e8325345c64d5b5562ee321465378102850297fbbd70fe78c5bd711e382015189e5a", 761},
		{"ntrulpr857", "919c675a5b1f642d97b866a284c633f52ad309a1f24a5713fa2f7839a84d07091b2c5a80841ce73a2090cc0ce707d9f262772f730d15905ab238a7be1c1e1e3e", 857},
		{"ntrulpr953", "2ae003933ca87d873956969977b3d7b5133e42df0868a0cbb77067cf9144ce18b0e4342ba850e2f4d46257aaea23f1e290448e3a34e6774f9594230343de7038", 953},
		{"ntrulpr1013", "5c054bab923095d3dc4250e5e71923c98b7e3bc778aa4a2a4235b8751106eac2cf0e41dc413d1b6fc7bdc8301a46ca206b19b6301c554cf643d473a55a5940a1", 1013},
		{"ntrulpr1277", "1ec1702ff090324385fdd98a7f1c1adfe80503593e3531c2c3ed7547df47da38fcdd8dedf142d2b426b3f98015b5c8fe3688b41808c513bdada66a15b7f727ab", 1277},
	}

	for _, kat := range kats {
		kat := kat
		t.Run(kat.name, func(t *testing.T) {
			testPQCgenLPRKATKem(t, kat.name, kat.want, kat.p)
		})
	}
}

func testPQCgenLPRKATKem(t *testing.T, name, expected string, p int) {
	scheme := schemes.ByName(name)
	if scheme == nil {
		t.Fatal()
	}

	var seed [48]byte
	kseed := make([]byte, scheme.SeedSize())
	eseed := make([]byte, scheme.EncapsulationSeedSize())
	seedBytes := 32

	for i := 0; i < 48; i++ {
		seed[i] = byte(i)
	}

	g1 := nist.NewDRBG(&seed)

	f := sha512.New()

	fmt.Fprintf(f, "# kem/%s\n\n", name)

	for i := 0; i < 100; i++ {
		g1.Fill(seed[:])

		fmt.Fprintf(f, "count = %d\n", i)
		fmt.Fprintf(f, "seed = %X\n", seed)

		g2 := nist.NewDRBG(&seed)

		g2.Fill(kseed[:seedBytes])
		for i := 0; i < p; i++ {
			g2.Fill(kseed[seedBytes+i*4 : seedBytes+i*4+4])
		}
		g2.Fill(kseed[seedBytes+p*4:])

		pk, sk := scheme.DeriveKeyPair(kseed)
		ppk, _ := pk.MarshalBinary()
		psk, _ := sk.MarshalBinary()

		g2.Fill(eseed)
		ct, ss1, err := scheme.EncapsulateDeterministically(pk, eseed)
		if err != nil {
			t.Fatal(err)
		}
		ss2, _ := scheme.Decapsulate(sk, ct)

		if !bytes.Equal(ss1[:], ss2[:]) {
			t.Fatal()
		}
		fmt.Fprintf(f, "pk = %X\n", ppk)
		fmt.Fprintf(f, "sk = %X\n", psk)
		fmt.Fprintf(f, "ct = %X\n", ct)
		fmt.Fprintf(f, "ss = %X\n\n", ss1)
	}
	if fmt.Sprintf("%x", f.Sum(nil)) != expected {
		t.Fatal()
	}
}

func testPQCgenStreamlinedKATKem(t *testing.T, name, expected string) {
	scheme := sntrupSchemes.ByName(name)
	if scheme == nil {
		t.Fatal()
	}

	var seed [48]byte

	for i := 0; i < 48; i++ {
		seed[i] = byte(i)
	}

	g1 := nist.NewDRBG(&seed)
	f := sha512.New()

	fmt.Fprintf(f, "# kem/%s\n\n", name)
	for i := 0; i < 100; i++ {
		g1.Fill(seed[:])

		fmt.Fprintf(f, "count = %d\n", i)
		fmt.Fprintf(f, "seed = %X\n", seed)

		g2 := nist.NewDRBG(&seed)

		pk, sk := scheme.DeriveKeyPairFromGen(&g2)
		ppk, _ := pk.MarshalBinary()
		psk, _ := sk.MarshalBinary()

		ct, ss1, _ := scheme.EncapsulateDeterministicallyFromGen(pk, &g2)
		ss2, _ := scheme.Decapsulate(sk, ct)
		if !bytes.Equal(ss1, ss2) {
			t.Fatal()
		}
		fmt.Fprintf(f, "pk = %X\n", ppk)
		fmt.Fprintf(f, "sk = %X\n", psk)
		fmt.Fprintf(f, "ct = %X\n", ct)
		fmt.Fprintf(f, "ss = %X\n\n", ss1)

	}
	if fmt.Sprintf("%x", f.Sum(nil)) != expected {
		t.Fatal()
	}
}
