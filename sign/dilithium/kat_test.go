package dilithium

// Code to generate the NIST "PQCsignKAT" test vectors.
// See PQCsignKAT_sign.c and randombytes.c in the reference implementation.

import (
	"crypto/aes"
	"crypto/sha256"
	"fmt"
	"testing"
)

// See NIST's PQCgenKAT.c.
type DRBG struct {
	key [32]byte
	v   [16]byte
}

func (g *DRBG) incV() {
	for j := 15; j >= 0; j-- {
		if g.v[j] == 255 {
			g.v[j] = 0
		} else {
			g.v[j]++
			break
		}
	}
}

// AES256_CTR_DRBG_Update(pd, &g.key, &g.v).
func (g *DRBG) update(pd *[48]byte) {
	var buf [48]byte
	b, _ := aes.NewCipher(g.key[:])
	for i := 0; i < 3; i++ {
		g.incV()
		b.Encrypt(buf[i*16:(i+1)*16], g.v[:])
	}
	if pd != nil {
		for i := 0; i < 48; i++ {
			buf[i] ^= pd[i]
		}
	}
	copy(g.key[:], buf[:32])
	copy(g.v[:], buf[32:])
}

// randombyte_init(seed, NULL, 256).
func NewDRBG(seed *[48]byte) (g DRBG) {
	g.update(seed)
	return
}

// randombytes.
func (g *DRBG) Fill(x []byte) {
	var block [16]byte

	b, _ := aes.NewCipher(g.key[:])
	for len(x) > 0 {
		g.incV()
		b.Encrypt(block[:], g.v[:])
		if len(x) < 16 {
			copy(x[:], block[:len(x)])
			break
		}
		copy(x[:], block[:])
		x = x[16:]
	}
	g.update(nil)
}

func TestPQCgenKATSign(t *testing.T) {
	// From SHA256SUMS in the reference implementation.
	testPQCgenKATSign(t, "Dilithium1", "dd83f8584fded0398547827edff081969335c32069f3e4a9dbd865fd5c2ecd2b")
	testPQCgenKATSign(t, "Dilithium2", "532f4a7a416bba96b607395a6d07fc0eaab1f1f968e49758d2a97c718de832e7")
	testPQCgenKATSign(t, "Dilithium3", "37a16744627f2566180a547d022f03a36d22c50080303027179751070e626c72")
	testPQCgenKATSign(t, "Dilithium4", "4c2e6d7c8675e9345e3ab7036a4e9fb786549d242462ba9b68f58db94e84147a")
	testPQCgenKATSign(t, "Dilithium1-AES", "68fabe91565c9a664d2461c7510ac32419eadfac0566dc3e9141d276bb98e11a")
	testPQCgenKATSign(t, "Dilithium2-AES", "08865a608edcdb5723769c583b37c17c9ff8cae578f1d88df7e173ed06dd23fa")
	testPQCgenKATSign(t, "Dilithium3-AES", "f3c5fcceafa9fb2462721f272791a26c9a123b3a07fad7e07dfec232085fdd7f")
	testPQCgenKATSign(t, "Dilithium4-AES", "8de4e2ac2032f714263aa0d045275ec62b6f192f8828cfe82b63ec0b0b32deb6")
}

func testPQCgenKATSign(t *testing.T, name, expected string) {
	mode := ModeByName(name)
	if mode == nil {
		t.Fatal()
	}

	var seed [48]byte
	var eseed [96]byte
	for i := 0; i < 48; i++ {
		seed[i] = byte(i)
	}
	f := sha256.New()
	g := NewDRBG(&seed)
	fmt.Fprintf(f, "# %s\n\n", name)
	for i := 0; i < 100; i++ {
		mlen := 33 * (i + 1)
		g.Fill(seed[:])
		msg := make([]byte, mlen)
		g.Fill(msg[:])
		fmt.Fprintf(f, "count = %d\n", i)
		fmt.Fprintf(f, "seed = %X\n", seed)
		fmt.Fprintf(f, "mlen = %d\n", mlen)
		fmt.Fprintf(f, "msg = %X\n", msg)
		g2 := NewDRBG(&seed)
		g2.Fill(eseed[:])
		pk, sk := mode.NewKeyFromExpandedSeed(&eseed)
		fmt.Fprintf(f, "pk = %X\n", pk.Bytes())
		fmt.Fprintf(f, "sk = %X\n", sk.Bytes())
		fmt.Fprintf(f, "smlen = %d\n", mlen+mode.SignatureSize())
		fmt.Fprintf(f, "sm = %X%X\n\n", mode.Sign(sk, msg[:]), msg)
	}
	if fmt.Sprintf("%x", f.Sum(nil)) != expected {
		t.Fatal()
	}
}
