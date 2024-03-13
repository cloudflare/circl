package tkn20_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	cpabe "github.com/cloudflare/circl/abe/cpabe/tkn20"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/xof"
)

func TestLongPlaintext(t *testing.T) {
	// Fixed PRNG for test reproducibility.
	prng := xof.SHAKE128.New()

	pk, msk, err := cpabe.Setup(prng)
	test.CheckNoErr(t, err, "setup failed")

	attrs := cpabe.Attributes{}
	attrs.FromMap(map[string]string{
		"occupation": "doctor",
		"country":    "US",
		"age":        "16",
	})

	sk, err := msk.KeyGen(prng, attrs)
	test.CheckNoErr(t, err, "master key generation failed")

	policy := cpabe.Policy{}
	err = policy.FromString(`(occupation: doctor) and (country: US)`)
	test.CheckNoErr(t, err, "policy parsing failed")

	const N = 20 // 2^N bytes of plaintext
	buffer := make([]byte, 1<<N)
	_, err = io.ReadFull(prng, buffer)
	test.CheckNoErr(t, err, "reading message from prgn failed")

	for i := 0; i < N; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			msg := buffer[:(1 << i)]

			ct, err := pk.Encrypt(prng, policy, msg)
			test.CheckNoErr(t, err, "encryption failed")

			t.Logf("length pt: %v ct: %v", len(msg), len(ct))

			pt, err := sk.Decrypt(ct)
			test.CheckNoErr(t, err, "decryption failed")

			got := sha256.Sum256(pt)
			want := sha256.Sum256(msg)
			if !bytes.Equal(got[:], want[:]) {
				test.ReportError(t, got, want)
			}
		})
	}
}
