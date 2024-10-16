package slhdsa

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestMessagePreHash(t *testing.T) {
	const N = 128
	context := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	for _, ph := range []PreHashID{
		NoPreHash,
		PreHashSHA256,
		PreHashSHA512,
		PreHashSHAKE128,
		PreHashSHAKE256,
	} {
		var msg []byte
		m0, err := NewMessageWithPreHash(ph)
		test.CheckNoErr(t, err, "NewMessageWithPreHash failed")

		for i := byte(0); i < N; i++ {
			_, errWrite := m0.Write([]byte{i})
			test.CheckNoErr(t, errWrite, "Write failed")
			msg = append(msg, i)
		}

		got, err := m0.getMsgPrime(context)
		test.CheckNoErr(t, err, "getMsgPrime failed")

		m1, err := NewMessageWithPreHash(ph)
		test.CheckNoErr(t, err, "NewMessageWithPreHash failed")

		_, err = m1.Write(msg)
		test.CheckNoErr(t, err, "Write failed")

		want, err := m1.getMsgPrime(context)
		test.CheckNoErr(t, err, "getMsgPrime failed")

		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, ph)
		}
	}
}

func TestMessageNoPreHash(t *testing.T) {
	const N = 128
	context := []byte("context string")

	var msg []byte
	var m0 Message
	for i := byte(0); i < N; i++ {
		_, errWrite := m0.Write([]byte{i})
		test.CheckNoErr(t, errWrite, "Write failed")
		msg = append(msg, i)
	}

	got, err := m0.getMsgPrime(context)
	test.CheckNoErr(t, err, "getMsgPrime failed")

	m1 := NewMessage(msg)
	want, err := m1.getMsgPrime(context)
	test.CheckNoErr(t, err, "getMsgPrime failed")

	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want)
	}

	m2, err := NewMessageWithPreHash(NoPreHash)
	test.CheckNoErr(t, err, "NewMessageWithPreHash failed")

	_, err = m2.Write(msg)
	test.CheckNoErr(t, err, "Write failed")

	want, err = m2.getMsgPrime(context)
	test.CheckNoErr(t, err, "getMsgPrime failed")

	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want)
	}
}
