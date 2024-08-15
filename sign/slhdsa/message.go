package slhdsa

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/xof"
)

// [Message] wraps the message to be signed.
// It implements the [io.Writer] interface, so the message can be provided
// in chunks before calling the [PrivateKey.SignRandomized],
// [PrivateKey.SignDeterministic], or [Verify] functions.
//
// There are two cases depending on whether the message must be pre-hashed:
//   - Hash Signing: Use [NewMessageWithPreHash] when the message is meant
//     to be hashed before signing. The calls to [Message.Write] are
//     directly passed to the specified pre-hash function.
//   - Pure Signing. Use [NewMessage] or just create a [Message] variable,
//     if the message must not be pre-hashed.
//     Calling [NewMessageWithPreHash] with [NoPreHash] is equivalent.
//     The calls to [Message.Write] copy the message into a internal buffer.
//     To avoid copies of the message, use [NewMessage] instead.
type Message struct {
	buffer bytes.Buffer
	hasher interface {
		io.Writer
		SumIdempotent([]byte)
	}
	isPreHash bool
	oid10     byte
	outLen    int
}

// [NewMessage] wraps a message for signing, also known as pure signing.
// Use this function or just create a [Message] variable, if the message
// must not be pre-hashed.
// Calling [NewMessageWithPreHash] with [NoPreHash] is equivalent.
// The calls to [Message.Write] copy the message into a internal buffer.
// To avoid copies of the message, use [NewMessage] instead.
func NewMessage(msg []byte) (m Message) {
	_ = m.init(NoPreHash, msg)
	return
}

// [NewMessageWithPreHash] wraps a message to be hashed before signing.
// The calls to [Message.Write] are directly passed to the specified
// pre-hash function.
// It returns an error if the pre-hash function is not supported.
func NewMessageWithPreHash(id PreHashID) (m Message, err error) {
	err = m.init(id, nil)
	return
}

// Write allows to provide the message to be signed in chunks.
// Depending on how the receiver was generated, Write will either copy the
// chunks into an internal buffer, or pass them to the pre-hash function.
func (m *Message) Write(p []byte) (n int, err error) {
	if m.isPreHash {
		return m.hasher.Write(p)
	} else {
		return m.buffer.Write(p)
	}
}

func (m *Message) init(ph PreHashID, msg []byte) (err error) {
	switch ph {
	case NoPreHash:
		m.isPreHash = false
		m.buffer = *bytes.NewBuffer(msg)
	case PreHashSHA256:
		m.isPreHash = true
		m.oid10 = 0x01
		m.outLen = crypto.SHA256.Size()
		m.hasher = &sha2rw{sha256.New()}
	case PreHashSHA512:
		m.isPreHash = true
		m.oid10 = 0x03
		m.outLen = crypto.SHA512.Size()
		m.hasher = &sha2rw{sha512.New()}
	case PreHashSHAKE128:
		m.isPreHash = true
		m.oid10 = 0x0B
		m.outLen = 256 / 8
		m.hasher = &sha3rw{sha3.NewShake128()}
	case PreHashSHAKE256:
		m.isPreHash = true
		m.oid10 = 0x0C
		m.outLen = 512 / 8
		m.hasher = &sha3rw{sha3.NewShake256()}
	default:
		return ErrPreHash
	}

	if m.isPreHash && msg != nil {
		_, err = m.hasher.Write(msg)
	}

	return err
}

func (m *Message) getMsgPrime(context []byte) (msgPrime []byte, err error) {
	// See FIPS 205 -- Section 10.2 -- Algorithm 23 and Algorithm 25.
	if len(context) > MaxContextSize {
		return nil, ErrContext
	}

	msgPrime = append([]byte{0, byte(len(context))}, context...)

	var phMsg []byte
	if !m.isPreHash {
		msgPrime[0] = 0x0
		phMsg = m.buffer.Bytes()
	} else {
		msgPrime[0] = 0x1

		oid := [11]byte{
			0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
		}
		oid[10] = m.oid10
		msgPrime = append(msgPrime, oid[:]...)

		phMsg = make([]byte, m.outLen)
		m.hasher.SumIdempotent(phMsg)
	}

	return append(msgPrime, phMsg...), nil
}

// PreHashID specifies a function for hashing the message before signing.
// The zero value is [NoPreHash] and stands for pure signing.
type PreHashID byte

const (
	NoPreHash       PreHashID = PreHashID(0)
	PreHashSHA256   PreHashID = PreHashID(crypto.SHA256)
	PreHashSHA512   PreHashID = PreHashID(crypto.SHA512)
	PreHashSHAKE128 PreHashID = PreHashID(xof.SHAKE128)
	PreHashSHAKE256 PreHashID = PreHashID(xof.SHAKE256)
)

func (id PreHashID) String() string {
	switch id {
	case NoPreHash:
		return "NoPreHash"
	case PreHashSHA256:
		return "PreHashSHA256"
	case PreHashSHA512:
		return "PreHashSHA512"
	case PreHashSHAKE128:
		return "PreHashSHAKE128"
	case PreHashSHAKE256:
		return "PreHashSHAKE256"
	default:
		return ErrPreHash.Error()
	}
}
