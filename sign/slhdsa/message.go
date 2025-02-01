package slhdsa

import (
	"crypto"
	"hash"
	"io"

	_ "golang.org/x/crypto/sha3"

	"github.com/cloudflare/circl/xof"
)

type PreHash struct {
	io.Writer
	size int
	oid  byte
}

func NewPreHashWithHash(h crypto.Hash) PreHash {
	supportedHashes := map[crypto.Hash]byte{
		crypto.SHA256:     1,
		crypto.SHA384:     2,
		crypto.SHA512:     3,
		crypto.SHA224:     4,
		crypto.SHA512_224: 5,
		crypto.SHA512_256: 6,
		crypto.SHA3_224:   7,
		crypto.SHA3_256:   8,
		crypto.SHA3_384:   9,
		crypto.SHA3_512:   10,
	}

	oid, ok := supportedHashes[h]
	if !ok {
		panic(ErrPreHash)
	}

	return PreHash{h.New(), h.Size(), oid}
}

func NewPreHashWithXof(x xof.ID) PreHash {
	switch x {
	case xof.SHAKE128:
		return PreHash{x.New(), 256 / 8, 11}
	case xof.SHAKE256:
		return PreHash{x.New(), 512 / 8, 12}
	default:
		panic(ErrPreHash)
	}
}

func (ph *PreHash) GetMessage() (*Messagito, error) {
	// Source https://csrc.nist.gov/Projects/computer-security-objects-register/algorithm-registration
	const oidLen = 11
	oid := [oidLen]byte{
		0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, ph.oid,
	}

	msg := make([]byte, oidLen, oidLen+ph.size)
	copy(msg, oid[:])
	switch f := ph.Writer.(type) {
	case hash.Hash:
		msg = f.Sum(msg)
		f.Reset()
	case xof.XOF:
		msg = msg[:cap(msg)]
		_, err := f.Read(msg[oidLen:])
		if err != nil {
			return nil, err
		}
		f.Reset()
	default:
		panic(ErrPreHash)
	}

	return &Messagito{msg, 1}, nil
}

type Messagito struct {
	msg       []byte
	isPreHash byte
}

func NewMessagito(msg []byte) *Messagito { return &Messagito{msg, 0} }

func (m Messagito) getMsgPrime(context []byte) ([]byte, error) {
	// See FIPS 205 -- Section 10.2 -- Algorithm 23 and Algorithm 25.
	if len(context) > MaxContextSize {
		return nil, ErrContext
	}

	return append(append([]byte{m.isPreHash, byte(len(context))}, context...), m.msg...), nil
}

// [Message] wraps the message to be signed.
// It implements the [io.Writer] interface, so the message can be provided
// in chunks before calling the [Sign] or [Verify] functions.
//
// There are two cases depending on whether the message must be pre-hashed:
//   - Hash Signing: Use [NewPreHashedMessage] when the message is meant
//     to be hashed before signing. The calls to [Message.Write] are
//     directly passed to the specified pre-hash function.
//   - Pure Signing. Use [NewMessage] or just create a [Message] variable,
//     if a pure signature must be created.
//     [NewMessage] is equialent to call [NewPreHashedMessage] with [Pure].
//     The calls to [Message.Write] copy the message into a internal buffer.
//     To avoid copies of the message, use [NewMessage] instead.
// type Message struct {
// 	buffer bytes.Buffer
// 	hasher interface {
// 		io.Writer
// 		SumIdempotent([]byte)
// 	}
// 	isPreHash bool
// 	oid10     byte
// 	outLen    int
// }

// // [NewMessage] wraps a message for signing, also known as pure signing.
// // Use this function or just create a [Message] variable, if the message
// // must not be pre-hashed.
// // [NewMessage] is equialent to call [NewPreHashedMessage] with [Pure].
// // The calls to [Message.Write] copy the message into an internal buffer.
// // To avoid copies of the message, use [NewMessage] instead.
// func NewMessage(msg []byte) (m Message) {
// 	_ = m.init(Pure, msg)
// 	return
// }

// // [NewPreHashedMessage] hashes the message before signing.
// // The calls to [Message.Write] are directly passed to the specified
// // pre-hash function.
// // It returns an error if the pre-hash function is not supported.
// func NewPreHashedMessage(id PreHashID) (m Message, err error) {
// 	err = m.init(id, nil)
// 	return
// }

// // Write allows to provide the message to be signed in chunks.
// // Depending on how the receiver was generated, Write will either copy the
// // chunks into an internal buffer, or pass them to the pre-hash function.
// func (m *Message) Write(p []byte) (n int, err error) {
// 	if m.isPreHash {
// 		return m.hasher.Write(p)
// 	} else {
// 		return m.buffer.Write(p)
// 	}
// }

// func (m *Message) init(ph PreHashID, msg []byte) (err error) {
// 	switch ph {
// 	case Pure:
// 		m.isPreHash = false
// 		m.buffer = *bytes.NewBuffer(msg)
// 	case PreHashSHA256:
// 		m.isPreHash = true
// 		m.oid10 = 0x01
// 		m.outLen = crypto.SHA256.Size()
// 		m.hasher = &sha2rw{sha256.New()}
// 	case PreHashSHA512:
// 		m.isPreHash = true
// 		m.oid10 = 0x03
// 		m.outLen = crypto.SHA512.Size()
// 		m.hasher = &sha2rw{sha512.New()}
// 	case PreHashSHAKE128:
// 		m.isPreHash = true
// 		m.oid10 = 0x0B
// 		m.outLen = 256 / 8
// 		m.hasher = &sha3rw{sha3.NewShake128()}
// 	case PreHashSHAKE256:
// 		m.isPreHash = true
// 		m.oid10 = 0x0C
// 		m.outLen = 512 / 8
// 		m.hasher = &sha3rw{sha3.NewShake256()}
// 	default:
// 		return ErrPreHash
// 	}

// 	if m.isPreHash && msg != nil {
// 		_, err = m.hasher.Write(msg)
// 	}

// 	return err
// }

// func (m *Message) getMsgPrime(context []byte) (msgPrime []byte, err error) {
// 	// See FIPS 205 -- Section 10.2 -- Algorithm 23 and Algorithm 25.
// 	if len(context) > MaxContextSize {
// 		return nil, ErrContext
// 	}

// 	msgPrime = append([]byte{0, byte(len(context))}, context...)

// 	var phMsg []byte
// 	if !m.isPreHash {
// 		msgPrime[0] = 0x0
// 		phMsg = m.buffer.Bytes()
// 	} else {
// 		msgPrime[0] = 0x1

// 		// Source https://csrc.nist.gov/Projects/computer-security-objects-register/algorithm-registration
// 		oid := [11]byte{
// 			0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
// 		}
// 		oid[10] = m.oid10
// 		msgPrime = append(msgPrime, oid[:]...)

// 		phMsg = make([]byte, m.outLen)
// 		m.hasher.SumIdempotent(phMsg)
// 	}

// 	return append(msgPrime, phMsg...), nil
// }

// // PreHashID specifies a function for hashing the message before signing.
// // The zero value is [NoPreHash] and stands for pure signing.
// type PreHashID byte

// const (
// 	Pure            PreHashID = PreHashID(0)
// 	PreHashSHA256   PreHashID = PreHashID(crypto.SHA256)
// 	PreHashSHA512   PreHashID = PreHashID(crypto.SHA512)
// 	PreHashSHAKE128 PreHashID = PreHashID(xof.SHAKE128)
// 	PreHashSHAKE256 PreHashID = PreHashID(xof.SHAKE256)
// )

// func (id PreHashID) String() string {
// 	switch id {
// 	case Pure:
// 		return "Pure"
// 	case PreHashSHA256:
// 		return "PreHashSHA256"
// 	case PreHashSHA512:
// 		return "PreHashSHA512"
// 	case PreHashSHAKE128:
// 		return "PreHashSHAKE128"
// 	case PreHashSHAKE256:
// 		return "PreHashSHAKE256"
// 	default:
// 		return ErrPreHash.Error()
// 	}
// }
