package slhdsa

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

// The independent oracle hashes the complete FIPS 205 input, including the
// public-seed block. It does not use the state's hash functions or input buffers.
func prefixDigest(seed, addr, msg []byte, wide bool) []byte {
	block := sha256.BlockSize
	if wide {
		block = sha512.BlockSize
	}
	in := make([]byte, block, block+len(addr)+len(msg))
	copy(in, seed)
	in = append(in, addr...)
	in = append(in, msg...)
	if wide {
		sum := sha512.Sum512(in)
		return sum[:len(seed)]
	}
	sum := sha256.Sum256(in)
	return sum[:len(seed)]
}

func prefixBytes(n, salt int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*29 + salt)
	}
	return out
}

// Restoring a saved prefix must still bind every address/message byte and must
// not carry a previous invocation's message into the next digest.
func TestSHA2PrefixDigests(t *testing.T) {
	for _, id := range []ID{SHA2_128s, SHA2_128f, SHA2_192s, SHA2_192f, SHA2_256s, SHA2_256f} {
		t.Run(id.String(), func(t *testing.T) {
			p := id.params()
			seed := prefixBytes(int(p.n), 17)
			original := bytes.Clone(seed)
			s := p.NewStatePub(seed)
			// Construction must own its prefix, independent of caller changes.
			clear(seed)
			for round := range 8 {
				addr := prefixBytes(addressSizeCompressed, round*31)
				m0 := prefixBytes(int(p.n), round+7)
				m1 := prefixBytes(int(p.n), round+81)
				copy(s.F.address.b, addr)
				s.F.SetMessage(m0)
				if !bytes.Equal(s.F.Final(), prefixDigest(original, addr, m0, false)) {
					t.Fatal("F differs from full-input SHA-256")
				}
				copy(s.H.address.b, addr)
				s.H.SetMsgs(m0, m1)
				joined := append(bytes.Clone(m0), m1...)
				if !bytes.Equal(s.H.Final(), prefixDigest(original, addr, joined, p.n != 16)) {
					t.Fatal("H differs from full-input SHA-2")
				}
				copy(s.T.address.b, addr)
				msg := prefixBytes(round*int(p.n), round)
				s.T.Reset()
				s.T.WriteMessage(msg[:len(msg)/2])
				s.T.WriteMessage(msg[len(msg)/2:])
				want := prefixDigest(original, addr, msg, p.n != 16)
				if !bytes.Equal(s.T.Final(), want) || !bytes.Equal(s.T.Final(), want) {
					t.Fatal("T differs from full-input SHA-2 or Final is not idempotent")
				}
			}
			input, output := s.F.input, s.F.output
			s.Clear()
			s.Clear() // Clearing an already-cleared state must remain harmless.
			if !bytes.Equal(input, make([]byte, len(input))) || !bytes.Equal(output, make([]byte, len(output))) {
				t.Fatal("Clear left owned F input or output bytes behind")
			}
		})
	}
}

type countedPrefixStream struct {
	inner interface {
		Write([]byte) (int, error)
		Reset()
		Final([]byte)
	}
	written int
}

func (h *countedPrefixStream) Write(p []byte) (int, error) {
	h.written += len(p)
	return h.inner.Write(p)
}
func (h *countedPrefixStream) Reset()           { h.inner.Reset() }
func (h *countedPrefixStream) Final(out []byte) { h.inner.Final(out) }

// Count the real hashing inputs after setup. Reintroducing the public-seed
// block on every invocation must fail this resource regression.
func TestSHA2PrefixReuse(t *testing.T) {
	for _, id := range []ID{SHA2_128s, SHA2_128f, SHA2_192s, SHA2_192f, SHA2_256s, SHA2_256f} {
		t.Run(id.String(), func(t *testing.T) {
			p := id.params()
			s := p.NewStatePub(prefixBytes(int(p.n), 9))
			defer s.Clear()
			for _, test := range []struct {
				name string
				base *baseHasher
				want int
			}{{"F", &s.F.baseHasher, addressSizeCompressed + int(p.n)}, {"H", &s.H.baseHasher, addressSizeCompressed + 2*int(p.n)}} {
				t.Run(test.name, func(t *testing.T) {
					original := test.base.hash
					written := 0
					test.base.hash = func(out, in []byte) {
						written += len(in)
						original(out, in)
					}
					for range 3 {
						test.base.Final()
					}
					if written != 3*test.want {
						t.Fatalf("hashed %d bytes after setup; want %d without repeated seed blocks", written, 3*test.want)
					}
				})
			}
			stream := &countedPrefixStream{inner: s.T.hash}
			s.T.hash = stream
			msg := prefixBytes(3*int(p.n), 21)
			for range 3 {
				s.T.Reset()
				s.T.WriteMessage(msg)
				s.T.Final()
			}
			if want := 3 * (addressSizeCompressed + len(msg)); stream.written != want {
				t.Fatalf("T hashed %d bytes after setup; want %d without repeated seed blocks", stream.written, want)
			}
		})
	}
}

// A saved prefix is useful only if restoring it and producing a truncated
// digest do not introduce allocations in the F/H/T hot loops.
func TestSHA2PrefixAllocations(t *testing.T) {
	for _, id := range []ID{SHA2_128s, SHA2_128f, SHA2_192s, SHA2_192f, SHA2_256s, SHA2_256f} {
		t.Run(id.String(), func(t *testing.T) {
			p := id.params()
			s := p.NewStatePub(prefixBytes(int(p.n), 5))
			defer s.Clear()
			msg := prefixBytes(int(p.n), 19)
			s.F.SetMessage(msg)
			s.H.SetMsgs(msg, msg)
			if n := testing.AllocsPerRun(100, func() {
				s.F.Final()
				s.H.Final()
				s.T.Reset()
				s.T.WriteMessage(msg)
				s.T.Final()
			}); n != 0 {
				t.Fatalf("F/H/T allocate after setup: %v allocations", n)
			}
		})
	}
}
