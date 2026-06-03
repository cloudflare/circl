package oprf

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
)

type commonClient interface {
	blind(inputs [][]byte, blinds []Blind) (*FinalizeData, *EvaluationRequest, error)
	DeterministicBlind(inputs [][]byte, blinds []Blind) (*FinalizeData, *EvaluationRequest, error)
	Blind(inputs [][]byte) (*FinalizeData, *EvaluationRequest, error)
	Finalize(d *FinalizeData, e *Evaluation) ([][]byte, error)
}

type c1 struct {
	PartialObliviousClient
	info []byte
}

func (c *c1) Finalize(f *FinalizeData, e *Evaluation) ([][]byte, error) {
	return c.PartialObliviousClient.Finalize(f, e, c.info)
}

type commonServer interface {
	Evaluate(req *EvaluationRequest) (*Evaluation, error)
	FullEvaluate(input []byte) ([]byte, error)
	VerifyFinalize(input, expectedOutput []byte) bool
	PublicKey() *PublicKey
}

type s1 struct {
	PartialObliviousServer
	info []byte
}

func (s *s1) Evaluate(req *EvaluationRequest) (*Evaluation, error) {
	return s.PartialObliviousServer.Evaluate(req, s.info)
}

func (s *s1) FullEvaluate(input []byte) ([]byte, error) {
	return s.PartialObliviousServer.FullEvaluate(input, s.info)
}

func (s *s1) VerifyFinalize(input, expectedOutput []byte) bool {
	return s.PartialObliviousServer.VerifyFinalize(input, s.info, expectedOutput)
}

type canMarshal interface {
	encoding.BinaryMarshaler
	UnmarshalBinary(id Suite, data []byte) (err error)
}

func testMarshal(t *testing.T, suite Suite, x, y canMarshal, name string) {
	t.Helper()

	wantBytes, err := x.MarshalBinary()
	test.CheckNoErr(t, err, "error on marshaling "+name)

	err = y.UnmarshalBinary(suite, wantBytes)
	test.CheckNoErr(t, err, "error on unmarshaling "+name)

	gotBytes, err := x.MarshalBinary()
	test.CheckNoErr(t, err, "error on marshaling "+name)

	if !bytes.Equal(gotBytes, wantBytes) {
		test.ReportError(t, gotBytes, wantBytes)
	}
}

func elementsMarshalBinary(g group.Group, e []group.Element) ([]byte, error) {
	output := make([]byte, 2, 2+len(e)*int(g.Params().CompressedElementLength))
	binary.BigEndian.PutUint16(output[0:2], uint16(len(e)))

	for i := range e {
		ei, err := e[i].MarshalBinaryCompress()
		if err != nil {
			return nil, err
		}
		output = append(output, ei...)
	}

	return output, nil
}

func testAPI(t *testing.T, server commonServer, client commonClient) {
	t.Helper()

	inputs := [][]byte{{0x00}, {0xFF}}
	finData, evalReq, err := client.Blind(inputs)
	test.CheckNoErr(t, err, "invalid blinding of client")

	blinds := finData.CopyBlinds()
	_, detEvalReq, err := client.DeterministicBlind(inputs, blinds)
	test.CheckNoErr(t, err, "invalid deterministic blinding of client")
	test.CheckOk(len(detEvalReq.Elements) == len(evalReq.Elements), "invalid number of evaluations", t)
	for i := range evalReq.Elements {
		test.CheckOk(evalReq.Elements[i].IsEqual(detEvalReq.Elements[i]), "invalid blinded element mismatch", t)
	}

	eval, err := server.Evaluate(evalReq)
	test.CheckNoErr(t, err, "invalid evaluation of server")
	test.CheckOk(eval != nil, "invalid evaluation of server: no evaluation", t)

	clientOutputs, err := client.Finalize(finData, eval)
	test.CheckNoErr(t, err, "invalid finalize of client")
	test.CheckOk(clientOutputs != nil, "invalid finalize of client: no outputs", t)

	for i := range inputs {
		valid := server.VerifyFinalize(inputs[i], clientOutputs[i])
		test.CheckOk(valid, "invalid verification from the server", t)

		serverOutput, err := server.FullEvaluate(inputs[i])
		test.CheckNoErr(t, err, "FullEvaluate failed")

		if !bytes.Equal(serverOutput, clientOutputs[i]) {
			test.ReportError(t, serverOutput, clientOutputs[i])
		}
	}
}

func TestAPI(t *testing.T) {
	info := []byte("shared info")

	for _, suite := range []Suite{
		SuiteRistretto255,
		SuiteP256,
		SuiteP384,
		SuiteP521,
	} {
		t.Run(suite.(fmt.Stringer).String(), func(t *testing.T) {
			private, err := GenerateKey(suite, rand.Reader)
			test.CheckNoErr(t, err, "failed private key generation")
			testMarshal(t, suite, private, new(PrivateKey), "PrivateKey")
			public := private.Public()
			testMarshal(t, suite, public, new(PublicKey), "PublicKey")

			t.Run("OPRF", func(t *testing.T) {
				s := NewServer(suite, private)
				c := NewClient(suite)
				testAPI(t, s, c)
			})

			t.Run("VOPRF", func(t *testing.T) {
				s := NewVerifiableServer(suite, private)
				c := NewVerifiableClient(suite, s.PublicKey())
				testAPI(t, s, c)
			})

			t.Run("POPRF", func(t *testing.T) {
				s := &s1{NewPartialObliviousServer(suite, private), info}
				c := &c1{NewPartialObliviousClient(suite, s.PublicKey()), info}
				testAPI(t, s, c)
			})
		})
	}
}

func TestErrors(t *testing.T) {
	goodID := SuiteP256
	strErrNil := "must be nil"
	strErrK := "must fail key"
	strErrC := "must fail client"
	strErrS := "must fail server"

	t.Run("badID", func(t *testing.T) {
		var badID Suite

		k, err := GenerateKey(badID, rand.Reader)
		test.CheckIsErr(t, err, strErrK)
		test.CheckOk(k == nil, strErrNil, t)

		k, err = DeriveKey(badID, BaseMode, nil, nil)
		test.CheckIsErr(t, err, strErrK)
		test.CheckOk(k == nil, strErrNil, t)

		err = new(PrivateKey).UnmarshalBinary(badID, nil)
		test.CheckIsErr(t, err, strErrK)

		err = new(PublicKey).UnmarshalBinary(badID, nil)
		test.CheckIsErr(t, err, strErrK)

		err = test.CheckPanic(func() { NewClient(badID) })
		test.CheckNoErr(t, err, strErrC)

		err = test.CheckPanic(func() { NewServer(badID, nil) })
		test.CheckNoErr(t, err, strErrS)

		err = test.CheckPanic(func() { NewVerifiableClient(badID, nil) })
		test.CheckNoErr(t, err, strErrC)

		err = test.CheckPanic(func() { NewVerifiableServer(badID, nil) })
		test.CheckNoErr(t, err, strErrS)

		err = test.CheckPanic(func() { NewPartialObliviousClient(badID, nil) })
		test.CheckNoErr(t, err, strErrC)

		err = test.CheckPanic(func() { NewPartialObliviousServer(badID, nil) })
		test.CheckNoErr(t, err, strErrS)
	})

	t.Run("nilPubKey", func(t *testing.T) {
		err := test.CheckPanic(func() { NewVerifiableClient(goodID, nil) })
		test.CheckNoErr(t, err, strErrC)
	})

	t.Run("nilCalls", func(t *testing.T) {
		c := NewClient(goodID)
		finData, evalReq, err := c.Blind(nil)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(finData == nil, strErrNil, t)
		test.CheckOk(evalReq == nil, strErrNil, t)

		var emptyEval Evaluation
		finData, _, _ = c.Blind([][]byte{[]byte("in0"), []byte("in1")})
		out, err := c.Finalize(finData, &emptyEval)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(out == nil, strErrNil, t)
	})

	t.Run("invalidProof", func(t *testing.T) {
		key, _ := GenerateKey(goodID, rand.Reader)
		s := NewVerifiableServer(goodID, key)
		c := NewVerifiableClient(goodID, key.Public())

		finData, evalReq, _ := c.Blind([][]byte{[]byte("in0"), []byte("in1")})
		_, _ = s.Evaluate(evalReq)
		_, evalReq, _ = c.Blind([][]byte{[]byte("in0"), []byte("in2")})
		badEV, _ := s.Evaluate(evalReq)
		_, err := c.Finalize(finData, badEV)
		test.CheckIsErr(t, err, strErrC)
	})

	t.Run("badKeyGen", func(t *testing.T) {
		key, err := GenerateKey(goodID, nil)
		test.CheckIsErr(t, err, strErrNil)
		test.CheckOk(key == nil, strErrNil, t)

		key, err = DeriveKey(goodID, Mode(8), nil, nil)
		test.CheckIsErr(t, err, strErrK)
		test.CheckOk(key == nil, strErrNil, t)
	})
}

// TestIdentityKeyRejection ensures the OPRF parsing boundary rejects the
// identity public key and the zero private key, as required by RFC 9497.
// Accepting them would let an attacker impersonate a verifiable OPRF server
// without a secret key (see ZK-dfh985d3).
func TestIdentityKeyRejection(t *testing.T) {
	suites := []Suite{SuiteRistretto255, SuiteP256, SuiteP384, SuiteP521}
	for _, suite := range suites {
		t.Run(suite.Identifier(), func(t *testing.T) {
			g := suite.Group()

			// Serialized identity element must be rejected as a public key.
			identity, err := g.Identity().MarshalBinaryCompress()
			test.CheckNoErr(t, err, "failed to marshal identity")
			err = new(PublicKey).UnmarshalBinary(suite, identity)
			test.CheckIsErr(t, err, "must reject identity public key")
			if err != ErrInvalidPublicKey {
				t.Fatalf("expected ErrInvalidPublicKey, got %v", err)
			}

			// Serialized zero scalar must be rejected as a private key.
			zero, err := g.NewScalar().MarshalBinary()
			test.CheckNoErr(t, err, "failed to marshal zero scalar")
			err = new(PrivateKey).UnmarshalBinary(suite, zero)
			test.CheckIsErr(t, err, "must reject zero private key")
			if err != ErrInvalidPrivateKey {
				t.Fatalf("expected ErrInvalidPrivateKey, got %v", err)
			}

			// Constructors must reject an identity public key defensively.
			idKey := &PublicKey{suite.(params), g.Identity()}
			err = test.CheckPanic(func() { NewVerifiableClient(suite, idKey) })
			test.CheckNoErr(t, err, "verifiable client must reject identity key")
			err = test.CheckPanic(func() { NewPartialObliviousClient(suite, idKey) })
			test.CheckNoErr(t, err, "partial oblivious client must reject identity key")

			// A valid key must still round-trip and be accepted.
			priv, err := GenerateKey(suite, rand.Reader)
			test.CheckNoErr(t, err, "failed to generate key")
			pubBytes, err := priv.Public().MarshalBinary()
			test.CheckNoErr(t, err, "failed to marshal public key")
			err = new(PublicKey).UnmarshalBinary(suite, pubBytes)
			test.CheckNoErr(t, err, "valid public key must be accepted")
			privBytes, err := priv.MarshalBinary()
			test.CheckNoErr(t, err, "failed to marshal private key")
			err = new(PrivateKey).UnmarshalBinary(suite, privBytes)
			test.CheckNoErr(t, err, "valid private key must be accepted")
		})
	}
}

func Example_oprf() {
	suite := SuiteP256
	//                                  Server(sk, pk, info*)
	private, _ := GenerateKey(suite, rand.Reader)
	server := NewServer(suite, private)
	//   Client(info*)
	client := NewClient(suite)
	//   =================================================================
	//   finData, evalReq = Blind(input)
	inputs := [][]byte{[]byte("first input"), []byte("second input")}
	finData, evalReq, _ := client.Blind(inputs)
	//
	//                               evalReq
	//                             ---------->
	//
	//                               evaluation = Evaluate(evalReq, info*)
	evaluation, _ := server.Evaluate(evalReq)
	//
	//                              evaluation
	//                             <----------
	//
	//   output = Finalize(finData, evaluation, info*)
	outputs, err := client.Finalize(finData, evaluation)
	fmt.Print(err == nil && len(inputs) == len(outputs))
	// Output: true
}

func BenchmarkAPI(b *testing.B) {
	for _, suite := range []Suite{
		SuiteRistretto255,
		SuiteP256,
		SuiteP384,
		SuiteP521,
	} {
		key, err := GenerateKey(suite, rand.Reader)
		test.CheckNoErr(b, err, "failed key generation")

		b.Run("OPRF/"+suite.Identifier(), func(b *testing.B) {
			s := NewServer(suite, key)
			c := NewClient(suite)
			benchAPI(b, s, c)
		})

		b.Run("VOPRF/"+suite.Identifier(), func(b *testing.B) {
			s := NewVerifiableServer(suite, key)
			c := NewVerifiableClient(suite, s.PublicKey())
			benchAPI(b, s, c)
		})

		b.Run("POPRF/"+suite.Identifier(), func(b *testing.B) {
			info := []byte("shared info")
			s := &s1{NewPartialObliviousServer(suite, key), info}
			c := &c1{NewPartialObliviousClient(suite, s.PublicKey()), info}
			benchAPI(b, s, c)
		})
	}
}

func benchAPI(b *testing.B, server commonServer, client commonClient) {
	b.Helper()
	inputs := [][]byte{[]byte("first input"), []byte("second input")}
	finData, evalReq, err := client.Blind(inputs)
	test.CheckNoErr(b, err, "failed client request")

	eval, err := server.Evaluate(evalReq)
	test.CheckNoErr(b, err, "failed server evaluate")

	clientOutputs, err := client.Finalize(finData, eval)
	test.CheckNoErr(b, err, "failed client finalize")

	b.Run("Client/Request", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = client.Blind(inputs)
		}
	})

	b.Run("Server/Evaluate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = server.Evaluate(evalReq)
		}
	})

	b.Run("Client/Finalize", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = client.Finalize(finData, eval)
		}
	})

	b.Run("Server/VerifyFinalize", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := range inputs {
				server.VerifyFinalize(inputs[j], clientOutputs[j])
			}
		}
	})

	b.Run("Server/FullEvaluate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := range inputs {
				_, _ = server.FullEvaluate(inputs[j])
			}
		}
	})
}
