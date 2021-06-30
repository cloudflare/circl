package oprf_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/oprf"
)

func TestOPRF(t *testing.T) {
	for _, suite := range []oprf.SuiteID{
		oprf.OPRFP256,
		oprf.OPRFP384,
		oprf.OPRFP521,
	} {
		for _, mode := range []oprf.Mode{
			oprf.BaseMode,
			oprf.VerifiableMode,
		} {
			suite, mode := suite, mode
			name := fmt.Sprintf("Suite%v/Mode%v", suite, mode)
			t.Run("API/"+name, func(tt *testing.T) { testAPI(tt, suite, mode) })
			t.Run("Serde/"+name, func(tt *testing.T) { testSerialization(tt, suite, mode) })
		}
	}
}

func testSerialization(t *testing.T, suite oprf.SuiteID, mode oprf.Mode) {
	privateKey, err := oprf.GenerateKey(suite, rand.Reader)
	test.CheckNoErr(t, err, "invalid key generation")

	var server *oprf.Server
	if mode == oprf.BaseMode {
		server, err = oprf.NewServer(suite, privateKey)
	} else if mode == oprf.VerifiableMode {
		server, err = oprf.NewVerifiableServer(suite, privateKey)
	}
	test.CheckNoErr(t, err, "invalid setup of server")

	input := []byte("hello world")
	outputA, err := server.FullEvaluate(input)
	test.CheckNoErr(t, err, "wrong full evaluate")

	encoded, err := privateKey.Serialize()
	test.CheckNoErr(t, err, "wrong serialize")

	recoveredPrivateKey := new(oprf.PrivateKey)
	err = recoveredPrivateKey.Deserialize(suite, encoded)
	test.CheckNoErr(t, err, "wrong deserialize")

	var recoveredServer *oprf.Server
	if mode == oprf.BaseMode {
		recoveredServer, err = oprf.NewServer(suite, recoveredPrivateKey)
	} else if mode == oprf.VerifiableMode {
		recoveredServer, err = oprf.NewVerifiableServer(suite, recoveredPrivateKey)
	}
	test.CheckNoErr(t, err, "invalid setup of server with key")

	outputB, err := recoveredServer.FullEvaluate(input)
	test.CheckNoErr(t, err, "invalid full evaluate")

	got := outputA
	want := outputB
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want, suite, mode)
	}
}

func testAPI(t *testing.T, suite oprf.SuiteID, mode oprf.Mode) {
	var err error
	var server *oprf.Server
	if mode == oprf.BaseMode {
		server, err = oprf.NewServer(suite, nil)
	} else if mode == oprf.VerifiableMode {
		server, err = oprf.NewVerifiableServer(suite, nil)
	}
	test.CheckOk(server.GetMode() == mode, "bad server mode", t)
	test.CheckNoErr(t, err, "invalid setup of server")

	var client *oprf.Client
	if mode == oprf.BaseMode {
		client, err = oprf.NewClient(suite)
	} else if mode == oprf.VerifiableMode {
		pkS := server.GetPublicKey()
		client, err = oprf.NewVerifiableClient(suite, pkS)
	}
	test.CheckOk(client.GetMode() == mode, "bad client mode", t)
	test.CheckNoErr(t, err, "invalid setup of client")

	inputs := [][]byte{{0x00}, {0xFF}}
	cr, err := client.Request(inputs)
	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}

	eval, err := server.Evaluate(cr.BlindedElements())
	if err != nil {
		t.Fatal("invalid evaluation of server: " + err.Error())
	}
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation")
	}
	sizes, err := oprf.GetSizes(suite)
	if err != nil {
		t.Fatal("invalid calling GetSizes: " + err.Error())
	}
	for _, e := range eval.Elements {
		if uint(len(e)) != sizes.SerializedElementLength {
			t.Fatal("invalid evaluation length")
		}
	}
	if mode == oprf.VerifiableMode {
		if uint(len(eval.Proof.C)) != sizes.SerializedScalarLength ||
			uint(len(eval.Proof.S)) != sizes.SerializedScalarLength {
			t.Fatal("invalid proof length")
		}
	}
	clientOutputs, err := client.Finalize(cr, eval)
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
	}

	if clientOutputs == nil {
		t.Fatal("invalid finalizing of client: no final byte array.")
	}

	for _, o := range clientOutputs {
		if uint(len(o)) != sizes.OutputLength {
			t.Fatal("invalid output length")
		}
	}

	for i := range inputs {
		valid := server.VerifyFinalize(inputs[i], clientOutputs[i])
		if !valid {
			t.Fatal("Invalid verification from the server")
		}

		serverOutput, err := server.FullEvaluate(inputs[i])
		if err != nil {
			t.Fatal("FullEvaluate failed", err)
		}
		if !bytes.Equal(serverOutput, clientOutputs[i]) {
			t.Fatalf("Client and server OPRF output mismatch, got client output %x, expected server output %x", serverOutput, clientOutputs[i])
		}
	}
}

func TestErrors(t *testing.T) {
	id := oprf.OPRFP256
	strErrNil := "must be nil"
	strErrK := "must fail key"
	strErrC := "must fail client"
	strErrS := "must fail server"

	t.Run("badID", func(t *testing.T) {
		var badID oprf.SuiteID

		k, err := oprf.GenerateKey(badID, rand.Reader)
		test.CheckIsErr(t, err, strErrK)
		test.CheckOk(k == nil, strErrNil, t)

		k, err = oprf.DeriveKey(badID, oprf.BaseMode, nil)
		test.CheckIsErr(t, err, strErrK)
		test.CheckOk(k == nil, strErrNil, t)

		err = new(oprf.PrivateKey).Deserialize(badID, nil)
		test.CheckIsErr(t, err, strErrK)

		err = new(oprf.PublicKey).Deserialize(badID, nil)
		test.CheckIsErr(t, err, strErrK)

		c, err := oprf.NewClient(badID)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(c == nil, strErrNil, t)

		s, err := oprf.NewServer(badID, nil)
		test.CheckIsErr(t, err, strErrS)
		test.CheckOk(s == nil, strErrNil, t)

		vc, err := oprf.NewVerifiableClient(badID, nil)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(vc == nil, strErrNil, t)
	})

	t.Run("nilPubKey", func(t *testing.T) {
		vc, err := oprf.NewVerifiableClient(id, nil)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(vc == nil, strErrNil, t)
	})

	t.Run("mismatchKeys", func(t *testing.T) {
		otherID := id + 1
		otherKey, _ := oprf.GenerateKey(otherID, rand.Reader)
		vs, err := oprf.NewServer(id, otherKey)
		test.CheckIsErr(t, err, strErrS)
		test.CheckOk(vs == nil, strErrNil, t)

		vc, err := oprf.NewVerifiableClient(id, otherKey.Public())
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(vc == nil, strErrNil, t)
	})

	t.Run("nilCalls", func(t *testing.T) {
		c, _ := oprf.NewClient(id)
		cl, err := c.Request(nil)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(cl == nil, strErrNil, t)

		var emptyEval oprf.Evaluation
		cl, _ = c.Request([][]byte{[]byte("in0"), []byte("in1")})
		out, err := c.Finalize(cl, &emptyEval)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(out == nil, strErrNil, t)

		s, _ := oprf.NewServer(id, nil)
		ev, err := s.Evaluate(nil)
		test.CheckIsErr(t, err, strErrS)
		test.CheckOk(ev == nil, strErrNil, t)
	})

	t.Run("invalidProof", func(t *testing.T) {
		key, _ := oprf.GenerateKey(id, rand.Reader)
		s, _ := oprf.NewVerifiableServer(id, key)
		c, _ := oprf.NewVerifiableClient(id, key.Public())
		cl, _ := c.Request([][]byte{[]byte("in0"), []byte("in1")})
		badEV, _ := s.Evaluate(cl.BlindedElements())
		badEV.Proof.C = nil
		badEV.Proof.S = nil
		out, err := c.Finalize(cl, badEV)
		test.CheckIsErr(t, err, strErrC)
		test.CheckOk(out == nil, strErrNil, t)
	})

	t.Run("badKeyGen", func(t *testing.T) {
		err := test.CheckPanic(func() { _, _ = oprf.GenerateKey(id, nil) })
		test.CheckNoErr(t, err, strErrNil)

		k, err := oprf.DeriveKey(id, oprf.Mode(2), nil)
		test.CheckIsErr(t, err, strErrK)
		test.CheckOk(k == nil, strErrNil, t)
	})
}

func BenchmarkOPRF(b *testing.B) {
	suite := oprf.OPRFP256
	serverBasic, err := oprf.NewServer(suite, nil)
	test.CheckNoErr(b, err, "failed server creation")
	clientBasic, err := oprf.NewClient(suite)
	test.CheckNoErr(b, err, "failed client creation")

	benchOprf(b, serverBasic, clientBasic)
}

func BenchmarkVOPRF(b *testing.B) {
	suite := oprf.OPRFP256
	serverVerif, err := oprf.NewVerifiableServer(suite, nil)
	test.CheckNoErr(b, err, "failed server creation")
	pkS := serverVerif.GetPublicKey()
	clientVerif, err := oprf.NewVerifiableClient(suite, pkS)
	test.CheckNoErr(b, err, "failed client creation")

	benchOprf(b, serverVerif, clientVerif)
}

func benchOprf(b *testing.B, server *oprf.Server, client *oprf.Client) {
	inputs := [][]byte{{0x00}, {0xFF}}
	cr, err := client.Request(inputs)
	test.CheckNoErr(b, err, "failed client request")
	eval, err := server.Evaluate(cr.BlindedElements())
	test.CheckNoErr(b, err, "failed server evaluate")
	clientOutputs, err := client.Finalize(cr, eval)
	test.CheckNoErr(b, err, "failed client finalize")

	b.Run("Client/Request", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = client.Request(inputs)
		}
	})

	b.Run("Server/Evaluate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = server.Evaluate(cr.BlindedElements())
		}
	})

	b.Run("Client/Finalize", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = client.Finalize(cr, eval)
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
