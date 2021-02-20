package oprf_test

import (
	"bytes"
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
	privateKey, err := oprf.GenerateKey(suite)
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
	test.CheckNoErr(t, err, "invalid setup of server")

	var client *oprf.Client
	if mode == oprf.BaseMode {
		client, err = oprf.NewClient(suite)
	} else if mode == oprf.VerifiableMode {
		pkS := server.GetPublicKey()
		client, err = oprf.NewVerifiableClient(suite, pkS)
	}
	test.CheckNoErr(t, err, "invalid setup of client")

	inputs := [][]byte{{0x00}, {0xFF}}
	cr, err := client.Request(inputs)
	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}

	eval, err := server.Evaluate(cr.BlindedElements)
	if err != nil {
		t.Fatal("invalid evaluation of server: " + err.Error())
	}
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation")
	}

	clientOutputs, err := client.Finalize(cr, eval)
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
	}

	if clientOutputs == nil {
		t.Fatal("invalid finalizing of client: no final byte array.")
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
