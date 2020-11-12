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
	keyPair, err := oprf.GenerateKeyPair(suite)
	test.CheckNoErr(t, err, "invalid key generation")

	server, err := oprf.NewServerWithKeyPair(suite, mode, *keyPair)
	test.CheckNoErr(t, err, "invalid setup of server")

	input := []byte("hello world")
	info := []byte("info")
	outputA, err := server.FullEvaluate(input, info)
	test.CheckNoErr(t, err, "wrong full evaluate")

	encoded, err := keyPair.Serialize()
	test.CheckNoErr(t, err, "wrong serialize")

	recoveredKeyPair := new(oprf.KeyPair)
	err = recoveredKeyPair.Deserialize(suite, encoded)
	test.CheckNoErr(t, err, "wrong deserialize")

	recoveredServer, err := oprf.NewServerWithKeyPair(suite, mode, *recoveredKeyPair)
	test.CheckNoErr(t, err, "invalid setup of server with key")

	outputB, err := recoveredServer.FullEvaluate(input, info)
	test.CheckNoErr(t, err, "invalid full evaluate")

	got := outputA
	want := outputB
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want, suite, mode)
	}
}

func testAPI(t *testing.T, suite oprf.SuiteID, mode oprf.Mode) {
	srv, err := oprf.NewServer(suite, mode)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	client, err := oprf.NewClient(suite, mode)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	inputs := [][]byte{
		{0x00},
		{0xFF},
	}
	cr, err := client.Request(inputs)
	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}

	eval, err := srv.Evaluate(cr.BlindedElements)
	if err != nil {
		t.Fatal("invalid evaluation of server: " + err.Error())
	}
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation")
	}

	info := []byte("test information")
	clientOutputs, err := client.Finalize(cr, eval, info)
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
	}

	if clientOutputs == nil {
		t.Fatal("invalid finalizing of client: no final byte array.")
	}

	for i := range inputs {
		valid := srv.VerifyFinalize(inputs[i], info, clientOutputs[i])
		if !valid {
			t.Fatal("Invalid verification from the server")
		}

		serverOutput, err := srv.FullEvaluate(inputs[i], info)
		if err != nil {
			t.Fatal("FullEvaluate failed", err)
		}
		if !bytes.Equal(serverOutput, clientOutputs[i]) {
			t.Fatalf("Client and server OPRF output mismatch, got client output %x, expected server output %x", serverOutput, clientOutputs[i])
		}
	}
}
