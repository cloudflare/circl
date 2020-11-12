package oprf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/oprf"
)

func TestServerSerialization(t *testing.T) {
	for _, suite := range []oprf.SuiteID{
		oprf.OPRFP256,
		oprf.OPRFP384,
		oprf.OPRFP521,
	} {
		keyPair, err := oprf.GenerateKeyPair(suite)
		test.CheckNoErr(t, err, "invalid key generation")

		server, err := oprf.NewServerWithKeyPair(suite, *keyPair)
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

		recoveredServer, err := oprf.NewServerWithKeyPair(suite, *recoveredKeyPair)
		test.CheckNoErr(t, err, "invalid setup of server with key")

		outputB, err := recoveredServer.FullEvaluate(input, info)
		test.CheckNoErr(t, err, "invalid full evaluate")

		got := outputA
		want := outputB
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, suite)
		}
	}
}

func TestOPRF(t *testing.T) {
	for _, suite := range []oprf.SuiteID{
		oprf.OPRFP256,
		oprf.OPRFP384,
		oprf.OPRFP521,
	} {
		suite := suite
		name := fmt.Sprintf("Suite#%v/Mode#%v", suite, oprf.BaseMode)
		t.Run(name, func(t *testing.T) {
			srv, err := oprf.NewServer(suite)
			if err != nil {
				t.Fatal("invalid setup of server: " + err.Error())
			}
			if srv == nil {
				t.Fatal("invalid setup of server: no server.")
			}

			client, err := oprf.NewClient(suite)
			if err != nil {
				t.Fatal("invalid setup of client: " + err.Error())
			}

			input := []byte{00}
			cr, err := client.Request(input)
			if err != nil {
				t.Fatal("invalid blinding of client: " + err.Error())
			}

			eval, err := srv.Evaluate(cr.BlindedToken)
			if err != nil {
				t.Fatal("invalid evaluation of server: " + err.Error())
			}
			if eval == nil {
				t.Fatal("invalid evaluation of server: no evaluation")
			}

			info := []byte("test information")
			clientOutput, err := cr.Finalize(eval, info)
			if err != nil {
				t.Fatal("invalid unblinding of client: " + err.Error())
			}

			if clientOutput == nil {
				t.Fatal("invalid finalizing of client: no final byte array.")
			}

			valid := srv.VerifyFinalize(input, info, clientOutput)
			if !valid {
				t.Fatal("Invalid verification from the server")
			}

			serverOutput, err := srv.FullEvaluate(input, info)
			if err != nil {
				t.Fatal("FullEvaluate failed", err)
			}
			if !bytes.Equal(serverOutput, clientOutput) {
				t.Fatalf("Client and server OPRF output mismatch, got client output %x, expected server output %x", serverOutput, clientOutput)
			}
		})
	}
}
