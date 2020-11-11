package oprf_test

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/oprf"
)

func TestServerSerialization(t *testing.T) {
	for _, suite := range []oprf.SuiteID{
		oprf.OPRFP256,
		oprf.OPRFP384,
		oprf.OPRFP521,
	} {
		keyPair, err := oprf.GenerateKeyPair(suite)
		if err != nil {
			t.Fatal("invalid key generation: " + err.Error())
		}

		server, err := oprf.NewServerWithKeyPair(suite, *keyPair)
		if err != nil {
			t.Fatal("invalid setup of server: " + err.Error())
		}

		input := []byte("hello world")
		info := []byte("info")
		outputA, errA := server.FullEvaluate(input, info)
		if errA != nil {
			t.Fatal(errA)
		}

		encoded := keyPair.Serialize()
		recoveredKeyPair := new(oprf.KeyPair)
		err = recoveredKeyPair.Deserialize(suite, encoded)
		if err != nil {
			t.Fatal(err)
		}

		recoveredServer, err := oprf.NewServerWithKeyPair(suite, *recoveredKeyPair)
		if err != nil {
			t.Fatal("invalid setup of server: " + err.Error())
		}

		outputB, errB := recoveredServer.FullEvaluate(input, info)
		if errB != nil {
			t.Fatal(errB)
		}
		if !bytes.Equal(outputA, outputB) {
			t.Fatal("failed to compute the same output after serializing and deserializing the key pair")
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
		t.Run(suite.String(), func(t *testing.T) {
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
