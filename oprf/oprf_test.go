package oprf_test

import (
	"testing"

	"github.com/cloudflare/circl/oprf"
)

func TestServerSetUp(t *testing.T) {
	srv, err := oprf.NewServer(oprf.OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	if srv.K == nil {
		t.Fatal("invalid setup of server: no keypair")
	}
}

func TestClientSetUp(t *testing.T) {
	client, err := oprf.NewClient(oprf.OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}
	if client == nil {
		t.Fatal("invalid setup of client: no server.")
	}
}

func TestClientBlind(t *testing.T) {
	client, err := oprf.NewClient(oprf.OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken, err := client.Blind([]byte{00})

	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}
	if token == nil {
		t.Fatal("invalid blinding of client: no token.")
	}

	if bToken == nil {
		t.Fatal("invalid blinding of client: no blinded token")
	}
}

func TestServerEvaluation(t *testing.T) {
	srv, err := oprf.NewServer(oprf.OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	client, err := oprf.NewClient(oprf.OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	_, bToken, err := client.Blind([]byte{00})
	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}

	eval := srv.Evaluate(bToken)
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation.")
	}
}

func TestClientUnblind(t *testing.T) {
	srv, err := oprf.NewServer(oprf.OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	client, err := oprf.NewClient(oprf.OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken, err := client.Blind([]byte{00})
	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}

	eval := srv.Evaluate(bToken)
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation.")
	}

	iToken, err := client.Unblind(token, eval)
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
	}

	if iToken == nil {
		t.Fatal("invalid unbliding of client: no issued Token.")
	}
}

func TestClientFinalize(t *testing.T) {
	srv, err := oprf.NewServer(oprf.OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	client, err := oprf.NewClient(oprf.OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken, err := client.Blind([]byte{00})
	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}

	eval := srv.Evaluate(bToken)
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation")
	}

	iToken, err := client.Unblind(token, eval)
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
	}

	if iToken == nil {
		t.Fatal("invalid unblinding of client: no issued Token.")
	}

	info := []byte{0x00, 0x01}
	h := client.Finalize(token, iToken, info)
	if !(len(h) > 0) {
		t.Fatal("invalid finalizing of client: no final byte array.")
	}
}
