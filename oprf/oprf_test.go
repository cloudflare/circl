package oprf

import (
	"testing"
)

func TestServerSetUp(t *testing.T) {
	srv, err := NewServer(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	if srv.ctx != "0003" {
		t.Fatal("invalid setup of server: no context")
	}

	if srv.K == nil {
		t.Fatal("invalid setup of server: no keypair")
	}
}

func TestClientSetUp(t *testing.T) {
	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}
	if client == nil {
		t.Fatal("invalid setup of client: no server.")
	}

	if client.ctx != "0003" {
		t.Fatal("invalid setup of client: no context")
	}
}

func TestClientBlind(t *testing.T) {
	client, err := NewClient(OPRFP256)
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
	srv, err := NewServer(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	_, bToken, err := client.Blind([]byte{00})
	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}

	eval, err := srv.Evaluate(bToken)
	if err != nil {
		t.Fatal("invalid evaluation of server: " + err.Error())
	}

	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation.")
	}
}

func TestClientUnblind(t *testing.T) {
	srv, err := NewServer(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken, err := client.Blind([]byte{00})
	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}

	eval, err := srv.Evaluate(bToken)
	if err != nil {
		t.Fatal("invalid evaluation of server: " + err.Error())
	}

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
	srv, err := NewServer(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken, err := client.Blind([]byte{00})
	if err != nil {
		t.Fatal("invalid blinding of client: " + err.Error())
	}

	eval, err := srv.Evaluate(bToken)
	if err != nil {
		t.Fatal("invalid evaluation of server: " + err.Error())
	}

	if eval == nil {
		t.Fatal("invalid evaluate of server: no evaluation.")
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
