package oprf

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/oprf/group"
)

func TestServerSetUp(t *testing.T) {
	srv, err := NewServer(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	if srv.Keys == nil {
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

	eval := srv.Evaluate(bToken)
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

func blindTest(c *group.Ciphersuite, in []byte) (*Token, BlindToken) {
	bytes, _ := hex.DecodeString("4c9b51eb104a0537de74f95aec979273cbeff69309db899e9dcc84f8b653cd26")
	x := new(big.Int).SetBytes(bytes)
	s := &group.Scalar{c, x}

	p, _ := c.HashToGroup(in)
	t := p.ScalarMult(s)
	bToken := t.Serialize()

	token := &Token{in, s}
	return token, bToken
}

func TestClientBlindVector(t *testing.T) {
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

	_, bToken := blindTest(client.suite, []byte{00})

	// From the test vectors
	testBToken, _ := hex.DecodeString("9d62b0aeca1dd7a60c57bc280e3c38fdebd0091b4631db42a7a310d4a3a98440")

	// Comparing this way due to the serialization differences in the sage poc
	if (bytes.Compare(testBToken[0:32], bToken[1:33])) != 0 {
		t.Errorf("blind elements are not equal: vectorToken: %x blindToken: %x", testBToken[0:32], bToken[1:33])
	}
}

func TestServerEvaluationVector(t *testing.T) {
	srv, err := NewServer(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}
	privKey, _ := hex.DecodeString("09f62b2ca2092229af9f6cfd594c10540773b0ab5c549f38960a78ef429a480f")
	srv.Keys.PrivK.X.SetBytes(privKey)

	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	_, bToken := blindTest(client.suite, []byte{00})

	eval := srv.Evaluate(bToken)
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation.")
	}

	// From the test vectors
	testEval, _ := hex.DecodeString("cf132894788f5fa25863be4b52cf9526e6c0391db964f011b239104571a9b757")

	// Comparing this way due to the serialization differences in the sage poc
	if (bytes.Compare(testEval[:], eval.element[1:33])) != 0 {
		t.Errorf("eval elements are not equal: vectorEval: %x eval: %x", testEval[:], eval.element[1:33])
	}
}

func TestClienUnblind(t *testing.T) {
	srv, err := NewServer(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}
	privKey, _ := hex.DecodeString("09f62b2ca2092229af9f6cfd594c10540773b0ab5c549f38960a78ef429a480f")
	srv.Keys.PrivK.X.SetBytes(privKey)

	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken := blindTest(client.suite, []byte{00})

	eval := srv.Evaluate(bToken)
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation.")
	}

	iToken, err := client.Unblind(token, eval)

	// From the test vectors
	testIToken, _ := hex.DecodeString("69146bc29e995590ab94335994b10230ed5c6c94f46475927ecad353b708597b")

	// Comparing this way due to the serialization differences in the sage poc
	if (bytes.Compare(testIToken[:], iToken[1:33])) != 0 {
		t.Errorf("unblind elements are not equal: vectorIToken: %x Issued Token: %x", testIToken[:], iToken[1:33])
	}
}
