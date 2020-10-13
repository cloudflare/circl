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
	bytes, _ := hex.DecodeString("e6db3004c35ec2cf97c4d462e4690e9859741c186b8e1138b977d547ad166951")
	x := new(big.Int).SetBytes(bytes)
	s := &group.Scalar{C: c, X: x}

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
	testBToken, _ := hex.DecodeString("02fb7eadba79acefca3e5401e291f2face38f4f3c159e8d636b29f650d96dfc3f1")
	if !bytes.Equal(testBToken[:], bToken[:]) {
		t.Errorf("blind elements are not equal: vectorToken: %x blindToken: %x", testBToken[:], bToken[:])
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
	privKey, _ := hex.DecodeString("7331fb3bfbc4a786af3a35e33b2d75db3929b4c033998526dc66d60f6531a255")
	srv.Keys.PrivK.X.SetBytes(privKey)

	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	_, bToken := blindTest(client.suite, []byte{00})

	eval, _ := srv.Evaluate(bToken)
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation.")
	}

	// From the test vectors
	testEval, _ := hex.DecodeString("02449231545a1770f3e3995e7a0f0a29a51995bf068c833dd1269295641e289cda")

	if !bytes.Equal(testEval[:], eval.element[:]) {
		t.Errorf("eval elements are not equal: vectorEval: %x eval: %x", testEval[:], eval.element[:])
	}
}

func TestClientUnblindVector(t *testing.T) {
	srv, err := NewServer(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}
	privKey, _ := hex.DecodeString("7331fb3bfbc4a786af3a35e33b2d75db3929b4c033998526dc66d60f6531a255")
	srv.Keys.PrivK.X.SetBytes(privKey)

	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken := blindTest(client.suite, []byte{00})

	eval, _ := srv.Evaluate(bToken)
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation.")
	}

	iToken, _ := client.Unblind(token, eval)

	// From the test vectors
	testIToken, _ := hex.DecodeString("0277f2ded1d0cbbc9a71504f94dd0aa997709f7adb3368631392313164273eb340")

	if !bytes.Equal(testIToken[:], iToken[:]) {
		t.Errorf("unblind elements are not equal: vectorIToken: %x Issued Token: %x", testIToken[:], iToken[:])
	}
}

func TestClientFinalizeVector(t *testing.T) {
	srv, err := NewServer(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}
	privKey, _ := hex.DecodeString("7331fb3bfbc4a786af3a35e33b2d75db3929b4c033998526dc66d60f6531a255")
	srv.Keys.PrivK.X.SetBytes(privKey)

	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken := blindTest(client.suite, []byte{00})

	eval, _ := srv.Evaluate(bToken)
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation.")
	}

	iToken, err := client.Unblind(token, eval)
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
	}

	if iToken == nil {
		t.Fatal("invalid unblinding of client: no issued Token.")
	}

	testOutput, _ := hex.DecodeString("dafd07b7ae978c791481d3cf6c3f6340742eab67f5771279f535ae6daf9df51b74dce7b28da84b6d6bca969b951a317449783acd18ba4cb748d70821e01e7230")

	info := []byte("test information")
	h := client.Finalize(token, iToken, info)

	if !bytes.Equal(testOutput[:], h[:]) {
		t.Errorf("finalize elements are not equal: vectorHash: %x hash: %x", testOutput[:], h[:])
	}
}
