package oprf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/oprf/group"
)

func TestServerSetUp(t *testing.T) {
	srv, err := NewServer(OPRFP256, nil, nil)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}

	if srv.Kp == nil {
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

func TestClientRequest(t *testing.T) {
	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken, err := client.Request([]byte{00})

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
	srv, err := NewServer(OPRFP256, nil, nil)
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

	_, bToken, err := client.Request([]byte{00})
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

func TestClientFinalize(t *testing.T) {
	srv, err := NewServer(OPRFP256, nil, nil)
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

	token, bToken, err := client.Request([]byte{00})
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

	iToken, h, err := client.Finalize(token, eval, []byte{0x00})
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
	}

	if iToken == nil {
		t.Fatal("invalid unblinding of client: no issued Token.")
	}

	if !(len(h) > 0) {
		t.Fatal("invalid finalizing of client: no final byte array.")
	}
}

func blindTest(c *group.Ciphersuite, in []byte) (*Token, BlindToken) {
	bytes, _ := hex.DecodeString("e6db3004c35ec2cf97c4d462e4690e9859741c186b8e1138b977d547ad166951")
	s := group.NewScalar(c)
	s.Set(bytes)

	p, _ := c.HashToGroup(in)
	t := p.ScalarMult(s)
	bToken := t.Serialize()

	token := &Token{in, s}
	return token, bToken
}

func TestClientRequestVector(t *testing.T) {
	t.Skip()
	srv, err := NewServer(OPRFP256, nil, nil)
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
		test.ReportError(t, bToken[:], testBToken[:], "request")
	}
}

func TestServerEvaluationVector(t *testing.T) {
	t.Skip()
	srv, err := NewServer(OPRFP256, nil, nil)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}
	privKey, _ := hex.DecodeString("7331fb3bfbc4a786af3a35e33b2d75db3929b4c033998526dc66d60f6531a255")
	srv.Kp.PrivK.Set(privKey)

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
		test.ReportError(t, eval.element[:], testEval[:], "eval")
	}
}

func TestClientUnblindVector(t *testing.T) {
	t.Skip()
	srv, err := NewServer(OPRFP256, nil, nil)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}
	privKey, _ := hex.DecodeString("7331fb3bfbc4a786af3a35e33b2d75db3929b4c033998526dc66d60f6531a255")
	srv.Kp.PrivK.Set(privKey)

	client, err := NewClient(OPRFP256)
	if err != nil {
		t.Fatal("invalid setup of client: " + err.Error())
	}

	token, bToken := blindTest(client.suite, []byte{00})

	eval, _ := srv.Evaluate(bToken)
	if eval == nil {
		t.Fatal("invalid evaluation of server: no evaluation.")
	}

	info := []byte("test information")
	iToken, h, _ := client.Finalize(token, eval, info)

	// From the test vectors
	testIToken, _ := hex.DecodeString("0277f2ded1d0cbbc9a71504f94dd0aa997709f7adb3368631392313164273eb340")

	if !bytes.Equal(testIToken[:], iToken[:]) {
		test.ReportError(t, iToken[:], testIToken[:], "finalize")
	}

	testOutput, _ := hex.DecodeString("dafd07b7ae978c791481d3cf6c3f6340742eab67f5771279f535ae6daf9df51b74dce7b28da84b6d6bca969b951a317449783acd18ba4cb748d70821e01e7230")

	if !bytes.Equal(testOutput[:], h[:]) {
		test.ReportError(t, h[:], testOutput[:], "finalize")
	}
}