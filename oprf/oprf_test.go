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

func TestClientVerifyFinalize(t *testing.T) {
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

	iToken, h, err := client.Finalize(token, eval, []byte("test information"))
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
	}

	if iToken == nil {
		t.Fatal("invalid unblinding of client: no issued Token.")
	}

	if !(len(h) > 0) {
		t.Fatal("invalid finalizing of client: no final byte array.")
	}

	b := srv.VerifyFinalize([]byte{00}, []byte("test information"), h)
	if b == false {
		t.Fatal("Invalid verification from the server")
	}
}

func blindTest(c *group.Ciphersuite, in []byte) (*Token, BlindToken) {
	bytes, _ := hex.DecodeString("bfaba18e6da8cc89f57dcfa306363716edf0d84fa4ffd1ad521e1982d0c95e37")
	s := group.NewScalar(c)
	s.Set(bytes)

	p, _ := c.HashToGroup(in)
	t := p.ScalarMult(s)
	bToken := t.Serialize()

	token := &Token{in, s}
	return token, bToken
}

func TestClientRequestVector(t *testing.T) {
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
	testBToken, _ := hex.DecodeString("02be6ec49d1419d565f2fa6afaaa084b23bb2d9dc0e0ce31cd636afa039cb366a5")
	if !bytes.Equal(testBToken[:], bToken[:]) {
		test.ReportError(t, bToken[:], testBToken[:], "request")
	}
}

func TestServerEvaluationVector(t *testing.T) {
	srv, err := NewServer(OPRFP256, nil, nil)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}
	privKey, _ := hex.DecodeString("40d0c9b6d03ec2b88a359bd81a60509bbbbb68e65c633c6711c1c75c215f7277")
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
	testEval, _ := hex.DecodeString("0237fdb9105aaebe0d0c502bcd37e6fd29b33489de892a1971cd87f41cdff50181")

	if !bytes.Equal(testEval[:], eval.element[:]) {
		test.ReportError(t, eval.element[:], testEval[:], "eval")
	}
}

func TestClientUnblindFinalizeVector(t *testing.T) {
	srv, err := NewServer(OPRFP256, nil, nil)
	if err != nil {
		t.Fatal("invalid setup of server: " + err.Error())
	}
	if srv == nil {
		t.Fatal("invalid setup of server: no server.")
	}
	privKey, _ := hex.DecodeString("40d0c9b6d03ec2b88a359bd81a60509bbbbb68e65c633c6711c1c75c215f7277")
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
	testIToken, _ := hex.DecodeString("03bc44ee69f4e459c322c2423e48b40cada036541e3c9077916e42c7ebfd2a5fa7")

	if !bytes.Equal(testIToken[:], iToken[:]) {
		test.ReportError(t, iToken[:], testIToken[:], "finalize")
	}

	testOutput, _ := hex.DecodeString("2820283d161267f22ff6faafde865973ed6f60fc25c2a194bb8e03ff1a96a096")

	if !bytes.Equal(testOutput[:], h[:]) {
		test.ReportError(t, h[:], testOutput[:], "finalize")
	}
}
