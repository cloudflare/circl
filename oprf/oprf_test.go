package oprf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
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

type Vector struct {
	Blind struct {
		Blinded string `json:"BlindedElement"`
		Token   string `json:"Token"`
	} `json:"Blind"`
	Output     string `json:"ClientOutput"`
	Evaluation struct {
		Eval string `json:"EvaluatedElement"`
	} `json:"Evaluation"`
	Input struct {
		In string `json:"ClientInput"`
	} `json:"Input"`
	Unblind struct {
		IToken string `json:"IssuedToken"`
	} `json:"Unblind"`
}

type Vectors struct {
	Info      string   `json:"info"`
	PrivK     string   `json:"skS"`
	SuiteName string   `json:"suite"`
	Vector    []Vector `json:"vectors"`
}

func (v *Vectors) readFile(t *testing.T, fileName string) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	err = json.Unmarshal(input, &v)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
}

func blindTest(c *group.Ciphersuite, v Vector) (*Token, BlindToken) {
	bytes, _ := hex.DecodeString(v.Blind.Token)
	s := group.NewScalar(c.Curve)
	s.Set(bytes)

	in, _ := hex.DecodeString(v.Input.In)
	p, _ := c.HashToGroup(in)
	t := p.ScalarMult(s)
	bToken := t.Serialize()

	token := &Token{in, s}
	return token, bToken
}

func (v *Vectors) runP256(t *testing.T) {
	for _, j := range v.Vector {
		srv, err := NewServer(OPRFP256)
		if err != nil {
			t.Fatal("invalid setup of server: " + err.Error())
		}
		if srv == nil {
			t.Fatal("invalid setup of server: no server.")
		}

		privKey, _ := hex.DecodeString(v.PrivK)
		srv.Kp.PrivK.Set(privKey)

		client, err := NewClient(OPRFP256)
		if err != nil {
			t.Fatal("invalid setup of client: " + err.Error())
		}

		token, bToken := blindTest(client.suite, j)
		testBToken, _ := hex.DecodeString(j.Blind.Blinded)

		if !bytes.Equal(testBToken[:], bToken[:]) {
			test.ReportError(t, bToken[:], testBToken[:], "request")
		}

		eval, _ := srv.Evaluate(bToken)
		if eval == nil {
			t.Fatal("invalid evaluation of server: no evaluation.")
		}

		testEval, _ := hex.DecodeString(j.Evaluation.Eval)
		if !bytes.Equal(testEval[:], eval.element[:]) {
			test.ReportError(t, eval.element[:], testEval[:], "eval")
		}

		info := []byte("test information")
		iToken, h, _ := client.Finalize(token, eval, info)

		testIToken, _ := hex.DecodeString(j.Unblind.IToken)
		if !bytes.Equal(testIToken[:], iToken[:]) {
			test.ReportError(t, iToken[:], testIToken[:], "finalize")
		}

		testOutput, _ := hex.DecodeString(j.Output)
		if !bytes.Equal(testOutput[:], h[:]) {
			test.ReportError(t, h[:], testOutput[:], "finalize")
		}
	}
}

func (v *Vectors) runP384(t *testing.T) {
	for _, j := range v.Vector {
		srv, err := NewServer(OPRFP384)
		if err != nil {
			t.Fatal("invalid setup of server: " + err.Error())
		}
		if srv == nil {
			t.Fatal("invalid setup of server: no server.")
		}

		privKey, _ := hex.DecodeString(v.PrivK)
		srv.Kp.PrivK.Set(privKey)

		client, err := NewClient(OPRFP384)
		if err != nil {
			t.Fatal("invalid setup of client: " + err.Error())
		}

		token, bToken := blindTest(client.suite, j)
		testBToken, _ := hex.DecodeString(j.Blind.Blinded)
		if !bytes.Equal(testBToken[:], bToken[:]) {
			test.ReportError(t, bToken[:], testBToken[:], "request")
		}

		eval, _ := srv.Evaluate(bToken)
		if eval == nil {
			t.Fatal("invalid evaluation of server: no evaluation.")
		}

		testEval, _ := hex.DecodeString(j.Evaluation.Eval)
		if !bytes.Equal(testEval[:], eval.element[:]) {
			test.ReportError(t, eval.element[:], testEval[:], "eval")
		}

		info := []byte("test information")
		iToken, h, _ := client.Finalize(token, eval, info)

		testIToken, _ := hex.DecodeString(j.Unblind.IToken)
		if !bytes.Equal(testIToken[:], iToken[:]) {
			test.ReportError(t, iToken[:], testIToken[:], "finalize")
		}

		testOutput, _ := hex.DecodeString(j.Output)
		if !bytes.Equal(testOutput[:], h[:]) {
			test.ReportError(t, h[:], testOutput[:], "finalize")
		}
	}
}

func (v *Vectors) runP521(t *testing.T) {
	for _, j := range v.Vector {
		srv, err := NewServer(OPRFP521)
		if err != nil {
			t.Fatal("invalid setup of server: " + err.Error())
		}
		if srv == nil {
			t.Fatal("invalid setup of server: no server.")
		}

		privKey, _ := hex.DecodeString(v.PrivK)
		srv.Kp.PrivK.Set(privKey)

		client, err := NewClient(OPRFP521)
		if err != nil {
			t.Fatal("invalid setup of client: " + err.Error())
		}

		token, bToken := blindTest(client.suite, j)
		testBToken, _ := hex.DecodeString(j.Blind.Blinded)

		if !bytes.Equal(testBToken[:], bToken[:]) {
			test.ReportError(t, bToken[:], testBToken[:], "request")
		}

		eval, _ := srv.Evaluate(bToken)
		if eval == nil {
			t.Fatal("invalid evaluation of server: no evaluation.")
		}

		testEval, _ := hex.DecodeString(j.Evaluation.Eval)
		if !bytes.Equal(testEval[:], eval.element[:]) {
			test.ReportError(t, eval.element[:], testEval[:], "eval")
		}

		info := []byte("test information")
		iToken, h, _ := client.Finalize(token, eval, info)

		testIToken, _ := hex.DecodeString(j.Unblind.IToken)
		if !bytes.Equal(testIToken[:], iToken[:]) {
			test.ReportError(t, iToken[:], testIToken[:], "finalize")
		}

		testOutput, _ := hex.DecodeString(j.Output)
		if !bytes.Equal(testOutput[:], h[:]) {
			test.ReportError(t, h[:], testOutput[:], "finalize")
		}
	}
}

func TestDraftVectors(t *testing.T) {
	// Test vectors from draft-05
	var v Vectors

	v.readFile(t, "testdata/256_vectors.json")
	t.Run("ORPF-P256", v.runP256)

	v.readFile(t, "testdata/384_vectors.json")
	t.Run("ORPF-P384", v.runP384)

	v.readFile(t, "testdata/521_vectors.json")
	t.Run("ORPF-P521", v.runP521)
}
