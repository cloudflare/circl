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

	h, err := client.Finalize(token, eval, []byte{0x00})
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
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

	h, err := client.Finalize(token, eval, []byte("test information"))
	if err != nil {
		t.Fatal("invalid unblinding of client: " + err.Error())
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

type Suite struct {
	P256 Vectors `json:"BaseP256-SHA256-SSWU-RO"`
	P384 Vectors `json:"BaseP384-SHA512-SSWU-RO"`
	P521 Vectors `json:"BaseP521-SHA512-SSWU-RO"`
}

func (s *Suite) readFile(t *testing.T, fileName string) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	err = json.Unmarshal(input, &s)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}
}

func (s *Suite) fillVectors(t *testing.T) [3]Vectors {
	var v [3]Vectors

	v[0].Info = s.P256.Info
	v[0].PrivK = s.P256.PrivK
	v[0].SuiteName = s.P256.SuiteName
	v[0].Vector = s.P256.Vector

	v[1].Info = s.P384.Info
	v[1].PrivK = s.P384.PrivK
	v[1].SuiteName = s.P384.SuiteName
	v[1].Vector = s.P384.Vector

	v[2].Info = s.P521.Info
	v[2].PrivK = s.P521.PrivK
	v[2].SuiteName = s.P521.SuiteName
	v[2].Vector = s.P521.Vector

	return v
}

func setUpParties(t *testing.T, name string) (*Server, *Client) {
	if name == "P256-SHA256-SSWU-RO" {
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

		return srv, client
	} else if name == "P384-SHA512-SSWU-RO" {
		srv, err := NewServer(OPRFP384)
		if err != nil {
			t.Fatal("invalid setup of server: " + err.Error())
		}
		if srv == nil {
			t.Fatal("invalid setup of server: no server.")
		}

		client, err := NewClient(OPRFP384)
		if err != nil {
			t.Fatal("invalid setup of client: " + err.Error())
		}

		return srv, client
	} else if name == "P521-SHA512-SSWU-RO" {
		srv, err := NewServer(OPRFP521)
		if err != nil {
			t.Fatal("invalid setup of server: " + err.Error())
		}
		if srv == nil {
			t.Fatal("invalid setup of server: no server.")
		}

		client, err := NewClient(OPRFP521)
		if err != nil {
			t.Fatal("invalid setup of client: " + err.Error())
		}

		return srv, client
	}

	return nil, nil

}

func blindTest(c *group.Ciphersuite, v Vector) (*Token, BlindToken) {
	bytes, _ := hex.DecodeString(v.Blind.Token[2:])
	s := group.NewScalar(c.Curve)
	s.Set(bytes)

	in, _ := hex.DecodeString(v.Input.In[2:])
	p, _ := c.HashToGroup(in)
	t := p.ScalarMult(s)
	bToken := t.Serialize()

	token := &Token{in, s}
	return token, bToken
}

func generateIssuedToken(c *Client, e *Evaluation, t *Token) IssuedToken {
	p := group.NewElement(c.suite.Curve)
	err := p.Deserialize(e.element)
	if err != nil {
		return nil
	}

	r := t.blind
	rInv := r.Inv()

	tt := p.ScalarMult(rInv)
	return tt.Serialize()
}

func (v *Vectors) run(t *testing.T) {
	srv, client := setUpParties(t, v.SuiteName)
	privKey, _ := hex.DecodeString(v.PrivK[2:])
	srv.Kp.PrivK.Set(privKey)

	for _, j := range v.Vector {
		token, bToken := blindTest(client.suite, j)
		testBToken, _ := hex.DecodeString(j.Blind.Blinded[2:])

		if !bytes.Equal(testBToken[:], bToken[:]) {
			test.ReportError(t, bToken[:], testBToken[:], "request")
		}

		eval, _ := srv.Evaluate(bToken)
		if eval == nil {
			t.Fatal("invalid evaluation of server: no evaluation.")
		}

		testEval, _ := hex.DecodeString(j.Evaluation.Eval[2:])
		if !bytes.Equal(testEval[:], eval.element[:]) {
			test.ReportError(t, eval.element[:], testEval[:], "eval")
		}

		info := []byte("test information")
		h, _ := client.Finalize(token, eval, info)
		iToken := generateIssuedToken(client, eval, token)

		testIToken, _ := hex.DecodeString(j.Unblind.IToken[2:])
		if !bytes.Equal(testIToken[:], iToken[:]) {
			test.ReportError(t, iToken[:], testIToken[:], "finalize")
		}

		testOutput, _ := hex.DecodeString(j.Output[2:])
		if !bytes.Equal(testOutput[:], h[:]) {
			test.ReportError(t, h[:], testOutput[:], "finalize")
		}
	}
}

func TestDraftVectors(t *testing.T) {
	// Test vectors from draft-05
	var s Suite

	s.readFile(t, "testdata/vectors.json")
	v := s.fillVectors(t)

	for i := range v {
		t.Run("ORPF-Base-Protocol", v[i].run)
	}
}
