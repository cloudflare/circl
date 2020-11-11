package oprf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

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

func (s *Suite) fillVectors() [3]Vectors {
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

var suiteMaps = map[string]SuiteID{
	"P256-SHA256-SSWU-RO": OPRFP256,
	"P384-SHA512-SSWU-RO": OPRFP384,
	"P521-SHA512-SSWU-RO": OPRFP521,
}

func setUpParties(t *testing.T, name string, privateKey []byte) (*Server, *Client) {
	suite, ok := suiteMaps[name]
	if !ok {
		t.Fatal("suite not found")
	}
	keyPair := new(KeyPair)
	err := keyPair.Deserialize(suite, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if name == "P256-SHA256-SSWU-RO" {
		srv, err := NewServerWithKeyPair(OPRFP256, *keyPair)
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
		srv, err := NewServerWithKeyPair(OPRFP384, *keyPair)
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
		srv, err := NewServerWithKeyPair(OPRFP521, *keyPair)
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

func blindTest(c *suite, ctx []byte, v Vector) *ClientRequest {
	bytes, _ := hex.DecodeString(v.Blind.Token[2:])
	s := c.Group.NewScl()
	err := s.UnmarshalBinary(bytes)
	if err != nil {
		return nil
	}
	in, _ := hex.DecodeString(v.Input.In[2:])
	dst := append(append([]byte{}, version...), ctx...)
	h2c := c.Group.Hashes(dst)
	p := h2c.Hash(in)

	t := c.Group.NewElt()
	t.Mul(p, s)
	bToken, err := t.MarshalBinaryCompress()
	if err != nil {
		return nil
	}

	token := &Token{in, s}
	return &ClientRequest{c, ctx, token, bToken}
}

func generateIssuedToken(c *Client, e *Evaluation, t *Token) IssuedToken {
	p := c.suite.Group.NewElt()
	err := p.UnmarshalBinary(e.Element)
	if err != nil {
		return nil
	}

	r := t.blind
	rInv := c.suite.Group.NewScl()
	rInv.Inv(r)

	tt := c.suite.Group.NewElt()
	tt.Mul(p, rInv)
	iToken, err := tt.MarshalBinaryCompress()
	if err != nil {
		return nil
	}
	return iToken
}

func (v *Vectors) run(t *testing.T) {
	privateKey, err := hex.DecodeString(v.PrivK[2:])
	if err != nil {
		t.Fatal(err)
	}
	srv, client := setUpParties(t, v.SuiteName, privateKey)

	for _, j := range v.Vector {
		cr := blindTest(client.suite, client.context, j)
		testBToken, _ := hex.DecodeString(j.Blind.Blinded[2:])

		if !bytes.Equal(testBToken[:], cr.BlindedToken[:]) {
			test.ReportError(t, cr.BlindedToken[:], testBToken[:], "request")
		}

		eval, _ := srv.Evaluate(cr.BlindedToken)
		if eval == nil {
			t.Fatal("invalid evaluation of server: no evaluation.")
		}

		testEval, _ := hex.DecodeString(j.Evaluation.Eval[2:])
		if !bytes.Equal(testEval[:], eval.Element[:]) {
			test.ReportError(t, eval.Element[:], testEval[:], "eval")
		}

		info := []byte("test information")
		h, _ := cr.Finalize(eval, info)
		iToken := generateIssuedToken(client, eval, cr.token)

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
	v := s.fillVectors()

	for i := range v {
		t.Run("ORPF-Base-Protocol/"+v[i].SuiteName, v[i].run)
	}
}
