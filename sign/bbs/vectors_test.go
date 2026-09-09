package bbs

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/internal/test"
)

func (id SuiteID) Name() string {
	return [...]string{
		SuiteBLS12381Shake256: "BLS12381SHAKE256",
		SuiteBLS12381Sha256:   "BLS12381SHA256",
	}[id]
}

// Test vectors taken from:
// https://github.com/decentralized-identity/bbs-signature/tree/main/tooling/fixtures/fixture_data
func TestVectors(t *testing.T) {
	for _, id := range []SuiteID{SuiteBLS12381Shake256, SuiteBLS12381Sha256} {
		t.Run(id.Name(), func(t *testing.T) {
			t.Run("Keygen", id.testKeygen)
			t.Run("MsgToScalar", id.testMsgToScalar)
			t.Run("HashToScalar", id.testHashToScalar)
			t.Run("Generators", id.testGenerators)
			t.Run("testSignature", id.testSignature)
			t.Run("Proof", id.testProof)
		})
	}
}

func (id SuiteID) testKeygen(t *testing.T) {
	v := new(struct {
		CaseName    string `json:"caseName"`
		KeyMaterial Hex    `json:"keyMaterial"`
		KeyInfo     Hex    `json:"keyInfo"`
		KeyDst      Hex    `json:"keyDst"`
		KeyPair     struct {
			SecretKey Hex `json:"secretKey"`
			PublicKey Hex `json:"publicKey"`
		} `json:"keyPair"`
	})
	readVector(t, "testdata/"+id.Name()+"/keypair.json", v)

	key, err := KeyGen(id, v.KeyMaterial, v.KeyInfo, v.KeyDst)
	test.CheckNoErr(t, err, "KeyGen failed")

	keyBytesWant := v.KeyPair.SecretKey
	keyBytesGot, err := key.MarshalBinary()
	test.CheckNoErr(t, err, "PrivateKey.MarshalBinary failed")
	if !bytes.Equal(keyBytesGot, keyBytesWant) {
		test.ReportError(t, keyBytesGot, keyBytesWant)
	}

	keyWant := new(PrivateKey)
	err = keyWant.UnmarshalBinary(v.KeyPair.SecretKey)
	test.CheckNoErr(t, err, "PrivateKey.UnmarshalBinary failed")
	if !key.Equal(keyWant) {
		test.ReportError(t, key, keyWant)
	}

	pub := key.Public().(*PublicKey)
	pubBytesWant := v.KeyPair.PublicKey
	pubBytesGot, err := pub.MarshalBinary()
	test.CheckNoErr(t, err, "PublicKey.MarshalBinary failed")
	if !bytes.Equal(pubBytesGot, pubBytesWant) {
		test.ReportError(t, pubBytesGot, pubBytesWant)
	}

	pubWant := new(PublicKey)
	err = pubWant.UnmarshalBinary(v.KeyPair.PublicKey)
	test.CheckNoErr(t, err, "PublicKey.UnmarshalBinary failed")
	if !pub.Equal(pubWant) {
		test.ReportError(t, pub, pubWant)
	}
}

func (id SuiteID) testHashToScalar(t *testing.T) {
	v := new(struct {
		CaseName string `json:"caseName"`
		Message  Hex    `json:"message"`
		Dst      Hex    `json:"dst"`
		Scalar   Hex    `json:"scalar"`
	})

	readVector(t, "testdata/"+id.Name()+"/h2s.json", v)

	s := id.new().hashToScalar(v.Message, v.Dst)
	got, err := s.MarshalBinary()
	test.CheckNoErr(t, err, "failed scalar.UnmarshalBinary")
	want := v.Scalar
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want)
	}
}

func (id SuiteID) testMsgToScalar(t *testing.T) {
	v := new(struct {
		CaseName string `json:"caseName"`
		Dst      Hex    `json:"dst"`
		Cases    []struct {
			Message Hex `json:"message"`
			Scalar  Hex `json:"scalar"`
		} `json:"cases"`
	})
	readVector(t, "testdata/"+id.Name()+"/MapMessageToScalarAsHash.json", v)

	suite := id.new()
	for i := range v.Cases {
		s := suite.hashToScalar(v.Cases[i].Message, suite.MapDST())
		got, err := s.MarshalBinary()
		test.CheckNoErr(t, err, "failed scalar.UnmarshalBinary")
		want := v.Cases[i].Scalar
		if !bytes.Equal(got, want) {
			test.ReportError(t, got, want, i)
		}
	}
}

func (id SuiteID) testGenerators(t *testing.T) {
	v := new(struct {
		P1            Hex   `json:"P1"`
		Q1            Hex   `json:"Q1"`
		MsgGenerators []Hex `json:"MsgGenerators"`
	})
	readVector(t, "testdata/"+id.Name()+"/generators.json", v)

	t.Run("p1", func(t *testing.T) {
		s := id.new()
		for i, doP1 := range []func() g1{
			func() g1 {
				var p1 [1]g1
				s.hashToGenerators(p1[:], s.BpGeneratorSeed(), 0)
				return p1[0]
			},
			s.getP1,
		} {
			p1 := doP1()
			got := p1.BytesCompressed()
			want := v.P1
			if !bytes.Equal(got, want) {
				test.ReportError(t, got, want, i)
			}
		}
	})

	t.Run("q1_gens", func(t *testing.T) {
		s := id.new()
		for fi, doGens := range []func([]g1){
			func(p []g1) { s.hashToGenerators(p, s.GeneratorSeed(), 0) },
			func(p []g1) { s.getQ1Gens(p) },
		} {
			Q1Gens := make([]g1, 1+len(v.MsgGenerators))
			doGens(Q1Gens)
			q1, gens := Q1Gens[0], Q1Gens[1:]
			got := q1.BytesCompressed()
			want := v.Q1
			if !bytes.Equal(got, want) {
				test.ReportError(t, got, want)
			}

			for i, want := range v.MsgGenerators {
				got := gens[i].BytesCompressed()
				if !bytes.Equal(got, want) {
					test.ReportError(t, got, want, fi, i)
				}
			}
		}
	})
}

func (id SuiteID) testSignature(t *testing.T) {
	type vector struct {
		CaseName      string `json:"caseName"`
		SignerKeyPair struct {
			SecretKey Hex `json:"secretKey"`
			PublicKey Hex `json:"publicKey"`
		} `json:"signerKeyPair"`
		Header    Hex   `json:"header"`
		Messages  []Hex `json:"messages"`
		Signature Hex   `json:"signature"`
		Result    struct {
			Valid bool `json:"valid"`
		} `json:"result"`
		Trace struct {
			B      Hex `json:"B"`
			Domain Hex `json:"domain"`
		} `json:"trace"`
	}

	files, err := filepath.Glob("./testdata/" + id.Name() + "/signature/*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		testName := strings.TrimSuffix(filepath.Base(file), ".json")

		t.Run(testName, func(t *testing.T) {
			v := new(vector)
			readVector(t, file, v)

			key := new(PrivateKey)
			err := key.UnmarshalBinary(v.SignerKeyPair.SecretKey)
			test.CheckNoErr(t, err, "failed PrivateKey.UnmarshalBinary")

			pubWant := new(PublicKey)
			err = pubWant.UnmarshalBinary(v.SignerKeyPair.PublicKey)
			test.CheckNoErr(t, err, "failed PublicKey.UnmarshalBinary")

			pubGot := key.PublicKey()
			if !pubGot.Equal(pubWant) && v.Result.Valid {
				test.ReportError(t, pubGot, pubWant)
			}

			messages := cvt(v.Messages)
			opts := SignOptions{ID: id, Header: v.Header}

			if v.Result.Valid {
				sig := Sign(key, messages, opts)
				sigBytesWant := v.Signature
				sigBytesGot, err := sig.MarshalBinary()
				test.CheckNoErr(t, err, "failed Signature.MarshalBinary")

				if !bytes.Equal(sigBytesGot, sigBytesWant) {
					test.ReportError(t, sigBytesGot, sigBytesWant)
				}

				valid := Verify(pubWant, &sig, messages, opts)
				test.CheckOk(valid, "verification should pass", t)
			} else {
				invalidSig := new(Signature)
				err := invalidSig.UnmarshalBinary(v.Signature)
				test.CheckNoErr(t, err, "failed Signature.UnmarshalBinary")

				invalid := Verify(pubWant, invalidSig, messages, opts)
				test.CheckOk(!invalid, "verification should fail", t)
			}
		})
	}
}

func (id SuiteID) testProof(t *testing.T) {
	type vector struct {
		CaseName           string `json:"caseName"`
		SignerPublicKey    Hex    `json:"signerPublicKey"`
		Signature          Hex    `json:"signature"`
		Header             Hex    `json:"header"`
		PresentationHeader Hex    `json:"presentationHeader"`
		Messages           []Hex  `json:"messages"`
		DisclosedIndexes   []uint `json:"disclosedIndexes"`
		Proof              Hex    `json:"proof"`
		Result             struct {
			Valid bool `json:"valid"`
		} `json:"result"`
		Trace struct {
			RandomScalars struct {
				R1            Hex   `json:"r1"`
				R2            Hex   `json:"r2"`
				ETilde        Hex   `json:"e_tilde"`
				R1Tilde       Hex   `json:"r1_tilde"`
				R3Tilde       Hex   `json:"r3_tilde"`
				MTildeScalars []Hex `json:"m_tilde_scalars"`
			} `json:"random_scalars"`
			ABar      string `json:"A_bar"`
			BBar      string `json:"B_bar"`
			D         string `json:"D"`
			T1        string `json:"T1"`
			T2        string `json:"T2"`
			Domain    string `json:"domain"`
			Challenge string `json:"challenge"`
		} `json:"trace"`
	}

	mockRandom := func(v *vector) (m MockRandom) {
		r := &v.Trace.RandomScalars
		m.order.SetBytes(bls12381.Order())
		m.s = append([]Hex{
			r.R1, r.R2, r.ETilde, r.R1Tilde, r.R3Tilde,
		}, r.MTildeScalars...)
		return
	}

	files, err := filepath.Glob("./testdata/" + id.Name() + "/proof/*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		testName := strings.TrimSuffix(filepath.Base(file), ".json")

		t.Run(testName, func(t *testing.T) {
			v := new(vector)
			readVector(t, file, v)

			pub := new(PublicKey)
			err = pub.UnmarshalBinary(v.SignerPublicKey)
			test.CheckNoErr(t, err, "failed PublicKey.UnmarshalBinary")

			sig := new(Signature)
			err := sig.UnmarshalBinary(v.Signature)
			test.CheckNoErr(t, err, "failed Signature.MarshalBinary")

			choices, err := Disclose(cvt(v.Messages), v.DisclosedIndexes)
			test.CheckNoErr(t, err, "failed Disclose")

			opts := ProveOptions{
				v.PresentationHeader, SignOptions{ID: id, Header: v.Header},
			}
			reader := mockRandom(v)
			proof, disclosed, err := Prove(&reader, pub, sig, choices, opts)
			test.CheckNoErr(t, err, "failed Prove")

			if v.Result.Valid {
				want := v.Proof
				got, err := proof.MarshalBinary()
				test.CheckNoErr(t, err, "failed Proof.MarshalBinary")

				if !bytes.Equal(got, want) {
					test.ReportError(t, got, want)
				}

				valid := VerifyProof(pub, proof, disclosed, opts)
				test.CheckOk(valid, "VerifyProof should pass", t)
			} else {
				invalidProof := new(Proof)
				err := invalidProof.UnmarshalBinary(v.Proof)
				test.CheckNoErr(t, err, "failed Proof.UnmarshalBinary")

				invalid := VerifyProof(pub, invalidProof, disclosed, opts)
				test.CheckOk(!invalid, "VerifyProof should fail", t)
			}
		})
	}
}

type MockRandom struct {
	s        []Hex
	i        int
	v, order big.Int
}

func (r *MockRandom) Read(b []byte) (int, error) {
	if len(b) != scalarSize {
		return 0, io.ErrShortBuffer
	}
	if r.i >= len(r.s) {
		return 0, io.EOF
	}

	// Convert to Montgomery representation.
	//   v' = vR mod order, where R=2^256.
	r.v.SetBytes(r.s[r.i]).Lsh(&r.v, 256).Mod(&r.v, &r.order).FillBytes(b)
	r.i++
	return scalarSize, nil
}

type Hex []byte

func (b *Hex) UnmarshalJSON(data []byte) (err error) {
	var s string
	err = json.Unmarshal(data, &s)
	if err == nil {
		*b, err = hex.DecodeString(s)
	}
	return
}

func readVector(t *testing.T, fileName string, vector interface{}) {
	file, err := os.Open(fileName)
	test.CheckNoErr(t, err, "error opening file")
	defer file.Close()

	bytes, err := io.ReadAll(file)
	test.CheckNoErr(t, err, "error reading bytes")

	err = json.Unmarshal(bytes, &vector)
	test.CheckNoErr(t, err, "error unmarshalling JSON file")
}

func cvt(x []Hex) (y [][]byte) {
	for i := range x {
		y = append(y, x[i])
	}
	return
}
