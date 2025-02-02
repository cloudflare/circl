package slhdsa

import (
	"archive/zip"
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/xof"
)

type acvpKeyGenPrompt struct {
	TestGroups []struct {
		TestType     string        `json:"testType"`
		ParameterSet string        `json:"parameterSet"`
		Tests        []keyGenInput `json:"tests"`
		TgID         int           `json:"tgId"`
	} `json:"testGroups"`
}

type keyGenInput struct {
	SkSeed Hex `json:"skSeed"`
	SkPrf  Hex `json:"skPrf"`
	PkSeed Hex `json:"pkSeed"`
	TcID   int `json:"tcId"`
}

type acvpKeyGenResult struct {
	TestGroups []struct {
		Tests []struct {
			Sk   Hex `json:"sk"`
			Pk   Hex `json:"pk"`
			TcID int `json:"tcId"`
		} `json:"tests"`
		TgID int `json:"tgId"`
	} `json:"testGroups"`
}

type acvpSigGenPrompt struct {
	TestGroups []struct {
		sigGenParams
		TestType string        `json:"testType"`
		Tests    []sigGenInput `json:"tests"`
		TgID     int           `json:"tgId"`
	} `json:"testGroups"`
}

type sigParams struct {
	ParameterSet string `json:"parameterSet"`
	SigInterface string `json:"signatureInterface"`
	PreHash      string `json:"preHash"`
}

type sigGenParams struct {
	sigParams
	IsDeterministic bool `json:"deterministic"`
}

type sigGenInput struct {
	HashAlg string `json:"hashAlg,omitempty"`
	Sk      Hex    `json:"sk"`
	Msg     Hex    `json:"message"`
	Ctx     Hex    `json:"context,omitempty"`
	AddRand Hex    `json:"additionalRandomness,omitempty"`
	TcID    int    `json:"tcId"`
}

type acvpSigGenResult struct {
	TestGroups []struct {
		Tests []struct {
			Signature Hex `json:"signature"`
			TcID      int `json:"tcId"`
		} `json:"tests"`
		TgID int `json:"tgId"`
	} `json:"testGroups"`
}

type acvpVerifyInput struct {
	TestGroups []struct {
		sigParams
		TestType string        `json:"testType"`
		Tests    []verifyInput `json:"tests"`
		TgID     int           `json:"tgId"`
	} `json:"testGroups"`
}

type verifyInput struct {
	HashAlg string `json:"hashAlg,omitempty"`
	Pk      Hex    `json:"pk"`
	Msg     Hex    `json:"message"`
	Sig     Hex    `json:"signature"`
	Ctx     Hex    `json:"context,omitempty"`
	TcID    int    `json:"tcId"`
}

type acvpVerifyResult struct {
	TestGroups []struct {
		Tests []struct {
			TcID       int  `json:"tcId"`
			TestPassed bool `json:"testPassed"`
		} `json:"tests"`
		TgID int `json:"tgId"`
	} `json:"testGroups"`
}

func TestACVP(t *testing.T) {
	t.Run("Keygen", testKeygen)
	t.Run("Sign", testSign)
	t.Run("Verify", testVerify)
}

func testKeygen(t *testing.T) {
	// https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.38/gen-val/json-files/SLH-DSA-keyGen-FIPS205
	inputs := new(acvpKeyGenPrompt)
	readVector(t, "testdata/keyGen_prompt.json.zip", inputs)
	outputs := new(acvpKeyGenResult)
	readVector(t, "testdata/keyGen_results.json.zip", outputs)

	for gi, group := range inputs.TestGroups {
		t.Run(fmt.Sprintf("TgID_%v", group.TgID), func(t *testing.T) {
			if strings.HasSuffix(group.ParameterSet, "s") {
				SkipLongTest(t)
			}

			for ti := range group.Tests {
				test.CheckOk(
					group.Tests[ti].TcID == outputs.TestGroups[gi].Tests[ti].TcID,
					"mismatch of TcID", t,
				)

				t.Run(fmt.Sprintf("TcID_%v", group.Tests[ti].TcID),
					func(t *testing.T) {
						acvpKeygen(t, group.ParameterSet, &group.Tests[ti],
							outputs.TestGroups[gi].Tests[ti].Sk,
							outputs.TestGroups[gi].Tests[ti].Pk,
						)
					})
			}
		})
	}
}

func testSign(t *testing.T) {
	// https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.38/gen-val/json-files/SLH-DSA-sigGen-FIPS205
	inputs := new(acvpSigGenPrompt)
	readVector(t, "testdata/sigGen_prompt.json.zip", inputs)
	outputs := new(acvpSigGenResult)
	readVector(t, "testdata/sigGen_results.json.zip", outputs)

	for gi, group := range inputs.TestGroups {
		test.CheckOk(group.TgID == outputs.TestGroups[gi].TgID, "mismatch of TgID", t)

		t.Run(fmt.Sprintf("TgID_%v", group.TgID), func(t *testing.T) {
			if strings.HasSuffix(group.ParameterSet, "s") {
				SkipLongTest(t)
			}

			for ti := range group.Tests {
				test.CheckOk(
					group.Tests[ti].TcID == outputs.TestGroups[gi].Tests[ti].TcID,
					"mismatch of TcID", t,
				)

				t.Run(fmt.Sprintf("TcID_%v", group.Tests[ti].TcID),
					func(t *testing.T) {
						acvpSign(t, &group.sigGenParams, &group.Tests[ti],
							outputs.TestGroups[gi].Tests[ti].Signature)
					})
			}
		})
	}
}

func testVerify(t *testing.T) {
	// https://github.com/usnistgov/ACVP-Server/tree/v1.1.0.38/gen-val/json-files/SLH-DSA-sigVer-FIPS205
	inputs := new(acvpVerifyInput)
	readVector(t, "testdata/verify_prompt.json.zip", inputs)
	outputs := new(acvpVerifyResult)
	readVector(t, "testdata/verify_results.json.zip", outputs)

	for gi, group := range inputs.TestGroups {
		test.CheckOk(group.TgID == outputs.TestGroups[gi].TgID, "mismatch of TgID", t)

		t.Run(fmt.Sprintf("TgID_%v", group.TgID), func(t *testing.T) {
			if strings.HasSuffix(group.ParameterSet, "s") {
				SkipLongTest(t)
			}

			for ti := range group.Tests {
				test.CheckOk(
					group.Tests[ti].TcID == outputs.TestGroups[gi].Tests[ti].TcID,
					"mismatch of TcID", t,
				)

				t.Run(fmt.Sprintf("TcID_%v", group.Tests[ti].TcID),
					func(t *testing.T) {
						acvpVerify(t, &group.sigParams, &group.Tests[ti],
							outputs.TestGroups[gi].Tests[ti].TestPassed,
						)
					})
			}
		})
	}
}

func acvpKeygen(
	t *testing.T, paramSet string, in *keyGenInput, wantSk, wantPk []byte,
) {
	id, err := IDByName(paramSet)
	test.CheckNoErr(t, err, "invalid ParameterSet")

	var buffer bytes.Buffer
	_, _ = buffer.Write(in.SkSeed)
	_, _ = buffer.Write(in.SkPrf)
	_, _ = buffer.Write(in.PkSeed)
	pk, sk, err := GenerateKey(&buffer, id)
	test.CheckNoErr(t, err, "GenerateKey failed")

	skGot, err := sk.MarshalBinary()
	test.CheckNoErr(t, err, "PrivateKey.MarshalBinary failed")

	if !bytes.Equal(skGot, wantSk) {
		test.ReportError(t, skGot, wantSk)
	}

	pkGot, err := pk.MarshalBinary()
	test.CheckNoErr(t, err, "PublicKey.MarshalBinary failed")

	if !bytes.Equal(pkGot, wantPk) {
		test.ReportError(t, pkGot, wantPk)
	}
}

func acvpSign(t *testing.T, p *sigGenParams, in *sigGenInput, wantSig []byte) {
	id, err := IDByName(p.ParameterSet)
	test.CheckNoErr(t, err, "invalid ParameterSet")

	sk := PrivateKey{ID: id}
	err = sk.UnmarshalBinary(in.Sk)
	test.CheckNoErr(t, err, "PrivateKey.UnmarshalBinary failed")

	var gotSig []byte
	if p.SigInterface == "internal" {
		SkipLongTest(t)

		addRand := sk.publicKey.seed
		if !p.IsDeterministic {
			addRand = in.AddRand
		}

		gotSig, err = slhSignInternal(&sk, in.Msg, addRand)
		test.CheckNoErr(t, err, "slhSignInternal failed")

		if !bytes.Equal(gotSig, wantSig) {
			more := " ... (more bytes differ)"
			got := hex.EncodeToString(gotSig[:10]) + more
			want := hex.EncodeToString(wantSig[:10]) + more
			test.ReportError(t, got, want)
		}

		valid := slhVerifyInternal(&sk.publicKey, in.Msg, gotSig)
		test.CheckOk(valid, "slhVerifyInternal failed", t)
	} else if p.SigInterface == "external" {
		var msg *Message
		if p.PreHash == "pure" {
			msg = NewMessage(in.Msg)
		} else if p.PreHash == "preHash" {
			ph := getPreHash(t, in.HashAlg)
			_, err = ph.Write(in.Msg)
			test.CheckNoErr(t, err, "PreHash Write failed")

			msg, err = ph.BuildMessage()
			test.CheckNoErr(t, err, "PreHash GetMessage failed")
		}

		if p.IsDeterministic {
			gotSig, err = SignDeterministic(&sk, msg, in.Ctx)
			test.CheckNoErr(t, err, "SignDeterministic failed")
		} else {
			gotSig, err = SignRandomized(&sk, bytes.NewReader(in.AddRand), msg, in.Ctx)
			test.CheckNoErr(t, err, "SignRandomized failed")
		}

		if !bytes.Equal(gotSig, wantSig) {
			more := " ... (more bytes differ)"
			got := hex.EncodeToString(gotSig[:10]) + more
			want := hex.EncodeToString(wantSig[:10]) + more
			test.ReportError(t, got, want)
		}

		pk := sk.PublicKey()
		valid := Verify(&pk, msg, gotSig, in.Ctx)
		test.CheckOk(valid, "Verify failed", t)
	}
}

func acvpVerify(t *testing.T, p *sigParams, in *verifyInput, want bool) {
	id, err := IDByName(p.ParameterSet)
	test.CheckNoErr(t, err, "invalid ParameterSet")

	pk := PublicKey{ID: id}
	err = pk.UnmarshalBinary(in.Pk)
	test.CheckNoErr(t, err, "PublicKey.UnmarshalBinary failed")

	var got bool
	if p.SigInterface == "internal" {
		SkipLongTest(t)
		got = slhVerifyInternal(&pk, in.Msg, in.Sig)
	} else if p.SigInterface == "external" {
		var msg *Message
		if p.PreHash == "pure" {
			msg = NewMessage(in.Msg)
		} else if p.PreHash == "preHash" {
			ph := getPreHash(t, in.HashAlg)
			_, err = ph.Write(in.Msg)
			test.CheckNoErr(t, err, "PreHash Write failed")

			msg, err = ph.BuildMessage()
			test.CheckNoErr(t, err, "PreHash GetMessage failed")
		}

		got = Verify(&pk, msg, in.Sig, in.Ctx)
	}

	if got != want {
		test.ReportError(t, got, want)
	}
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
	zipFile, err := zip.OpenReader(fileName)
	test.CheckNoErr(t, err, "error opening file")
	defer zipFile.Close()

	jsonFile, err := zipFile.File[0].Open()
	test.CheckNoErr(t, err, "error opening unzipping file")
	defer jsonFile.Close()

	input, err := io.ReadAll(jsonFile)
	test.CheckNoErr(t, err, "error reading bytes")

	err = json.Unmarshal(input, &vector)
	test.CheckNoErr(t, err, "error unmarshalling JSON file")
}

func getPreHash(t *testing.T, s string) *PreHash {
	m := make(map[string]*PreHash)
	m["SHA2-224"], _ = NewPreHashWithHash(crypto.SHA224)
	m["SHA2-256"], _ = NewPreHashWithHash(crypto.SHA256)
	m["SHA2-384"], _ = NewPreHashWithHash(crypto.SHA384)
	m["SHA2-512"], _ = NewPreHashWithHash(crypto.SHA512)
	m["SHA2-512/224"], _ = NewPreHashWithHash(crypto.SHA512_224)
	m["SHA2-512/256"], _ = NewPreHashWithHash(crypto.SHA512_256)
	m["SHA3-224"], _ = NewPreHashWithHash(crypto.SHA3_224)
	m["SHA3-256"], _ = NewPreHashWithHash(crypto.SHA3_256)
	m["SHA3-384"], _ = NewPreHashWithHash(crypto.SHA3_384)
	m["SHA3-512"], _ = NewPreHashWithHash(crypto.SHA3_512)
	m["SHAKE-128"], _ = NewPreHashWithXof(xof.SHAKE128)
	m["SHAKE-256"], _ = NewPreHashWithXof(xof.SHAKE256)

	ph, ok := m[s]
	test.CheckOk(ok, fmt.Sprintf("preHash algorithm not supported %v", s), t)
	return ph
}
