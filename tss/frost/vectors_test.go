package frost

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/secretsharing"
)

type vector struct {
	Config struct {
		MAXPARTICIPANTS uint16 `json:"MAX_PARTICIPANTS,string"`
		NUMPARTICIPANTS uint16 `json:"NUM_PARTICIPANTS,string"`
		MINPARTICIPANTS uint16 `json:"MIN_PARTICIPANTS,string"`
		Name            string `json:"name"`
		Group           string `json:"group"`
		Hash            string `json:"hash"`
	} `json:"config"`
	Inputs struct {
		GroupSecretKey              string   `json:"group_secret_key"`
		GroupPublicKey              string   `json:"group_public_key"`
		Message                     string   `json:"message"`
		SharePolynomialCoefficients []string `json:"share_polynomial_coefficients"`
		Participants                struct {
			Num1 struct {
				ParticipantShare string `json:"participant_share"`
			} `json:"1"`
			Num2 struct {
				ParticipantShare string `json:"participant_share"`
			} `json:"2"`
			Num3 struct {
				ParticipantShare string `json:"participant_share"`
			} `json:"3"`
		} `json:"participants"`
	} `json:"inputs"`
	RoundOneOutputs struct {
		ParticipantList string `json:"participant_list"`
		Participants    struct {
			Num1 struct {
				HidingNonceRandomness  string `json:"hiding_nonce_randomness"`
				BindingNonceRandomness string `json:"binding_nonce_randomness"`
				HidingNonce            string `json:"hiding_nonce"`
				BindingNonce           string `json:"binding_nonce"`
				HidingNonceCommitment  string `json:"hiding_nonce_commitment"`
				BindingNonceCommitment string `json:"binding_nonce_commitment"`
				BindingFactorInput     string `json:"binding_factor_input"`
				BindingFactor          string `json:"binding_factor"`
			} `json:"1"`
			Num3 struct {
				HidingNonceRandomness  string `json:"hiding_nonce_randomness"`
				BindingNonceRandomness string `json:"binding_nonce_randomness"`
				HidingNonce            string `json:"hiding_nonce"`
				BindingNonce           string `json:"binding_nonce"`
				HidingNonceCommitment  string `json:"hiding_nonce_commitment"`
				BindingNonceCommitment string `json:"binding_nonce_commitment"`
				BindingFactorInput     string `json:"binding_factor_input"`
				BindingFactor          string `json:"binding_factor"`
			} `json:"3"`
		} `json:"participants"`
	} `json:"round_one_outputs"`
	RoundTwoOutputs struct {
		ParticipantList string `json:"participant_list"`
		Participants    struct {
			Num1 struct {
				SigShare string `json:"sig_share"`
			} `json:"1"`
			Num3 struct {
				SigShare string `json:"sig_share"`
			} `json:"3"`
		} `json:"participants"`
	} `json:"round_two_outputs"`
	FinalOutput struct {
		Sig string `json:"sig"`
	} `json:"final_output"`
}

func fromHex(t *testing.T, s, errMsg string) []byte {
	t.Helper()
	bytes, err := hex.DecodeString(s)
	test.CheckNoErr(t, err, "decoding "+errMsg)

	return bytes
}

func toBytesScalar(t *testing.T, s group.Scalar) []byte {
	t.Helper()
	bytes, err := s.MarshalBinary()
	test.CheckNoErr(t, err, "decoding scalar")

	return bytes
}

func toBytesElt(t *testing.T, e group.Element) []byte {
	t.Helper()
	bytes, err := e.MarshalBinaryCompress()
	test.CheckNoErr(t, err, "decoding element")

	return bytes
}

func toScalar(t *testing.T, g group.Group, s, errMsg string) group.Scalar {
	t.Helper()
	r := g.NewScalar()
	rBytes := fromHex(t, s, errMsg)
	err := r.UnmarshalBinary(rBytes)
	test.CheckNoErr(t, err, errMsg)

	return r
}

func compareBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want)
	}
}

func (v *vector) test(t *testing.T, suite Suite) {
	privKey := &PrivateKey{suite, toScalar(t, suite.g, v.Inputs.GroupSecretKey, "bad private key"), nil}
	pubKeyGroup := privKey.Public()
	compareBytes(t, toBytesElt(t, pubKeyGroup.key), fromHex(t, v.Inputs.GroupPublicKey, "bad public key"))

	p1 := PeerSigner{
		Suite:      suite,
		threshold:  v.Config.NUMPARTICIPANTS,
		maxSigners: v.Config.MAXPARTICIPANTS,
		keyShare: secretsharing.Share{
			ID:    suite.g.NewScalar().SetUint64(1),
			Value: toScalar(t, suite.g, v.Inputs.Participants.Num1.ParticipantShare, "signer share value"),
		},
		myPubKey: nil,
	}

	/*p2 := PeerSigner{
		Suite:      suite,
		threshold:  v.Config.NUMPARTICIPANTS,
		maxSigners: v.Config.MAXPARTICIPANTS,
		keyShare: secretsharing.Share{
			ID: suite.g.NewScalar().SetUint64(2),
			Value: toScalar(t, suite.g, v.Inputs.Participants.Num2.ParticipantShare, "signer share value"),
		},
		myPubKey: nil,
	}*/

	p3 := PeerSigner{
		Suite:      suite,
		threshold:  v.Config.NUMPARTICIPANTS,
		maxSigners: v.Config.MAXPARTICIPANTS,
		keyShare: secretsharing.Share{
			ID:    suite.g.NewScalar().SetUint64(3),
			Value: toScalar(t, suite.g, v.Inputs.Participants.Num3.ParticipantShare, "signer share value"),
		},
		myPubKey: nil,
	}

	hn1 := toScalar(t, suite.g, v.RoundOneOutputs.Participants.Num1.HidingNonce, "hiding nonce")
	bn1 := toScalar(t, suite.g, v.RoundOneOutputs.Participants.Num1.BindingNonce, "binding nonce")
	nonce1, commit1, err := p1.commitWithNonce(hn1, bn1)
	test.CheckNoErr(t, err, "failed to commit")

	compareBytes(t, toBytesElt(t, commit1.hiding), fromHex(t, v.RoundOneOutputs.Participants.Num1.HidingNonceCommitment, "hiding nonce commit"))
	compareBytes(t, toBytesElt(t, commit1.binding), fromHex(t, v.RoundOneOutputs.Participants.Num1.BindingNonceCommitment, "binding nonce commit"))

	hn3 := toScalar(t, suite.g, v.RoundOneOutputs.Participants.Num3.HidingNonce, "hiding nonce")
	bn3 := toScalar(t, suite.g, v.RoundOneOutputs.Participants.Num3.BindingNonce, "binding nonce")
	nonce3, commit3, err := p3.commitWithNonce(hn3, bn3)
	test.CheckNoErr(t, err, "failed to commit")

	compareBytes(t, toBytesElt(t, commit3.hiding), fromHex(t, v.RoundOneOutputs.Participants.Num3.HidingNonceCommitment, "hiding nonce commit"))
	compareBytes(t, toBytesElt(t, commit3.binding), fromHex(t, v.RoundOneOutputs.Participants.Num3.BindingNonceCommitment, "binding nonce commit"))

	msg := fromHex(t, v.Inputs.Message, "bad msg")
	commits := []*Commitment{commit1, commit3}
	bindingFactors, err := suite.getBindingFactors(commits, msg)
	test.CheckNoErr(t, err, "failed to get binding factors")

	compareBytes(t, toBytesScalar(t, bindingFactors[0].factor), fromHex(t, v.RoundOneOutputs.Participants.Num1.BindingFactor, "binding factor"))
	compareBytes(t, toBytesScalar(t, bindingFactors[1].factor), fromHex(t, v.RoundOneOutputs.Participants.Num3.BindingFactor, "binding factor"))

	signShares1, err := p1.Sign(msg, pubKeyGroup, nonce1, commits)
	test.CheckNoErr(t, err, "failed to sign share")
	compareBytes(t, toBytesScalar(t, signShares1.s.Value), fromHex(t, v.RoundTwoOutputs.Participants.Num1.SigShare, "sign share"))

	signShares3, err := p3.Sign(msg, pubKeyGroup, nonce3, commits)
	test.CheckNoErr(t, err, "failed to sign share")
	compareBytes(t, toBytesScalar(t, signShares3.s.Value), fromHex(t, v.RoundTwoOutputs.Participants.Num3.SigShare, "sign share"))

	combiner, err := NewCombiner(suite, uint(v.Config.MINPARTICIPANTS-1), uint(v.Config.MAXPARTICIPANTS))
	test.CheckNoErr(t, err, "failed to create combiner")

	signShares := []*SignShare{signShares1, signShares3}
	signature, err := combiner.Sign(msg, commits, signShares)
	test.CheckNoErr(t, err, "failed to create signature")
	compareBytes(t, signature, fromHex(t, v.FinalOutput.Sig, "signature"))

	valid := Verify(suite, pubKeyGroup, msg, signature)
	test.CheckOk(valid == true, "invalid signature", t)
}

func readFile(t *testing.T, fileName string) *vector {
	t.Helper()
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, err := io.ReadAll(jsonFile)
	if err != nil {
		t.Fatalf("File %v can not be read. Error: %v", fileName, err)
	}

	var v vector
	err = json.Unmarshal(input, &v)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}

	return &v
}

func TestVectors(t *testing.T) {
	// Draft published at https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-frost-11
	// Test vectors at https://github.com/cfrg/draft-irtf-cfrg-frost
	// Version supported: v11
	suite, vector := P256, readFile(t, "testdata/frost_p256_sha256.json")
	t.Run(fmt.Sprintf("%v", suite), func(tt *testing.T) { vector.test(tt, suite) })

	suite, vector = Ristretto255, readFile(t, "testdata/frost_ristretto255_sha512.json")
	t.Run(fmt.Sprintf("%v", suite), func(tt *testing.T) { vector.test(tt, suite) })
}
