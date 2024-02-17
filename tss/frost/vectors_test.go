package frost

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/secretsharing"
)

type vector struct {
	Config struct {
		MAXSIGNERS int    `json:"MAX_PARTICIPANTS,string"`
		NUMSIGNERS int    `json:"NUM_PARTICIPANTS,string"`
		MINSIGNERS int    `json:"MIN_PARTICIPANTS,string"`
		Name       string `json:"name"`
		Group      string `json:"group"`
		Hash       string `json:"hash"`
	} `json:"config"`
	Inputs struct {
		GroupSecretKey string   `json:"group_secret_key"`
		GroupPublicKey string   `json:"group_public_key"`
		Message        string   `json:"message"`
		PolyCoeffs     []string `json:"share_polynomial_coefficients"`
		Signers        []int    `json:"participant_list"`
		Shares         []struct {
			ID          int    `json:"identifier"`
			SignerShare string `json:"participant_share"`
		} `json:"participant_shares"`
	} `json:"inputs"`
	RoundOneOutputs struct {
		Outputs []struct {
			ID                     int    `json:"identifier"`
			HidingNonceRnd         string `json:"hiding_nonce_randomness"`
			BindingNonceRnd        string `json:"binding_nonce_randomness"`
			HidingNonce            string `json:"hiding_nonce"`
			BindingNonce           string `json:"binding_nonce"`
			HidingNonceCommitment  string `json:"hiding_nonce_commitment"`
			BindingNonceCommitment string `json:"binding_nonce_commitment"`
			BindingFactorInput     string `json:"binding_factor_input"`
			BindingFactor          string `json:"binding_factor"`
		} `json:"outputs"`
	} `json:"round_one_outputs"`
	RoundTwoOutputs struct {
		Outputs []struct {
			ID       int    `json:"identifier"`
			SigShare string `json:"sig_share"`
		} `json:"outputs"`
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
		test.ReportError(t, fmt.Sprintf("%x", got), fmt.Sprintf("%x", want))
	}
}

func (v *vector) test(t *testing.T, s Suite) {
	Threshold := v.Config.MINSIGNERS - 1
	NumPeers := v.Config.NUMSIGNERS
	MaxPeers := v.Config.MAXSIGNERS

	test.CheckOk(MaxPeers == len(v.Inputs.Shares), "bad number of shares", t)
	test.CheckOk(NumPeers == len(v.Inputs.Signers), "bad number of signers", t)
	test.CheckOk(NumPeers == len(v.RoundOneOutputs.Outputs), "bad number of outputs round one", t)
	test.CheckOk(NumPeers == len(v.RoundTwoOutputs.Outputs), "bad number of outputs round two", t)

	params := s.getParams()
	g := params.group()
	privKey := PrivateKey{s, toScalar(t, g, v.Inputs.GroupSecretKey, "bad private key"), nil}
	groupPublicKey := privKey.PublicKey()
	compareBytes(t, toBytesElt(t, groupPublicKey.key), fromHex(t, v.Inputs.GroupPublicKey, "bad public key"))

	peers := make(map[int]PeerSigner)
	for _, inputs := range v.Inputs.Shares {
		keyShare := secretsharing.Share{
			ID:    g.NewScalar().SetUint64(uint64(inputs.ID)),
			Value: toScalar(t, g, inputs.SignerShare, "peer share"),
		}
		peers[inputs.ID] = PeerSigner{
			Suite:          s,
			threshold:      uint16(Threshold),
			maxSigners:     uint16(MaxPeers),
			keyShare:       keyShare,
			groupPublicKey: groupPublicKey,
			myPublicKey:    nil,
		}
	}

	var commitList []Commitment
	var pkSigners []PublicKey
	nonces := make(map[int]Nonce)

	for _, roundOne := range v.RoundOneOutputs.Outputs {
		peer := peers[roundOne.ID]
		hnr := fromHex(t, roundOne.HidingNonceRnd, "hiding nonce rand")
		bnr := fromHex(t, roundOne.BindingNonceRnd, "binding nonce rand")

		nonce, commit, err := peer.commitWithRandomness(hnr, bnr)
		test.CheckNoErr(t, err, "failed to commit")

		compareBytes(t, toBytesScalar(t, nonce.hiding), fromHex(t, roundOne.HidingNonce, "hiding nonce"))
		compareBytes(t, toBytesScalar(t, nonce.binding), fromHex(t, roundOne.BindingNonce, "binding nonce"))
		compareBytes(t, toBytesElt(t, commit.hiding), fromHex(t, roundOne.HidingNonceCommitment, "hiding nonce commit"))
		compareBytes(t, toBytesElt(t, commit.binding), fromHex(t, roundOne.BindingNonceCommitment, "binding nonce commit"))

		nonces[roundOne.ID] = *nonce
		commitList = append(commitList, *commit)
		pkSigners = append(pkSigners, peer.PublicKey())
	}

	msg := fromHex(t, v.Inputs.Message, "bad msg")
	bindingFactors, err := getBindingFactors(params, msg, groupPublicKey, commitList)
	test.CheckNoErr(t, err, "failed to get binding factors")

	for i := range bindingFactors {
		compareBytes(t, toBytesScalar(t, bindingFactors[i].factor), fromHex(t, v.RoundOneOutputs.Outputs[i].BindingFactor, "binding factor"))
	}

	var signShareList []SignShare
	for _, roundTwo := range v.RoundTwoOutputs.Outputs {
		peer := peers[roundTwo.ID]
		signShare, errr := peer.Sign(msg, groupPublicKey, nonces[roundTwo.ID], commitList)
		test.CheckNoErr(t, errr, "failed to sign share")

		compareBytes(t, toBytesScalar(t, signShare.s.ID), toBytesScalar(t, g.NewScalar().SetUint64(uint64(roundTwo.ID))))
		compareBytes(t, toBytesScalar(t, signShare.s.Value), fromHex(t, roundTwo.SigShare, "sign share"))

		signShareList = append(signShareList, *signShare)
	}

	coordinator, err := NewCoordinator(s, uint(Threshold), uint(MaxPeers))
	test.CheckNoErr(t, err, "failed to create combiner")

	ok := coordinator.CheckSignShares(msg, groupPublicKey, signShareList, commitList, pkSigners)
	test.CheckOk(ok == true, "invalid signature shares", t)

	signature, err := coordinator.Aggregate(msg, groupPublicKey, signShareList, commitList)
	test.CheckNoErr(t, err, "failed to create signature")
	compareBytes(t, signature, fromHex(t, v.FinalOutput.Sig, "signature"))

	valid := Verify(msg, groupPublicKey, signature)
	test.CheckOk(valid == true, "invalid signature", t)
}

func readFile(t *testing.T, fileName string) *vector {
	t.Helper()
	input, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}

	var v vector
	err = json.Unmarshal(input, &v)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}

	return &v
}

func TestVectors(t *testing.T) {
	// Draft published at https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-frost-15
	// Test vectors at https://github.com/cfrg/draft-irtf-cfrg-frost
	// Version supported: v15
	suite, vector := P256, readFile(t, "testdata/frost_p256_sha256.json")
	t.Run(fmt.Sprintf("%v", suite), func(tt *testing.T) { vector.test(tt, suite) })

	suite, vector = Ristretto255, readFile(t, "testdata/frost_ristretto255_sha512.json")
	t.Run(fmt.Sprintf("%v", suite), func(tt *testing.T) { vector.test(tt, suite) })
}
