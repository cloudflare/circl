package arc_test

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/ac/arc"
	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
	"golang.org/x/crypto/cryptobyte"
)

type vector struct {
	ARCV1P256 struct {
		Credential struct {
			Blindings []test.HexBytes `json:"Blindings"`
			U         test.HexBytes   `json:"U"`
			UPrime    test.HexBytes   `json:"U_prime"`
			X1        test.HexBytes   `json:"X1"`
			M1        test.HexBytes   `json:"m1"`
		} `json:"Credential"`
		CredentialRequest struct {
			Blindings      []test.HexBytes `json:"Blindings"`
			M1             test.HexBytes   `json:"m1"`
			M1Enc          test.HexBytes   `json:"m1_enc"`
			M2             test.HexBytes   `json:"m2"`
			M2Enc          test.HexBytes   `json:"m2_enc"`
			Proof          test.HexBytes   `json:"proof"`
			R1             test.HexBytes   `json:"r1"`
			R2             test.HexBytes   `json:"r2"`
			RequestContext test.HexBytes   `json:"request_context"`
		} `json:"CredentialRequest"`
		CredentialResponse struct {
			Blindings []test.HexBytes `json:"Blindings"`
			HAux      test.HexBytes   `json:"H_aux"`
			U         test.HexBytes   `json:"U"`
			X0Aux     test.HexBytes   `json:"X0_aux"`
			X1Aux     test.HexBytes   `json:"X1_aux"`
			X2Aux     test.HexBytes   `json:"X2_aux"`
			B         test.HexBytes   `json:"b"`
			EncUPrime test.HexBytes   `json:"enc_U_prime"`
			Proof     test.HexBytes   `json:"proof"`
		} `json:"CredentialResponse"`
		Presentation []vectorPresentation `json:"Presentation"`
		ServerKey    struct {
			PubX0  test.HexBytes `json:"X0"`
			PubX1  test.HexBytes `json:"X1"`
			PubX2  test.HexBytes `json:"X2"`
			PrivX0 test.HexBytes `json:"x0"`
			PrivX1 test.HexBytes `json:"x1"`
			PrivX2 test.HexBytes `json:"x2"`
			PrivXb test.HexBytes `json:"xb"`
		} `json:"ServerKey"`
	} `json:"ARCV1-P256"`
}

type vectorPresentation struct {
	Blindings           []test.HexBytes `json:"Blindings"`
	U                   test.HexBytes   `json:"U"`
	UPrimeCommit        test.HexBytes   `json:"U_prime_commit"`
	A                   test.HexBytes   `json:"a"`
	M1Commit            test.HexBytes   `json:"m1_commit"`
	Nonce               string          `json:"nonce"`
	PresentationContext test.HexBytes   `json:"presentation_context"`
	Proof               test.HexBytes   `json:"proof"`
	R                   test.HexBytes   `json:"r"`
	Tag                 test.HexBytes   `json:"tag"`
	Z                   test.HexBytes   `json:"z"`
}

func TestVectors(t *testing.T) {
	input, err := test.ReadGzip("testdata/draft_v01.json.gz")
	test.CheckNoErr(t, err, "failed ReadGzip")

	var v vector
	err = json.Unmarshal(input, &v)
	test.CheckNoErr(t, err, "failed json unmarshal")

	id := arc.SuiteP256
	t.Run(id.String(), func(t *testing.T) {
		priv, pub := testKeys(t, id, &v)
		credential := testCredential(t, id, &priv, &pub, &v)
		testPresentation(t, id, &priv, &credential, &v)
	})
}

func testKeys(t *testing.T, id arc.SuiteID, v *vector) (arc.PrivateKey, arc.PublicKey) {
	wantPriv := &arc.PrivateKey{ID: id}
	doUnmarshal(t, wantPriv,
		v.ARCV1P256.ServerKey.PrivX0,
		v.ARCV1P256.ServerKey.PrivX1,
		v.ARCV1P256.ServerKey.PrivX2,
		v.ARCV1P256.ServerKey.PrivXb,
	)

	wantPub := &arc.PublicKey{ID: id}
	doUnmarshal(t, wantPub,
		v.ARCV1P256.ServerKey.PubX0,
		v.ARCV1P256.ServerKey.PubX1,
		v.ARCV1P256.ServerKey.PubX2,
	)

	reader := keygenMockReader(v)
	gotPriv := arc.KeyGen(&reader, id)
	gotPub := gotPriv.PublicKey()

	if !gotPriv.Equal(wantPriv) {
		test.ReportError(t, gotPriv, wantPriv)
	}

	if !gotPub.Equal(wantPub) {
		test.ReportError(t, gotPub, wantPub)
	}

	test.CheckMarshal(t, &gotPriv, &arc.PrivateKey{ID: id})
	test.CheckMarshal(t, &gotPub, &arc.PublicKey{ID: id})

	return gotPriv, gotPub
}

func testCredential(
	t *testing.T,
	id arc.SuiteID,
	priv *arc.PrivateKey,
	pub *arc.PublicKey,
	v *vector,
) arc.Credential {
	wantCredReq := &arc.CredentialRequest{ID: id}
	doUnmarshal(t, wantCredReq,
		v.ARCV1P256.CredentialRequest.M1Enc,
		v.ARCV1P256.CredentialRequest.M2Enc,
		v.ARCV1P256.CredentialRequest.Proof,
	)

	wantFin := &arc.Finalizer{ID: id}
	doUnmarshal(t, wantFin,
		v.ARCV1P256.CredentialRequest.M1,
		v.ARCV1P256.CredentialRequest.M2,
		v.ARCV1P256.CredentialRequest.R1,
		v.ARCV1P256.CredentialRequest.R2,
	)

	wantCredRes := &arc.CredentialResponse{ID: id}
	doUnmarshal(t, wantCredRes,
		v.ARCV1P256.CredentialResponse.U,
		v.ARCV1P256.CredentialResponse.EncUPrime,
		v.ARCV1P256.CredentialResponse.X0Aux,
		v.ARCV1P256.CredentialResponse.X1Aux,
		v.ARCV1P256.CredentialResponse.X2Aux,
		v.ARCV1P256.CredentialResponse.HAux,
		v.ARCV1P256.CredentialResponse.Proof,
	)

	wantCredential := &arc.Credential{ID: id}
	doUnmarshal(t, wantCredential,
		v.ARCV1P256.Credential.M1,
		v.ARCV1P256.Credential.U,
		v.ARCV1P256.Credential.UPrime,
		v.ARCV1P256.Credential.X1,
	)

	reader := credRequestMockReader(v)
	gotFin, gotCredReq := arc.Request(
		&reader, id, v.ARCV1P256.CredentialRequest.RequestContext,
	)

	if !gotFin.IsEqual(wantFin) {
		test.ReportError(t, gotFin, wantFin)
	}

	if !gotCredReq.IsEqual(wantCredReq) {
		test.ReportError(t, gotCredReq, wantCredReq)
	}

	reader = credResponseMockReader(v)
	gotCredRes, err := arc.Response(&reader, priv, &gotCredReq)
	test.CheckNoErr(t, err, "failed Response")

	if !gotCredRes.IsEqual(wantCredRes) {
		test.ReportError(t, gotCredRes, wantCredRes)
	}

	gotCredential, err := arc.Finalize(&gotFin, &gotCredReq, gotCredRes, pub)
	test.CheckNoErr(t, err, "failed Finalize")

	if !gotCredential.IsEqual(wantCredential) {
		test.ReportError(t, gotCredential, wantCredential)
	}

	test.CheckMarshal(t, wantCredReq, &arc.CredentialRequest{ID: id})
	test.CheckMarshal(t, wantFin, &arc.Finalizer{ID: id})
	test.CheckMarshal(t, wantCredRes, &arc.CredentialResponse{ID: id})
	test.CheckMarshal(t, wantCredential, &arc.Credential{ID: id})

	return *gotCredential
}

func testPresentation(
	t *testing.T,
	id arc.SuiteID,
	priv *arc.PrivateKey,
	cred *arc.Credential,
	v *vector,
) {
	MaxPres := uint16(len(v.ARCV1P256.Presentation))
	reqCtx := v.ARCV1P256.CredentialRequest.RequestContext
	presCtx := v.ARCV1P256.Presentation[0].PresentationContext
	state, err0 := arc.NewState(cred, presCtx, MaxPres)
	test.CheckNoErr(t, err0, "failed NewState")

	for i := range MaxPres {
		vectorPres := v.ARCV1P256.Presentation[i]
		wantPresentation := &arc.Presentation{ID: id}
		doUnmarshal(t, wantPresentation,
			vectorPres.U,
			vectorPres.UPrimeCommit,
			vectorPres.M1Commit,
			vectorPres.Tag,
			vectorPres.Proof,
		)

		reader := presentMockReader(t, &vectorPres)
		nonce, gotPresentation, err := state.Present(&reader)
		test.CheckNoErr(t, err, "failed presentation")

		if !gotPresentation.IsEqual(wantPresentation) {
			test.ReportError(t, gotPresentation, wantPresentation)
		}

		ok := arc.Verify(priv, gotPresentation, reqCtx, presCtx, *nonce, MaxPres)
		test.CheckOk(ok, "invalid presentation", t)

		test.CheckMarshal(t, wantPresentation, &arc.Presentation{ID: id})
		test.CheckMarshal(t, state, &arc.State{ID: id})
	}

	// Check no more presentations can be generated.
	nonce, presentation, err := state.Present(rand.Reader)
	test.CheckOk(nonce == nil, "nonce must be nil", t)
	test.CheckOk(presentation == nil, "presentation must be nil", t)
	test.CheckIsErr(t, err, "present must fail")
	test.CheckMarshal(t, state, &arc.State{ID: id})
}

type mockReader []test.HexBytes

func (m *mockReader) Read(b []byte) (int, error) {
	if len(*m) == 0 {
		return 0, io.EOF
	}

	n := copy(b, (*m)[0])
	*m = (*m)[1:]
	return n, nil
}

func keygenMockReader(v *vector) (m mockReader) {
	return append(m,
		v.ARCV1P256.ServerKey.PrivX0,
		v.ARCV1P256.ServerKey.PrivX1,
		v.ARCV1P256.ServerKey.PrivX2,
		v.ARCV1P256.ServerKey.PrivXb)
}

func credRequestMockReader(v *vector) (m mockReader) {
	return append(append(m,
		v.ARCV1P256.CredentialRequest.M1,
		v.ARCV1P256.CredentialRequest.R1,
		v.ARCV1P256.CredentialRequest.R2,
	), v.ARCV1P256.CredentialRequest.Blindings...)
}

func credResponseMockReader(v *vector) (m mockReader) {
	return append(append(m,
		v.ARCV1P256.CredentialResponse.B),
		v.ARCV1P256.CredentialResponse.Blindings...)
}

func presentMockReader(t *testing.T, v *vectorPresentation) (m mockReader) {
	nonce, err := strconv.ParseUint(v.Nonce, 0, 8)
	test.CheckNoErr(t, err, "failed presentation")

	return append(append(m,
		v.A, v.R, v.Z, []byte{byte(nonce)}), v.Blindings...)
}

func doUnmarshal(t testing.TB, v conv.UnmarshalingValue, h ...[]byte) {
	t.Helper()
	data := cryptobyte.String(slices.Concat(h...))
	ok := v.Unmarshal(&data)
	test.CheckOk(ok, "failed UnmarshalBinary", t)
}
