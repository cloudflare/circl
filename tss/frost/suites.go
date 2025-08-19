package frost

import (
	"crypto"
	_ "crypto/sha256" // added to link library.
	_ "crypto/sha512" // added to link library.

	r255 "github.com/bwesterb/go-ristretto"
	"github.com/cloudflare/circl/group"
)

type Suite uint8

const (
	Ristretto255 Suite = iota
	P256
)

func (s Suite) String() string {
	switch s {
	case Ristretto255:
		return paramsRis.String()
	case P256:
		return paramsP256.String()
	default:
		return "frost: undefined suite"
	}
}

var (
	paramsRis  = &suiteRis255{suiteCommon{group.Ristretto255, crypto.SHA512, "FROST-RISTRETTO255-SHA512-v1"}}
	paramsP256 = &suiteP{suiteCommon{group.P256, crypto.SHA256, "FROST-P256-SHA256-v1"}}
)

func (s Suite) getParams() params {
	switch s {
	case Ristretto255:
		return paramsRis
	case P256:
		return paramsP256
	default:
		panic("frost: undefined suite")
	}
}

type params interface {
	group() group.Group
	h1(m []byte) group.Scalar
	h2(m []byte) group.Scalar
	h3(m []byte) group.Scalar
	h4(m []byte) []byte
	h5(m []byte) []byte
}

const (
	labelRho   = "rho"
	labelChal  = "chal"
	labelNonce = "nonce"
	labelMsg   = "msg"
	labelCom   = "com"
)

type suiteCommon struct {
	g       group.Group
	hash    crypto.Hash
	context string
}

func (s suiteCommon) String() string     { return s.context[:len(s.context)-3] }
func (s suiteCommon) group() group.Group { return s.g }
func (s suiteCommon) h4(m []byte) []byte { return s.hashLabeled(labelMsg, m) }
func (s suiteCommon) h5(m []byte) []byte { return s.hashLabeled(labelCom, m) }
func (s suiteCommon) hashLabeled(label string, m []byte) []byte {
	H := s.hash.New()
	_, _ = H.Write([]byte(s.context + label))
	_, _ = H.Write(m)
	return H.Sum(nil)
}

type suiteP struct{ suiteCommon }

func (s suiteP) h1(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.context+labelRho)) }
func (s suiteP) h2(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.context+labelChal)) }
func (s suiteP) h3(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.context+labelNonce)) }

type suiteRis255 struct{ suiteCommon }

func (s suiteRis255) getScalar(input []byte) group.Scalar {
	var data [64]byte
	copy(data[:], input[:64])
	y := new(r255.Scalar).SetReduced(&data)
	bytes, _ := y.MarshalBinary()
	z := group.Ristretto255.NewScalar()
	_ = z.UnmarshalBinary(bytes)
	return z
}

func (s suiteRis255) h1(m []byte) group.Scalar { return s.getScalar(s.hashLabeled(labelRho, m)) }
func (s suiteRis255) h2(m []byte) group.Scalar { return s.getScalar(s.hashLabeled(labelChal, m)) }
func (s suiteRis255) h3(m []byte) group.Scalar { return s.getScalar(s.hashLabeled(labelNonce, m)) }
