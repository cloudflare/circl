package frost

import (
	"crypto"
	_ "crypto/sha256" // added to link library.
	_ "crypto/sha512" // added to link library.
	"fmt"

	r255 "github.com/bwesterb/go-ristretto"
	"github.com/cloudflare/circl/group"
)

var (
	P256         = Suite{group.P256, suiteP{group.P256, suiteCommon{crypto.SHA256, "FROST-P256-SHA256-v11"}}}
	Ristretto255 = Suite{group.Ristretto255, suiteRis255{suiteCommon{crypto.SHA512, "FROST-RISTRETTO255-SHA512-v11"}}}
)

type Suite struct {
	g      group.Group
	hasher interface {
		h1(m []byte) group.Scalar
		h2(m []byte) group.Scalar
		h3(m []byte) group.Scalar
		h4(m []byte) []byte
		h5(m []byte) []byte
	}
}

func (s Suite) String() string { return s.hasher.(fmt.Stringer).String() }

const (
	labelRho   = "rho"
	labelChal  = "chal"
	labelNonce = "nonce"
	labelMsg   = "msg"
	labelCom   = "com"
)

type suiteCommon struct {
	hash    crypto.Hash
	context string
}

func (s suiteCommon) String() string     { return s.context[:len(s.context)-4] }
func (s suiteCommon) h4(m []byte) []byte { return s.hashLabeled(labelMsg, m) }
func (s suiteCommon) h5(m []byte) []byte { return s.hashLabeled(labelCom, m) }
func (s suiteCommon) hashLabeled(label string, m []byte) []byte {
	H := s.hash.New()
	_, _ = H.Write([]byte(s.context + label))
	_, _ = H.Write(m)
	return H.Sum(nil)
}

type suiteP struct {
	g group.Group
	suiteCommon
}

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
