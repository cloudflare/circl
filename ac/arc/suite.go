package arc

import (
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/cryptobyte"
)

// SuiteID is an identifier of the supported suite.
type SuiteID int

const (
	// SuiteP256 uses the P256 elliptic curve group.
	SuiteP256 SuiteID = iota + 1
	// SuiteRistretto255 uses the Ristretto elliptic curve group.
	SuiteRistretto255
)

func (id SuiteID) String() string {
	switch id {
	case SuiteP256:
		return suiteNameP256
	case SuiteRistretto255:
		return suiteNameRistretto255
	default:
		return ErrSuite.Error()
	}
}

func (id SuiteID) getSuite() *suite {
	switch id {
	case SuiteP256:
		return &suiteP256
	case SuiteRistretto255:
		return &suiteRistretto255
	default:
		panic(ErrSuite)
	}
}

var suiteP256, suiteRistretto255 suite

func init() {
	initSuite(&suiteP256, group.P256, contextStringP256)
	initSuite(&suiteRistretto255, group.Ristretto255, contextStringRist)
}

type suite struct {
	g          group.Group
	genG, genH elt
	ctx        string
}

func initSuite(s *suite, g group.Group, context string) {
	s.g = g
	s.ctx = context
	s.genG = s.g.Generator()
	b, _ := eltCom{s.genG}.MarshalBinary()
	s.genH = s.hashToGroup(b, labelGenH)
}

func (s *suite) chalContext(ctx string) string     { return s.ctx + ctx }
func (s *suite) sizeElement() uint                 { return s.g.Params().CompressedElementLength }
func (s *suite) newElement() elt                   { return s.g.NewElement() }
func (s *suite) newScalar() scalar                 { return s.g.NewScalar() }
func (s *suite) randomScalar(rnd io.Reader) scalar { return s.g.RandomNonZeroScalar(rnd) }
func (s *suite) hashToScalar(msg []byte, dst string) scalar {
	return s.g.HashToScalar(msg, []byte(labelHashScalar+s.ctx+dst))
}

func (s *suite) hashToGroup(msg []byte, dst string) elt {
	return s.g.HashToElement(msg, []byte(labelHashGroup+s.ctx+dst))
}

func (s *suite) initElt(v ...*elt) {
	for i := range v {
		*v[i] = s.g.NewElement()
	}
}

func (s *suite) initScalar(v ...*scalar) {
	for i := range v {
		*v[i] = s.g.NewScalar()
	}
}

func printAny(v ...any) (s string) {
	var b strings.Builder
	for i := range v {
		fmt.Fprintf(&b, "%v\n", v[i])
	}
	return b.String()
}

type (
	scalar = group.Scalar
	elt    = group.Element
)

// eltCom enforces the use of compressed elements for serialization.
type eltCom struct{ elt }

func (e eltCom) Size() uint {
	return e.elt.Group().Params().CompressedElementLength
}

func (e eltCom) MarshalBinary() ([]byte, error) {
	return conv.MarshalBinaryLen(e, e.Size())
}

func (e eltCom) UnmarshalBinary(b []byte) error {
	return conv.UnmarshalBinary(e, b)
}

func (e eltCom) Marshal(b *cryptobyte.Builder) error {
	data, err := e.elt.MarshalBinaryCompress()
	if err != nil {
		return err
	}

	b.AddBytes(data)
	return nil
}

func (e eltCom) Unmarshal(s *cryptobyte.String) bool {
	data := make([]byte, e.Size())
	return s.CopyBytes(data) && e.elt.UnmarshalBinary(data) == nil
}

const (
	suiteNameP256         = "P256"
	contextStringP256     = "ARCV1-P256"
	suiteNameRistretto255 = "Ristretto255"
	contextStringRist     = "ARCV1-Ristretto255"
	labelGenH             = "generatorH"
	labelTag              = "Tag"
	labelHashScalar       = "HashToScalar-"
	labelHashGroup        = "HashToGroup-"
	labelRequestContext   = "requestContext"
	labelCRequest         = "CredentialRequest"
	labelCResponse        = "CredentialResponse"
	labelCPresentation    = "CredentialPresentation"
)
