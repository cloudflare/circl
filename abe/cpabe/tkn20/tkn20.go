// Package tkn20 implements a ciphertext-policy ABE by Tomida, Kawahara, Nishimaki.
//
// This is an implementation of an IND-CCA2 secure variant of the Ciphertext-Policy
// Attribute Based Encryption (CP-ABE) scheme by
// J. Tomida, Y. Kawahara, and R. Nishimaki. Fast, compact, and expressive
// attribute-based encryption. In A. Kiayias, M. Kohlweiss, P. Wallden, and
// V. Zikas, editors, PKC, volume 12110 of Lecture Notes in Computer Science,
// pages 3–33. Springer, 2020. https://eprint.iacr.org/2019/966
package tkn20

import (
	cryptoRand "crypto/rand"
	"io"

	"github.com/cloudflare/circl/abe/cpabe/tkn20/internal/dsl"
	"github.com/cloudflare/circl/abe/cpabe/tkn20/internal/tkn"
)

type PublicKey struct {
	pp tkn.PublicParams
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.pp.MarshalBinary()
}

func (p *PublicKey) UnmarshalBinary(data []byte) error {
	return p.pp.UnmarshalBinary(data)
}

func (p *PublicKey) Equal(p2 *PublicKey) bool {
	return p.pp.Equal(&p2.pp)
}

func (p *PublicKey) Encrypt(rand io.Reader, policy Policy, msg []byte) ([]byte, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}
	return tkn.EncryptCCA(rand, &p.pp, &policy.policy, msg)
}

type SystemSecretKey struct {
	sp tkn.SecretParams
}

func (msk *SystemSecretKey) MarshalBinary() ([]byte, error) {
	return msk.sp.MarshalBinary()
}

func (msk *SystemSecretKey) UnmarshalBinary(data []byte) error {
	return msk.sp.UnmarshalBinary(data)
}

func (msk *SystemSecretKey) Equal(msk2 *SystemSecretKey) bool {
	return msk.sp.Equal(&msk2.sp)
}

func (msk *SystemSecretKey) KeyGen(rand io.Reader, attrs Attributes) (AttributeKey, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}
	sk, err := tkn.DeriveAttributeKeysCCA(rand, &msk.sp, &attrs.attrs)
	return AttributeKey{*sk}, err
}

type AttributeKey struct {
	ak tkn.AttributesKey
}

func (s *AttributeKey) MarshalBinary() ([]byte, error) {
	return s.ak.MarshalBinary()
}

func (s *AttributeKey) UnmarshalBinary(data []byte) error {
	return s.ak.UnmarshalBinary(data)
}

func (s *AttributeKey) Equal(s2 *AttributeKey) bool {
	return s.ak.Equal(&s2.ak)
}

func (s *AttributeKey) Decrypt(ct []byte) ([]byte, error) {
	return tkn.DecryptCCA(ct, &s.ak)
}

type Policy struct {
	policy tkn.Policy
}

func (p *Policy) FromString(str string) error {
	policy, err := dsl.Run(str)
	if err != nil {
		return err
	}
	p.policy = *policy
	return nil
}

func (p *Policy) String() string {
	return p.policy.String()
}

func (p *Policy) ExtractFromCiphertext(ct []byte) error {
	return p.policy.ExtractFromCiphertext(ct)
}

func (p *Policy) ExtractAttributeValuePairs() map[string][]string {
	pairs := make(map[string][]string, len(p.policy.Inputs))
	for _, w := range p.policy.Inputs {
		pairs[w.Label] = append(pairs[w.Label], w.RawValue)
	}
	return pairs
}

func (p *Policy) Equal(p2 *Policy) bool {
	return p.policy.Equal(&p2.policy)
}

func (p *Policy) Satisfaction(a Attributes) bool {
	_, err := p.policy.Satisfaction(&a.attrs)
	return err == nil
}

// An Attribute is some characteristic associated with an entity.
// For example, a user can have an Attribute with Key `country` and Value `US`.
// An Attribute can also support wildcards. This means that if a Policy has a term
// where the attribute's value is a wildcard, such as `country: *`, this user will
// be able to satisfy it as long as it has an Attribute with Key `country`, irrespective of the Value.
// SupportWildcard set to false (as is the default) will not allow this user to satisfy
// a Policy such as `country: *`.
//
// Attribute is not used directly for any purposes such as generating keys.
// Users must use the function [NewAttributes] to first construct the struct Attributes,
// which can then be used for various purposes.
type Attribute struct {
	Key             string
	Value           string
	SupportWildcard bool
}

// Attributes correspond to a set of Attributes(s) associated with some entity.
// Attributes can be used for various purposes, such as generating an AttributeKey corresponding to
// this set of attributes.
type Attributes struct {
	attrs tkn.Attributes
}

// Equal checks equality of two sets of Attributes.
func (a *Attributes) Equal(a2 *Attributes) bool {
	return a.attrs.Equal(&a2.attrs)
}

// CouldDecrypt checks if a given set of attributes are capable of decrypting a ciphertext
// encrypted under some policy. This method can be helpful for determining satisfaction when the Policy
// and/or AttributeKey is unknown, such as when a user without the relevant attributes is trying to determine
// who possess access of a given resource.
func (a *Attributes) CouldDecrypt(ciphertext []byte) bool {
	return tkn.CouldDecrypt(ciphertext, &a.attrs)
}

// NewAttributes takes as input a list of Attribute(s) that are associated with some entity, and returns Attributes.
func NewAttributes(in []Attribute) Attributes {
	attrs := make(map[string]tkn.Attribute, len(in))
	for _, attr := range in {
		attrs[attr.Key] = tkn.Attribute{
			Wild:  attr.SupportWildcard,
			Value: tkn.HashStringToScalar(dsl.AttrHashKey, attr.Value),
		}
	}
	return Attributes{attrs: attrs}
}

func Setup(rand io.Reader) (PublicKey, SystemSecretKey, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}
	pp, sp, err := tkn.GenerateParams(rand)
	return PublicKey{*pp}, SystemSecretKey{*sp}, err
}
