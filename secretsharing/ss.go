// Package secretsharing provides methods to split secrets in shares.
//
// A (t,n) secret sharing allows to split a secret into n shares, such that the
// secret can be only recovered given more than t shares.
//
// The New function creates a Shamir secret sharing [1], which relies on
// Lagrange polynomial interpolation.
//
// The NewVerifiable function creates a Feldman secret sharing [2], which
// extends Shamir's by allowing to verify that a share corresponds to the
// secret.
//
// References
//  [1] https://dl.acm.org/doi/10.1145/359168.359176
//  [2] https://ieeexplore.ieee.org/document/4568297
package secretsharing

import (
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/math/polynomial"
)

// Share represents a share of a secret.
type Share struct {
	ID    uint
	Share group.Scalar
}

// SecretSharing implements a (t,n) Shamir's secret sharing.
type SecretSharing interface {
	// Params returns the t and n parameters of the secret sharing.
	Params() (t, n uint)
	// Shard splits the secret into n shares.
	Shard(rnd io.Reader, secret group.Scalar) []Share
	// Recover returns the secret provided more than t shares are given.
	Recover(shares []Share) (secret group.Scalar, err error)
}

type ss struct {
	g    group.Group
	t, n uint
}

// New returns a struct implementing SecretSharing interface. A (t,n) secret
// sharing allows to split a secret into n shares, such that the secret can be
// only recovered given more than t shares. It panics if 0 < t <= n does not
// hold.
func New(g group.Group, t, n uint) (ss, error) {
	if !(0 < t && t <= n) {
		return ss{}, errors.New("secretsharing: bad parameters")
	}
	s := ss{g: g, t: t, n: n}
	var _ SecretSharing = s // checking at compile-time
	return s, nil
}

func (s ss) Params() (t, n uint) { return s.t, s.n }

func (s ss) polyFromSecret(rnd io.Reader, secret group.Scalar) (p polynomial.Polynomial) {
	c := make([]group.Scalar, s.t+1)
	for i := range c {
		c[i] = s.g.RandomScalar(rnd)
	}
	c[0].Set(secret)
	return polynomial.New(c)
}

func (s ss) generateShares(poly polynomial.Polynomial) []Share {
	shares := make([]Share, s.n)
	x := s.g.NewScalar()
	for i := range shares {
		id := i + 1
		x.SetUint64(uint64(id))
		shares[i].ID = uint(id)
		shares[i].Share = poly.Evaluate(x)
	}

	return shares
}

func (s ss) Shard(rnd io.Reader, secret group.Scalar) []Share {
	return s.generateShares(s.polyFromSecret(rnd, secret))
}

func (s ss) Recover(shares []Share) (group.Scalar, error) {
	if l := len(shares); l <= int(s.t) {
		return nil, fmt.Errorf("secretsharing: does not reach the threshold %v with %v shares", s.t, l)
	} else if l > int(s.n) {
		return nil, fmt.Errorf("secretsharing: %v shares above max number of shares %v", l, s.n)
	}

	x := make([]group.Scalar, len(shares))
	px := make([]group.Scalar, len(shares))
	for i := range shares {
		x[i] = s.g.NewScalar()
		x[i].SetUint64(uint64(shares[i].ID))
		px[i] = shares[i].Share
	}

	l := polynomial.NewLagrangePolynomial(x, px)
	zero := s.g.NewScalar()

	return l.Evaluate(zero), nil
}

type SharesCommitment = []group.Element

type vss struct{ s ss }

// SecretSharing implements a (t,n) Feldman's secret sharing.
type VerifiableSecretSharing interface {
	// Params returns the t and n parameters of the secret sharing.
	Params() (t, n uint)
	// Shard splits the secret into n shares, and a commitment of the secret
	// and the shares.
	Shard(rnd io.Reader, secret group.Scalar) ([]Share, SharesCommitment)
	// Recover returns the secret provided more than t shares are given.
	Recover(shares []Share) (secret group.Scalar, err error)
	// Verify returns true if the share corresponds to a committed secret using
	// the commitment produced by Shard.
	Verify(share Share, coms SharesCommitment) bool
}

// New returns a struct implementing VerifiableSecretSharing interface. A (t,n)
// secret sharing allows to split a secret into n shares, such that the secret
// can be only recovered given more than t shares. It is possible to verify
// whether a share corresponds to a secret. It panics if 0 < t <= n does not
// hold.
func NewVerifiable(g group.Group, t, n uint) (vss, error) {
	s, err := New(g, t, n)
	v := vss{s}
	var _ VerifiableSecretSharing = v // checking at compile-time
	return v, err
}

func (v vss) Params() (t, n uint) { return v.s.Params() }

func (v vss) Shard(rnd io.Reader, secret group.Scalar) ([]Share, SharesCommitment) {
	poly := v.s.polyFromSecret(rnd, secret)
	shares := v.s.generateShares(poly)
	coeffs := poly.Coefficients()
	shareComs := make(SharesCommitment, len(coeffs))
	for i := range coeffs {
		shareComs[i] = v.s.g.NewElement().MulGen(coeffs[i])
	}

	return shares, shareComs
}

func (v vss) Verify(s Share, c SharesCommitment) bool {
	if len(c) != int(v.s.t+1) {
		return false
	}

	lc := len(c) - 1
	sum := v.s.g.NewElement().Set(c[lc])
	x := v.s.g.NewScalar()
	for i := lc - 1; i >= 0; i-- {
		x.SetUint64(uint64(s.ID))
		sum.Mul(sum, x)
		sum.Add(sum, c[i])
	}
	polI := v.s.g.NewElement().MulGen(s.Share)
	return polI.IsEqual(sum)
}

func (v vss) Recover(shares []Share) (group.Scalar, error) { return v.s.Recover(shares) }
