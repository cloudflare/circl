// Package hpke implements hybrid public/private-key encryption.
//
// HPKE works for any combination of an asymmetric-key encapsulation mechanism
// (KEM), a key derivation function (KDF), and an authenticated symmetric-key
// encryption scheme with additional data (AEAD).
//
// Specification in https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke
package hpke

import "github.com/cloudflare/circl/kem"

const versionLabel = "HPKE-06"

// Exporter is
type Exporter interface {
	Export(expCtx []byte, len uint16) []byte
}

// Sealer is
type Sealer interface {
	Exporter
	Seal(pt, aad []byte) (ct []byte, err error)
}

// Opener is
type Opener interface {
	Exporter
	Open(ct, aad []byte) (pt []byte, err error)
}

// ModeID represents an HPKE variant.
type ModeID = uint8

const (
	// Base provides hybrid public-key encryption to a public key.
	Base ModeID = 0x00
	// PSK provides hybrid public-key encryption with authentication using a pre-shared key.
	PSK ModeID = 0x01
	// Auth provides hybrid public-key encryption with authentication using an asymmetric key.
	Auth ModeID = 0x02
	// AuthPSK provides hybrid public-key encryption with authentication using both a pre-shared key and an asymmetric key.
	AuthPSK ModeID = 0x03
)

type Suite struct {
	KemID  KemID
	KdfID  KdfID
	AeadID AeadID
}

type state struct {
	Suite
	modeID ModeID
	skS    kem.PrivateKey
	pkS    kem.PublicKey
	psk    []byte
	pskID  []byte
}

type Sender struct {
	state
	pkR  kem.PublicKey
	info []byte
	seed []byte
}

func (s Suite) NewSender(pkR kem.PublicKey, info, seed []byte) *Sender {
	return &Sender{state: state{Suite: s}, pkR: pkR, info: info, seed: seed}
}

func (s *Sender) Setup() (enc []byte, seal Sealer, err error) {
	s.modeID = Base
	return s.allSetup()
}
func (s *Sender) SetupAuth(skS kem.PrivateKey) (enc []byte, seal Sealer, err error) {
	s.modeID = Auth
	s.state.skS = skS
	return s.allSetup()
}
func (s *Sender) SetupPSK(psk, pskID []byte) (enc []byte, seal Sealer, err error) {
	s.modeID = PSK
	s.state.psk = psk
	s.state.pskID = pskID
	return s.allSetup()
}
func (s *Sender) SetupAuthPSK(skS kem.PrivateKey, psk, pskID []byte) (enc []byte, seal Sealer, err error) {
	s.modeID = AuthPSK
	s.state.skS = skS
	s.state.psk = psk
	s.state.pskID = pskID
	return s.allSetup()
}

type Receiver struct {
	state
	skR  kem.PrivateKey
	enc  []byte
	info []byte
}

func (s Suite) NewReceiver(skR kem.PrivateKey, info []byte) *Receiver {
	return &Receiver{state: state{Suite: s}, skR: skR, info: info}
}

func (r *Receiver) Setup(enc []byte) (Opener, error) {
	r.modeID = Base
	r.enc = enc
	return r.allSetup()
}
func (r *Receiver) SetupAuth(enc []byte, pkS kem.PublicKey) (Opener, error) {
	r.modeID = Auth
	r.enc = enc
	r.state.pkS = pkS
	return r.allSetup()
}
func (r *Receiver) SetupPSK(enc, psk, pskID []byte) (Opener, error) {
	r.modeID = PSK
	r.enc = enc
	r.state.psk = psk
	r.state.pskID = pskID
	return r.allSetup()
}
func (r *Receiver) SetupAuthPSK(enc, psk, pskID []byte, pkS kem.PublicKey) (Opener, error) {
	r.modeID = AuthPSK
	r.enc = enc
	r.state.psk = psk
	r.state.pskID = pskID
	r.state.pkS = pkS
	return r.allSetup()
}

func (s *Sender) allSetup() ([]byte, Sealer, error) {
	err := s.validate()
	if err != nil {
		return nil, nil, err
	}

	var enc, ss []byte
	switch s.modeID {
	case Base, PSK:
		enc, ss, err = s.encap(s.pkR)
	case Auth, AuthPSK:
		enc, ss, err = s.encapAuth(s.pkR, s.skS)
	}
	if err != nil {
		return nil, nil, err
	}

	ctx, err := s.keySchedule(ss, s.info, s.psk, s.pskID)
	if err != nil {
		return nil, nil, err
	}

	return enc, &sealCxt{ctx}, nil
}

func (r *Receiver) allSetup() (Opener, error) {
	err := r.validate()
	if err != nil {
		return nil, err
	}

	var ss []byte
	switch r.modeID {
	case Base, PSK:
		ss, err = r.decap(r.skR, r.enc)
	case Auth, AuthPSK:
		ss, err = r.decapAuth(r.skR, r.enc, r.pkS)
	}
	if err != nil {
		return nil, err
	}

	ctx, err := r.keySchedule(ss, r.info, r.psk, r.pskID)
	if err != nil {
		return nil, err
	}
	return &openCxt{ctx}, nil
}
