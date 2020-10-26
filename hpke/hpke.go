// Package hpke implements hybrid public key encryption.
package hpke

import (
	"crypto"
)

// ModeID is
type ModeID uint8

const (
	// Base is
	Base ModeID = iota
	// PSK is
	PSK
	// Auth is
	Auth
	// AuthPSK is
	AuthPSK
)

// Mode is
type Mode struct {
	ModeID
	KemInfo  DHkemID
	HkdfInfo HkdfID
	AeadInfo AeadID
}

// Seal is
func (m Mode) Seal(pkR crypto.PublicKey, info, aad, pt []byte) (enc, ct []byte, err error) {
	enc, ctx, err := m.SetupBaseS(pkR, info)
	if err != nil {
		return nil, nil, err
	}
	ct, err = ctx.Seal(aad, pt)
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, nil
}

// Open is
func (m Mode) Open(skR crypto.PrivateKey, enc, info, aad, ct []byte) ([]byte, error) {
	ctx, err := m.SetupBaseR(skR, enc, info)
	if err != nil {
		return nil, err
	}
	return ctx.Open(aad, ct)
}

// SetupBaseS is
func (m Mode) SetupBaseS(pkR crypto.PublicKey, info []byte) ([]byte, EncContext, error) {
	enc, ss, err := m.encap(pkR)
	if err != nil {
		return nil, nil, err
	}
	ctx, err := m.keySchedule(ss, info, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	return enc, ctx, nil
}

// SetupBaseR is
func (m Mode) SetupBaseR(skR crypto.PrivateKey, enc, info []byte) (DecContext, error) {
	ss, err := m.decap(skR, enc)
	if err != nil {
		return nil, err
	}
	return m.keySchedule(ss, info, nil, nil)
}
