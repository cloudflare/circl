// +build ignore
// The previous line (and this one up to the warning below) is removed by the
// template generator.

// Code generated from params.templ.go. DO NOT EDIT.

package internal

import (
	"github.com/cloudflare/circl/pke/kyber/internal/common"
)

const (
	K             = {{.K}}
	Eta1          = {{.Eta1}}
	DU            = {{.DU}}
	DV            = {{.DV}}
	PublicKeySize = 32 + K*common.PolySize

	PrivateKeySize = K * common.PolySize

	PlaintextSize  = common.PlaintextSize
	SeedSize       = 32
	CiphertextSize = {{.CiphertextSize}}
)
