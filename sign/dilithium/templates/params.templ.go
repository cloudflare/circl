// +build ignore
// The previous line (and this one up to the warning below) is removed by the
// template generator.

// Code generated from params.templ.go. DO NOT EDIT.

package internal

const (
	Name           = "{{ .Name }}"
	UseAES         = {{ .UseAES }}
	PublicKeySize  = {{ .PublicKeySize }}
	PrivateKeySize = {{ .PrivateKeySize }}
	SignatureSize  = {{ .SignatureSize }}
	K              = {{ .K }}
	L              = {{ .L }}
	Eta            = {{ .Eta }}
	DoubleEtaBits  = {{ .DoubleEtaBits }}
	Beta           = {{ .Beta }}
	Omega          = {{ .Omega }}
	Tau            = {{ .Tau }}
	Gamma1         = {{ .Gamma1 }}
	Gamma2         = {{ .Gamma2 }}
)
