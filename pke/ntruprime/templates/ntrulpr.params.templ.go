// +build ignore
// The previous line (and this one up to the warning below) is removed by the
// template generator.

// Code generated from ntrulpr.params.templ.go
package ntruprime

const (
	P             = {{.P}}
	Q             = {{.Q}}
	RoundedBytes = {{.Rounded_bytes}}

	W    = {{.W}} 
	Tau0 = {{.Tau0}}
	Tau1 = {{.Tau1}}
	Tau2 = {{.Tau2}}
	Tau3 = {{.Tau3}}

	I = 256
)

const (

	// Size of the established shared key.
	SharedKeySize = {{.SharedKeySize}}

	// Size of the encapsulated shared key.
	CiphertextSize = {{.CiphertextSize}}

	// Size of a packed public key.
	PublicKeySize = {{.PublicKeySize}}

	// Size of a packed private key.
	PrivateKeySize = {{.PrivateKeySize}}
)
