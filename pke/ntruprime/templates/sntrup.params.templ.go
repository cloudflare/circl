// +build ignore
// The previous line (and this one up to the warning below) is removed by the
// template generator.

// Code generated from sntrup.params.templ.go. DO NOT EDIT.
package ntruprime
const (
	P             = {{.P}}
	Q             = {{.Q}}
	RoundedBytes = {{.Rounded_bytes}}
	RqBytes      = {{.Rq_bytes}}
	W             = {{.W}}
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
