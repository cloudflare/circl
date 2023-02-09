package ECDSAOT

import (
	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/tss/ecdsa/ot/Fmul"
)

// The sender of Fmul
type AlicePre struct {
	label   []byte
	kAPrime group.Scalar
	RPrime  group.Element // R' = [kA']G
	kA      group.Scalar  // kA = H(R') + kA'
	kAInv   group.Scalar  // 1/kA
	DB      group.Element // From bob
	R       group.Element // R =  [kA]DB
	Rx      group.Scalar  // x coordinate of point [kA][kB]G

	a         group.Scalar      // A random blinding for beaver's triple
	ta        group.Scalar      // Additive share of a*b
	receivera Fmul.ReceiverFmul // Receiver of Fmul for a*b

	tkA           group.Scalar      // Additive share of 1/kA*1/kB
	receiverkAInv Fmul.ReceiverFmul // Receiver of Fmul for 1/kA*1/kB
	myGroup       group.Group       // The elliptic curve we operate in
}

// The receiver of Fmul
type BobPre struct {
	label []byte
	kB    group.Scalar
	kBInv group.Scalar // 1/kB

	DB group.Element // DB = [kB]G
	R  group.Element // R =  [kA]DB
	Rx group.Scalar  // x coordinate of point [kA][kB]G

	b       group.Scalar    // A random blinding for beaver's triple
	tb      group.Scalar    // Additive share of a*b
	senderb Fmul.SenderFmul // Sender of Fmul for a*b

	tkB         group.Scalar    // Additive share of 1/kA*1/kB
	senderkBInv Fmul.SenderFmul // Sender of Fmul for 1/kA*1/kB
	myGroup     group.Group     // The elliptic curve we operate in
}

// The final shares need to be saved
type Alice struct {
	myGroup  group.Group // The elliptic curve we operate in
	keyShare group.Scalar
	a        group.Scalar // A random blinding for beaver's triple
	kA       group.Scalar // Multiplicative share of the instance key
	ta       group.Scalar // Additive share of a*b
	tkA      group.Scalar // Additive share of 1/kA*1/kB
	Rx       group.Scalar // x coordinate of point [kA][kB]G
	beaver   group.Scalar //skA/(kA*a)
}

type Bob struct {
	myGroup  group.Group // The elliptic curve we operate in
	keyShare group.Scalar
	b        group.Scalar // A random blinding for beaver's triple
	kB       group.Scalar // Multiplicative share of the instance key
	tb       group.Scalar // Additive share of a*b
	tkB      group.Scalar // Additive share of 1/kA*1/kB
	Rx       group.Scalar // x coordinate of point [kA][kB]G
	beaver   group.Scalar //skB/(kB*b)

}
