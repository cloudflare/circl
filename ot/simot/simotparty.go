package simot

import "github.com/cloudflare/circl/group"

type Sender struct {
	index   int           // Indicate which OT
	m0      []byte        // The M0 message from sender
	m1      []byte        // The M1 message from sender
	a       group.Scalar  // The randomness of the sender
	A       group.Element // [a]G
	B       group.Element // The random group element from the receiver
	k0      []byte        // The encryption key of M0
	k1      []byte        // The encryption key of M1
	e0      []byte        // The encryption of M0 under k0
	e1      []byte        // The encryption of M1 under k1
	myGroup group.Group   // The elliptic curve we operate in
}

type Receiver struct {
	index   int           // Indicate which OT
	c       int           // The choice bit of the receiver
	A       group.Element // The random group element from the sender
	b       group.Scalar  // The randomness of the receiver
	B       group.Element // B = [b]G if c == 0, B = A+[b]G if c == 1
	kR      []byte        // The decryption key of receiver
	ec      []byte        // The encryption of mc
	mc      []byte        // The decrypted message from sender
	myGroup group.Group   // The elliptic curve we operate in
}
