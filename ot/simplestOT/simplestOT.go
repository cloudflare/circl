// Reference: https://eprint.iacr.org/2015/267.pdf (1 out of 2 OT case)
// Sender has 2 messages m0, m1
// Receiver receives mc based on the choice bit c

package simplestOT

import (
	"github.com/cloudflare/circl/group"
)

// Input: myGroup, the group we operate in
// Input: m0, m1 the 2 message of the sender
// Input: choice, the bit c of the receiver
// Input: index, the index of this BaseOT
func BaseOT(myGroup group.Group, sender *SenderSimOT, receiver *ReceiverSimOT, m0, m1 []byte, choice, index int) error {

	// Initialization
	A := sender.InitSender(myGroup, m0, m1, index)

	// Round 1
	// Sender sends A to receiver
	B := receiver.Round1Receiver(myGroup, choice, index, A)

	// Round 2
	// Receiver sends B to sender
	e0, e1 := sender.Round2Sender(B)

	// Round 3
	// Sender sends e0 e1 to receiver
	errDec := receiver.Round3Receiver(e0, e1, receiver.c)
	if errDec != nil {
		return errDec
	}

	return nil
}
