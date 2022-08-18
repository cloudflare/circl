// Reference: https://eprint.iacr.org/2021/1373.pdf
// Sender and receiver has private input a and b
// Sender and receiver get s1 and s2 such that a*b = s1+s2 from Fmul
// This scheme based on pure OT but not OT extension

package Fmul

import (
	"github.com/cloudflare/circl/group"
)

// Input: myGroup, the group we operate in
// Input: securityParameter
// Output: The number of BaseOT needed
func DecideNumOT(myGroup group.Group, sp int) int {
	numBaseOT := int(myGroup.Params().ScalarLength*8) + sp
	return numBaseOT
}

// Input: aInput, bInput, the private input from both sender and receiver
// Input: myGroup, the group we operate in
// Input: n, the total number of BaseOT
func Fmul(sender *SenderFmul, receiver *ReceiverFmul, aInput, bInput group.Scalar, myGroup group.Group, n int) error {
	// Sender Initialization
	As := sender.SenderInit(myGroup, aInput, n)

	// ---- Round1: Sender sends As to receiver ----

	Bs := receiver.ReceiverRound1(myGroup, As, bInput, n)

	// ---- Round 2: Receiver sends Bs = [bi]G or Ai+[bi]G to sender ----

	e0s, e1s := sender.SenderRound2(Bs, n)

	// ---- Round 3: Sender sends e0s, e1s to receiver ----

	sigma, vs, errDec := receiver.ReceiverRound3(e0s, e1s, n)
	if errDec != nil {
		return errDec
	}

	// ---- Round 4: receiver sends sigma as well as vs to sender ----

	sender.SenderRound4(vs, sigma, n)

	return nil
}
