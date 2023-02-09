package Fmul

import (
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/ot/simplestOT"
	"golang.org/x/sync/errgroup"
)

// ---- Sender Initialization ----

// Input: myGroup, the group we operate in
// Input: a, the sender private input
// Input: n, the total number of BaseOT
// Output: Array of A=[ai]G for n BaseOT
func (sender *SenderFmul) SenderInit(myGroup group.Group, a group.Scalar, n int) []group.Element {
	sender.myGroup = myGroup
	sender.a = a.Copy()
	sender.deltas = make([]group.Scalar, n)
	sender.m0s = make([][]byte, n)
	sender.m1s = make([][]byte, n)
	sender.baseOTsenders = make([]simplestOT.SenderSimOT, n)

	var fmulWait sync.WaitGroup
	fmulWait.Add(n)
	for i := 0; i < n; i++ {
		go func(index int) {
			defer fmulWait.Done()
			sender.deltas[index] = myGroup.RandomNonZeroScalar(rand.Reader)
			m0iScalar := myGroup.NewScalar()
			m0iScalar.Sub(sender.deltas[index], sender.a)

			m0iByte, err := m0iScalar.MarshalBinary()
			if err != nil {
				panic(err)
			}
			sender.m0s[index] = m0iByte

			m1iScalar := myGroup.NewScalar()
			m1iScalar.Add(sender.deltas[index], sender.a)

			m1iByte, err := m1iScalar.MarshalBinary()
			if err != nil {
				panic(err)
			}
			sender.m1s[index] = m1iByte

			// n Base OT Sender Initialization
			var BaseOTSender simplestOT.SenderSimOT
			BaseOTSender.InitSender(myGroup, sender.m0s[index], sender.m1s[index], index)
			sender.baseOTsenders[index] = BaseOTSender
		}(i)
	}
	fmulWait.Wait()

	sender.s1 = myGroup.NewScalar()
	sender.s1.SetUint64(0)

	As := make([]group.Element, n)
	for i := 0; i < n; i++ {
		As[i] = sender.baseOTsenders[i].A.Copy()
	}
	return As

}

// ---- Round1: Sender sends As to receiver ----

// Receiver randomly generates n choice bits, either 0 or 1 for BaseOT, either -1(Scalar) or 1(Scalar) for Fmul
// Matching 0 or 1 to -1(Scalar) or 1(Scalar) in constant time
// Input: myGroup, the group we operate in
// Input: As, the n [ai]G received from sender
// Input: b, the receiver private input
// Input: n, the total number of BaseOT
// Output: Array of B = [b]G if c == 0, B = A+[b]G if c == 1
func (receiver *ReceiverFmul) ReceiverRound1(myGroup group.Group, As []group.Element, b group.Scalar, n int) []group.Element {
	receiver.myGroup = myGroup
	receiver.b = b.Copy()
	receiver.ts = make([]int, n)
	receiver.tsScalar = make([]group.Scalar, n)
	receiver.zs = make([]group.Scalar, n)
	receiver.vs = make([]group.Scalar, n)

	Scalar1 := myGroup.NewScalar()
	Scalar1.SetUint64(1)
	Scalar1.Neg(Scalar1)

	receiver.baseOTreceivers = make([]simplestOT.ReceiverSimOT, n)

	var fmulWait sync.WaitGroup
	fmulWait.Add(n)
	for i := 0; i < n; i++ {
		go func(index int) {
			defer fmulWait.Done()
			currScalar := myGroup.NewScalar()
			binaryBig, err := rand.Int(rand.Reader, big.NewInt(2))
			if err != nil {
				panic(err)
			}
			receiver.ts[index] = int(binaryBig.Int64())
			currScalar.SetUint64(uint64(2 * receiver.ts[index]))
			currScalar.Neg(currScalar)
			receiver.tsScalar[index] = Scalar1.Copy()
			receiver.tsScalar[index].Sub(receiver.tsScalar[index], currScalar)
			receiver.zs[index] = myGroup.NewScalar()
			receiver.baseOTreceivers[index].Round1Receiver(myGroup, receiver.ts[index], index, As[index])
		}(i)
	}
	fmulWait.Wait()

	receiver.s2 = myGroup.NewScalar()
	receiver.s2.SetUint64(0)

	Bs := make([]group.Element, n)
	for i := 0; i < n; i++ {
		Bs[i] = receiver.baseOTreceivers[i].B.Copy()
	}
	return Bs
}

// ---- Round 2: Receiver sends Bs = [bi]G or Ai+[bi]G to sender ----

// Input: Bs, the n [bi]G or Ai+[bi]G received from receiver
// Input: n, the total number of BaseOT
// Output: Array of m0s encryptions and m1s encryptions
func (sender *SenderFmul) SenderRound2(Bs []group.Element, n int) ([][]byte, [][]byte) {
	var fmulWait sync.WaitGroup
	fmulWait.Add(n)
	for i := 0; i < n; i++ {
		go func(index int) {
			defer fmulWait.Done()
			sender.baseOTsenders[index].Round2Sender(Bs[index])
		}(i)
	}
	fmulWait.Wait()

	e0s := make([][]byte, n)
	e1s := make([][]byte, n)
	for i := 0; i < n; i++ {
		e0s[i], e1s[i] = sender.baseOTsenders[i].Returne0e1()
	}

	return e0s, e1s
}

// ---- Round 3: Sender sends e0s, e1s to receiver ----

// Input: e0s, e1s, the encryptions of m0s and m1s
// Input: n, the total number of BaseOT
// Ouptut: Blinding sigma and Array of v
func (receiver *ReceiverFmul) ReceiverRound3(e0s, e1s [][]byte, n int) (group.Scalar, []group.Scalar, error) {
	var errGroup errgroup.Group
	receiver.s2.SetUint64(0)

	for i := 0; i < n; i++ {
		func(index int) {
			errGroup.Go(func() error {
				errDec := receiver.baseOTreceivers[index].Round3Receiver(e0s[index], e1s[index], receiver.ts[index])
				if errDec != nil {
					return errDec
				}
				mc := receiver.baseOTreceivers[index].Returnmc()
				errByte := receiver.zs[index].UnmarshalBinary(mc)
				if errByte != nil {
					panic(errByte)
				}
				return nil
			})
		}(i)
	}

	if err := errGroup.Wait(); err != nil {
		return nil, nil, err
	}

	// v \times t = b
	vn := receiver.b.Copy()
	for i := 0; i < n-1; i++ {
		receiver.vs[i] = receiver.myGroup.RandomNonZeroScalar(rand.Reader)
		vt := receiver.myGroup.NewScalar()
		vt.Mul(receiver.tsScalar[i], receiver.vs[i])
		vn.Sub(vn, vt)
	}
	tsnInv := receiver.myGroup.NewScalar()
	tsnInv.Inv(receiver.tsScalar[n-1])
	vn.Mul(vn, tsnInv)
	receiver.vs[n-1] = vn
	receiver.sigma = receiver.myGroup.RandomNonZeroScalar(rand.Reader)

	for i := 0; i < n; i++ {
		vzi := receiver.myGroup.NewScalar()
		vzi.Mul(receiver.vs[i], receiver.zs[i])
		receiver.s2.Add(receiver.s2, vzi)
	}

	// s2 = v \times z + sigma
	receiver.s2.Add(receiver.s2, receiver.sigma)

	sigma := receiver.sigma.Copy()
	vs := make([]group.Scalar, n)
	for i := 0; i < n; i++ {
		vs[i] = receiver.vs[i].Copy()
	}

	return sigma, vs, nil
}

// ---- Round 4: receiver sends sigma as well as vs to sender ----

// Input: vs, from receiver
// Input: sigma, blinding from receiver
// Input: n, the total number of BaseOT
func (sender *SenderFmul) SenderRound4(vs []group.Scalar, sigma group.Scalar, n int) {
	sender.s1.SetUint64(0)

	vdelta := sender.myGroup.NewScalar()

	// s1 = - v \times delta - sigma
	for i := 0; i < n; i++ {
		vdelta.Mul(vs[i], sender.deltas[i])
		sender.s1.Sub(sender.s1, vdelta)
	}
	sender.s1.Sub(sender.s1, sigma)
}

func (sender *SenderFmul) Returns1() group.Scalar {
	return sender.s1
}

func (receiver *ReceiverFmul) Returns2() group.Scalar {
	return receiver.s2
}
