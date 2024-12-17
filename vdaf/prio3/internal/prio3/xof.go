package prio3

import (
	"encoding/binary"
	"math"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/vdaf/prio3/arith"
)

// xofTS allows to derive seeds and vector of elements from TurboSHAKE.
type xofTS[V arith.Vec[V, E], E arith.Elt] struct {
	usage  *[2]byte
	Header []byte
	sha3.State
}

// NewXof returns an xofTS from an ID and context.
func NewXof[V arith.Vec[V, E], E arith.Elt](
	id uint32, context []byte,
) (x xofTS[V, E], err error) {
	const (
		Version              = 12
		AlgoClass            = 0
		TurboShake128DS      = 1
		dstPrefixLen    uint = 8
		maxContextSize  uint = math.MaxUint16 - dstPrefixLen
	)

	if len(context) > int(maxContextSize) {
		return x, ErrContextSize
	}

	lenDST := dstPrefixLen + uint(len(context))
	usagePos := dstPrefixLen
	headerLen := 2 + lenDST + 1
	x.Header = make([]byte, 0, headerLen)
	// | 2 | uint16(len(dst)) | little-endian |
	// | 1 | Version          |
	// | 1 | AlgoClass        |
	// | 4 | ID               | big-endian    |
	// | 2 | Usage            | big-endian    |
	// | * | context          |
	// | 1 | SeedSize         |
	x.Header = binary.LittleEndian.AppendUint16(x.Header, uint16(lenDST))
	x.Header = append(x.Header, Version)
	x.Header = append(x.Header, AlgoClass)
	x.Header = binary.BigEndian.AppendUint32(x.Header, id)
	x.Header = binary.BigEndian.AppendUint16(x.Header, 0)
	x.Header = append(x.Header, context...)
	x.Header = append(x.Header, uint8(SeedSize))
	x.usage = (*[2]byte)(x.Header[usagePos : usagePos+2])
	x.State = sha3.NewTurboShake128(TurboShake128DS)
	return x, nil
}

func (x *xofTS[V, E]) Init(usage uint16, s *Seed) error {
	binary.BigEndian.PutUint16(x.usage[:], usage)
	x.Reset()
	_, err := x.Write(x.Header)
	if err != nil {
		return err
	}

	_, err = x.Write(s[:])
	if err != nil {
		return err
	}

	return nil
}

func (x *xofTS[V, E]) SetBinderByte(binder ...byte) error {
	_, err := x.Write(binder)
	return err
}

func (x *xofTS[V, E]) SetBinderBytes(binder ...[]byte) error {
	for i := range binder {
		_, err := x.Write(binder[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func (x *xofTS[V, E]) helperMeasShareEnc(
	encOut []byte, out V, aggID uint8, s *Seed,
) error {
	err := x.Init(usageMeasuShare, s)
	if err != nil {
		return err
	}

	err = x.SetBinderByte(aggID)
	if err != nil {
		return err
	}

	return out.RandomSHA3Bytes(encOut, &x.State)
}

func (x *xofTS[V, E]) helperMeasShare(out V, aggID uint8, s *Seed) error {
	err := x.Init(usageMeasuShare, s)
	if err != nil {
		return err
	}

	err = x.SetBinderByte(aggID)
	if err != nil {
		return err
	}

	return out.RandomSHA3(&x.State)
}

func (x *xofTS[V, E]) helperProofsShare(out V, aggID uint8, s *Seed) error {
	err := x.Init(usageProofShare, s)
	if err != nil {
		return err
	}

	err = x.SetBinderByte(numProofs, aggID)
	if err != nil {
		return err
	}

	return out.RandomSHA3(&x.State)
}

func (x *xofTS[V, E]) proveRands(out V, proveSeed *Seed) error {
	err := x.Init(usageProveRandomness, proveSeed)
	if err != nil {
		return err
	}

	err = x.SetBinderByte(numProofs)
	if err != nil {
		return err
	}

	return out.RandomSHA3(&x.State)
}

func (x *xofTS[V, E]) queryRands(out V, k *VerifyKey, nonce *Nonce) error {
	err := x.Init(usageQueryRandomness, (*Seed)(k))
	if err != nil {
		return err
	}

	err = x.SetBinderBytes([]byte{numProofs}, nonce[:])
	if err != nil {
		return err
	}

	return out.RandomSHA3(&x.State)
}

func (x *xofTS[V, E]) jointRandPart(
	out []byte, blind *Seed, aggID uint8, nonce *Nonce, measShareEnc []byte,
) error {
	err := x.Init(usageJointRandPart, blind)
	if err != nil {
		return err
	}

	err = x.SetBinderBytes([]byte{aggID}, nonce[:], measShareEnc)
	if err != nil {
		return err
	}

	_, err = x.Read(out)
	return err
}

func (x *xofTS[V, E]) jointRandSeed(jointRandParts []byte) (s Seed, err error) {
	var zeros Seed
	err = x.Init(usageJointRandSeed, &zeros)
	if err != nil {
		return s, err
	}

	err = x.SetBinderBytes(jointRandParts)
	if err != nil {
		return s, err
	}

	_, err = x.Read(s[:])
	return
}

func (x *xofTS[V, E]) jointRands(out V, jointRandSeed *Seed) error {
	err := x.Init(usageJointRandomness, jointRandSeed)
	if err != nil {
		return err
	}

	err = x.SetBinderByte(numProofs)
	if err != nil {
		return err
	}

	return out.RandomSHA3(&x.State)
}

const (
	usageMeasuShare uint16 = iota + 1
	usageProofShare
	usageJointRandomness
	usageProveRandomness
	usageQueryRandomness
	usageJointRandSeed
	usageJointRandPart
)
