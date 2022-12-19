package tkn

import (
	"encoding/binary"
	"fmt"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
)

const (
	bkAttribute   = "internal-boneh-katz-transform-attribute"
	attributeSize = pairing.ScalarSize + 1
)

type Wire struct {
	Label    string
	RawValue string
	Value    *pairing.Scalar
	Positive bool
}

func (w *Wire) String() string {
	if w.Positive {
		return fmt.Sprintf("%s:%s", w.Label, w.RawValue)
	}
	return fmt.Sprintf("not %s:%s", w.Label, w.RawValue)
}

type Policy struct {
	Inputs []Wire
	F      Formula // monotonic boolean formula
}

type Attribute struct {
	wild  bool // false if tame
	Value *pairing.Scalar
}

func (a *Attribute) marshalBinary() ([]byte, error) {
	ret := make([]byte, 1)
	if a.wild {
		ret[0] = 1
	}
	aBytes, err := a.Value.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(ret, aBytes...), nil
}

func (a *Attribute) unmarshalBinary(data []byte) error {
	if len(data) != attributeSize {
		return fmt.Errorf("unmarshalling Attribute failed: invalid input length, expected: %d, received: %d",
			attributeSize,
			len(data))
	}
	a.wild = false
	if data[0] == 1 {
		a.wild = true
	}
	a.Value = &pairing.Scalar{}
	err := a.Value.UnmarshalBinary(data[1:])
	if err != nil {
		return fmt.Errorf("unmarshalling Attribute failed: %w", err)
	}
	return nil
}

func (a *Attribute) Equal(b *Attribute) bool {
	return a.wild == b.wild && a.Value.IsEqual(b.Value) == 1
}

type Attributes map[string]Attribute

func (a *Attributes) marshalBinary() ([]byte, error) {
	ret := make([]byte, 2)
	binary.LittleEndian.PutUint16(ret[0:], uint16(len(*a)))

	aBytes, err := marshalBinarySortedMapAttribute(*a)
	if err != nil {
		return nil, fmt.Errorf("marshalling Attributes failed: %w", err)
	}
	ret = append(ret, aBytes...)

	return ret, nil
}

func (a *Attributes) unmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("unmarshalling Attributes failed: data too short")
	}
	n := int(binary.LittleEndian.Uint16(data))
	data = data[2:]
	*a = make(map[string]Attribute, n)
	for i := 0; i < n; i++ {
		labelBytes, rem, err := removeLenPrefixed(data)
		if err != nil {
			return fmt.Errorf("unmarshalling Attributes failed: %w", err)
		}
		if len(rem) < attributeSize {
			return fmt.Errorf("unmarshalling Attributes failed: data too short")
		}
		attr := Attribute{}
		err = attr.unmarshalBinary(rem[:attributeSize])
		if err != nil {
			return fmt.Errorf("unmarshalling Attributes failed: %w", err)
		}
		(*a)[string(labelBytes)] = attr
		data = rem[attributeSize:]
	}
	if len(data) != 0 {
		return fmt.Errorf("unmarshalling Attributes failed: excess bytes remain in data")
	}
	return nil
}

func (a *Attributes) Equal(b *Attributes) bool {
	if len(*a) != len(*b) {
		return false
	}
	for k := range *a {
		v := (*a)[k]
		if v2, ok := (*b)[k]; !(ok && v2.Equal(&v)) {
			return false
		}
	}
	return true
}

func (w *Wire) MarshalBinary() ([]byte, error) {
	strBytes := []byte(w.Label)
	valBytes := []byte(w.RawValue)
	intBytes, err := w.Value.MarshalBinary()
	if err != nil {
		return nil, err
	}
	totalLen := len(strBytes) + len(valBytes) + len(intBytes) + 2 + 2 + 2 + 1
	ret := make([]byte, totalLen)
	where := 0
	binary.LittleEndian.PutUint16(ret[where:], uint16(len(strBytes)))
	where += 2
	where += copy(ret[where:], strBytes)
	binary.LittleEndian.PutUint16(ret[where:], uint16(len(valBytes)))
	where += 2
	where += copy(ret[where:], valBytes)
	binary.LittleEndian.PutUint16(ret[where:], uint16(len(intBytes)))
	where += 2
	where += copy(ret[where:], intBytes)
	if w.Positive {
		ret[where] = 1
	} else {
		ret[where] = 0
	}
	return ret, nil
}

func (w *Wire) UnmarshalBinary(data []byte) error {
	where := 0
	if len(data) < 2 {
		return fmt.Errorf("data not long enough")
	}
	strLen := int(binary.LittleEndian.Uint16(data[where:]))
	where += 2
	if len(data[where:]) < strLen {
		return fmt.Errorf("data not long enough")
	}
	w.Label = string(data[where : where+strLen])
	where += strLen

	if len(data[where:]) < 2 {
		return fmt.Errorf("data not long enough")
	}
	valLen := int(binary.LittleEndian.Uint16(data[where:]))
	where += 2
	if len(data[where:]) < valLen {
		return fmt.Errorf("data not long enough")
	}
	w.RawValue = string(data[where : where+valLen])
	where += valLen

	if len(data[where:]) < 2 {
		return fmt.Errorf("data not long enough")
	}
	intLen := int(binary.LittleEndian.Uint16(data[where:]))
	where += 2
	if len(data[where:]) < intLen {
		return fmt.Errorf("data not long enough")
	}
	w.Value = &pairing.Scalar{}
	w.Value.SetBytes(data[where : where+intLen])
	where += intLen
	if len(data[where:]) < 1 {
		return fmt.Errorf("data not long enough")
	}
	if data[where] == 1 {
		w.Positive = true
	} else {
		w.Positive = false
	}
	return nil
}

func (w *Wire) Equal(w2 *Wire) bool {
	return w.Label == w2.Label && w.RawValue == w2.RawValue && w.Positive == w2.Positive && w.Value.IsEqual(w2.Value) == 1
}

func (p *Policy) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 2)
	fBytes, err := p.F.MarshalBinary()
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint16(ret[0:2], uint16(len(fBytes)))
	ret = append(ret, fBytes...)
	ret = append(ret, 0, 0)
	binary.LittleEndian.PutUint16(ret[len(ret)-2:], uint16(len(p.Inputs)))
	for i := 0; i < len(p.Inputs); i++ {
		input, err := p.Inputs[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		ret = append(ret, 0, 0)
		binary.LittleEndian.PutUint16(ret[len(ret)-2:], uint16(len(input)))
		ret = append(ret, input...)
	}
	return ret, nil
}

func (p *Policy) UnmarshalBinary(data []byte) error {
	// Extract formula
	if len(data) < 2 {
		return fmt.Errorf("data not long enough")
	}
	fLen := uint(binary.LittleEndian.Uint16(data))
	data = data[2:]
	err := p.F.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	data = data[fLen:]
	// Extract wires
	if len(data) < 2 {
		return fmt.Errorf("data not long enough")
	}
	nWires := int(binary.LittleEndian.Uint16(data))
	data = data[2:]
	p.Inputs = make([]Wire, nWires)
	for i := 0; i < nWires; i++ {
		wireLen := uint(binary.LittleEndian.Uint16(data))
		data = data[2:]
		err = p.Inputs[i].UnmarshalBinary(data)
		data = data[wireLen:]
		if err != nil {
			return fmt.Errorf("data not long enough")
		}
	}
	return nil
}

func (p *Policy) Equal(p2 *Policy) bool {
	if len(p.Inputs) != len(p2.Inputs) {
		return false
	}
	if !p.F.Equal(p2.F) {
		return false
	}
	for i := range p.Inputs {
		if !p.Inputs[i].Equal(&p2.Inputs[i]) {
			return false
		}
	}
	return true
}

func (p *Policy) String() string {
	// gateAssign takes n wires (intermediates and outputs) and maps to the gate
	// that set them. For details, refer to [Formula].
	offset := len(p.F.Gates) + 1
	gateAssign := make([]int, len(p.F.Gates))
	for i, gate := range p.F.Gates {
		gateAssign[gate.Out-offset] = i
	}
	return p.printWire(gateAssign, 2*len(p.F.Gates))
}

func (p *Policy) printWire(gateAssign []int, wire int) string {
	n := len(p.F.Gates)
	if wire < n+1 {
		return p.Inputs[wire].String()
	}
	gate := p.F.Gates[gateAssign[wire-n-1]]
	return fmt.Sprintf("(%s %s %s)", p.printWire(gateAssign, gate.In0), gate.operator(), p.printWire(gateAssign, gate.In1))
}

type match struct {
	wire  int
	label string
}

type Satisfaction struct {
	matches []match
}

func (p *Policy) pi() []int {
	ret := make([]int, len(p.Inputs))
	counts := make(map[string]int)
	for i := 0; i < len(p.Inputs); i++ {
		// Paper would have us put a +1 here
		// we change the indexing instead
		ret[i] = counts[p.Inputs[i].Label]
		counts[p.Inputs[i].Label]++
	}
	return ret
}

func (p *Policy) Satisfaction(attr *Attributes) (*Satisfaction, error) {
	// For now its all of the wires, so we don't need to look at the formula.
	var matches []match
	for i := 0; i < len(p.Inputs); i++ {
		wire := p.Inputs[i]
		at, ok := (*attr)[wire.Label]
		if !ok {
			continue // missing Attribute might not be needed
		}
		if wire.Positive {
			if (wire.Value.IsEqual(at.Value) == 1) || at.wild {
				matches = append(matches, match{i, wire.Label})
			}
		} else {
			if (wire.Value.IsEqual(at.Value) == 0) || at.wild {
				matches = append(matches, match{i, wire.Label})
			}
		}
	}
	matches, err := p.F.satisfaction(matches)
	if err != nil {
		return nil, err
	}

	return &Satisfaction{
		matches,
	}, nil
}

// Carry Out the augmentation under the BK transform
func (p *Policy) transformBK(val *pairing.Scalar) *Policy {
	ret := new(Policy)
	for i := 0; i < len(p.Inputs); i++ {
		ret.Inputs = append(ret.Inputs, p.Inputs[i])
	}
	ret.Inputs = append(ret.Inputs, Wire{
		Label:    bkAttribute,
		Value:    val,
		Positive: true,
	})
	ret.F = p.F.insertAnd()
	return ret
}

func transformAttrsBK(attr *Attributes) *Attributes {
	ret := make(map[string]Attribute)
	for name, val := range *attr {
		ret[name] = val
	}
	ret[bkAttribute] = Attribute{
		wild:  true,
		Value: &pairing.Scalar{},
	}
	return (*Attributes)(&ret)
}
