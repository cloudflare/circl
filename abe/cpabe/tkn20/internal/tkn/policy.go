package tkn

import (
	"fmt"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/cryptobyte"
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
	aBytes, err := marshalBinarySortedMapAttribute(*a)
	if err != nil {
		return nil, fmt.Errorf("marshalling Attributes failed: %w", err)
	}
	b := cryptobyte.NewBuilder(nil)
	if err = leUint16(len(*a)).Marshal(b); err != nil {
		return nil, fmt.Errorf("too many attributes")
	}
	b.AddBytes(aBytes)
	return b.Bytes()
}

func (a *Attributes) unmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)
	n16, ok := readLEUint16(&s)
	if !ok {
		return fmt.Errorf("unmarshalling Attributes failed: data too short")
	}
	n := int(n16)
	data = s
	*a = make(map[string]Attribute, n)
	for range n {
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
	b := cryptobyte.NewBuilder(nil)
	b.AddValue(lenPrefixed16(strBytes))
	b.AddValue(lenPrefixed16(valBytes))
	b.AddValue(lenPrefixed16(intBytes))
	if w.Positive {
		b.AddUint8(1)
	} else {
		b.AddUint8(0)
	}
	return b.Bytes()
}

func (w *Wire) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)

	strLen, ok := readLEUint16(&s)
	var strBytes []byte
	if !ok || !s.ReadBytes(&strBytes, int(strLen)) {
		return fmt.Errorf("data not long enough")
	}
	w.Label = string(strBytes)

	valLen, ok := readLEUint16(&s)
	var valBytes []byte
	if !ok || !s.ReadBytes(&valBytes, int(valLen)) {
		return fmt.Errorf("data not long enough")
	}
	w.RawValue = string(valBytes)

	intLen, ok := readLEUint16(&s)
	var intBytes []byte
	if !ok || !s.ReadBytes(&intBytes, int(intLen)) {
		return fmt.Errorf("data not long enough")
	}
	w.Value = &pairing.Scalar{}
	w.Value.SetBytes(intBytes)

	var positive uint8
	if !s.ReadUint8(&positive) {
		return fmt.Errorf("data not long enough")
	}
	w.Positive = positive == 1
	return nil
}

func (w *Wire) Equal(w2 *Wire) bool {
	return w.Label == w2.Label && w.RawValue == w2.RawValue && w.Positive == w2.Positive && w.Value.IsEqual(w2.Value) == 1
}

func (p *Policy) MarshalBinary() ([]byte, error) {
	fBytes, err := p.F.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddValue(lenPrefixed16(fBytes))
	if err = leUint16(len(p.Inputs)).Marshal(b); err != nil {
		return nil, fmt.Errorf("too many wires")
	}
	for i := 0; i < len(p.Inputs); i++ {
		input, err := p.Inputs[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		b.AddValue(lenPrefixed16(input))
	}
	return b.Bytes()
}

func (p *Policy) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)

	// Extract formula
	fLen, ok := readLEUint16(&s)
	var fBytes []byte
	if !ok || !s.ReadBytes(&fBytes, int(fLen)) {
		return fmt.Errorf("data not long enough")
	}
	if err := p.F.UnmarshalBinary(fBytes); err != nil {
		return err
	}

	// Extract wires
	nWires16, ok := readLEUint16(&s)
	if !ok {
		return fmt.Errorf("data not long enough")
	}
	nWires := int(nWires16)
	if nWires != len(p.F.Gates)+1 {
		return fmt.Errorf("invalid policy: %d wires declared, but a formula with %d gates requires exactly %d input wires", nWires, len(p.F.Gates), len(p.F.Gates)+1)
	}
	p.Inputs = make([]Wire, nWires)
	for i := range nWires {
		wireLen, ok := readLEUint16(&s)
		var wireBytes []byte
		if !ok || !s.ReadBytes(&wireBytes, int(wireLen)) {
			return fmt.Errorf("data not long enough")
		}
		if err := p.Inputs[i].UnmarshalBinary(wireBytes); err != nil {
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
