package tkn

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Andgate = iota
	Orgate
)

// Gate is a Gate in a monotone boolean formula.
type Gate struct {
	Class int // either Andgate or Orgate
	In0   int // numbering of wires
	In1   int
	Out   int
}

func (g Gate) operator() string {
	switch g.Class {
	case Andgate:
		return "and"
	case Orgate:
		return "or"
	default:
		return "unknown"
	}
}

// Formula represents a monotone boolean circuit with Inputs not
// repeated.  The representation is as follows: for n Gates there n+1
// input wires, 1 output Wire, and n-1 intermediate wires.  That's
// because there are 2n Inputs to all Gates and n outputs since every
// Gate is 2:1.
//
// The wires are conceptually in an array. Wires 0 through n are
// the input wires, and Wire 2n is the output Wire. If there are wires
// between n and 2n they are intermediate wires.
//
// All intermediate and input wires must be used exactly once as Inputs.
type Formula struct {
	Gates []Gate
}

func (g Gate) Equal(g2 Gate) bool {
	if (g.Class != g2.Class) || (g.Out != g2.Out) {
		return false
	}
	if g.In0 == g2.In0 && g.In1 == g2.In1 {
		return true
	}
	if g.In0 == g2.In1 && g.In1 == g2.In0 {
		return true
	}
	return false
}

func (f *Formula) MarshalBinary() ([]byte, error) {
	n := len(f.Gates)
	ret := make([]byte, 2+7*n)
	binary.LittleEndian.PutUint16(ret, uint16(len(f.Gates)))
	for i := 0; i < n; i++ {
		ret[7*i+2] = byte(f.Gates[i].Class)
		binary.LittleEndian.PutUint16(ret[7*i+2+1:], uint16(f.Gates[i].In0))
		binary.LittleEndian.PutUint16(ret[7*i+2+3:], uint16(f.Gates[i].In1))
		binary.LittleEndian.PutUint16(ret[7*i+2+5:], uint16(f.Gates[i].Out))
	}
	return ret, nil
}

func (f *Formula) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("too short data")
	}
	n := int(binary.LittleEndian.Uint16(data[0:2]))
	f.Gates = make([]Gate, n)
	for i := 0; i < n; i++ {
		f.Gates[i].Class = int(data[7*i+2])
		f.Gates[i].In0 = int(binary.LittleEndian.Uint16(data[7*i+2+1:]))
		f.Gates[i].In1 = int(binary.LittleEndian.Uint16(data[7*i+2+3:]))
		f.Gates[i].Out = int(binary.LittleEndian.Uint16(data[7*i+2+5:]))
	}
	return nil
}

func (f *Formula) wellformed() error {
	// Check every Wire used once
	n := len(f.Gates)
	inputs := make([]bool, 2*n) // n+1 already, n-1 intermediates
	outputs := make([]bool, n)
	for i, gate := range f.Gates {
		if gate.In0 > 2*n-1 || gate.In0 < 0 {
			return fmt.Errorf("Gate %d has an Out of range In0", i)
		}
		if inputs[gate.In0] {
			return fmt.Errorf("Gate %d has In0 that is already used", i)
		}
		inputs[gate.In0] = true
		if gate.In1 > 2*n-1 || gate.In1 < 0 {
			return fmt.Errorf("Gate %d has an Out of range In1", i)
		}
		if inputs[gate.In1] {
			return fmt.Errorf("Gate %d has In1 that is already used", i)
		}
		inputs[gate.In1] = true
		if gate.Out > 2*n || gate.Out < n+1 {
			return fmt.Errorf("Gate %d has an Out of range Out", i)
		}
		outputs[gate.Out-(n+1)] = true
	}
	for i, wire := range inputs {
		if !wire {
			return fmt.Errorf("unused input Wire %d", i)
		}
	}
	for i, wire := range outputs {
		if !wire {
			return fmt.Errorf("unused output Wire %d", i+(n+1))
		}
	}
	return nil
}

// Sort the Gates so that Inputs are set before outputs.
func (f *Formula) toposort() error {
	err := f.wellformed()
	if err != nil {
		return err
	}
	n := len(f.Gates)
	if n == 0 {
		return nil
	}
	// Intermediate wires are indexed after subtracting n+1
	outputGate := make([]int, n) // the Gate that sets this Wire
	inputGate := make([]int, n)  // the Gate that uses this intermediate Wire.
	counts := make([]int, n)     // the number of Inputs no yet output
	queue := make([]int, 0, n)
	reordered := make([]Gate, 0, n)
	inputGate[n-1] = -1 // No Gate uses the output as input

	for i, gate := range f.Gates {
		outputGate[gate.Out-(n+1)] = i
		if gate.In0 > n {
			inputGate[gate.In0-(n+1)] = i
			counts[i]++
		}
		if gate.In1 > n {
			inputGate[gate.In1-(n+1)] = i
			counts[i]++
		}
	}
	for i := 0; i < n; i++ {
		if counts[i] == 0 {
			queue = append(queue, i)
		}
	}
	if len(queue) == 0 {
		return fmt.Errorf("no starting gates")
	}
	for len(queue) > 0 {
		reordered = append(reordered, f.Gates[queue[0]])
		next := inputGate[f.Gates[queue[0]].Out-(n+1)]
		if next >= 0 {
			counts[next]--
			if counts[next] == 0 {
				queue = append(queue, next)
			}
		}
		queue = queue[1:]
	}
	if len(reordered) != n {
		return fmt.Errorf("not all gates were extracted. check for loops")
	}

	f.Gates = reordered
	return nil
}

// Given a set of possible Inputs (not necessarily in order!)
// return a subset that satisfy the formula with no extras.
func (f *Formula) satisfaction(available []match) ([]match, error) {
	err := f.toposort()
	if err != nil {
		return nil, err
	}
	n := len(f.Gates)
	assignments := make([][]int, 2*n+1)
	for _, match := range available {
		assignments[match.wire] = []int{match.wire}
	}
	for _, gate := range f.Gates {
		switch gate.Class {
		case Andgate:
			if assignments[gate.In0] == nil || assignments[gate.In1] == nil {
				assignments[gate.Out] = nil
			} else {
				assignments[gate.Out] = make([]int, 0, len(assignments[gate.In0])+len(assignments[gate.In1]))
				assignments[gate.Out] = append(assignments[gate.Out], assignments[gate.In0]...)
				assignments[gate.Out] = append(assignments[gate.Out], assignments[gate.In1]...)
			}
		case Orgate:
			if assignments[gate.In0] == nil && assignments[gate.In1] == nil {
				assignments[gate.Out] = nil
			} else {
				assignments[gate.Out] = assignments[gate.In0]
				if assignments[gate.Out] == nil {
					assignments[gate.Out] = assignments[gate.In1]
				}
				if (len(assignments[gate.In1]) < len(assignments[gate.Out])) && assignments[gate.In1] != nil {
					assignments[gate.Out] = assignments[gate.In1]
				}
			}
		default:
			return nil, fmt.Errorf("unmatched case")
		}
	}
	if assignments[2*n] == nil {
		return nil, fmt.Errorf("no satisfying assignment")
	}
	ret := make([]match, 0)
	for _, wire := range assignments[2*n] {
		for _, match := range available {
			if match.wire == wire {
				ret = append(ret, match)
			}
		}
	}
	return ret, nil
}

// share distributes an input into shares for a secret sharing system
// for the formula: the original vector can be recovered from shares
// that satisfy the formula, by adding them all up.
func (f *Formula) share(rand io.Reader, k *matrixZp) ([]*matrixZp, error) {
	err := f.toposort()
	if err != nil {
		return nil, err
	}
	n := len(f.Gates)
	shares := make([]*matrixZp, 2*n+1)
	// Reverse order: we want to set the share of the output ahead of the Inputs
	shares[2*n] = k
	for i := len(f.Gates) - 1; i >= 0; i-- {
		gate := f.Gates[i]
		switch gate.Class {
		case Andgate:
			shares[gate.In0], err = randomMatrixZp(rand, k.rows, k.cols)
			if err != nil {
				return nil, err
			}
			shares[gate.In1] = newMatrixZp(k.rows, k.cols)
			shares[gate.In0].sub(shares[gate.Out], shares[gate.In1])

		case Orgate:
			shares[gate.In0] = newMatrixZp(k.rows, k.cols)
			shares[gate.In0].set(shares[gate.Out])
			shares[gate.In1] = newMatrixZp(k.rows, k.cols)
			shares[gate.In1].set(shares[gate.Out])
		}
	}
	return shares[0 : n+1], nil
}

// insertAnd adds and Gate for a new input
func (f *Formula) insertAnd() Formula {
	// Let n=3
	// The old Inputs are 0, 1, 2, 3.
	// Old intermediates 4, 5,
	// Old output 6.
	// The old Inputs are Inputs 0,1,2,3 and new input 4
	// Intermediates are all shifted up by 1: 5, 6
	// Old output is also shifted up but is the intermediate 7
	// New output 8.
	n := len(f.Gates)
	gates := make([]Gate, len(f.Gates)+1)
	newInput := func(in int) int {
		if in > n {
			return in + 1
		} else {
			return in
		}
	}

	for i := 0; i < n; i++ {
		gates[i].Class = f.Gates[i].Class
		gates[i].In0 = newInput(f.Gates[i].In0)
		gates[i].In1 = newInput(f.Gates[i].In1)
		gates[i].Out = f.Gates[i].Out + 1
	}
	gates[n].Class = Andgate
	// if there were zero gates, then In0 = 0, In1 = 1, Out = 2
	if n == 0 {
		gates[n].In0 = n
	} else {
		gates[n].In0 = n + 1
	}
	gates[n].In1 = 2*n + 1
	gates[n].Out = 2*n + 2
	return Formula{
		Gates: gates,
	}
}

func (f *Formula) Equal(g Formula) bool {
	if len(f.Gates) != len(g.Gates) {
		return false
	}
	for i := 0; i < len(f.Gates); i++ {
		if !f.Gates[i].Equal(g.Gates[i]) {
			return false
		}
	}
	return true
}
