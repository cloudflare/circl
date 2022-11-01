package dsl

import (
	"fmt"

	"github.com/cloudflare/circl/abe/cpabe/tkn20/internal/tkn"
)

var operators = map[string]int{
	"and": tkn.Andgate,
	"or":  tkn.Orgate,
}

type attrValue struct {
	value    string
	positive bool
}

type attr struct {
	key string
	id  int
}

type gate struct {
	op  string
	in1 attr
	in2 attr
	out attr
}

type Ast struct {
	wires map[attr]attrValue
	gates []gate
}

func (t *Ast) RunPasses() (*tkn.Policy, error) {
	inputs, err := t.hashAttrValues()
	if err != nil {
		return nil, fmt.Errorf("attribute values could not be hashed: %s", err)
	}

	gates, err := t.transformGates()
	if err != nil {
		return nil, fmt.Errorf("gates could not be converted into a formula: %s", err)
	}

	return &tkn.Policy{
		Inputs: inputs,
		F:      tkn.Formula{Gates: gates},
	}, nil
}

func (t *Ast) hashAttrValues() ([]tkn.Wire, error) {
	wires := make([]tkn.Wire, len(t.wires))
	for k, v := range t.wires {
		value := tkn.HashStringToScalar(AttrHashKey, v.value)
		if value == nil {
			return nil, fmt.Errorf("error on hashing")
		}
		wire := tkn.Wire{
			Label:    k.key,
			RawValue: v.value,
			Value:    value,
			Positive: v.positive,
		}
		wires[k.id] = wire
	}
	return wires, nil
}

func (t *Ast) transformGates() ([]tkn.Gate, error) {
	lenGates := len(t.gates)
	gates := make([]tkn.Gate, lenGates)
	for i, g := range t.gates {
		class, ok := operators[g.op]
		if !ok {
			return nil, fmt.Errorf("invalid operator %s", g.op)
		}
		wireIDs := [3]int{g.in1.id, g.in2.id, g.out.id}
		for j, wireID := range wireIDs {
			if wireID < 0 {
				wireIDs[j] = -1*wireID + lenGates
			}
		}
		gate := tkn.Gate{
			Class: class,
			In0:   wireIDs[0],
			In1:   wireIDs[1],
			Out:   wireIDs[2],
		}
		gates[i] = gate
	}
	return gates, nil
}
