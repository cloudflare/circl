package tkn

import (
	"testing"
)

var AttrHashKey = []byte("attribute value hashing")

func TestWireSerialization(t *testing.T) {
	in := &Wire{"a", "0", HashStringToScalar(AttrHashKey, "0"), true}
	data, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("error in marshaling: %s", err)
	}
	out := &Wire{}
	err = out.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("error in unmarshaling: %s", err)
	}
	if !in.Equal(out) {
		t.Fatalf("failure to round trip")
	}
}

func TestPolicySerialization(t *testing.T) {
	in := Policy{
		Inputs: []Wire{
			{"a", "1", HashStringToScalar(AttrHashKey, "1"), true},
			{"b", "xx", HashStringToScalar(AttrHashKey, "xx"), true},
			{"c", "3", HashStringToScalar(AttrHashKey, "3"), true},
		},
		F: Formula{
			Gates: []Gate{
				{Andgate, 0, 1, 3},
				{Andgate, 2, 3, 4},
			},
		},
	}
	data, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("error in marshalling: %s", err)
	}
	out := Policy{}
	err = out.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("error in unmarshaling: %s", err)
	}
	if !in.F.Equal(out.F) {
		t.Fatalf("formulas do not match")
	}
	for i, input := range in.Inputs {
		if !input.Equal(&out.Inputs[i]) {
			t.Fatal("failure to round trip: inputs do not match")
		}
	}
}

type TestCase struct {
	p *Policy
	a *Attributes
}

func TestSatisfaction(t *testing.T) {
	testCases := []TestCase{
		{
			&Policy{
				Inputs: []Wire{
					{"a", "0", ToScalar(0), true},
				},
				F: Formula{
					Gates: []Gate{},
				},
			},
			&Attributes{
				"a": {
					wild:  false,
					Value: ToScalar(0),
				},
			},
		},
		{
			&Policy{
				Inputs: []Wire{
					{"a", "1", ToScalar(1), true},
					{"b", "2", ToScalar(2), true},
					{"c", "3", ToScalar(3), true},
				},
				F: Formula{
					Gates: []Gate{
						{Andgate, 0, 1, 3},
						{Andgate, 2, 3, 4},
					},
				},
			},
			&Attributes{
				"d": {
					wild:  false,
					Value: ToScalar(4),
				},
				"c": {
					wild:  false,
					Value: ToScalar(3),
				},
				"b": {
					wild:  false,
					Value: ToScalar(2),
				},
				"a": {
					wild:  false,
					Value: ToScalar(1),
				},
			},
		},
		{
			&Policy{
				Inputs: []Wire{
					{"a", "1", ToScalar(1), false},
					{"b", "2", ToScalar(2), true},
					{"c", "3", ToScalar(3), true},
				},
				F: Formula{
					Gates: []Gate{
						{Andgate, 0, 1, 3},
						{Andgate, 2, 3, 4},
					},
				},
			},
			&Attributes{
				"d": {
					wild:  false,
					Value: ToScalar(4),
				},
				"c": {
					wild:  false,
					Value: ToScalar(3),
				},
				"b": {
					wild:  false,
					Value: ToScalar(2),
				},
				"a": {
					wild:  false,
					Value: ToScalar(2),
				},
			},
		},
	}

	for _, args := range testCases {
		sat, err := args.p.Satisfaction(args.a)
		if err != nil {
			t.Fatalf("no satisfaction found for valid program: %s", err)
		}
		for i := 0; i < len(sat.matches); i++ {
			match := sat.matches[i]
			if args.p.Inputs[match.wire].Positive {
				if args.p.Inputs[match.wire].Value.IsEqual((*args.a)[match.label].Value) == 0 || match.label != args.p.Inputs[match.wire].Label {
					t.Errorf("mismatch of Attribute name or Value")
				}
			} else {
				if match.label != args.p.Inputs[match.wire].Label {
					t.Errorf("mismatch of Attribute name")
				}
			}
		}
	}
}

func TestMarshalAttribute(t *testing.T) {
	in := Attribute{true, ToScalar(1)}
	data, err := in.marshalBinary()
	if err != nil {
		t.Fatalf("error in marshaling: %s", err)
	}
	out := Attribute{}
	err = out.unmarshalBinary(data)
	if err != nil {
		t.Fatalf("error in unmarshaling: %s", err)
	}
	if !in.Equal(&out) {
		t.Fatal("failure to roundtrip")
	}
}

func TestMarshalAttributes(t *testing.T) {
	in := Attributes{
		"cat": {
			wild:  true,
			Value: ToScalar(0),
		},
		"bree": {
			wild:  false,
			Value: ToScalar(2),
		},
		"a": {
			wild:  true,
			Value: ToScalar(2),
		},
	}
	data, err := in.marshalBinary()
	if err != nil {
		t.Fatalf("error in marshaling: %s", err)
	}

	// check if deserializing into non-empty struct works
	out := &Attributes{
		"evil": {
			wild:  true,
			Value: ToScalar(0),
		},
		"bree": {
			wild:  false,
			Value: ToScalar(2),
		},
		"a": {
			wild:  true,
			Value: ToScalar(2),
		},
	}
	if in.Equal(out) {
		t.Fatalf("shouldn't be equal")
	}
	err = out.unmarshalBinary(data)
	if err != nil {
		t.Fatalf("error in unmarshaling: %s", err)
	}
	if !in.Equal(out) {
		t.Fatal("failure to roundtrip")
	}

	err = out.unmarshalBinary(append(data, 0))
	if err == nil {
		t.Fatalf("data has excess bytes, deserialization should fail")
	}
}
