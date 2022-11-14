package tkn

import (
	"testing"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
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
			{"c", "*", &pairing.Scalar{}, true},
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
				"a": {false, ToScalar(0)},
			},
		},
		{
			&Policy{
				Inputs: []Wire{
					{"a", "*", &pairing.Scalar{}, true},
					{"b", "*", &pairing.Scalar{}, false},
					{"c", "*", &pairing.Scalar{}, false},
				},
				F: Formula{
					Gates: []Gate{
						{Andgate, 0, 1, 3},
						{Andgate, 2, 3, 4},
					},
				},
			},
			&Attributes{
				"a": {true, ToScalar(1)},
				"b": {true, ToScalar(2)},
				"c": {false, ToScalar(3)},
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
				"d": {false, ToScalar(4)},
				"c": {false, ToScalar(3)},
				"b": {false, ToScalar(2)},
				"a": {false, ToScalar(1)},
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
				"d": {false, ToScalar(4)},
				"c": {false, ToScalar(3)},
				"b": {false, ToScalar(2)},
				"a": {false, ToScalar(2)},
			},
		},
	}

	for _, test := range testCases {
		sat, err := test.p.Satisfaction(test.a)
		if err != nil {
			t.Fatalf("no satisfaction found for valid program: %s", err)
		}
		for i := 0; i < len(sat.matches); i++ {
			match := sat.matches[i]
			if test.p.Inputs[match.wire].Positive {
				if (test.p.Inputs[match.wire].Value.IsEqual((*test.a)[match.label].Value) == 0 && !(*test.a)[match.label].Wild) || match.label != test.p.Inputs[match.wire].Label {
					t.Errorf("mismatch of Attribute name or Value")
				}
			} else {
				if match.label != test.p.Inputs[match.wire].Label {
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
			Wild:  true,
			Value: ToScalar(0),
		},
		"bree": {
			Wild:  false,
			Value: ToScalar(2),
		},
		"a": {
			Wild:  true,
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
			Wild:  true,
			Value: ToScalar(0),
		},
		"bree": {
			Wild:  false,
			Value: ToScalar(2),
		},
		"a": {
			Wild:  true,
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
