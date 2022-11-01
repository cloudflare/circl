package dsl_test

import (
	"errors"
	"testing"

	"github.com/cloudflare/circl/abe/cpabe/tkn20/internal/dsl"
	"github.com/cloudflare/circl/abe/cpabe/tkn20/internal/tkn"
)

var testCases = []struct {
	input  string
	output *tkn.Policy
	err    error
}{
	{
		input: "",
		err:   errors.New("expected parentheses or literal"),
	},
	{
		input: "&",
		err:   errors.New("unexpected character(s): '&'"),
	},
	{
		input: "country: north korea",
		err:   errors.New("unexpected token korea, expected logical operator \"and\" or \"or\""),
	},
	{
		input: "(country: congo",
		err:   errors.New("expected ')' after expression"),
	},
	{
		input: "(country: china or taiwan)",
		err:   errors.New("expected parentheses or literal"),
	},
	{
		input: "not (planet: arakis",
		err:   errors.New("expected ')' after expression"),
	},
	{
		input: "ocean: indian and ship: rms titanic",
		err:   errors.New("unexpected token titanic, expected logical operator \"and\" or \"or\""),
	},
	{
		input: "not (spice: saffron and region: persia)",
		output: &tkn.Policy{
			Inputs: []tkn.Wire{
				{Label: "spice", RawValue: "saffron", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "saffron"), Positive: false},
				{Label: "region", RawValue: "persia", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "persia"), Positive: false},
			},
			F: tkn.Formula{
				Gates: []tkn.Gate{
					{Class: tkn.Orgate, In0: 0, In1: 1, Out: 2},
				},
			},
		},
	},
	{
		input: "not (spice: mace or spice: nutmeg)",
		output: &tkn.Policy{
			Inputs: []tkn.Wire{
				{Label: "spice", RawValue: "mace", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "mace"), Positive: false},
				{Label: "spice", RawValue: "nutmeg", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "nutmeg"), Positive: false},
			},
			F: tkn.Formula{
				Gates: []tkn.Gate{
					{Class: tkn.Andgate, In0: 0, In1: 1, Out: 2},
				},
			},
		},
	},
	{
		input: "((region: caribean)) or (not (((fruit: stonefruit and not flower: hibiscus) or spice: mace) and not (family: extracts or family: chilis)))",
		output: &tkn.Policy{
			Inputs: []tkn.Wire{
				{Label: "region", RawValue: "caribean", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "caribean"), Positive: true},
				{Label: "fruit", RawValue: "stonefruit", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "stonefruit"), Positive: false},
				{Label: "flower", RawValue: "hibiscus", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "hibiscus"), Positive: true},
				{Label: "spice", RawValue: "mace", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "mace"), Positive: false},
				{Label: "family", RawValue: "extracts", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "extracts"), Positive: true},
				{Label: "family", RawValue: "chilis", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "chilis"), Positive: true},
			},
			F: tkn.Formula{
				Gates: []tkn.Gate{
					{Class: tkn.Orgate, In0: 1, In1: 2, Out: 6},
					{Class: tkn.Andgate, In0: 3, In1: 6, Out: 7},
					{Class: tkn.Orgate, In0: 4, In1: 5, Out: 8},
					{Class: tkn.Orgate, In0: 7, In1: 8, Out: 9},
					{Class: tkn.Orgate, In0: 0, In1: 9, Out: 10},
				},
			},
		},
	},
	{
		input: "(9country8: france)",
		output: &tkn.Policy{
			Inputs: []tkn.Wire{
				{Label: "9country8", RawValue: "france", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "france"), Positive: true},
			},
			F: tkn.Formula{
				Gates: []tkn.Gate{},
			},
		},
	},
	{
		input: "((country : afghanistan) or (country: bactria)) and (not (king: alexander))",
		output: &tkn.Policy{
			Inputs: []tkn.Wire{
				{Label: "country", RawValue: "afghanistan", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "afghanistan"), Positive: true},
				{Label: "country", RawValue: "bactria", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "bactria"), Positive: true},
				{Label: "king", RawValue: "alexander", Value: tkn.HashStringToScalar(dsl.AttrHashKey, "alexander"), Positive: false},
			},
			F: tkn.Formula{
				Gates: []tkn.Gate{
					{Class: tkn.Orgate, In0: 0, In1: 1, Out: 3},
					{Class: tkn.Andgate, In0: 3, In1: 2, Out: 4},
				},
			},
		},
	},
}

func TestDsl(t *testing.T) {
	for _, test := range testCases {
		t.Run("TestDsl:"+test.input, func(t *testing.T) {
			a, err := dsl.Run(test.input)
			if test.err == nil {
				if err != nil {
					t.Fatal(err)
				}
				if !a.Equal(test.output) {
					t.Fatalf("incorrect attributes: expected %v, received: %v", test.output, a)
				}
			} else {
				if err == nil {
					t.Fatalf("this should fail")
				}
				if test.err.Error() != err.Error() {
					t.Fatalf("incorrect error: expected: %v, received: %v", test.err, err)
				}
			}
		})
	}
}
