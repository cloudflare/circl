package dsl_test

import (
	"errors"
	"strings"
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

func TestParserDepthLimit(t *testing.T) {
	// Inputs nested far beyond maxParseDepth (64) must return the depth-limit
	// error rather than recursing until the goroutine stack overflows. Both
	// recursion drivers are exercised: nested groups and chained "not".
	want := "policy exceeds maximum nesting depth of 64"
	for _, in := range []string{
		strings.Repeat("(", 1000),    // nested groups
		strings.Repeat("not ", 1000), // chained "not"
	} {
		_, err := dsl.Run(in)
		if err == nil {
			t.Errorf("expected a depth-limit error for input of length %d, got nil", len(in))
			continue
		}
		if err.Error() != want {
			t.Errorf("expected error %q, received %q", want, err.Error())
		}
	}

	// A policy nested well within the limit must still parse successfully.
	valid := strings.Repeat("(", 16) + "region: US" + strings.Repeat(")", 16)
	if _, err := dsl.Run(valid); err != nil {
		t.Errorf("valid nested policy was rejected: %v", err)
	}
}

// Parser.parse() parses an expresion and returns without checking that it read all tokens. This
// allows for masking policies by manipulating it such that the policy is made to be 'complete' up
// to the portion of the policy one wishes to apply. No errors/information is returned to make this
// obvious
func TestParserSilentlyDropsTrailingContent(t *testing.T) {
	for _, policy := range []string{"country:US)", "country:US) or admin:true", "country:US)))", "country:US and region:US) ignored:garbage"} {
		t.Run(policy, func(t *testing.T) {
			if _, err := dsl.Run(policy); err == nil {
				t.Errorf("Parsed incomplete policy: %v", policy)
			}
		})
	}
}

// DSL should allow for case-mismatching overlap between the "and" and "or" delimiters
func TestLookalikeOperatorsAreParsedAsIdentifiers(t *testing.T) {
	if _, err := dsl.Run("AND:foo"); err != nil {
		t.Errorf("'AND' failed to parse as an identifier: %v", err)
	}
	if _, err := dsl.Run("OR:foo"); err != nil {
		t.Errorf("'OR' failed to parse as an identifier: %v", err)
	}
	if _, err := dsl.Run("Not:foo"); err != nil {
		t.Errorf("'Not' failed to parse as an identifier: %v", err)
	}

	if _, err := dsl.Run("key:AND"); err != nil {
		t.Errorf("'AND' failed to parse as an identifier: %v", err)
	}
	if _, err := dsl.Run("key:OR"); err != nil {
		t.Errorf("'AND' failed to parse as an identifier: %v", err)
	}

	if _, err := dsl.Run("and:foo"); err == nil {
		t.Errorf("'and' was parsed as an identifier: %v", err)
	}
	if _, err := dsl.Run("key:and"); err == nil {
		t.Errorf("'and' was parsed as an identifier: %v", err)
	}
	if _, err := dsl.Run("or:foo"); err == nil {
		t.Errorf("'or' failed to parse as an identifier: %v", err)
	}
	if _, err := dsl.Run("key:or"); err == nil {
		t.Errorf("'or' failed to parse as an identifier: %v", err)
	}
	if _, err := dsl.Run("not:foo"); err == nil {
		t.Errorf("'not' failed to parse as an identifier: %v", err)
	}

}
