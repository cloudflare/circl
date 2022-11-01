package dsl

import (
	"errors"
	"testing"
)

func TestLexerErr(t *testing.T) {
	l := newLexer("sleep: @)")
	err := l.scanTokens()
	expectedErr := errors.New("unexpected character(s): '@'")
	if err == nil {
		t.Fatalf("missing expected err %v", expectedErr)
	}
	if expectedErr.Error() != err.Error() {
		t.Fatalf("incorrect error: expected %v, received %v", expectedErr, err)
	}
}

func TestLexer(t *testing.T) {
	l := newLexer("(sleep \n: \nnice\n)")
	err := l.scanTokens()
	if err != nil {
		t.Fatal(err)
	}

	types := []string{LeftParen, Identifier, Colon, Identifier, RightParen, EOF}

	if len(l.tokens) != len(types) {
		t.Fatalf("expected %d tokens, received: %v", len(types), len(l.tokens))
	}
	for i, typ := range types {
		if typ != l.tokens[i].Type {
			t.Fatalf("expected token %s, received: %s", typ, l.tokens[i].Type)
		}
	}

	if l.tokens[2].Line != 2 {
		t.Fatalf("expected line 2, received: %d", l.tokens[2].Line)
	}
	if l.tokens[3].Line != 3 {
		t.Fatalf("expected line 3, received: %d", l.tokens[3].Line)
	}
}
