package dsl

import (
	"fmt"
	"strings"
)

var keywords = map[string]string{
	"and": And,
	"or":  Or,
	"not": Not,
}

type Lexer struct {
	source   string
	tokens   []Token
	start    int
	curr     int
	line     int
	hadError bool
}

func newLexer(source string) Lexer {
	return Lexer{
		source:   source,
		tokens:   nil,
		start:    0,
		curr:     0,
		line:     1,
		hadError: false,
	}
}

func (l *Lexer) scanTokens() error {
	errMsg := "unexpected character(s): "
	for l.curr < len(l.source) {
		l.start = l.curr
		c := l.source[l.curr]
		l.curr++
		switch c {
		case '(':
			l.addToken(LeftParen)
		case ')':
			l.addToken(RightParen)
		case ':':
			l.addToken(Colon)
		case ' ', '\r', '\t':
		case '\n':
			l.line++
		default:
			if isAlphaNumeric(c) {
				l.identifier()
			} else {
				errMsg += fmt.Sprintf("'%s' ", string(c))
				l.hadError = true
			}
		}
	}
	l.addToken(EOF)
	if l.hadError {
		return fmt.Errorf(strings.TrimSpace(errMsg))
	}
	return nil
}

func (l *Lexer) addToken(tokenType string) {
	token := Token{
		tokenType,
		l.source[l.start:l.curr],
		l.line,
	}
	l.tokens = append(l.tokens, token)
}

func (l *Lexer) identifier() {
	for l.curr < len(l.source) {
		if isAlphaNumeric(l.source[l.curr]) {
			l.curr++
		} else {
			break
		}
	}
	tokenType, ok := keywords[l.source[l.start:l.curr]]
	if !ok {
		tokenType = Identifier
	}
	l.addToken(tokenType)
}
