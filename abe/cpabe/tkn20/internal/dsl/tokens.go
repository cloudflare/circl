package dsl

const (
	LeftParen  = "("
	RightParen = ")"
	Colon      = ":"
	Asterix    = "*"
	And        = "and"
	Or         = "or"
	Not        = "not"
	Identifier = "identifier"
	EOF        = "eof"
)

type Token struct {
	Type   string
	Lexeme string
	Line   int
}
