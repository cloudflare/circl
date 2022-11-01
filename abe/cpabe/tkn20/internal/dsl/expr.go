package dsl

type Expr interface {
	Accept(ExprVisitor)
}

type ExprVisitor interface {
	visitBinary(binary Binary)
	visitUnary(unary Unary)
	visitGrouping(grouping Grouping)
	visitLiteral(literal Literal)
}

// Binary is used for And, Or
type Binary struct {
	Left     Expr
	Operator Token
	Right    Expr
	Output   attr
}

func (b Binary) Accept(visitor ExprVisitor) {
	visitor.visitBinary(b)
}

// Unary is used for Not
type Unary struct {
	Operator Token
	Right    Expr
}

func (u Unary) Accept(visitor ExprVisitor) {
	visitor.visitUnary(u)
}

// Grouping is used for LeftParen, RightParen
type Grouping struct {
	Expr Expr
}

func (g Grouping) Accept(visitor ExprVisitor) {
	visitor.visitGrouping(g)
}

type Literal struct {
	Key   attr
	Value attrValue
}

func (l Literal) Accept(visitor ExprVisitor) {
	visitor.visitLiteral(l)
}
