package dsl

type Interpreter struct {
	Literal
}

func (i *Interpreter) Evaluate(expr Expr) Literal {
	expr.Accept(i)
	return i.Literal
}

func (i *Interpreter) visitBinary(b Binary) {
	i.Literal.Key = b.Output
}

func (i *Interpreter) visitUnary(u Unary) {
	i.Evaluate(u.Right)
}

func (i *Interpreter) visitGrouping(g Grouping) {
	g.Expr.Accept(i)
}

func (i *Interpreter) visitLiteral(at Literal) {
	i.Literal = at
}
