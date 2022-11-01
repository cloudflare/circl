package dsl

import (
	"fmt"
)

type Parser struct {
	tokens   []Token
	curr     int
	wires    map[attr]attrValue
	gates    []gate
	negative bool
}

func newParser(tokens []Token) Parser {
	return Parser{
		tokens:   tokens,
		curr:     0,
		wires:    make(map[attr]attrValue),
		gates:    make([]gate, 0),
		negative: false,
	}
}

func (p *Parser) parse() (Ast, error) {
	_, err := p.expression()
	if err != nil {
		return Ast{}, err
	}
	return Ast{
		wires: p.wires,
		gates: p.gates,
	}, nil
}

func (p *Parser) expression() (Expr, error) {
	return p.or()
}

func (p *Parser) or() (Expr, error) {
	expr, err := p.and()
	if err != nil {
		return nil, err
	}

	for p.tokens[p.curr].Type == Or {
		orToken := p.tokens[p.curr]
		p.curr++
		right, err := p.and()
		if err != nil {
			return nil, err
		}
		in1 := extractAttr(expr)
		in2 := extractAttr(right)
		newGate := gate{
			op:  Or,
			in1: in1,
			in2: in2,
			out: attr{
				key: "",
				id:  -(len(p.gates) + 1),
			},
		}
		if p.negative {
			newGate.op = And
		}
		p.gates = append(p.gates, newGate)

		expr = Binary{
			Left:     expr,
			Operator: orToken,
			Right:    right,
			Output:   p.gates[len(p.gates)-1].out,
		}
	}
	return expr, nil
}

func (p *Parser) and() (Expr, error) {
	expr, err := p.not()
	if err != nil {
		return nil, err
	}

	for p.tokens[p.curr].Type == And {
		andToken := p.tokens[p.curr]
		p.curr++
		right, err := p.not()
		if err != nil {
			return nil, err
		}
		in1 := extractAttr(expr)
		in2 := extractAttr(right)
		newGate := gate{
			op:  And,
			in1: in1,
			in2: in2,
			out: attr{
				key: "",
				id:  -(len(p.gates) + 1),
			},
		}
		if p.negative {
			newGate.op = Or
		}
		p.gates = append(p.gates, newGate)

		expr = Binary{
			Left:     expr,
			Operator: andToken,
			Right:    right,
			Output:   p.gates[len(p.gates)-1].out,
		}
	}
	return expr, nil
}

func (p *Parser) not() (Expr, error) {
	if p.tokens[p.curr].Type == Not {
		p.curr++
		currWires := make(map[attr]int)
		for wire := range p.wires {
			currWires[wire] = 1
		}
		p.negative = !p.negative
		right, err := p.not()
		p.negative = !p.negative
		if err != nil {
			return nil, err
		}
		for k, v := range p.wires {
			_, ok := currWires[k]
			if !ok {
				v.positive = !v.positive
				p.wires[k] = v
			}
		}
		return Unary{
			Operator: p.tokens[p.curr-1],
			Right:    right,
		}, nil
	}

	return p.primary()
}

func (p *Parser) primary() (Expr, error) {
	if p.tokens[p.curr].Type == LeftParen {
		p.curr++
		expr, err := p.expression()
		if err != nil {
			return nil, err
		}
		if !(p.tokens[p.curr].Type == RightParen) {
			return nil, fmt.Errorf("expected ')' after expression")
		}
		p.curr++
		return Grouping{
			Expr: expr,
		}, nil
	}

	if p.tokens[p.curr].Type == Identifier {
		if p.tokens[p.curr+1].Type == Colon {
			if p.tokens[p.curr+2].Type == Identifier {
				nextToken := p.tokens[p.curr+3].Type
				if (nextToken == Identifier) ||
					(nextToken == Colon) ||
					(nextToken == LeftParen) ||
					(nextToken == Not) {
					return nil, fmt.Errorf(
						"unexpected token %s, expected logical operator \"and\" or \"or\"",
						p.tokens[p.curr+3].Lexeme)
				}
				key := p.tokens[p.curr]
				value := p.tokens[p.curr+2]
				currAttr := attr{
					key: key.Lexeme,
					id:  len(p.wires),
				}
				attrVal := attrValue{
					value:    value.Lexeme,
					positive: true,
				}
				p.wires[currAttr] = attrVal
				p.curr += 3
				return Literal{
					Key:   currAttr,
					Value: attrVal,
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("expected parentheses or literal")
}

func extractAttr(expr Expr) attr {
	i := Interpreter{}
	expr.Accept(&i)
	return i.Literal.Key
}
