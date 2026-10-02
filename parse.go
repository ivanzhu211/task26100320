package shieldcore

import "fmt"

// regex AST nodes.
type node interface{ nodeTag() }

type maskNode struct{ mask [2]uint64 } // literal, dot, or char class
type concatNode struct{ parts []node }
type altNode struct{ branches []node }
type starNode struct{ sub node }
type plusNode struct{ sub node }
type questNode struct{ sub node }
type emptyNode struct{}

func (maskNode) nodeTag()   {}
func (concatNode) nodeTag() {}
func (altNode) nodeTag()    {}
func (starNode) nodeTag()   {}
func (plusNode) nodeTag()   {}
func (questNode) nodeTag()  {}
func (emptyNode) nodeTag()  {}

func maskOf(b byte) [2]uint64 {
	var m [2]uint64
	m[b/64] |= 1 << (b % 64)
	return m
}

func fullMask() [2]uint64 { return [2]uint64{^uint64(0), ^uint64(0)} }

func negateMask(m [2]uint64) [2]uint64 { return [2]uint64{^m[0], ^m[1]} }

func setBit(m *[2]uint64, b byte) { m[b/64] |= 1 << (b % 64) }

// parser is a recursive-descent parser for the supported regex subset:
// literals, escaped metacharacters, dot, char classes (ranges, negation),
// groups, alternation, and * + ? quantifiers.
type parser struct {
	s   string
	pos int
}

func parsePattern(pat string) (node, error) {
	p := &parser{s: pat}
	n, err := p.parseAlt()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.s) {
		return nil, fmt.Errorf("unexpected %q at offset %d", p.s[p.pos], p.pos)
	}
	return n, nil
}

func (p *parser) peek() (byte, bool) {
	if p.pos >= len(p.s) {
		return 0, false
	}
	return p.s[p.pos], true
}

func (p *parser) next() byte {
	c := p.s[p.pos]
	p.pos++
	return c
}

// alt := concat ('|' concat)*
func (p *parser) parseAlt() (node, error) {
	first, err := p.parseConcat()
	if err != nil {
		return nil, err
	}
	branches := []node{first}
	for {
		c, ok := p.peek()
		if !ok || c != '|' {
			break
		}
		p.next()
		b, err := p.parseConcat()
		if err != nil {
			return nil, err
		}
		branches = append(branches, b)
	}
	if len(branches) == 1 {
		return branches[0], nil
	}
	return altNode{branches: branches}, nil
}

// concat := repeat*
func (p *parser) parseConcat() (node, error) {
	var parts []node
	for {
		c, ok := p.peek()
		if !ok || c == '|' || c == ')' {
			break
		}
		n, err := p.parseRepeat()
		if err != nil {
			return nil, err
		}
		parts = append(parts, n)
	}
	switch len(parts) {
	case 0:
		return emptyNode{}, nil
	case 1:
		return parts[0], nil
	default:
		return concatNode{parts: parts}, nil
	}
}

// repeat := atom ('*'|'+'|'?')*
func (p *parser) parseRepeat() (node, error) {
	n, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	for {
		c, ok := p.peek()
		if !ok {
			return n, nil
		}
		switch c {
		case '*':
			p.next()
			n = starNode{sub: n}
		case '+':
			p.next()
			n = plusNode{sub: n}
		case '?':
			p.next()
			n = questNode{sub: n}
		default:
			return n, nil
		}
	}
}

func isMeta(c byte) bool {
	switch c {
	case '(', ')', '|', '*', '+', '?', '[', ']', '.', '\\':
		return true
	}
	return false
}

// atom := '(' alt ')' | '[' class ']' | '.' | '\' char | literal
func (p *parser) parseAtom() (node, error) {
	c, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("unexpected end of pattern")
	}
	switch {
	case c == '(':
		p.next()
		n, err := p.parseAlt()
		if err != nil {
			return nil, err
		}
		if c, ok := p.peek(); !ok || c != ')' {
			return nil, fmt.Errorf("missing )")
		}
		p.next()
		return n, nil
	case c == '[':
		return p.parseClass()
	case c == '.':
		p.next()
		return maskNode{mask: fullMask()}, nil
	case c == '\\':
		p.next()
		b, err := p.parseEscape()
		if err != nil {
			return nil, err
		}
		return maskNode{mask: maskOf(b)}, nil
	case c == '*' || c == '+' || c == '?':
		return nil, fmt.Errorf("quantifier %q without operand at offset %d", c, p.pos)
	case c == ')':
		return nil, fmt.Errorf("unmatched ) at offset %d", p.pos)
	default:
		p.next()
		if c >= 0x80 {
			return nil, fmt.Errorf("non-ASCII byte in pattern at offset %d", p.pos-1)
		}
		return maskNode{mask: maskOf(c)}, nil
	}
}

// parseEscape reads the char after a backslash. Metacharacters become
// literals; \n \t \r map to their control bytes.
func (p *parser) parseEscape() (byte, error) {
	c, ok := p.peek()
	if !ok {
		return 0, fmt.Errorf("trailing backslash")
	}
	p.next()
	switch c {
	case 'n':
		return '\n', nil
	case 't':
		return '\t', nil
	case 'r':
		return '\r', nil
	}
	if c >= 0x80 {
		return 0, fmt.Errorf("non-ASCII escape")
	}
	return c, nil
}

// class := '[' '^'? (item)* ']' ; item := char | char '-' char
func (p *parser) parseClass() (node, error) {
	p.next() // consume '['
	neg := false
	if c, ok := p.peek(); ok && c == '^' {
		p.next()
		neg = true
	}
	var m [2]uint64
	for {
		c, ok := p.peek()
		if !ok {
			return nil, fmt.Errorf("unterminated character class")
		}
		if c == ']' {
			p.next()
			if neg {
				m = negateMask(m)
			}
			return maskNode{mask: m}, nil
		}
		lo, err := p.parseClassChar()
		if err != nil {
			return nil, err
		}
		// Range only if '-' is followed by a real char (not ']').
		if c, ok := p.peek(); ok && c == '-' && p.pos+1 < len(p.s) && p.s[p.pos+1] != ']' {
			p.next() // consume '-'
			hi, err := p.parseClassChar()
			if err != nil {
				return nil, err
			}
			if hi < lo {
				return nil, fmt.Errorf("invalid range %q-%q", lo, hi)
			}
			for b := lo; b <= hi; b++ {
				setBit(&m, b)
			}
		} else {
			setBit(&m, lo)
		}
	}
}

func (p *parser) parseClassChar() (byte, error) {
	c, ok := p.peek()
	if !ok {
		return 0, fmt.Errorf("unterminated character class")
	}
	if c == '\\' {
		p.next()
		return p.parseEscape()
	}
	p.next()
	if c >= 0x80 {
		return 0, fmt.Errorf("non-ASCII byte in character class")
	}
	return c, nil
}
