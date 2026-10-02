package shieldcore

// node is a regex AST node.
type node struct {
	kind     nodeKind
	bits     [2]uint64 // literal / dot / class char set (kindLit..kindClass)
	children []*node   // concat / alternation branches
	child    *node     // quantifier operand
}

type nodeKind int

const (
	kindEmpty nodeKind = iota
	kindChar
	kindDot
	kindClass
	kindConcat
	kindAlt
	kindStar
	kindPlus
	kindQuest
)

// parseRegex parses the supported regex subset into an AST.
//
// Grammar:
//
//	alt    := concat ('|' concat)*
//	concat := repeat*
//	repeat := atom ('*' | '+' | '?')?
//	atom   := '(' alt ')' | class | '.' | '\' char | literal
//	class  := '[' '^'? (range | char)* ']'
func parseRegex(pattern string) (*node, error) {
	p := &parser{s: pattern}
	n, err := p.parseAlt()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.s) {
		return nil, errSyntax(p.pos, "unexpected character")
	}
	return n, nil
}

type parseError struct {
	pos int
	msg string
}

func (e *parseError) Error() string { return e.msg }

func errSyntax(pos int, msg string) error { return &parseError{pos: pos, msg: msg} }

type parser struct {
	s   string
	pos int
}

func (p *parser) peek() byte {
	if p.pos >= len(p.s) {
		return 0
	}
	return p.s[p.pos]
}

func (p *parser) next() byte {
	c := p.peek()
	p.pos++
	return c
}

func (p *parser) parseAlt() (*node, error) {
	branches := []*node{}
	for {
		n, err := p.parseConcat()
		if err != nil {
			return nil, err
		}
		branches = append(branches, n)
		if p.peek() != '|' {
			break
		}
		p.pos++
	}
	if len(branches) == 1 {
		return branches[0], nil
	}
	return &node{kind: kindAlt, children: branches}, nil
}

func (p *parser) parseConcat() (*node, error) {
	var parts []*node
	for p.pos < len(p.s) && p.peek() != '|' && p.peek() != ')' {
		n, err := p.parseRepeat()
		if err != nil {
			return nil, err
		}
		parts = append(parts, n)
	}
	switch len(parts) {
	case 0:
		return &node{kind: kindEmpty}, nil
	case 1:
		return parts[0], nil
	}
	return &node{kind: kindConcat, children: parts}, nil
}

func (p *parser) parseRepeat() (*node, error) {
	n, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	switch p.peek() {
	case '*':
		p.pos++
		return &node{kind: kindStar, child: n}, nil
	case '+':
		p.pos++
		return &node{kind: kindPlus, child: n}, nil
	case '?':
		p.pos++
		return &node{kind: kindQuest, child: n}, nil
	}
	return n, nil
}

func (p *parser) parseAtom() (*node, error) {
	if p.pos >= len(p.s) {
		return nil, errSyntax(p.pos, "unexpected end of pattern")
	}
	switch c := p.next(); c {
	case '(':
		n, err := p.parseAlt()
		if err != nil {
			return nil, err
		}
		if p.peek() != ')' {
			return nil, errSyntax(p.pos, "missing closing parenthesis")
		}
		p.pos++
		return n, nil
	case ')':
		return nil, errSyntax(p.pos-1, "unmatched closing parenthesis")
	case '.':
		var bits [2]uint64
		for b := 0; b < 128; b++ {
			bits[b>>6] |= 1 << (uint(b) & 63)
		}
		return &node{kind: kindDot, bits: bits}, nil
	case '[':
		return p.parseClass()
	case '\\':
		c, err := p.parseEscaped()
		if err != nil {
			return nil, err
		}
		return charNode(c), nil
	case '*', '+', '?', '|':
		return nil, errSyntax(p.pos-1, "quantifier or alternation without operand")
	default:
		if c >= 128 {
			return nil, errSyntax(p.pos-1, "non-ASCII character in pattern")
		}
		return charNode(c), nil
	}
}

// parseEscaped returns the literal byte after a backslash. Any ASCII byte
// may be escaped; this covers literal escapes of metacharacters.
func (p *parser) parseEscaped() (byte, error) {
	if p.pos >= len(p.s) {
		return 0, errSyntax(p.pos, "trailing backslash")
	}
	c := p.next()
	if c >= 128 {
		return 0, errSyntax(p.pos-1, "non-ASCII escape")
	}
	return c, nil
}

func (p *parser) parseClass() (*node, error) {
	negate := false
	if p.peek() == '^' {
		negate = true
		p.pos++
	}
	var bits [2]uint64
	for {
		if p.pos >= len(p.s) {
			return nil, errSyntax(p.pos, "unterminated character class")
		}
		if p.peek() == ']' {
			p.pos++
			break
		}
		lo, err := p.parseClassChar()
		if err != nil {
			return nil, err
		}
		hi := lo
		if p.peek() == '-' && p.pos+1 < len(p.s) && p.s[p.pos+1] != ']' {
			p.pos++
			hi, err = p.parseClassChar()
			if err != nil {
				return nil, err
			}
			if hi < lo {
				return nil, errSyntax(p.pos, "invalid character range")
			}
		}
		for b := lo; ; b++ {
			bits[b>>6] |= 1 << (uint(b) & 63)
			if b == hi {
				break
			}
		}
	}
	if negate {
		bits[0] = ^bits[0]
		bits[1] = ^bits[1]
	}
	return &node{kind: kindClass, bits: bits}, nil
}

func (p *parser) parseClassChar() (byte, error) {
	if p.peek() == '\\' {
		p.pos++
		return p.parseEscaped()
	}
	c := p.next()
	if c >= 128 {
		return 0, errSyntax(p.pos-1, "non-ASCII character in class")
	}
	return c, nil
}

func charNode(c byte) *node {
	var bits [2]uint64
	bits[c>>6] |= 1 << (uint(c) & 63)
	return &node{kind: kindChar, bits: bits}
}
