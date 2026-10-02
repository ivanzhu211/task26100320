package shieldcore

// nfaState is one state of a Thompson NFA over all rules.
type nfaState struct {
	eps        [2]int // epsilon targets, -1 = none
	tr         []charTrans
	acceptRule int // rule index if this is an accept state, else -1
}

type charTrans struct {
	mask [2]uint64 // 128-bit ASCII byte set
	to   int
}

// nfa is the combined automaton for a whole ruleset.
type nfa struct {
	states     []nfaState
	ruleStart  []int   // start state per rule
	ruleAccept []int   // accept state per rule
	sccOf      []int   // state -> SCC id (epsilon graph)
	sccTopo    []int   // SCC ids in topological order (sources first)
	sccMember  [][]int // SCC id -> member states
}

type builder struct {
	states []nfaState
}

func (b *builder) addState() int {
	b.states = append(b.states, nfaState{eps: [2]int{-1, -1}, acceptRule: -1})
	return len(b.states) - 1
}

func (b *builder) addEps(from, to int) {
	s := &b.states[from]
	if s.eps[0] == -1 {
		s.eps[0] = to
	} else {
		s.eps[1] = to
	}
}

// frag is a partially built fragment with one start and one accept state.
type frag struct{ start, accept int }

func (b *builder) build(n node) frag {
	switch t := n.(type) {
	case emptyNode:
		s := b.addState()
		a := b.addState()
		b.addEps(s, a)
		return frag{s, a}
	case maskNode:
		s := b.addState()
		a := b.addState()
		b.states[s].tr = append(b.states[s].tr, charTrans{mask: t.mask, to: a})
		return frag{s, a}
	case concatNode:
		first := b.build(t.parts[0])
		cur := first
		for _, part := range t.parts[1:] {
			next := b.build(part)
			b.addEps(cur.accept, next.start)
			cur = frag{cur.start, next.accept}
		}
		return cur
	case altNode:
		s := b.addState()
		a := b.addState()
		for _, br := range t.branches {
			f := b.build(br)
			b.addEps(s, f.start)
			b.addEps(f.accept, a)
		}
		return frag{s, a}
	case starNode:
		s := b.addState()
		a := b.addState()
		f := b.build(t.sub)
		b.addEps(s, f.start)
		b.addEps(s, a)
		b.addEps(f.accept, f.start)
		b.addEps(f.accept, a)
		return frag{s, a}
	case plusNode:
		a := b.addState()
		f := b.build(t.sub)
		b.addEps(f.accept, f.start)
		b.addEps(f.accept, a)
		return frag{f.start, a}
	case questNode:
		s := b.addState()
		a := b.addState()
		f := b.build(t.sub)
		b.addEps(s, f.start)
		b.addEps(s, a)
		b.addEps(f.accept, a)
		return frag{s, a}
	}
	panic("unreachable")
}

// buildNFA compiles parsed patterns into the combined NFA and computes the
// SCC decomposition of its epsilon graph (needed for O(S) closures, since
// Kleene star introduces epsilon cycles).
func buildNFA(asts []node) *nfa {
	b := &builder{}
	n := &nfa{}
	for i, ast := range asts {
		f := b.build(ast)
		n.ruleStart = append(n.ruleStart, f.start)
		n.ruleAccept = append(n.ruleAccept, f.accept)
		b.states[f.accept].acceptRule = i
	}
	n.states = b.states
	n.computeSCC()
	return n
}

// computeSCC runs Tarjan's algorithm over epsilon edges only and records
// SCC ids in topological order (sources first), plus membership lists.
func (n *nfa) computeSCC() {
	m := len(n.states)
	index := make([]int, m)
	low := make([]int, m)
	onStack := make([]bool, m)
	for i := range index {
		index[i] = -1
	}
	n.sccOf = make([]int, m)
	var stack []int
	counter := 0
	var topo []int // completed SCCs: sinks first

	var strongconnect func(v int)
	strongconnect = func(v int) {
		index[v] = counter
		low[v] = counter
		counter++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range n.states[v].eps {
			if w < 0 {
				continue
			}
			if index[w] == -1 {
				strongconnect(w)
				if low[w] < low[v] {
					low[v] = low[w]
				}
			} else if onStack[w] && index[w] < low[v] {
				low[v] = index[w]
			}
		}
		if low[v] == index[v] {
			sccID := len(topo)
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				n.sccOf[w] = sccID
				if w == v {
					break
				}
			}
			topo = append(topo, sccID)
		}
	}
	for v := 0; v < m; v++ {
		if index[v] == -1 {
			strongconnect(v)
		}
	}

	// Tarjan emits sinks first; reverse for sources-first topological order.
	n.sccTopo = make([]int, len(topo))
	for i, id := range topo {
		n.sccTopo[len(topo)-1-i] = id
	}
	n.sccMember = make([][]int, len(topo))
	for v := 0; v < m; v++ {
		c := n.sccOf[v]
		n.sccMember[c] = append(n.sccMember[c], v)
	}
}
