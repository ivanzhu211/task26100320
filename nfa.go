package shieldcore

// trans is a character-set transition.
type trans struct {
	bits [2]uint64
	to   int
}

// nfa is a Thompson NFA with the epsilon-graph SCC condensation
// precomputed in topological order, so each closure step is O(states).
type nfa struct {
	eps    [][]int   // epsilon transitions per state
	tr     [][]trans // char transitions per state
	comps  [][]int   // epsilon SCCs, predecessors first
	preds  [][]int   // predecessor component indices per component
	compOf []int     // state -> component index
	start  int       // global start state
}

// buildNFA compiles all rule ASTs into one combined NFA and returns it
// together with the per-rule accept state ids. When reversed is true the
// automaton accepts the reversed language (all edges flipped).
func buildNFA(asts []*node, reversed bool) (*nfa, []int) {
	b := &builder{}
	global := b.newState()
	accepts := make([]int, len(asts))
	for i, ast := range asts {
		s, a := buildFrag(b, ast)
		b.eps[global] = append(b.eps[global], s)
		accepts[i] = a
	}
	if reversed {
		return reverseNFA(b, global, accepts)
	}
	a := &nfa{eps: b.eps, tr: b.tr, start: global}
	a.analyze()
	return a, accepts
}

type builder struct {
	eps [][]int
	tr  [][]trans
}

func (b *builder) newState() int {
	b.eps = append(b.eps, nil)
	b.tr = append(b.tr, nil)
	return len(b.eps) - 1
}

// buildFrag adds states for n and returns its (start, accept) pair.
func buildFrag(b *builder, n *node) (int, int) {
	switch n.kind {
	case kindEmpty:
		s := b.newState()
		a := b.newState()
		b.eps[s] = append(b.eps[s], a)
		return s, a
	case kindChar, kindDot, kindClass:
		s := b.newState()
		a := b.newState()
		b.tr[s] = append(b.tr[s], trans{bits: n.bits, to: a})
		return s, a
	case kindConcat:
		var s, a, prev int
		for i, c := range n.children {
			cs, ca := buildFrag(b, c)
			if i == 0 {
				s = cs
			} else {
				b.eps[prev] = append(b.eps[prev], cs)
			}
			prev = ca
			a = ca
		}
		return s, a
	case kindAlt:
		s := b.newState()
		a := b.newState()
		for _, c := range n.children {
			cs, ca := buildFrag(b, c)
			b.eps[s] = append(b.eps[s], cs)
			b.eps[ca] = append(b.eps[ca], a)
		}
		return s, a
	case kindStar:
		s := b.newState()
		a := b.newState()
		cs, ca := buildFrag(b, n.child)
		b.eps[s] = append(b.eps[s], cs, a)
		b.eps[ca] = append(b.eps[ca], cs, a)
		return s, a
	case kindPlus:
		s := b.newState()
		a := b.newState()
		cs, ca := buildFrag(b, n.child)
		b.eps[s] = append(b.eps[s], cs)
		b.eps[ca] = append(b.eps[ca], cs, a)
		return s, a
	case kindQuest:
		s := b.newState()
		a := b.newState()
		cs, ca := buildFrag(b, n.child)
		b.eps[s] = append(b.eps[s], cs, a)
		b.eps[ca] = append(b.eps[ca], a)
		return s, a
	}
	panic("unreachable")
}

// reverseNFA flips every edge; the new global start reaches each rule's
// accept state, and each rule's accept becomes its original start.
func reverseNFA(b *builder, global int, accepts []int) (*nfa, []int) {
	n := len(b.eps)
	rev := &builder{eps: make([][]int, n), tr: make([][]trans, n)}
	for u := 0; u < n; u++ {
		for _, v := range b.eps[u] {
			rev.eps[v] = append(rev.eps[v], u)
		}
		for _, t := range b.tr[u] {
			rev.tr[t.to] = append(rev.tr[t.to], trans{bits: t.bits, to: u})
		}
	}
	start := len(rev.eps)
	rev.eps = append(rev.eps, nil)
	rev.tr = append(rev.tr, nil)
	revAccepts := make([]int, len(accepts))
	// In the forward NFA, rule i's start is reached from global; in the
	// reversed NFA that edge becomes ruleStart -> global, so the reversed
	// accept of rule i is the target of global's i-th epsilon edge.
	for i, ruleStart := range b.eps[global] {
		rev.eps[start] = append(rev.eps[start], accepts[i])
		revAccepts[i] = ruleStart
	}
	a := &nfa{eps: rev.eps, tr: rev.tr, start: start}
	a.analyze()
	return a, revAccepts
}

// analyze computes epsilon-graph SCCs (Tarjan) and the condensation in
// topological order (predecessors first).
func (a *nfa) analyze() {
	n := len(a.eps)
	index := make([]int, n)
	low := make([]int, n)
	onStack := make([]bool, n)
	for i := range index {
		index[i] = -1
	}
	var stack []int
	counter := 0
	var sccs [][]int

	var strongconnect func(v int)
	strongconnect = func(v int) {
		index[v] = counter
		low[v] = counter
		counter++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range a.eps[v] {
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
			var comp []int
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			sccs = append(sccs, comp)
		}
	}
	for v := 0; v < n; v++ {
		if index[v] == -1 {
			strongconnect(v)
		}
	}

	// Tarjan emits sinks first; reverse for predecessor-first order.
	a.compOf = make([]int, n)
	a.comps = make([][]int, len(sccs))
	for i, comp := range sccs {
		ci := len(sccs) - 1 - i
		a.comps[ci] = comp
		for _, s := range comp {
			a.compOf[s] = ci
		}
	}
	a.preds = make([][]int, len(sccs))
	for v := 0; v < n; v++ {
		for _, w := range a.eps[v] {
			cv, cw := a.compOf[v], a.compOf[w]
			if cv != cw {
				a.preds[cw] = append(a.preds[cw], cv)
			}
		}
	}
}
