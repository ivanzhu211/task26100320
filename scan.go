package shieldcore

// simulate runs one pass over text. At every position p it seeds the
// global start state with p (match-anywhere), computes the epsilon
// closure via the precomputed SCC condensation, and calls visit with
// the per-state best origin values: the minimum seed for the forward
// pass, the maximum seed for the backward pass. After visit it consumes
// one byte (text[p] forward, text[p-1] backward).
//
// Time is O((N+1) x states); the three scratch slices are O(states).
func (a *nfa) simulate(text string, backward bool, visit func(p int, val []int)) {
	nst := len(a.eps)
	val := make([]int, nst)
	seed := make([]int, nst)
	compVal := make([]int, len(a.comps))
	for i := range seed {
		seed[i] = -1
	}
	better := func(cur, cand int) int {
		if cand < 0 {
			return cur
		}
		if cur < 0 {
			return cand
		}
		if backward {
			if cand > cur {
				return cand
			}
			return cur
		}
		if cand < cur {
			return cand
		}
		return cur
	}
	n := len(text)
	for step := 0; step <= n; step++ {
		p := step
		if backward {
			p = n - step
		}
		seed[a.start] = better(seed[a.start], p)
		for ci, comp := range a.comps {
			bst := -1
			for _, s := range comp {
				bst = better(bst, seed[s])
			}
			for _, pc := range a.preds[ci] {
				bst = better(bst, compVal[pc])
			}
			compVal[ci] = bst
			for _, s := range comp {
				val[s] = bst
			}
		}
		visit(p, val)
		if step == n {
			break
		}
		var c byte
		if backward {
			c = text[p-1]
		} else {
			c = text[p]
		}
		for i := range seed {
			seed[i] = -1
		}
		for s := 0; s < nst; s++ {
			v := val[s]
			if v < 0 {
				continue
			}
			for _, t := range a.tr[s] {
				if c < 128 && t.bits[c>>6]>>(uint(c)&63)&1 == 1 {
					seed[t.to] = better(seed[t.to], v)
				}
			}
		}
	}
}
