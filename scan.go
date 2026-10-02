package shieldcore

// scan simulates the combined NFA over text once, left to right.
//
// At each position i the start state of every rule is injected with start
// position i, so every candidate substring start is considered in a single
// pass (no per-start restarts). Each SCC of the epsilon graph carries the
// minimum start position that can reach it; min-start dominates because any
// continuation reachable from a later start is reachable from an earlier
// one, and a longer (earlier-started) substring still intersects every taint
// interval the shorter one did.
//
// For each rule and end position i we therefore get L(i), the minimum start
// of any accepted substring ending at i. Restricting candidates to
// (L(i), i) is safe: if (s*, i*) is an optimal qualifying substring, then
// (L(i*), i*) starts no later, ends at the same place, and still intersects
// the same taint, so the optimum over the restricted set equals the global
// optimum. Empty matches (start == i) are discarded.
func (rs *Ruleset) scan(text string, taints []Interval) []Evidence {
	n := rs.nfa
	m := len(n.states)
	numRules := len(rs.ids)
	numSCC := len(n.sccTopo)

	// All scratch buffers are allocated once per Scan: O(S) extra memory,
	// zero per-position allocation.
	rawGen := make([]int, m)
	rawStart := make([]int, m)
	rawList := make([]int, 0, m)
	nextGen := make([]int, m)
	nextStart := make([]int, m)
	nextList := make([]int, 0, m)
	sccGen := make([]int, m)
	// Generation stamps must not collide with the zero value at position 0.
	for j := range rawGen {
		rawGen[j] = -1
		nextGen[j] = -1
	}
	for j := range sccGen {
		sccGen[j] = -1
	}
	sccMin := make([]int, numSCC)
	sccList := make([]int, 0, numSCC)

	bestSet := make([]bool, numRules)
	bestS := make([]int, numRules)
	bestE := make([]int, numRules)

	tIdx := 0 // count of taint intervals with Start < i (monotone in i)

	relaxSCC := func(c, start, gen int) {
		if sccGen[c] != gen {
			sccGen[c] = gen
			sccMin[c] = start
			sccList = append(sccList, c)
		} else if start < sccMin[c] {
			sccMin[c] = start
		}
	}

	for i := 0; i <= len(text); i++ {
		for tIdx < len(taints) && taints[tIdx].Start < i {
			tIdx++
		}

		// Inject every rule's start state with start position i.
		for _, st := range n.ruleStart {
			if rawGen[st] != i {
				rawGen[st] = i
				rawStart[st] = i
				rawList = append(rawList, st)
			}
		}

		// Epsilon closure: seed SCCs from raw states, then propagate
		// min-start along the SCC DAG in topological order.
		for _, st := range rawList {
			relaxSCC(n.sccOf[st], rawStart[st], i)
		}
		for _, c := range n.sccTopo {
			if sccGen[c] != i {
				continue
			}
			s := sccMin[c]
			for _, st := range n.sccMember[c] {
				for _, e := range n.states[st].eps {
					if e >= 0 {
						relaxSCC(n.sccOf[e], s, i)
					}
				}
			}
		}

		// Accept check: one accept state per rule; candidate (L(i), i).
		for r := 0; r < numRules; r++ {
			c := n.sccOf[n.ruleAccept[r]]
			if sccGen[c] != i {
				continue
			}
			s := sccMin[c]
			if s >= i { // empty match is not evidence
				continue
			}
			// Intersects taint iff the last interval starting before i
			// (which has the largest end among them) ends after s.
			if tIdx == 0 || taints[tIdx-1].End <= s {
				continue
			}
			if !bestSet[r] || s <= bestS[r] {
				bestSet[r] = true
				bestS[r] = s
				bestE[r] = i
			}
		}

		if i == len(text) {
			break
		}

		// Step: consume text[i] from every active state.
		c := text[i]
		if c < 0x80 {
			bit := uint64(1) << (c % 64)
			word := c / 64
			for _, c2 := range sccList {
				for _, st := range n.sccMember[c2] {
					s := sccMin[c2]
					for _, tr := range n.states[st].tr {
						if tr.mask[word]&bit == 0 {
							continue
						}
						if nextGen[tr.to] != i+1 {
							nextGen[tr.to] = i + 1
							nextStart[tr.to] = s
							nextList = append(nextList, tr.to)
						} else if s < nextStart[tr.to] {
							nextStart[tr.to] = s
						}
					}
				}
			}
		}

		rawGen, nextGen = nextGen, rawGen
		rawStart, nextStart = nextStart, rawStart
		rawList, nextList = nextList, rawList[:0]
		sccList = sccList[:0]
	}

	var out []Evidence
	for r := 0; r < numRules; r++ {
		if bestSet[r] {
			out = append(out, Evidence{ID: rs.ids[r], Start: bestS[r], End: bestE[r]})
		}
	}
	return out
}
