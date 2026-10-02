// Package shieldcore implements a taint-constraint detection rule library.
// Callers supply decoded request text and taint spans for untrusted sources;
// this package performs rule matching and evidence location only.
package shieldcore

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Span is a half-open byte interval [Start, End).
type Span struct {
	Start int
	End   int
}

// Evidence is a single match report for a hit rule.
type Evidence struct {
	ID    string
	Start int
	End   int
}

// Ruleset is a compiled, reusable set of rules.
type Ruleset struct {
	ids        []string
	fwd        *nfa
	rev        *nfa
	fwdAccepts []int
	revAccepts []int
}

// Compile parses a JSON array of {"id","pattern"} rules into a Ruleset.
// At most 500 rules; each pattern at most 256 bytes; ids must be unique.
func Compile(ruleJSON []byte) (*Ruleset, error) {
	var jrs []struct {
		ID      string `json:"id"`
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(ruleJSON, &jrs); err != nil {
		return nil, fmt.Errorf("shieldcore: invalid rules JSON: %w", err)
	}
	if len(jrs) > 500 {
		return nil, errors.New("shieldcore: more than 500 rules")
	}
	seen := make(map[string]bool, len(jrs))
	asts := make([]*node, len(jrs))
	ids := make([]string, len(jrs))
	for i, jr := range jrs {
		if jr.ID == "" {
			return nil, fmt.Errorf("shieldcore: rule %d: empty id", i)
		}
		if seen[jr.ID] {
			return nil, fmt.Errorf("shieldcore: duplicate rule id %q", jr.ID)
		}
		seen[jr.ID] = true
		if len(jr.Pattern) > 256 {
			return nil, fmt.Errorf("shieldcore: rule %q: pattern exceeds 256 bytes", jr.ID)
		}
		ast, err := parseRegex(jr.Pattern)
		if err != nil {
			return nil, fmt.Errorf("shieldcore: rule %q: %v at offset %d", jr.ID, err, err.(*parseError).pos)
		}
		asts[i] = ast
		ids[i] = jr.ID
	}
	fwd, fwdAccepts := buildNFA(asts, false)
	rev, revAccepts := buildNFA(asts, true)
	return &Ruleset{
		ids:        ids,
		fwd:        fwd,
		rev:        rev,
		fwdAccepts: fwdAccepts,
		revAccepts: revAccepts,
	}, nil
}

// Scan returns one Evidence per hit rule, in rule input order.
// taints must be non-empty, sorted by start, and non-overlapping.
//
// A rule hits iff some non-empty substring fully accepted by its pattern
// intersects a taint span. The evidence is the hit substring with the
// smallest start; ties are broken by the largest end.
//
// The forward pass computes, for every end position, the minimum start
// of any accepted substring ending there; the minimum-start substring
// intersects a taint span iff any substring with that end does. The
// backward pass on the reversed automaton then yields, for the chosen
// start, the maximum end. Total time O((N+1) x S + T), memory O(S).
func (rs *Ruleset) Scan(text string, taints []Span) ([]Evidence, error) {
	n := len(text)
	for i, t := range taints {
		if t.Start < 0 || t.Start >= t.End || t.End > n {
			return nil, fmt.Errorf("shieldcore: invalid taint span %v", t)
		}
		if i > 0 && taints[i-1].End > t.Start {
			return nil, fmt.Errorf("shieldcore: taint spans not sorted or overlapping at %v", t)
		}
	}
	r := len(rs.ids)
	if r == 0 {
		return nil, nil
	}
	start := make([]int, r) // min start among taint-intersecting matches
	end := make([]int, r)   // max end for that start
	for i := range start {
		start[i] = -1
	}
	ti := 0 // intervals with Start < p (monotone in p)
	rs.fwd.simulate(text, false, func(p int, val []int) {
		for ti < len(taints) && taints[ti].Start < p {
			ti++
		}
		if ti == 0 {
			return
		}
		// Intervals are sorted and non-overlapping, so the last one with
		// Start < p also has the largest End: [v, p) intersects some
		// taint span iff that End > v.
		b := taints[ti-1].End
		for i := 0; i < r; i++ {
			v := val[rs.fwdAccepts[i]]
			if v >= 0 && v < p && b > v && (start[i] < 0 || v < start[i]) {
				start[i] = v
			}
		}
	})
	rs.rev.simulate(text, true, func(p int, val []int) {
		for i := 0; i < r; i++ {
			if start[i] == p {
				if v := val[rs.revAccepts[i]]; v > end[i] {
					end[i] = v
				}
			}
		}
	})
	var out []Evidence
	for i := 0; i < r; i++ {
		if start[i] >= 0 {
			out = append(out, Evidence{ID: rs.ids[i], Start: start[i], End: end[i]})
		}
	}
	return out, nil
}
