// Package shieldcore implements a taint-constraint detection rule library.
// Callers provide decoded request text and taint intervals for untrusted
// sources; this package only performs rule matching and evidence location.
package shieldcore

import (
	"encoding/json"
	"fmt"
)

const (
	maxRules        = 500
	maxPatternBytes = 256
)

// Rule is a single detection rule decoded from JSON.
type Rule struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
}

// Interval is a half-open byte range [Start, End) of tainted input.
type Interval struct {
	Start int
	End   int
}

// Evidence reports one hit: the rule ID and the half-open byte range
// [Start, End) of the matched substring.
type Evidence struct {
	ID    string `json:"id"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// Ruleset is a compiled, reusable set of rules.
type Ruleset struct {
	ids []string
	nfa *nfa
}

// Compile parses a JSON array of rules into a reusable Ruleset.
// At most 500 rules, each pattern at most 256 bytes, IDs unique.
func Compile(data []byte) (*Ruleset, error) {
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("shieldcore: invalid JSON: %w", err)
	}
	if len(rules) > maxRules {
		return nil, fmt.Errorf("shieldcore: %d rules exceeds limit %d", len(rules), maxRules)
	}
	seen := make(map[string]bool, len(rules))
	asts := make([]node, len(rules))
	ids := make([]string, len(rules))
	for i, r := range rules {
		if len(r.Pattern) > maxPatternBytes {
			return nil, fmt.Errorf("shieldcore: rule %q pattern of %d bytes exceeds limit %d", r.ID, len(r.Pattern), maxPatternBytes)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("shieldcore: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		ast, err := parsePattern(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("shieldcore: rule %q: %w", r.ID, err)
		}
		asts[i] = ast
		ids[i] = r.ID
	}
	return &Ruleset{ids: ids, nfa: buildNFA(asts)}, nil
}

// Scan runs the compiled ruleset over ASCII text with the given taint
// intervals and returns one Evidence per matching rule, in rule input
// order. The caller must provide taint intervals sorted by start,
// non-overlapping, and non-empty; positions are zero-based half-open byte
// ranges. Rules only hit on non-empty substrings intersecting a taint
// interval, so with no taints nothing can hit.
func Scan(rs *Ruleset, text string, taints []Interval) []Evidence {
	if rs == nil || len(rs.ids) == 0 || len(taints) == 0 {
		return nil
	}
	return rs.scan(text, taints)
}
