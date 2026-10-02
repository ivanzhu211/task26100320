package shieldcore

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// The reference implementation below is deliberately independent from the
// production matcher: it enumerates every non-empty substring and checks
// full acceptance with Go's regexp (RE2). Only used on small inputs.

func refScan(patterns []string, text string, taints []Interval) []Evidence {
	var out []Evidence
	for i, pat := range patterns {
		re := regexp.MustCompile(`(?s)^(?:` + pat + `)$`)
		bestS, bestE := -1, -1
		for s := 0; s < len(text); s++ {
			for e := s + 1; e <= len(text); e++ {
				if !re.MatchString(text[s:e]) {
					continue
				}
				hit := false
				for _, iv := range taints {
					if s < iv.End && iv.Start < e {
						hit = true
						break
					}
				}
				if !hit {
					continue
				}
				if bestS < 0 || s < bestS || (s == bestS && e > bestE) {
					bestS, bestE = s, e
				}
			}
		}
		if bestS >= 0 {
			out = append(out, Evidence{ID: fmt.Sprintf("r%d", i), Start: bestS, End: bestE})
		}
	}
	return out
}

var metachars = []byte{'.', '|', '*', '+', '?', '(', ')', '[', ']', '\\'}

func genLeaf(r *rand.Rand) string {
	switch r.Intn(6) {
	case 0:
		return "."
	case 1:
		return `\` + string(metachars[r.Intn(len(metachars))])
	default:
		return string("abc"[r.Intn(3)])
	}
}

func genClass(r *rand.Rand) string {
	var sb strings.Builder
	sb.WriteString("[")
	if r.Intn(3) == 0 {
		sb.WriteString("^")
	}
	n := 1 + r.Intn(3)
	for i := 0; i < n; i++ {
		lo := "abc"[r.Intn(3)]
		if r.Intn(2) == 0 {
			hi := lo + byte(r.Intn(int('c'-lo)+1))
			sb.WriteByte(lo)
			sb.WriteByte('-')
			sb.WriteByte(hi)
		} else {
			sb.WriteByte(lo)
		}
	}
	sb.WriteString("]")
	return sb.String()
}

func genAlt(r *rand.Rand, depth int) string {
	n := 1 + r.Intn(2)
	parts := make([]string, n)
	for i := range parts {
		parts[i] = genConcat(r, depth)
	}
	return strings.Join(parts, "|")
}

func genConcat(r *rand.Rand, depth int) string {
	n := r.Intn(3)
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteString(genRepeat(r, depth))
	}
	return sb.String()
}

func genRepeat(r *rand.Rand, depth int) string {
	a := genAtom(r, depth)
	switch r.Intn(4) {
	case 0:
		return a + "*"
	case 1:
		return a + "+"
	case 2:
		return a + "?"
	}
	return a
}

func genAtom(r *rand.Rand, depth int) string {
	if depth > 0 {
		switch r.Intn(4) {
		case 0:
			return "(" + genAlt(r, depth-1) + ")"
		case 1:
			return genClass(r)
		}
	}
	return genLeaf(r)
}

func genText(r *rand.Rand) string {
	n := r.Intn(11)
	alpha := "ab"
	if r.Intn(3) == 0 {
		alpha = "abc"
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte(alpha[r.Intn(len(alpha))])
	}
	return sb.String()
}

func genTaints(r *rand.Rand, n int) []Interval {
	var out []Interval
	for tries := 0; tries < 10 && len(out) < 3; tries++ {
		s := r.Intn(n + 1)
		e := s + r.Intn(n-s+1)
		if e == s {
			continue
		}
		ok := true
		for _, iv := range out {
			if s < iv.End && iv.Start < e {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, Interval{s, e})
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Start < out[j-1].Start; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func TestDifferentialAgainstReference(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	for iter := 0; iter < 3000; iter++ {
		numRules := 1 + r.Intn(4)
		patterns := make([]string, numRules)
		var rulesJSON strings.Builder
		rulesJSON.WriteString("[")
		for i := range patterns {
			patterns[i] = genAlt(r, 3)
			if i > 0 {
				rulesJSON.WriteString(",")
			}
			fmt.Fprintf(&rulesJSON, `{"id":"r%d","pattern":%q}`, i, patterns[i])
		}
		rulesJSON.WriteString("]")
		text := genText(r)
		taints := genTaints(r, len(text))

		rs, err := Compile([]byte(rulesJSON.String()))
		if err != nil {
			t.Fatalf("iter %d: Compile(%s): %v", iter, rulesJSON.String(), err)
		}
		got := Scan(rs, text, taints)
		want := refScan(patterns, text, taints)
		if len(got) != len(want) {
			t.Fatalf("iter %d: patterns=%q text=%q taints=%v\ngot  %v\nwant %v", iter, patterns, text, taints, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter %d: patterns=%q text=%q taints=%v\ngot  %v\nwant %v", iter, patterns, text, taints, got, want)
			}
		}
	}
}
