package shieldcore

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"regexp"
	"testing"
)

// reference is an independent oracle: it enumerates every non-empty
// substring, tests full acceptance with the standard library regexp
// engine, and applies the selection rule directly. It is only used for
// small randomized tests and shares no code with the production matcher.
func reference(t *testing.T, rules [][2]string, text string, taints []Span) []Evidence {
	t.Helper()
	n := len(text)
	var out []Evidence
	for _, r := range rules {
		re, err := regexp.Compile("(?s)^(" + r[1] + ")$")
		if err != nil {
			t.Fatalf("reference: bad pattern %q: %v", r[1], err)
		}
		bestS, bestE := -1, -1
		for i := 0; i < n; i++ {
			for j := i + 1; j <= n; j++ {
				if !re.MatchString(text[i:j]) {
					continue
				}
				ok := false
				for _, sp := range taints {
					if sp.Start < j && sp.End > i {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
				if bestS < 0 || i < bestS || (i == bestS && j > bestE) {
					bestS, bestE = i, j
				}
			}
		}
		if bestS >= 0 {
			out = append(out, Evidence{ID: r[0], Start: bestS, End: bestE})
		}
	}
	return out
}

var litPool = []byte{'a', 'b', 'c'}
var escPool = []byte{'.', '*', '+', '?', '(', ')', '[', ']', '|', '\\'}

func genAtom(r *rand.Rand, depth int) string {
	switch r.Intn(5) {
	case 0:
		return string(litPool[r.Intn(len(litPool))])
	case 1:
		return `\` + string(escPool[r.Intn(len(escPool))])
	case 2:
		return "."
	case 3:
		if r.Intn(2) == 0 {
			return "[a-c]"
		}
		return "[^ab]"
	default:
		if depth <= 0 {
			return string(litPool[r.Intn(len(litPool))])
		}
		return "(" + genAlt(r, depth-1) + ")"
	}
}

func genRepeat(r *rand.Rand, depth int) string {
	s := genAtom(r, depth)
	switch r.Intn(4) {
	case 0:
		return s + "*"
	case 1:
		return s + "+"
	case 2:
		return s + "?"
	}
	return s
}

func genConcat(r *rand.Rand, depth int) string {
	n := r.Intn(3) // may be empty
	s := ""
	for i := 0; i < n; i++ {
		s += genRepeat(r, depth)
	}
	return s
}

func genAlt(r *rand.Rand, depth int) string {
	s := genConcat(r, depth)
	for r.Intn(2) == 0 {
		s += "|" + genConcat(r, depth)
	}
	return s
}

func TestRandomizedAgainstReference(t *testing.T) {
	r := rand.New(rand.NewSource(20261002))
	for iter := 0; iter < 4000; iter++ {
		n := r.Intn(11)
		text := make([]byte, n)
		for i := range text {
			text[i] = litPool[r.Intn(len(litPool))]
		}
		if n > 0 && r.Intn(4) == 0 {
			text[r.Intn(n)] = '\n'
		}
		nr := 1 + r.Intn(3)
		rules := make([][2]string, nr)
		jr := make([]map[string]string, nr)
		for i := 0; i < nr; i++ {
			pat := genAlt(r, 2)
			rules[i] = [2]string{fmt.Sprintf("r%d", i), pat}
			jr[i] = map[string]string{"id": rules[i][0], "pattern": pat}
		}
		var taints []Span
		pos := 0
		for pos < n && r.Intn(2) == 0 {
			ln := 1 + r.Intn(3)
			if pos+ln > n {
				break
			}
			taints = append(taints, Span{pos, pos + ln})
			pos += ln + r.Intn(2)
		}
		raw, _ := json.Marshal(jr)
		rs, err := Compile(raw)
		if err != nil {
			t.Fatalf("iter %d: Compile(%s): %v", iter, raw, err)
		}
		got, err := rs.Scan(string(text), taints)
		if err != nil {
			t.Fatalf("iter %d: Scan: %v", iter, err)
		}
		want := reference(t, rules, string(text), taints)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("iter %d:\ntext=%q taints=%v rules=%v\ngot  %v\nwant %v",
				iter, string(text), taints, rules, got, want)
		}
	}
}
