package shieldcore

import (
	"reflect"
	"strings"
	"testing"
)

func compileOrFail(t *testing.T, rules ...Rule) *Ruleset {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("[")
	for i, r := range rules {
		if i > 0 {
			sb.WriteString(",")
		}
		b, _ := jsonMarshal(r)
		sb.Write(b)
	}
	sb.WriteString("]")
	rs, err := Compile([]byte(sb.String()))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return rs
}

func jsonMarshal(r Rule) ([]byte, error) {
	q := func(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }
	return []byte(`{"id":` + q(r.ID) + `,"pattern":` + q(r.Pattern) + `}`), nil
}

func scanOne(t *testing.T, pattern, text string, taints []Interval) []Evidence {
	t.Helper()
	rs := compileOrFail(t, Rule{ID: "r1", Pattern: pattern})
	return Scan(rs, text, taints)
}

func TestOverlapNoMiss(t *testing.T) {
	// "aba" over "ababa": leftmost match [0,3) is untainted; the hit is [2,5).
	got := scanOne(t, "aba", "ababa", []Interval{{4, 5}})
	want := []Evidence{{ID: "r1", Start: 2, End: 5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestAlternationOrderIrrelevant(t *testing.T) {
	for _, pat := range []string{"a|aa", "aa|a"} {
		got := scanOne(t, pat, "aa", []Interval{{0, 1}})
		want := []Evidence{{ID: "r1", Start: 0, End: 2}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("pattern %q: got %v want %v", pat, got, want)
		}
	}
}

func TestEmptyMatchCapablePatterns(t *testing.T) {
	// "a*" accepts the empty string, but only non-empty evidence counts.
	got := scanOne(t, "a*", "aa", []Interval{{0, 2}})
	want := []Evidence{{ID: "r1", Start: 0, End: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Only empty matches available (text "b"): no evidence.
	if got := scanOne(t, "a*", "b", []Interval{{0, 1}}); got != nil {
		t.Fatalf("expected no evidence, got %v", got)
	}
	// Empty-only pattern never hits.
	if got := scanOne(t, "()", "abc", []Interval{{0, 3}}); got != nil {
		t.Fatalf("expected no evidence, got %v", got)
	}
	// Star over a group, hit in the middle.
	got = scanOne(t, "(ab)*", "xxabab", []Interval{{3, 4}})
	want = []Evidence{{ID: "r1", Start: 2, End: 6}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestNoTaintNoHit(t *testing.T) {
	rs := compileOrFail(t, Rule{ID: "r1", Pattern: "a+"})
	if got := Scan(rs, "aaaa", nil); got != nil {
		t.Fatalf("expected no evidence without taints, got %v", got)
	}
}

func TestResultOrderFollowsRuleOrder(t *testing.T) {
	rs := compileOrFail(t,
		Rule{ID: "z-last-in-text", Pattern: "b"},
		Rule{ID: "a-first-in-text", Pattern: "a"},
		Rule{ID: "no-hit", Pattern: "c+"},
	)
	got := Scan(rs, "ab", []Interval{{0, 2}})
	want := []Evidence{
		{ID: "z-last-in-text", Start: 1, End: 2},
		{ID: "a-first-in-text", Start: 0, End: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRegexFeatures(t *testing.T) {
	cases := []struct {
		pat, text string
		taint     Interval
		want      *Evidence
	}{
		{`a\.b`, "xa.by", Interval{0, 3}, &Evidence{ID: "r1", Start: 1, End: 4}},     // escaped metachar
		{`a.b`, "a\nb", Interval{1, 2}, &Evidence{ID: "r1", Start: 0, End: 3}},       // dot matches newline
		{`[a-c]+`, "zabcz", Interval{1, 2}, &Evidence{ID: "r1", Start: 1, End: 4}},   // class range
		{`[^a-c]+`, "abXYab", Interval{2, 3}, &Evidence{ID: "r1", Start: 2, End: 4}}, // negated class
		{`ab?c`, "xac", Interval{2, 3}, &Evidence{ID: "r1", Start: 1, End: 3}},       // question
		{`(ab|cd)+e`, "zabcdex", Interval{5, 6}, &Evidence{ID: "r1", Start: 1, End: 6}},
		{`a\+b`, "a+b", Interval{0, 3}, &Evidence{ID: "r1", Start: 0, End: 3}},
		{`[\\]`, "a\\b", Interval{1, 2}, &Evidence{ID: "r1", Start: 1, End: 2}}, // class with escaped backslash
		{`foo`, "bar", Interval{0, 3}, nil},
	}
	for _, tc := range cases {
		got := scanOne(t, tc.pat, tc.text, []Interval{tc.taint})
		if tc.want == nil {
			if got != nil {
				t.Errorf("pat %q text %q: got %v want nil", tc.pat, tc.text, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != *tc.want {
			t.Errorf("pat %q text %q: got %v want %v", tc.pat, tc.text, got, tc.want)
		}
	}
}

func TestTaintBoundary(t *testing.T) {
	// Match [1,3) only intersects taint [3,4)? No: [1,3) and [3,4) are disjoint.
	got := scanOne(t, "b+", "abb", []Interval{{3, 4}})
	if got != nil {
		t.Fatalf("expected no evidence, got %v", got)
	}
	// Taint [2,3) intersects [1,3).
	got = scanOne(t, "b+", "abb", []Interval{{2, 3}})
	want := []Evidence{{ID: "r1", Start: 1, End: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Multiple taint intervals: earliest qualifying start wins.
	got = scanOne(t, "a", "a_a_a", []Interval{{0, 1}, {4, 5}})
	want = []Evidence{{ID: "r1", Start: 0, End: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestCompileValidation(t *testing.T) {
	if _, err := Compile([]byte(`not json`)); err == nil {
		t.Error("expected error for invalid JSON")
	}
	if _, err := Compile([]byte(`[{"id":"a","pattern":"x"},{"id":"a","pattern":"y"}]`)); err == nil {
		t.Error("expected error for duplicate id")
	}
	if _, err := Compile([]byte(`[{"id":"a","pattern":"` + strings.Repeat("a", 257) + `"}]`)); err == nil {
		t.Error("expected error for oversized pattern")
	}
	var many strings.Builder
	many.WriteString("[")
	for i := 0; i <= 500; i++ {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(`{"id":"r`)
		many.WriteString(strings.Repeat("x", 1))
		many.WriteString(string(rune('A' + i%26)))
		many.WriteString(string(rune('0' + (i/26)%10)))
		many.WriteString(string(rune('0' + i%10)))
		many.WriteString(`","pattern":"a"}`)
	}
	many.WriteString("]")
	if _, err := Compile([]byte(many.String())); err == nil {
		t.Error("expected error for >500 rules")
	}
	for _, bad := range []string{"(", "a)", "[a", "[z-a]", "a\\", "*a", "a|*"} {
		if _, err := Compile([]byte(`[{"id":"a","pattern":` + `"` + strings.ReplaceAll(bad, `\`, `\\`) + `"}]`)); err == nil {
			t.Errorf("expected compile error for pattern %q", bad)
		}
	}
}
