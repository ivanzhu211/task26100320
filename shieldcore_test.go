package shieldcore

import (
	"encoding/json"
	"reflect"
	"testing"
)

func compile(t *testing.T, rules ...[2]string) *Ruleset {
	t.Helper()
	var jr []map[string]string
	for _, r := range rules {
		jr = append(jr, map[string]string{"id": r[0], "pattern": r[1]})
	}
	raw, err := json.Marshal(jr)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return rs
}

func scan(t *testing.T, rs *Ruleset, text string, taints ...Span) []Evidence {
	t.Helper()
	ev, err := rs.Scan(text, taints)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return ev
}

func TestOverlapMissRegression(t *testing.T) {
	rs := compile(t, [2]string{"r1", "aba"})
	got := scan(t, rs, "ababa", Span{4, 5})
	want := []Evidence{{ID: "r1", Start: 2, End: 5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAlternationOrderIndependent(t *testing.T) {
	for _, pat := range []string{"a|aa", "aa|a"} {
		rs := compile(t, [2]string{"r1", pat})
		got := scan(t, rs, "aa", Span{0, 1})
		want := []Evidence{{ID: "r1", Start: 0, End: 2}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("pattern %q: got %v, want %v", pat, got, want)
		}
	}
}

func TestEmptyMatchNotEvidence(t *testing.T) {
	rs := compile(t, [2]string{"r1", "a*"})
	if got := scan(t, rs, "bbb", Span{0, 1}); got != nil {
		t.Fatalf("empty-only matches must not hit, got %v", got)
	}
	if got := scan(t, rs, "aab", Span{2, 3}); got != nil {
		t.Fatalf("match not touching taint must not hit, got %v", got)
	}
	got := scan(t, rs, "aab", Span{0, 1})
	want := []Evidence{{ID: "r1", Start: 0, End: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNoTaintNoHit(t *testing.T) {
	rs := compile(t, [2]string{"r1", "a+"})
	if got := scan(t, rs, "aaa"); got != nil {
		t.Fatalf("no taints must yield no hits, got %v", got)
	}
}

func TestDotMatchesNewline(t *testing.T) {
	rs := compile(t, [2]string{"r1", "a.b"})
	got := scan(t, rs, "a\nb", Span{1, 2})
	want := []Evidence{{ID: "r1", Start: 0, End: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestClassesAndEscapes(t *testing.T) {
	rs := compile(t,
		[2]string{"cls", "x[a-c]+y"},
		[2]string{"neg", "x[^a-c]+y"},
		[2]string{"esc", `a\*b`},
		[2]string{"grp", "(ab|cd)?e"},
	)
	got := scan(t, rs, "xbcy xdy a*b cde", Span{1, 2}, Span{6, 7}, Span{14, 15})
	want := []Evidence{
		{ID: "cls", Start: 0, End: 4},
		{ID: "neg", Start: 5, End: 8},
		{ID: "grp", Start: 13, End: 16},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got = scan(t, rs, "a*b", Span{1, 2})
	want = []Evidence{{ID: "esc", Start: 0, End: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestResultOrderFollowsRuleOrder(t *testing.T) {
	rs := compile(t, [2]string{"z", "b"}, [2]string{"a", "b"})
	got := scan(t, rs, "b", Span{0, 1})
	want := []Evidence{{ID: "z", Start: 0, End: 1}, {ID: "a", Start: 0, End: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCompileValidation(t *testing.T) {
	if _, err := Compile([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if _, err := Compile([]byte(`[{"id":"a","pattern":"x"},{"id":"a","pattern":"y"}]`)); err == nil {
		t.Fatal("expected error for duplicate id")
	}
	if _, err := Compile([]byte(`[{"id":"a","pattern":"(x"}]`)); err == nil {
		t.Fatal("expected error for bad pattern")
	}
	long := make([]byte, 257)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := Compile([]byte(`[{"id":"a","pattern":"` + string(long) + `"}]`)); err == nil {
		t.Fatal("expected error for oversized pattern")
	}
}

func TestScanValidation(t *testing.T) {
	rs := compile(t, [2]string{"r1", "a"})
	if _, err := rs.Scan("abc", []Span{{2, 2}}); err == nil {
		t.Fatal("expected error for empty taint span")
	}
	if _, err := rs.Scan("abc", []Span{{1, 3}, {2, 3}}); err == nil {
		t.Fatal("expected error for overlapping taint spans")
	}
	if _, err := rs.Scan("abc", []Span{{2, 3}, {0, 1}}); err == nil {
		t.Fatal("expected error for unsorted taint spans")
	}
	if _, err := rs.Scan("abc", []Span{{0, 4}}); err == nil {
		t.Fatal("expected error for out-of-range taint span")
	}
}
