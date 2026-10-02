package shieldcore

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

func compileBench(b testing.TB, pattern string) *Ruleset {
	b.Helper()
	rs, err := Compile([]byte(`[{"id":"p","pattern":` + `"` + strings.ReplaceAll(pattern, `\`, `\\`) + `"}]`))
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}
	return rs
}

func runTimed(t *testing.T, rs *Ruleset, text string, taints []Interval) ([]Evidence, time.Duration, uint64) {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	ev := Scan(rs, text, taints)
	dur := time.Since(start)
	runtime.ReadMemStats(&after)
	return ev, dur, after.TotalAlloc - before.TotalAlloc
}

// TestPerformance runs the required experiments: for N in
// {100k, 200k, 400k} consecutive 'a' bytes, a failing match of
// "(a|aa)*b" and a fully-tainted successful match of "a+".
// Time must scale linearly in N; allocated memory must stay constant
// (buffers are O(S), allocated once per Scan, nothing per position).
func TestPerformance(t *testing.T) {
	sizes := []int{100_000, 200_000, 400_000}
	rsFail := compileBench(t, "(a|aa)*b")
	rsOK := compileBench(t, "a+")

	t.Logf("%10s | %22s | %22s", "N", "fail (a|aa)*b", "success a+")
	t.Logf("%10s | %10s %10s | %10s %10s", "", "time", "alloc", "time", "alloc")
	for _, n := range sizes {
		text := strings.Repeat("a", n)

		ev, durF, allocF := runTimed(t, rsFail, text, []Interval{{0, n}})
		if ev != nil {
			t.Fatalf("N=%d: expected no evidence for failing pattern, got %v", n, ev)
		}

		ev, durS, allocS := runTimed(t, rsOK, text, []Interval{{0, n}})
		if len(ev) != 1 || ev[0].Start != 0 || ev[0].End != n {
			t.Fatalf("N=%d: expected single evidence [0,%d), got %v", n, n, ev)
		}

		t.Logf("%10d | %10s %10s | %10s %10s", n,
			durF.Round(time.Microsecond), formatBytes(allocF),
			durS.Round(time.Microsecond), formatBytes(allocS))
	}
}

func formatBytes(b uint64) string {
	return fmt.Sprintf("%dB", b)
}

func itoa(b uint64) string {
	return fmt.Sprintf("%d", b)
}

func BenchmarkScanFail(b *testing.B) {
	for _, n := range []int{100_000, 200_000, 400_000} {
		rs := compileBench(b, "(a|aa)*b")
		text := strings.Repeat("a", n)
		taints := []Interval{{0, n}}
		b.Run(itoa(uint64(n)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				Scan(rs, text, taints)
			}
		})
	}
}

func BenchmarkScanSuccess(b *testing.B) {
	for _, n := range []int{100_000, 200_000, 400_000} {
		rs := compileBench(b, "a+")
		text := strings.Repeat("a", n)
		taints := []Interval{{0, n}}
		b.Run(itoa(uint64(n)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				Scan(rs, text, taints)
			}
		})
	}
}
