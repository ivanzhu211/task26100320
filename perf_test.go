package shieldcore

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestPerfScaling runs the required scaling experiments. The NFA state
// count S is fixed by the patterns, so scan time must grow linearly with
// N and per-scan allocation must stay constant (O(S), independent of N).
func TestPerfScaling(t *testing.T) {
	fail := compile(t, [2]string{"fail", "(a|aa)*b"})
	ok := compile(t, [2]string{"ok", "a+"})
	type row struct {
		n         int
		failDur   time.Duration
		okDur     time.Duration
		failAlloc uint64
		okAlloc   uint64
	}
	var rows []row
	for _, n := range []int{100_000, 200_000, 400_000} {
		text := strings.Repeat("a", n)
		taints := []Span{{0, n}}

		runtime.GC()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		t0 := time.Now()
		ev, err := fail.Scan(text, taints)
		failDur := time.Since(t0)
		runtime.ReadMemStats(&m1)
		if err != nil {
			t.Fatal(err)
		}
		if ev != nil {
			t.Fatalf("n=%d: (a|aa)*b on all-a text must not hit, got %v", n, ev)
		}
		failAlloc := m1.TotalAlloc - m0.TotalAlloc

		runtime.GC()
		runtime.ReadMemStats(&m0)
		t0 = time.Now()
		ev, err = ok.Scan(text, taints)
		okDur := time.Since(t0)
		runtime.ReadMemStats(&m1)
		if err != nil {
			t.Fatal(err)
		}
		if len(ev) != 1 || ev[0].Start != 0 || ev[0].End != n {
			t.Fatalf("n=%d: a+ must yield one full-text evidence, got %v", n, ev)
		}
		okAlloc := m1.TotalAlloc - m0.TotalAlloc

		rows = append(rows, row{n, failDur, okDur, failAlloc, okAlloc})
		t.Logf("N=%7d  fail=(a|aa)*b %9v alloc=%6dB   ok=a+ %9v alloc=%6dB",
			n, failDur, failAlloc, okDur, okAlloc)
	}
	// Per-scan allocation is O(S): doubling and quadrupling N must not
	// grow it meaningfully (allowing small GC/allocator noise).
	for _, r := range rows[1:] {
		base := rows[0]
		pairs := [][2]uint64{
			{r.failAlloc, base.failAlloc},
			{r.okAlloc, base.okAlloc},
		}
		for _, pr := range pairs {
			if pr[0] > pr[1]+4096 {
				t.Fatalf("n=%d: per-scan allocation grew from %dB to %dB; must be O(S)",
					r.n, pr[1], pr[0])
			}
		}
	}
	// Time must scale roughly linearly: 4x the input well under 16x time.
	if rows[2].failDur > 16*rows[0].failDur+50*time.Millisecond ||
		rows[2].okDur > 16*rows[0].okDur+50*time.Millisecond {
		t.Fatalf("superlinear scaling: %+v", rows)
	}
	t.Logf("time ratio N=400k/100k: fail=%.2f ok=%.2f (linear would be 4)",
		float64(rows[2].failDur)/float64(rows[0].failDur),
		float64(rows[2].okDur)/float64(rows[0].okDur))
}
