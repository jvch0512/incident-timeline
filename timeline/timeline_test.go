package timeline

import (
	"strings"
	"testing"
	"time"
)

func ev(t string, k Kind, txt string) Event {
	ts, err := time.Parse(time.RFC3339, t)
	if err != nil {
		panic(err)
	}
	return Event{Time: ts, Source: "s", Text: txt, Kind: k}
}

func TestParseReportsBadLinesButKeepsGoodOnes(t *testing.T) {
	in := "# comment\n\n" +
		`{"time":"2026-01-01T00:00:00Z","source":"a","event":"ok","kind":"start"}` + "\n" +
		`not json` + "\n" +
		`{"source":"a","event":"no time"}` + "\n" +
		`{"time":"2026-01-01T00:01:00Z","event":"bad kind","kind":"wat"}` + "\n" +
		`{"time":"2026-01-01T01:00:00+02:00","event":"tz"}` + "\n"
	got, errs := Parse(strings.NewReader(in))
	if len(got) != 2 || len(errs) != 3 {
		t.Fatalf("events=%d errs=%d (%v)", len(got), len(errs), errs)
	}
	if got[1].Kind != Info || got[1].Time.Hour() != 23 || got[1].Time.Location() != time.UTC {
		t.Fatalf("default kind or UTC conversion wrong: %+v", got[1])
	}
	if !strings.Contains(errs[0].Error(), "line 4") {
		t.Fatalf("line numbers should count comments and blanks: %v", errs[0])
	}
}

func TestMergeOrdersAndDeduplicates(t *testing.T) {
	a := []Event{ev("2026-01-01T10:00:00Z", Info, "late"), ev("2026-01-01T08:00:00Z", Info, "early")}
	b := []Event{ev("2026-01-01T08:00:00Z", Info, "early"), ev("2026-01-01T09:00:00Z", Info, "mid")}
	got := Merge(a, b)
	if len(got) != 3 || got[0].Text != "early" || got[1].Text != "mid" || got[2].Text != "late" {
		t.Fatalf("%+v", got)
	}
}

func TestMetrics(t *testing.T) {
	events := Merge([]Event{
		ev("2026-03-02T02:14:09Z", Start, "x"), ev("2026-03-02T03:05:00Z", Detect, "x"),
		ev("2026-03-02T05:40:00Z", Contain, "x"), ev("2026-03-02T09:10:00Z", Resolve, "x"),
	})
	m := Compute(events, 90*time.Minute)
	if m.TTD == nil || *m.TTD != 50*time.Minute+51*time.Second {
		t.Fatalf("ttd %v", m.TTD)
	}
	if m.TTC == nil || *m.TTC != 2*time.Hour+35*time.Minute {
		t.Fatalf("ttc %v", m.TTC)
	}
	if m.TTR == nil || *m.TTR != 6*time.Hour+55*time.Minute+51*time.Second {
		t.Fatalf("ttr %v", m.TTR)
	}
	if len(m.Gaps) != 2 { // 03:05 to 05:40 and 05:40 to 09:10
		t.Fatalf("gaps %+v", m.Gaps)
	}
}

func TestMissingMilestonesAreNil(t *testing.T) {
	m := Compute(Merge([]Event{ev("2026-01-01T00:00:00Z", Start, "x")}), 0)
	if m.TTD != nil || m.TTC != nil || m.TTR != nil || len(m.Gaps) != 0 {
		t.Fatalf("%+v", m)
	}
	if got := Compute(nil, time.Hour); got.TTD != nil {
		t.Fatal("empty input")
	}
	// detect without a declared start still allows containment time
	m = Compute(Merge([]Event{ev("2026-01-01T00:00:00Z", Detect, "x"), ev("2026-01-01T00:10:00Z", Contain, "x")}), 0)
	if m.TTD != nil || m.TTC == nil || *m.TTC != 10*time.Minute {
		t.Fatalf("%+v", m)
	}
}

func TestContainBeforeDetectIsIgnored(t *testing.T) {
	m := Compute(Merge([]Event{
		ev("2026-01-01T00:00:00Z", Start, "x"), ev("2026-01-01T00:05:00Z", Contain, "early"),
		ev("2026-01-01T01:00:00Z", Detect, "x"), ev("2026-01-01T01:30:00Z", Contain, "real"),
	}), 0)
	if m.TTC == nil || *m.TTC != 30*time.Minute {
		t.Fatalf("ttc %v", m.TTC)
	}
}

func TestHuman(t *testing.T) {
	cases := map[time.Duration]string{45 * time.Second: "45s", 5 * time.Minute: "5m", 90 * time.Second: "1m 30s", 2 * time.Hour: "2h", 125 * time.Minute: "2h 5m", -time.Minute: "-1m"}
	for d, want := range cases {
		if got := Human(d); got != want {
			t.Errorf("%v: got %q want %q", d, got, want)
		}
	}
}

func TestMarkdownEscapesTableBreakers(t *testing.T) {
	events := []Event{{Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Source: "a|b", Text: "x | y\nz", Kind: Info}}
	md := Markdown(events, Compute(events, 0))
	if !strings.Contains(md, `a\|b`) || !strings.Contains(md, `x \| y z`) {
		t.Fatalf("not escaped:\n%s", md)
	}
	if !strings.Contains(md, "not reached") {
		t.Fatal("unreached milestones should be stated")
	}
}
