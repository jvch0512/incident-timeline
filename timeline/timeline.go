// Package timeline merges incident events from several sources into one ordered timeline
// and computes the classic response metrics (time to detect, contain, resolve).
package timeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Kind classifies an event for metric computation.
type Kind string

const (
	Start   Kind = "start"   // when the incident really began (e.g. malicious login)
	Detect  Kind = "detect"  // first alert or human noticed
	Contain Kind = "contain" // spread stopped (account disabled, host isolated)
	Resolve Kind = "resolve" // normal service restored
	Info    Kind = "info"
)

// Event is one line of the incident record.
type Event struct {
	Time   time.Time `json:"time"`
	Source string    `json:"source"`
	Text   string    `json:"event"`
	Kind   Kind      `json:"kind"`
}

// Parse reads JSON lines. Blank lines and lines starting with # are skipped.
// Every malformed line is reported with its number; valid lines are still returned.
func Parse(r io.Reader) ([]Event, []error) {
	var events []Event
	var errs []error
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			errs = append(errs, fmt.Errorf("line %d: %v", n, err))
			continue
		}
		if e.Time.IsZero() {
			errs = append(errs, fmt.Errorf("line %d: missing or invalid time (use RFC 3339)", n))
			continue
		}
		if e.Kind == "" {
			e.Kind = Info
		}
		switch e.Kind {
		case Start, Detect, Contain, Resolve, Info:
		default:
			errs = append(errs, fmt.Errorf("line %d: unknown kind %q", n, e.Kind))
			continue
		}
		e.Time = e.Time.UTC()
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, err)
	}
	return events, errs
}

// Merge orders events by time; ties keep input order (stable) and exact duplicates are dropped.
func Merge(sets ...[]Event) []Event {
	var all []Event
	for _, s := range sets {
		all = append(all, s...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	out := all[:0:0]
	for _, e := range all {
		if len(out) > 0 && out[len(out)-1] == e {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Metrics holds response durations. A nil pointer means the milestone never happened.
type Metrics struct {
	TTD  *time.Duration // start to first detect
	TTC  *time.Duration // detect to first contain after it
	TTR  *time.Duration // start to last resolve
	Gaps []Gap
}

// Gap is a silent period longer than the threshold between two consecutive events.
type Gap struct {
	From, To time.Time
	Length   time.Duration
}

func first(events []Event, k Kind, after time.Time) *Event {
	for i := range events {
		if events[i].Kind == k && !events[i].Time.Before(after) {
			return &events[i]
		}
	}
	return nil
}

// Compute derives the metrics. Events must be sorted (use Merge).
func Compute(events []Event, gapThreshold time.Duration) Metrics {
	var m Metrics
	if len(events) == 0 {
		return m
	}
	start := first(events, Start, events[0].Time)
	det := (*Event)(nil)
	if start != nil {
		det = first(events, Detect, start.Time)
		if det != nil {
			d := det.Time.Sub(start.Time)
			m.TTD = &d
		}
	} else {
		det = first(events, Detect, events[0].Time)
	}
	if det != nil {
		if c := first(events, Contain, det.Time); c != nil {
			d := c.Time.Sub(det.Time)
			m.TTC = &d
		}
	}
	if start != nil {
		var last *Event
		for i := range events {
			if events[i].Kind == Resolve && !events[i].Time.Before(start.Time) {
				last = &events[i]
			}
		}
		if last != nil {
			d := last.Time.Sub(start.Time)
			m.TTR = &d
		}
	}
	for i := 1; i < len(events); i++ {
		if g := events[i].Time.Sub(events[i-1].Time); gapThreshold > 0 && g >= gapThreshold {
			m.Gaps = append(m.Gaps, Gap{events[i-1].Time, events[i].Time, g})
		}
	}
	return m
}

// Human formats a duration like "2h 5m" or "45s".
func Human(d time.Duration) string {
	d = d.Round(time.Second)
	if d < 0 {
		return "-" + Human(-d)
	}
	h, mi, s := int(d/time.Hour), int(d%time.Hour/time.Minute), int(d%time.Minute/time.Second)
	switch {
	case h > 0 && mi > 0:
		return fmt.Sprintf("%dh %dm", h, mi)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	case mi > 0 && s > 0:
		return fmt.Sprintf("%dm %ds", mi, s)
	case mi > 0:
		return fmt.Sprintf("%dm", mi)
	}
	return fmt.Sprintf("%ds", s)
}

func fmtMetric(name string, d *time.Duration) string {
	if d == nil {
		return fmt.Sprintf("- %s: not reached", name)
	}
	return fmt.Sprintf("- %s: %s", name, Human(*d))
}

// Markdown renders the timeline and metrics as a post-incident report section.
func Markdown(events []Event, m Metrics) string {
	var b strings.Builder
	b.WriteString("## Timeline (UTC)\n\n| Time | Source | Type | Event |\n|---|---|---|---|\n")
	for _, e := range events {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", e.Time.Format("2006-01-02 15:04:05"), esc(e.Source), e.Kind, esc(e.Text))
	}
	b.WriteString("\n## Response metrics\n\n")
	b.WriteString(fmtMetric("Time to detect (start to detect)", m.TTD) + "\n")
	b.WriteString(fmtMetric("Time to contain (detect to contain)", m.TTC) + "\n")
	b.WriteString(fmtMetric("Time to resolve (start to last resolve)", m.TTR) + "\n")
	if len(m.Gaps) > 0 {
		b.WriteString("\n## Silent gaps\n\n")
		for _, g := range m.Gaps {
			fmt.Fprintf(&b, "- %s of silence between %s and %s\n", Human(g.Length), g.From.Format("15:04:05"), g.To.Format("15:04:05"))
		}
	}
	return b.String()
}

// esc keeps log text from breaking the Markdown table.
func esc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
