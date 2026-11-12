package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jvch0512/incident-timeline/timeline"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("incident-timeline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit JSON instead of Markdown")
	gap := fs.Duration("gap", 30*time.Minute, "report silent gaps at least this long (0 disables)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: incident-timeline [-json] [-gap 30m] file.jsonl [more.jsonl ...]  (use - for stdin)")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	var sets [][]timeline.Event
	bad := 0
	for _, p := range fs.Args() {
		var r io.Reader = stdin
		if p != "-" {
			f, err := os.Open(p)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			defer f.Close()
			r = f
		}
		ev, errs := timeline.Parse(r)
		for _, e := range errs {
			fmt.Fprintf(stderr, "%s: %v\n", p, e)
			bad++
		}
		sets = append(sets, ev)
	}
	events := timeline.Merge(sets...)
	m := timeline.Compute(events, *gap)
	if *asJSON {
		out := map[string]any{"events": events, "gaps": len(m.Gaps)}
		for k, v := range map[string]*time.Duration{"ttd_seconds": m.TTD, "ttc_seconds": m.TTC, "ttr_seconds": m.TTR} {
			if v != nil {
				out[k] = v.Seconds()
			} else {
				out[k] = nil
			}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		fmt.Fprint(stdout, timeline.Markdown(events, m))
	}
	if bad > 0 {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
