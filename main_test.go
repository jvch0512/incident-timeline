package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func exec(args []string, stdin string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestSamplesMergeIntoOneTimeline(t *testing.T) {
	code, out, _ := exec([]string{"samples/firewall.jsonl", "samples/helpdesk.jsonl"}, "")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"Time to detect (start to detect): 50m 51s", "Time to contain (detect to contain): 2h 35m", "Time to resolve (start to last resolve): 6h 55m", "Silent gaps", "Account jdoe disabled \\| sessions revoked"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "Passwords rotated") != 1 {
		t.Error("duplicate event should be removed")
	}
}

func TestJSONOutputAndStdin(t *testing.T) {
	in := `{"time":"2026-01-01T00:00:00Z","event":"a","kind":"start"}` + "\n" + `{"time":"2026-01-01T00:10:00Z","event":"b","kind":"detect"}` + "\n"
	code, out, _ := exec([]string{"-json", "-"}, in)
	if code != 0 {
		t.Fatal(code)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err, out)
	}
	if v["ttd_seconds"].(float64) != 600 || v["ttc_seconds"] != nil {
		t.Fatalf("%v", v)
	}
}

func TestExitCodes(t *testing.T) {
	if code, _, _ := exec(nil, ""); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code, _, _ := exec([]string{"missing.jsonl"}, ""); code != 2 {
		t.Errorf("missing file: %d", code)
	}
	if code, _, e := exec([]string{"-"}, "garbage\n"); code != 1 || !strings.Contains(e, "line 1") {
		t.Errorf("bad line should exit 1 with the line number: %d %q", code, e)
	}
}
