# incident-timeline

Merge incident evidence from several sources (VPN, EDR, SOC notes, helpdesk) into one ordered timeline and compute the response metrics a post-incident report needs: time to detect, time to contain, time to resolve, plus silent gaps. Go standard library only.

> Built with AI assistance (Claude) as part of a security portfolio. The sample incident is fictional.

## Input

JSON lines, one event per line. `time` must be RFC 3339 (any offset, normalised to UTC). `kind` is one of `start`, `detect`, `contain`, `resolve`, `info` (default).

```json
{"time":"2026-03-02T02:14:09Z","source":"vpn","event":"Login from unusual country","kind":"start"}
```

## Usage

```bash
go run . samples/firewall.jsonl samples/helpdesk.jsonl          # Markdown report section
go run . -json -gap 1h samples/*.jsonl                            # machine readable
cat events.jsonl | go run . -
```

Exit codes: 0 ok, 1 some input lines were invalid (valid lines are still used and each bad line is reported with its number), 2 usage or file error.

## Definitions

- Time to detect: first `start` to the first `detect` after it.
- Time to contain: first `detect` to the first `contain` after it (a containment before detection is ignored).
- Time to resolve: first `start` to the last `resolve`.
- A milestone that never happened is reported as "not reached", never as zero.
- Exact duplicate events across sources are dropped. Pipes and newlines in text are escaped so the Markdown table never breaks.

## Tests

`go test -race ./...` covers parsing errors, ordering, deduplication, each metric, missing milestones, formatting and the CLI contract. CI runs on Linux, macOS and Windows.

MIT licensed.
