# AGENTS.md — cybersec-intel

Quick reference for AI agents working on this project. Read this before touching the code.

## Fast facts

| | |
|---|---|
| What | Terminal threat-intel tool: feeds, indicator lookups, passive site check, CVE → exploit search |
| Version | 1.2.0 (`VERSION` in `intel.py`; keep `CHANGELOG.md` and `README.md` in step) |
| Code | one file, `intel.py`, Python 3.9+, standard library only |
| Run | `python3 intel.py` (interactive) or `python3 intel.py --help` (one-shot modes) |
| Keys | `.env` beside `intel.py`; template in `.env.example` |
| Local state | `.cache.json`, `.state.json`, `exports/` — all git-ignored |
| Tests | no suite; verify by running the commands under *Testing* |

## Hard rules

1. **Never display secrets.** Do not `cat` `.env`, echo key values, or put a key in a shell command string. To check which keys exist, print variable names only. Read keys inside Python from the file. Never write a key into a report, log, commit or test fixture.
2. **Never commit local state.** `.env`, `.cache.json`, `.state.json` and `exports/` hold keys or investigation data. They are in `.gitignore`; keep them there.
3. **Free options only.** This tool targets free API tiers. Do not add a source or endpoint that needs a paid plan. Probe an endpoint with a real free key before building on it; several "free" endpoints turn out to be restricted.
4. **Passive only.** The tool must never connect to the indicator being investigated. Every request goes to a third-party intelligence service.
5. **Standard library only.** No third-party Python packages.
6. **Spend quota carefully.** VirusTotal allows about 500 requests a day and 4 a minute. When testing, reuse cached indicators (`8.8.8.8`, `185.220.101.1`, `example.org`, `CVE-2021-44228`) and check `.state.json` afterwards.
7. **Do not change the look.** Keep the existing colors, layout and row format unless asked.
8. **Ask before saving reports** anywhere outside `exports/`.

## Layout

Everything is in `intel.py`, in this order:

| Section | Contents |
|---|---|
| Config | `VERSION`, `HOST_TTL`, `RATE_LIMITS`, `HOST_QUOTA`, `DAILY_LIMITS`, `QUOTA_VAR`, `SOURCES` |
| Core | `classify()`, `Res`, `Bul`, `unpack()`, `Throttle`, cache, quota state, `http_json()` |
| Local exploit indexes | Exploit-DB CSV, Metasploit metadata JSON, Nuclei template walk; `local_exploits()`, `mark_vulns()`, `epss_scores()` |
| Sources | one `src_*` function per engine |
| CVE and PoC | `src_nvd_cve`, `src_cvedb`, `src_poc_github`, `src_poc_local`, `src_otx_cve` |
| Feeds | `feed_*` functions |
| Deep mode and keyless | `src_vt_*`, `src_abuse_block`, `src_rdap_*`, `src_crtsh`, `deep_jobs()` |
| Pivoting | `pivot_of()` |
| Job tables | `base_jobs()`, `jobs_for()`, `prescan_jobs()`, `cve_jobs()`, `feed_jobs()` |
| Exports | CSV, Markdown report, row coloring |
| TUI | `class Tui` |
| CLI | `run_jobs()`, `cli_*`, `main()` |

## Conventions

- **A source returns a `Res`**: `Res(fields, score, notes, text)`. `fields` is a list of `(label, value)`. A plain list value is joined on one line when short; wrap it in `Bul(...)` to force one item per line. The same `Res` feeds the text view, CSV, report and `--json`, so never format output outside it.
- **A feed returns a list of strings.**
- **Missing key or "nothing to show"** → `raise Skip("reason")`. Use `need("VAR_NAME")` to fetch a key. A real failure should raise normally; `fail_text()` formats it.
- **All HTTP goes through `http_json()`.** It applies throttle, quota, cache and one retry on 502/503/504. Do not call `urllib` directly from a source.
- **Slim large answers** with the `shape=` argument so the cache stays small; entries over 120 KB are not written to disk.
- **Keys in URLs**: only a `key=` query parameter is redacted from the cache key. Prefer headers; if a service needs another parameter name, extend `RE_KEYPARAM`.
- **Scores** only matter in the site check. A source used only in lookups should return score 0. The total is capped by `total_score()`.
- **Row coloring** is driven by text patterns in `RE_POS_RED` / `RE_POS_YEL` (for example `Listed     YES`, `malicious:3`, `EXPLOIT` at end of line). Keep those phrasings when editing a source.
- **Remote text is untrusted.** `Res.lines()` and `unpack()` strip control characters; do not bypass them when printing.

## Adding a source

1. Probe the endpoint with a real free key and confirm the free tier allows it.
2. Add the host to `RATE_LIMITS` and `HOST_TTL`.
3. If it has a daily limit, add it to `DAILY_LIMITS` and `QUOTA_VAR`, and either map the host in `HOST_QUOTA` or pass `quota="Label"` to `http_json()`.
4. Write `src_name(...)` returning a `Res`.
5. Register it in `base_jobs()`, `prescan_jobs()` or `deep_jobs()` with a unique title.
6. Add the title to `EXPECTED` (expected seconds, used for the progress bar).
7. If it needs a new key, add it to `SOURCES` and to `.env.example`.
8. Update `README.md` and `CHANGELOG.md`.

## Testing

```bash
python3 -m py_compile intel.py
python3 intel.py --version
python3 intel.py --lookup 8.8.8.8
python3 intel.py --poc CVE-2021-44228
python3 intel.py --prescan example.org
python3 intel.py --feed
python3 intel.py --lookup 8.8.8.8 --json | python3 -m json.tool > /dev/null
```

For the interactive screen, drive it in a detached `tmux` session (`send-keys`, then `capture-pane -p`). Reading raw curses output from a pty is unreliable because curses only redraws changed cells.

After touching `http_json()`, check that no key reached the cache: count matches of each key in `.cache.json` from inside Python, without printing the key.

## Releasing

1. Bump `VERSION` in `intel.py`.
2. Add a section to `CHANGELOG.md`.
3. Update the version in this file and any changed options in `README.md`.
4. Before committing, confirm `git status` shows none of `.env`, `.cache.json`, `.state.json`, `exports/`.

## Known upstream behaviour

- Shodan free plan: `/shodan/host/{ip}` returns 403 "Requires membership" for some IPs, consistently per IP (not a rate limit). `/dns/*` is paid.
- NVD: often 20 s+ per query and occasional 503. Feed queries use a 60 s timeout.
- crt.sh: frequent timeouts.
- ThreatFox `search_ioc` finds nothing for full URLs, so URL lookups search by host and filter.
- VirusTotal: 404 for unknown URLs and hashes is normal and is shown as a skip.
- MyThreatIntel is optional; without a token its sections always skip.
