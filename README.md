# cybersec-intel

**Version 1.2.0** · Python 3.9+ · MIT license · [Changelog](CHANGELOG.md)

A single-file terminal tool for threat intelligence: live threat feeds, indicator lookups, passive site reputation checks and CVE → exploit search. It runs as an interactive screen (TUI) or as one-shot commands, and uses only free API tiers and keyless services.

All lookups are **passive**: the tool asks third-party engines about an indicator and never connects to the target itself.

## Requirements

- Python 3.9+ (standard library only, no `pip install`)
- Linux terminal with `curses` support
- Optional, for local exploit search: `exploitdb` (searchsploit), `metasploit-framework`, `nuclei` templates — all present on Kali by default

## Install

```bash
git clone https://github.com/hunt3r-1/cybersec-intel.git
cd cybersec-intel
./install.sh
```

`install.sh` creates `.env` from `.env.example` (mode `600`) and puts a `cybersec-intel` launcher in `~/.local/bin` that runs `intel.py` from this folder. `./uninstall.sh` removes the launcher and leaves the folder alone.

No installer needed if you prefer: copy `.env.example` to `.env` and run `python3 intel.py`.

## Run

```bash
cybersec-intel                 # interactive screen
python3 intel.py               # same, from this folder
cybersec-intel --version
```

## API keys

Keys are read from the `.env` file next to `intel.py` (template: `.env.example`). Every key is optional and every service has a free tier. A missing key only disables that source; everything else keeps working.

| Variable | Service | Used for |
|---|---|---|
| `VT_API_KEY` | VirusTotal | reputation of IP, domain, URL, hash; deep mode relations and sandbox behaviour |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IP abuse score, attack categories, /24 block check, blacklist feed |
| `OTX_API_KEY` | AlienVault OTX | pulses, passive DNS, linked malware, CVE exploit intel, subscribed pulses feed |
| `NVD_API_KEY` | NVD | CVE detail, critical CVE feed, CISA KEV feed (key raises the rate limit) |
| `SHODAN_API_KEY` | Shodan | host lookup: services, versions, TLS certificates |
| `URLHAUS_AUTH_KEY` | abuse.ch | one key for URLhaus, ThreatFox and MalwareBazaar |
| `MYTHREATINTEL_TOKEN` | MyThreatIntel | optional leaks / IOC source |

Keyless sources, always on: Shodan InternetDB, Shodan CVEDB, CIRCL, OSV, FIRST EPSS, RDAP, crt.sh, and the nomi-sec PoC-in-GitHub index.

Keep `.env` at mode `600`. The tool never prints keys and keeps them out of its cache file.

## Indicators

| Type | Example |
|---|---|
| IPv4 / IPv6 | `8.8.8.8`, `2606:4700:4700::1111` |
| Domain | `example.org` |
| URL | `http://example.org/path` |
| File hash | MD5, SHA-1 or SHA-256 |
| CVE | `CVE-2021-44228` |
| Advisory | `GHSA-xxxx-xxxx-xxxx`, `PYSEC-2024-1` |

Private and reserved addresses (`10.x`, `192.168.x`, `::1`, …) are rejected and never sent to any API.

## Interactive screen

| View | Key | What it shows |
|---|---|---|
| Dashboard | `F1` | which keys are loaded, help, today's quota use |
| Threat feed | `F2` | NVD critical/high CVEs (7d), CISA KEV additions (30d), ThreatFox IOCs (24h), URLhaus live URLs, OTX subscribed pulses, AbuseIPDB blacklist, CIRCL latest |
| Lookup | `F3` | everything known about one indicator |
| Site check | `F4` | passive reputation verdict (0–100) for a URL, domain or IP |

### Keys

| Key | Action |
|---|---|
| `F1`–`F4`, `←` `→` | switch view |
| `↑` `↓`, `PgUp` `PgDn`, `Home` | scroll (numpad 8/2/4/6 also works on dashboard and feed) |
| `Enter` | run the lookup / site check for the typed indicator |
| `Tab` | select mode: highlights rows that contain an IP, domain, hash, URL or CVE |
| `Enter` (in select mode) | pivot — look up the highlighted indicator |
| `Tab` / `Esc` (in select mode) | leave select mode |
| `Ctrl+B` | back to the previous lookup |
| `Ctrl+D` | deep mode for the current lookup (IP, domain, hash) |
| `r` | refresh feed / repeat site check |
| `Ctrl+E` | export the current view to CSV in `exports/` |
| `Ctrl+R` | save a Markdown report (lookup and site check) |
| `Esc` | clear the input line |
| `q` | quit (from dashboard or feed) |

Paste with `Ctrl+Shift+V`.

## Command line

```bash
cybersec-intel --lookup 8.8.8.8                  # one-shot lookup
cybersec-intel --lookup example.org --deep       # lookup plus deep mode
cybersec-intel --prescan http://example.org/x    # passive site check with verdict
cybersec-intel --poc CVE-2021-44228              # exploit / PoC search only
cybersec-intel --feed                            # print the threat feed
cybersec-intel --file targets.txt                # bulk lookup, one indicator per line
cybersec-intel --prescan-file sites.txt          # bulk site check with summary table
```

| Option | Meaning |
|---|---|
| `--lookup INDICATOR` | look up an IP, domain, URL, hash, CVE, GHSA or PYSEC id |
| `--prescan URL\|DOMAIN\|IP` | passive reputation check with a 0–100 score |
| `--poc CVE` | search public PoCs and ready-made exploits for a CVE |
| `--file PATH` | bulk lookup; `#` starts a comment, duplicates are skipped |
| `--prescan-file PATH` | bulk site check, ends with a score summary |
| `--deep` | with `--lookup` / `--file`: add deep-mode sources |
| `--feed` | print the threat feed and exit |
| `--csv PATH` | also write results to CSV (works with bulk modes) |
| `--json` | print JSON instead of the text view (an array in bulk modes) |
| `--version` | print the version |

Exit code is `2` when a single indicator is rejected (unrecognized or private).

## What each lookup returns

**IP** — Shodan host (services, versions, TLS, tags), Shodan InternetDB (ports, CVEs), AbuseIPDB (score, attack categories, latest reports), VirusTotal, ThreatFox, URLhaus, OTX pulses, OTX passive DNS and linked malware, RDAP network owner and abuse contact.

**Domain** — VirusTotal, ThreatFox, URLhaus, OTX pulses, OTX passive DNS, RDAP registration and domain age, crt.sh subdomains.

**URL** — URLhaus, VirusTotal, ThreatFox (by host), OTX.

**Hash** — VirusTotal, MalwareBazaar (family, tags, YARA, vendor verdicts), ThreatFox, OTX.

**CVE** — NVD (CVSS, CWE, affected products, KEV dates, exploit-tagged references), Shodan CVEDB (KEV, EPSS, ransomware use), PoC search (below), OTX CVE intel, CIRCL.

**GHSA / PYSEC** — OSV advisory, then the CVE engines and PoC search through the advisory's CVE alias.

### CVE → PoC search

- **GitHub** — public PoC repositories sorted by stars.
- **Local tools** (offline) — matching Exploit-DB entries, Metasploit modules with rank, and Nuclei templates, each with the command to use it.
- **OTX** — "seen in the wild" flag and exploit links.
- **NVD** — references tagged *Exploit*.

On IP lookups, every CVE that Shodan lists for the host shows its EPSS probability and a mark such as `[msf:2 edb:1 nuclei] EXPLOIT` when a ready exploit exists locally. Exploitable CVEs are listed first.

### Deep mode (`--deep` or `Ctrl+D`)

Opt-in, because VirusTotal's free tier allows 4 requests a minute.

| Indicator | Extra sources |
|---|---|
| IP | domains hosted on it, malware samples that contact it, AbuseIPDB report for the whole /24 |
| Domain | subdomains and resolved IPs, related malware samples |
| Hash | sandbox behaviour: verdicts, MITRE techniques, network contacts, DNS, processes, commands, dropped files, registry, Sigma rules |

## Site check score

Each source adds points; the total is capped at 100.

| Score | Verdict |
|---|---|
| 60–100 | MALICIOUS |
| 30–59 | SUSPICIOUS |
| 8–29 | WEAK SIGNALS |
| 0–7 | NO MAJOR SIGNALS |

Signals include VirusTotal detections and categories, URLhaus and ThreatFox listings, AbuseIPDB confidence, CVEs on exposed services, OTX pulses, and domain age (+20 under 30 days, +10 under 90 days).

## Limits and safety

- **Rate limits** are enforced per service; a slow service never blocks the others.
- **Daily quotas** stop a source before the free limit is reached: VirusTotal 450, AbuseIPDB 900, NVD 4000, AbuseIPDB block check 90, AbuseIPDB blacklist 4. Counters reset each day and show on the dashboard.
- **Cache**: answers are kept from 30 minutes to 24 hours depending on the source, in memory and in `.cache.json` (mode `600`). Repeat lookups cost no quota.
- **Terminal safety**: control characters are stripped from all remote text.
- **CSV safety**: cells that start with `=`, `+`, `-` or `@` are escaped.

## Known free-tier limits

- **Shodan** (free plan): host lookup is refused for some IPs with "Requires membership". This is per IP, not a rate limit; InternetDB still gives ports and CVEs for those. DNS lookups need a paid plan and are not used.
- **NVD** can be slow (20 s or more per query) or return 503. The feed section then shows a failure line; press `r` to retry.
- **crt.sh** sometimes times out. Retry later.

## Files

| Path | Purpose |
|---|---|
| `intel.py` | the whole tool |
| `.env.example` | key template; copy to `.env` |
| `install.sh`, `uninstall.sh` | add / remove the `cybersec-intel` launcher |
| `AGENTS.md` | quick reference for AI agents working on this code |
| `CHANGELOG.md` | release notes |
| `.env` | your API keys (git-ignored) |
| `.cache.json` | response cache (git-ignored) |
| `.state.json` | daily quota counters (git-ignored) |
| `exports/` | CSV exports and Markdown reports (git-ignored) |

## License

MIT — see [LICENSE](LICENSE).

## Legal

Use this tool only for systems and investigations you are authorized to work on. Exploit references are shown for authorized security testing and defense.
