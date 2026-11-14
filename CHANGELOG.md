# Changelog

## 1.2.0 — 2026-11-13

### Added
- **CVE → PoC search** (`--poc CVE`, and in every CVE lookup): public GitHub PoCs, local Exploit-DB / Metasploit / Nuclei matches with ready commands, OTX exploit links and "seen in the wild", NVD exploit-tagged references.
- **Exploit marks on hosts**: CVEs that Shodan lists for an IP show EPSS and `[msf edb nuclei] EXPLOIT` when a local exploit exists.
- **Deep mode** (`--deep`, `Ctrl+D`): VirusTotal hosted domains, subdomains, related malware, sandbox behaviour; AbuseIPDB /24 block report.
- **Pivoting** in the interactive screen: `Tab` selects a row, `Enter` looks it up, `Ctrl+B` goes back.
- **New sources**: Shodan host lookup, ThreatFox, MalwareBazaar, OTX passive DNS and linked malware, RDAP (domain age, network owner), crt.sh subdomains, FIRST EPSS.
- **New feeds**: CISA KEV additions, ThreatFox IOCs, OTX subscribed pulses, AbuseIPDB blacklist.
- **More detail**: NVD CWE, affected products and KEV dates; AbuseIPDB attack categories and latest reports.
- **CLI**: `--json`, `--file`, `--prescan-file`, `--deep`, `--poc`, `--version`. `--csv` works with bulk modes.
- IPv6 indicators.

### Changed
- NVD feed now filters critical/high on the server instead of sorting the first 60 CVEs of the week.
- Cache lifetime is per source (30 minutes to 24 hours) instead of 2 minutes for everything.
- One slow service no longer blocks requests to the others.
- Site check score is capped at 100 and now counts domain age and ThreatFox listings.
- Lookup and site check share one function per source.

### Fixed
- Invalid IPs such as `999.1.1.1` are rejected; private and reserved addresses are never sent to an API.
- URL paths keep their case (only scheme and host are lowercased).
- Blank rows in the CIRCL feed.
- URLhaus age calculation for entries added today.

### Security
- Control characters are stripped from all remote text before display.
- API keys passed in a URL are kept out of the cache file.

## 1.0.0 — 2026-08-21

- First version: dashboard, threat feed (NVD, URLhaus, CIRCL), indicator lookup, passive site check, CSV export and Markdown reports.
