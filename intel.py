#!/usr/bin/env python3
"""cybersec-intel: minimal terminal window for cybersecurity threat feeds and IOC lookups."""

import argparse
import base64
import csv
import curses
import datetime
import ipaddress
import json
import os
import queue
import re
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, OrderedDict
from concurrent.futures import ThreadPoolExecutor

VERSION = "1.2.0"

APP_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(APP_DIR, ".env")
STATE_FILE = os.path.join(APP_DIR, ".state.json")
DISK_CACHE = os.path.join(APP_DIR, ".cache.json")

DEFAULT_TTL = 300
FEED_COOLDOWN = 60
MIN, HOUR = 60, 3600

# how long an answer stays valid, per source (feeds pass their own shorter ttl)
HOST_TTL = {
    "services.nvd.nist.gov": 6 * HOUR,
    "cvedb.shodan.io": 12 * HOUR,
    "vulnerability.circl.lu": 6 * HOUR,
    "api.osv.dev": 12 * HOUR,
    "raw.githubusercontent.com": 6 * HOUR,
    "www.virustotal.com": 3 * HOUR,
    "api.abuseipdb.com": 1 * HOUR,
    "otx.alienvault.com": 1 * HOUR,
    "internetdb.shodan.io": 6 * HOUR,
    "api.shodan.io": 6 * HOUR,
    "urlhaus-api.abuse.ch": 30 * MIN,
    "threatfox-api.abuse.ch": 30 * MIN,
    "mb-api.abuse.ch": 6 * HOUR,
    "mythreatintel.secureit.es": 10 * MIN,
    "rdap.org": 24 * HOUR,
    "crt.sh": 12 * HOUR,
    "api.first.org": 12 * HOUR,
}

RATE_LIMITS = {
    "services.nvd.nist.gov": 6.5,
    "www.virustotal.com": 15.5,
    "api.abuseipdb.com": 2.0,
    "otx.alienvault.com": 1.0,
    "urlhaus-api.abuse.ch": 1.5,
    "threatfox-api.abuse.ch": 1.5,
    "mb-api.abuse.ch": 1.5,
    "internetdb.shodan.io": 1.1,
    "api.shodan.io": 1.1,
    "cvedb.shodan.io": 1.0,
    "vulnerability.circl.lu": 2.0,
    "mythreatintel.secureit.es": 1.0,
    "api.osv.dev": 0.5,
    "raw.githubusercontent.com": 0.5,
    "rdap.org": 1.0,
    "crt.sh": 2.0,
    "api.first.org": 1.0,
}

HOST_QUOTA = {
    "www.virustotal.com": "VirusTotal",
    "api.abuseipdb.com": "AbuseIPDB",
    "services.nvd.nist.gov": "NVD",
}

DAILY_LIMITS = {
    "VirusTotal": 450,
    "AbuseIPDB": 900,
    "NVD": 4000,
    "Abuse-block": 90,
    "Abuse-blacklist": 4,
}

QUOTA_VAR = {"VirusTotal": "VT_API_KEY", "AbuseIPDB": "ABUSEIPDB_API_KEY", "NVD": "NVD_API_KEY",
             "Abuse-block": "ABUSEIPDB_API_KEY", "Abuse-blacklist": "ABUSEIPDB_API_KEY"}

SOURCES = [
    ("MYTHREATINTEL_TOKEN", "MyThreatIntel"),
    ("NVD_API_KEY", "NVD"),
    ("VT_API_KEY", "VirusTotal"),
    ("ABUSEIPDB_API_KEY", "AbuseIPDB"),
    ("OTX_API_KEY", "AlienVault OTX"),
    ("SHODAN_API_KEY", "Shodan"),
    ("URLHAUS_AUTH_KEY", "abuse.ch URLhaus/ThreatFox/Bazaar"),
]

VAR_BY_NAME = {name: var for var, name in SOURCES}

RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
RE_CVE_ANY = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
RE_GHSA = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$", re.I)
RE_PYSEC = re.compile(r"^PYSEC-\d{4}-\d{1,6}$", re.I)
RE_HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
RE_URL = re.compile(r"^https?://\S+$", re.I)
RE_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
RE_KEYPARAM = re.compile(r"([?&]key=)[^&]+")

UNRECOGNIZED = "unrecognized indicator (IP, domain, URL, hash, CVE, PYSEC or GHSA)"


def clean_indicator(raw):
    txt = re.sub(r"\[20[01]~", "", str(raw))
    return "".join(ch for ch in txt if 32 <= ord(ch) <= 126).strip()


def clean_text(text):
    """Strip control characters so remote data cannot inject terminal escapes."""
    return "".join(ch if ch.isprintable() else " " for ch in str(text))


def classify(raw):
    """Return (kind, normalized indicator, error). kind is None when unrecognized."""
    ind = clean_indicator(raw)
    try:
        ip = ipaddress.ip_address(ind.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            return "ip", str(ip), f"{ip} is a private/reserved address - not sent to external APIs"
        return "ip", str(ip), None
    if RE_CVE.match(ind.upper()):
        return "cve", ind.upper(), None
    if RE_GHSA.match(ind):
        return "advisory", "GHSA" + ind[4:].lower(), None
    if RE_PYSEC.match(ind):
        return "advisory", ind.upper(), None
    if RE_HASH.match(ind.lower()):
        return "hash", ind.lower(), None
    if RE_URL.match(ind):
        parts = urllib.parse.urlsplit(ind)
        fixed = parts._replace(scheme=parts.scheme.lower(), netloc=parts.netloc.lower())
        return "url", urllib.parse.urlunsplit(fixed), None
    if RE_DOMAIN.match(ind.lower()):
        return "domain", ind.lower(), None
    return None, ind, UNRECOGNIZED


def detect(ind):
    return classify(ind)[0]


class Skip(Exception):
    pass


class QuotaExceeded(Skip):
    pass


class Bul(list):
    """A list that is always rendered one item per line."""


class Res:
    """Result of one source: labelled fields, a risk score and human notes."""

    def __init__(self, fields=None, score=0, notes=None, text=""):
        self.fields = list(fields or [])
        self.score = int(score)
        self.notes = list(notes or [])
        self.text = str(text or "")

    def lines(self):
        out = [f"+ {n}" for n in self.notes]
        if out:
            out.append("")
        for label, val in self.fields:
            if isinstance(val, (list, tuple)):
                items = [str(v) for v in val]
                short = (not isinstance(val, Bul) and all(len(i) <= 28 for i in items)
                         and sum(len(i) + 1 for i in items) <= 84)
                if not items:
                    out.append(f"{label:<10} -")
                elif short:
                    out.append(f"{label:<10} {','.join(items)}")
                else:
                    out.append(f"{label:<10} {len(items)}")
                    out += [f"  - {i[:104]}" for i in items]
            else:
                out.append(f"{label:<10} {val}")
        if self.text:
            out += [""] + textwrap.wrap(self.text, 96)[:6]
        return [clean_text(l) for l in out]

    def as_dict(self):
        data = OrderedDict()
        for label, val in self.fields:
            data[label.strip()] = list(val) if isinstance(val, (list, tuple)) else val
        d = {"score": self.score, "notes": self.notes, "data": data}
        if getattr(self, "all_names", None):
            d["all_names"] = self.all_names
        if self.text:
            d["summary"] = self.text
        return d


def unpack(result):
    """Normalize a job result (Res or plain row list) to (score, lines, raw)."""
    if isinstance(result, Res):
        return result.score, result.lines(), result.as_dict()
    rows = [clean_text(r) for r in result]
    return 0, rows, {"rows": rows}


def total_score(scores):
    return min(sum(scores), 100)


class Throttle:
    def __init__(self):
        self.lock = threading.Lock()
        self.next = {}

    def wait(self, host):
        interval = RATE_LIMITS.get(host)
        if not interval:
            return
        with self.lock:
            now = time.monotonic()
            at = max(now, self.next.get(host, 0.0))
            self.next[host] = at + interval
        if at > now:
            time.sleep(at - now)


THROTTLE = Throttle()

_cache = {}
_cache_lock = threading.Lock()
_disk_lock = threading.Lock()
DCACHE_MAX = 250
DCACHE_ENTRY_MAX = 120_000


def cache_get(key):
    with _cache_lock:
        hit = _cache.get(key)
        if hit and time.monotonic() < hit[0]:
            return hit[1]
        if hit:
            _cache.pop(key, None)
    return dcache_get(key)


def cache_set(key, value, ttl):
    with _cache_lock:
        _cache[key] = (time.monotonic() + ttl, value)
    dcache_set(key, value, ttl)


def _dcache_valid(entry, now):
    return (isinstance(entry, list) and len(entry) == 3
            and isinstance(entry[0], (int, float)) and isinstance(entry[1], (int, float))
            and now - entry[0] < entry[1])


def _dcache_load():
    try:
        with open(DISK_CACHE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _dcache_save(data):
    tmp = DISK_CACHE + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, DISK_CACHE)
    except OSError:
        pass


def dcache_get(key):
    with _disk_lock:
        entry = _dcache_load().get(key)
    if not _dcache_valid(entry, time.time()):
        return None
    return entry[2]


def dcache_set(key, value, ttl):
    try:
        if len(json.dumps(value)) > DCACHE_ENTRY_MAX:
            return
    except (TypeError, ValueError):
        return
    with _disk_lock:
        now = time.time()
        data = {k: v for k, v in _dcache_load().items() if k != key and _dcache_valid(v, now)}
        data[key] = [now, ttl, value]
        while len(data) > DCACHE_MAX:
            data.pop(next(iter(data)))
        _dcache_save(data)


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            st = json.load(fh)
        if st.get("date") == datetime.date.today().isoformat():
            return st
    except (OSError, ValueError):
        pass
    return {"date": datetime.date.today().isoformat(), "counts": {}}


_state_lock = threading.Lock()


def bump_daily(source):
    with _state_lock:
        st = load_state()
        counts = st.setdefault("counts", {})
        counts[source] = counts.get(source, 0) + 1
        tmp = STATE_FILE + ".tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(st, fh)
            os.replace(tmp, STATE_FILE)
        except OSError:
            pass
        return counts[source]


def check_quota(source):
    used = load_state().get("counts", {}).get(source, 0)
    limit = DAILY_LIMITS.get(source)
    if limit is not None and used >= limit:
        raise QuotaExceeded(f"daily safety quota reached ({used}/{limit}), source paused until tomorrow")


def quota_summary():
    counts = load_state().get("counts", {})
    parts = [f"{name} {counts.get(name, 0)}/{DAILY_LIMITS[name]}"
             for name in DAILY_LIMITS if ENV.get(QUOTA_VAR[name])]
    return "quota today: " + (", ".join(parts) or "no metered keys")


def load_env():
    env = {}
    try:
        with open(ENV_FILE, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    except OSError:
        pass
    return env


ENV = load_env()
if ENV.get("NVD_API_KEY"):
    RATE_LIMITS["services.nvd.nist.gov"] = 0.7


def need(var):
    val = ENV.get(var)
    if not val:
        raise Skip(f"{var} not set, source skipped")
    return val


def http_json(url, headers=None, data=None, timeout=12, json_body=None, ttl=None, shape=None,
              quota=None):
    """GET/POST returning parsed JSON, with throttle, quota and cache.

    shape: optional function that slims the parsed answer before it is cached.
    """
    host = urllib.parse.urlsplit(url).netloc
    if json_body is not None:
        sig = json.dumps(json_body, sort_keys=True)
    else:
        sig = urllib.parse.urlencode(sorted((data or {}).items()))
    key = RE_KEYPARAM.sub(r"\1*", url) + "|" + sig
    cached = cache_get(key)
    if cached is not None:
        return cached
    quota = quota or HOST_QUOTA.get(host)
    if quota:
        check_quota(quota)
    hdrs = {"User-Agent": f"cybersec-intel/{VERSION} (threat-intel-dashboard)"}
    hdrs.update(headers or {})
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif data is not None:
        body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, headers=hdrs, data=body,
                                 method="POST" if body is not None else "GET")
    raw = b""
    for attempt in (0, 1):
        THROTTLE.wait(host)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            break
        except urllib.error.HTTPError as exc:
            if exc.code in (502, 503, 504) and attempt == 0:
                time.sleep(2)
                continue
            raise
    parsed = json.loads(raw.decode(errors="replace"))
    if shape:
        parsed = shape(parsed)
    cache_set(key, parsed, ttl or HOST_TTL.get(host, DEFAULT_TTL))
    if quota:
        bump_daily(quota)
    return parsed


def g(obj, *path, default="-"):
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur in (None, "") else cur


def dump_lines(data, width=96, limit=12):
    txt = json.dumps(data, ensure_ascii=False)
    wrapped = textwrap.wrap(txt, width) or ["null"]
    extra = len(wrapped) - limit
    return wrapped[:limit] + ([f"... (+{extra} more lines)"] if extra > 0 else [])


def days_since(stamp):
    try:
        then = datetime.datetime.strptime(str(stamp)[:10], "%Y-%m-%d")
    except ValueError:
        return None
    return max((datetime.datetime.now() - then).days, 0)


# --------------------------------------------------------------------------
# local exploit indexes (Exploit-DB, Metasploit, Nuclei) - offline, no quota
# --------------------------------------------------------------------------

EDB_CSV = "/usr/share/exploitdb/files_exploits.csv"
MSF_META = "/usr/share/metasploit-framework/db/modules_metadata_base.json"
MSF_RANK = {600: "excellent", 500: "great", 400: "good", 300: "normal",
            200: "average", 100: "low", 0: "manual"}

_local = {}
_local_lock = threading.Lock()


def _edb_index():
    idx = {}
    try:
        with open(EDB_CSV, encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                for code in set(c.upper() for c in RE_CVE_ANY.findall(row.get("codes") or "")):
                    idx.setdefault(code, []).append({
                        "id": row.get("id", "?"), "title": row.get("description", ""),
                        "type": row.get("type", ""), "platform": row.get("platform", ""),
                        "verified": row.get("verified") == "1", "date": row.get("date_published", "")})
    except OSError:
        return None
    for rows in idx.values():
        rows.sort(key=lambda e: (not e["verified"], e["date"]), reverse=False)
    return idx


def _msf_index():
    try:
        with open(MSF_META, encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, ValueError):
        return None
    idx = {}
    for mod in meta.values():
        if not isinstance(mod, dict):
            continue
        for ref in mod.get("references") or []:
            if str(ref).upper().startswith("CVE-"):
                idx.setdefault(str(ref).upper(), []).append({
                    "name": mod.get("fullname", "?"), "rank": MSF_RANK.get(mod.get("rank"), "?"),
                    "order": (not str(mod.get("fullname", "")).startswith("exploit/"),
                              -(mod.get("rank") or 0)),
                    "date": str(mod.get("disclosure_date") or "")[:10]})
    for mods in idx.values():
        mods.sort(key=lambda m: m["order"])
    return idx


def _nuclei_dirs():
    dirs = []
    try:
        with open(os.path.expanduser("~/.config/nuclei/.templates-config.json"), encoding="utf-8") as fh:
            dirs.append(json.load(fh).get("nuclei-templates-directory"))
    except (OSError, ValueError):
        pass
    dirs += [os.path.expanduser("~/nuclei-templates"), os.path.expanduser("~/.local/nuclei-templates")]
    seen = []
    for d in dirs:
        if d and os.path.isdir(d) and d not in seen:
            seen.append(d)
    return seen


def _nuclei_index():
    dirs = _nuclei_dirs()
    if not dirs:
        return None
    idx = {}
    for base in dirs:
        for root, subdirs, files in os.walk(base):
            subdirs[:] = [s for s in subdirs if not s.startswith(".")]
            for name in files:
                stem, ext = os.path.splitext(name)
                if ext in (".yaml", ".yml") and RE_CVE.match(stem.upper()):
                    idx.setdefault(stem.upper(), []).append(os.path.relpath(os.path.join(root, name), base))
    return idx


def local_exploits(cve):
    """Exploits for a CVE in local tool databases. A value of None means tool not installed."""
    with _local_lock:
        if not _local:
            _local.update(edb=_edb_index(), msf=_msf_index(), nuclei=_nuclei_index())
    cve = cve.upper()
    return {k: (None if idx is None else idx.get(cve, [])) for k, idx in _local.items()}


def exploit_marks(cve):
    loc = local_exploits(cve)
    parts = []
    if loc["msf"]:
        parts.append(f"msf:{len(loc['msf'])}")
    if loc["edb"]:
        parts.append(f"edb:{len(loc['edb'])}")
    if loc["nuclei"]:
        parts.append("nuclei")
    return f"[{' '.join(parts)}]" if parts else ""


def epss_scores(cves):
    """EPSS exploitation probability per CVE (FIRST.org, keyless). Empty on failure."""
    scores = {}
    ids = sorted({str(c).upper() for c in cves if RE_CVE.match(str(c).upper())})
    for i in range(0, min(len(ids), 240), 80):
        try:
            d = http_json("https://api.first.org/data/v1/epss?cve=" + ",".join(ids[i:i + 80]), timeout=12)
        except (urllib.error.URLError, TimeoutError, ValueError):
            break
        for row in d.get("data") or []:
            try:
                scores[str(row["cve"]).upper()] = float(row["epss"])
            except (KeyError, TypeError, ValueError):
                continue
    return scores


def epss_txt(value):
    return f"EPSS {value * 100:5.1f}%" if value is not None else "EPSS     -"


def mark_vulns(vulns, limit=10):
    """Annotate CVE ids with EPSS and local exploit availability, most usable first."""
    epss = epss_scores(vulns) if vulns else {}
    marked = [(v, exploit_marks(v), epss.get(str(v).upper())) for v in vulns]
    marked.sort(key=lambda x: (not x[1], -(x[2] or 0), x[0]))
    rows = [f"{v:<16} {epss_txt(e)}{f'  {m} EXPLOIT' if m else ''}" for v, m, e in marked[:limit]]
    extra = len(marked) - limit
    if extra > 0:
        rows.append(f"... +{extra} more")
    return Bul(rows), sum(1 for _v, m, _e in marked if m)


# --------------------------------------------------------------------------
# sources: one function per engine, used by both lookup and site check
# --------------------------------------------------------------------------

BAD_WORDS = ("malware", "phish", "scam", "fraud", "crack", "keygen", "warez",
             "pirat", "spyware", "spam", "unwanted", "malicious", "botnet",
             "payload", "trojan", "downloader", "c2")
PULSE_BAD = ("ransom", "malware", "c2", "phish", "stealer", "botnet",
             "exploit", "fraud", "loader", "dropper")


def mti(source, **params):
    tok = need("MYTHREATINTEL_TOKEN")
    qs = urllib.parse.urlencode({"source": source, **params})
    d = http_json(f"https://mythreatintel.secureit.es/api/?{qs}",
                  {"Authorization": f"Bearer {tok}"})
    return dump_lines(d)


def src_mti_ioc(ind):
    return Res([("Raw", Bul(mti("iocs", indicator=ind)))],
               notes=["MyThreatIntel knows this indicator"])


def vt_stats(attrs):
    st = attrs.get("last_analysis_stats") or {}
    order = ["malicious", "suspicious", "harmless", "undetected", "timeout"]
    return " ".join(f"{k}:{st.get(k, 0)}" for k in order)


def src_vt(kind, ind):
    key = need("VT_API_KEY")
    if kind == "url":
        path = "urls/" + base64.urlsafe_b64encode(ind.encode()).decode().rstrip("=")
    elif kind == "ip":
        path = "ip_addresses/" + urllib.parse.quote(ind, safe=":")
    elif kind == "hash":
        path = "files/" + urllib.parse.quote(ind)
    else:
        path = "domains/" + urllib.parse.quote(ind)
    try:
        d = http_json(f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": key})
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise Skip("not found in VirusTotal")
        raise
    a = (d.get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
    score = min(mal * 6, 45) + min(sus * 3, 15)
    cats = [f"{k}:{v}" for k, v in (a.get("categories") or {}).items()]
    hits = sorted(c for c in set(cats) if any(w in c.lower() for w in BAD_WORDS))
    score += min(len(hits) * 8, 24)
    notes = []
    if mal:
        notes.append(f"{mal} VT engines flag it malicious")
    if hits:
        notes.append("VT categories: " + ", ".join(hits[:3]))
    fields = [("Engines", vt_stats(a))]
    if kind == "ip":
        fields += [("Reputation", g(a, "reputation")),
                   ("Location", f"{g(a, 'country')}  AS{g(a, 'asn')} {g(a, 'as_owner')}")]
    elif kind == "domain":
        dns = [f"{r.get('type', '?')} {r.get('value', '')}" for r in (a.get("last_dns_records") or [])[:6]]
        fields += [("Categories", ", ".join(cats[:4]) or "-"),
                   ("Reputation", g(a, "reputation")),
                   ("Registrar", g(a, "registrar")),
                   ("DNS", Bul(dns))]
    elif kind == "url":
        fields += [("Categories", ", ".join(cats[:4]) or "-"),
                   ("Final URL", str(g(a, "last_final_url"))[:90])]
    else:
        fields += [("Label", g(a, "popular_threat_classification", "suggested_threat_label")),
                   ("Type", f"{g(a, 'type_description')}  tags:{','.join((a.get('type_tags') or [])[:6])}"),
                   ("Name", g(a, "meaningful_name")),
                   ("Size", g(a, "size"))]
    return Res(fields, score, notes)


def src_urlhaus(kind, ind):
    hdr = {"Auth-Key": need("URLHAUS_AUTH_KEY")}
    if kind == "url":
        d = http_json("https://urlhaus-api.abuse.ch/v1/url/", hdr, {"url": ind})
        info = d.get("urlinfo") or (d if d.get("query_status") == "ok" else {})
        entries = [info] if d.get("query_status") == "ok" else []
        tags = info.get("tags") or []
        status = g(info, "url_status")
    else:
        d = http_json("https://urlhaus-api.abuse.ch/v1/host/", hdr, {"host": ind})
        entries = d.get("urls") or []
        tags = sorted({str(t) for u in entries for t in (u.get("tags") or [])})[:6]
        online = sum(1 for u in entries if u.get("url_status") == "online")
        status = f"{online} online / {len(entries)} total"
    if not entries:
        return Res([("Listed", "no")])
    threat = g(entries[0], "threat")
    ages = [a for a in (days_since(u.get("date_added")) for u in entries) if a is not None]
    newest = min(ages) if ages else None
    if newest is None or newest <= 90:
        age = f"{newest}d old" if newest is not None else "age unknown"
        score, notes = 35, [f"URLhaus lists it ({threat if threat != '-' else 'malware'}, {age})"]
    else:
        score, notes = 12, [f"URLhaus historic listing only ({newest}d old)"]
    return Res([("Listed", "YES" + (f"  ({len(entries)} URL(s) seen)" if kind != "url" else "")),
                ("Status", status),
                ("Threat", threat),
                ("Tags", list(tags)),
                ("First seen", str(g(entries[-1], "date_added"))[:19])], score, notes)


def otx_base(kind, ind):
    if kind == "ip":
        return "IPv6" if ":" in ind else "IPv4"
    return {"domain": "domain", "url": "url", "hash": "file"}[kind]


def otx_get(path, timeout=15, shape=None):
    return http_json(f"https://otx.alienvault.com/api/v1/{path}",
                     {"X-OTX-API-KEY": need("OTX_API_KEY")}, timeout=timeout, shape=shape)


def src_otx(kind, ind):
    d = otx_get(f"indicators/{otx_base(kind, ind)}/{urllib.parse.quote(ind, safe=':/')}/general")
    pi = d.get("pulse_info") or {}
    names = [str(p.get("name", "?")) for p in (pi.get("pulses") or [])]
    count = pi.get("count", 0)
    hits = [n for n in names if any(w in n.lower() for w in PULSE_BAD)]
    score = min(count // 5, 4) + min(len(hits) * 3, 9)
    notes = []
    if hits:
        notes.append(f"{len(hits)} OTX pulse(s) reference threats")
    elif count:
        notes.append(f"referenced in {count} community pulses")
    fields = [("Pulses", count)]
    if names:
        fields.append(("Names", Bul(n[:70] for n in names[:5])))
    for key in ("country_name", "asn"):
        if d.get(key):
            fields.append((key, d[key]))
    return Res(fields, score, notes)


def src_otx_related(kind, ind):
    """Passive DNS history and malware samples seen talking to an IP/domain."""
    base = otx_base(kind, ind)
    fields = []
    try:
        d = otx_get(f"indicators/{base}/{ind}/passive_dns", timeout=20,
                    shape=lambda x: {"count": x.get("count", 0),
                                     "passive_dns": (x.get("passive_dns") or [])[:40]})
        recs = d.get("passive_dns") or []
        seen, rows = set(), []
        for r in recs:
            other = r.get("hostname") if kind == "ip" else r.get("address")
            if not other or other in seen or other == ind:
                continue
            seen.add(other)
            rows.append(f"{str(r.get('last', ''))[:10]}  {str(r.get('record_type', '')):<5} {other}")
        fields += [("pDNS recs", d.get("count", len(recs))), ("pDNS", Bul(rows[:10]))]
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        fields.append(("pDNS", f"unavailable ({type(exc).__name__})"))
    notes = []
    try:
        m = otx_get(f"indicators/{base}/{ind}/malware", timeout=20,
                    shape=lambda x: {"count": x.get("count", 0), "data": (x.get("data") or [])[:8]})
        samples = m.get("data") or []
        rows = []
        for s in samples:
            det = next((str(v) for v in (s.get("detections") or {}).values() if v), "")
            rows.append(f"{str(s.get('hash', '?'))[:64]}  {det[:34]}")
        fields += [("Malware", m.get("count", len(samples))), ("Samples", Bul(rows[:6]))]
        if samples:
            notes.append(f"{m.get('count', len(samples))} malware sample(s) linked on OTX")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        fields.append(("Malware", f"unavailable ({type(exc).__name__})"))
    return Res(fields, 0, notes)


ABUSE_CATS = {1: "DNS compromise", 2: "DNS poisoning", 3: "fraud orders", 4: "DDoS", 5: "FTP brute-force",
              6: "ping of death", 7: "phishing", 8: "fraud VoIP", 9: "open proxy", 10: "web spam",
              11: "email spam", 12: "blog spam", 13: "VPN IP", 14: "port scan", 15: "hacking",
              16: "SQL injection", 17: "spoofing", 18: "brute-force", 19: "bad web bot",
              20: "exploited host", 21: "web app attack", 22: "SSH", 23: "IoT targeted"}


def _slim_abuse(d):
    a = dict(d.get("data") or {})
    reports = a.pop("reports", None) or []
    cats = Counter(c for r in reports for c in (r.get("categories") or []))
    a["_cats"] = cats.most_common(6)
    a["_recent"] = [{"at": str(r.get("reportedAt", ""))[:16], "cc": r.get("reporterCountryCode") or "??",
                     "comment": str(r.get("comment") or "")[:90]} for r in reports[:4]]
    return {"data": a}


def src_abuse(ip):
    key = need("ABUSEIPDB_API_KEY")
    d = http_json("https://api.abuseipdb.com/api/v2/check?"
                  + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}),
                  {"Key": key, "Accept": "application/json"}, shape=_slim_abuse)
    a = d.get("data") or {}
    conf = int(a.get("abuseConfidenceScore") or 0)
    fields = [("Abuse", f"{conf}%  reports:{a.get('totalReports', 0)}  reporters:{a.get('numDistinctUsers', 0)}"),
              ("Location", f"{g(a, 'countryCode')}  usage:{g(a, 'usageType')}"),
              ("ISP", f"{g(a, 'isp')}  ({g(a, 'domain')})"),
              ("Tor", f"{a.get('isTor', False)}  whitelisted:{a.get('isWhitelisted', False)}"),
              ("Last seen", str(g(a, "lastReportedAt"))[:16])]
    cats = [f"{ABUSE_CATS.get(c, c)} x{n}" for c, n in a.get("_cats") or []]
    if cats:
        fields.append(("Attacks", Bul(cats)))
    recent = [f"{r['at']} {r['cc']}  {r['comment']}" for r in a.get("_recent") or []]
    if recent:
        fields.append(("Reports", Bul(recent)))
    notes = [f"AbuseIPDB confidence {conf}%"] if conf >= 25 else []
    return Res(fields, min(conf // 2, 40), notes)


def src_inetdb(ip):
    try:
        d = http_json(f"https://internetdb.shodan.io/{urllib.parse.quote(ip, safe=':')}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise Skip("not indexed by Shodan InternetDB")
        raise
    if d.get("detail"):
        raise Skip(f"InternetDB: {d['detail']}")
    vulns = d.get("vulns") or []
    rows, exploitable = mark_vulns(vulns)
    fields = [("Ports", [str(p) for p in d.get("ports") or []]),
              ("Hostnames", (d.get("hostnames") or [])[:4]),
              ("CPEs", Bul((d.get("cpes") or [])[:6])),
              ("Tags", d.get("tags") or [])]
    if vulns:
        fields.append(("Vulns", rows))
    else:
        fields.append(("Vulns", 0))
    notes = [f"{len(vulns)} CVEs on exposed services"] if vulns else []
    if exploitable:
        notes.append(f"{exploitable} of them have a local exploit (msf/edb/nuclei)")
    return Res(fields, min(len(vulns) * 4, 20), notes)


def _slim_shodan(d):
    svcs, seen = [], set()
    for s in d.get("data") or []:
        ident = (s.get("port"), s.get("transport"))
        if ident in seen:
            continue
        seen.add(ident)
        cert = (s.get("ssl") or {}).get("cert") or {}
        http = s.get("http") or {}
        svcs.append({"port": s.get("port"), "transport": s.get("transport", "tcp"),
                     "product": s.get("product"), "version": s.get("version"),
                     "module": (s.get("_shodan") or {}).get("module"),
                     "cn": (cert.get("subject") or {}).get("CN"),
                     "issuer": (cert.get("issuer") or {}).get("O") or (cert.get("issuer") or {}).get("CN"),
                     "expires": str(cert.get("expires") or "")[:8], "expired": cert.get("expired"),
                     "title": http.get("title"), "server": http.get("server"), "waf": http.get("waf"),
                     "vulns": sorted((s.get("vulns") or {}).keys()),
                     "seen": str(s.get("timestamp") or "")[:10]})
    slim = {k: d.get(k) for k in ("org", "isp", "asn", "os", "country_code", "city", "hostnames",
                                  "domains", "tags", "last_update", "ports")}
    slim["vulns"] = sorted(set(d.get("vulns") or []) | {v for s in svcs for v in s["vulns"]})
    slim["services"] = sorted(svcs, key=lambda s: s["port"] or 0)[:40]
    return slim


SHODAN_BAD_TAGS = {"c2", "malware", "compromised", "botnet"}


def src_shodan_host(ip):
    key = need("SHODAN_API_KEY")
    try:
        d = http_json(f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip, safe=':')}?key={key}",
                      timeout=25, shape=_slim_shodan)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise Skip("no Shodan data for this IP")
        if exc.code == 401:
            raise Skip("Shodan key rejected")
        if exc.code == 403:
            raise Skip("Shodan free plan does not cover this IP (membership needed) - use InternetDB data")
        raise
    rows = []
    for s in d.get("services") or []:
        what = " ".join(str(x) for x in (s.get("product"), s.get("version")) if x) or (s.get("module") or "?")
        extra = []
        if s.get("title"):
            extra.append(f'"{str(s["title"]).strip()[:30]}"')
        if s.get("waf"):
            extra.append(f"waf:{s['waf']}")
        if s.get("cn"):
            exp = s.get("expires") or ""
            when = f"{exp[:4]}-{exp[4:6]}-{exp[6:8]}" if len(exp) == 8 else "?"
            flag = " EXPIRED" if s.get("expired") else ""
            extra.append(f"tls:{str(s['cn'])[:28]} exp {when}{flag}")
        rows.append(f"{s.get('port')}/{s.get('transport')}  {what[:34]}  {' '.join(extra)}".rstrip())
    tags = d.get("tags") or []
    bad = sorted(SHODAN_BAD_TAGS & {str(t).lower() for t in tags})
    vulns = d.get("vulns") or []
    fields = [("Org", f"{g(d, 'org')}  ({g(d, 'isp')})  {g(d, 'asn')}"),
              ("Location", f"{g(d, 'country_code')} {g(d, 'city')}"),
              ("OS", g(d, "os")),
              ("Hostnames", Bul((d.get("hostnames") or [])[:6])),
              ("Tags", tags),
              ("Updated", str(g(d, "last_update"))[:10]),
              ("Ports", [str(p) for p in sorted(d.get("ports") or [])]),
              ("Services", Bul(rows[:20]))]
    notes = []
    if vulns:
        marked, exploitable = mark_vulns(vulns)
        fields.append(("Vulns", marked))
        if exploitable:
            notes.append(f"{exploitable} Shodan-listed CVE(s) have a local exploit")
    if bad:
        notes.append("Shodan tags: " + ", ".join(bad))
    return Res(fields, 15 if bad else 0, notes)


def _tf_host(item):
    ioc, typ = str(item.get("ioc", "")), item.get("ioc_type")
    if typ == "url":
        return (urllib.parse.urlsplit(ioc).hostname or "").lower()
    if typ == "ip:port":
        return ioc.rsplit(":", 1)[0]
    return ioc.lower()


def threatfox(body, timeout=20, ttl=None, shape=None):
    return http_json("https://threatfox-api.abuse.ch/api/v1/", {"Auth-Key": need("URLHAUS_AUTH_KEY")},
                     json_body=body, timeout=timeout, ttl=ttl, shape=shape)


def src_threatfox(kind, ind):
    term = (urllib.parse.urlsplit(ind).hostname or ind) if kind == "url" else ind
    d = threatfox({"query": "search_ioc", "search_term": term, "exact_match": False})
    items = d.get("data") if isinstance(d.get("data"), list) else []
    if kind == "hash" and not items:
        d = threatfox({"query": "search_hash", "hash": ind})
        items = d.get("data") if isinstance(d.get("data"), list) else []
    if kind != "hash":
        host = term.lower()
        items = [x for x in items
                 if _tf_host(x) == host or (kind != "ip" and _tf_host(x).endswith("." + host))]
    if not items:
        return Res([("Listed", "no")])
    conf = max(int(x.get("confidence_level") or 0) for x in items)
    families = sorted({str(x.get("malware_printable") or x.get("malware") or "?") for x in items})
    threats = sorted({str(x.get("threat_type") or "?") for x in items})
    tags = sorted({str(t) for x in items for t in (x.get("tags") or [])})[:8]
    firsts = sorted(str(x.get("first_seen") or "")[:10] for x in items if x.get("first_seen"))
    lasts = sorted(str(x.get("last_seen") or x.get("first_seen") or "")[:10] for x in items)
    rows = [f"{str(x.get('ioc', '?'))[:60]}  {x.get('malware_printable', '?')} {x.get('confidence_level', '?')}%"
            for x in items[:6]]
    score = 35 if conf >= 75 else 25 if conf >= 50 else 12
    what = "host of this URL" if kind == "url" else "it"
    notes = [f"ThreatFox lists {what} as {', '.join(threats[:2])} ({', '.join(families[:2])}, confidence {conf}%)"]
    return Res([("Listed", f"YES  ({len(items)} IOC(s))"),
                ("Malware", Bul(families[:6])),
                ("Threat", threats),
                ("Confidence", f"{conf}%"),
                ("Seen", f"{firsts[0] if firsts else '-'} .. {lasts[-1] if lasts else '-'}"),
                ("Tags", tags),
                ("IOCs", Bul(rows)),
                ("Reference", str(g(items[0], "reference"))[:96])], score, notes)


def _none(val):
    return "-" if val in (None, "", "None") else val


def src_bazaar(h):
    d = http_json("https://mb-api.abuse.ch/api/v1/", {"Auth-Key": need("URLHAUS_AUTH_KEY")},
                  {"query": "get_info", "hash": h}, timeout=20)
    if d.get("query_status") != "ok" or not d.get("data"):
        return Res([("Listed", "no")])
    s = d["data"][0]
    sig = _none(s.get("signature"))
    vendors = []
    for name, info in (s.get("vendor_intel") or {}).items():
        if not isinstance(info, dict):
            continue
        verdict = (info.get("malware_family") or info.get("family_name") or info.get("threat_name")
                   or info.get("verdict") or info.get("status") or info.get("detection"))
        if verdict:
            vendors.append(f"{name}: {str(verdict)[:60]}")
    yara = sorted({str(y.get("rule_name")) for y in (s.get("yara_rules") or []) if y.get("rule_name")})
    intel = s.get("intelligence") or {}
    fields = [("Listed", "YES"),
              ("Signature", sig),
              ("File", f"{_none(s.get('file_name'))}  {_none(s.get('file_type'))}  {_none(s.get('file_size'))} bytes"),
              ("SHA256", _none(s.get("sha256_hash"))),
              ("First seen", str(_none(s.get("first_seen")))[:19]),
              ("Delivery", f"{_none(s.get('delivery_method'))}  origin:{_none(s.get('origin_country'))}"),
              ("Tags", s.get("tags") or []),
              ("Downloads", f"{_none(intel.get('downloads'))}  uploads:{_none(intel.get('uploads'))}"),
              ("Vendors", Bul(vendors[:6])),
              ("YARA", Bul(yara[:8]))]
    label = sig if sig != "-" else "unclassified"
    return Res(fields, 45, [f"MalwareBazaar has this sample ({label})"])


# --------------------------------------------------------------------------
# CVE sources and PoC / exploit search
# --------------------------------------------------------------------------

def cvss_of(c, best=False):
    """(score, severity, vector) of an NVD CVE record, or None."""
    met = c.get("metrics") or {}
    found = []
    for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        top = None
        for m in met.get(name) or []:
            cd = m.get("cvssData") or {}
            sc = cd.get("baseScore")
            if isinstance(sc, (int, float)) and (top is None or sc > top[0]):
                top = (sc, str(cd.get("baseSeverity") or m.get("baseSeverity") or "").upper(),
                       str(cd.get("vectorString") or ""))
        if top:
            if not best:
                return top
            if name == "cvssMetricV2" and found:
                break
            found.append(top)
    return max(found, key=lambda t: t[0]) if found else None


def nvd_desc(c):
    return next((x.get("value", "") for x in c.get("descriptions") or [] if x.get("lang") == "en"), "")


def nvd_get(params, ttl=None, timeout=45):
    hdr = {"apiKey": ENV["NVD_API_KEY"]} if ENV.get("NVD_API_KEY") else None
    return http_json("https://services.nvd.nist.gov/rest/json/cves/2.0?" + params, hdr,
                     timeout=timeout, ttl=ttl)


def nvd_window(days):
    end = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    start = end - datetime.timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    return start.strftime(fmt), end.strftime(fmt)


def nvd_products(c):
    seen = OrderedDict()
    for conf in c.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = str(m.get("criteria", "")).split(":")
                if not m.get("vulnerable") or len(parts) < 6:
                    continue
                rng = ""
                if m.get("versionStartIncluding"):
                    rng += f">={m['versionStartIncluding']} "
                if m.get("versionStartExcluding"):
                    rng += f">{m['versionStartExcluding']} "
                if m.get("versionEndExcluding"):
                    rng += f"<{m['versionEndExcluding']}"
                if m.get("versionEndIncluding"):
                    rng += f"<={m['versionEndIncluding']}"
                label = rng.strip() or (parts[5] if parts[5] not in ("*", "-") else "all versions")
                vers = seen.setdefault(f"{parts[3]}:{parts[4]}", [])
                if label not in vers:
                    vers.append(label)
    return [f"{name}  {', '.join(v[:3])}{' ...' if len(v) > 3 else ''}" for name, v in list(seen.items())[:8]]


def src_nvd_cve(cve):
    d = nvd_get(urllib.parse.urlencode({"cveId": cve}))
    vulns = d.get("vulnerabilities") or []
    if not vulns:
        return Res([("Found", "not in NVD")])
    c = vulns[0].get("cve") or {}
    cv = cvss_of(c)
    cwes = sorted({x.get("value", "") for w in c.get("weaknesses") or []
                   for x in w.get("description") or [] if str(x.get("value", "")).startswith("CWE-")})
    refs = c.get("references") or []
    exploits = []
    for r in refs:
        if "Exploit" in (r.get("tags") or []) and r.get("url") not in exploits:
            exploits.append(r.get("url"))
    fields = [("ID", c.get("id", cve)),
              ("CVSS", f"{cv[0]}  ({cv[1] or '-'})  {cv[2]}" if cv else "-  (not scored yet)"),
              ("Published", f"{str(g(c, 'published'))[:10]}  status:{g(c, 'vulnStatus')}"),
              ("CWE", cwes)]
    notes = []
    if c.get("cisaExploitAdd"):
        fields.append(("KEV", f"YES  added {c['cisaExploitAdd']}  due {g(c, 'cisaActionDue')}  "
                              f"{str(g(c, 'cisaVulnerabilityName'))[:50]}"))
        notes.append("CISA KEV: exploited in the wild")
    else:
        fields.append(("KEV", "no"))
    products = nvd_products(c)
    if products:
        fields.append(("Affected", Bul(products)))
    fields.append(("References", len(refs)))
    if exploits:
        fields.append(("Exploit refs", Bul(str(u)[:104] for u in exploits[:6])))
        notes.append(f"{len(exploits)} NVD reference(s) tagged Exploit")
    return Res(fields, 0, notes, nvd_desc(c))


def src_cvedb(cve):
    try:
        d = http_json(f"https://cvedb.shodan.io/cve/{cve}", timeout=15)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise Skip("not found in Shodan CVEDB")
        raise
    epss, rank = d.get("epss"), d.get("ranking_epss")
    epss_txt = "-"
    if isinstance(epss, (int, float)):
        epss_txt = f"{epss * 100:.2f}% chance of exploitation in 30d"
        if isinstance(rank, (int, float)):
            epss_txt += f"  (top {max((1 - rank) * 100, 0.01):.2f}% of all CVEs)"
    fields = [("CVSS", g(d, "cvss")),
              ("KEV", "YES" if d.get("kev") else "no"),
              ("EPSS", epss_txt),
              ("Ransomware", g(d, "ransomware_campaign"))]
    if d.get("propose_action"):
        fields.append(("Action", str(d["propose_action"])[:96]))
    notes = ["Shodan CVEDB: known exploited (KEV)"] if d.get("kev") else []
    return Res(fields, 0, notes, str(d.get("summary") or ""))


def record_score(d):
    cont = d.get("containers") or {}
    blocks = list((cont.get("cna") or {}).get("metrics") or [])
    for adp in cont.get("adp") or []:
        blocks += adp.get("metrics") or []
    for m in blocks:
        block = m.get("cvssV3_1") or m.get("cvssV3_0") or m.get("cvssV4_0") or {}
        if block.get("baseScore") is not None:
            return (block["baseScore"], str(block.get("baseSeverity", "")).upper(),
                    str(block.get("vectorString", "")))
    legacy = d.get("cvss")
    return (legacy, "", "") if legacy not in (None, "") else ("-", "", "")


def src_circl_cve(cve):
    d = http_json(f"https://vulnerability.circl.lu/api/cve/{cve}", timeout=15)
    if not isinstance(d, dict) or not d:
        return Res([("Found", "not in CIRCL")])
    cna = (d.get("containers") or {}).get("cna") or {}
    desc = next((x.get("value", "") for x in cna.get("descriptions") or []
                 if x.get("lang") == "en"), "")
    score, sev, vector = record_score(d)
    summ = g(d, "summary")
    return Res([("CVSS", f"{score}  ({sev or '-'})  {vector}"),
                ("Published", str(g(d.get("cveMetadata") or {}, "datePublished"))[:10])],
               text=desc if summ == "-" else str(summ))


def _slim_poc(repos):
    repos = [r for r in repos if isinstance(r, dict)] if isinstance(repos, list) else []
    repos.sort(key=lambda r: -(r.get("stargazers_count") or 0))
    return {"total": len(repos),
            "top": [{"url": r.get("html_url"), "stars": r.get("stargazers_count") or 0,
                     "created": str(r.get("created_at") or "")[:7],
                     "desc": str(r.get("description") or "")[:60]} for r in repos[:10]]}


def src_poc_github(cve):
    """Public PoC repositories, from the nomi-sec/PoC-in-GitHub index (keyless)."""
    year = cve.split("-")[1]
    try:
        d = http_json(f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json",
                      timeout=15, shape=_slim_poc)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return Res([("Repos", "none tracked on GitHub")])
        raise
    if not d.get("total"):
        return Res([("Repos", "none tracked on GitHub")])
    rows = [f"{r['stars']:>5}*  {r['url']}  ({r['created']})" for r in d["top"]]
    return Res([("Repos", d["total"]), ("Top PoCs", Bul(rows))], 0,
               [f"{d['total']} public PoC repo(s) on GitHub"])


def src_poc_local(cve):
    """Exploit-DB, Metasploit and Nuclei databases installed on this machine."""
    loc = local_exploits(cve)
    fields, counts = [], []
    edb = loc["edb"]
    if edb is None:
        fields.append(("Exploit-DB", "not installed (apt install exploitdb)"))
    elif edb:
        rows = [f"EDB-{e['id']}  {e['type']}/{e['platform']}{' verified' if e['verified'] else ''}  "
                f"{e['title'][:60]}" for e in edb[:8]]
        fields += [("Exploit-DB", Bul(rows)), ("  copy it", f"searchsploit -m {edb[0]['id']}")]
        counts.append(f"{len(edb)} Exploit-DB")
    else:
        fields.append(("Exploit-DB", "none"))
    msf = loc["msf"]
    if msf is None:
        fields.append(("Metasploit", "not installed"))
    elif msf:
        fields += [("Metasploit", Bul(f"{m['name']}  (rank {m['rank']}, {m['date']})" for m in msf[:8])),
                   ("  use it", f"msfconsole -q -x 'use {msf[0]['name']}; info'")]
        counts.append(f"{len(msf)} Metasploit")
    else:
        fields.append(("Metasploit", "none"))
    nuc = loc["nuclei"]
    if nuc is None:
        fields.append(("Nuclei", "templates not found"))
    elif nuc:
        fields += [("Nuclei", Bul(nuc[:4])), ("  run it", f"nuclei -id {cve} -u <target>")]
        counts.append("Nuclei template")
    else:
        fields.append(("Nuclei", "none"))
    notes = ["ready-made exploit available: " + ", ".join(counts)] if counts else []
    return Res(fields, 0, notes)


def _slim_otx_cve(d):
    seen, rows = set(), []
    for e in d.get("exploits") or []:
        ident = e.get("url") or e.get("name")
        if not ident or ident in seen:
            continue
        seen.add(ident)
        rows.append({"url": e.get("url"), "name": e.get("name"), "source": e.get("source"),
                     "type": e.get("type"), "platform": e.get("platform")})
    return {"pulses": (d.get("pulse_info") or {}).get("count", 0), "seen_wild": d.get("seen_wild"),
            "epss": d.get("epss"), "n_exploits": len(rows), "exploits": rows[:10]}


def src_otx_cve(cve):
    try:
        d = otx_get(f"indicators/cve/{cve}/general", timeout=20, shape=_slim_otx_cve)
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 404):
            raise Skip("not found in OTX")
        raise
    rows = [f"{(e.get('source') or e.get('type') or '?')}: {str(e.get('url') or e.get('name'))[:90]}"
            for e in d.get("exploits") or []]
    fields = [("Seen wild", "YES" if d.get("seen_wild") else "no"),
              ("Pulses", d.get("pulses", 0)),
              ("Exploits", d.get("n_exploits", 0))]
    if rows:
        fields.append(("Links", Bul(rows)))
    notes = []
    if d.get("seen_wild"):
        notes.append("OTX: seen exploited in the wild")
    if d.get("n_exploits"):
        notes.append(f"OTX tracks {d['n_exploits']} exploit reference(s)")
    return Res(fields, 0, notes)


def src_osv_advisory(ind):
    try:
        d = http_json(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(ind)}", timeout=15)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise Skip(f"{ind} not found in OSV")
        raise
    aliases = [str(a) for a in d.get("aliases") or []]
    sev = next((s.get("score", "") for s in d.get("severity") or []
                if str(s.get("type", "")).startswith("CVSS")), "")
    pkgs = []
    for a in d.get("affected") or []:
        p = a.get("package") or {}
        fix = "-"
        for r in a.get("ranges") or []:
            for e in r.get("events") or []:
                if e.get("fixed"):
                    fix = e["fixed"]
        pkgs.append(f"{p.get('ecosystem', '?')}/{p.get('name', '?')} fixed:{fix}")
    return Res([("ID", d.get("id", ind)),
                ("Aliases", aliases[:6]),
                ("Severity", sev or "-"),
                ("Affected", Bul(pkgs[:5]))],
               text=str(d.get("summary") or d.get("details") or ""))


def advisory_cve(ind):
    """CVE alias of a GHSA/PYSEC advisory, so the CVE engines can be chained."""
    try:
        d = http_json(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(ind)}", timeout=15)
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None
    return next((str(a).upper() for a in d.get("aliases") or [] if RE_CVE.match(str(a).upper())), None)


# --------------------------------------------------------------------------
# feeds
# --------------------------------------------------------------------------

def feed_nvd():
    start, end = nvd_window(7)
    window = f"pubStartDate={start}&pubEndDate={end}&resultsPerPage=100"
    found, errors = {}, []

    def fetch(sev):
        try:
            return nvd_get(f"{window}&{sev}", ttl=15 * MIN, timeout=60)
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            errors.append(exc)
            return {}

    def collect(answers):
        for d in answers:
            for v in d.get("vulnerabilities") or []:
                c = v.get("cve") or {}
                cv = cvss_of(c, best=True)
                if c.get("id") and cv:
                    found.setdefault(c["id"], (cv[0], cv[1], str(c.get("published", ""))[:10],
                                               bool(c.get("cisaExploitAdd")), nvd_desc(c)))

    with ThreadPoolExecutor(max_workers=2) as ex:
        collect(ex.map(fetch, ("cvssV3Severity=CRITICAL", "cvssV4Severity=CRITICAL")))
    if len(found) < 15 and not errors:
        collect([fetch("cvssV3Severity=HIGH")])
    if not found and errors:
        raise errors[0]
    items = sorted(found.items(), key=lambda kv: (-kv[1][0], kv[0]))
    rows = [f"{sev:<8} {score:>4}  {cid:<16} {pub[5:]}  {'KEV ' if kev else ''}{desc[:66]}"
            for cid, (score, sev, pub, kev, desc) in items[:15]]
    return rows or ["no critical/high CVEs published in the last 7 days"]


def feed_kev():
    start, end = nvd_window(30)
    d = nvd_get(f"hasKev&kevStartDate={start}&kevEndDate={end}&resultsPerPage=100", ttl=30 * MIN)
    items = []
    for v in d.get("vulnerabilities") or []:
        c = v.get("cve") or {}
        cv = cvss_of(c, best=True)
        items.append((str(c.get("cisaExploitAdd", "")), c.get("id", "?"), cv[0] if cv else "-",
                      exploit_marks(c.get("id", "")), str(c.get("cisaVulnerabilityName") or nvd_desc(c))))
    items.sort(reverse=True)
    items = items[:12]
    epss = epss_scores(cid for _a, cid, _s, _m, _n in items)
    rows = [f"{added}  {cid:<16} {score:>4}  {epss_txt(epss.get(cid))}  {name[:46]}  {marks}".rstrip()
            for added, cid, score, marks, name in items]
    return rows or ["no CVEs added to CISA KEV in the last 30 days"]


def _slim_tf_feed(d):
    data = d.get("data") if isinstance(d.get("data"), list) else []
    fams = Counter(str(x.get("malware_printable") or "?") for x in data)
    keep = ("ioc", "ioc_type", "malware_printable", "confidence_level", "first_seen", "threat_type")
    return {"total": len(data), "families": fams.most_common(8),
            "latest": [{k: x.get(k) for k in keep} for x in data[:10]]}


def feed_threatfox():
    d = threatfox({"query": "get_iocs", "days": 1}, timeout=30, ttl=10 * MIN, shape=_slim_tf_feed)
    if not d.get("total"):
        return ["no IOCs reported in the last 24h"]
    rows = [f"{d['total']} IOCs in 24h - top: " + ", ".join(f"{n} x{c}" for n, c in d["families"][:6])]
    for x in d["latest"]:
        rows.append(f"{str(x.get('first_seen') or '')[5:16]}  {str(x.get('ioc_type') or ''):<11} "
                    f"{str(x.get('malware_printable') or '?')[:18]:<18} {str(x.get('ioc') or '')[:52]}")
    return rows


def feed_urlhaus():
    d = http_json("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/40/",
                  {"Auth-Key": need("URLHAUS_AUTH_KEY")}, ttl=5 * MIN)
    agg = OrderedDict()
    for u in d.get("urls") or []:
        h = str(u.get("host", "?"))
        if h not in agg:
            agg[h] = [1, str(u.get("threat", ""))[:22], str(u.get("date_added", ""))[:16]]
        else:
            agg[h][0] += 1
    rows = [f"{h:<26} x{v[0]:<3} {v[1]:<22} {v[2]}" for h, v in list(agg.items())[:10]]
    return rows or ["no live URLs returned"]


def _slim_pulses(d):
    out = []
    for p in d.get("results") or []:
        fams = [f.get("display_name") if isinstance(f, dict) else f for f in p.get("malware_families") or []]
        out.append({"name": p.get("name"), "modified": str(p.get("modified") or "")[:10],
                    "n": len(p.get("indicators") or []), "adversary": p.get("adversary"),
                    "families": [str(f) for f in fams if f][:3]})
    return {"results": out}


def feed_otx():
    d = otx_get("pulses/subscribed?limit=10", timeout=25, shape=_slim_pulses)
    rows = []
    for p in d.get("results") or []:
        who = " / ".join(x for x in ([p.get("adversary")] + (p.get("families") or [])) if x)
        rows.append(f"{p['modified']}  {p['n']:>4} IOCs  {str(p.get('name') or '?')[:56]}"
                    + (f"  [{who[:30]}]" if who else ""))
    return rows or ["no subscribed pulses (subscribe to authors on otx.alienvault.com)"]


def feed_circl():
    d = http_json("https://vulnerability.circl.lu/api/last", timeout=20, ttl=10 * MIN)
    rows = []
    for c in (d or []):
        cid = c.get("id") or (c.get("cveMetadata") or {}).get("cveId")
        summ = str(c.get("details") or "")
        if c.get("cveMetadata"):
            cna = (c.get("containers") or {}).get("cna") or {}
            summ = str(cna.get("title") or next((x.get("value", "") for x in cna.get("descriptions") or []
                                                 if str(x.get("lang", "")).startswith("en")), ""))
        if not cid:
            doc = c.get("document") or {}
            track = doc.get("tracking") or {}
            cid = track.get("id") or doc.get("title") or "?"
            cves = [str(v.get("cve")) for v in (c.get("vulnerabilities") or []) if v.get("cve")]
            if cves:
                cid = f"{cid}: {','.join(cves[:2])}"
            summ = summ or str(doc.get("title") or "")
        score = record_score(c)[0]
        label = str(score)
        if score == "-":
            for s in c.get("severity") or []:
                vec = str(s.get("score", ""))
                if vec.startswith("CVSS:"):
                    label = vec.split("/")[0] + "/.."
                    break
        rows.append(f"{str(cid)[:26]:<26} {label:>12}  {summ[:70]}")
        if len(rows) >= 10:
            break
    return rows or ["no data"]


# --------------------------------------------------------------------------
# deep mode (opt-in, costs quota) and keyless enrichment
# --------------------------------------------------------------------------

def epoch_day(value):
    try:
        return datetime.datetime.fromtimestamp(int(value), datetime.timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OverflowError, OSError):
        return "-"


def vt_get(path, shape=None, timeout=25):
    try:
        return http_json(f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": need("VT_API_KEY")},
                         timeout=timeout, shape=shape)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise Skip("not found in VirusTotal")
        raise


def _slim_vt_resolutions(d):
    rows = []
    for r in d.get("data") or []:
        a = r.get("attributes") or {}
        rows.append({"host": a.get("host_name"), "date": epoch_day(a.get("date")),
                     "mal": (a.get("host_name_last_analysis_stats") or {}).get("malicious", 0)})
    return {"count": (d.get("meta") or {}).get("count", len(rows)), "rows": rows}


def src_vt_resolutions(ip):
    """Domains that pointed at this IP (VirusTotal passive DNS)."""
    d = vt_get(f"ip_addresses/{urllib.parse.quote(ip, safe=':')}/resolutions?limit=20",
               shape=_slim_vt_resolutions)
    rows = [f"{r['date']}  {r['host']}" + (f"  malicious:{r['mal']}" if r["mal"] else "")
            for r in d.get("rows") or [] if r.get("host")]
    bad = sum(1 for r in d.get("rows") or [] if r.get("mal"))
    notes = [f"{bad} of the latest hosted domains are flagged malicious"] if bad else []
    return Res([("Total", d.get("count", len(rows))), ("Domains", Bul(rows))], 0, notes)


def _slim_vt_files(d):
    rows = []
    for f in d.get("data") or []:
        a = f.get("attributes") or {}
        st = a.get("last_analysis_stats") or {}
        rows.append({"sha256": f.get("id"), "mal": st.get("malicious", 0),
                     "total": sum(v for v in st.values() if isinstance(v, int)),
                     "label": g(a, "popular_threat_classification", "suggested_threat_label", default="")
                              or a.get("meaningful_name") or a.get("type_tag") or ""})
    rows.sort(key=lambda r: -r["mal"])
    return {"count": (d.get("meta") or {}).get("count", len(rows)), "files": rows}


def src_vt_files(kind, ind):
    """Files seen talking to this IP/domain in sandboxes."""
    base = "ip_addresses" if kind == "ip" else "domains"
    d = vt_get(f"{base}/{urllib.parse.quote(ind, safe=':')}/communicating_files?limit=10",
               shape=_slim_vt_files)
    files = d.get("files") or []
    rows = [f"{f['sha256']}  {f['mal']}/{f['total']}  {str(f['label'])[:26]}" for f in files]
    bad = sum(1 for f in files if f["mal"] >= 5)
    notes = [f"{bad} detected malware sample(s) communicate with it"] if bad else []
    return Res([("Total", d.get("count", len(files))), ("Files", Bul(rows))], 0, notes)


def _slim_vt_domain_rel(d):
    data = d.get("data") or {}
    rel = data.get("relationships") or {}
    dom = str(data.get("id") or "")
    subs = [str(x.get("id")) for x in (rel.get("subdomains") or {}).get("data") or [] if x.get("id")]
    ips = [str(x.get("id"))[:-len(dom)] for x in (rel.get("resolutions") or {}).get("data") or []
           if dom and str(x.get("id", "")).endswith(dom)]
    return {"subdomains": subs, "ips": ips,
            "more": bool(((rel.get("subdomains") or {}).get("meta") or {}).get("cursor"))}


def src_vt_domain_rel(dom):
    """Subdomains and resolved IPs known to VirusTotal, in one request."""
    d = vt_get(f"domains/{urllib.parse.quote(dom)}?relationships=subdomains,resolutions",
               shape=_slim_vt_domain_rel)
    subs, ips = d.get("subdomains") or [], d.get("ips") or []
    fields = [("Subdomains", Bul(subs)), ("Resolved", Bul(ips))]
    if d.get("more"):
        fields.append(("Note", "first 20 shown, VirusTotal knows more"))
    return Res(fields)


def _pick(item, *keys):
    if isinstance(item, dict):
        return next((str(item[k]) for k in keys if item.get(k)), "")
    return str(item)


def _slim_vt_behaviour(d):
    b = d.get("data") or {}

    def take(name, limit, *keys):
        seen = []
        for item in b.get(name) or []:
            txt = _pick(item, *keys)[:100]
            if txt and txt not in seen:
                seen.append(txt)
        return {"n": len(seen), "top": seen[:limit]}

    mitre = OrderedDict()
    for t in b.get("mitre_attack_techniques") or []:
        if isinstance(t, dict) and t.get("id"):
            mitre.setdefault(t["id"], str(t.get("signature_description") or "")[:70])
    traffic = []
    for t in b.get("ip_traffic") or []:
        if isinstance(t, dict) and t.get("destination_ip"):
            row = f"{t['destination_ip']}:{t.get('destination_port', '?')}/{t.get('transport_layer_protocol', '?')}"
            if row not in traffic:
                traffic.append(row)
    sigma = []
    for r in b.get("sigma_analysis_results") or []:
        if isinstance(r, dict) and r.get("rule_title"):
            row = f"[{r.get('rule_level', '?')}] {r['rule_title']}"[:100]
            if row not in sigma:
                sigma.append(row)
    return {"verdicts": [str(v) for v in b.get("verdicts") or []][:6],
            "tags": [str(t) for t in b.get("tags") or []][:8],
            "mitre": [f"{k}  {v}" for k, v in list(mitre.items())[:12]], "n_mitre": len(mitre),
            "traffic": {"n": len(traffic), "top": traffic[:8]},
            "sigma": {"n": len(sigma), "top": sigma[:6]},
            "dns": take("dns_lookups", 8, "hostname"),
            "processes": take("processes_created", 6),
            "commands": take("command_executions", 6),
            "dropped": take("files_dropped", 6, "path"),
            "registry": take("registry_keys_set", 6, "key"),
            "mutexes": take("mutexes_created", 5),
            "services": take("services_started", 5)}


def src_vt_behaviour(h):
    """What the sample did in VirusTotal sandboxes."""
    d = vt_get(f"files/{urllib.parse.quote(h)}/behaviour_summary", shape=_slim_vt_behaviour)
    fields = [("Verdicts", d.get("verdicts") or []), ("Tags", Bul(d.get("tags") or []))]
    if d.get("mitre"):
        fields.append((f"MITRE ({d.get('n_mitre', 0)})", Bul(d["mitre"])))
    for label, key in (("Contacts", "traffic"), ("DNS", "dns"), ("Processes", "processes"),
                       ("Commands", "commands"), ("Dropped", "dropped"), ("Registry", "registry"),
                       ("Mutexes", "mutexes"), ("Services", "services"), ("Sigma", "sigma")):
        block = d.get(key) or {}
        if block.get("n"):
            fields.append((f"{label} ({block['n']})", Bul(block.get("top") or [])))
    bad = [v for v in d.get("verdicts") or [] if v.upper() in ("MALWARE", "RANSOM", "TROJAN", "STEALER", "RAT")]
    notes = [f"sandbox verdict: {', '.join(bad)}"] if bad else []
    return Res(fields, 0, notes)


def _slim_abuse_block(d):
    a = d.get("data") or {}
    hosts = a.get("reportedAddress") or []
    hosts.sort(key=lambda h: (-(h.get("abuseConfidenceScore") or 0), -(h.get("numReports") or 0)))
    return {"network": f"{a.get('minAddress')} - {a.get('maxAddress')}",
            "possible": a.get("numPossibleHosts") or 256, "reported": len(hosts),
            "bad": sum(1 for h in hosts if (h.get("abuseConfidenceScore") or 0) >= 50),
            "top": [{"ip": h.get("ipAddress"), "conf": h.get("abuseConfidenceScore") or 0,
                     "reports": h.get("numReports") or 0,
                     "last": str(h.get("mostRecentReport") or "")[:10]} for h in hosts[:10]]}


def src_abuse_block(ip):
    """Abuse reports for the whole /24 around an IPv4 address."""
    key = need("ABUSEIPDB_API_KEY")
    if ":" in ip:
        raise Skip("block check is IPv4 only")
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    d = http_json("https://api.abuseipdb.com/api/v2/check-block?"
                  + urllib.parse.urlencode({"network": str(net), "maxAgeInDays": "30"}),
                  {"Key": key, "Accept": "application/json"}, shape=_slim_abuse_block,
                  quota="Abuse-block", ttl=6 * HOUR)
    rows = [f"{h['ip']:<16} Abuse {h['conf']:>3}%  reports:{h['reports']:<5} last {h['last']}"
            for h in d.get("top") or []]
    notes = []
    if d.get("bad", 0) >= 20:
        notes.append(f"bad neighbourhood: {d['bad']} hosts in the /24 at 50%+ abuse confidence")
    return Res([("Network", f"{net}  ({d.get('network')})"),
                ("Reported", f"{d.get('reported', 0)} of {d.get('possible', 256)} hosts in 30 days, "
                             f"{d.get('bad', 0)} at 50%+ confidence"),
                ("Worst", Bul(rows))], 0, notes)


def _slim_blacklist(d):
    data = d.get("data") or []
    countries = Counter(str(x.get("countryCode") or "??") for x in data)
    latest = sorted(data, key=lambda x: str(x.get("lastReportedAt") or ""), reverse=True)[:8]
    return {"total": len(data), "generated": str((d.get("meta") or {}).get("generatedAt") or "")[:16],
            "countries": countries.most_common(8),
            "latest": [{"ip": x.get("ipAddress"), "cc": x.get("countryCode") or "??",
                        "at": str(x.get("lastReportedAt") or "")[:16]} for x in latest]}


def feed_blacklist():
    d = http_json("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&limit=2000",
                  {"Key": need("ABUSEIPDB_API_KEY"), "Accept": "application/json"}, timeout=25,
                  shape=_slim_blacklist, quota="Abuse-blacklist", ttl=6 * HOUR)
    if not d.get("total"):
        return ["blacklist returned no addresses"]
    rows = [f"{d['total']} IPs at 100% confidence ({d['generated']}) - top: "
            + ", ".join(f"{cc} x{n}" for cc, n in d["countries"][:7])]
    rows += [f"{x['at']}  {x['cc']}  {x['ip']}" for x in d["latest"]]
    return rows


def rdap_get(path):
    return http_json(f"https://rdap.org/{path}", {"Accept": "application/rdap+json"}, timeout=15)


def _rdap_entities(obj, depth=0):
    for ent in obj.get("entities") or []:
        if isinstance(ent, dict):
            yield ent
            if depth < 2:
                yield from _rdap_entities(ent, depth + 1)


def _vcard(ent, field):
    card = ent.get("vcardArray") or []
    for item in (card[1] if len(card) > 1 and isinstance(card[1], list) else []):
        if isinstance(item, list) and len(item) >= 4 and item[0] == field and item[3]:
            return str(item[3])
    return ""


def src_rdap_domain(host):
    """Registration data and domain age (RDAP, keyless). Young domains are a risk signal."""
    labels = host.lower().strip(".").split(".")
    d, name = None, host
    for start in range(0, max(len(labels) - 1, 1))[:4]:
        name = ".".join(labels[start:])
        try:
            d = rdap_get(f"domain/{urllib.parse.quote(name)}")
            break
        except urllib.error.HTTPError as exc:
            if exc.code not in (400, 404):
                raise
    if not isinstance(d, dict) or d.get("errorCode"):
        raise Skip("no RDAP record (this TLD may not publish RDAP)")
    events = {str(e.get("eventAction")): str(e.get("eventDate") or "")[:10] for e in d.get("events") or []}
    registered = events.get("registration", "-")
    age = days_since(registered)
    registrar = next((_vcard(e, "fn") or str(e.get("handle") or "") for e in _rdap_entities(d)
                      if "registrar" in (e.get("roles") or [])), "-")
    score, notes = 0, []
    if age is not None and age < 30:
        score, notes = 20, [f"domain registered only {age} day(s) ago"]
    elif age is not None and age < 90:
        score, notes = 10, [f"young domain, registered {age} days ago"]
    return Res([("Domain", name),
                ("Registered", f"{registered}  ({age} days ago)" if age is not None else registered),
                ("Expires", events.get("expiration", "-")),
                ("Updated", events.get("last changed", "-")),
                ("Registrar", registrar or "-"),
                ("Status", Bul([str(x) for x in (d.get("status") or [])[:4]])),
                ("NS", Bul([str(n.get("ldhName", "")).lower() for n in (d.get("nameservers") or [])[:6]]))],
               score, notes)


def src_rdap_ip(ip):
    """Network owner and abuse contact (RDAP, keyless)."""
    try:
        d = rdap_get(f"ip/{urllib.parse.quote(ip, safe=':')}")
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 404):
            raise Skip("no RDAP record for this IP")
        raise
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in d.get("cidr0_cidrs") or []]
    org = next((_vcard(e, "fn") for e in _rdap_entities(d)
                if "registrant" in (e.get("roles") or []) and _vcard(e, "fn")), "-")
    abuse = next((_vcard(e, "email") for e in _rdap_entities(d)
                  if "abuse" in (e.get("roles") or []) and _vcard(e, "email")), "-")
    return Res([("Network", f"{g(d, 'name')}  ({g(d, 'handle')})"),
                ("Range", f"{g(d, 'startAddress')} - {g(d, 'endAddress')}"),
                ("CIDR", cidrs[:4]),
                ("Country", g(d, "country")),
                ("Owner", org),
                ("Abuse", abuse)])


def _slim_crtsh(dom):
    def shape(rows):
        names = {}
        for r in rows if isinstance(rows, list) else []:
            seen = str(r.get("not_before") or "")[:10]
            for n in str(r.get("name_value") or "").lower().split("\n"):
                n = n.strip().lstrip("*.")
                if n and (n == dom or n.endswith("." + dom)) and seen > names.get(n, ""):
                    names[n] = seen
        ordered = sorted(names.items(), key=lambda kv: kv[1], reverse=True)
        return {"certs": len(rows) if isinstance(rows, list) else 0, "total": len(ordered),
                "names": ordered[:150]}
    return shape


def src_crtsh(dom):
    """Subdomains from certificate transparency logs (crt.sh, keyless, fully passive)."""
    d = http_json("https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{dom}", "output": "json"}),
                  timeout=40, shape=_slim_crtsh(dom))
    names = [n for n in d.get("names") or [] if n[0] != dom]
    if not d.get("certs"):
        return Res([("Certs", "none logged")])
    rows = [f"{seen}  {name}" for name, seen in names[:25]]
    fields = [("Certs", d.get("certs", 0)), ("Hostnames", d.get("total", 0)), ("Subdomains", Bul(rows))]
    if len(names) > 25:
        fields.append(("Note", f"25 most recent of {len(names)} shown (use --json for 150)"))
    res = Res(fields)
    res.all_names = [name for name, _seen in names]
    return res


def host_of(kind, ind):
    """Domain to run domain-only engines on, for a domain or URL indicator."""
    if kind == "domain":
        return ind
    if kind == "url":
        host = (urllib.parse.urlsplit(ind).hostname or "").lower()
        return host if RE_DOMAIN.match(host) else None
    return None


def deep_jobs(kind, ind):
    if kind == "ip":
        return [("VT hosted domains (deep)", lambda: src_vt_resolutions(ind)),
                ("VT related files (deep)", lambda: src_vt_files("ip", ind)),
                ("AbuseIPDB /24 block (deep)", lambda: src_abuse_block(ind))]
    if kind == "domain":
        return [("VT subdomains + IPs (deep)", lambda: src_vt_domain_rel(ind)),
                ("VT related files (deep)", lambda: src_vt_files("domain", ind))]
    if kind == "hash":
        return [("VT sandbox behaviour (deep)", lambda: src_vt_behaviour(ind))]
    return []


# --------------------------------------------------------------------------
# pivoting: find an indicator inside a result row
# --------------------------------------------------------------------------

RE_REPORT_ROW = re.compile(r"^\s*-\s\d{4}-\d\d-\d\dT\d\d:\d\d \S\S\s")  # free-text abuse report comments
RE_TOKEN = re.compile(r"[^\s,()\[\]\"'<>|]+")
REF_HOSTS = ("github.com", "packetstormsecurity.com", "exploit-db.com", "virustotal.com", "nist.gov",
             "immunityinc.com", "fraunhofer.de", "mitre.org", "cisa.gov", "abuse.ch", "alienvault.com")
NOT_TLDS = {"py", "rb", "sh", "txt", "yaml", "yml", "php", "html", "htm", "json", "exe", "dll", "zip",
            "md", "pl", "js", "jar", "ps", "bat", "so", "bin", "xml", "conf", "log", "gz", "tar"}


def pivot_of(text, current=None):
    """First lookup-able indicator in a result row, or None."""
    text = str(text)
    if text.lstrip().startswith(("-- ", "+ ", "working", "VERDICT", "contributors")):
        return None
    if RE_REPORT_ROW.match(text):
        return None
    m = RE_CVE_ANY.search(text)
    if m:
        cve = m.group(0).upper()
        return cve if cve != current else None
    for tok in RE_TOKEN.findall(text):
        tok = tok.strip(".;:")
        low = tok.lower()
        if low.startswith(("http://", "https://")):
            host = urllib.parse.urlsplit(tok).hostname or ""
            if any(host == r or host.endswith("." + r) for r in REF_HOSTS):
                return None
            kind, ind, err = classify(tok)
        else:
            if ":" in tok and tok.count(":") == 1:
                left, right = tok.split(":")
                tok = left if right.isdigit() or "/" in right else right
            kind, ind, err = classify(tok)
            if kind == "domain" and ind.rsplit(".", 1)[-1] in NOT_TLDS:
                continue
        if kind and not err and ind != current:
            return ind
    return None


# --------------------------------------------------------------------------
# job tables
# --------------------------------------------------------------------------

def cve_jobs(cve, full=True):
    jobs = [("NVD", lambda: src_nvd_cve(cve)),
            ("Shodan CVEDB", lambda: src_cvedb(cve)),
            ("PoC: GitHub", lambda: src_poc_github(cve)),
            ("PoC: local tools", lambda: src_poc_local(cve)),
            ("OTX CVE intel", lambda: src_otx_cve(cve))]
    if full:
        jobs += [("CIRCL", lambda: src_circl_cve(cve)),
                 ("MyThreatIntel", lambda: mti("cve", cve=cve))]
    return jobs


def jobs_for(kind, ind, deep=False):
    return base_jobs(kind, ind) + (deep_jobs(kind, ind) if deep else [])


def base_jobs(kind, ind):
    if kind == "advisory":
        def chained(src):
            def run():
                cve = advisory_cve(ind)
                if not cve:
                    raise Skip("advisory has no CVE alias")
                res = src(cve)
                res.fields.insert(0, ("Via", cve))
                return res
            return run
        return [("OSV advisory", lambda: src_osv_advisory(ind)),
                ("NVD (CVE alias)", chained(src_nvd_cve)),
                ("Shodan CVEDB (CVE alias)", chained(src_cvedb)),
                ("PoC: GitHub (CVE alias)", chained(src_poc_github)),
                ("PoC: local tools (CVE alias)", chained(src_poc_local))]
    if kind == "ip":
        return [("Shodan host", lambda: src_shodan_host(ind)),
                ("Shodan InternetDB", lambda: src_inetdb(ind)),
                ("AbuseIPDB", lambda: src_abuse(ind)),
                ("VirusTotal", lambda: src_vt("ip", ind)),
                ("ThreatFox", lambda: src_threatfox("ip", ind)),
                ("URLhaus", lambda: src_urlhaus("ip", ind)),
                ("AlienVault OTX", lambda: src_otx("ip", ind)),
                ("OTX passive DNS", lambda: src_otx_related("ip", ind)),
                ("RDAP network owner", lambda: src_rdap_ip(ind))]
    if kind == "domain":
        return [("VirusTotal", lambda: src_vt("domain", ind)),
                ("ThreatFox", lambda: src_threatfox("domain", ind)),
                ("URLhaus", lambda: src_urlhaus("domain", ind)),
                ("AlienVault OTX", lambda: src_otx("domain", ind)),
                ("OTX passive DNS", lambda: src_otx_related("domain", ind)),
                ("RDAP domain age", lambda: src_rdap_domain(ind)),
                ("crt.sh subdomains", lambda: src_crtsh(ind)),
                ("MyThreatIntel leaks", lambda: mti("leaks", domain=ind))]
    if kind == "hash":
        return [("VirusTotal", lambda: src_vt("hash", ind)),
                ("MalwareBazaar", lambda: src_bazaar(ind)),
                ("ThreatFox", lambda: src_threatfox("hash", ind)),
                ("AlienVault OTX", lambda: src_otx("hash", ind))]
    if kind == "url":
        return [("URLhaus", lambda: src_urlhaus("url", ind)),
                ("VirusTotal", lambda: src_vt("url", ind)),
                ("ThreatFox", lambda: src_threatfox("url", ind)),
                ("AlienVault OTX", lambda: src_otx("url", ind))]
    if kind == "cve":
        return cve_jobs(ind)
    return []


def prescan_jobs(kind, ind):
    if kind not in ("url", "domain", "ip"):
        return []
    jobs = []
    if kind == "ip":
        jobs += [("Shodan host", lambda: src_shodan_host(ind)),
                 ("Shodan InternetDB", lambda: src_inetdb(ind)),
                 ("AbuseIPDB", lambda: src_abuse(ind))]
    jobs += [("VirusTotal", lambda: src_vt(kind, ind)),
             ("URLhaus", lambda: src_urlhaus(kind, ind)),
             ("ThreatFox", lambda: src_threatfox(kind, ind)),
             ("AlienVault OTX", lambda: src_otx(kind, ind))]
    host = host_of(kind, ind)
    if host:
        jobs.append(("RDAP domain age", lambda: src_rdap_domain(host)))
    jobs.append(("MyThreatIntel IOCs", lambda: src_mti_ioc(ind)))
    return jobs


def feed_jobs():
    return [("NVD critical/high CVEs (7d)", feed_nvd),
            ("CISA KEV additions (30d)", feed_kev),
            ("ThreatFox IOCs (24h)", feed_threatfox),
            ("URLhaus live URLs", feed_urlhaus),
            ("OTX subscribed pulses", feed_otx),
            ("AbuseIPDB blacklist", feed_blacklist),
            ("CIRCL latest", feed_circl)]


def verdict_of(total):
    if total >= 60:
        return "MALICIOUS - avoid", "red"
    if total >= 30:
        return "SUSPICIOUS - caution advised", "yel"
    if total >= 8:
        return "WEAK SIGNALS - review manually", "mag"
    return "NO MAJOR SIGNALS", "grn"


# --------------------------------------------------------------------------
# exports
# --------------------------------------------------------------------------

def csv_field(text):
    t = str(text).replace("\t", " ").replace("\r", " ")
    if t[:1] in ("=", "+", "-", "@"):
        t = "'" + t
    if any(c in t for c in (",", '"', "\n")):
        t = '"' + t.replace('"', '""') + '"'
    return t


def export_csv_file(path, indicator, kind, sections, append=False):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a" if append else "w", encoding="utf-8", newline="") as fh:
        if not append:
            fh.write("timestamp,indicator,type,source,status,score,details\n")
        for title, entry in sections.items():
            status = entry[0]
            score = entry[3] if len(entry) > 3 else 0
            details = " | ".join(str(l) for l in entry[1] if str(l).strip())
            fh.write(",".join(csv_field(x) for x in
                              (ts, indicator, kind, title, status, score, details)) + "\n")
    return path


RE_POS_RED = re.compile(r"malicious:[1-9]|Listed\s+YES|\bKEV\s+yes\b|Seen wild\s+YES|\bEXPLOIT$|EXPIRED", re.I)
RE_POS_YEL = re.compile(r"suspicious:[1-9]", re.I)
RE_ABUSE_PCT = re.compile(r"\bAbuse\s+(\d+)%", re.I)


def classify_row(text):
    m = RE_ABUSE_PCT.search(text)
    abuse = int(m.group(1)) if m else -1
    if RE_POS_RED.search(text) or abuse >= 30:
        return "red"
    if RE_POS_YEL.search(text) or 10 <= abuse <= 29:
        return "yel"
    return None


def keyword_class(text):
    t = text.upper()
    if "CRITICAL" in t:
        return "red"
    if "HIGH" in t:
        return "mag"
    if "MEDIUM" in t:
        return "yel"
    if "LOW" in t:
        return "grn"
    return None


def row_class(text):
    c = classify_row(text) or keyword_class(text)
    if c is None and text.startswith("+ "):
        return "yel"
    return c


def build_report(indicator, kind, sections):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = ["# cybersec-intel report", "",
             f"- indicator: `{indicator}`",
             f"- type: {kind}",
             f"- generated: {ts}",
             ""]
    if kind == "site-check":
        total = total_score((e[3] if len(e) > 3 else 0) for e in sections.values())
        label, _pair = verdict_of(total)
        contrib = ", ".join(f"{t} +{e[3]}" for t, e in sections.items()
                            if len(e) > 3 and e[3])
        lines.append(f"**verdict: {label} (score {total}/100)**")
        lines.append("")
        if contrib:
            lines.append(f"contributors: {contrib}")
            lines.append("")
    for title, entry in sections.items():
        status = entry[0]
        score = entry[3] if len(entry) > 3 else 0
        lines.append(f"## {title} [{status}]" + (f" (+{score})" if score else ""))
        lines.append("")
        for r in entry[1]:
            s = str(r).strip()
            if s:
                lines.append(f"- {s}")
        lines.append("")
    return "\n".join(lines) + "\n"


def write_report_file(path, indicator, kind, sections):
    full = os.path.expanduser(path)
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd = os.open(full, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(build_report(indicator, kind, sections))
    return full


def fail_text(exc):
    if isinstance(exc, urllib.error.HTTPError):
        hint = {401: " (key rejected)", 403: " (not allowed on this plan)",
                429: " (rate limited, try later)"}.get(exc.code, "")
        return f"HTTP {exc.code} {exc.reason}{hint}"
    return f"{type(exc).__name__}: {exc}"


SPIN = "|/-\\"

EXPECTED = {"NVD": 6, "VirusTotal": 9, "AbuseIPDB": 6, "AlienVault OTX": 6,
            "OTX passive DNS": 14, "OTX CVE intel": 8, "Shodan host": 8,
            "Shodan InternetDB": 4, "Shodan CVEDB": 5, "CIRCL": 8,
            "URLhaus": 5, "ThreatFox": 6, "MalwareBazaar": 6,
            "PoC: GitHub": 4, "PoC: local tools": 3,
            "MyThreatIntel leaks": 8, "MyThreatIntel": 8, "MyThreatIntel IOCs": 8,
            "NVD critical/high CVEs (7d)": 30, "CISA KEV additions (30d)": 8,
            "ThreatFox IOCs (24h)": 10, "URLhaus live URLs": 5,
            "OTX subscribed pulses": 10, "CIRCL latest": 10, "OSV advisory": 6,
            "AbuseIPDB blacklist": 5, "RDAP domain age": 4, "RDAP network owner": 4,
            "crt.sh subdomains": 20, "VT hosted domains (deep)": 20, "VT related files (deep)": 35,
            "VT subdomains + IPs (deep)": 20, "VT sandbox behaviour (deep)": 20,
            "AbuseIPDB /24 block (deep)": 5}


class Tui:
    def __init__(self, stdscr):
        self.scr = stdscr
        curses.curs_set(0)
        stdscr.timeout(150)
        curses.start_color()
        curses.use_default_colors()
        for i, fg in enumerate((curses.COLOR_RED, curses.COLOR_YELLOW, curses.COLOR_GREEN,
                                curses.COLOR_CYAN, curses.COLOR_MAGENTA, curses.COLOR_WHITE), 1):
            curses.init_pair(i, fg, -1)
        self.C_RED, self.C_YEL, self.C_GRN, self.C_CYN, self.C_MAG, self.C_WHT = range(1, 7)
        self.view = 0
        self.offset = 0
        self.buf = ""
        self.enter_pending = False
        self.prompting = False
        self.last_query = None
        self.history = []
        self.pick = None
        self.pivots = []
        self.targets = []
        self._pcache = {}
        self.results = OrderedDict()
        self.scans = OrderedDict()
        self.scan_scores = {}
        self.last_scan = None
        self.feed = OrderedDict()
        self.feed_pending = 0
        self.feed_ts = 0.0
        self.q = queue.Queue()
        self.msg = "press F1/F2/F3/F4 to switch views"
        self.reload_feed()

    def attr(self, pair, bold=False):
        return curses.color_pair(pair) | (curses.A_BOLD if bold else 0)

    def status_attr(self, status):
        return {"ok": self.attr(self.C_GRN),
                "fail": self.attr(self.C_RED),
                "skip": self.attr(self.C_YEL),
                "running": self.attr(self.C_CYN, True)}.get(status, 0)

    def row_attr(self, text):
        c = row_class(str(text))
        return {"red": self.attr(self.C_RED, True),
                "yel": self.attr(self.C_YEL),
                "mag": self.attr(self.C_MAG),
                "grn": self.attr(self.C_GRN)}.get(c, 0)

    def reload_feed(self, force=False):
        if not force and self.feed_pending == 0:
            remaining = FEED_COOLDOWN - (time.time() - self.feed_ts)
            if remaining > 0:
                self.msg = f"feed cooldown: {int(remaining) + 1}s left (rate-limit protection)"
                return False
        jobs = feed_jobs()
        now = time.time()
        self.feed = OrderedDict((t, ("running", [], now, 0)) for t, _ in jobs)
        self.feed_pending = len(jobs)
        self.feed_ts = time.time()
        for t, fn in jobs:
            threading.Thread(target=self._worker, args=("feed", t, fn), daemon=True).start()
        return True

    def _worker(self, bucket, title, fn):
        try:
            score, lines, _raw = unpack(fn())
            self.q.put((bucket, title, "ok", lines, score))
        except Skip as exc:
            self.q.put((bucket, title, "skip", [str(exc)], 0))
        except Exception as exc:
            self.q.put((bucket, title, "fail", [fail_text(exc)], 0))

    def drain(self):
        try:
            while True:
                bucket, title, status, lines, score = self.q.get_nowait()
                if bucket == "feed":
                    self.feed[title] = (status, lines, 0.0, score)
                    self.feed_pending -= 1
                elif bucket == "scan":
                    self.scans[title] = (status, lines, 0.0, score)
                    if status == "ok":
                        self.scan_scores[title] = score
                else:
                    self.results[title] = (status, lines, 0.0, score)
        except queue.Empty:
            pass

    def do_lookup(self, raw, deep=False, push=True):
        kind, ind, err = classify(raw)
        if err:
            self.msg = err
            return
        if push and self.last_query and self.last_query != ind:
            self.history = (self.history + [self.last_query])[-30:]
        self.pick = None
        jobs = jobs_for(kind, ind, deep)
        now = time.time()
        self.results = OrderedDict((t, ("running", [], now, 0)) for t, _ in jobs)
        self.last_query = ind
        self.buf = ""
        self.offset = 0
        self.msg = (f"deep lookup {kind}: {ind} (VirusTotal extras wait ~15s each)" if deep
                    else f"looking up {kind}: {ind}")
        for t, fn in jobs:
            threading.Thread(target=self._worker, args=("lookup", t, fn), daemon=True).start()

    def do_prescan(self, raw):
        kind, ind, err = classify(raw)
        if not err and kind not in ("url", "domain", "ip"):
            err = "site check accepts URL, domain or IP only"
        if err:
            self.msg = err
            return
        self.pick = None
        jobs = prescan_jobs(kind, ind)
        now = time.time()
        self.scans = OrderedDict((t, ("running", [], now, 0)) for t, _ in jobs)
        self.scan_scores = {}
        self.last_scan = ind
        self.buf = ""
        self.offset = 0
        self.msg = f"passive site check ({kind}): {ind}"
        for t, fn in jobs:
            threading.Thread(target=self._worker, args=("scan", t, fn), daemon=True).start()

    def dash_lines(self):
        lines = [(f"CYBERSEC THREAT INTEL  v{VERSION}", self.attr(self.C_CYN, True)), ("", 0)]
        for var, name in SOURCES:
            if ENV.get(var):
                lines.append((f"  [ok]   {name:<34} key loaded", self.attr(self.C_GRN)))
            else:
                lines.append((f"  [--]   {name:<34} no key, source skipped", self.attr(self.C_YEL)))
        lines += [("", 0),
                  ("views: [F1] dash  [F2] feed  [F3] lookup  [F4] site check", self.attr(self.C_WHT)),
                  ("lookup: IP | domain | URL | hash | CVE | PYSEC | GHSA", self.attr(self.C_WHT)),
                  ("CVE lookup adds PoC search: GitHub, Exploit-DB, Metasploit, Nuclei, OTX", self.attr(self.C_WHT)),
                  ("IP lookup marks CVEs that have a local exploit [msf edb nuclei]", self.attr(self.C_WHT)),
                  ("pivot: Tab selects a row with an IP/domain/hash/CVE, Enter looks it up, ^b goes back", self.attr(self.C_WHT)),
                  ("deep: ^d in lookup adds VirusTotal relations/sandbox + AbuseIPDB /24 (uses quota)", self.attr(self.C_WHT)),
                  ("paste: ctrl+shift+v   copy: select text + ctrl+shift+c", self.attr(self.C_WHT)),
                  ("export csv: ^e    save report: ^r (lookup & site check)", self.attr(self.C_WHT)),
                  ("arrows: <-> switch tabs   up/down scroll   numpad 4/6/8/2 works too", self.attr(self.C_WHT)),
                  ("keys are read from the .env file beside this script", self.attr(self.C_WHT)),
                  (quota_summary(), self.attr(self.C_CYN)),
                  ("rate limits + daily quotas + per-source cache (30min-12h) enforced", self.attr(self.C_YEL))]
        return lines

    def section(self, store, show_spin):
        lines = []
        if show_spin:
            lines.append(("working...", self.attr(self.C_CYN, True)))
        for title, entry in store.items():
            status, rows = entry[0], entry[1]
            if status == "running":
                elapsed = time.time() - entry[2]
                if elapsed >= 5:
                    pct = min(int(elapsed / EXPECTED.get(title, 10) * 100), 95)
                    cells = "#" * (pct // 10) + "-" * (10 - pct // 10)
                    head = f"-- {title} [{cells}] {pct:>3}% {elapsed:.0f}s"
                else:
                    ch = SPIN[int(time.time() * 4) % 4]
                    head = f"-- {title} [{ch}] {elapsed:.0f}s"
                attr = self.attr(self.C_CYN, True)
            else:
                head = f"-- {title} [{status}]"
                attr = self.status_attr(status) | curses.A_BOLD
            lines.append((head, attr))
            for r in rows:
                lines.append((f"   {r}", self.row_attr(str(r))))
            lines.append(("", 0))
        return lines

    def feed_lines(self):
        return self.section(self.feed, self.feed_pending)

    def lookup_lines(self):
        if not self.results:
            return [("type or paste an indicator below, then press Enter", self.attr(self.C_WHT)),
                    ("accepts: IP | domain | URL | hash | CVE | PYSEC | GHSA", self.attr(self.C_WHT))]
        running = sum(1 for e in self.results.values() if e[0] == "running")
        return self.section(self.results, running)

    def sitecheck_lines(self):
        if not self.scans:
            return [("passive site reputation check - enter URL, domain or IP below", self.attr(self.C_WHT)),
                    ("queries VT, URLhaus, ThreatFox, OTX, AbuseIPDB, Shodan, RDAP - never touches the target", self.attr(self.C_WHT)),
                    ("examples: http://free-toolz.example | crack-site.example | 185.220.101.1", self.attr(self.C_WHT))]
        lines = []
        pending = any(e[0] == "running" for e in self.scans.values())
        total = total_score(self.scan_scores.values())
        if pending:
            lines.append(("scoring...", self.attr(self.C_CYN, True)))
        else:
            label, pair = verdict_of(total)
            name = {"red": self.C_RED, "yel": self.C_YEL,
                    "mag": self.C_MAG, "grn": self.C_GRN}[pair]
            lines.append((f"VERDICT: {label}   score {total}/100", self.attr(name, True)))
            contrib = ", ".join(f"{t} +{s}" for t, s in self.scan_scores.items() if s)
            lines.append((f"contributors: {contrib or 'none'}", self.attr(self.C_WHT)))
            lines.append(("", 0))
        running = sum(1 for e in self.scans.values() if e[0] == "running")
        return lines + self.section(self.scans, running)

    def pivot_cached(self, text, current):
        key = (text, current)
        if key not in self._pcache:
            if len(self._pcache) > 4000:
                self._pcache.clear()
            self._pcache[key] = pivot_of(text, current)
        return self._pcache[key]

    def start_pick(self):
        if not self.pivots:
            self.msg = "nothing to pivot on in this view"
            return
        self.pick = next((n for n, row in enumerate(self.pivots) if row >= self.offset), 0)
        self.msg = "select: up/down choose a highlighted row, Enter looks it up, Tab/Esc leaves"

    def handle_pick_key(self, key):
        """Keys while a pivot row is selected. Returns False to let the normal handler run."""
        step = 0
        if key == 27:
            seq = self._read_esc()
            if seq in ("[A", "Ox"):
                step = -1
            elif seq in ("[B", "Or"):
                step = 1
            elif seq == "OM":
                key = 10
            else:
                self.pick = None
                self.msg = "selection closed"
                return True
        if key in (curses.KEY_UP, ord("8"), ord("k")):
            step = -1
        elif key in (curses.KEY_DOWN, ord("2"), ord("j")):
            step = 1
        elif key == curses.KEY_PPAGE:
            step = -8
        elif key == curses.KEY_NPAGE:
            step = 8
        if step:
            self.pick = min(max(self.pick + step, 0), max(len(self.pivots) - 1, 0))
            return True
        if key in (10, 13, curses.KEY_ENTER):
            target = self.targets[self.pick] if self.pick < len(self.targets) else None
            self.pick = None
            if target:
                self.view = 2
                self.do_lookup(target)
            return True
        if key == 9:
            self.pick = None
            self.msg = "selection closed"
            return True
        if key == -1 or key == curses.KEY_RESIZE:
            return key == -1
        self.pick = None
        return False

    def go_back(self):
        if not self.history:
            self.msg = "no earlier lookup to go back to"
            return
        prev = self.history.pop()
        self.view = 2
        self.do_lookup(prev, push=False)
        self.msg = f"back to {prev}"

    def go_deep(self):
        if not self.last_query:
            self.msg = "look something up first, then ^d for deep mode"
            return
        kind = classify(self.last_query)[0]
        if not deep_jobs(kind, self.last_query):
            self.msg = "deep mode applies to IP, domain and hash lookups"
            return
        self.do_lookup(self.last_query, deep=True, push=False)

    def export_csv(self):
        if self.view == 1:
            sections, ind, kind = self.feed, "threat-feed", "feed"
        elif self.view == 3:
            if not self.scans:
                self.msg = "nothing to export yet"
                return
            sections, ind, kind = self.scans, self.last_scan or "?", "site-check"
        else:
            if not self.results:
                self.msg = "nothing to export yet"
                return
            sections, ind, kind = self.results, self.last_query or "?", "lookup"
        name = re.sub(r"[^A-Za-z0-9._-]", "_", str(ind))[:40] or "export"
        path = os.path.join(APP_DIR, "exports",
                            f"{time.strftime('%Y%m%d_%H%M%S')}_{name}.csv")
        try:
            export_csv_file(path, ind, kind, sections)
            self.msg = f"exported: {os.path.basename(path)}"
        except OSError as exc:
            self.msg = f"export failed: {exc}"

    def clamp_offset(self, total, avail):
        if avail <= 0 or total <= avail:
            self.offset = 0
        elif self.offset > total - avail:
            self.offset = total - avail
        if self.offset < 0:
            self.offset = 0

    def draw(self):
        scr = self.scr
        scr.erase()
        h, w = scr.getmaxyx()
        if h < 6 or w < 48:
            scr.addnstr(0, 0, "terminal too small", max(w - 1, 0))
            scr.refresh()
            return
        scr.addnstr(0, 0, " CYBERSEC INTEL ".ljust(w), w - 1, self.attr(self.C_CYN, True))
        scr.addnstr(0, w - 9, time.strftime("%H:%M:%S"), 8, self.attr(self.C_WHT))
        body = (self.dash_lines, self.feed_lines, self.lookup_lines, self.sitecheck_lines)[self.view]()
        avail = h - 4 - (1 if self.view in (2, 3) else 0)
        current = {2: self.last_query, 3: self.last_scan}.get(self.view)
        self.pivots, self.targets = [], []
        if self.view in (1, 2, 3):
            for i, (text, _a) in enumerate(body):
                target = self.pivot_cached(str(text), current)
                if target:
                    self.pivots.append(i)
                    self.targets.append(target)
        chosen = -1
        if self.pick is not None:
            if not self.pivots:
                self.pick = None
            else:
                self.pick = min(self.pick, len(self.pivots) - 1)
                chosen = self.pivots[self.pick]
                if chosen < self.offset:
                    self.offset = chosen
                elif avail > 0 and chosen >= self.offset + avail:
                    self.offset = chosen - avail + 1
                self.msg = f"Enter looks up: {self.targets[self.pick]}   (Tab/Esc leaves)"
        self.clamp_offset(len(body), max(avail, 1))
        for i, (text, a) in enumerate(body[self.offset:self.offset + max(avail, 0)]):
            if self.offset + i == chosen:
                scr.addnstr(2 + i, 0, "> " + str(text).ljust(w), w - 1, curses.A_REVERSE | curses.A_BOLD)
            else:
                scr.addnstr(2 + i, 2, str(text), w - 3, a)
        if self.view in (2, 3):
            prefix = "save report to: " if self.prompting else "> "
            scr.addnstr(h - 3, 0, (prefix + self.buf + "_").ljust(w), w - 1,
                        self.attr(self.C_CYN if self.prompting else self.C_GRN, True))
        foot = "[F1-4]views  Tab select+Enter pivot  ^d deep  ^b back  r refresh  ^e csv  ^r report  q quit"
        scr.addnstr(h - 2, 0, foot.ljust(w), w - 1, curses.A_REVERSE)
        scr.addnstr(h - 1, 0, self.msg[-(w - 1):], w - 1, self.attr(self.C_YEL))
        scr.refresh()

    def _read_esc(self):
        seq = ""
        self.scr.timeout(30)
        while len(seq) < 8:
            k = self.scr.getch()
            if k == -1:
                break
            if 32 <= k <= 126:
                seq += chr(k)
            if k == 126:
                break
        self.scr.timeout(150)
        return seq

    def _read_burst(self, first):
        acc = chr(first)
        self.scr.timeout(35)
        while True:
            k = self.scr.getch()
            if k == -1:
                break
            if k == 27:
                self._read_esc()
                continue
            if k in (10, 13):
                self.enter_pending = True
                break
            if k == 9:
                continue
            if 32 <= k <= 126 or 160 <= k <= 255:
                acc += chr(k)
        self.scr.timeout(150)
        return acc

    def submit_input(self):
        if not self.buf.strip():
            self.msg = "type or paste an indicator, then Enter"
            return
        if self.view == 2:
            self.do_lookup(self.buf)
        else:
            self.do_prescan(self.buf)

    def start_report(self):
        if self.view == 3:
            if not self.scans:
                self.msg = "nothing scanned yet"
                return
            if any(e[0] == "running" for e in self.scans.values()):
                self.msg = "scan still running, wait for verdict"
                return
        elif not self.results:
            self.msg = "no lookup results yet"
            return
        ind = (self.last_scan if self.view == 3 else self.last_query) or "?"
        name = re.sub(r"[^A-Za-z0-9._-]", "_", str(ind))[:40] or "target"
        self.prompting = True
        self.buf = os.path.join(APP_DIR, "exports",
                                f"report_{name}_{time.strftime('%Y%m%d_%H%M%S')}.md")
        self.offset = 0
        self.msg = "edit path, Enter saves, Esc cancels"

    def handle_prompt_key(self, key):
        printable = 32 <= key <= 126 or 160 <= key <= 255
        done = False
        if key in (10, 13):
            done = True
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            self.buf = self.buf[:-1]
        elif key == 27:
            seq = self._read_esc()
            if not seq:
                self.prompting = False
                self.buf = ""
                self.msg = "report cancelled"
        elif printable:
            self.buf += self._read_burst(key)
            if self.enter_pending:
                self.enter_pending = False
                done = True
        if done:
            path = os.path.expanduser(self.buf.strip())
            self.prompting = False
            self.buf = ""
            self.save_report(path)

    def save_report(self, path):
        if not path:
            self.msg = "report cancelled"
            return
        if self.view == 3:
            ind, kind, sections = self.last_scan or "?", "site-check", self.scans
        else:
            ind, kind, sections = self.last_query or "?", "lookup", self.results
        try:
            write_report_file(path, ind, kind, sections)
            self.msg = f"report saved: {os.path.basename(path)}"
        except OSError as exc:
            self.msg = f"report failed: {exc}"

    def switch_view(self, delta):
        self.pick = None
        self.view = (self.view + delta) % 4
        self.offset = 0
        if self.view == 1 and self.feed_pending == 0 and time.time() - self.feed_ts > 900:
            self.reload_feed(force=True)
        self.msg = ("dashboard", "threat feed", "indicator lookup", "site check")[self.view]

    def run(self):
        while True:
            self.drain()
            self.draw()
            key = self.scr.getch()
            if self.prompting:
                self.handle_prompt_key(key)
                continue
            if self.pick is not None and self.handle_pick_key(key):
                continue
            if key == 9 and self.view in (1, 2, 3):
                self.start_pick()
                continue
            if key == 2:
                self.go_back()
                continue
            if key == 4 and self.view == 2:
                self.go_deep()
                continue
            if curses.KEY_F1 <= key <= curses.KEY_F4:
                self.view = key - curses.KEY_F1
                self.pick = None
                self.offset = 0
                if self.view == 1 and self.feed_pending == 0 and time.time() - self.feed_ts > 900:
                    self.reload_feed(force=True)
                self.msg = ("dashboard", "threat feed", "indicator lookup", "site check")[self.view]
                continue
            if key in (curses.KEY_LEFT, curses.KEY_RIGHT):
                self.switch_view(1 if key == curses.KEY_RIGHT else -1)
                continue
            if key == curses.KEY_RESIZE:
                self.scr.clear()
                continue
            if key == 27:
                seq = self._read_esc()
                if seq in ("[D", "Ot"):
                    self.switch_view(-1)
                elif seq in ("[C", "Ov"):
                    self.switch_view(1)
                elif seq in ("[A", "Ox"):
                    self.offset = max(self.offset - 1, 0)
                elif seq in ("[B", "Or"):
                    self.offset += 1
                elif seq == "OM" and self.view in (2, 3):
                    self.submit_input()
                elif not seq and self.view in (2, 3):
                    self.buf = ""
                continue
            if key == ord("q") and self.view not in (2, 3):
                return
            if key == ord("r") and self.view not in (2,):
                if self.view == 1 and self.reload_feed():
                    self.msg = "refreshing feeds"
                elif self.view == 3 and self.last_scan:
                    self.do_prescan(self.last_scan)
                continue
            if key == 5 and self.view in (1, 2, 3):
                self.export_csv()
                continue
            if key == 18 and self.view in (2, 3):
                self.start_report()
                continue
            page = max(self.scr.getmaxyx()[0] - 5, 1)
            if key == curses.KEY_UP:
                self.offset = max(self.offset - 1, 0)
                continue
            if key == curses.KEY_DOWN:
                self.offset += 1
                continue
            if key == curses.KEY_PPAGE:
                self.offset -= page
                continue
            if key == curses.KEY_NPAGE:
                self.offset += page
                continue
            if key == curses.KEY_HOME:
                self.offset = 0
                continue
            if self.view in (0, 1) and key in (ord("2"), ord("4"), ord("6"), ord("8")):
                if key == ord("8"):
                    self.offset = max(self.offset - 1, 0)
                elif key == ord("2"):
                    self.offset += 1
                elif key == ord("4"):
                    self.switch_view(-1)
                else:
                    self.switch_view(1)
                continue
            if self.view in (2, 3):
                printable = 32 <= key <= 126 or 160 <= key <= 255
                if key in (10, 13):
                    self.submit_input()
                elif key in (curses.KEY_BACKSPACE, 127, 8):
                    self.buf = self.buf[:-1]
                elif printable:
                    self.buf += self._read_burst(key)
                    if self.enter_pending:
                        self.enter_pending = False
                        self.submit_input()
            self.offset = max(self.offset, 0)


ANSI = {"red": "\033[31m", "yel": "\033[33m", "grn": "\033[32m",
        "mag": "\033[35m", "cyn": "\033[36m", "b": "\033[1m", "o": "\033[0m"}
ROW_ANSI = {"red": "red", "yel": "yel", "mag": "mag", "grn": "grn"}
QUIET = False


def out(text="", color=None, bold=False):
    if QUIET:
        return
    if sys.stdout.isatty() and (color or bold):
        print(f"{ANSI['b'] if bold else ''}{ANSI.get(color, '')}{text}{ANSI['o']}")
    else:
        print(text)


def run_jobs(jobs):
    """Run source jobs in parallel. Returns (sections for export, raw data for JSON)."""
    res = OrderedDict((t, ("running", [], "cyn", 0)) for t, _ in jobs)
    raw = OrderedDict((t, {}) for t, _ in jobs)

    def one(item):
        t, fn = item
        try:
            score, lines, data = unpack(fn())
            res[t] = ("ok", lines, "grn", score)
            raw[t] = {"status": "ok", **data}
        except Skip as exc:
            res[t] = ("skip", [str(exc)], "yel", 0)
            raw[t] = {"status": "skip", "message": str(exc)}
        except Exception as exc:
            res[t] = ("fail", [fail_text(exc)], "red", 0)
            raw[t] = {"status": "fail", "message": fail_text(exc)}

    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(one, jobs))
    return res, raw


def show_sections(res):
    for t, (status, rows, color, _s) in res.items():
        out(f"\n== {t} [{status}]", color, True)
        for r in rows:
            out(f"  {r}", ROW_ANSI.get(row_class(str(r))))


def record(ind, kind, res, raw, **extra):
    doc = OrderedDict(indicator=ind, type=kind, generated=time.strftime("%Y-%m-%dT%H:%M:%S"))
    doc.update(extra)
    doc["sources"] = raw
    return {"indicator": ind, "kind": kind, "sections": res, "json": doc}


def rejected(raw, message):
    out(message, "red")
    doc = OrderedDict(indicator=clean_indicator(raw), type=None, error=message, sources={})
    return {"indicator": clean_indicator(raw), "kind": "rejected", "sections": OrderedDict(),
            "json": doc, "error": message}


def cli_feed():
    out("CYBERSEC THREAT FEED", "cyn", True)
    res, raw = run_jobs(feed_jobs())
    show_sections(res)
    return record("threat-feed", "feed", res, raw)


def cli_lookup(raw_ind, poc_only=False, deep=False):
    kind, ind, err = classify(raw_ind)
    if poc_only and not err and kind != "cve":
        err = "--poc needs a CVE id, e.g. CVE-2021-44228"
    if err:
        return rejected(raw_ind, err)
    jobs = cve_jobs(ind, full=False) if poc_only else jobs_for(kind, ind, deep)
    if deep and not poc_only and not deep_jobs(kind, ind):
        out("note: --deep adds nothing for this indicator type (IP, domain and hash only)", "yel")
    res, raw = run_jobs(jobs)
    out(f"{'POC SEARCH' if poc_only else 'LOOKUP'} {kind}: {ind}", "cyn", True)
    show_sections(res)
    return record(ind, kind, res, raw)


def cli_prescan(raw_ind):
    kind, ind, err = classify(raw_ind)
    if not err and kind not in ("url", "domain", "ip"):
        err = "site check accepts URL, domain or IP only"
    if err:
        return rejected(raw_ind, err)
    res, raw = run_jobs(prescan_jobs(kind, ind))
    out(f"SITE CHECK (passive) {kind}: {ind}", "cyn", True)
    show_sections(res)
    scores = {t: e[3] for t, e in res.items() if e[0] == "ok"}
    total = total_score(scores.values())
    label, color = verdict_of(total)
    out(f"\nVERDICT: {label}   score {total}/100", color, True)
    contrib = ", ".join(f"{t} +{s}" for t, s in scores.items() if s)
    out(f"contributors: {contrib or 'none'}")
    return record(ind, f"site-check:{kind}", res, raw, verdict=label, score=total)


def read_indicators(path):
    with open(os.path.expanduser(path), encoding="utf-8", errors="replace") as fh:
        items = [clean_indicator(l.split("#", 1)[0]) for l in fh]
    seen = []
    for item in items:
        if item and item not in seen:
            seen.append(item)
    return seen


def main():
    global QUIET
    ap = argparse.ArgumentParser(prog="cybersec-intel",
                                 description="Minimal terminal window for cybersecurity threat intel.")
    ap.add_argument("--version", action="version", version=f"cybersec-intel {VERSION}")
    ap.add_argument("--lookup", metavar="INDICATOR",
                    help="one-shot lookup: IP, domain, URL, hash, CVE, PYSEC or GHSA id")
    ap.add_argument("--prescan", metavar="URL|DOMAIN|IP",
                    help="passive site reputation check (no contact with target)")
    ap.add_argument("--poc", metavar="CVE",
                    help="search public PoCs/exploits for a CVE (GitHub, Exploit-DB, Metasploit, Nuclei, OTX)")
    ap.add_argument("--file", metavar="PATH",
                    help="bulk lookup: one indicator per line (# starts a comment)")
    ap.add_argument("--prescan-file", metavar="PATH",
                    help="bulk passive site check: one URL/domain/IP per line")
    ap.add_argument("--deep", action="store_true",
                    help="with --lookup/--file: add VirusTotal relations/sandbox behaviour and "
                         "AbuseIPDB /24 check (slower, uses more daily quota)")
    ap.add_argument("--feed", action="store_true", help="print current threat feed and exit")
    ap.add_argument("--csv", metavar="PATH", help="also export results to CSV")
    ap.add_argument("--json", action="store_true",
                    help="print machine-readable JSON instead of the text view")
    args = ap.parse_args()
    QUIET = args.json

    records, bulk = [], False
    if args.lookup:
        records.append(cli_lookup(args.lookup, deep=args.deep))
    elif args.poc:
        records.append(cli_lookup(args.poc, poc_only=True))
    elif args.prescan:
        records.append(cli_prescan(args.prescan))
    elif args.feed:
        records.append(cli_feed())
    elif args.file or args.prescan_file:
        bulk = True
        fn = (lambda item: cli_lookup(item, deep=args.deep)) if args.file else cli_prescan
        try:
            items = read_indicators(args.file or args.prescan_file)
        except OSError as exc:
            print(f"cannot read indicator file: {exc.strerror}", file=sys.stderr)
            sys.exit(2)
        for n, item in enumerate(items, 1):
            out(f"\n######## [{n}/{len(items)}] {item}", "cyn", True)
            records.append(fn(item))
        if not QUIET and args.prescan_file:
            out("\nSUMMARY", "cyn", True)
            for r in records:
                doc = r["json"]
                if r.get("error"):
                    out(f"  {'-':>3}  {r['indicator']:<40} skipped: {r['error']}", "yel")
                else:
                    out(f"  {doc['score']:>3}  {r['indicator']:<40} {doc['verdict']}",
                        verdict_of(doc["score"])[1])
    else:
        run_tui()
        return

    if args.csv:
        wrote = False
        for r in records:
            if r["sections"]:
                export_csv_file(args.csv, r["indicator"], r["kind"], r["sections"], append=wrote)
                wrote = True
        if wrote:
            out(f"csv exported: {args.csv}", "grn")
    if args.json:
        docs = [r["json"] for r in records]
        print(json.dumps(docs if bulk else docs[0], indent=2, ensure_ascii=False))
    if not bulk and records[0].get("error"):
        sys.exit(2)


def run_tui():
    fd = None
    try:
        fd = sys.stdout.fileno()
        os.write(fd, b"\x1b=")
    except OSError:
        pass
    try:
        curses.wrapper(lambda stdscr: Tui(stdscr).run())
    except KeyboardInterrupt:
        pass
    finally:
        if fd is not None:
            try:
                os.write(fd, b"\x1b>")
            except OSError:
                pass


if __name__ == "__main__":
    main()
