"""
process.py - turn raw internet-scan banners (zstd NDJSON) into one scored row per company.

Usage:
    python process.py firmable.zst                 # whole file
    python process.py firmable.zst --limit 200000  # quick test on the first N records

Output (same folder):
    companies.parquet   one row per company: score, tier, signal counts, top reasons
    companies_top.csv   top 5,000 companies, for a quick look in Excel
    run_stats.txt       what was read, skipped and why

Design notes
- Streams the file: never decompresses to disk, memory grows with #companies, not #records.
- Company key = registered domain (record.domains, else SSL certificate CN).
- Records behind a CDN/WAF (tag 'cdn') are the provider's servers, not the company's:
  they add a 'protected by WAF/CDN' maturity signal and nothing else.
- Honeypots are dropped (they advertise fake vulnerabilities).
- Generic ISP reverse-DNS names (e.g. 1-2-3-4.dsl.isp.net) are dropped: that's a home user, not a company.
- CVEs are weighted by real-world exploitation (CISA KEV, ransomware use, EPSS), not by raw count.
"""
import sys, io, re, math, time, argparse, collections
import zstandard as zstd
try:
    import orjson as _j
    loads = _j.loads
except ImportError:
    import json as _j
    loads = _j.loads

# ---------------------------------------------------------------- signal definitions
# key: (points, label shown to the salesperson)
SIGNALS = {
    "kev_cve":        (25, "actively exploited CVE (CISA KEV)"),
    "ransomware_cve": (20, "CVE used by ransomware gangs"),
    "critical_cve":   (10, "critical CVE likely to be exploited (CVSS 9+, EPSS >= 10%)"),
    "edge_risky":     (15, "VPN/firewall appliance that is vulnerable or end-of-life"),
    "remote_access":  (12, "remote access open to the internet (RDP/VNC/Telnet/SMB)"),
    "database_open":  (12, "database or cluster open to the internet"),
    "ics":            (12, "industrial control system exposed"),
    "eol":            (8,  "end-of-life software or OS"),
    "iot_mgmt":       (5,  "cameras / device management exposed (CCTV, SNMP, FTP, IPMI)"),
    "weak_tls":       (3,  "outdated encryption (SSLv2/3, TLS 1.0/1.1)"),
    "expired_cert":   (3,  "expired SSL certificate"),
    "self_signed":    (3,  "self-signed SSL certificate"),
    "login_exposed":  (3,  "login page exposed"),
    "open_dir":       (3,  "open directory listing"),
}
MATURITY = {
    "waf_cdn":     (-5, "already behind a WAF/CDN (Cloudflare, Imperva, Akamai...)"),
    "securitytxt": (-3, "publishes security.txt"),
    "hsts":        (-1, "uses HSTS"),
    "pqc":         (-2, "supports post-quantum crypto"),
}

REMOTE_KEYS = {"rdp_encryption", "vnc", "telnet", "smb", "netbios", "msrpc"}
REMOTE_PORTS = {3389, 5900, 5901, 23, 445, 139, 135}
DB_KEYS = {"mysql", "mysqlx", "mongodb", "redis", "couchdb", "influxdb", "kubernetes", "mssql_ssrp",
           "elastic", "oracle_tnslsnr", "pgbouncer", "memcached", "cassandra"}
DB_PORTS = {3306, 27017, 6379, 5984, 8086, 9200, 6443, 10250, 1433, 1521, 5432, 11211, 9042}
ICS_KEYS = {"siemens_s7", "bacnet", "modbus", "dnp3", "trane_tracer_sc", "ethernetip", "codesys"}
IOT_KEYS = {"dahua", "dahua_dvr_web", "hikvision", "snmp", "ftp", "ipmi", "hp_ilo", "ip_camera"}
EDGE_RE = re.compile(r"fortinet|fortigate|sonicwall|check ?point|checkpoint|cisco asa|pix|pulse secure|ivanti|"
                     r"citrix|netscaler|globalprotect|palo alto|mikrotik|f5 big-ip|watchguard|zyxel|draytek", re.I)
EOL_OS_RE = re.compile(r"windows (xp|7|vista|2000|2003|2008|8)\b|windows server 200[038]|linux 2\.", re.I)
WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
PROVIDER_DOMAINS = {"amazonaws.com", "cloudfront.net", "googleusercontent.com", "akamaitechnologies.com",
                    "akamaiedge.net", "incapdns.net", "cloudapp.net", "azure.com", "linodeusercontent.com",
                    "vultrusercontent.com", "your-server.de", "fastly.net", "cloudflare.net", "aliyuncs.com",
                    "googlevideo.com", "1e100.net", "digitaloceanspaces.com", "herokuapp.com", "fly.dev"}
SLD = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}


def reg_domain(name):
    """crude registered-domain extraction (good enough for cert CNs)."""
    name = (name or "").lower().strip().lstrip("*.").rstrip(".")
    if "." not in name or re.fullmatch(r"[\d.]+", name):
        return None
    p = name.split(".")
    if len(p) >= 3 and p[-2] in SLD and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


PTR_WORDS = re.compile(r"(^|[.\-])(dsl|adsl|vdsl|dyn|dynamic|dynip|pool|cable|dhcp|ppp|pppoe|cpe|customer|cust|"
                       r"client|home|res|resi|broadband|bb|fttx|ftth|fiber|static|user|subscriber|mobile|"
                       r"wireless|lte|gprs|ip)[.\-\d]", re.I)
ISP_ORG = re.compile(r"telecom|telekom|communications|broadband|cable|dsl|internet service|isp\b|home clients|"
                     r"mobile|wireless|telefonica|vodafone|orange|comcast|charter|verizon|at&t|viettel|vnpt|"
                     r"telstra|bharti|jio|claro|vivo|movistar|swisscom|virgin media|sfr|bouygues|free sas|"
                     r"ftth|fibre|fiber|tele2|telia|telenor|kpn|proximus|belgacom|rostelecom|chinanet|unicom|"
                     r"china mobile|kt corp|korea telecom|sk broadband|lg (powercomm|uplus)", re.I)


def is_generic_ptr(hostnames, ip):
    """ISP reverse-DNS (203-0-113-25.dsl.isp.net, cpe-1-2-3-4.res.isp.com, d4c3b2a1.static.isp.net)
    -> a home/consumer connection, not a company."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    hexip = "".join(f"{int(x):02x}" for x in parts)
    for h in hostnames:
        h = h.lower()
        first = h.split(".")[0]
        if (("-".join(parts) in h) or ("-".join(reversed(parts)) in h) or ip in h
                or "".join(f"{int(x):03d}" for x in parts) in h or hexip in h
                or len(re.findall(r"\d+", first)) >= 3
                or (PTR_WORDS.search(h) and re.search(r"\d", first))):
            return True
    return False


def company_key(r):
    for d in r.get("domains") or []:
        d = d.lower()
        if d not in PROVIDER_DOMAINS:
            return d, "domain"
    cert = ((r.get("ssl") or {}).get("cert") or {}).get("subject") or {}
    d = reg_domain(cert.get("CN"))
    if d and d not in PROVIDER_DOMAINS:
        return d, "cert"
    return None, None


def record_signals(r, tags):
    """return set of signal keys + KEV/ransomware CVE ids for one record (non-CDN, non-honeypot)."""
    s = set()
    kev, rans = set(), set()
    port = r.get("port")
    vulns = r.get("vulns") or {}
    for cve, d in vulns.items():
        if not isinstance(d, dict):
            continue
        if d.get("kev"):
            kev.add(cve)
            if d.get("verified"):
                s.add("kev_verified")
        if d.get("ransomware_campaign"):
            rans.add(cve)
        cv, ep = d.get("cvss") or 0, d.get("epss") or 0
        if isinstance(cv, (int, float)) and isinstance(ep, (int, float)) and cv >= 9 and ep >= 0.10:
            s.add("critical_cve")
    if kev: s.add("kev_cve")
    if rans: s.add("ransomware_cve")

    prod = f"{r.get('product') or ''} {r.get('os') or ''}"
    is_eol = "eol-product" in tags or "eol-os" in tags or bool(EOL_OS_RE.search(r.get("os") or ""))
    is_edge = bool(EDGE_RE.search(prod)) or any(k in r for k in ("fortinet", "checkpoint", "mikrotik_routeros", "mikrotik_winbox"))
    if is_eol: s.add("eol")
    if is_edge and (vulns or is_eol): s.add("edge_risky")
    if REMOTE_KEYS & r.keys() or port in REMOTE_PORTS: s.add("remote_access")
    if DB_KEYS & r.keys() or port in DB_PORTS or "database" in tags: s.add("database_open")
    if ICS_KEYS & r.keys() or "ics" in tags: s.add("ics")
    if IOT_KEYS & r.keys() or "iot" in tags: s.add("iot_mgmt")
    if "open-dir" in tags or "open_dir" in r: s.add("open_dir")

    ssl = r.get("ssl")
    if ssl:
        if WEAK_TLS & set(ssl.get("versions") or []): s.add("weak_tls")
        cert = ssl.get("cert") or {}
        if cert.get("expired"): s.add("expired_cert")
        if "self-signed" in tags or (cert.get("subject") and cert.get("subject") == cert.get("issuer")):
            s.add("self_signed")
    http = r.get("http")
    if http:
        t = (http.get("title") or "").lower()
        if "login" in t or "sign in" in t or "log in" in t: s.add("login_exposed")
        if "index of /" in t: s.add("open_dir")
    return s, kev, rans


def maturity_signals(r, tags):
    m = set()
    if "cdn" in tags: m.add("waf_cdn")
    if "pqc" in tags: m.add("pqc")
    http = r.get("http")
    if http:
        if http.get("securitytxt"): m.add("securitytxt")
        if "HSTS" in (http.get("components") or {}): m.add("hsts")
    return m


def new_company():
    return {"records": 0, "ips": set(), "ports": set(), "sig": collections.Counter(), "mat": set(),
            "kev": set(), "rans": set(), "country": collections.Counter(), "org": collections.Counter(),
            "cloud": set(), "products": collections.Counter(), "key_src": None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    stats = collections.Counter()
    cos = {}
    t0 = time.time()
    with open(a.path, "rb") as f:
        reader = io.TextIOWrapper(zstd.ZstdDecompressor().stream_reader(f), encoding="utf-8", errors="replace")
        for line in reader:
            stats["lines"] += 1
            try:
                r = loads(line)
            except Exception:
                stats["bad json"] += 1
                continue
            tags = set(r.get("tags") or [])
            if "honeypot" in tags:
                stats["skipped: honeypot"] += 1
                continue
            key, src = company_key(r)
            if not key:
                stats["skipped: no domain / cert name"] += 1
                continue
            if is_generic_ptr(r.get("hostnames") or [], r.get("ip_str")):
                stats["skipped: ISP home connection (generic reverse DNS)"] += 1
                continue
            c = cos.get(key)
            if c is None:
                c = cos[key] = new_company(); c["key_src"] = src
            c["records"] += 1
            if len(c["ips"]) < 5000: c["ips"].add(r.get("ip_str"))
            if len(c["ports"]) < 500: c["ports"].add(r.get("port"))
            c["country"][(r.get("location") or {}).get("country_code")] += 1
            c["org"][r.get("org")] += 1
            prov = (r.get("cloud") or {}).get("provider")
            if prov: c["cloud"].add(prov)
            if r.get("product"): c["products"][r["product"]] += 1
            c["mat"] |= maturity_signals(r, tags)
            if "cdn" in tags:
                stats["cdn/waf records (risk not scored)"] += 1
                continue
            sig, kev, rans = record_signals(r, tags)
            for s in sig: c["sig"][s] += 1
            if len(c["kev"]) < 50: c["kev"] |= kev
            if len(c["rans"]) < 50: c["rans"] |= rans
            stats["scored records"] += 1
            if stats["lines"] % 500_000 == 0:
                rate = stats["lines"] / (time.time() - t0)
                print(f"  {stats['lines']:,} records | {len(cos):,} companies | {rate:,.0f} rec/s", flush=True)
            if a.limit and stats["lines"] >= a.limit:
                break

    # ---------------------------------------------------------------- score
    def pts(w, n):
        # first hit = full points, more hits add a little (log), capped at 2x -> 50 cameras != 50x points
        return 0 if n <= 0 else w * min(1 + math.log2(n) / 3, 2)

    rows = []
    for dom, c in cos.items():
        n_ips = len(c["ips"])
        top_org = c["org"].most_common(1)[0][0] or ""
        # an ISP's own domain covering many customer IPs = consumer network, not a prospect
        is_isp = n_ips >= 50 and bool(ISP_ORG.search(top_org))
        parts = []
        for k, (w, label) in SIGNALS.items():
            n = len(c["kev"]) if k == "kev_cve" else len(c["rans"]) if k == "ransomware_cve" else c["sig"][k]
            p = pts(w, n)
            if k == "kev_cve" and p and not c["sig"]["kev_verified"]:
                label += " - inferred from software version"
            if p: parts.append((p, f"{label} x{n}" if n > 1 else label))
        risk = sum(p for p, _ in parts)
        mat = sum(MATURITY[m][0] for m in c["mat"])
        score = max(risk + mat, 0)
        parts.sort(reverse=True)
        # distinct kinds of evidence (CVE flags count as one kind: they come from the same banner)
        kinds = {("cve" if k in ("kev_cve", "ransomware_cve", "critical_cve") else k)
                 for k in SIGNALS if (len(c["kev"]) if k == "kev_cve" else len(c["rans"]) if k == "ransomware_cve" else c["sig"][k]) > 0}
        rows.append({
            "company": dom,
            "is_isp": is_isp,
            "signal_kinds": len(kinds),
            "kev_verified": c["sig"]["kev_verified"] > 0,
            "score": round(score, 1),
            "risk_points": round(risk, 1),
            "maturity_points": mat,
            "top_reasons": " | ".join(l for _, l in parts[:3]),
            "maturity": " | ".join(MATURITY[m][1] for m in sorted(c["mat"])),
            "servers": n_ips,
            "open_services": c["records"],
            "distinct_ports": len(c["ports"]),
            "footprint": "large" if n_ips >= 50 else "medium" if n_ips >= 10 else "small",
            "country": c["country"].most_common(1)[0][0],
            "hosting_org": c["org"].most_common(1)[0][0],
            "cloud": ", ".join(sorted(c["cloud"])),
            "top_products": ", ".join(p for p, _ in c["products"].most_common(5)),
            "kev_cves": ", ".join(sorted(c["kev"])[:10]),
            "ransomware_cves": ", ".join(sorted(c["rans"])[:10]),
            "identified_by": c["key_src"],
            **{f"n_{k}": (len(c["kev"]) if k == "kev_cve" else len(c["rans"]) if k == "ransomware_cve" else c["sig"][k])
               for k in SIGNALS},
        })

    import pandas as pd
    df = pd.DataFrame(rows)
    stats["companies excluded as ISP / consumer network"] = int(df["is_isp"].sum())
    df = df[~df["is_isp"]].drop(columns="is_isp")
    df = df.sort_values(["score", "signal_kinds", "servers"], ascending=False).reset_index(drop=True)
    df["rank"] = df.index + 1
    df["tier"] = pd.cut(df["score"], [-1, 0.01, 10, 30, 1e9], labels=["No signal", "Low", "Warm", "Hot"]).astype(str)
    # Hot needs independent evidence: at least 2 different kinds of signal
    df.loc[(df["tier"] == "Hot") & (df["signal_kinds"] < 2), "tier"] = "Warm"
    df.to_parquet("companies_agg.parquet", index=False)  # raw per-company aggregates; score.py turns these into the final ranking
    df.head(5000).to_csv("companies_top.csv", index=False)

    secs = time.time() - t0
    with open("run_stats.txt", "w", encoding="utf-8") as out:
        lines = [f"run time: {secs/60:.1f} min", *(f"{k}: {v:,}" for k, v in stats.items()),
                 f"companies: {len(df):,}", "tiers: " + ", ".join(f"{k} {v:,}" for k, v in df['tier'].value_counts().items())]
        out.write("\n".join(lines))
    print("\n".join(lines))
    print("\nTOP 15:")
    print(df[["rank", "company", "score", "tier", "servers", "top_reasons"]].head(15).to_string(index=False, max_colwidth=90))


if __name__ == "__main__":
    main()

