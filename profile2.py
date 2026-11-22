"""Second look: what values the security-relevant fields hold. Prints counts only."""
import sys, json, io, collections, zstandard as zstd

path = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 200000
C = collections.defaultdict(collections.Counter)
n = 0
RISKY = {"rdp_encryption", "smb", "telnet", "vnc", "ftp", "mysql", "mssql_ssrp", "mongodb", "redis", "couchdb",
         "influxdb", "kubernetes", "ollama", "microsoft_exchange", "fortinet", "checkpoint", "snmp", "ipmi",
         "hp_ilo", "open_dir", "hikvision", "dahua", "siemens_s7", "bacnet", "netbios", "msrpc", "ldap",
         "mikrotik_routeros", "mikrotik_winbox", "synology_dsm", "qnap", "vmware", "elastic", "docker"}

def headers_text(h):
    if isinstance(h, dict): return " ".join(h.keys()).lower()
    return str(h or "").lower()

with open(path, "rb") as f:
    reader = io.TextIOWrapper(zstd.ZstdDecompressor().stream_reader(f), encoding="utf-8", errors="replace")
    for line in reader:
        try: r = json.loads(line)
        except Exception: continue
        n += 1
        for t in r.get("tags") or []: C["tags"][t] += 1
        C["has domain"][bool(r.get("domains"))] += 1
        C["has hostname"][bool(r.get("hostnames"))] += 1
        C["org (top)"][r.get("org")] += 1
        C["cloud provider"][(r.get("cloud") or {}).get("provider")] += 1
        C["os"][r.get("os")] += 1
        if r.get("product"): C["product"][r["product"]] += 1
        for k in r:
            if k in RISKY: C["risky service"][k] += 1
        v = r.get("vulns")
        if v:
            C["vulns per record"][min(len(v), 20)] += 1
            for cve, d in v.items():
                if isinstance(d, dict):
                    for kk in d: C["vuln sub-fields"][kk] += 1
                    cv = d.get("cvss")
                    if isinstance(cv, (int, float)): C["cvss band"]["9-10" if cv >= 9 else "7-9" if cv >= 7 else "4-7" if cv >= 4 else "<4"] += 1
                    if d.get("kev") or d.get("cisa_kev"): C["kev"]["yes"] += 1
        s = r.get("ssl")
        if s:
            for ver in s.get("versions") or []: C["ssl versions offered"][ver] += 1
            cert = s.get("cert") or {}
            C["cert expired"][cert.get("expired")] += 1
            subj, iss = cert.get("subject") or {}, cert.get("issuer") or {}
            C["cert self-signed"][bool(subj) and subj == iss] += 1
            C["cert issuer"][(iss or {}).get("O")] += 1
        h = r.get("http")
        if h:
            C["http server"][(h.get("server") or "").split(" ")[0][:40]] += 1
            C["security.txt present"][bool(h.get("securitytxt"))] += 1
            ht = headers_text(h.get("headers")) + " " + str(r.get("data", ""))[:3000].lower()
            C["HSTS header"]["strict-transport-security" in ht] += 1
            C["CSP header"]["content-security-policy" in ht] += 1
            for comp in (h.get("components") or {}): C["web components"][comp] += 1
            t = (h.get("title") or "").lower()
            if "index of" in t: C["http title flags"]["open directory"] += 1
            if "login" in t or "sign in" in t: C["http title flags"]["login page"] += 1
        C["timestamp month"][str(r.get("timestamp", ""))[:7]] += 1
        if n >= N:
            print(f"compressed bytes read for {n} records: {f.tell():,}")
            break

print(f"records: {n}\n")
for name, ctr in C.items():
    print(f"== {name}")
    for k, c in ctr.most_common(20): print(f"   {str(k)[:60]:60} {c:>8}  {100*c/n:5.1f}%")
    print()
