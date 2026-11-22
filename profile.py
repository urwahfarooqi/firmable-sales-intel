import sys, json, io, collections, zstandard as zstd

path = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 200000   # records to sample
keys, nested, ports, modules, countries = (collections.Counter() for _ in range(5))
orgs, domains = collections.Counter(), collections.Counter()
n = bad = 0
with open(path, "rb") as f:
    reader = io.TextIOWrapper(zstd.ZstdDecompressor().stream_reader(f), encoding="utf-8", errors="replace")
    for line in reader:
        try:
            r = json.loads(line)
        except Exception:
            bad += 1; continue
        n += 1
        for k, v in r.items():
            keys[k] += 1
            if isinstance(v, dict):
                for k2 in v: nested[f"{k}.{k2}"] += 1
        ports[r.get("port")] += 1
        modules[(r.get("_shodan") or {}).get("module")] += 1
        countries[(r.get("location") or {}).get("country_code")] += 1
        orgs[r.get("org")] += 1
        for d in r.get("domains") or []: domains[d] += 1
        if n >= N: break

print(f"records read: {n}, bad lines: {bad}\n")
print("TOP-LEVEL FIELDS (% of records):")
for k, c in keys.most_common(): print(f"  {k:30} {100*c/n:5.1f}%")
print("\nNESTED FIELDS:")
for k, c in nested.most_common(60): print(f"  {k:40} {100*c/n:5.1f}%")
for title, ctr in [("PORTS", ports), ("SERVICES", modules), ("COUNTRIES", countries)]:
    print(f"\nTOP {title}:"); [print(f"  {k}: {c}") for k, c in ctr.most_common(15)]
print(f"\ndistinct orgs: {len(orgs)}, distinct domains: {len(domains)}")
