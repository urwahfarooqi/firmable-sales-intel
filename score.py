"""
score.py - rank companies from the per-company aggregates written by process.py.

    python score.py            # companies_agg.parquet -> companies.parquet, companies_top.csv

Scoring is separate from ingestion on purpose: weights and rules can change in seconds
without re-reading 18M raw records (in production: re-score nightly from the merged aggregates).
"""
import math, re
import pandas as pd
from process import SIGNALS, MATURITY, ISP_ORG

# Hosting / VPS providers: their customers' servers carry the provider's reverse-DNS domain.
HOSTING_ORG = re.compile(r"hosting|ovh|godaddy|contabo|hetzner|namecheap|strato|interserver|hostpapa|hostwinds|"
                         r"digitalocean|linode|akamai|vultr|leaseweb|ionos|1&1|hostinger|bluehost|dreamhost|"
                         r"rackspace|softlayer|international business machines|spacex|starlink|scaleway|online s\.a\.s|"
                         r"choopa|psychz|m247|hivelocity|colocrossing|quadranet|server|datacenter|data center|"
                         r"cloud|vps|dedicated|locaweb|afrihost|dattatec|alibaba|aliyun|tencent|amazon|google|microsoft",
                         re.I)
JUNK_DOMAIN = re.compile(r"in-addr\.arpa$|ip6\.arpa$|^localhost|localdomain|^local$|^(example|test)\.(com|org|net)$", re.I)
PROVIDER_DOMAIN_WORDS = re.compile(r"server|hosting|host|vps|vds|dedi|srv|node|reverse|rdns|dns|cloud|static|dynamic|"
                                   r"customer|clientes|broadband|dsl|cable|fiber|fibra|isp|telecom|datacenter", re.I)

# Evidence an attacker can use directly, not inferred from a version banner.
STRONG = ["n_remote_access", "n_database_open", "n_ics", "n_edge_risky", "n_open_dir"]
MAT_BY_LABEL = {label: pts for pts, label in MATURITY.values()}
LARGE = 100  # servers under one domain


def pts(w, n):
    return 0 if n <= 0 else w * min(1 + math.log2(n) / 3, 2)


def is_provider(r):
    dom, org = r["company"], str(r["hosting_org"] or "")
    if JUNK_DOMAIN.search(dom):
        return True
    if r["servers"] >= 20 and (ISP_ORG.search(org) or HOSTING_ORG.search(org)):
        # the domain belongs to the network operator itself -> its customers, not one company
        return True
    if r["servers"] >= 10 and (PROVIDER_DOMAIN_WORDS.search(dom.rsplit(".", 1)[0]) or dom.endswith(".cloud")):
        return True
    return False


def score_row(r):
    parts = []
    for k, (w, label) in SIGNALS.items():
        n = int(r[f"n_{k}"])
        if not n:
            continue
        if k in ("kev_cve", "ransomware_cve") and not r["kev_verified"]:
            w, label = w / 2, label + " - inferred from software version"
        parts.append((pts(w, n), f"{label} x{n}" if n > 1 else label))
    risk = sum(p for p, _ in parts)
    mat = sum(MAT_BY_LABEL.get(m, 0) for m in str(r["maturity"] or "").split(" | ") if m)
    parts.sort(reverse=True)
    strong = bool(r["kev_verified"]) or any(r[c] > 0 for c in STRONG)
    return pd.Series({"risk_points": round(risk, 1), "maturity_points": mat, "score": round(max(risk + mat, 0), 1),
                      "top_reasons": " | ".join(l for _, l in parts[:3]), "has_direct_evidence": strong})


def main():
    df = pd.read_parquet("companies_agg.parquet")
    n0 = len(df)
    prov = df.apply(is_provider, axis=1)
    df = df[~prov].copy()
    df[["risk_points", "maturity_points", "score", "top_reasons", "has_direct_evidence"]] = df.apply(score_row, axis=1)
    df = df.sort_values(["score", "signal_kinds", "servers"], ascending=False).reset_index(drop=True)
    df["rank"] = df.index + 1
    df["tier"] = pd.cut(df["score"], [-1, 0.01, 10, 30, 1e9], labels=["No signal", "Low", "Warm", "Hot"]).astype(str)
    # Hot = high score AND something an attacker can use directly (verified KEV, exposed RDP/DB/ICS, vulnerable VPN)
    df.loc[(df["tier"] == "Hot") & ~df["has_direct_evidence"], "tier"] = "Warm"
    # 100+ servers under one domain is almost always an ISP / hosting network (its customers' machines),
    # occasionally a university or very large enterprise -> separate bucket for a human to check.
    df["segment"] = df["servers"].ge(LARGE).map({True: "Large network - verify", False: "Company"})
    df.loc[df["segment"] != "Company", "tier"] = "Review"
    df = pd.concat([df[df["segment"] == "Company"], df[df["segment"] != "Company"]]).reset_index(drop=True)
    df["rank"] = df.index + 1
    df.to_parquet("companies.parquet", index=False)
    df.head(5000).to_csv("companies_top.csv", index=False)

    with open("score_stats.txt", "w", encoding="utf-8") as out:
        out.write(f"companies in: {n0:,}\nexcluded as hosting/ISP/junk domain: {int(prov.sum()):,}\n"
                  f"companies ranked: {len(df):,}\ntiers: " +
                  ", ".join(f"{k} {v:,}" for k, v in df["tier"].value_counts().items()) + "\n")
    print(f"in {n0:,} | excluded providers {int(prov.sum()):,} | ranked {len(df):,}")
    print(df["tier"].value_counts().to_string())


if __name__ == "__main__":
    main()
