"""Streamlit app: find and prioritise companies that need cybersecurity help.
Run locally:  streamlit run app.py
"""
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Security Need Finder", page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------- optional password gate
# The data names real companies with real exposures, so the hosted app is not open to everyone.
try:
    pw = st.secrets.get("APP_PASSWORD")
except Exception:  # no secrets file locally -> no password
    pw = None
if pw:
    if not st.session_state.get("ok"):
        st.title("🛡️ Security Need Finder")
        if st.text_input("Password", type="password") == pw:
            st.session_state["ok"] = True
            st.rerun()
        st.stop()

SIGNAL_LABELS = {
    "n_kev_cve": "Actively exploited CVE (KEV)",
    "n_ransomware_cve": "Ransomware-linked CVE",
    "n_critical_cve": "Critical CVE, likely exploited",
    "n_edge_risky": "Vulnerable / EOL VPN-firewall",
    "n_remote_access": "Remote access exposed",
    "n_database_open": "Database exposed",
    "n_ics": "Industrial control exposed",
    "n_eol": "End-of-life software",
    "n_iot_mgmt": "Cameras / device mgmt exposed",
    "n_weak_tls": "Outdated encryption",
    "n_expired_cert": "Expired certificate",
    "n_self_signed": "Self-signed certificate",
    "n_login_exposed": "Login page exposed",
    "n_open_dir": "Open directory",
}
PITCH = {
    "n_kev_cve": "Vulnerability management / patching - hackers are already using these holes.",
    "n_ransomware_cve": "Ransomware readiness: these exact flaws were used by ransomware gangs.",
    "n_edge_risky": "Their VPN/firewall is a known ransomware entry point - edge security / firewall refresh.",
    "n_remote_access": "Exposed RDP/SMB is the #1 ransomware entry - zero-trust remote access.",
    "n_database_open": "Data exposed to the internet - data security / cloud posture management.",
    "n_ics": "OT/ICS security - industrial systems visible online.",
    "n_eol": "Unsupported software - asset management and patching.",
    "n_iot_mgmt": "IoT/camera exposure - network segmentation and IoT security.",
    "n_weak_tls": "Basic hygiene gaps - attack surface management.",
    "n_expired_cert": "Certificate lifecycle management.",
}


@st.cache_data
def load():
    return pd.read_parquet("companies.parquet")


df = load()

st.title("🛡️ Security Need Finder")
st.caption("Companies ranked by how urgently they need cybersecurity help, from internet-facing scan data. "
           "Score = weighted risk signals minus maturity signals.")

# ---------------------------------------------------------------- filters
with st.sidebar:
    st.header("Filters")
    q = st.text_input("Search company domain")
    tiers = st.multiselect("Tier", ["Hot", "Warm", "Low", "No signal", "Review"], default=["Hot", "Warm"],
                           help="Review = 100+ servers under one domain: usually an ISP or hosting network, check by hand")
    countries = st.multiselect("Country", sorted(df["country"].dropna().unique()))
    size = st.multiselect("Footprint", ["large", "medium", "small"])
    must = st.multiselect("Must have signal", list(SIGNAL_LABELS.values()))
    hide_waf = st.checkbox("Hide companies already behind a WAF/CDN", value=False)

f = df[df["tier"].isin(tiers)] if tiers else df
if q: f = f[f["company"].str.contains(q.lower(), na=False)]
if countries: f = f[f["country"].isin(countries)]
if size: f = f[f["footprint"].isin(size)]
for lbl in must:
    col = next(k for k, v in SIGNAL_LABELS.items() if v == lbl)
    f = f[f[col] > 0]
if hide_waf: f = f[~f["maturity"].fillna("").str.contains("WAF")]

# ---------------------------------------------------------------- KPIs
k1, k2, k3, k4 = st.columns(4)
k1.metric("Companies shown", f"{len(f):,}")
k2.metric("Hot", f"{(f['tier'] == 'Hot').sum():,}")
k3.metric("Exploited CVE: verified / inferred",
          f"{int(f['kev_verified'].sum()):,} / {int(((f['n_kev_cve'] > 0) & ~f['kev_verified']).sum()):,}",
          help="Verified = confirmed by the scanner. Inferred = guessed from the software version banner.")
k4.metric("Remote access exposed", f"{(f['n_remote_access'] > 0).sum():,}")

tab1, tab2, tab3 = st.tabs(["Ranked accounts", "Account detail", "How scoring works"])

with tab1:
    show = f[["rank", "company", "tier", "score", "top_reasons", "footprint", "servers", "country", "maturity"]]
    st.dataframe(show.head(1000), use_container_width=True, hide_index=True,
                 column_config={"score": st.column_config.ProgressColumn("score", format="%.0f", min_value=0,
                                                                          max_value=float(df["score"].max() or 1))})
    st.download_button("Download filtered list (CSV)", f.to_csv(index=False), "accounts.csv")

with tab2:
    pick = st.selectbox("Company", f["company"].head(1000))
    if pick:
        r = df[df["company"] == pick].iloc[0]
        a, b, c, d = st.columns(4)
        a.metric("Rank", f"#{int(r['rank']):,}"); b.metric("Score", r["score"])
        c.metric("Tier", r["tier"]); d.metric("Servers seen", int(r["servers"]))
        st.subheader("Why this account")
        found = [(SIGNAL_LABELS[k], int(r[k])) for k in SIGNAL_LABELS if r[k] > 0]
        if found:
            st.dataframe(pd.DataFrame(found, columns=["Signal", "Servers / CVEs"]), hide_index=True)
        else:
            st.write("No risk signals found.")
        if r["maturity"]:
            st.info("Maturity: " + r["maturity"])
        st.subheader("Talking points")
        pts = [PITCH[k] for k in PITCH if r[k] > 0]
        for p in pts[:4] or ["No urgent exposure - nurture, not a priority call."]:
            st.write("• " + p)
        with st.expander("Technical detail"):
            st.write({"Country": r["country"], "Hosting": r["hosting_org"], "Cloud": r["cloud"],
                      "Products seen": r["top_products"], "KEV CVEs": r["kev_cves"],
                      "Ransomware CVEs": r["ransomware_cves"], "Identified by": r["identified_by"]})

with tab3:
    st.markdown("""
**Signals (points per company, first hit = full points, repeats add a little, capped at 2x)**

| Signal | Points |
|---|---|
| CVE on CISA KEV (actively exploited) | 25 |
| CVE used in ransomware campaigns | 20 |
| VPN/firewall appliance vulnerable or end-of-life | 15 |
| RDP / VNC / Telnet / SMB open | 12 |
| Database / Kubernetes open | 12 |
| Industrial control system exposed | 12 |
| Critical CVE with EPSS >= 10% | 10 |
| End-of-life software / OS | 8 |
| Cameras, SNMP, FTP, IPMI exposed | 5 |
| Weak TLS, expired / self-signed cert, login page, open directory | 3 each |
| **Maturity:** behind WAF/CDN -5, security.txt -3, post-quantum crypto -2, HSTS -1 | |

**Cleaning:** honeypots removed; CDN/WAF edge servers are the provider's, so they only count as maturity;
ISP home connections (generic reverse DNS) removed; companies identified by domain, else SSL certificate name.

**Tiers:** Hot > 30, Warm 10-30, Low 0-10.
""")
