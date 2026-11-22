# Security Need Finder: sales intelligence from internet scan data

**Live app:** {{APP_URL}} (password shared separately)

A cybersecurity sales team wants to know **which companies need help right now** and **what to say when they call**.
This project turns one raw internet-scan file (18.2M server banners, 11.7 GB zstd) into a ranked list of
companies, each with a score, a tier and plain-English reasons a salesperson can use as talking points.

## 1. What is in the data

One record = one internet-facing server/port seen by a scanner (Shodan-style banner, NDJSON).
I profiled it before writing any scoring (`profile.py`, `profile2.py`, first 200K records):

- Every record has `domains`, `org`, `port`, `location`; 74% have a domain we can tie to a company.
- Security-relevant fields are sparse: `http` 20%, `ssl` 6%, `vulns` 2.1%, risky services under 1% each.
- `vulns` entries carry **cvss, epss, kev (CISA Known Exploited) and ransomware_campaign** flags.
- `org` is mostly **Incapsula/Imperva (31%) and Google (21%)**: the hosting or security provider, not the company.

## 2. Hidden signals (what you would miss by scoring the raw file)

| Finding | What it means | What I did |
|---|---|---|
| Half the records are CDN/WAF edge servers | A CVE on an Imperva IP is Imperva's, not the customer's | Edge servers add a **"already pays for a WAF"** maturity signal, never risk points |
| 1.3% are honeypots | They advertise fake vulnerabilities and would top any naive ranking | Dropped |
| Thousands of "domains" are ISPs (`*.spectrum.com`, `*.dsl.isp.net`) | Home routers carrying the ISP's name, not a buyer | Generic reverse-DNS patterns dropped; ISP domains excluded |
| Raw CVE counts are inflated | Many CVEs are inferred from a version banner; 1 server can list 20+ | Score **exploitation** (KEV, ransomware, EPSS), not counts; label inferred-only KEVs |
| security.txt / HSTS are almost never present | Absence does not separate companies | Used only as small *maturity* credits when present |
| VPN/firewall appliances (FortiGate, SonicWall, Check Point, Cisco) | Today's main ransomware entry point | Separate high-weight signal when vulnerable or end-of-life |

## 3. Scoring

Per company (registered domain, or SSL certificate name when no domain):

| Signal | Points |
|---|---|
| CVE on CISA KEV (actively exploited) | 25 |
| CVE used in ransomware campaigns | 20 |
| VPN/firewall appliance vulnerable or end-of-life | 15 |
| RDP / VNC / Telnet / SMB exposed | 12 |
| Database / Kubernetes exposed | 12 |
| Industrial control system exposed | 12 |
| Critical CVE (CVSS 9+) with EPSS >= 10% | 10 |
| End-of-life software / OS | 8 |
| Cameras, SNMP, FTP, IPMI exposed | 5 |
| Weak TLS, expired/self-signed cert, exposed login, open directory | 3 each |
| Maturity: WAF/CDN -5, security.txt -3, post-quantum TLS -2, HSTS -1 | |

- First hit gets full points; repeats add a little (log), capped at 2x, so 50 cameras do not outweigh one exploited VPN.
- **Tiers:** Hot > 30 **and at least 2 different kinds of evidence**; Warm 10-30; Low 0-10.
- Each company keeps its **top 3 reasons**, footprint (servers seen) and the KEV/ransomware CVE ids.
- Points are hand-set from how attacks actually start (exploited edge devices, exposed remote access, exposed data).
  With win/loss data from the sales team I would fit these weights instead.

## 4. How I checked it works

1. **Profiled before scoring:** the field-coverage numbers above decided which signals were usable.
2. **Read the top of the list after every full run.**
   - Run 1 ranked ISPs first (Spectrum, Orange, Vodafone...) and produced 48K "Hot" companies, 37K of them
     a single server whose only reason was one version-inferred KEV CVE.
   - Fixes: broader reverse-DNS/ISP exclusion, "Hot needs 2+ kinds of evidence", inferred-KEV labelling.
   - Run 2: {{RUN2_SUMMARY}}
3. **Spot checks:** manually reviewed the top {{N_SPOT}} Hot accounts against their raw records. {{SPOT_RESULT}}
4. **Run stats** (`run_stats.txt`) log every record read, skipped and why, so drops are visible, not silent.

## 5. Results (this file)

{{RESULTS_TABLE}}

## 6. Scaling to thousands of files a month

- `process.py` **streams** zstd NDJSON: memory grows with the number of companies, not records
  (18.2M records in ~20 min on a laptop, single core).
- Production design: one worker per incoming file (AWS Batch / Cloud Run jobs, or Spark on EMR/Glue), each writing
  **per-file company aggregates** to Parquet in S3; a nightly job merges aggregates (latest sighting wins per server)
  and re-scores only companies that changed. The scoring is a pure function of the aggregates, so weights can be changed
  without re-reading raw data.
- Add a `first_seen / last_seen` per signal to surface **"new this week"** exposures, the strongest trigger for outreach.

## 7. How I used AI

- I used **Claude (Claude Code)** as a pair programmer: it wrote the profiling, processing and app code from my
  decisions, and explained unfamiliar security fields.
- I looked at the data myself first (field coverage, value distributions) and chose the signals from that.
- **How I knew it was right:** every claim was checked against the data. The first full run looked plausible but
  was wrong (ISPs at the top, too many Hot); I caught that by reading the results, not by trusting the code.
- **Cost:** the pipeline makes **no LLM API calls**, so scoring 18M records costs only compute (~20 min on a laptop).
  Development used a Claude subscription.

## 8. Run it

```bash
pip install -r requirements.txt zstandard
python profile.py  firmable.zst 200000   # field coverage
python profile2.py firmable.zst 200000   # value distributions
python process.py  firmable.zst          # -> companies.parquet, companies_top.csv, run_stats.txt
streamlit run app.py
```
The raw data file is not in the repo.

## Limitations
- One snapshot: no history, so no "new exposure" trigger yet.
- Company = domain; subsidiaries and multi-domain companies are not merged.
- No firmographics (industry, headcount): footprint is a rough proxy for size and budget.
- Weights are expert-set, not trained.
