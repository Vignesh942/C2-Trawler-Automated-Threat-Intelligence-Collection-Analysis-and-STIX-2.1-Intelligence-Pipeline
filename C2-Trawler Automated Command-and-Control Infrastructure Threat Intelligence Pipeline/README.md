# C2-Trawler

Automated command-and-control (C2) infrastructure threat intelligence pipeline. C2-Trawler collects indicators from free public feeds, normalizes and deduplicates them, enriches them with DNS/RDAP lookups, maps malware families to MITRE ATT&CK, and produces two analyst-ready outputs:

- **Human-readable report** for triage and executive review
- **STIX 2.1 bundle** for SIEM and threat intel platform ingestion

## Highlights

- End-to-end CTI workflow in a single CLI
- Free data sources only (ThreatFox, URLHaus, OpenPhish)
- Canonical malware family normalization aligned with MITRE mappings
- Best-effort enrichment with graceful failure handling
- Structured exports (JSON, CSV, STIX 2.1)

## Architecture

```text
Collection -> Normalization -> Deduplication -> Enrichment
    -> Malware Profiling -> MITRE Mapping -> STIX 2.1 -> Reporting -> Export
```

## Data Sources

| Source | Content |
|--------|---------|
| ThreatFox | Malware infrastructure and C2 indicators |
| URLHaus | Recent malicious URLs |
| OpenPhish | Active phishing URLs |

API keys are optional and loaded from `.env`. If ThreatFox returns `401 Unauthorized`, add a free ThreatFox API key as `THREATFOX_API_KEY`.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

## Quick Start

Run the full offline demo (no network required):

```powershell
python main.py run --sample --skip-enrichment
```

Run the full live pipeline:

```powershell
python main.py run
```

Fast live run without enrichment:

```powershell
python main.py run --skip-enrichment
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `python main.py run` | Full pipeline |
| `python main.py collect --days 3` | Collect raw feeds only |
| `python main.py normalize` | Normalize raw feed data |
| `python main.py dedupe` | Deduplicate normalized IOCs |
| `python main.py enrich` | Enrich unique IOCs |
| `python main.py profile` | Malware family statistics |
| `python main.py mitre` | MITRE ATT&CK mapping |
| `python main.py stix` | Generate STIX 2.1 bundle |
| `python main.py report` | Generate analyst reports |
| `python main.py export` | Export IOC JSON/CSV |
| `python main.py search-ip <ip>` | Search by IPv4 |
| `python main.py search-domain <domain>` | Search by domain |
| `python main.py search-malware <family>` | Search by malware family |

## Outputs

### Human-readable report

- `reports/threat_report.txt` — executive summary, feed breakdown, malware families, ATT&CK techniques, recommended actions
- `reports/threat_report.json` — structured equivalent for automation

### STIX 2.1 for SIEM

- `exports/stix_bundle.json` — STIX 2.1 bundle with indicators, malware objects, ATT&CK patterns, relationships, and report metadata
- `reports/stix_bundle.json` — duplicate copy for report packaging

### Supporting artifacts

- `data/raw/` — raw collector responses
- `data/normalized_iocs.json`, `data/unique_iocs.json`, `data/enriched_iocs.json`
- `reports/malware_statistics.json`, `reports/mitre_mapping.json`
- `exports/iocs.json`, `exports/iocs.csv`
- `logs/c2_trawler.log`

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `THREATFOX_API_KEY` | empty | Optional ThreatFox authentication |
| `REQUEST_TIMEOUT` | `120` | HTTP timeout in seconds |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## Notes

- Enrichment is best-effort. DNS, RDAP, or WHOIS failures are captured in each record's `enrichment.errors` list and the pipeline continues.
- WHOIS is disabled by default because public WHOIS servers often time out or rate-limit. Use `--enable-whois` when registrar metadata is required.
- By default, enrichment runs on the first 500 records. Use `--enrichment-limit 0` for all records or `--skip-enrichment` for the fastest run.
- STIX generation includes up to 1,000 indicators per run for performance. Use `--skip-stix` to bypass STIX entirely on very large datasets.
- Edit `mitre/mappings.json` to extend ATT&CK mappings for additional malware families.

## Tech Stack

Python 3.11+, `requests`, `stix2`, `python-dotenv`, `ipwhois`, `python-whois`
