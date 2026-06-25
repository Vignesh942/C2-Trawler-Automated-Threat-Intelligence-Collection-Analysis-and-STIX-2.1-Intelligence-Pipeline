# C2-Trawler

<img width="1024" height="1024" alt="C2-Trawler_logo" src="https://github.com/user-attachments/assets/2360f3df-13c4-49c9-aacb-7cc77466e608" />


## Automated Threat Intelligence Collection, Analysis, and STIX 2.1 Intelligence Pipeline

C2-Trawler is a Python-based Cyber Threat Intelligence (CTI) pipeline that automates the collection, processing, enrichment, and reporting of malicious infrastructure indicators from multiple open-source threat intelligence feeds.

The project aggregates threat data from ThreatFox, URLHaus, and OpenPhish, normalizes Indicators of Compromise (IOCs), maps malware activity to MITRE ATT&CK techniques, generates STIX 2.1 threat intelligence bundles, and produces analyst-friendly intelligence reports.

Rather than manually reviewing thousands of threat indicators across multiple feeds, C2-Trawler transforms raw threat data into actionable intelligence for SOC analysts, threat hunters, and security researchers.

---

## Key Features

### Multi-Source Threat Intelligence Collection

Collects threat indicators from:

* ThreatFox
* URLHaus
* OpenPhish

Supported IOC Types:

* IPv4 Addresses
* Domains
* URLs

---

### IOC Normalization and Deduplication

* Normalizes data from multiple feeds into a common schema
* Removes duplicate indicators
* Maintains source attribution
* Standardizes IOC formats

---

### Malware Profiling

Identifies and categorizes malware families such as:

* Mozi
* Mirai
* Remcos
* AsyncRAT
* Lumma
* AgentTesla
* FormBook
* Vidar
* Sliver
* Cobalt Strike

Generates statistics on:

* Most observed malware families
* Threat categories
* IOC distributions

---

### MITRE ATT&CK Mapping

Maps malware families to ATT&CK techniques including:

* T1071 – Application Layer Protocol
* T1105 – Ingress Tool Transfer
* T1056 – Input Capture
* T1566 – Phishing
* T1204 – User Execution
* T1573 – Encrypted Channel

Provides contextual intelligence for threat hunting and detection engineering.

---

### STIX 2.1 Intelligence Generation

Generates structured STIX 2.1 intelligence bundles containing:

* Indicator Objects
* Malware Objects
* Attack Pattern Objects
* Relationship Objects

Example Relationship:

Indicator → Malware → ATT&CK Technique

The generated bundle can be imported into:

* OpenCTI
* MISP
* Wazuh
* Other STIX/TAXII-compatible platforms

---

### Threat Intelligence Reporting

Automatically generates:

* Executive Summary
* Threat Category Analysis
* Malware Family Rankings
* IOC Statistics
* ATT&CK Analysis
* Threat Assessment
* Recommended Actions

Outputs include:

* TXT Reports
* JSON Reports
* CSV Exports
* STIX 2.1 Bundles

---

## Architecture

<img width="843" height="728" alt="C2-Trawler — Automated C2 Threat Intelligence Pipeline - visual selection" src="https://github.com/user-attachments/assets/792f504e-8925-4c91-9a2c-90cdec263812" />



## Example Output

### Collection Statistics

* Total Indicators: 23,000+
* Multiple Threat Feeds Aggregated
* Automated IOC Processing
* ATT&CK Technique Mapping
* STIX Intelligence Bundle Generation

### Top Malware Families

* Mozi
* Mirai
* Remcos
* AsyncRAT
* Lumma

### Threat Categories

* Malware Download
* Botnet Command & Control
* Phishing
* Payload Delivery

---

## Project Structure

```text
c2-trawler/

├── collectors/
├── normalizer/
├── enrichment/
├── mitre/
├── stix_generator/
├── reporting/
├── exports/
├── reports/
├── data/
├── logs/
├── utils/
├── main.py
├── requirements.txt
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/c2-trawler.git
cd c2-trawler
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Run a complete intelligence collection cycle:

```bash
python main.py
```

Search for an IP:

```bash
python main.py search-ip 1.2.3.4
```

Search for a domain:

```bash
python main.py search-domain example.com
```

Search for a malware family:

```bash
python main.py search-malware Remcos
```

---

## Generated Artifacts

### Reports

```text
reports/threat_report.txt
reports/threat_report.json
```

### IOC Exports

```text
exports/iocs.json
exports/iocs.csv
```

### STIX Intelligence

```text
exports/stix_bundle.json
```

---

## Skills Demonstrated

* Threat Intelligence Operations
* Cyber Threat Intelligence (CTI)
* IOC Collection and Analysis
* MITRE ATT&CK Framework
* STIX 2.1 Intelligence Modeling
* Threat Reporting
* Security Automation
* Python Development
* Data Processing and Normalization
* Threat Feed Integration

---

## Future Improvements

* Historical trend analysis
* Daily malware activity tracking
* Threat feed scheduling
* TAXII support
* IOC reputation scoring
* OpenCTI integration
* Threat campaign correlation
* Detection rule generation

---

