# Threat Intelligence IOC Triage Tool

A small, polished Django portfolio project for defensive cybersecurity workflows. The app accepts a CSV of suspicious indicators of compromise (IOCs), validates and classifies each indicator, performs safe local/passive enrichment, maps conservative MITRE ATT&CK context, scores confidence, and generates a Markdown or PDF report.

## Features

- CSV upload with required columns: `indicator`, `type`, `source`, `date_found`
- IOC detection for IPv4, IPv6, URLs, domains, MD5, SHA1, and SHA256 hashes
- Safe local enrichment only; no scanning, probing, exploitation, or content execution
- Placeholder API hooks for VirusTotal and AbuseIPDB through environment variables
- Results table with filtering by detected type and confidence level
- Badges for IOC type, reputation, and confidence
- Markdown report download and PDF export through ReportLab
- Basic service tests for detection, invalid inputs, confidence, and MITRE mapping

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On macOS/Linux, activate the virtual environment with `source .venv/bin/activate` instead.

## Database migrations

```bash
python manage.py migrate
```

## Start the server

```bash
python manage.py runserver
```

Open <http://127.0.0.1:8000/> and upload `sample_iocs.csv`.

## Run tests

```bash
python manage.py test
```

## Example CSV

```csv
indicator,type,source,date_found
185.199.108.153,ip,SIEM alert,2026-05-01
secure-login-update-example.com,domain,Email gateway,2026-05-01
http://45.77.12.10/login/update.exe,url,Proxy logs,2026-05-02
44d88612fea8a8f36de82e1278abb02f,hash,EDR alert,2026-05-02
```

## Screenshots

Placeholder for portfolio screenshots:

- Home/upload page
- Results table with filters
- Markdown report preview

## Portfolio explanation

This project demonstrates practical defensive engineering: secure file handling, robust validation, modular service design, transparent confidence scoring, and careful ATT&CK mapping without overclaiming attribution. It is intentionally local-first and safe for demos because enrichment is passive and API keys are optional environment variables only.

## Security notes

- Only `.csv` uploads are accepted.
- Upload size is limited to 2 MB.
- Uploaded content is parsed as text and never executed.
- The application does not actively scan, probe, exploit, brute force, or run malware.
- External API keys, if later used, should be stored only in environment variables such as `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY`.
- `.env`, virtual environments, SQLite databases, and upload directories are ignored by Git.
