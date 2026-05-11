# Threat Intelligence IOC Triage Tool

A small, polished Django portfolio project for defensive cybersecurity workflows. The app accepts a CSV of suspicious indicators of compromise (IOCs), validates and classifies each indicator, performs safe local/passive enrichment, maps conservative MITRE ATT&CK context, scores confidence, and generates a Markdown or PDF report.

## Features

- CSV upload for up to five files at a time, each 3 MB or smaller, with required columns: `indicator`, `type`, `source`, `date_found`
- IOC detection for IPv4, IPv6, URLs, domains, MD5, SHA1, and SHA256 hashes
- Safe local enrichment only; no scanning, probing, exploitation, or content execution
- Placeholder API hooks for VirusTotal and AbuseIPDB through environment variables
- Results table with filtering by detected type and confidence level
- Badges for IOC type, reputation, and confidence
- Markdown report download and PDF export with ReportLab when installed plus a built-in fallback PDF writer
- Basic service tests for detection, invalid inputs, confidence, and MITRE mapping

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On macOS/Linux, activate the virtual environment with `source .venv/bin/activate` instead.

## Database migrations

Run Django management commands from the folder that contains `manage.py` (the project root):

```bash
python manage.py migrate
```

If you accidentally use Python's module mode, this project also includes compatibility wrappers for:

```bash
python -m manage migrate
python -m manage.py migrate
```

The normal Django form, `python manage.py migrate`, is still recommended.

## Start the server

```bash
python manage.py runserver
```

Open <http://127.0.0.1:8000/> and upload `sample_iocs.csv` for a quick demo or `sample_iocs_comprehensive.csv` for a richer dataset with 180 suspicious IOC rows.

## Run tests

```bash
python manage.py test
```


## Troubleshooting management commands on Windows

Do not run `python -m manage.py migrate` from a directory that does not contain the project files. In PowerShell, first change into the repository folder and confirm `manage.py` is present:

```powershell
cd "D:\HOC\IOC Triage"
dir manage.py
python manage.py migrate
```

If `dir manage.py` does not show the file, you are in the wrong folder or the project files were not copied there.

## Example CSV files

The repository includes two ready-to-upload CSV files:

- `sample_iocs.csv` — a compact four-row smoke-test dataset.
- `sample_iocs_comprehensive.csv` — a richer 180-row dataset with IP, domain, URL, and hash examples from varied sources and dates.

Compact example format:

```csv
indicator,type,source,date_found
185.199.108.153,ip,SIEM alert,2026-05-01
secure-login-update-example.com,domain,Email gateway,2026-05-01
http://45.77.12.10/login/update.exe,url,Proxy logs,2026-05-02
44d88612fea8a8f36de82e1278abb02f,hash,EDR alert,2026-05-02
```

## PDF export

PDF downloads work with ReportLab when dependencies are installed from `requirements.txt`. If ReportLab is unavailable, the app falls back to a simple built-in PDF writer so users can still download the report instead of seeing an install error.

## Screenshots

Placeholder for portfolio screenshots:

- Home/upload page
- Results table with filters
- Markdown report preview

## Portfolio explanation

This project demonstrates practical defensive engineering: secure file handling, robust validation, modular service design, transparent confidence scoring, and careful ATT&CK mapping without overclaiming attribution. It is intentionally local-first and safe for demos because enrichment is passive and API keys are optional environment variables only.

## Security notes

- Only `.csv` uploads are accepted.
- Upload batches are limited to five CSV files, and each file must be 3 MB or smaller.
- Uploaded content is parsed as text and never executed.
- The application does not actively scan, probe, exploit, brute force, or run malware.
- External API keys, if later used, should be stored only in environment variables such as `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY`.
- `.env`, virtual environments, SQLite databases, and upload directories are ignored by Git.
