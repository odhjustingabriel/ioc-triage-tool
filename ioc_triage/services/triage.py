import csv
import ipaddress
import os
import re
from dataclasses import dataclass
from io import TextIOWrapper
from typing import Iterable
from urllib.parse import urlparse

REQUIRED_COLUMNS = {"indicator", "type", "source", "date_found"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "update", "account", "free", "bonus"}
EXECUTABLE_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]+$")


@dataclass
class TriageResult:
    indicator: str
    submitted_type: str
    detected_type: str
    source: str
    date_found: str
    is_valid: bool
    validation_notes: str
    reputation: str
    reputation_notes: str
    asn: str
    country: str
    malware_family: str
    mitre_tactic: str
    mitre_technique: str
    mitre_notes: str
    confidence_level: str
    confidence_reason: str


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return bool(parsed.scheme and parsed.netloc)


def is_domain(value: str) -> bool:
    candidate = value.strip().rstrip(".")
    return not is_ip(candidate) and not is_url(candidate) and bool(DOMAIN_RE.match(candidate))


def detect_hash_type(value: str) -> str:
    candidate = value.strip()
    if not HASH_RE.match(candidate):
        return ""
    return {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(candidate), "")


def detect_ioc_type(indicator: str) -> str:
    value = (indicator or "").strip()
    if is_ip(value):
        return "ip"
    if is_url(value):
        return "url"
    if is_domain(value):
        return "domain"
    if detect_hash_type(value):
        return "hash"
    return "unknown"


def suspicious_keyword_hits(value: str) -> list[str]:
    lower_value = value.lower()
    return sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lower_value)


def enrich_ip(indicator: str) -> dict:
    ip_obj = ipaddress.ip_address(indicator)
    if ip_obj.is_private:
        return {
            "reputation": "Benign",
            "reputation_notes": "Private/internal IP address; treat as local context unless seen in suspicious logs.",
            "asn": "Not applicable - private IP",
            "country": "Private/internal network",
            "signals": [],
        }
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
        return {
            "reputation": "Unknown",
            "reputation_notes": "Reserved, loopback, link-local, multicast, or otherwise non-routable IP address.",
            "asn": "Reserved/non-routable address",
            "country": "Not geolocated",
            "signals": [],
        }
    return {
        "reputation": "Unknown",
        "reputation_notes": "Public IP address. Passive ASN/reputation lookup is not configured; verify with approved sources.",
        "asn": "External ASN lookup not configured",
        "country": "External GeoIP lookup not configured",
        "signals": ["public_ip"],
    }


def enrich_domain(indicator: str) -> dict:
    hits = suspicious_keyword_hits(indicator)
    reputation = "Suspicious" if hits else "Unknown"
    notes = "Domain requires passive WHOIS/reputation verification."
    if hits:
        notes += f" Suspicious keyword(s) observed: {', '.join(hits)}."
    return {"reputation": reputation, "reputation_notes": notes, "signals": hits}


def enrich_url(indicator: str) -> dict:
    parsed = urlparse(indicator)
    host = parsed.hostname or ""
    signals = []
    if host and is_ip(host):
        signals.append("IP address used as host")
    domain_parts = [part for part in host.split(".") if part]
    if len(domain_parts) >= 5:
        signals.append("many subdomains")
    hits = suspicious_keyword_hits(indicator)
    signals.extend([f"keyword:{hit}" for hit in hits])
    if len(indicator) > 120:
        signals.append("long URL length")
    if parsed.path.lower().endswith(EXECUTABLE_EXTENSIONS):
        signals.append("executable file extension in path")

    if len(signals) >= 2 or "executable file extension in path" in signals:
        reputation = "Malicious"
    elif signals:
        reputation = "Suspicious"
    else:
        reputation = "Unknown"
    notes = f"Parsed URL with scheme '{parsed.scheme}', host '{host}', and path '{parsed.path or '/'}'."
    if signals:
        notes += f" Suspicious pattern(s): {', '.join(signals)}."
    return {"reputation": reputation, "reputation_notes": notes, "signals": signals}


def enrich_hash(indicator: str) -> dict:
    hash_type = detect_hash_type(indicator)
    return {
        "reputation": "Unknown",
        "reputation_notes": f"{hash_type} hash identified. Submit to approved malware intelligence platforms if policy allows.",
        "malware_family": "Unknown",
        "signals": [hash_type.lower()],
    }


def local_enrichment(indicator: str, detected_type: str) -> dict:
    if detected_type == "ip":
        return enrich_ip(indicator)
    if detected_type == "domain":
        return enrich_domain(indicator)
    if detected_type == "url":
        return enrich_url(indicator)
    if detected_type == "hash":
        return enrich_hash(indicator)
    return {"reputation": "Unknown", "reputation_notes": "Indicator could not be classified for local enrichment.", "signals": []}


def virustotal_enrichment_placeholder(indicator: str) -> dict:
    if not os.getenv("VIRUSTOTAL_API_KEY"):
        return {"configured": False, "notes": "VirusTotal API key not configured; local passive enrichment used."}
    return {"configured": True, "notes": "Placeholder only; no external call is made by this demo app."}


def abuseipdb_enrichment_placeholder(indicator: str) -> dict:
    if not os.getenv("ABUSEIPDB_API_KEY"):
        return {"configured": False, "notes": "AbuseIPDB API key not configured; local passive enrichment used."}
    return {"configured": True, "notes": "Placeholder only; no external call is made by this demo app."}


def assign_mitre(detected_type: str, reputation: str, signals: Iterable[str], malware_family: str = "") -> tuple[str, str, str]:
    signal_text = " ".join(signals).lower()
    if detected_type in {"domain", "url"} and any(keyword in signal_text for keyword in SUSPICIOUS_KEYWORDS):
        return (
            "Initial Access",
            "Phishing: Spearphishing Link / T1566.002",
            "Suspicious URL/domain terms are consistent with a possible phishing lure, but require verification.",
        )
    if detected_type in {"domain", "ip", "url"} and reputation in {"Suspicious", "Malicious"}:
        return (
            "Command and Control",
            "Application Layer Protocol / T1071",
            "Network IOC has suspicious characteristics and could be used for callback/C2; mapping is conservative.",
        )
    if detected_type == "hash" and malware_family and malware_family != "Unknown":
        return (
            "Execution",
            "User Execution / T1204",
            "Hash has an associated malware family, suggesting potential execution risk if delivered to users.",
        )
    return "Unmapped", "Not enough evidence", "Insufficient evidence for a confident ATT&CK mapping."


def score_confidence(is_valid: bool, reputation: str, signals: Iterable[str]) -> tuple[str, str]:
    signals = list(signals)
    if not is_valid:
        return "Low", "Invalid or unclassified IOC; not enough evidence for action."
    if reputation == "Malicious" or (reputation == "Suspicious" and len(signals) >= 2):
        return "High", "Valid IOC with multiple suspicious signals or malicious reputation."
    if reputation == "Suspicious" or signals:
        return "Medium", "Valid IOC with some suspicious context, but additional verification is recommended."
    return "Low", "Valid IOC, but reputation is unknown or evidence is limited."


def triage_indicator(row: dict) -> TriageResult:
    indicator = (row.get("indicator") or "").strip()
    submitted_type = (row.get("type") or "").strip().lower() or "unspecified"
    source = (row.get("source") or "").strip() or "Unknown"
    date_found = (row.get("date_found") or "").strip() or "Unknown"
    detected_type = detect_ioc_type(indicator)
    is_valid = detected_type != "unknown"

    validation_notes = "Valid IOC detected."
    if not is_valid:
        validation_notes = "Invalid or unsupported IOC format."
    elif submitted_type not in {detected_type, "unspecified"}:
        validation_notes = f"Submitted type '{submitted_type}' conflicts with detected type '{detected_type}'."

    enrichment = local_enrichment(indicator, detected_type)
    malware_family = enrichment.get("malware_family", "")
    signals = enrichment.get("signals", [])
    mitre_tactic, mitre_technique, mitre_notes = assign_mitre(
        detected_type, enrichment["reputation"], signals, malware_family
    )
    confidence_level, confidence_reason = score_confidence(is_valid, enrichment["reputation"], signals)

    return TriageResult(
        indicator=indicator,
        submitted_type=submitted_type,
        detected_type=detected_type,
        source=source,
        date_found=date_found,
        is_valid=is_valid,
        validation_notes=validation_notes,
        reputation=enrichment["reputation"],
        reputation_notes=enrichment["reputation_notes"],
        asn=enrichment.get("asn", ""),
        country=enrichment.get("country", ""),
        malware_family=malware_family,
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        mitre_notes=mitre_notes,
        confidence_level=confidence_level,
        confidence_reason=confidence_reason,
    )


def parse_csv_upload(uploaded_file) -> list[TriageResult]:
    text_file = TextIOWrapper(uploaded_file.file, encoding="utf-8-sig", newline="")
    reader = csv.DictReader(text_file)
    if not reader.fieldnames:
        raise ValueError("CSV file is empty or missing a header row.")
    normalized = {field.strip().lower() for field in reader.fieldnames if field}
    missing = REQUIRED_COLUMNS - normalized
    if missing:
        raise ValueError(f"CSV is missing required column(s): {', '.join(sorted(missing))}.")

    results = []
    for row_number, raw_row in enumerate(reader, start=2):
        row = {str(key).strip().lower(): value for key, value in raw_row.items() if key is not None}
        if not any((value or "").strip() for value in row.values()):
            continue
        try:
            results.append(triage_indicator(row))
        except Exception as exc:  # keep malformed rows from crashing the upload workflow
            results.append(
                TriageResult(
                    indicator=(row.get("indicator") or f"Row {row_number}").strip(),
                    submitted_type=(row.get("type") or "unspecified").strip(),
                    detected_type="unknown",
                    source=(row.get("source") or "Unknown").strip(),
                    date_found=(row.get("date_found") or "Unknown").strip(),
                    is_valid=False,
                    validation_notes=f"Row could not be processed safely: {exc}",
                    reputation="Unknown",
                    reputation_notes="No enrichment performed for malformed row.",
                    asn="",
                    country="",
                    malware_family="",
                    mitre_tactic="Unmapped",
                    mitre_technique="Not enough evidence",
                    mitre_notes="Malformed row prevented mapping.",
                    confidence_level="Low",
                    confidence_reason="Malformed row; no reliable evidence.",
                )
            )
    if not results:
        raise ValueError("CSV did not contain any IOC rows to process.")
    return results
