from collections import Counter, defaultdict
from io import BytesIO


def _escape(value):
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def generate_markdown_report(records):
    records = list(records)
    total = len(records)
    valid = sum(1 for record in records if record.is_valid)
    invalid = total - valid
    high_confidence = sum(1 for record in records if record.confidence_level == "High")
    type_counts = Counter(record.detected_type for record in records)
    most_common = type_counts.most_common(1)[0][0] if type_counts else "None"
    takeaway = "Prioritize high-confidence and suspicious network indicators for verification."
    if high_confidence == 0:
        takeaway = "No high-confidence findings were produced; validate context before blocking indicators."

    lines = [
        "# Threat Intelligence IOC Triage Report",
        "",
        "## Executive Summary",
        f"- Total IOCs processed: {total}",
        f"- Valid IOCs: {valid}",
        f"- Invalid IOCs: {invalid}",
        f"- High confidence findings: {high_confidence}",
        f"- Most common IOC type: {most_common}",
        f"- Main analyst takeaway: {takeaway}",
        "",
        "## IOC Summary",
        "| Indicator | Type | Reputation | Confidence | MITRE Mapping | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for record in records:
        mitre = f"{record.mitre_tactic} - {record.mitre_technique}"
        lines.append(
            f"| {_escape(record.indicator)} | {_escape(record.detected_type)} | {_escape(record.reputation)} | "
            f"{_escape(record.confidence_level)} | {_escape(mitre)} | {_escape(record.reputation_notes)} |"
        )

    lines.extend(["", "## High Risk Indicators"])
    high_risk = [r for r in records if r.confidence_level == "High" or r.reputation in {"Malicious", "Suspicious"}]
    if high_risk:
        for record in high_risk:
            lines.append(
                f"- **{record.indicator}** ({record.detected_type}) — {record.reputation}, "
                f"{record.confidence_level} confidence. {record.confidence_reason}"
            )
    else:
        lines.append("- No high-risk indicators identified by local passive enrichment.")

    lines.extend(["", "## Enrichment Notes"])
    for record in records:
        lines.append(f"- **{record.indicator}**: {record.reputation_notes}")

    lines.extend(["", "## MITRE ATT&CK Mapping"])
    grouped = defaultdict(list)
    for record in records:
        grouped[(record.mitre_tactic, record.mitre_technique)].append(record)
    for (tactic, technique), grouped_records in sorted(grouped.items()):
        lines.append(f"### {tactic} — {technique}")
        for record in grouped_records:
            lines.append(f"- {record.indicator}: {record.mitre_notes}")
        lines.append("")

    lines.extend(
        [
            "## Confidence Explanation",
            "- High: valid IOC with multiple suspicious signals or malicious reputation.",
            "- Medium: valid IOC with some suspicious evidence that needs verification.",
            "- Low: invalid IOC, unknown reputation, or insufficient evidence.",
            "",
            "## Analyst Notes",
            "- Passive enrichment only; this app does not scan, probe, exploit, or execute uploaded content.",
            "- API enrichment is not configured unless approved keys are added through environment variables.",
            "- MITRE mappings are evidence-based estimates, not confirmed attribution.",
            "",
            "## Recommendations",
            "- Block confirmed malicious domains/IPs after verification.",
            "- Investigate endpoints that contacted suspicious URLs/domains.",
            "- Search SIEM/logs for matching IOCs.",
            "- Submit hashes to malware analysis platforms if allowed by policy.",
            "- Reassess low-confidence indicators before taking action.",
            "",
        ]
    )
    return "\n".join(lines)


def generate_pdf_report(records):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    markdown = generate_markdown_report(records)
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title="Threat Intelligence IOC Triage Report")
    styles = getSampleStyleSheet()
    story = []
    for line in markdown.splitlines():
        if line.startswith("# "):
            story.append(Paragraph(line[2:], styles["Title"]))
        elif line.startswith("## "):
            story.append(Spacer(1, 12))
            story.append(Paragraph(line[3:], styles["Heading2"]))
        elif line.startswith("### "):
            story.append(Paragraph(line[4:], styles["Heading3"]))
        elif line.strip():
            story.append(Paragraph(line.replace("**", ""), styles["BodyText"]))
        else:
            story.append(Spacer(1, 6))
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
