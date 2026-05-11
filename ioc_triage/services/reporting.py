from collections import Counter, defaultdict
from io import BytesIO
import importlib.util
import re
import textwrap


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


def _generate_reportlab_pdf(markdown):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

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


def _pdf_escape(value):
    return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _plain_report_lines(markdown):
    lines = []
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if line.startswith("|---"):
            continue
        line = line.replace("|", "  ")
        line = re.sub(r"^[#]+\s*", "", line)
        line = line.replace("**", "")
        if not line:
            lines.append("")
            continue
        wrapped = textwrap.wrap(line, width=100) or [""]
        lines.extend(wrapped)
    return lines


def _generate_basic_pdf(markdown):
    lines = _plain_report_lines(markdown)
    lines_per_page = 48
    pages = [lines[index : index + lines_per_page] for index in range(0, len(lines), lines_per_page)] or [[]]

    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    kids = []
    next_object_id = 4
    for page_lines in pages:
        page_id = next_object_id
        content_id = next_object_id + 1
        next_object_id += 2
        kids.append(f"{page_id} 0 R")
        text_commands = ["BT", "/F1 10 Tf", "50 742 Td", "14 TL"]
        for line in page_lines:
            text_commands.append(f"({_pdf_escape(line)}) Tj")
            text_commands.append("T*")
        text_commands.append("ET")
        stream = "\n".join(text_commands).encode("latin-1", "replace")
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
        objects[content_id] = b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"

    objects[2] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode("ascii")

    output = BytesIO()
    output.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id in range(1, max(objects) + 1):
        offsets.append(output.tell())
        output.write(f"{object_id} 0 obj\n".encode("ascii"))
        output.write(objects[object_id])
        output.write(b"\nendobj\n")
    xref_offset = output.tell()
    output.write(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.write(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return output.getvalue()


def generate_pdf_report(records):
    markdown = generate_markdown_report(records)
    if importlib.util.find_spec("reportlab") is not None:
        return _generate_reportlab_pdf(markdown)
    return _generate_basic_pdf(markdown)
