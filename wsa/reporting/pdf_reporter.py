"""
Professional PDF Report Generator for Wireless Network Security Assessment.

Produces an audit-grade, self-contained PDF security assessment report
complete with executive summary, risk-scoring charts, discovered networks table,
findings with severity tags, technical impact, and remediation steps.
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from wsa.reporting.assessment import Assessment, data_source_note

# Brand colors
COLOR_PRIMARY = colors.HexColor("#4c1d95")  # Deep Purple / Indigo
COLOR_SECONDARY = colors.HexColor("#6d28d9")
COLOR_ACCENT = colors.HexColor("#be185d")  # Dark Pink / Magenta
COLOR_DARK = colors.HexColor("#1e1b4b")
COLOR_MUTED = colors.HexColor("#64748b")
COLOR_LIGHT_BG = colors.HexColor("#f8fafc")

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#16a34a"),
    "INFO": colors.HexColor("#2563eb"),
}

SEV_BG_COLORS = {
    "CRITICAL": colors.HexColor("#fee2e2"),
    "HIGH": colors.HexColor("#ffedd5"),
    "MEDIUM": colors.HexColor("#fef9c3"),
    "LOW": colors.HexColor("#dcfce7"),
    "INFO": colors.HexColor("#dbeafe"),
}


def to_pdf(
    assessment_or_record: Union[Assessment, Dict[str, Any]],
    output_path: Optional[Union[str, Path]] = None,
) -> bytes:
    """
    Generate a standalone PDF report from an Assessment instance or assessment record dict.
    """
    # Normalize input into unified dictionary
    if isinstance(assessment_or_record, Assessment):
        from wsa.reporting.json_reporter import _assessment_to_dict
        data = _assessment_to_dict(assessment_or_record)
    else:
        data = dict(assessment_or_record)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        str(output_path) if output_path else buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.white,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#e2e8f0"),
    )
    h2_style = ParagraphStyle(
        "Heading2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=COLOR_PRIMARY,
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=COLOR_DARK,
    )
    body_bold = ParagraphStyle(
        "BodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    small_style = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=COLOR_MUTED,
    )

    story = []

    # 1. Header Banner
    source_filename = data.get("source_filename") or data.get("filename") or Path(data.get("source_file", "Capture")).name
    timestamp = data.get("analysis_timestamp", "N/A")
    data_source = data.get("data_source", "pcap_offline")

    header_table_data = [
        [
            Paragraph("WIRELESS NETWORK SECURITY ASSESSMENT", title_style),
            Paragraph(f"<b>REPORT DATE:</b><br/>{timestamp[:19].replace('T', ' ')} UTC", subtitle_style),
        ],
        [
            Paragraph(f"<b>Target:</b> {source_filename} &nbsp;|&nbsp; <b>Mode:</b> {data_source.upper()}", subtitle_style),
            Paragraph("<b>ENGINE:</b> WSA Security Suite v1.0", subtitle_style),
        ],
    ]
    header_table = Table(header_table_data, colWidths=[380, 160])
    header_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_PRIMARY),
            ("PADDING", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])
    )
    story.append(header_table)
    story.append(Spacer(1, 12))

    # Provenance notice
    note_text = data.get("data_source_note") or data_source_note(data_source)
    prov_data = [[Paragraph(f"<b>PROVENANCE &amp; AUDIT SCOPE:</b> {note_text}", small_style)]]
    prov_table = Table(prov_data, colWidths=[540])
    prov_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ede9fe")),
            ("BORDER", (0, 0), (-1, -1), 1, colors.HexColor("#c4b5fd")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(prov_table)
    story.append(Spacer(1, 10))

    # 2. Executive Summary Metrics
    summary = data.get("summary", {})
    risk_score = summary.get("total_risk_score", 0)
    networks_count = summary.get("total_networks", len(data.get("networks", [])))
    frames_count = summary.get("total_frames", 0)
    findings_count = summary.get("total_findings", 0)
    sev_counts = summary.get("severity_counts", {})

    risk_label = "CRITICAL RISK" if risk_score >= 80 else ("HIGH RISK" if risk_score >= 40 else ("MEDIUM RISK" if risk_score >= 15 else ("LOW RISK" if risk_score > 0 else "SECURE")))
    risk_color = COLOR_ACCENT if risk_score >= 40 else (COLOR_PRIMARY if risk_score > 0 else colors.HexColor("#16a34a"))

    metric_cells = [
        [
            Paragraph(f"<font color='{risk_color.hexval()}'><b>{risk_score}</b></font><br/><font size='7' color='#64748b'>RISK SCORE ({risk_label})</font>", body_bold),
            Paragraph(f"<b>{networks_count}</b><br/><font size='7' color='#64748b'>DISCOVERED NETWORKS</font>", body_bold),
            Paragraph(f"<b>{findings_count}</b><br/><font size='7' color='#64748b'>SECURITY FINDINGS</font>", body_bold),
            Paragraph(f"<b>{frames_count}</b><br/><font size='7' color='#64748b'>ANALYZED FRAMES</font>", body_bold),
        ]
    ]
    metric_table = Table(metric_cells, colWidths=[135, 135, 135, 135])
    metric_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("INNERGRID", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 8),
        ])
    )
    story.append(metric_table)
    story.append(Spacer(1, 10))

    # Severity distribution bar
    sev_row = [
        Paragraph(f"<b>Critical:</b> {sev_counts.get('CRITICAL', 0)}", body_style),
        Paragraph(f"<b>High:</b> {sev_counts.get('HIGH', 0)}", body_style),
        Paragraph(f"<b>Medium:</b> {sev_counts.get('MEDIUM', 0)}", body_style),
        Paragraph(f"<b>Low:</b> {sev_counts.get('LOW', 0)}", body_style),
        Paragraph(f"<b>Info:</b> {sev_counts.get('INFO', 0)}", body_style),
    ]
    sev_table = Table([sev_row], colWidths=[108, 108, 108, 108, 108])
    sev_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), SEV_BG_COLORS["CRITICAL"]),
            ("BACKGROUND", (1, 0), (1, 0), SEV_BG_COLORS["HIGH"]),
            ("BACKGROUND", (2, 0), (2, 0), SEV_BG_COLORS["MEDIUM"]),
            ("BACKGROUND", (3, 0), (3, 0), SEV_BG_COLORS["LOW"]),
            ("BACKGROUND", (4, 0), (4, 0), SEV_BG_COLORS["INFO"]),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ])
    )
    story.append(sev_table)
    story.append(Spacer(1, 14))

    # 3. Discovered Wireless Networks Section
    story.append(Paragraph("DISCOVERED WIRELESS ACCESS POINTS (Airodump-ng Inspection)", h2_style))
    networks = data.get("networks", [])
    if networks:
        net_headers = ["SSID", "BSSID", "Channel", "Signal", "Encryption", "Auth", "WPS", "Findings"]
        net_rows = [[Paragraph(f"<b>{h}</b>", body_bold) for h in net_headers]]

        for net in networks:
            ssid_name = net.get("ssid")
            if ssid_name is None:
                ssid_display = "<i>(IE Absent)</i>"
            elif ssid_name == "":
                ssid_display = "<i>(Hidden SSID)</i>"
            else:
                ssid_display = ssid_name[:18]

            bssid = net.get("bssid", "N/A")
            channel = str(net.get("channel", "N/A"))
            rssi = f"{net.get('avg_rssi_dbm'):.0f} dBm" if net.get("avg_rssi_dbm") is not None else "N/A"
            cipher = net.get("cipher", "UNKNOWN")
            auth = net.get("auth_type", "UNKNOWN")
            wps = "YES" if net.get("wps_present") else "No"
            f_count = len(net.get("findings", []))

            net_rows.append([
                Paragraph(ssid_display, body_style),
                Paragraph(f"<font size='7' face='Courier'>{bssid}</font>", body_style),
                Paragraph(channel, body_style),
                Paragraph(rssi, body_style),
                Paragraph(f"<b>{cipher}</b>", body_style),
                Paragraph(auth, body_style),
                Paragraph(wps, body_style),
                Paragraph(str(f_count), body_bold),
            ])

        net_table = Table(net_rows, colWidths=[100, 105, 45, 55, 65, 55, 45, 70])
        net_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )
        story.append(net_table)
    else:
        story.append(Paragraph("No wireless networks were discovered in this capture.", body_style))

    story.append(Spacer(1, 14))

    # 4. Detailed Security Findings & Risk Scoring Section
    story.append(Paragraph("VULNERABILITY FINDINGS &amp; REMEDIATION GUIDANCE", h2_style))

    all_findings = []
    for net in networks:
        for f in net.get("findings", []):
            item = dict(f)
            item["target_ssid"] = net.get("ssid")
            item["target_bssid"] = net.get("bssid")
            all_findings.append(item)

    # Sort findings by severity
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: sev_rank.get(x.get("severity", "INFO"), 5))

    if all_findings:
        for f in all_findings:
            sev = f.get("severity", "INFO")
            title = f.get("title", "Finding")
            rule_id = f.get("rule_id", "RULE")
            ssid = f.get("target_ssid") or "N/A"
            bssid = f.get("target_bssid") or "N/A"
            evidence = f.get("evidence", "Observed frame feature")
            explanation = f.get("explanation", "")
            impact = f.get("impact", "")
            remediation = f.get("remediation", "")

            sev_color_hex = SEV_COLORS.get(sev, colors.gray).hexval()

            card_content = [
                [
                    Paragraph(f"<font color='{sev_color_hex}'><b>[{sev}]</b></font> <b>{rule_id}: {title}</b>", body_bold),
                    Paragraph(f"<b>Target:</b> {ssid} ({bssid})", small_style),
                ],
                [
                    Paragraph(f"<b>Evidence:</b> <font face='Courier' size='7'>{evidence}</font>", small_style),
                    Paragraph("", small_style),
                ],
                [
                    Paragraph(f"<b>Explanation:</b> {explanation}", body_style),
                    Paragraph("", small_style),
                ],
            ]
            if impact:
                card_content.append([Paragraph(f"<b>Threat Impact:</b> {impact}", body_style), Paragraph("", small_style)])
            if remediation:
                card_content.append([Paragraph(f"<b>Remediation Steps:</b> {remediation}", body_style), Paragraph("", small_style)])

            f_table = Table(card_content, colWidths=[420, 120])
            f_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffffff")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                    ("LINELEFT", (0, 0), (0, -1), 3, SEV_COLORS.get(sev, colors.gray)),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("SPAN", (0, 1), (1, 1)),
                    ("SPAN", (0, 2), (1, 2)),
                ] + ([("SPAN", (0, 3), (1, 3))] if impact else [])
                  + ([("SPAN", (0, 4 if impact else 3), (1, 4 if impact else 3))] if remediation else [])
                )
            )
            story.append(KeepTogether([f_table, Spacer(1, 6)]))
    else:
        clean_box = [[Paragraph("<b>CLEAN ASSESSMENT:</b> No security vulnerabilities or policy violations were detected. All observed networks adhere to robust security standards.", body_style)]]
        clean_table = Table(clean_box, colWidths=[540])
        clean_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#dcfce7")),
                ("BORDER", (0, 0), (-1, -1), 1, colors.HexColor("#86efac")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ])
        )
        story.append(clean_table)

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1")))
    story.append(Paragraph("Wireless Network Security Assessment — Generated by WSA on Kali Linux", small_style))

    doc.build(story)

    if output_path:
        return Path(output_path).read_bytes()
    return buffer.getvalue()
