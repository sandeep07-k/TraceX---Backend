from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


BASE_DIR = Path(__file__).resolve().parents[3]

REPORT_DIR = BASE_DIR / "reports"


def safe(value: Any) -> str:
    """
    Convert any value into safe display text.
    """
    if value is None:
        return "N/A"

    return str(value)


def build_table(
    rows: list[list[Any]],
    col_widths: list[float] | None = None,
) -> Table:
    table = Table(
        rows,
        colWidths=col_widths,
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (-1, -1),
                    "Helvetica",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    return table


def generate_report(
    case_id: str,
    analysis: dict[str, Any],
    filename: str,
) -> str:
    """
    Generate a forensic PDF report from stored analysis.
    """

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_path = (
        REPORT_DIR
        / f"{case_id}_forensic_report.pdf"
    )

    document = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="TraceX Forensic Report",
        author="TraceX",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TraceXTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "TraceXSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        spaceAfter=20,
    )

    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=7,
    )

    normal_style = ParagraphStyle(
        "NormalCustom",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
    )

    story = []

    # ------------------------------------------
    # Cover
    # ------------------------------------------

    story.append(
        Paragraph(
            "TraceX",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "AI-Powered Email Threat Detection & "
            "Forensic Intelligence",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Forensic Investigation Report</b><br/>"
            f"Case ID: {safe(case_id)}<br/>"
            f"Source File: {safe(filename)}",
            normal_style,
        )
    )

    story.append(
        Spacer(
            1,
            10 * mm,
        )
    )

    risk = analysis.get(
        "risk",
        {},
    )

    risk_score = risk.get(
        "score",
        0,
    )

    risk_level = risk.get(
        "level",
        "UNKNOWN",
    )

    risk_table = build_table(
        [
            ["Metric", "Result"],
            [
                "Risk Score",
                f"{risk_score}/100",
            ],
            [
                "Risk Level",
                risk_level,
            ],
        ],
        col_widths=[
            60 * mm,
            80 * mm,
        ],
    )

    story.append(
        risk_table
    )

    story.append(
        PageBreak()
    )

    # ------------------------------------------
    # 1. Email Summary
    # ------------------------------------------

    story.append(
        Paragraph(
            "1. Email Summary",
            section_style,
        )
    )

    email = analysis.get(
        "email",
        {},
    )

    email_rows = [
        ["Field", "Value"],
        [
            "Sender",
            safe(email.get("sender")),
        ],
        [
            "Sender Email",
            safe(email.get("sender_email")),
        ],
        [
            "Recipients",
            safe(
                ", ".join(
                    email.get(
                        "recipients",
                        [],
                    )
                )
            ),
        ],
        [
            "Subject",
            safe(email.get("subject")),
        ],
        [
            "Date",
            safe(email.get("date")),
        ],
        [
            "Reply-To",
            safe(email.get("reply_to")),
        ],
        [
            "Return-Path",
            safe(email.get("return_path")),
        ],
        [
            "Message-ID",
            safe(email.get("message_id")),
        ],
    ]

    story.append(
        build_table(
            email_rows,
            col_widths=[
                45 * mm,
                125 * mm,
            ],
        )
    )

    # ------------------------------------------
    # 2. Risk Assessment
    # ------------------------------------------

    story.append(
        Paragraph(
            "2. Risk Assessment",
            section_style,
        )
    )

    explanations = risk.get(
        "explanations",
        [],
    )

    explanation_rows = [
        [
            "Severity",
            "Category",
            "Score",
            "Explanation",
        ]
    ]

    for item in explanations:

        explanation_rows.append(
            [
                safe(
                    item.get(
                        "severity"
                    )
                ),
                safe(
                    item.get(
                        "category"
                    )
                ),
                safe(
                    item.get(
                        "score_contribution"
                    )
                ),
                safe(
                    item.get(
                        "message"
                    )
                ),
            ]
        )

    if len(explanation_rows) == 1:

        explanation_rows.append(
            [
                "INFO",
                "Risk",
                "0",
                "No significant risk evidence recorded.",
            ]
        )

    story.append(
        build_table(
            explanation_rows,
            col_widths=[
                25 * mm,
                40 * mm,
                20 * mm,
                85 * mm,
            ],
        )
    )

    # ------------------------------------------
    # 3. Authentication
    # ------------------------------------------

    story.append(
        Paragraph(
            "3. Email Authentication",
            section_style,
        )
    )

    authentication = analysis.get(
        "authentication",
        {},
    )

    auth_rows = [
        ["Check", "Status", "Source"],
        [
            "SPF",
            safe(
                authentication.get(
                    "spf",
                    {}
                ).get(
                    "status"
                )
            ),
            safe(
                authentication.get(
                    "spf",
                    {}
                ).get(
                    "source"
                )
            ),
        ],
        [
            "DKIM",
            safe(
                authentication.get(
                    "dkim",
                    {}
                ).get(
                    "status"
                )
            ),
            safe(
                authentication.get(
                    "dkim",
                    {}
                ).get(
                    "source"
                )
            ),
        ],
        [
            "DMARC",
            safe(
                authentication.get(
                    "dmarc",
                    {}
                ).get(
                    "status"
                )
            ),
            safe(
                authentication.get(
                    "dmarc",
                    {}
                ).get(
                    "source"
                )
            ),
        ],
    ]

    story.append(
        build_table(
            auth_rows,
            col_widths=[
                50 * mm,
                50 * mm,
                70 * mm,
            ],
        )
    )

    # ------------------------------------------
    # 4. Header Forensics
    # ------------------------------------------

    story.append(
        Paragraph(
            "4. Header Forensics",
            section_style,
        )
    )

    header = analysis.get(
        "header_forensics",
        {},
    )

    header_rows = [
        ["Finding", "Value"],
        [
            "Reply-To mismatch",
            safe(
                header.get(
                    "reply_to_mismatch"
                )
            ),
        ],
        [
            "Return-Path mismatch",
            safe(
                header.get(
                    "return_path_mismatch"
                )
            ),
        ],
        [
            "Relay header count",
            safe(
                header.get(
                    "received_header_count"
                )
            ),
        ],
        [
            "Observed relay IPs",
            safe(
                ", ".join(
                    header.get(
                        "received_ips",
                        []
                    )
                )
            ),
        ],
    ]

    story.append(
        build_table(
            header_rows,
            col_widths=[
                65 * mm,
                105 * mm,
            ],
        )
    )

    # ------------------------------------------
    # 5. Threat Analysis
    # ------------------------------------------

    story.append(
        Paragraph(
            "5. Threat Analysis",
            section_style,
        )
    )

    threat = analysis.get(
        "threat_analysis",
        {},
    )

    threat_rows = [
        [
            "Category",
            "Detected",
            "Score",
        ],
        [
            "Phishing",
            safe(
                threat.get(
                    "phishing",
                    {}
                ).get(
                    "detected"
                )
            ),
            safe(
                threat.get(
                    "phishing",
                    {}
                ).get(
                    "score"
                )
            ),
        ],
        [
            "BEC",
            safe(
                threat.get(
                    "bec",
                    {}
                ).get(
                    "detected"
                )
            ),
            safe(
                threat.get(
                    "bec",
                    {}
                ).get(
                    "score"
                )
            ),
        ],
        [
            "Impersonation",
            safe(
                threat.get(
                    "impersonation",
                    {}
                ).get(
                    "detected"
                )
            ),
            safe(
                threat.get(
                    "impersonation",
                    {}
                ).get(
                    "score"
                )
            ),
        ],
    ]

    story.append(
        build_table(
            threat_rows,
            col_widths=[
                80 * mm,
                45 * mm,
                45 * mm,
            ],
        )
    )

    # ------------------------------------------
    # 6. AI Analysis
    # ------------------------------------------

    story.append(
        Paragraph(
            "6. AI Analysis",
            section_style,
        )
    )

    ai = analysis.get(
        "ai_analysis",
        {},
    )

    prediction = ai.get(
        "prediction",
        {},
    )

    ai_rows = [
        ["Metric", "Value"],
        [
            "Model",
            safe(
                ai.get("model")
            ),
        ],
        [
            "Classification",
            safe(
                prediction.get(
                    "label"
                )
            ),
        ],
        [
            "Phishing Probability",
            safe(
                prediction.get(
                    "phishing_probability"
                )
            ),
        ],
        [
            "Confidence",
            safe(
                prediction.get(
                    "confidence"
                )
            ),
        ],
    ]

    story.append(
        build_table(
            ai_rows,
            col_widths=[
                65 * mm,
                105 * mm,
            ],
        )
    )

    # ------------------------------------------
    # 7. IOCs
    # ------------------------------------------

    story.append(
        Paragraph(
            "7. Indicators of Compromise",
            section_style,
        )
    )

    intelligence = analysis.get(
        "intelligence",
        {}
    )

    iocs = intelligence.get(
        "iocs",
        {}
    )

    ioc_rows = [
        ["Type", "Value", "Source", "Confidence"]
    ]

    for ioc in iocs.get(
        "all",
        [],
    ):

        ioc_rows.append(
            [
                safe(
                    ioc.get("type")
                ),
                safe(
                    ioc.get("value")
                ),
                safe(
                    ioc.get("source")
                ),
                safe(
                    ioc.get("confidence")
                ),
            ]
        )

    if len(ioc_rows) == 1:
        ioc_rows.append(
            [
                "INFO",
                "No IOCs",
                "TraceX",
                "N/A",
            ]
        )

    story.append(
        build_table(
            ioc_rows,
            col_widths=[
                25 * mm,
                75 * mm,
                45 * mm,
                25 * mm,
            ],
        )
    )

    # ------------------------------------------
    # 8. Relay Trace
    # ------------------------------------------

    story.append(
        Paragraph(
            "8. Relay Path",
            section_style,
        )
    )

    relay = analysis.get(
        "relay_trace",
        {}
    )

    relay_rows = [
        [
            "Hop",
            "From",
            "By",
            "IP(s)",
            "Timestamp",
        ]
    ]

    for hop in relay.get(
        "relay_chain",
        [],
    ):

        relay_rows.append(
            [
                safe(
                    hop.get("hop")
                ),
                safe(
                    hop.get("from_host")
                ),
                safe(
                    hop.get("by_host")
                ),
                safe(
                    ", ".join(
                        hop.get(
                            "ips",
                            [],
                        )
                    )
                ),
                safe(
                    hop.get("timestamp")
                ),
            ]
        )

    if len(relay_rows) == 1:
        relay_rows.append(
            [
                "-",
                "No relay data",
                "-",
                "-",
                "-",
            ]
        )

    story.append(
        build_table(
            relay_rows,
            col_widths=[
                12 * mm,
                43 * mm,
                43 * mm,
                35 * mm,
                37 * mm,
            ],
        )
    )

    # ------------------------------------------
    # 9. Correlation
    # ------------------------------------------

    story.append(
        Paragraph(
            "9. Forensic Correlation",
            section_style,
        )
    )

    correlation = analysis.get(
        "correlation",
        {}
    )

    relationships = correlation.get(
        "relationships",
        [],
    )

    correlation_rows = [
        [
            "Type",
            "Severity",
            "Message",
        ]
    ]

    for item in relationships:

        correlation_rows.append(
            [
                safe(
                    item.get("type")
                ),
                safe(
                    item.get(
                        "severity"
                    )
                ),
                safe(
                    item.get(
                        "message"
                    )
                ),
            ]
        )

    if len(correlation_rows) == 1:
        correlation_rows.append(
            [
                "INFO",
                "INFO",
                "No correlation findings.",
            ]
        )

    story.append(
        build_table(
            correlation_rows,
            col_widths=[
                55 * mm,
                25 * mm,
                90 * mm,
            ],
        )
    )

    # ------------------------------------------
    # 10. Investigation Summary
    # ------------------------------------------

    story.append(
    Paragraph(
        "10. Investigation Summary",
        section_style,
    )
    )

    summary = (
        f"TraceX analyzed the submitted email and "
        f"generated an overall risk assessment of "
        f"<b>{safe(risk_score)}/100</b> "
        f"({safe(risk_level)}). "
        f"The assessment combines header forensics, "
        f"email authentication evidence, threat "
        f"indicators, AI-assisted language analysis, "
        f"IOC intelligence and relay-path information. "
        f"Geolocation or infrastructure information "
        f"should be interpreted as investigative evidence "
        f"rather than definitive attribution."
    )

    story.append(
        Paragraph(
            summary,
            normal_style,
        )
    )

    story.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    story.append(
        Paragraph(
            "Generated by TraceX",
            subtitle_style,
        )
    )

    document.build(
        story
    )

    return str(report_path)