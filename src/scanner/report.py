"""
report.py

Generates a professional HTML report from scan findings.
Produces a self-contained single HTML file with embedded CSS —
no external dependencies needed to open it.
"""

import os
from datetime import datetime


SEVERITY_COLORS = {
    "High":   {"bg": "#ff4d4d", "light": "#fff0f0", "border": "#ff4d4d"},
    "Medium": {"bg": "#ff9900", "light": "#fff7e6", "border": "#ff9900"},
    "Low":    {"bg": "#3399ff", "light": "#e6f2ff", "border": "#3399ff"},
    "Error":  {"bg": "#888888", "light": "#f5f5f5", "border": "#888888"},
}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Error": 3}


def _severity_badge(severity: str) -> str:
    colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Low"])
    return (
        f'<span style="background:{colors["bg"]};color:white;'
        f'padding:3px 10px;border-radius:12px;font-size:0.8em;'
        f'font-weight:bold;letter-spacing:0.5px;">{severity}</span>'
    )


def _finding_card(finding: dict) -> str:
    severity = finding.get("severity", "Low")
    colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Low"])
    check = finding.get("check", "Unknown Check")
    description = finding.get("description", "")
    recommendation = finding.get("recommendation", "")
    url = finding.get("url", finding.get("page", ""))

    url_row = ""
    if url:
        url_row = f"""
        <tr>
            <td style="padding:6px 0;color:#666;width:130px;">URL</td>
            <td style="padding:6px 0;">
                <code style="font-size:0.85em;word-break:break-all;">{url}</code>
            </td>
        </tr>"""

    return f"""
    <div style="border:1px solid {colors['border']};border-left:5px solid {colors['bg']};
                border-radius:6px;padding:20px 24px;margin-bottom:18px;
                background:{colors['light']};">
        <div style="display:flex;justify-content:space-between;
                    align-items:center;margin-bottom:12px;">
            <h3 style="margin:0;font-size:1em;color:#1a1a1a;">{check}</h3>
            {_severity_badge(severity)}
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:0.92em;">
            {url_row}
            <tr>
                <td style="padding:6px 0;color:#666;width:130px;
                           vertical-align:top;">Description</td>
                <td style="padding:6px 0;">{description}</td>
            </tr>
            <tr>
                <td style="padding:6px 0;color:#666;
                           vertical-align:top;">Recommendation</td>
                <td style="padding:6px 0;color:#2d7a2d;">{recommendation}</td>
            </tr>
        </table>
    </div>"""


def _summary_bar(findings: list) -> str:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Error": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1

    cards = ""
    for severity, count in counts.items():
        colors = SEVERITY_COLORS[severity]
        cards += f"""
        <div style="flex:1;min-width:120px;text-align:center;
                    background:{colors['light']};border:1px solid {colors['border']};
                    border-radius:8px;padding:16px 8px;">
            <div style="font-size:2em;font-weight:bold;
                        color:{colors['bg']};">{count}</div>
            <div style="color:#555;font-size:0.9em;
                        margin-top:4px;">{severity}</div>
        </div>"""

    return f"""
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:32px;">
        {cards}
    </div>"""


def generate_html_report(
    findings: list,
    target: str,
    output_path: str = "reports/scan_report.html",
    scanner_version: str = "1.0.0"
) -> str:
    """
    Generates a self-contained HTML report from scan findings.

    Args:
        findings:        List of finding dicts from all scanner modules.
        target:          The URL that was scanned.
        output_path:     Where to save the report.
        scanner_version: Version string shown in the report header.

    Returns:
        The absolute path to the saved report file.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Low"), 99)
    )

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)

    # Build finding cards grouped by severity
    finding_cards = ""
    if sorted_findings:
        for finding in sorted_findings:
            finding_cards += _finding_card(finding)
    else:
        finding_cards = """
        <div style="text-align:center;padding:40px;color:#555;">
            ✅ No vulnerabilities found.
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Report — {target}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
                         Roboto, sans-serif;
            background: #f4f6f9;
            color: #1a1a1a;
            padding: 32px 16px;
        }}
        .container {{
            max-width: 860px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
            overflow: hidden;
        }}
        .header {{
            background: #1a1a2e;
            color: white;
            padding: 32px 40px;
        }}
        .header h1 {{
            font-size: 1.6em;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        .header .meta {{
            font-size: 0.88em;
            opacity: 0.75;
            line-height: 1.8;
        }}
        .body {{
            padding: 32px 40px;
        }}
        h2 {{
            font-size: 1.1em;
            color: #1a1a2e;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid #f0f0f0;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            font-size: 0.8em;
            color: #aaa;
            border-top: 1px solid #f0f0f0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Web Vulnerability Scanner</h1>
            <div class="meta">
                <div>Target: <strong>{target}</strong></div>
                <div>Scan Time: {scan_time}</div>
                <div>Total Findings: <strong>{total}</strong></div>
                <div>Scanner Version: v{scanner_version}</div>
            </div>
        </div>
        <div class="body">
            <h2>Summary</h2>
            {_summary_bar(findings)}
            <h2>Findings</h2>
            {finding_cards}
        </div>
        <div class="footer">
            Generated by Web Vulnerability Scanner v{scanner_version} —
            For educational use only
        </div>
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return os.path.abspath(output_path)
