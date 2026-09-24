"""Render a scan report to a self-contained HTML page (no external assets)."""

from __future__ import annotations

from html import escape

from mavs_scan.model import ScanReport, Severity

_SEV_CLASS = {
    Severity.CRITICAL: "crit",
    Severity.HIGH: "high",
    Severity.MEDIUM: "med",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

_CSS = """
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e6e6e6}
a{color:#6cf}
header{padding:20px 24px;background:#161b22;border-bottom:1px solid #2a2f37}
h1{margin:0;font-size:18px;letter-spacing:.5px}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px 24px;margin:16px 0}
.meta div{color:#9aa4b2}.meta b{color:#e6e6e6}
.score{display:flex;gap:16px;align-items:center;margin:16px 0}
.grade{font-size:34px;font-weight:700;padding:6px 18px;border-radius:10px;background:#222;}
.pills span{display:inline-block;padding:3px 10px;border-radius:20px;margin:2px;font-size:12px;font-weight:600}
.crit{background:#7b1fa2;color:#fff}.high{background:#c62828;color:#fff}.med{background:#ef6c00;color:#fff}
.low{background:#0277bd;color:#fff}.info{background:#37474f;color:#fff}.good{background:#2e7d32;color:#fff}
.f{border:1px solid #2a2f37;border-radius:10px;margin:12px 0;overflow:hidden;background:#141922}
.f>summary{cursor:pointer;padding:12px 16px;list-style:none;display:flex;gap:10px;align-items:center}
.f>summary::-webkit-details-marker{display:none}
.f .body{padding:0 16px 16px 16px;border-top:1px solid #2a2f37}
.tag{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;text-transform:uppercase}
.rid{color:#7d8590;font-size:12px;margin-left:auto}
pre{background:#0b0e12;border:1px solid #2a2f37;border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.evi{color:#9aa4b2;font-size:13px}
.exploit{border-left:3px solid #ef6c00;padding-left:12px}
form{margin:12px 0;padding:16px;background:#161b22;border:1px dashed #2a2f37;border-radius:10px}
button{background:#238636;color:#fff;border:0;padding:8px 16px;border-radius:8px;font-weight:600;cursor:pointer}
.muted{color:#7d8590;font-size:12px}
"""


def _pills(report: ScanReport) -> str:
    counts = report.counts()
    out = []
    for sev in reversed(Severity):
        n = counts[sev.label]
        if n:
            out.append(f'<span class="{_SEV_CLASS[sev]}">{n} {sev.label}</span>')
    return "".join(out) or '<span class="good">0 findings</span>'


def _finding_html(finding) -> str:
    cls = _SEV_CLASS[finding.severity]
    parts = [
        '<details class="f"><summary>',
        f'<span class="tag {cls}">{finding.severity.label}</span>',
        f"<b>{escape(finding.title)}</b>",
        f'<span class="rid">{escape(finding.rule_id)}</span></summary><div class="body">',
        f"<p>{escape(finding.description)}</p>",
    ]
    meta = " | ".join(escape(m) for m in (finding.cwe, finding.masvs, finding.reference) if m)
    if meta:
        parts.append(f'<p class="muted">{meta}</p>')
    if finding.evidence:
        items = "".join(f"<li>{escape(e)}</li>" for e in finding.evidence)
        parts.append(f'<div class="evi"><b>Evidence</b><ul>{items}</ul></div>')
    if finding.verify:
        parts.append(f"<p><b>Verify:</b> {escape(finding.verify)}</p>")
    if finding.exploit:
        parts.append(
            f'<div class="exploit"><b>Exploit / manual check</b><pre>{escape(finding.exploit)}</pre></div>'
        )
    parts.append("</div></details>")
    return "".join(parts)


def _upload_form() -> str:
    return (
        '<form method="post" action="/scan" enctype="multipart/form-data">'
        "<b>Scan another package</b><br>"
        '<input type="file" name="file" accept=".apk,.xapk" required> '
        "<button type=submit>Scan</button>"
        '<div class="muted">Runs the same static engine as the CLI. Files stay on this host.</div>'
        "</form>"
    )


def page(report: ScanReport | None) -> str:
    """Return a complete HTML document for ``report`` (or an empty landing)."""
    body = [
        f"<style>{_CSS}</style>",
        "<header><h1>MAVS &mdash; Mobile App Vulnerability Scanner</h1></header>",
        '<div class="wrap">',
        _upload_form(),
    ]
    if report is None:
        body.append('<p class="muted">No scan loaded. Upload an APK or XAPK above.</p></div>')
        return "".join(body)
    app = report.app
    body.append(
        '<div class="meta">'
        f"<div>Package<br><b>{escape(app.package or '?')}</b></div>"
        f"<div>Version<br><b>{escape(app.version_name or '?')} ({escape(app.version_code or '?')})</b></div>"
        f"<div>SDK<br><b>min {app.min_sdk or '?'} / target {app.target_sdk or '?'}</b></div>"
        f"<div>Type<br><b>{report.file_type}</b></div>"
        f"<div>Permissions<br><b>{len(app.permissions)}</b></div>"
        f"<div>SHA-256<br><b class=muted>{report.sha256[:32]}…</b></div>"
        "</div>",
    )
    body.append(
        f'<div class="score"><div class="grade">{report.grade}</div>'
        f"<div><b>{report.risk_score}/100</b> risk score<br>"
        f'<div class="pills">{_pills(report)}</div></div></div>',
    )
    body.append(
        f'<p class="muted">{len(report.findings)} finding(s). '
        "Static observations, not proof of runtime exploitability.</p>"
    )
    body.extend(_finding_html(f) for f in report.findings)
    body.append("</div>")
    return "".join(body)
