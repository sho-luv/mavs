"""Terminal rendering of a scan report with verbose and exploit modes.

The default view lists findings worst-first. ``-v`` adds evidence and metadata;
``-e`` adds the manual verification and exploitation guidance carried from the
original tool. Colour is disabled when output is not a TTY.
"""

from __future__ import annotations

import sys
from typing import TextIO

from mavs_scan.model import ScanReport, Severity

BANNER = r"""
                                   ╓
                        ╕         ╒╣╕                     ╣╣╣─    ╦╣╣
                ╓      ║╬         ╣╣╣      ╒             ╣╣╣─  ╒╣╣╩╙╣╬║╣
                ╣╕     ╣╣        ╫╣ ╫╣     ╡  ╔         ╣╣╣   ╦╣╩   ║╣╬
               ╣╣╣    ║╣╣╬      ╔╣╩  ╫╣╖  ╞╬  ╣╣       ╣╣╣   ╣╣╬    ╞╩
             ╒╣╣╩╣╣╖ ╔╣╬╣╣╕    ╔╣╣╗╗╦╦╣╣╦╦╣╣  ╣╣╣     ╣╣╣     ╙╣╣╣╦╗╖
            ╔╣╣╜  ╝╣╣╣╜ ╙╣╣═╩╜║╣╣╜     ╫╣╖     ╣╣╣  ╒╣╣╣          ╠╜╝╣╣╣╣╗╖
          ╓╣╣╩           ╚╣╣ ╦╣╬        ╚╣╗     ╣╣╬╓╣╣╬      ╓╦╣╣╣╩      ╙╙╝╣╣╣╗╖
        ╒╣╣╬╗╗╗           ╚╣╣╖           ╙╣╣╗   ╙╣╣╣╣╩    ╓╣╣╩╙ ║╣             ╙╣╣╣╖
      ╓╣╣╝╜╙╙╙╙            ╚╣╣╖╦           ╙╝╣╗╖ ╫╣╣╬    ├╣╣╖    ╬           ╓╓╗╣╣╣╩
                       ║╣╣╣╣╣╣╣╣╣╖           ╓╣╣╣ ╣╬      ╙╙╝╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╝╝╜╙╙
                             └╙╙╨╝╝╝╝╝╝╝╝╝╨╜╜╙╙╙   ╣

        Mobile Application Vulnerability Scanner | @sho_luv
"""

_RESET = "\033[0m"
_COLOR = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[0;33m",
    Severity.LOW: "\033[0;36m",
    Severity.INFO: "\033[0;37m",
}
_BWHITE = "\033[1;37m"
_BYELLOW = "\033[1;33m"
_UWHITE = "\033[4;37m"


def render(
    report: ScanReport,
    *,
    verbose: bool = False,
    exploit: bool = False,
    color: bool | None = None,
    out: TextIO | None = None,
) -> None:
    """Write a human-readable report to ``out`` (stdout by default)."""
    stream = out or sys.stdout
    use_color = stream.isatty() if color is None else color
    write = _writer(stream, use_color)

    write(f"{_BWHITE}{BANNER}{_RESET}" if use_color else BANNER)
    _header(report, write, use_color)
    _summary(report, write, use_color)

    if not report.findings:
        write("\nNo findings from the supported checks. This is not proof of security.\n")
    for finding in report.findings:
        _finding(finding, write, use_color, verbose=verbose, exploit=exploit)

    _coverage(report, write, use_color)
    write(
        "\nStatic findings record what is present in the package. They are not proof "
        "of runtime exploitability; verify each on a device.\n",
    )


def _writer(stream: TextIO, use_color: bool):
    def write(text: str) -> None:
        stream.write(text if use_color else _strip(text))
        stream.write("\n")

    return write


def _strip(text: str) -> str:
    import re  # noqa: PLC0415

    return re.sub(r"\033\[[0-9;]*m", "", text)


def _c(text: str, code: str, use_color: bool) -> str:
    return f"{code}{text}{_RESET}" if use_color else text


def _header(report: ScanReport, write, use_color: bool) -> None:
    app = report.app
    write(f" Target:       {_c(report.target, _BWHITE, use_color)}")
    write(f" Type:         {report.file_type}")
    write(f" SHA-256:      {report.sha256}")
    write(f" Package:      {_c(app.package or '?', _BWHITE, use_color)}")
    write(f" Version:      {app.version_name or '?'} ({app.version_code or '?'})")
    write(f" SDK:          min {app.min_sdk or '?'} / target {app.target_sdk or '?'}")
    write(f" Main activity:{app.main_activity or '?'}")
    write(f" Permissions:  {len(app.permissions)}")


def _summary(report: ScanReport, write, use_color: bool) -> None:
    counts = report.counts()
    parts = [
        _c(f"{counts[s.label]} {s.label}", _COLOR[s], use_color)
        for s in reversed(Severity)
        if counts[s.label]
    ]
    write(f"\n{_UWHITE if use_color else ''} Summary {_RESET if use_color else ''}")
    write(
        f" Risk score:   {_c(str(report.risk_score), _BYELLOW, use_color)}/100  "
        f"Grade: {_c(report.grade, _BYELLOW, use_color)}"
    )
    write(f" Findings:     {len(report.findings)}  ({'  '.join(parts) or 'none'})")


def _finding(finding, write, use_color: bool, *, verbose: bool, exploit: bool) -> None:
    color = _COLOR[finding.severity]
    tag = _c(f"[{finding.severity.label.upper()}]", color, use_color)
    write(f"\n{tag} {_c(finding.title, _BWHITE, use_color)}  ({finding.rule_id})")
    write(f"    {finding.description}")
    meta = [m for m in (finding.cwe, finding.masvs) if m]
    if meta:
        write(f"    {' | '.join(meta)}")
    if verbose and finding.evidence:
        write(f"    {_c('Evidence:', _UWHITE, use_color)}")
        for item in finding.evidence:
            write(f"      - {item}")
    if verbose and finding.verify:
        write(f"    {_c('Verify:', _UWHITE, use_color)} {finding.verify}")
    if exploit and finding.exploit:
        write(f"    {_c('[+] Exploit:', _BYELLOW, use_color)}")
        for line in finding.exploit.splitlines():
            write(f"      {line}")


def _coverage(report: ScanReport, write, use_color: bool) -> None:
    incomplete = [c for c in report.coverage if c.status != "ok"]
    if not incomplete:
        return
    write(f"\n{_c('Coverage notes:', _UWHITE, use_color)}")
    for item in incomplete:
        write(f"  [{item.status}] {item.stage}: {item.detail}")
