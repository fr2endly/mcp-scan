"""
Reporting: console, JSON, Markdown and SARIF (for GitHub Code Scanning).
"""

import json
from collections import Counter

from .severity import Finding, Severity

BANNER = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
    Severity.INFO: "⚪ INFO",
}

SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]

INFORMATION_URI = "https://github.com/fr2endly/mcp-scan"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-int(f.severity), f.check_id, f.tool_name or ""))


def print_console(findings: list[Finding], target: str, tool_count: int) -> None:
    print()
    print(f"{'=' * 72}")
    print(f"  mcp-scan · {target}")
    print(f"  tools: {tool_count} · findings: {len(findings)}")
    print(f"{'=' * 72}")

    counts = Counter(f.severity for f in findings)
    for severity in SEVERITY_ORDER:
        if counts.get(severity):
            print(f"  {BANNER[severity]:<14} {counts[severity]}")
    print()

    for finding in sort_findings(findings):
        print(f"{BANNER[finding.severity]}  [{finding.check_id}] {finding.title}")
        if finding.tool_name:
            print(f"    tool: {finding.tool_name}")
        if finding.evidence:
            for line in finding.evidence.splitlines()[:4]:
                print(f"    ↳ {line[:160]}")
        if finding.recommendation:
            print(f"    → {finding.recommendation[:300]}")
        print()

    risky = [f for f in findings if f.severity >= Severity.HIGH]
    if risky:
        print("⚠️  Verdict: do NOT connect this server to an agent without manual review.")
        print(f"   {len(risky)} findings at HIGH or above.")
    else:
        print("✅ Verdict: no obvious signs of attack.")
        print("   This is not a safety guarantee. The scanner reads configuration,")
        print("   not runtime behaviour. Pair it with a sandbox and an egress allowlist.")
    print()


def to_json(findings: list[Finding], target: str, meta: dict) -> str:
    return json.dumps({
        "scanner": "mcp-scan",
        "version": "0.1.0",
        "target": target,
        "meta": meta,
        "summary": {
            severity.label.lower(): sum(1 for f in findings if f.severity == severity)
            for severity in SEVERITY_ORDER
        },
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }, indent=2, ensure_ascii=False)


def to_markdown(findings: list[Finding], target: str, meta: dict) -> str:
    lines = [
        "# mcp-scan report",
        "",
        f"- **Target:** `{target}`",
        f"- **Tools discovered:** {meta.get('tool_count', 0)}",
        f"- **Date:** {meta.get('scanned_at', '')}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    counts = Counter(f.severity for f in findings)
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity.label} | {counts.get(severity, 0)} |")

    lines += ["", "## Findings", ""]
    for finding in sort_findings(findings):
        lines += [
            f"### {BANNER[finding.severity]} {finding.title}",
            "",
            f"- **Check ID:** `{finding.check_id}`",
        ]
        if finding.tool_name:
            lines.append(f"- **Tool:** `{finding.tool_name}`")
        if finding.evidence:
            lines += ["- **Evidence:**", "", "```", finding.evidence[:1200], "```"]
        if finding.recommendation:
            lines += [f"- **Recommendation:** {finding.recommendation}"]
        if finding.reference:
            lines += [f"- **Reference:** {finding.reference}"]
        lines.append("")

    return "\n".join(lines)


def to_sarif(findings: list[Finding], target: str) -> dict:
    """SARIF 2.1.0, which is what GitHub Code Scanning ingests."""
    rules = {}
    results = []
    for finding in findings:
        if finding.check_id not in rules:
            rules[finding.check_id] = {
                "id": finding.check_id,
                "shortDescription": {"text": finding.title},
                "helpUri": finding.reference or "https://modelcontextprotocol.io",
            }
        sarif_level = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }[finding.severity]
        results.append({
            "ruleId": finding.check_id,
            "level": sarif_level,
            "message": {
                "text": f"{finding.title}\n\n{finding.evidence}\n\n{finding.recommendation}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                    "region": {"startLine": 1},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-scan",
                    "version": "0.1.0",
                    "informationUri": INFORMATION_URI,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
