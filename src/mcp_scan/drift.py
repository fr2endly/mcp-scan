"""
Rug pull / drift.

Saves a snapshot of tools/list and diffs it on the next run. This is the only
check that defends against a server which behaves perfectly during review and
rewrites its descriptions after you install it.
"""

import hashlib
import json
import os
import time
from pathlib import Path

from .severity import Finding, Severity

SNAPSHOT_DIR = Path(os.environ.get("MCP_SCAN_SNAPSHOTS", ".mcp-scan-snapshots"))


def _slug(target: str) -> str:
    return hashlib.sha256(target.encode()).hexdigest()[:16]


def _tool_fingerprint(tool: dict) -> dict:
    """A stable fingerprint: the name, plus a separate hash of the description and schema."""
    name = tool.get("name", "<unnamed>")
    payload = json.dumps(tool, sort_keys=True, ensure_ascii=False)
    return {
        "name": name,
        "hash": hashlib.sha256(payload.encode()).hexdigest(),
        "description_hash": hashlib.sha256(
            str(tool.get("description", "")).encode()
        ).hexdigest(),
        "schema_hash": hashlib.sha256(
            json.dumps(tool.get("inputSchema") or {}, sort_keys=True).encode()
        ).hexdigest(),
    }


def snapshot_and_diff(target: str, tools: list[dict], update: bool = True) -> list[Finding]:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    path = SNAPSHOT_DIR / f"{_slug(target)}.json"

    current = {fp["name"]: fp for fp in map(_tool_fingerprint, tools)}
    now = int(time.time())

    if not path.exists():
        if update:
            path.write_text(json.dumps({
                "target": target,
                "created": now,
                "updated": now,
                "runs": 1,
                "tools": current,
            }, indent=2, ensure_ascii=False))
        return [Finding(
            check_id="MCP-DRIFT-000",
            title="Baseline snapshot created for this server",
            severity=Severity.INFO,
            tool_name=None,
            evidence=f"{path} · {len(current)} tools",
            recommendation=(
                "Run mcp-scan periodically (cron or CI). If a description changes the "
                "scanner will report drift, and that is the rug pull."
            ),
            reference="Supply chain integrity",
        )]

    try:
        previous = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    prev_tools: dict = previous.get("tools", {})
    findings: list[Finding] = []

    added = sorted(set(current) - set(prev_tools))
    removed = sorted(set(prev_tools) - set(current))
    changed_desc = sorted(
        name for name in set(current) & set(prev_tools)
        if current[name]["description_hash"] != prev_tools[name]["description_hash"]
    )
    changed_schema = sorted(
        name for name in set(current) & set(prev_tools)
        if current[name]["schema_hash"] != prev_tools[name]["schema_hash"]
    )

    if added:
        findings.append(Finding(
            check_id="MCP-DRIFT-001",
            title="New tools appeared on the server",
            severity=Severity.HIGH,
            tool_name=None,
            evidence=f"added: {added}",
            recommendation=(
                "A new tool on an already-installed server is the classic rug pull: get "
                "through review with a harmless set, then add the malicious one. Review "
                "every new tool by hand."
            ),
            reference="Rug pull attack",
        ))

    if changed_desc:
        findings.append(Finding(
            check_id="MCP-DRIFT-002",
            title="Descriptions of existing tools changed",
            severity=Severity.CRITICAL,
            tool_name=None,
            evidence=f"descriptions changed: {changed_desc}",
            recommendation=(
                "A description goes straight into the model's context, so changing it "
                "changes what the agent does without touching a line of server code. "
                "Disconnect this server now and diff it manually."
            ),
            reference="Rug pull / tool poisoning",
        ))

    if changed_schema:
        findings.append(Finding(
            check_id="MCP-DRIFT-003",
            title="Input schemas changed",
            severity=Severity.HIGH,
            tool_name=None,
            evidence=f"schemas changed: {changed_schema}",
            recommendation=(
                "Look at the diff. A widened schema can mean new access to data that the "
                "tool did not used to receive."
            ),
            reference="Rug pull",
        ))

    if removed:
        findings.append(Finding(
            check_id="MCP-DRIFT-004",
            title="Tools were removed from the server",
            severity=Severity.MEDIUM,
            tool_name=None,
            evidence=f"removed: {removed}",
            recommendation=(
                "Removing a safe tool and replacing it with a similar-looking one is also "
                "a substitution pattern."
            ),
            reference="Tool shadowing",
        ))

    if not findings:
        findings.append(Finding(
            check_id="MCP-DRIFT-OK",
            title="No changes since the last snapshot",
            severity=Severity.INFO,
            tool_name=None,
            evidence=f"snapshot from {previous.get('created')}, runs: {previous.get('runs', 1)}",
            recommendation="",
            reference="",
        ))

    if update:
        path.write_text(json.dumps({
            "target": target,
            "created": previous.get("created", now),
            "updated": now,
            "runs": previous.get("runs", 1) + 1,
            "tools": current,
        }, indent=2, ensure_ascii=False))

    return findings
