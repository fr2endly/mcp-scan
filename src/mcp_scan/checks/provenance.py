"""
Server provenance and metadata.

Not attacks on their own. What they do is make drift tracking possible: without
a version there is nothing stable to snapshot against.
"""

from ..severity import Finding, Severity


def check_server_metadata(init_result: dict, target: str) -> list[Finding]:
    findings: list[Finding] = []
    info = init_result.get("serverInfo") or {}
    name = info.get("name", "")
    version = info.get("version", "")

    if not version:
        findings.append(Finding(
            check_id="MCP-PROV-001",
            title="Server does not report a version",
            severity=Severity.INFO,
            tool_name=None,
            evidence=f"serverInfo: {info}",
            recommendation=(
                "Without a version you cannot pin a snapshot or track a rug pull. Ask the "
                "provider for one, or fall back to snapshotting by content hash."
            ),
            reference="Supply chain integrity",
        ))

    if not name:
        findings.append(Finding(
            check_id="MCP-PROV-002",
            title="Server does not report a name",
            severity=Severity.INFO,
            tool_name=None,
            evidence=f"target: {target}",
            recommendation=(
                "Suggests a hand-rolled server, or one that has been deliberately "
                "stripped of identifying metadata."
            ),
            reference="Supply chain integrity",
        ))

    capabilities = init_result.get("capabilities") or {}
    if capabilities.get("logging"):
        findings.append(Finding(
            check_id="MCP-PROV-003",
            title="Server declares a logging capability",
            severity=Severity.LOW,
            tool_name=None,
            evidence=f"capabilities: {list(capabilities.keys())}",
            recommendation=(
                "Logging means the server may send information about calls somewhere. "
                "Find out what it logs and where that goes."
            ),
            reference="OWASP LLM02",
        ))

    return findings
