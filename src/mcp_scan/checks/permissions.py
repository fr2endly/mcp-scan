"""
Secrets, filesystem access, command execution, network egress, scope.

These look at more than the description: parameter names in inputSchema, enum
values and defaults all end up in the context too, and all of them can carry
an instruction or leak a path.
"""

import json
import re

from ..severity import Finding, Severity

SECRET_KEYS = [
    "api_key", "apikey", "secret", "token", "password", "passwd", "credential",
    "private_key", "access_key", "auth", "bearer", "session_id", "cookie",
    "aws_access", "aws_secret", "ghp_", "sk-", "xoxb",
]

SECRET_ENV = [
    r"\$\{?[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*\}?",
    r"\bos\.environ\b", r"\bprocess\.env\b", r"\benv\[", r"\.env\b",
    r"~/?\.(aws|config|netrc|npmrc|git-credentials)\b",
]

FS_SENSITIVE = [
    r"~/\.ssh", r"~/\.aws", r"~/\.gnupg", r"/etc/(passwd|shadow|sudoers)",
    r"/root/", r"%USERPROFILE%", r"\\AppData\\",
    r"id_rsa", r"id_ed25519", r"known_hosts", r"authorized_keys",
    r"\.kube/config", r"\.docker/config\.json",
]

FS_TRAVERSAL = [r"\.\./", r"\.\.\\", r"/\.\./"]

EXEC_PATTERNS = [
    r"\bshell\b", r"\bexec\b", r"\bsubprocess\b", r"\beval\b", r"\bsystem\b",
    r"\bbash\s+-c\b", r"\bsh\s+-c\b", r"\bpowershell\b", r"\bcmd\.exe\b",
    r"\brun_command\b", r"\bexecute_command\b", r"\bchild_process\b",
]

EGRESS_PATTERNS = [
    r"\bfetch\b", r"\bhttp_get\b", r"\bhttp_post\b", r"\brequest\b",
    r"\burllib\b", r"\baxios\b", r"\bgot\b", r"\bcurl\b", r"\bwget\b",
    r"\bsocket\b", r"\bconnect\b",
]


def _blob(tool: dict) -> str:
    """The whole tool as one lowercase string, so keys and schema values are searchable."""
    return json.dumps(tool, ensure_ascii=False).lower()


def _param_names(tool: dict) -> list[str]:
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    return list(props.keys())


def _enum_and_defaults(tool: dict) -> list[str]:
    values: list[str] = []
    schema = tool.get("inputSchema") or {}
    for prop in (schema.get("properties") or {}).values():
        if not isinstance(prop, dict):
            continue
        if "default" in prop:
            values.append(str(prop["default"]))
        for enum_value in prop.get("enum") or []:
            values.append(str(enum_value))
    return values


def _matched(patterns: list[str], haystack: str) -> list[str]:
    """What actually matched, not the regex that matched it.

    Reporting the pattern is useless to a reader: `~/\\.ssh` tells them
    nothing, `~/.ssh/id_rsa` tells them exactly where to look.
    """
    out = []
    for pattern in patterns:
        for m in re.finditer(pattern, haystack):
            text = m.group(0)
            if text not in out:
                out.append(text)
    return out


def check_permissions(tool: dict) -> list[Finding]:
    findings: list[Finding] = []
    name = tool.get("name", "<unnamed>")
    blob = _blob(tool)
    params = _param_names(tool)
    literals = " ".join(_enum_and_defaults(tool)).lower()
    haystack = f"{blob} {' '.join(params).lower()} {literals}"

    # Secrets and environment variables
    hits = [key for key in SECRET_KEYS if key in blob]
    env_hits = [
        m.group(0) for pattern in SECRET_ENV
        for m in [re.search(pattern, blob)] if m
    ]
    if hits or env_hits:
        findings.append(Finding(
            check_id="MCP-PERM-001",
            title="Tool requests or reads secrets / environment variables",
            severity=Severity.CRITICAL,
            tool_name=name,
            evidence=f"keys: {sorted(set(hits))[:8]}; env patterns: {sorted(set(env_hits))[:5]}",
            recommendation=(
                "A tool has no business holding your keys. A server that takes a secret as a "
                "parameter is either badly designed or harvesting credentials. Never pass "
                "secrets in tool arguments; let the host process read them from its own "
                "environment, and only for servers you trust."
            ),
            reference="OWASP LLM02: Sensitive Information Disclosure",
        ))

    # Sensitive paths and traversal.
    # FS_TRAVERSAL holds regexes, not literals: do not re.escape() them.
    sens = _matched(FS_SENSITIVE, haystack)
    trav = _matched(FS_TRAVERSAL, haystack)
    if sens:
        findings.append(Finding(
            check_id="MCP-PERM-002",
            title="Tool references sensitive filesystem paths",
            severity=Severity.CRITICAL,
            tool_name=name,
            evidence=f"matched paths: {sens[:6]}",
            recommendation=(
                "Deny it. No legitimate MCP tool needs ~/.ssh, ~/.aws or /etc/passwd."
            ),
            reference="OWASP LLM06: Excessive Agency",
        ))
    if trav:
        findings.append(Finding(
            check_id="MCP-PERM-003",
            title="Possible path traversal in the description or in default values",
            severity=Severity.HIGH,
            tool_name=name,
            evidence=f"matched: {trav[:4]}",
            recommendation=(
                "Confirm the server normalises paths and confines them to a working "
                "directory (chroot or an allowlist)."
            ),
            reference="CWE-22: Path Traversal",
        ))

    # Arbitrary command execution
    exec_hits = _matched(EXEC_PATTERNS, blob)
    if exec_hits:
        findings.append(Finding(
            check_id="MCP-PERM-004",
            title="Tool executes arbitrary commands",
            severity=Severity.HIGH,
            tool_name=name,
            evidence=f"matched: {exec_hits[:6]}",
            recommendation=(
                "Not hostile by itself; shell tools are legitimate. But they should never "
                "reach an agent without a sandbox, a command allowlist and human "
                "confirmation on each invocation."
            ),
            reference="OWASP LLM06: Excessive Agency",
        ))

    # Network egress to an arbitrary address
    egress_hits = _matched(EGRESS_PATTERNS, blob)
    if egress_hits and not sens:
        findings.append(Finding(
            check_id="MCP-PERM-005",
            title="Tool makes network requests to arbitrary addresses",
            severity=Severity.MEDIUM,
            tool_name=name,
            evidence=f"matched: {egress_hits[:6]}",
            recommendation=(
                "Constrain egress with a domain allowlist at the host network layer. "
                "Asking the model nicely in a prompt is not a control."
            ),
            reference="OWASP LLM06: Excessive Agency",
        ))

    # Unconstrained schema, or an enum with fifty entries nobody will read
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    unbounded = []
    for pname, pdef in props.items():
        if not isinstance(pdef, dict):
            continue
        ptype = pdef.get("type")
        if ptype in (None, "any") or (isinstance(ptype, list) and len(ptype) > 2):
            unbounded.append(pname)
        if "enum" in pdef and len(pdef["enum"]) > 50:
            unbounded.append(f"{pname} (enum {len(pdef['enum'])})")
    if unbounded:
        findings.append(Finding(
            check_id="MCP-PERM-006",
            title="Parameters with no type constraint, or an over-broad enum",
            severity=Severity.LOW,
            tool_name=name,
            evidence=f"parameters: {unbounded[:8]}",
            recommendation=(
                "A loose schema widens the attack surface: the agent can pass something "
                "the author never anticipated."
            ),
            reference="CWE-20: Improper Input Validation",
        ))

    return findings


def check_scope(tools: list[dict]) -> list[Finding]:
    """Server-level check: too many tools in one place."""
    if len(tools) > 20:
        return [Finding(
            check_id="MCP-SCOPE-001",
            title="Server exposes an excessive number of tools",
            severity=Severity.MEDIUM,
            tool_name=None,
            evidence=f"{len(tools)} tools in a single server",
            recommendation=(
                "Every tool takes up context and widens the attack surface. Past twenty "
                "tools the agent starts choosing badly, and an attacker has plenty of "
                "cover to hide a malicious one among the legitimate ones."
            ),
            reference="OWASP LLM06: Excessive Agency",
        )]
    return []
