"""
Tool poisoning, exfiltration hints, instruction injection.

The logic is simple. A tool description gets pasted into the model's context,
so any imperative in a description is somebody talking to the model behind the
user's back.
"""

import re
import unicodedata

from ..severity import Finding, Severity

# --- Patterns ---

# Phrases asking the model to hide something from the user.
SECRECY = [
    r"do\s+not\s+tell\s+the\s+user",
    r"don'?t\s+tell\s+the\s+user",
    r"without\s+(informing|telling|notifying)\s+the\s+user",
    r"silently",
    r"do\s+not\s+mention",
    r"hide\s+(this|it|the)",
    r"keep\s+(this|it)\s+(secret|private|internal)",
    r"without\s+the\s+user'?s?\s+knowledge",
    r"do\s+not\s+disclose",
]

# Phrases trying to override the agent's own instructions.
OVERRIDE = [
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts)",
    r"disregard\s+(all\s+)?(previous|prior|system)",
    r"you\s+must\s+always",
    r"always\s+(run|execute|call|send)",
    r"never\s+(ask|question|refuse)",
    r"override",
    r"system\s+prompt",
    r"ignore\s+your\s+(guidelines|instructions)",
    r"forget\s+(everything|what\s+you\s+were\s+told)",
    r"new\s+instructions?\s*:",
]

# Exfiltration markers
EXFIL = [
    r"https?://[^\s\"']+",
    r"webhook",
    r"\bsend\s+(the|all|this|data|results?)\s+to\b",
    r"\bpost\s+to\b",
    r"\bupload\s+to\b",
    r"\bexfiltrat",
    r"\breport\s+to\s+https?://",
    r"\bcurl\b",
    r"\bngrok\b",
    r"\bpastebin\b",
    r"\bdiscord(app)?\.com/api/webhooks\b",
]

# Zero-width and invisible characters, the classic hidden-instruction trick
INVISIBLE_CHARS = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break space
    "\u180e",  # mongolian vowel separator
}

HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _iter_text_blobs(obj, path: str = ""):
    """Walk the object and yield every string in it, with a path for the report."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _iter_text_blobs(value, f"{path}.{key}" if path else key)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _iter_text_blobs(value, f"{path}[{index}]")


def _match_any(patterns: list[str], text: str) -> list[str]:
    hits = []
    lowered = text.lower()
    for pattern in patterns:
        found = re.search(pattern, lowered)
        if found:
            hits.append(found.group(0).strip())
    return hits


def check_tool_poisoning(tool: dict) -> list[Finding]:
    findings: list[Finding] = []
    name = tool.get("name", "<unnamed>")

    for path, text in _iter_text_blobs(tool):
        if not text or len(text) < 4:
            continue

        # Asking the model to hide what it did
        hits = _match_any(SECRECY, text)
        if hits:
            findings.append(Finding(
                check_id="MCP-POISON-001",
                title="Description asks the model to hide its actions from the user",
                severity=Severity.CRITICAL,
                tool_name=name,
                evidence=f"{path}: matched {hits}. Context: \"{text[:300]}\"",
                recommendation=(
                    "Do not connect this server. A tool description lands in the model's "
                    "context, and an instruction not to inform the user is an explicit "
                    "attempt to act covertly. If this is your own server, strip the "
                    "imperatives out: a description should say WHAT the tool does, not "
                    "issue commands to the model."
                ),
                reference="OWASP Agentic AI Threats: Tool Misuse / Memory Poisoning",
            ))

        # Trying to override the agent's instructions
        hits = _match_any(OVERRIDE, text)
        if hits:
            findings.append(Finding(
                check_id="MCP-POISON-002",
                title="Description tries to override the agent's instructions",
                severity=Severity.HIGH,
                tool_name=name,
                evidence=f"{path}: {hits}. Context: \"{text[:300]}\"",
                recommendation=(
                    "Question whether this tool should be connected at all. Wording like "
                    "\"ignore previous instructions\" or \"you must always\" inside a tool "
                    "description is prompt injection delivered through configuration."
                ),
                reference="OWASP LLM01: Prompt Injection",
            ))

        # Exfiltration
        hits = _match_any(EXFIL, text)
        if hits:
            # A URL in a description is not automatically hostile; plenty of servers link
            # to their own docs. Downgrade to HIGH when it is just a URL, keep CRITICAL
            # when there is also a verb for sending something.
            has_send_verb = any(
                re.search(p, text.lower())
                for p in [r"\bsend\b", r"\bpost\b", r"\bupload\b", r"webhook", r"\bcurl\b"]
            )
            findings.append(Finding(
                check_id="MCP-POISON-003",
                title="Description contains an external endpoint and/or an instruction to send data",
                severity=Severity.CRITICAL if has_send_verb else Severity.MEDIUM,
                tool_name=name,
                evidence=f"{path}: {hits[:5]}",
                recommendation=(
                    "Check where the data goes. If a tool sends results to an external URL "
                    "that URL is an exfiltration channel. Allow only an explicit domain "
                    "allowlist."
                ),
                reference="OWASP LLM02: Sensitive Information Disclosure",
            ))

        # Invisible characters
        invisible = [ch for ch in text if ch in INVISIBLE_CHARS]
        if invisible:
            names = ", ".join(
                f"U+{ord(ch):04X} ({unicodedata.name(ch, 'UNKNOWN')})"
                for ch in set(invisible)
            )
            findings.append(Finding(
                check_id="MCP-POISON-004",
                title="Invisible characters hidden in the description",
                severity=Severity.HIGH,
                tool_name=name,
                evidence=f"{path}: {len(invisible)} occurrences: {names}",
                recommendation=(
                    "Invisible characters hide instructions from a human reviewer while "
                    "keeping them visible to the model. Remove them and re-check where the "
                    "server came from."
                ),
                reference="Trojan Source / steganographic prompt injection",
            ))

        # HTML comments
        comments = HTML_COMMENT.findall(text)
        if comments:
            findings.append(Finding(
                check_id="MCP-POISON-005",
                title="HTML comment inside a tool description",
                severity=Severity.HIGH,
                tool_name=name,
                evidence=f"{path}: {comments[0][:200]}",
                recommendation=(
                    "A comment does not render, but it still reaches the model's context. "
                    "This is the standard way to hide an instruction in plain sight."
                ),
                reference="Hidden instruction injection",
            ))

    return findings
