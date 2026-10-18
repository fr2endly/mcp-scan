"""
Encoded payloads in descriptions, schemas and defaults.

Base64 and hex blobs in a tool description have almost no legitimate use, and
one obvious illegitimate one: getting an instruction past a reviewer who is
only skimming the text.
"""

import base64
import binascii
import re

from ..severity import Finding, Severity

B64_LONG = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
HEX_LONG = re.compile(r"\b(?:0x)?[0-9a-fA-F]{40,}\b")

# What counts as hostile once decoded
DECODED_RED_FLAGS = [
    r"<\s*system\s*>", r"<\s*/?\s*instructions?\s*>", r"ignore\s+previous",
    r"curl\s", r"wget\s", r"powershell", r"/bin/(ba)?sh", r"nc\s+-",
    r"base64\s+-d", r"eval\(", r"exec\(", r"document\.cookie",
]


def _all_strings(obj) -> list[str]:
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for value in obj.values():
            out.extend(_all_strings(value))
    elif isinstance(obj, list):
        for value in obj:
            out.extend(_all_strings(value))
    return out


def check_encoded_payloads(tool: dict) -> list[Finding]:
    findings: list[Finding] = []
    name = tool.get("name", "<unnamed>")

    for text in _all_strings(tool):
        for match in B64_LONG.finditer(text):
            token = match.group(0)
            decoded_preview = ""
            suspicious = False
            try:
                raw = base64.b64decode(token, validate=True)
                decoded = raw.decode("utf-8", errors="replace")
                decoded_preview = decoded[:200]
                suspicious = any(
                    re.search(p, decoded, re.IGNORECASE) for p in DECODED_RED_FLAGS
                )
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue  # not base64, just a long token

            if suspicious:
                findings.append(Finding(
                    check_id="MCP-ENC-001",
                    title="Encoded payload containing instructions or commands",
                    severity=Severity.CRITICAL,
                    tool_name=name,
                    evidence=f"token ({len(token)} chars). Decoded: \"{decoded_preview}\"",
                    recommendation=(
                        "Do not connect this server. Base64 is used here to get past a "
                        "reviewer who only skims the description."
                    ),
                    reference="Steganographic prompt injection",
                ))
            else:
                findings.append(Finding(
                    check_id="MCP-ENC-002",
                    title="Long base64 string in a description or schema",
                    severity=Severity.MEDIUM,
                    tool_name=name,
                    evidence=f"token of {len(token)} chars; decoded excerpt: \"{decoded_preview[:120]}\"",
                    recommendation=(
                        "Ask where this came from. There is almost no legitimate reason "
                        "to keep base64 in a tool description."
                    ),
                    reference="Steganographic prompt injection",
                ))

        for match in HEX_LONG.finditer(text):
            token = match.group(0)
            body = token[2:] if token.lower().startswith("0x") else token
            try:
                decoded = bytes.fromhex(body).decode("utf-8", errors="replace")
            except ValueError:
                continue
            if any(re.search(p, decoded, re.IGNORECASE) for p in DECODED_RED_FLAGS):
                findings.append(Finding(
                    check_id="MCP-ENC-003",
                    title="Hex-encoded payload containing commands",
                    severity=Severity.CRITICAL,
                    tool_name=name,
                    evidence=f"decoded: \"{decoded[:200]}\"",
                    recommendation="Do not connect this server.",
                    reference="Steganographic prompt injection",
                ))

    return findings
