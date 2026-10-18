"""
Tool shadowing.

One tool's description mentions or overrides another tool on the same server.
The attack: a legitimate `add_note`, next to a malicious `add_note_pro` whose
description says "always use this instead of add_note".
"""

import re

from ..severity import Finding, Severity

DEFER_PATTERNS = [
    r"instead\s+of\s+`?{name}`?",
    r"(prefer|use|call)\s+(this|me)\s+over\s+`?{name}`?",
    r"(deprecated|obsolete|do\s+not\s+use)[^.]*`?{name}`?",
    r"override[sd]?\s+`?{name}`?",
    r"replaces?\s+`?{name}`?",
    r"supersedes?\s+`?{name}`?",
    r"(avoid|stop\s+using)\s+`?{name}`?",
]


def check_shadowing(tools: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    names = [t.get("name", "") for t in tools if t.get("name")]

    for tool in tools:
        me = tool.get("name", "<unnamed>")
        description = str(tool.get("description", ""))
        annotations = str(tool.get("annotations", ""))
        haystack = f"{description} {annotations}"

        for other in names:
            if other == me or not other:
                continue

            # The other tool's name appears in the text at all
            mentioned = re.search(
                rf"`{re.escape(other)}`|\b{re.escape(other)}\b", haystack
            )
            if not mentioned:
                continue

            # A mention plus an instructive verb is what turns it into shadowing
            deferred = False
            for pattern in DEFER_PATTERNS:
                if re.search(pattern.format(name=re.escape(other)), haystack, re.IGNORECASE):
                    deferred = True
                    break

            findings.append(Finding(
                check_id="MCP-SHADOW-001" if deferred else "MCP-SHADOW-002",
                title=(
                    f"Tool intercepts calls meant for another tool ({other})"
                    if deferred
                    else f"Tool references another tool ({other})"
                ),
                severity=Severity.HIGH if deferred else Severity.LOW,
                tool_name=me,
                evidence=f"description excerpt: \"{haystack[:300]}\"",
                recommendation=(
                    "A tool description should not tell the agent which other tool to use. "
                    "That is the interception mechanism: a malicious tool posing as an "
                    "improved version of a legitimate one."
                    if deferred
                    else "Check the context of the mention. Cross-references between tools "
                         "are fine in documentation, not as directives to the agent."
                ),
                reference="Tool shadowing (Invariant Labs, 2025)",
            ))

    # Separately: names close enough that the model will pick the wrong one.
    # This is typosquatting inside a single server.
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if a != b and _is_confusable(a, b):
                findings.append(Finding(
                    check_id="MCP-SHADOW-003",
                    title=f"Tool names are easy to confuse: {a} / {b}",
                    severity=Severity.MEDIUM,
                    tool_name=None,
                    evidence=f"`{a}` and `{b}` differ only slightly",
                    recommendation=(
                        "The model can call the wrong one. If one of them was added later "
                        "and holds broader permissions, that is the substitution pattern."
                    ),
                    reference="Typosquatting / tool confusion",
                ))

    return findings


def _is_confusable(a: str, b: str) -> bool:
    """One insertion, deletion or substitution apart, or a _v2 / _pro / _new suffix."""
    a_norm, b_norm = a.lower(), b.lower()
    if a_norm == b_norm:
        return False
    suffixes = ("_pro", "_v2", "_new", "_fast", "_safe", "_better", "2", "pro", "new")
    for suffix in suffixes:
        if a_norm == b_norm + suffix or b_norm == a_norm + suffix:
            return True
        if a_norm == b_norm + suffix.lstrip("_") or b_norm == a_norm + suffix.lstrip("_"):
            return True
    # Levenshtein distance of exactly one
    if abs(len(a_norm) - len(b_norm)) > 1:
        return False
    longer, shorter = (a_norm, b_norm) if len(a_norm) >= len(b_norm) else (b_norm, a_norm)
    if len(longer) == len(shorter):
        diffs = sum(1 for x, y in zip(longer, shorter) if x != y)
        return diffs == 1
    i = j = diffs = 0
    while i < len(longer) and j < len(shorter):
        if longer[i] == shorter[j]:
            i += 1
            j += 1
        else:
            diffs += 1
            if diffs > 1:
                return False
            i += 1
    return True
