from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Finding:
    """One finding. Every check produces zero or more of these."""

    def __init__(
        self,
        check_id: str,
        title: str,
        severity: Severity,
        tool_name: str | None = None,
        evidence: str = "",
        recommendation: str = "",
        reference: str = "",
    ):
        self.check_id = check_id
        self.title = title
        self.severity = severity
        self.tool_name = tool_name
        self.evidence = evidence
        self.recommendation = recommendation
        self.reference = reference

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.label,
            "severity_score": int(self.severity),
            "tool": self.tool_name,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "reference": self.reference,
        }

    def __repr__(self) -> str:
        scope = f" [{self.tool_name}]" if self.tool_name else ""
        return f"<{self.severity.label}{scope} {self.title}>"
