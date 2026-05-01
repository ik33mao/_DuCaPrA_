from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanFinding:
    rule_id: str
    severity: str
    message: str


@dataclass(frozen=True)
class ScanResult:
    allowed: bool
    findings: tuple[ScanFinding, ...]

    @property
    def reason(self) -> str:
        return "; ".join(f"{finding.rule_id}: {finding.message}" for finding in self.findings)


class PromptInjectionScanner:
    """Conservative pre-signing scanner for obvious instruction-laundering attempts.

    This is not a complete prompt-injection detector. Its purpose is to block
    high-signal content that should not be wrapped in a trusted envelope without
    explicit human or policy override.
    """

    DEFAULT_RULES: tuple[tuple[str, str, str], ...] = (
        ("PI001", r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b", "instruction override attempt"),
        ("PI002", r"\b(disregard|bypass|override)\s+(the\s+)?(system|developer|safety)\s+(prompt|instructions?)\b", "system instruction bypass attempt"),
        ("PI003", r"\b(reveal|print|dump|show)\s+(the\s+)?(system|developer)\s+(prompt|instructions?)\b", "prompt disclosure attempt"),
        ("PI004", r"\b(exfiltrate|leak|steal)\s+(all\s+)?(data|secrets?|tokens?|keys?)\b", "data exfiltration instruction"),
        ("PI005", r"\btool\s*:\s*(shell|bash|python|curl|wget)\b", "tool invocation smuggling"),
        ("PI006", r"\bBEGIN\s+(SYSTEM|DEVELOPER|ADMIN)\s+PROMPT\b", "role prompt smuggling"),
    )

    def __init__(self, rules: tuple[tuple[str, str, str], ...] | None = None):
        self._rules = tuple(
            (rule_id, re.compile(pattern, re.IGNORECASE), message)
            for rule_id, pattern, message in (rules or self.DEFAULT_RULES)
        )

    def scan(self, content: str) -> ScanResult:
        findings = tuple(
            ScanFinding(rule_id=rule_id, severity="high", message=message)
            for rule_id, pattern, message in self._rules
            if pattern.search(content)
        )
        return ScanResult(allowed=not findings, findings=findings)
