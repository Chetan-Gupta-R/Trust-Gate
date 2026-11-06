import re
from typing import Any


_PATTERNS = (
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?"
            r"(?:previous|prior|earlier)\s+(?:system\s+)?"
            r"(?:instructions?|rules?|prompts?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_instruction_override",
        re.compile(
            r"\boverride\s+(?:(?:the|all)\s+)?(?:system|previous|prior)\s+"
            r"(?:instructions?|rules?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "beneficiary_change",
        re.compile(
            r"\b(?:change|switch|replace|update)\s+(?:the\s+)?"
            r"(?:payment\s+)?beneficiar(?:y|ies)(?:\s+(?:bank|account|details))?"
            r"\b|\bsend\s+(?:the\s+)?payment\s+to\s+(?:a\s+)?"
            r"(?:different|new|another)\s+(?:bank\s+)?account\b",
            re.IGNORECASE,
        ),
    ),
    (
        "concealment",
        re.compile(
            r"\b(?:do\s+not|don['’]t)\s+(?:tell|inform|notify)\s+"
            r"(?:the\s+)?(?:user|recipient|accounts?\s+payable)\b"
            r"|\bhide\s+(?:this|the)\s+(?:instruction|message|request)\b"
            r"|\bkeep\s+this\s+(?:instruction|change|request)\s+secret\b",
            re.IGNORECASE,
        ),
    ),
    (
        "unauthorized_urgent_action",
        re.compile(
            r"\bprocess\s+(?:this\s+)?(?:immediately|right\s+away|now)\s+"
            r"without\s+(?:approval|authorization|verification)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "confidential_data_request",
        re.compile(
            r"\b(?:reveal|disclose|expose)\b.{0,50}\b"
            r"(?:confidential|secret|sensitive)\s+(?:information|data|details)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "privilege_escalation",
        re.compile(
            r"\byou\s+are\s+now\s+(?:the\s+)?"
            r"(?:system\s+administrator|admin|system)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verification_bypass",
        re.compile(
            r"\b(?:bypass|skip|disable)\s+(?:all\s+)?"
            r"(?:the\s+)?(?:vendor\s+)?verification\b"
            r"|\bdo\s+not\s+perform\s+(?:any\s+)?security\s+checks\b",
            re.IGNORECASE,
        ),
    ),
)


def _snippet(text: str, start: int, end: int, radius: int = 70) -> str:
    snippet = text[max(0, start - radius):min(len(text), end + radius)].strip()
    if len(snippet) > 200:
        snippet = snippet[:197].rstrip() + "..."
    return snippet


def detect_prompt_injection(document_text: Any) -> dict[str, Any]:
    """Find common malicious instruction indicators in untrusted document text."""
    if not isinstance(document_text, str):
        return {
            "detected": False,
            "risk_level": "LOW",
            "matched_patterns": [],
            "suspicious_instructions": [],
            "evidence": [],
            "concealment_detected": False,
        }

    normalized_text = re.sub(r"\s+", " ", document_text).strip()
    matched_patterns: list[str] = []
    suspicious_instructions: list[str] = []

    for name, pattern in _PATTERNS:
        match = pattern.search(normalized_text)
        if match:
            matched_patterns.append(name)
            suspicious_instructions.append(
                _snippet(normalized_text, match.start(), match.end())
            )

    detected = bool(matched_patterns)
    return {
        "detected": detected,
        "risk_level": "CRITICAL" if detected else "LOW",
        "matched_patterns": matched_patterns,
        "suspicious_instructions": suspicious_instructions,
        "evidence": [
            f"Suspicious instruction detected: {instruction}"
            for instruction in suspicious_instructions
        ],
        "concealment_detected": "concealment" in matched_patterns,
    }
