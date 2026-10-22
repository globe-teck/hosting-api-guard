"""Redaction of tokens, auth headers and usernames in log lines and errors."""
import re

_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(panel|token|bearer|basic)\s+[^\s\"',]+"), r"\1\2 [REDACTED]"),
    (re.compile(r"(?i)\b(token|api_?key|password|passwd|secret|pass)\b(\s*[\"']?\s*(?:=|:(?!:))\s*[\"']?)[^\s\"'&,}]+"), r"\1\2[REDACTED]"),
    (re.compile(r"\b[A-Z0-9]{32}\b"), "[REDACTED-TOKEN]"),  # 32-char API tokens
    (re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
]


def redact(text, usernames=()):
    """Return text with secrets and the given usernames masked."""
    s = str(text)
    for pat, rep in _PATTERNS:
        s = pat.sub(rep, s)
    for u in sorted({u for u in usernames if u}, key=len, reverse=True):
        s = re.sub(r"(?<![\w.-])" + re.escape(u) + r"(?![\w-])", "[USER]", s)
    return s
