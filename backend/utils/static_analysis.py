import re
from typing import Optional

# ==========================================
# WAF ENGINE: THREAT SIGNATURES
# ==========================================

THREAT_SIGNATURES = [
    {
        "intent": "Prompt Injection / Direct Evasion",
        "id": "AML.T0051",
        "risk_score": 9.5,
        "risk_level": "CRITICAL",
        "patterns": [
            re.compile(r"(ignore|disregard)\s+(all\s+)?(previous\s+)?(instructions|prompts|rules|directives)", re.I),
            re.compile(r"you\s+are\s+(now\s+)?(a\s+)?(DAN|admin|developer|unfiltered|jailbroken)", re.I),
            re.compile(r"developer\s+mode\s+enabled", re.I),
            re.compile(r"simulate\s+a\s+(hypothetical|fictional)\s+scenario\s+where", re.I),
            re.compile(r"bypassing\s+(filters|safety|guardrails)", re.I)
        ]
    },
    {
        "intent": "System Prompt Leakage",
        "id": "LLM06",  # Sensitive Information Disclosure
        "risk_score": 9.0,
        "risk_level": "CRITICAL",
        "patterns": [
            re.compile(r"(repeat|print|show)\s+(all\s+)?(the\s+)?(above|previous|initial)\s+(text|instructions|rules)",
                       re.I),
            re.compile(r"what\s+(were|are)\s+your\s+(hidden\s+)?(rules|instructions|system\s+prompt)", re.I),
            re.compile(r"translate\s+your\s+system\s+prompt", re.I)
        ]
    },
    {
        "intent": "Code & Command Injection",
        "id": "LLM02",  # Insecure Output Handling
        "risk_score": 8.8,
        "risk_level": "HIGH",
        "patterns": [
            re.compile(r"(?i)(/bin/bash|/bin/sh|os\.system|subprocess\.Popen|eval\(|exec\()"),
            re.compile(r"(?i)(DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+.*?\s+SET|UNION\s+SELECT)")
        ]
    },
    {
        "intent": "Path Traversal / LFI",
        "id": "LLM07",  # Insecure Plugin Design
        "risk_score": 9.0,
        "risk_level": "CRITICAL",
        "patterns": [
            re.compile(r"(\.\./|\.\.\\){2,}"),
            re.compile(r"(?i)(/etc/passwd|/etc/shadow|/etc/hosts|~/.ssh|/root/)"),
            re.compile(r"(?i)(C:\\Windows\\System32|C:\\boot\.ini)")
        ]
    },
    {
        "intent": "SSRF / Internal Network Scanning",
        "id": "LLM07",
        "risk_score": 8.8,
        "risk_level": "HIGH",
        "patterns": [
            re.compile(r"(?i)(http|https|ftp)://(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)"),
            re.compile(r"(?i)169\.254\.169\.254"),
            re.compile(r"(?i)file:///")
        ]
    },
    {
        "intent": "PII & Financial Data Exposure",
        "id": "LLM06",
        "risk_score": 8.5,
        "risk_level": "HIGH",
        "patterns": [
            re.compile(r"\b(?:\d[ -]*?){13,16}\b"),  # Credit Cards
            re.compile(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b", re.I)  # Codice Fiscale
        ]
    },
    {
        "intent": "Data Exfiltration / Credentials",
        "id": "LLM06",
        "risk_score": 8.5,
        "risk_level": "HIGH",
        "patterns": [
            re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
            re.compile(r"sk-[a-zA-Z0-9]{48}"),  # OpenAI Key
            re.compile(r"(?i)(password|passwd|secret|api[_\s-]?key|token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\+]{8,}['\"]?")
        ]
    },
    {
        "intent": "Obfuscated Payload / Evasion",
        "id": "AML.T0043",
        "risk_score": 8.0,
        "risk_level": "HIGH",
        "patterns": [
            re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),  # Base64
            re.compile(r"(\\x[0-9a-fA-F]{2}){4,}")  # Hex
        ]
    }
]


def perform_static_analysis(text: str) -> Optional[dict]:
    """
    Analisi Fail-Fast tramite Threat Signatures pre-compilate.
    """
    normalized_text = re.sub(r'\s+', ' ', text).strip()

    for signature in THREAT_SIGNATURES:
        for pattern in signature["patterns"]:
            if pattern.search(normalized_text):
                return {
                    "risk_score": signature["risk_score"],
                    "risk_level": signature["risk_level"],
                    "intent": signature["intent"],
                    "id": signature["id"]
                }

    return None