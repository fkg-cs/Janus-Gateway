import re
from typing import Optional

# ==========================================
# WAF ENGINE: SURGICAL THREAT SIGNATURES
# ==========================================
# Questa versione contiene SOLO Indicatori di Compromissione (IOC) ad alta fedeltà.
# Lascia l'analisi del linguaggio naturale e delle iniezioni logiche al motore AI.

THREAT_SIGNATURES = [
    {
        "intent": "Critical Cloud Metadata SSRF",
        "id": "LLM07",  # Insecure Plugin Design / SSRF
        "risk_score": 9.5,
        "risk_level": "CRITICAL",
        "impact": "Direct attempt to query cloud metadata endpoints to steal IAM tokens.",
        "patterns": [
            # L'IP universale per i metadati cloud (AWS/Azure/GCP). Praticamente zero falsi positivi.
            re.compile(r"(?i)169\.254\.169\.254")
        ]
    },
    {
        "intent": "Critical System File Access (LFI)",
        "id": "LLM07",
        "risk_score": 9.0,
        "risk_level": "CRITICAL",
        "impact": "Targeted access to highly restricted OS credential files.",
        "patterns": [
            # Rimosso /etc/passwd perché troppo comune in esempi didattici. Tenuti solo file letali.
            re.compile(r"(?i)(/etc/shadow|/etc/gshadow|/root/\.ssh/id_rsa|C:\\Windows\\System32\\config\\SAM)")
        ]
    },
    {
        "intent": "Hardcoded Secrets / API Keys Leakage",
        "id": "LLM06", # Sensitive Information Disclosure
        "risk_score": 9.8,
        "risk_level": "CRITICAL",
        "impact": "Leakage of highly privileged infrastructure secrets allowing potential full system takeover.",
        "patterns": [
            re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
            re.compile(r"sk-[a-zA-Z0-9]{48}") # OpenAI API Key
        ]
    },
    {
        "intent": "Heavy Obfuscated Payload / Evasion",
        "id": "AML.T0043",
        "risk_score": 7.5,
        "risk_level": "HIGH",
        "impact": "Attempt to bypass semantic filters using heavy encoding. Requires active investigation.",
        "patterns": [
            # Modificato per catturare solo stringhe Base64 molto lunghe (evita falsi positivi su piccoli ID o JWT innocui)
            re.compile(r"\b(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b"),
            # Almeno 8 byte esadecimali consecutivi
            re.compile(r"(\\x[0-9a-fA-F]{2}){8,}")
        ]
    }
]

def perform_static_analysis(text: str) -> Optional[dict]:
    """
    Analizza il testo usando firme ad altissima fedeltà (Fail-Fast).
    Se il WAF non rileva nulla di letale, passa la palla all'AI per l'analisi semantica profonda.
    """
    normalized_text = re.sub(r'\s+', ' ', text).strip()

    for signature in THREAT_SIGNATURES:
        for pattern in signature["patterns"]:
            if pattern.search(normalized_text):
                return {
                    "risk_score": signature["risk_score"],
                    "risk_level": signature["risk_level"],
                    "intent": signature["intent"],
                    "id": signature["id"],
                    "impact": signature["impact"]
                }

    return None