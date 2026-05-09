# 🛡️ Janus Gateway: Advanced LLM Security Engine# 🛡️ Janus Gateway: Advanced LLM Security Engine

[![MITRE ATLAS Aligned](https://img.shields.io/badge/MITRE%20ATLAS-Aligned-blue)](https://atlas.mitre.org/)
[![OWASP Top 10 LLM](https://img.shields.io/badge/OWASP-Top%2010%20LLM-red)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)

**Janus Gateway** is a high-performance, multi-layered security middleware designed to protect Large Language Model (LLM) applications from semantic threats, prompt injections, and adversarial attacks. 

Developed as part of a Master's Thesis at the **University of Bari "Aldo Moro"**, Janus integrates industry-standard threat taxonomies with real-time AI-driven inference to provide a robust defense-in-depth architecture.

---

## 🚀 Key Features

* **Hybrid Inspection Engine**: Combines high-fidelity static signatures (WAF Layer) with deep semantic reasoning (AI Layer).
* **Semantic Guardrails**: Detects deceptive intent even when hidden behind benign wrappers like translations, summaries, or fictional storytelling.
* **Industry Standard Alignment**: Full correlation with **MITRE ATLAS™** and **OWASP Top 10 for LLMs**.
* **Dynamic Risk Scoring**: Aggregates base AI scores with architectural modifiers (e.g., OWASP LLM01 Indirect Injection) and static penalties for hardened security.
* **Fail-Safe Architecture**: Implements preventive blocks during system anomalies to ensure zero-leakage security.

---

## 🏗️ Architecture

Janus operates as a **Dual-Layer Proxy**:

1.  **Layer 1: Static WAF (Surgical Regex)**
    * Intercepts known IoCs (Indicators of Compromise).
    * Blocks hardcoded secrets, cloud metadata SSRF attempts, and critical LFI paths.
    * Zero-latency "Fail-Fast" mechanism.

2.  **Layer 2: Semantic AI Engine (LLM-in-the-Loop)**
    * Powered by models like **Llama 3.1 8B** via **Groq LPU** (Low Latency) or **Ollama** (Local execution).
    * Analyzes intent, reasoning, and deceptive roleplay (DAN, Jailbreaks).
    * Maps threats to specific Technique IDs (e.g., AML.T0051).

---

## 📊 Performance & Validation

Janus is rigorously tested against an adversarial dataset generated through AI Red Teaming. Our latest evaluation highlights:

* **93% Recall on CRITICAL threats**: Ensuring that host-level attacks (RCE, LFI, System Prompt leakage) are blocked with maximum reliability.
* **Context-Aware Baseline**: Minimizes false positives through a "Theoretical Loophole" protocol that safely processes educational queries and academic theory without triggering alert fatigue.

> [!TIP]
> View our latest **Confusion Matrix** in the `/docs/evaluation` folder to see the systematic alignment across all risk levels.

---

## 🛠️ Getting Started

### Prerequisites
* Python 3.10+
* Groq API Key or a local Ollama instance

### Installation
```bash
git clone [https://github.com/YourUsername/JanusGateway.git](https://github.com/YourUsername/JanusGateway.git)
cd JanusGateway
pip install -r requirements.txt
Run the BackendBashcd backend
uvicorn main:app --reload
🛡️ Security MappingThreat ClassTarget ScoreAlignmentExample IntentCRITICAL9.0 - 10.0MITRE AML.T0051RCE, System Prompt Leakage, LFIHIGH7.0 - 8.9OWASP LLM01Jailbreaks (DAN), Phishing, PII ExtractionMEDIUM4.0 - 6.9OWASP LLM02Generic Exploit Probing, Payload TestingLOW2.0 - 3.9-Fictional Hacking Stories, Dark HumorBENIGN0.0 - 1.9-Academic Theory, Cybersecurity Definitions📜 AcknowledgmentsSpecial thanks to the Università degli Studi di Bari "Aldo Moro" and the MITRE ATLAS community for providing the frameworks that made this research possible.Developed by Francesco Guarini.

[![MITRE ATLAS Aligned](https://img.shields.io/badge/MITRE%20ATLAS-Aligned-blue)](https://atlas.mitre.org/)
[![OWASP Top 10 LLM](https://img.shields.io/badge/OWASP-Top%2010%20LLM-red)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)

**Janus Gateway** is a high-performance, multi-layered security middleware designed to protect Large Language Model (LLM) applications from semantic threats, prompt injections, and adversarial attacks. 

Developed as part of a Master's Thesis at the **University of Bari "Aldo Moro"**, Janus integrates industry-standard threat taxonomies with real-time AI-driven inference to provide a robust defense-in-depth architecture.

---

## 🚀 Key Features

* **Hybrid Inspection Engine**: Combines high-fidelity static signatures (WAF Layer) with deep semantic reasoning (AI Layer).
* **Semantic Guardrails**: Detects deceptive intent even when hidden behind benign wrappers like translations, summaries, or fictional storytelling.
* **Industry Standard Alignment**: Full correlation with **MITRE ATLAS™** and **OWASP Top 10 for LLMs**.
* **Dynamic Risk Scoring**: Aggregates base AI scores with architectural modifiers (e.g., OWASP LLM01 Indirect Injection) and static penalties for hardened security.
* **Fail-Safe Architecture**: Implements preventive blocks during system anomalies to ensure zero-leakage security.

---

## 🏗️ Architecture

Janus operates as a **Dual-Layer Proxy**:

1.  **Layer 1: Static WAF (Surgical Regex)**
    * Intercepts known IoCs (Indicators of Compromise).
    * Blocks hardcoded secrets, cloud metadata SSRF attempts, and critical LFI paths.
    * Zero-latency "Fail-Fast" mechanism.

2.  **Layer 2: Semantic AI Engine (LLM-in-the-Loop)**
    * Powered by models like **Llama 3.1 8B** via **Groq LPU** (Low Latency) or **Ollama** (Local execution).
    * Analyzes intent, reasoning, and deceptive roleplay (DAN, Jailbreaks).
    * Maps threats to specific Technique IDs (e.g., AML.T0051).

---

## 📊 Performance & Validation

Janus is rigorously tested against an adversarial dataset generated through AI Red Teaming. Our latest evaluation highlights:

* **93% Recall on CRITICAL threats**: Ensuring that host-level attacks (RCE, LFI, System Prompt leakage) are blocked with maximum reliability.
* **Context-Aware Baseline**: Minimizes false positives through a "Theoretical Loophole" protocol that safely processes educational queries and academic theory without triggering alert fatigue.

> [!TIP]
> View our latest **Confusion Matrix** in the `/docs/evaluation` folder to see the systematic alignment across all risk levels.

