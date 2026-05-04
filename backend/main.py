import os
import json
import requests
import yaml
import traceback
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from stix2 import MemoryStore, Filter

from utils.static_analysis import perform_static_analysis

# ==========================================
# 1. INIZIALIZZAZIONE APP E THREAT INTEL AUTOMATION
# ==========================================
app = FastAPI(title="Janus Gateway API")

STIX_PATH = os.path.join(os.path.dirname(__file__), "../knowledge_base/mitre_atlas.json")
YAML_PATH = os.path.join(os.path.dirname(__file__), "../knowledge_base/mitre_atlas.yaml")

ATLAS_STIX_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"
ATLAS_YAML_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"


def update_atlas_knowledge_base():
    """Scarica sia la struttura STIX sia i dati crudi YAML (Source of Truth) all'avvio."""
    print("⏳ Controllo aggiornamenti MITRE ATLAS in corso...")

    # 1. Download STIX JSON (Struttura) + stampe a video per server
    try:
        res_stix = requests.get(ATLAS_STIX_URL, timeout=10)
        res_stix.raise_for_status()
        with open(STIX_PATH, "w", encoding="utf-8") as f:
            f.write(res_stix.text)
        print("✅ Struttura STIX aggiornata con successo.")
    except Exception as e:
        print(f"⚠️ Impossibile scaricare STIX. Uso cache locale. Errore: {e}")

    # 2. Download YAML (Dati Empirici e Case Studies)
    try:
        res_yaml = requests.get(ATLAS_YAML_URL, timeout=10)
        res_yaml.raise_for_status()
        with open(YAML_PATH, "w", encoding="utf-8") as f:
            f.write(res_yaml.text)
        print("✅ Database YAML (Source of Truth) aggiornato con successo.")
    except Exception as e:
        print(f"⚠️ Impossibile scaricare YAML. Uso cache locale. Errore: {e}")


# Esecuzione scaricamento automatico
update_atlas_knowledge_base()

# Caricamento STIX in memoria (Grafo Relazionale)
store = MemoryStore()
if os.path.exists(STIX_PATH):
    store.load_from_file(STIX_PATH)

# Caricamento YAML in memoria (Dizionario Python Veloce) + stampe a video per server
atlas_yaml_db = {}
if os.path.exists(YAML_PATH):
    try:
        with open(YAML_PATH, "r", encoding="utf-8") as f:
            atlas_yaml_db = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Errore nel caricamento del file YAML: {e}")


# ==========================================
# 2. MODELLI DATI (PYDANTIC)
# ==========================================
class DocumentMetadata(BaseModel):
    filename: str
    file_type: str
    file_size: int


class PayloadRequest(BaseModel):
    user_prompt: str
    document_text: Optional[str] = None
    document_metadata: Optional[DocumentMetadata] = None


class RiskAnalysisResponse(BaseModel):
    risk_score: float
    risk_level: str
    detected_intent: str
    atlas_technique_id: Optional[str] = None
    impact: str
    mitigation_action: str
    analysis_layer: Optional[str] = "N/A"


# ==========================================
# 3. ROTTE API: KNOWLEDGE BASE EXPLORER
# ==========================================
@app.get("/techniques")
async def get_all_techniques():
    techniques = store.query([Filter("type", "=", "attack-pattern")])
    output = []
    for t in techniques:
        # Se la tecnica non ha la voce 'external_references', restituisce una lista vuota [] invece di crashare.
        refs = getattr(t, 'external_references', [])
        atlas_id = next((ext.external_id for ext in refs if getattr(ext, 'source_name', '') == "mitre-atlas"), "N/A")

        output.append({
            "id": atlas_id,
            "name": t.name,
            "stix_id": t.id
        })
    return sorted(output, key=lambda x: x['id'])


@app.get("/techniques/{stix_id}")
async def get_technique_details(stix_id: str):
    technique = store.get(stix_id)
    if not technique:
        raise HTTPException(status_code=404, detail="Tecnica non trovata")

    # Estrazione sicura dell'ID ATLAS (es. AML.T0051)
    refs = getattr(technique, 'external_references', [])
    atlas_id = next((ext.external_id for ext in refs if getattr(ext, 'source_name', '') == "mitre-atlas"), "N/A")

    created_str = technique.created.strftime("%d %B %Y") if hasattr(technique, 'created') else "N/A"
    modified_str = technique.modified.strftime("%d %B %Y") if hasattr(technique, 'modified') else "N/A"

    mitigations = []
    case_studies_count = 0
    maturity_level = "Theoretical"

    # ---  RICERCA NEL DATABASE YAML IN RAM ---
    if atlas_id != "N/A" and atlas_yaml_db:

        # 1. ESTRAZIONE MITIGAZIONI (Dal YAML per testo completo)
        techniques_list = atlas_yaml_db.get("techniques", [])
        for t_yaml in techniques_list:
            if t_yaml.get("id") == atlas_id:
                yaml_mits = t_yaml.get("mitigations", [])
                for ym in yaml_mits:
                    if isinstance(ym, dict):
                        # Estraiamo ID e descrizione specifica per questa tecnica
                        m_id = ym.get("mitigation", "")
                        m_desc = ym.get("description", "")

                        # Incrociamo i dati per trovare il NOME UFFICIALE della mitigazione
                        m_name = m_id
                        for global_m in atlas_yaml_db.get("mitigations", []):
                            if global_m.get("id") == m_id:
                                m_name = f"{m_id} - {global_m.get('name', 'Mitigazione')}"
                                break

                        # Formattazione elegante con Markdown
                        mitigations.append(f"**{m_name}**: {m_desc}")
                    elif isinstance(ym, str):
                        mitigations.append(ym)
                break  # Tecnica elaborata, esci dal ciclo

        # 2. ESTRAZIONE CASE STUDIES (Risoluzione problema STIX via YAML)
        case_studies_list = atlas_yaml_db.get("case-studies", atlas_yaml_db.get("case_studies", []))
        for cs in case_studies_list:
            cs_string = json.dumps(cs, default=str)
            if atlas_id in cs_string:
                case_studies_count += 1

        if case_studies_count > 0:
            maturity_level = "Demonstrated"

    # --- FALLBACK: GRAFO STIX (Se il YAML fosse irraggiungibile) ---
    if not mitigations:
        mitigation_rels = store.query([
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "mitigates"),
            Filter("target_ref", "=", technique.id)
        ])
        for rel in mitigation_rels:
            coa = store.get(rel.source_ref)
            if coa and coa.type == "course-of-action":
                desc = getattr(coa, 'description', '')
                mitigations.append(f"**{coa.name}**: {desc}")

    # Fallback legacy property
    if not mitigations:
        old_mits = getattr(technique, 'x_mitre_mitigations', [])
        for m in old_mits:
            mitigations.append(str(m))

    mitigations_count = len(mitigations)

    return {
        "id": atlas_id,
        "name": technique.name,
        "description": getattr(technique, 'description', ''),
        "platforms": getattr(technique, 'x_mitre_platforms', []),
        "tactics": [ref.phase_name for ref in getattr(technique, 'kill_chain_phases', [])],
        "mitigations": mitigations,
        "mitigations_count": mitigations_count,
        "created": created_str,
        "modified": modified_str,
        "case_studies_count": case_studies_count,
        "maturity_level": maturity_level
    }


@app.get("/owasp")
def get_owasp_top10():
    try:
        with open("../knowledge_base/owasp_llm_kb.json", "r", encoding="utf-8") as file:
            data = json.load(file)
            return data  # <--- SE MANCA QUESTO, IL FRONTEND RICEVE 'None'
    except Exception as e:
        return {"error": f"Errore interno del server: {str(e)}"}


# ==========================================
# 5. ROTTE API: DYNAMIC RISK ENGINE (TEST MODE DEBUG)
# ==========================================
@app.post("/api/v1/analyze", response_model=RiskAnalysisResponse)
async def analyze_security_payload(payload: PayloadRequest):
    try:
        combined_text = payload.user_prompt
        if payload.document_text:
            combined_text += f"\n\n[DOCUMENT CONTENT]:\n{payload.document_text}"

        # LAYER 1: WAF STATICO
        static_result = perform_static_analysis(combined_text)

        if static_result:
            return RiskAnalysisResponse(
                risk_score=float(static_result["risk_score"]),
                risk_level=str(static_result["risk_level"]),
                detected_intent=str(static_result["intent"]),
                impact=str(static_result.get("impact", "Impact not predicted by WAF")),  # Assicurato
                atlas_technique_id=static_result.get("id"),
                mitigation_action="Hard Block: Payload intercepted by Gateway Regex.",
                analysis_layer="Static Regex (WAF Layer)"
            )

        # ==========================================
        # LAYER 2: OLLAMA (MESSO IN PAUSA)
        # ==========================================
        return RiskAnalysisResponse(
            risk_score=0.0,
            risk_level="LOW",
            detected_intent="Clean Input: No WAF signature detected. (Ollama Bypassed)",
            impact="No malicious impact expected. The payload passed static analysis.",
            atlas_technique_id=None,
            mitigation_action="No action required. Safe to forward to LLM.",
            analysis_layer="Static Regex (WAF Layer Only)"
        )

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(error_details)

        return RiskAnalysisResponse(
            risk_score=0.0,
            risk_level="CRITICAL",
            detected_intent=f"BACKEND CRASH: {str(e)}",
            impact="The system encountered a fatal exception during analysis.",
            atlas_technique_id="SYS.ERR",
            mitigation_action=f"Error Traceback: {error_details[:200]}...",
            analysis_layer="System Exception"
        )
