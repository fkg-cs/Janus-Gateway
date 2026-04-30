import json

from fastapi import FastAPI, HTTPException
from stix2 import MemoryStore, Filter
import os

app = FastAPI(title="Janus Gateway API")

# Carichiamo la base di conoscenza all'avvio
STIX_PATH = os.path.join(os.path.dirname(__file__), "../knowledge_base/mitre_atlas.json")
store = MemoryStore()
store.load_from_file(STIX_PATH)


@app.get("/techniques")
async def get_all_techniques():
    """Restituisce un elenco sintetico di tutte le tecniche ATLAS"""
    techniques = store.query([Filter("type", "=", "attack-pattern")])
    output = []
    for t in techniques:
        # Estraiamo l'ID ATLAS (es. AML.T0051)
        atlas_id = next((ext.external_id for ext in t.external_references if ext.source_name == "mitre-atlas"), "N/A")
        output.append({
            "id": atlas_id,
            "name": t.name,
            "stix_id": t.id
        })
    # Ordiniamo per ID
    return sorted(output, key=lambda x: x['id'])


@app.get("/techniques/{stix_id}")
async def get_technique_details(stix_id: str):
    technique = store.get(stix_id)
    if not technique:
        raise HTTPException(status_code=404, detail="Tecnica non trovata")

    atlas_id = next((ext.external_id for ext in technique.external_references if ext.source_name == "mitre-atlas"),
                    "N/A")

    # Formattazione delle date (giorno Mese Anno)
    created_str = technique.created.strftime("%d %B %Y") if hasattr(technique, 'created') else "N/A"
    modified_str = technique.modified.strftime("%d %B %Y") if hasattr(technique, 'modified') else "N/A"

    # Mitigazioni (dipende da come STIX ATLAS le salva, spesso in x_mitre_mitigations)
    mitigations = getattr(technique, 'x_mitre_mitigations', [])

    # Case Studies (spesso salvati come riferimenti esterni o array custom)
    # Contiamo quante external_references sono di tipo "case-study" o calcoliamo da un campo custom
    case_studies = [ref for ref in getattr(technique, 'external_references', []) if
                    ref.source_name == "mitre-atlas-case-study"]
    case_studies_count = len(case_studies)

    # Una tecnica è "Demonstrated" se ha almeno un caso di studio reale documentato
    demonstrated = "Yes" if case_studies_count > 0 else "No"

    return {
        "id": atlas_id,
        "name": technique.name,
        "description": technique.description,
        "platforms": getattr(technique, 'x_mitre_platforms', []),
        "tactics": [ref.phase_name for ref in getattr(technique, 'kill_chain_phases', [])],
        "mitigations": mitigations,
        "created": created_str,
        "modified": modified_str,
        "case_studies_count": case_studies_count,
        "demonstrated": demonstrated
    }

@app.get("/owasp")
async def get_owasp_top10():
    """Restituisce la Knowledge Base OWASP Top 10 for LLMs"""
    owasp_path = os.path.join(os.path.dirname(__file__), "../knowledge_base/owasp_llm_kb.json")
    with open(owasp_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["OWASP_LLM_TOP_10"]