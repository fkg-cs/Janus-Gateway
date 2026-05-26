import json
import traceback
from fastapi import APIRouter, HTTPException
from stix2 import Filter

# Importazione esplicita e sicura dei modelli dati
from schema.models import PayloadRequest, RiskAnalysisResponse

# Importazione dei moduli dai motori segregati
from engines.intel_engine import store, atlas_yaml_db, OWASP_PATH
from engines.waf_engine import perform_static_analysis
from engines.llm_engine import evaluate_with_llm

router = APIRouter()

@router.get("/techniques")
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
@router.get("/techniques/{stix_id}")
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
    case_studies_details = []
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

                # INIZIALIZZAZIONE SICURA (Esattamente come il tuo codice base)
                c_name = cs.get("name", "Unknown Case Study")
                c_summary = cs.get("summary", "No summary available.")
                c_desc = cs.get("description", "No detailed description available.")

                # TENTATIVO DI ARRICCHIMENTO PROTETTO
                try:
                    meta_badges = []
                    c_date = cs.get("incident-date", cs.get("incident_date", ""))
                    c_target = cs.get("target", "")
                    c_actor = cs.get("actor", "")
                    c_reporter = cs.get("reporter", "")

                    if c_date: meta_badges.append(f"**📅 Date:** {c_date}")
                    if c_target: meta_badges.append(f"**🎯 Target:** {c_target}")
                    if c_actor: meta_badges.append(f"**👤 Actor:** {c_actor}")
                    if c_reporter: meta_badges.append(f"**📢 Reporter:** {c_reporter}")

                    meta_string = " | ".join(meta_badges) + "\n\n---\n\n" if meta_badges else ""

                    # Ricerca delle procedure
                    extracted_desc = cs.get("description", "")
                    if not extracted_desc:
                        raw_steps = cs.get("procedure", cs.get("procedure-steps", []))
                        if isinstance(raw_steps, list):
                            step_strings = []
                            for i, step in enumerate(raw_steps, start=1):
                                if isinstance(step, dict) and "description" in step:
                                    # i è il numero dell'iterazione, str(step['description']) è il testo
                                    step_strings.append(f"{i}) {str(step['description']).strip()}\n")

                            if step_strings:
                                # Uniamo le stringhe con un a capo
                                extracted_desc = "**Attack Procedure:**\n\n" + "\n".join(step_strings)

                    # Se abbiamo trovato procedure o metadati, sovrascriviamo la c_desc di default
                    if extracted_desc:
                        c_desc = meta_string + extracted_desc
                    elif meta_string:
                        c_desc = meta_string + "*(Detailed procedure not available in ATLAS database)*"

                except Exception as e:
                    # Se l'arricchimento fa i capricci, ignoriamo l'errore!
                    # c_desc rimarrà "No detailed description available." e il server non crasherà.
                    print(f"Ignorato errore formattazione nel Case Study {c_name}: {e}")

                # APPEND GARANTITO (Esattamente come il tuo codice base)
                case_studies_details.append({
                    "name": c_name,
                    "summary": c_summary,
                    "description": c_desc
                })

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
        "case_studies": case_studies_details,
        "maturity_level": maturity_level
    }

@router.get("/owasp")
def get_owasp_top10():
    try:
        with open("../knowledge_base/owasp_llm_kb.json", "r", encoding="utf-8") as file:
            data = json.load(file)
            return data  # <--- SE MANCA QUESTO, IL FRONTEND RICEVE 'None'
    except Exception as e:
        return {"error": f"Errore interno del server: {str(e)}"}


@router.post("/api/v1/analyze", response_model=RiskAnalysisResponse)
async def analyze_security_payload(payload: PayloadRequest):
    try:
        combined_text = payload.user_prompt
        if payload.document_text:
            combined_text += f"\n\n[DOCUMENT CONTENT]:\n{payload.document_text}"

        # 1. WAF STATICO (Fail-Fast)
        static_result = perform_static_analysis(combined_text)
        if static_result:
            return RiskAnalysisResponse(
                risk_score=float(static_result["risk_score"]),
                risk_level=str(static_result["risk_level"]),
                detected_intent=str(static_result["intent"]),
                reasoning="Payload intercepted by security signatures (WAF Layer).",
                impact=str(static_result.get("impact", "Impact defined at WAF Layer.")),
                atlas_technique_id=static_result.get("id"),
                mitigation_action="Hard Block: Payload intercepted by attack's signature detection.",
                analysis_layer="Static Regex (WAF Layer)"
            )

        # 2. CONTROLLO METADATI (Static Penalty x indirect prompt injection)
        static_penalty = 0.0
        is_indirect = bool(payload.document_text or payload.document_metadata)
        if payload.document_metadata:
            meta_dump = str(payload.document_metadata.model_dump()).upper()
            if any(k in meta_dump for k in ["SYSTEM", "IGNORE", "INSTRUCTION", "OVERRIDE"]):
                static_penalty = 2.5

        # 3. MOTORE SEMANTICO (analisi semantica con LLM engine)
        return evaluate_with_llm(payload, combined_text, static_penalty, is_indirect)

    except Exception as e:
        error_details = traceback.format_exc()
        print(error_details)
        return RiskAnalysisResponse(
            risk_score=0.0,
            risk_level="ERROR",
            detected_intent=f"BACKEND CRASH: {str(e)}",
            reasoning="Backend system crash during analysis.",
            impact="The system encountered a fatal exception.",
            atlas_technique_id="SYS.ERR",
            mitigation_action=f"Error Traceback: {error_details[:200]}...",
            analysis_layer="System Exception"
        )