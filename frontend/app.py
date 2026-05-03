import streamlit as st
import requests
from pathlib import Path
from PIL import Image
import PyPDF2  # <-- Aggiunto per il parsing dei documenti

# --- CONFIGURATION ---
st.set_page_config(page_title="Janus Gateway - Security Core", page_icon="🛡️", layout="wide")

# URL del backend (FastAPI)
API_URL = "http://127.0.0.1:8000"

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    .block-container {
        padding-top: 2rem;
    }
    div[role="radiogroup"] {
        display: flex;
        flex-direction: row;
        justify-content: center;
        background-color: #F4F6F9;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid #E2E8F0;
        gap: 30px;
    }
    div[role="radiogroup"] label {
        cursor: pointer;
        font-weight: 500;
        color: #004B87 !important;
    }
    </style>
""", unsafe_allow_html=True)

# --- HEADER & LOGO ---
col_logo, col_title = st.columns([1, 10])

with col_logo:
    # Percorso assoluto e sicuro tramite pathlib
    logo_path = Path(__file__).parent / "assets" / "logo.png"

    try:
        # Se il file esiste, lo apriamo via PIL
        if logo_path.exists():
            img = Image.open(logo_path)  # <-- LETTURA SICURA DEL CONTENUTO BINARIO
            st.image(img, width=80)
        else:
            st.write("🛡️")  # Placeholder se il file manca
    except Exception:
        # Se c'è un errore imprevisto, mostra uno scudo
        st.write("🛡️")

with col_title:
    st.title("Janus Gateway")
    st.caption("Advanced Semantic Risk Engine & Threat Intelligence")

st.write("---")

# --- TOP NAVIGATION BAR ---
page = st.radio(
    "Navigation",
    ["Basi di Conoscenza", "Dynamic Risk Engine"],
    horizontal=True,
    label_visibility="collapsed"
)

# --- PAGE 1: BASI DI CONOSCENZA ---
if page == "Basi di Conoscenza":
    tab1, tab2 = st.tabs(["MITRE ATLAS™ Explorer", "OWASP LLM Top 10"])

    with tab1:
        st.subheader("Adversarial Threat Landscape for AI Systems")
        try:
            response = requests.get(f"{API_URL}/techniques")
            techniques = response.json()
            col_list, col_details = st.columns([1, 2])

            with col_list:
                tech_display = [f"{t['id']} - {t['name']}" for t in techniques]
                selected_tech_name = st.selectbox("Seleziona una tecnica:", tech_display)
                selected_index = tech_display.index(selected_tech_name)
                selected_stix_id = techniques[selected_index]['stix_id']

            with col_details:
                detail_res = requests.get(f"{API_URL}/techniques/{selected_stix_id}")
                tech = detail_res.json()

                st.header(f"{tech['id']}: {tech['name']}")

                # --- DASHBOARD METADATI INTEGRATA ---
                col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                with col_m1:
                    # Cambiato da Demonstrated a Maturity Level
                    st.metric("Maturity Level", tech.get('maturity_level', 'N/A'))
                with col_m2:
                    st.metric("Case Studies", tech.get('case_studies_count', 0))
                with col_m3:
                    st.metric("Mitigations", tech.get('mitigations_count', 0))
                with col_m4:
                    st.metric("Platforms", len(tech.get('platforms', [])))

                st.divider()

                # Informazioni Temporali e Tattiche
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**📅 Created:** {tech.get('created', 'N/A')}")
                    st.markdown(f"**🔄 Last Modified:** {tech.get('modified', 'N/A')}")
                with c2:
                    tactics = tech.get('tactics', [])
                    st.markdown(f"**🎯 Tactics:** {', '.join(tactics) if tactics else 'N/A'}")

                st.subheader("Description")
                st.write(tech.get('description', 'No description avilable.'))

                if tech.get('mitigations'):
                    st.subheader("🛡Mitigations")
                    for m in tech['mitigations']:
                        st.info(m)

        except Exception as e:
            st.error(f"Connessione API fallita o errore nel caricamento: {e}")

    with tab2:
        st.subheader("Top 10 Critical Vulnerabilities for LLM Applications")
        try:
            owasp_res = requests.get(f"{API_URL}/owasp")
            for item in owasp_res.json():
                with st.expander(f"{item['id']} - {item['name']}"):
                    st.write(item['description'])
                    st.markdown(f"**Impact:** :blue[{item['impact']}]")
        except:
            st.error("Dati OWASP non disponibili.")

# --- PAGE 2: RISK ENGINE ---
elif page == "Dynamic Risk Engine":
    st.subheader("Dynamic Semantic Analysis")
    st.markdown("Acquisizione e ispezione multi-livello (WAF + AI Locale).")

    with st.container():
        user_prompt = st.text_area("User Prompt", placeholder="Inserisci l'interazione da analizzare...", height=150)

        # Accettiamo più formati per mettere alla prova il parsing
        uploaded_file = st.file_uploader("Upload Document (PDF, TXT, CSV, MD)", type=["pdf", "txt", "csv", "md"])

        if st.button("Esegui Security Analysis", use_container_width=True):
            if not user_prompt and not uploaded_file:
                st.warning("Fornire almeno un prompt di testo o un documento per l'analisi.")
            else:
                with st.spinner("Analisi Statica e Inferenza Semantica in corso..."):

                    document_text = ""
                    document_metadata = None

                    # 1. Estrazione Metadati e Testo Grezzo
                    if uploaded_file is not None:
                        document_metadata = {
                            "filename": uploaded_file.name,
                            "file_type": uploaded_file.type,
                            "file_size": uploaded_file.size
                        }
                        try:
                            if uploaded_file.name.endswith(".pdf"):
                                reader = PyPDF2.PdfReader(uploaded_file)
                                for page in reader.pages:
                                    extracted = page.extract_text()
                                    if extracted:
                                        document_text += extracted + "\n"
                            else:
                                # Parsing generico per file testuali (TXT, CSV, MD)
                                document_text = uploaded_file.getvalue().decode("utf-8", errors="ignore")
                        except Exception as e:
                            st.error(f"Errore durante l'estrazione del testo: {e}")

                    # 2. Orchestrazione: Invio Payload al Backend
                    payload = {
                        "user_prompt": user_prompt,
                        "document_text": document_text if document_text else None,
                        "document_metadata": document_metadata
                    }

                    try:
                        res = requests.post(f"{API_URL}/api/v1/analyze", json=payload)
                        res.raise_for_status()
                        result = res.json()

                        # 3. Presentazione Output e Metriche
                        score = result['risk_score']

                        st.divider()

                        # Mostra chi ha fatto l'analisi
                        st.caption(f"🛡️ **Motore di ispezione intervenuto:** `{result['analysis_layer']}`")

                        if score >= 8.0:
                            st.error(f"🚨 CRITICAL RISK - Score: {score}/10")
                        elif score >= 5.0:
                            st.warning(f"⚠️ HIGH RISK - Score: {score}/10")
                        else:
                            st.success(f"✅ SECURE - Score: {score}/10")

                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(f"**Intento Rilevato:** {result['detected_intent']}")
                            if result.get('atlas_technique_id'):
                                st.markdown(f"**Tassonomia (ATLAS/OWASP):** `{result['atlas_technique_id']}`")
                        with col2:
                            st.info(f"**Azione Intrapresa:** {result['mitigation_action']}")

                    except Exception as e:
                        st.error(f"Errore di comunicazione con il Backend: {e}")