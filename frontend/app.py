import streamlit as st
import requests
from pathlib import Path
from PIL import Image
import PyPDF2

# --- CONFIGURATION ---
st.set_page_config(page_title="Janus Gateway - Security Core", page_icon="🛡️", layout="wide")

# URL del backend (FastAPI)
API_URL = "http://127.0.0.1:8000"

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    /* Spaziatura generale */
    .block-container {
        padding-top: 2rem;
    }

    /* Stile della Navigation Bar centrale */
    div[role="radiogroup"].stRadio > div {
        display: flex;
        flex-direction: row;
        justify-content: center;
        background-color: #F4F6F9;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid #E2E8F0;
        gap: 30px;
    }

    /* Stile delle metriche (Cards) */
    [data-testid="stMetric"] {
        background-color: #ffffff;
        border: 1px solid #e0e4e8;
        border-radius: 8px;
        padding: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.02);
    }

    /* Box Descrizione custom */
    .description-box {
        border: 1px solid #e0e4e8;
        border-radius: 8px;
        padding: 20px;
        background-color: #ffffff;
        margin-top: 1rem;
        margin-bottom: 1rem;
    }

    /* Link GitHub in alto a destra */
    .github-wrapper {
        display: flex;
        justify-content: flex-end;
        align-items: center;
        height: 100%;
        margin-top: 15px;
    }
    .github-link {
        display: flex;
        align-items: center;
        gap: 8px;
        text-decoration: none;
        color: #24292e;
        font-weight: 600;
        font-size: 0.95rem;
        transition: color 0.2s;
    }
    .github-link:hover {
        color: #0366d6;
    }
    </style>
""", unsafe_allow_html=True)

# --- HEADER & LOGO ---
col_logo, col_title, col_link = st.columns([1, 8, 2])

with col_logo:
    logo_path = Path(__file__).parent / "assets" / "logo.png"
    try:
        if logo_path.exists():
            img = Image.open(logo_path)
            st.image(img, width=80)
        else:
            st.write("🛡️")
    except Exception:
        st.write("🛡️")

with col_title:
    st.title("Janus Gateway")
    st.caption("Advanced Semantic Risk Engine & Threat Intelligence for LLM")

with col_link:
    github_url = "https://github.com/fkg-cs/Janus-Gateway"

    # SVG Ufficiale di GitHub + Link
    st.markdown(f"""
        <div class="github-wrapper">
            <a href="{github_url}" target="_blank" class="github-link">
                <svg height="22" width="22" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"></path>
                </svg>
                View on GitHub
            </a>
        </div>
    """, unsafe_allow_html=True)

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
        st.write("")  # Spazio extra
        try:
            response = requests.get(f"{API_URL}/techniques")
            techniques = response.json()
            tech_display = [f"{t['id']} - {t['name']}" for t in techniques]

            # Layout asimmetrico come in figura (Lista a sinistra, Dettagli a destra)
            col_list, col_details = st.columns([1, 2.5])

            with col_list:
                # Barra di ricerca visiva
                search_term = st.text_input("🔍 Cerca tecniche...", "")
                filtered_techs = [t for t in tech_display if search_term.lower() in t.lower()]

                # Contenitore con barra di scorrimento integrata
                with st.container(height=500):
                    if filtered_techs:
                        selected_tech_name = st.radio("Lista", filtered_techs, label_visibility="collapsed")
                        selected_index = tech_display.index(selected_tech_name)
                        selected_stix_id = techniques[selected_index]['stix_id']
                    else:
                        st.warning("Nessuna tecnica trovata.")
                        selected_stix_id = None

            with col_details:
                if selected_stix_id:
                    detail_res = requests.get(f"{API_URL}/techniques/{selected_stix_id}")
                    tech = detail_res.json()

                    st.header(f"{tech['id']}: {tech['name']}")

                    # --- DASHBOARD METADATI (Cards con icone) ---
                    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                    with col_m1:
                        st.metric("📈 Maturity Level", tech.get('maturity_level', 'N/A'))
                    with col_m2:
                        st.metric("📄 Case Studies", tech.get('case_studies_count', 0))
                    with col_m3:
                        st.metric("🛡️ Mitigations", tech.get('mitigations_count', 0))
                    with col_m4:
                        st.metric("💻 Platforms", len(tech.get('platforms', [])))

                    st.divider()

                    # Informazioni Temporali e Tattiche tradotte
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.markdown(f"**📅 Created** {tech.get('created', 'N/A')}")
                    with c2:
                        st.markdown(f"**🕒 Last modified:** {tech.get('modified', 'N/A')}")
                    with c3:
                        tactics = tech.get('tactics', [])
                        st.markdown(f"**🎯 Tattic:** {', '.join(tactics) if tactics else 'N/A'}")

                    # Box Descrizione con stile
                    desc_text = tech.get('description', 'No description avalaible.')
                    st.markdown(f"""
                        <div class="description-box">
                            <h4 style="margin-top:0px; margin-bottom: 10px; color: #1f2937;">Description</h4>
                            <p style="color: #4b5563; line-height: 1.6;">{desc_text}</p>
                        </div>
                    """, unsafe_allow_html=True)

                    if tech.get('mitigations'):
                        st.subheader("🛡️ Mitigations")
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

        uploaded_file = st.file_uploader("Upload Document (PDF, TXT, CSV, MD)", type=["pdf", "txt", "csv", "md"])

        if st.button("Esegui Security Analysis", use_container_width=True):
            if not user_prompt and not uploaded_file:
                st.warning("Fornire almeno un prompt di testo o un documento per l'analisi.")
            else:
                with st.spinner("Analisi Statica e Inferenza Semantica in corso..."):

                    document_text = ""
                    document_metadata = None

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
                                document_text = uploaded_file.getvalue().decode("utf-8", errors="ignore")
                        except Exception as e:
                            st.error(f"Errore durante l'estrazione del testo: {e}")

                    payload = {
                        "user_prompt": user_prompt,
                        "document_text": document_text if document_text else None,
                        "document_metadata": document_metadata
                    }

                    try:
                        res = requests.post(f"{API_URL}/api/v1/analyze", json=payload)
                        res.raise_for_status()
                        result = res.json()

                        score = result['risk_score']

                        st.divider()

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
                            st.info(f"**Mitigazioni suggerite:** {result['mitigation_action']}")

                    except Exception as e:
                        st.error(f"Errore di comunicazione con il Backend: {e}")