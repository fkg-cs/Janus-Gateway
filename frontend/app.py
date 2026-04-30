import streamlit as st
import requests
from pathlib import Path
from PIL import Image  # <-- Nuova importazione professionale e SICURA

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

    # [IL RESTO DEL CODICE: KNOWLEDGE EXPLORER] ...
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
                details = detail_res.json()
                st.header(f"{details['id']}: {details['name']}")
                st.markdown(
                    f"**Demonstrated:** {details.get('demonstrated', 'N/A')} | **Mitigations:** {len(details.get('mitigations', [])) if details.get('mitigations') else 0}")
                st.divider()
                st.write(details.get('description', 'Nessuna descrizione disponibile.'))
        except:
            st.error("Connessione API fallita.")

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
    user_prompt = st.text_area("User Prompt", placeholder="Inserisci il prompt...", height=200)
    uploaded_file = st.file_uploader("Upload Document", type=["pdf", "txt"])
    if st.button("Esegui Security Analysis", use_container_width=True):
        if "injection" in user_prompt.lower():
            st.error("🚨 CRITICAL RISK DETECTED!")
        else:
            st.success("Analisi completata con successo.")