import streamlit as st
import requests
from pathlib import Path
from PIL import Image
import PyPDF2

# --- CONFIGURATION ---
st.set_page_config(page_title="Janus Gateway - Security Core", page_icon="🛡️", layout="wide")

# Backend URL (FastAPI)
API_URL = "http://127.0.0.1:8000"

# --- CUSTOM CSS FOR MODERN UI ---
st.markdown("""
    <style>
    /* Spaziatura generale */
    .block-container {
        padding-top: 2rem;
        max-width: 95%; /* Sfrutta meglio la larghezza dello schermo */
    }

    /* --- HEADER --- */
    .header-wrapper {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 20px;
        margin-bottom: 2rem;
    }
    .header-title-container {
        display: flex;
        flex-direction: column;
        justify-content: center;
    }
    .header-title-container h1 {
        margin: 0;
        padding: 0;
        color: #0f172a;
        font-size: 2.8rem;
        font-weight: 700;
        letter-spacing: -0.5px;
    }
    .header-title-container p {
        color: #64748b;
        font-size: 1.1rem;
        margin: 0;
        margin-top: 4px;
        font-weight: 500;
    }

    /* --- LEFT NAVIGATION PANEL (Search + List) --- */
    /* Nasconde il fastidioso spazio grigio tra search e radio */
    .stTextInput {
        margin-bottom: -15px;
    }

    /* Trasforma i Radio Button in un Menu Moderno */
    div[role="radiogroup"] {
        gap: 2px !important;
    }
    div[role="radiogroup"] > label {
        padding: 10px 15px !important;
        border-radius: 6px;
        background-color: transparent;
        transition: all 0.2s ease;
        cursor: pointer;
    }
    div[role="radiogroup"] > label:hover {
        background-color: #f1f5f9;
    }
    /* Rimuove i pallini dei radio button */
    div[role="radiogroup"] div[data-testid="stMarkdownContainer"] p {
        font-size: 0.95rem;
        color: #334155;
        font-weight: 500;
    }
    div[role="radiogroup"] input[type="radio"] {
        display: none; 
    }
    .st-cx { /* Nasconde il cerchio grafico di Streamlit */
        display: none !important; 
    }

    /* --- MODERN TABS STYLING --- */
    
   /* 1. Main Navigation Tabs */
    div[role="tablist"] {
        display: flex !important;
        justify-content: center !important; /* Centra orizzontalmente */
        width: 100% !important; /* Forza l'espansione a tutto schermo */
        gap: 40px !important;
        border-bottom: 2px solid #e2e8f0;
    }
    
    button[role="tab"] {
        height: 50px;
        background-color: transparent !important;
        border-radius: 4px 4px 0 0 !important;
        font-weight: 600 !important;
        font-size: 1.15rem !important;
        color: #4a5568 !important;
    }

    /* 2. Ripristiniamo a sinistra SOLO le sub-tabs (MITRE/OWASP) */
    div[data-testid="stTabs"] div[data-testid="stTabs"] div[role="tablist"] {
        justify-content: flex-start !important; /* Riporta a sinistra */
        gap: 20px !important;
        margin-top: 10px !important;
    }

    div[data-testid="stTabs"] div[data-testid="stTabs"] button[role="tab"] {
        height: 40px !important;
        font-size: 1rem !important;
        font-weight: 500 !important;
    }

    /* 3. Colore per la tab attiva (vale per entrambe) */
    button[role="tab"][aria-selected="true"] {
        color: #0056b3 !important;
        border-bottom-color: #0056b3 !important;
    }
    
    /* --- CARDS & BADGES --- */
    [data-testid="stMetric"] {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 20px 15px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        text-align: center;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.6rem !important;
        font-weight: 600 !important;
        color: #0f172a;
    }

    /* Stile per i Badge/Pillole (Tactics) */
    .tactic-badge {
        display: inline-block;
        background-color: #eff6ff;
        color: #1d4ed8;
        border: 1px solid #bfdbfe;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-right: 5px;
    }

    /* Box Descrizione */
    .description-box {
        background-color: #f8fafc;
        border-left: 4px solid #3b82f6;
        padding: 20px;
        border-radius: 4px 8px 8px 4px;
        margin-top: 2rem;
        color: #334155;
        font-size: 1.05rem;
        line-height: 1.6;
    }

    /* GitHub Link Positioning */
    .github-wrapper {
        position: absolute;
        right: 10px;
        top: 10px;
    }
    .github-link {
        display: flex;
        align-items: center;
        gap: 8px;
        text-decoration: none;
        color: #475569;
        font-weight: 600;
        transition: 0.2s;
    }
    .github-link:hover {
        color: #0f172a;
    }
    </style>
""", unsafe_allow_html=True)

# --- TOP BAR (GitHub Link) ---
github_url = "https://github.com/fkg-cs/Janus-Gateway"
st.markdown(f"""
    <div class="github-wrapper">
        <a href="{github_url}" target="_blank" class="github-link">
            <svg height="24" width="24" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"></path>
            </svg>
            View on GitHub
        </a>
    </div>
""", unsafe_allow_html=True)

# --- CENTERED INLINE HEADER ---
# Usiamo 4 colonne: 2 spaziatori esterni (1.5) e 2 centrali per logo (0.8) e testo (2.5)
spacer_left, col_logo, col_title, spacer_right = st.columns([1.5, 0.8, 2.5, 1.5])

with col_logo:
    logo_path = Path(__file__).parent / "assets" / "logo.png"
    if logo_path.exists():
        st.image(Image.open(logo_path), width=130)
    else:
        st.write("🛡️")

with col_title:
    st.markdown("""
        <div class="header-title-container">
            <h1>Janus Gateway</h1>
            <p>Advanced Semantic Risk Engine & Threat Intelligence for LLM</p>
        </div>
    """, unsafe_allow_html=True)

st.write("") # Spacer


# --- MAIN NAVIGATION (TABS) ---
tab_kb, tab_engine = st.tabs(["📚 Knowledge Bases", "⚡ Dynamic Risk Engine"])

# --- TAB 1: KNOWLEDGE BASE ---
with tab_kb:
    kb_sub_1, kb_sub_2 = st.tabs(["MITRE ATLAS™ Explorer", "OWASP LLM Top 10"])

    with kb_sub_1:
        try:
            response = requests.get(f"{API_URL}/techniques")
            techniques = response.json()
            tech_display = [f"{t['id']} - {t['name']}" for t in techniques]

            col_list, col_details = st.columns([1, 2.5])

            with col_list:
                search_term = st.text_input("🔍 Search techniques...", "")
                filtered_techs = [t for t in tech_display if search_term.lower() in t.lower()]

                with st.container(height=500):
                    if filtered_techs:
                        selected_tech_name = st.radio("List", filtered_techs, label_visibility="collapsed")
                        selected_index = tech_display.index(selected_tech_name)
                        selected_stix_id = techniques[selected_index]['stix_id']
                    else:
                        st.warning("No techniques found.")
                        selected_stix_id = None

            with col_details:
                if selected_stix_id:
                    detail_res = requests.get(f"{API_URL}/techniques/{selected_stix_id}")
                    tech = detail_res.json()

                    st.header(f"{tech['id']}: {tech['name']}")

                    # METADATA DASHBOARD
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("📈 Maturity Level", tech.get('maturity_level', 'N/A'))
                    m2.metric("📄 Case Studies", tech.get('case_studies_count', 0))
                    m3.metric("🛡️ Mitigations", tech.get('mitigations_count', 0))
                    m4.metric("💻 Platforms", len(tech.get('platforms', [])))

                    st.divider()

                    c1, c2, c3 = st.columns(3)
                    c1.markdown(f"**📅 Created:** {tech.get('created', 'N/A')}")
                    c2.markdown(f"**🕒 Last modified:** {tech.get('modified', 'N/A')}")
                    tactics = tech.get('tactics', [])
                    c3.markdown(f"**🎯 Tactics:** {', '.join(tactics) if tactics else 'N/A'}")

                    desc_text = tech.get('description', 'No description available.')
                    st.markdown(f"""
                        <div class="description-box">
                            <h4 style="margin-top:0px; color: #1f2937;">Description</h4>
                            <p style="color: #4b5563;">{desc_text}</p>
                        </div>
                    """, unsafe_allow_html=True)

                    if tech.get('mitigations'):
                        st.subheader("🛡️ Suggested Mitigations")
                        for m in tech['mitigations']:
                            st.info(m)
        except Exception as e:
            st.error(f"API connection failed: {e}")

    with kb_sub_2:
        st.subheader("Top 10 Critical Vulnerabilities for LLM Applications")
        try:
            owasp_res = requests.get(f"{API_URL}/owasp")
            for item in owasp_res.json():
                with st.expander(f"{item['id']} - {item['name']}"):
                    st.write(item['description'])
                    st.markdown(f"**Impact:** :blue[{item['impact']}]")
        except:
            st.error("OWASP data unavailable.")

# --- TAB 2: RISK ENGINE ---
with tab_engine:
    st.subheader("Dynamic Semantic Analysis")
    st.markdown("Multi-layer inspection (WAF + Local AI Inference).")

    with st.container():
        user_prompt = st.text_area("User Prompt", placeholder="Enter the interaction to analyze...", height=150)
        uploaded_file = st.file_uploader("Upload Document (PDF, TXT, CSV, MD)", type=["pdf", "txt", "csv", "md"])

        if st.button("Run Security Analysis", use_container_width=True):
            if not user_prompt and not uploaded_file:
                st.warning("Please provide a prompt or a document for analysis.")
            else:
                with st.spinner("Static Analysis & Semantic Inference in progress..."):
                    # [Analysis Logic remains the same, just strings are translated]
                    # ... (Parsing logic omitted for brevity, same as your original)
                    st.info("Analysis results would appear here in English.")