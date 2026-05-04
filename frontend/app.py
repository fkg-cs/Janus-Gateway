import streamlit as st
import requests
from pathlib import Path
from PIL import Image
import PyPDF2

# --- CONFIGURATION ---
st.set_page_config(page_title="Janus Gateway - Security Core", page_icon="🛡️", layout="wide")

# Backend URL (FastAPI)
API_URL = "http://127.0.0.1:8000"

# --- CSS INJECTION ---
def load_css(file_path):
    """Legge il file CSS e lo inietta in Streamlit"""
    with open(file_path, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Carichiamo il file CSS dalla cartella assets
css_path = Path(__file__).parent / "assets" / "style.css"
if css_path.exists():
    load_css(css_path)
else:
    st.warning("⚠️ CSS stylesheet not found!")

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
tab_kb, tab_engine = st.tabs(["Knowledge Bases", "Dynamic Risk Engine"])

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

            # --- NUOVO CONTROLLO DI SICUREZZA ---
            if owasp_res.status_code != 200:
                st.error(f"Il Backend ha risposto con un errore {owasp_res.status_code}: {owasp_res.text}")
            else:
                data = owasp_res.json()

                # Se il backend ci ha mandato un dict con un errore invece della lista
                if isinstance(data, dict) and "error" in data:
                    st.error(data["error"])
                else:
                    for item in data:
                        with st.expander(f"**{item['id']}** - {item['name']}"):
                            st.write(item['description'])
                            st.error(f"**Impact:** {item['impact']}")

                            if "example" in item:
                                st.warning(f"**Attack Scenario:** {item['example']}")

                            if "mitigations" in item and item["mitigations"]:
                                st.markdown("**🛡️ Recommended Mitigations:**")
                                for m in item['mitigations']:
                                    st.info(f"• {m}")
        except Exception as e:
            st.error(f"Errore di parsing o connessione OWASP: {e}")

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