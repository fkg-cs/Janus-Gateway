import base64
import html as html_lib
import re
import streamlit as st
import requests
from pathlib import Path
import PyPDF2

# --- CONFIGURATION ---
st.set_page_config(page_title="Janus Gateway", page_icon="🛡️", layout="wide")
API_URL = "http://127.0.0.1:8000"


# --- CSS ---
def load_css(file_path):
    with open(file_path, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


css_path = Path(__file__).parent / "assets" / "style.css"
if css_path.exists():
    load_css(css_path)

# --- HEADER ---
logo_path = Path(__file__).parent / "assets" / "logo.png"
github_url = "https://github.com/fkg-cs/Janus-Gateway"

if logo_path.exists():
    logo_b64 = base64.b64encode(logo_path.read_bytes()).decode()
    logo_html = f'<img src="data:image/png;base64,{logo_b64}" class="header-logo" alt="Janus Gateway">'
else:
    logo_html = '<span class="header-logo-fallback">🛡️</span>'

# Aggiunto z-index: 9999 per evitare che layer invisibili di Streamlit blocchino il click sul pulsante GitHub
st.markdown(f"""
<div class="header-wrapper" style="position: relative; z-index: 9999;">
  {logo_html}
  <div class="header-title-container">
    <h1>Janus Gateway</h1>
    <p>Threat Intelligence &amp; Prompt Risk Engine for LLM</p>
  </div>
  <div class="status-pill"><span class="status-dot"></span>system online</div>
  <a href="{github_url}" target="_blank" class="github-link" style="position: relative; z-index: 9999;">
    <svg height="16" width="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"/>
    </svg>
    View on GitHub
  </a>
</div>
""", unsafe_allow_html=True)


# ─── HELPERS ────────────────────────────────────────────

def _e(text):
    """HTML-escape a value safely."""
    return html_lib.escape(str(text)) if text is not None else ""


def _md_inline(text):
    """Escape HTML, then re-allow **bold** markdown."""
    return re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', _e(text))


_SVG_BASE = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"'
_SHIELD_SVG = f'<svg {_SVG_BASE}><path d="M12 3l8 3v6c0 4.5-3.4 8.4-8 9-4.6-.6-8-4.5-8-9V6l8-3z"/></svg>'
_ALERT_SVG = f'<svg {_SVG_BASE}><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
_WARN_SVG = f'<svg {_SVG_BASE}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
_CHECK_SVG = f'<svg {_SVG_BASE}><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
_BRAIN_SVG   = f'<svg {_SVG_BASE}><path d="M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z"/><path d="M12 5a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z"/><path d="M15 13a4.5 4.5 0 0 1-3-4 4.5 4.5 0 0 1-3 4"/><path d="M17.599 6.5a3 3 0 0 0 .399-1.375"/><path d="M6.002 5.125A3 3 0 0 0 6.401 6.5"/><path d="M3.477 10.896a4 4 0 0 1 .585-.396"/><path d="M19.938 10.5a4 4 0 0 1 .585.396"/><path d="M6 18a4 4 0 0 1-1.967-.516"/><path d="M19.967 17.484A4 4 0 0 1 18 18"/></svg>'
_CHEVRON_SVG = f'<svg {_SVG_BASE}><polyline points="6 9 12 15 18 9"/></svg>'
_CALENDAR_SVG = f'<svg {_SVG_BASE} style="width:14px;height:14px;"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>'
_CLOCK_SVG = f'<svg {_SVG_BASE} style="width:14px;height:14px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>'
_TARGET_SVG = f'<svg {_SVG_BASE} style="width:14px;height:14px;"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>'
_USER_SVG = f'<svg {_SVG_BASE} style="width:14px;height:14px;"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'
_GATEWAY_SVG = f'<svg {_SVG_BASE}><path d="M4 22v-4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v4"/><path d="M14 6L10 6"/><path d="M14 10L10 10"/><path d="M12 2v10"/><path d="M8 14H4v-4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v4h-4"/></svg>'


def render_mitigations(items):
    """Renders a list of mitigations as clean white cards with minimal shield icon."""
    rows = "".join(
        f'<div class="mit-row"><span class="mit-row-icon">{_SHIELD_SVG}</span><div>{_md_inline(m)}</div></div>'
        for m in items
    )
    return f'<div class="mit-list">{rows}</div>'


def render_callout(title, body, variant="blue"):
    """Description-box family card: colored left accent + mono uppercase label."""
    return (
        f'<div class="callout-box {variant}">'
        f'<h4>{_e(title)}</h4>'
        f'<p>{_md_inline(body)}</p>'
        f'</div>'
    )


def render_meta_strip(maturity, cases, mitigations, platforms=None, created=None, modified=None, tactics=None):
    """Renders the meta-strip + optional info-strip as compact HTML."""
    cols_class = "meta-strip" if platforms is not None else "meta-strip cols-3"
    p_cell = (
        f'<div class="meta-cell"><div class="meta-label">Platforms</div><div class="meta-value">{_e(platforms)}</div></div>'
        if platforms is not None else ""
    )
    info_strip = ""
    if created or modified or tactics is not None:
        tactics_str = ", ".join(tactics) if tactics else "N/A"
        info_strip = (
            '<div class="info-strip">'
            f'<div class="info-cell"><span class="info-cell-icon">{_CALENDAR_SVG}</span><div><div class="info-cell-lbl">Created</div><div class="info-cell-val">{_e(created or "N/A")}</div></div></div>'
            f'<div class="info-cell"><span class="info-cell-icon">{_CLOCK_SVG}</span><div><div class="info-cell-lbl">Last modified</div><div class="info-cell-val">{_e(modified or "N/A")}</div></div></div>'
            f'<div class="info-cell"><span class="info-cell-icon">{_TARGET_SVG}</span><div><div class="info-cell-lbl">Tactics</div><div class="info-cell-val">{_e(tactics_str)}</div></div></div>'
            '</div>'
        )
    return (
        '<div class="meta-block">'
        f'<div class="{cols_class}">'
        f'<div class="meta-cell"><div class="meta-label">Maturity Level</div><div class="meta-value">{_e(maturity)}</div></div>'
        f'<div class="meta-cell"><div class="meta-label">Case Studies</div><div class="meta-value">{_e(cases)}</div></div>'
        f'<div class="meta-cell"><div class="meta-label">Mitigations</div><div class="meta-value">{_e(mitigations)}</div></div>'
        f'{p_cell}'
        '</div>'
        f'{info_strip}'
        '</div>'
    )


def render_result_block(result):
    """Renders the structured Risk Engine result block as compact HTML.
    Includes XAI expander as a native <details> element so it's visually
    part of the same card (not a separate Streamlit widget)."""
    score = result["risk_score"]

    if score >= 9.0:
        banner_cls, banner_svg, label = "risk-banner--critical", _ALERT_SVG, "CRITICAL RISK PROMPT"
        action = "Hard Block &amp; Alert (Immediate halt and priority notification to the SOC)"
    elif score >= 7.0:
        banner_cls, banner_svg, label = "risk-banner--high", _ALERT_SVG, "HIGH RISK PROMPT"
        action = "Preventive Block (Session interruption and payload isolation)"
    elif score >= 4.0:
        banner_cls, banner_svg, label = "risk-banner--medium", _WARN_SVG, "MEDIUM RISK PROMPT"
        action = "Log &amp; Guardrail (Analysis recorded, activation of preventive semantic filters)"
    else:
        banner_cls, banner_svg, label = "risk-banner--low", _CHECK_SVG, "SECURE PROMPT — LOW RISK"
        action = "Allow (Payload is processed without restrictions)"

    layer_raw = _e(result.get("analysis_layer", "N/A"))
    if "(" in layer_raw:
        layer_name, layer_rest = layer_raw.split("(", 1)
        layer_detail = f"<span class='trigger-detail'>({layer_rest}</span>"
    else:
        layer_name, layer_detail = layer_raw, ""

    atlas_id = result.get("atlas_technique_id", "N/A")
    if atlas_id and atlas_id != "N/A":
        ids = [i.strip() for i in atlas_id.split("|")]
        taxonomy_html = " ".join(
            f'<a href="/?tech_id={_e(tid)}" target="_blank" class="tax-link">{_e(tid)} ↗</a>'
            for tid in ids
        )
    else:
        taxonomy_html = '<span style="font-family:\'IBM Plex Mono\',monospace;font-size:.82rem;color:var(--slate-400)">N/A</span>'

    intent = _e(result.get("detected_intent", "N/A"))
    impact = _e(result.get("impact", "N/A"))
    mitigation = _e(result.get("mitigation_action", "N/A"))
    reasoning = _e(result.get("reasoning", "No reasoning provided by the engine."))

    return (
        '<div class="result-block">'
        f'<div class="trigger-bar"><span class="trigger-icon">{_SHIELD_SVG}</span><span><strong>Inspection Engine triggered:</strong> <span class="trigger-name">{layer_name.strip()}</span> {layer_detail}</span></div>'
        f'<div class="risk-banner {banner_cls}"><span class="risk-banner-icon">{banner_svg}</span><span class="risk-banner-label">{label}</span><span class="risk-banner-score">— Score: {score}/10</span></div>'
        f'<div class="action-row"><strong>Action:</strong> {action}</div>'
        '<div class="detail-grid">'
        f'<div class="dg-col"><div class="dg-label">Detected Intent</div><div class="dg-val">{intent}</div><hr class="dg-sep"/><div class="dg-label">Taxonomy</div>{taxonomy_html}</div>'
        f'<div class="dg-col"><div class="dg-label">Potential Impact</div><div class="dg-val">{impact}</div></div>'
        f'<div class="dg-col"><div class="dg-label defense">Mitigation</div><div class="dg-val mit-val">{mitigation}</div></div>'
        '</div>'
        f'<details class="xai-expander" open><summary class="xai-summary"><span class="xai-icon">{_BRAIN_SVG}</span><span class="xai-title">Risk Engine Reasoning (XAI)</span><span class="xai-chevron">{_CHEVRON_SVG}</span></summary><div class="xai-body"><p>{reasoning}</p></div></details>'
        '</div>'
    )


# ─── DEEP LINKING: ISOLATED KB VIEW ─────────────────────

query_params = st.query_params
if "tech_id" in query_params:
    tech_id = query_params["tech_id"]

    if st.button("← Back to Janus Gateway", type="secondary"):
        st.query_params.clear()
        st.rerun()

    st.markdown("<div style='margin-top: 1.8rem;'></div>", unsafe_allow_html=True)

    try:
        if tech_id.startswith("AML."):
            techs = requests.get(f"{API_URL}/techniques").json()
            stix_id = next((t["stix_id"] for t in techs if t["id"] == tech_id), None)

            if stix_id:
                tech = requests.get(f"{API_URL}/techniques/{stix_id}").json()
                st.markdown(f'<h3 class="tech-detail-title">{_e(tech["id"])}: {_e(tech["name"])}</h3>',
                            unsafe_allow_html=True)

                # Aggiunti tutti i parametri per mantenere la UI uguale al main panel
                st.markdown(render_meta_strip(
                    maturity=tech.get("maturity_level", "N/A"),
                    cases=tech.get("case_studies_count", 0),
                    mitigations=tech.get("mitigations_count", 0),
                    platforms=len(tech.get("platforms", [])),
                    created=tech.get("created", "N/A"),
                    modified=tech.get("modified", "N/A"),
                    tactics=tech.get("tactics", []),
                ), unsafe_allow_html=True)

                st.markdown('<div class="section-label">Description</div>', unsafe_allow_html=True)
                st.markdown(
                    f'<div class="description-text">{_md_inline(tech.get("description", "No description available."))}</div>',
                    unsafe_allow_html=True)

                if tech.get("mitigations"):
                    st.markdown('<div class="section-label defense">Suggested Mitigations</div>',
                                unsafe_allow_html=True)
                    st.markdown(render_mitigations(tech["mitigations"]), unsafe_allow_html=True)

                if tech.get("case_studies"):
                    st.markdown('<div class="section-label">Real-World Case Studies</div>', unsafe_allow_html=True)
                    for cs in tech["case_studies"]:
                        with st.expander(cs["name"], expanded=False):
                            st.markdown(f"**Summary:** {cs.get('summary', 'No summary.')}")
                            st.divider()

                            # Filtro per sostituire dinamicamente le emoji con gli SVG in stile inline
                            desc = cs.get("description", "No description available.")
                            desc = desc.replace("📅",
                                                f'<span style="display:inline-flex;align-items:center;color:var(--slate-400);margin-right:4px;vertical-align:-2px;">{_CALENDAR_SVG}</span>')
                            desc = desc.replace("🎯",
                                                f'<span style="display:inline-flex;align-items:center;color:var(--slate-400);margin-right:4px;vertical-align:-2px;">{_TARGET_SVG}</span>')
                            desc = desc.replace("🕵️",
                                                f'<span style="display:inline-flex;align-items:center;color:var(--slate-400);margin-right:4px;vertical-align:-2px;">{_USER_SVG}</span>')
                            desc = desc.replace("👤",
                                                f'<span style="display:inline-flex;align-items:center;color:var(--slate-400);margin-right:4px;vertical-align:-2px;">{_USER_SVG}</span>')
                            st.markdown(desc, unsafe_allow_html=True)
                else:
                    st.info("No historical case studies found for this technique.")
            else:
                st.error("Technique not found in MITRE ATLAS database.")

        elif tech_id.startswith("LLM"):
            owasp_data = requests.get(f"{API_URL}/owasp").json()
            item = next((i for i in owasp_data if i["id"].startswith(tech_id)), None)

            if item:
                st.markdown(f'<h3 class="tech-detail-title">{_e(item["id"])}: {_e(item["name"])}</h3>',
                            unsafe_allow_html=True)
                st.markdown(render_callout("Description", item["description"], "blue"), unsafe_allow_html=True)
                st.markdown(render_callout("Impact", item["impact"], "red"), unsafe_allow_html=True)
                if "example" in item:
                    st.markdown(render_callout("Attack Scenario", item["example"], "amber"), unsafe_allow_html=True)
                if "mitigations" in item:
                    st.markdown('<div class="section-label">Recommended Mitigations</div>', unsafe_allow_html=True)
                    st.markdown(render_mitigations(item["mitigations"]), unsafe_allow_html=True)
            else:
                st.error("Vulnerability not found in OWASP database.")

    except Exception as e:
        st.error(f"Cannot connect to backend: {e}")

    st.stop()

# ─── MAIN NAVIGATION ────────────────────────────────────

tab_kb, tab_engine = st.tabs(["Knowledge Bases", "Risk Engine"])

# ── TAB 1: KNOWLEDGE BASE ───────────────────────────────
with tab_kb:
    col_list, col_details = st.columns([1, 2.5])

    # ── LEFT SIDEBAR — pill toggle + search + list ────────
    with col_list:
        kb_type = st.radio(
            "KB type",
            ["MITRE ATLAS™", "OWASP LLM"],
            horizontal=True,
            label_visibility="collapsed",
            key="kb_type",
        )

        placeholder = "Search techniques…" if kb_type == "MITRE ATLAS™" else "Search vulnerabilities…"
        search_term = st.text_input(
            "Search",
            placeholder=placeholder,
            label_visibility="collapsed",
            key="kb_search",
        )

        selected_stix_id = None
        selected_owasp_item = None

        if kb_type == "MITRE ATLAS™":
            try:
                response = requests.get(f"{API_URL}/techniques")
                techniques = response.json()
                tech_display = [f"{t['id']} — {t['name']}" for t in techniques]
                filtered_techs = [t for t in tech_display if search_term.lower() in t.lower()]
                if filtered_techs:
                    selected_tech_name = st.radio("Techniques", filtered_techs, label_visibility="collapsed",
                                                  key="tech_radio")
                    selected_index = tech_display.index(selected_tech_name)
                    selected_stix_id = techniques[selected_index]["stix_id"]
                else:
                    st.warning("No techniques found.")
            except Exception as e:
                st.error(f"API connection failed: {e}")
        else:
            try:
                owasp_res = requests.get(f"{API_URL}/owasp")
                if owasp_res.status_code == 200:
                    owasp_data = owasp_res.json()
                    if isinstance(owasp_data, list):
                        owasp_display = [f"{item['id']} — {item['name']}" for item in owasp_data]
                        filtered_owasp = [o for o in owasp_display if search_term.lower() in o.lower()]
                        if filtered_owasp:
                            selected_owasp_name = st.radio("Vulnerabilities", filtered_owasp,
                                                           label_visibility="collapsed", key="owasp_radio")
                            selected_owasp_index = owasp_display.index(selected_owasp_name)
                            selected_owasp_item = owasp_data[selected_owasp_index]
                        else:
                            st.warning("No vulnerabilities found.")
                    elif isinstance(owasp_data, dict) and "error" in owasp_data:
                        st.error(owasp_data["error"])
                else:
                    st.error(f"Backend error {owasp_res.status_code}")
            except Exception as e:
                st.error(f"OWASP connection error: {e}")

    # ── RIGHT DETAIL PANEL ────────────────────────────────
    with col_details:
        if kb_type == "MITRE ATLAS™" and selected_stix_id:
            try:
                tech = requests.get(f"{API_URL}/techniques/{selected_stix_id}").json()
                st.markdown(f'<h3 class="tech-detail-title">{_e(tech["id"])}: {_e(tech["name"])}</h3>',
                            unsafe_allow_html=True)

                st.markdown(render_meta_strip(
                    maturity=tech.get("maturity_level", "N/A"),
                    cases=tech.get("case_studies_count", 0),
                    mitigations=tech.get("mitigations_count", 0),
                    platforms=len(tech.get("platforms", [])),
                    created=tech.get("created", "N/A"),
                    modified=tech.get("modified", "N/A"),
                    tactics=tech.get("tactics", []),
                ), unsafe_allow_html=True)

                st.markdown('<div class="section-label">Description</div>', unsafe_allow_html=True)
                st.markdown(
                    f'<div class="description-text">{_md_inline(tech.get("description", "No description available."))}</div>',
                    unsafe_allow_html=True)

                if tech.get("mitigations"):
                    st.markdown('<div class="section-label defense">Suggested Mitigations</div>',
                                unsafe_allow_html=True)
                    st.markdown(render_mitigations(tech["mitigations"]), unsafe_allow_html=True)

                if tech.get("case_studies"):
                    st.markdown('<div class="section-label">Real-World Case Studies</div>', unsafe_allow_html=True)
                    for cs in tech["case_studies"]:
                        with st.expander(cs["name"], expanded=False):
                            st.markdown(f"**Summary:** {cs.get('summary', 'No summary.')}")
                            st.divider()

                            # Filtro per sostituire dinamicamente le emoji con gli SVG in stile inline
                            desc = cs.get("description", "No description available.")
                            desc = desc.replace("📅",
                                                f'<span style="display:inline-flex;align-items:center;color:var(--slate-400);margin-right:4px;vertical-align:-2px;">{_CALENDAR_SVG}</span>')
                            desc = desc.replace("🎯",
                                                f'<span style="display:inline-flex;align-items:center;color:var(--slate-400);margin-right:4px;vertical-align:-2px;">{_TARGET_SVG}</span>')
                            desc = desc.replace("🕵️",
                                                f'<span style="display:inline-flex;align-items:center;color:var(--slate-400);margin-right:4px;vertical-align:-2px;">{_USER_SVG}</span>')
                            desc = desc.replace("👤",
                                                f'<span style="display:inline-flex;align-items:center;color:var(--slate-400);margin-right:4px;vertical-align:-2px;">{_USER_SVG}</span>')
                            st.markdown(desc, unsafe_allow_html=True)
                elif tech.get("case_studies_count", 0) > 0:
                    st.info("Case studies exist but detailed data was not loaded from YAML.")
            except Exception as e:
                st.error(f"Failed to load technique: {e}")

        elif kb_type == "OWASP LLM" and selected_owasp_item:
            item = selected_owasp_item
            st.markdown(f'<h3 class="tech-detail-title">{_e(item["id"])}: {_e(item["name"])}</h3>',
                        unsafe_allow_html=True)

            st.markdown('<div class="section-label">Description</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="description-text">{_md_inline(item["description"])}</div>',
                        unsafe_allow_html=True)

            st.markdown('<div class="section-label">Impact</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="description-text">{_md_inline(item["impact"])}</div>', unsafe_allow_html=True)

            if "example" in item:
                st.markdown('<div class="section-label">Attack Scenario</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="description-text">{_md_inline(item["example"])}</div>',
                            unsafe_allow_html=True)

            if "mitigations" in item and item["mitigations"]:
                st.markdown('<div class="section-label defense">Recommended Mitigations</div>', unsafe_allow_html=True)
                st.markdown(render_mitigations(item["mitigations"]), unsafe_allow_html=True)

# ── TAB 2: RISK ENGINE ──────────────────────────────────
with tab_engine:
    user_prompt = st.text_area(
        "User Prompt and attachments Analysis",
        placeholder="Insert the prompt to analyze,upload a document below and click run analysis...",
        height=160,
    )

    col_upload, col_run = st.columns([3.2, 1])
    with col_upload:
        uploaded_file = st.file_uploader(
            "Upload document (PDF, TXT, CSV, MD)",
            type=["pdf", "txt", "csv", "md"],
            label_visibility="collapsed",
        )
    with col_run:
        run_clicked = st.button("▶  Run analysis", type="primary", use_container_width=True, key="run_btn")

    if run_clicked:
        if not user_prompt and not uploaded_file:
            st.warning("Please provide a prompt or a document for analysis.")
        else:
            with st.spinner("Static analysis & semantic inference in progress…"):

                document_text = ""
                document_metadata = None

                if uploaded_file is not None:
                    document_metadata = {
                        "filename": uploaded_file.name,
                        "file_type": uploaded_file.type,
                        "file_size": uploaded_file.size,
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
                        st.error(f"Error during text extraction: {e}")

                payload = {
                    "user_prompt": user_prompt,
                    "document_text": document_text if document_text else None,
                    "document_metadata": document_metadata,
                }

                try:
                    res = requests.post(f"{API_URL}/api/v1/analyze", json=payload)
                    res.raise_for_status()
                    result = res.json()

                    # Full structured result block (XAI expander is inside)
                    st.markdown(render_result_block(result), unsafe_allow_html=True)

                except requests.exceptions.RequestException as e:
                    st.error(f"Backend communication error: {e}")