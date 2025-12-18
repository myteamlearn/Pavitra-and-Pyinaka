# sbom_dashboard_with_ollama.py
import streamlit as st
import pandas as pd
import json
import requests
from collections import defaultdict
import plotly.graph_objects as go
import html

# =====================================================
# Config
# =====================================================
st.set_page_config(
    page_title="SBOM Vulnerability Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

OLLAMA_API = "http://127.0.0.1:11434/api/generate"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible"]
SEV_COLORS = {
    "Critical": "#e53935",
    "High": "#fb8c00",
    "Medium": "#fdd835",
    "Low": "#42a5f5",
    "Negligible": "#9e9e9e"
}

# =====================================================
# Helpers
# =====================================================
def normalize_severity(s):
    if not s:
        return "Negligible"
    s = str(s).upper()
    if s.startswith("CRIT"): return "Critical"
    if s.startswith("HIGH"): return "High"
    if s.startswith("MED"):  return "Medium"
    if s.startswith("LOW"):  return "Low"
    return "Negligible"

def parse_sbom_json(js):
    vulns = []
    for res in js.get("Results", []):
        for v in res.get("Vulnerabilities", []) or []:
            vulns.append({
                "id": v.get("VulnerabilityID",""),
                "severity": normalize_severity(v.get("Severity")),
                "fix_available": bool(v.get("FixedVersion")),
                "affected_item_name": v.get("PkgName","Unknown"),
                "published_date": (v.get("PublishedDate","") or "").split("T")[0],
                "description": v.get("Description",""),
                "url": v.get("PrimaryURL","")
            })
    return pd.DataFrame(vulns)

# =====================================================
# Sidebar
# =====================================================
with st.sidebar:
    st.markdown("<div style='display:flex;align-items:center;gap:10px'><div style='width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#5b9cff,#a67cff);display:flex;align-items:center;justify-content:center;font-weight:700'>SB</div><div style='font-weight:700'>GenAI Based<br>Vulnerability Scanning</div></div>", unsafe_allow_html=True)
    st.markdown("---")
    # Navigation links - use HTML anchor links to section ids
    nav_html = """
    <div style="display:flex;flex-direction:column;gap:8px">
      <a href="#overview" style="text-decoration:none"><button style="width:100%;padding:8px;border-radius:8px;background:#121318;color:#fff;border:1px solid #263047">Overview</button></a>
      <a href="#package-insights" style="text-decoration:none"><button style="width:100%;padding:8px;border-radius:8px;background:#121318;color:#fff;border:1px solid #263047">Charts & Insights</button></a>
      <a href="#vuln-severity" style="text-decoration:none"><button style="width:100%;padding:8px;border-radius:8px;background:#121318;color:#fff;border:1px solid #263047">Severity counts</button></a>
      <a href="#vuln-tables" style="text-decoration:none"><button style="width:100%;padding:8px;border-radius:8px;background:#121318;color:#fff;border:1px solid #263047">Vulnerabilities</button></a>
    </div>
    """
    st.markdown(nav_html, unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # Ask Ollama button (anchor to AI section)
    st.markdown('<a href="#ai-assistant-ollama" style="text-decoration:none"><button style="width:100%;padding:8px;border-radius:8px;background:#2c73ff;color:#fff;border:none">Ask Ollama</button></a>', unsafe_allow_html=True)
    st.markdown("<p style='color:#a7b0c0;font-size:12px'>Click \"Ask Ollama\" to jump to assistant (you can choose model/params there).</p>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""

""", unsafe_allow_html=True)

    # file input will be inside main area (hidden), so these controls trigger it via JS

st.markdown("<style>body { background:#0f1115; color:#e8edf5 } .stButton>button { background:#0d1114; }</style>", unsafe_allow_html=True)


# =====================================================
# Upload
# =====================================================
uploaded_file = st.file_uploader(
    "Upload SBOM JSON",
    type=["json"]
)

df = pd.DataFrame()

if uploaded_file:
    try:
        raw = json.load(uploaded_file)
        df = parse_sbom_json(raw)
        st.success("SBOM loaded")
    except Exception as e:
        st.error(f"Parse error: {e}")

if df.empty:
    df = pd.DataFrame(columns=[
        "id","severity","fix_available",
        "affected_item_name","published_date",
        "description","url"
    ])

# =====================================================
# Overview
# =====================================================
st.markdown('<a id="overview"></a>', unsafe_allow_html=True)
st.markdown("## Overview")

c1,c2,c3,c4 = st.columns(4)
c1.metric("Total Vulnerabilities", len(df))
c2.metric("Critical", int((df["severity"]=="Critical").sum()))
c3.metric("Fixable", int(df["fix_available"].sum()))
c4.metric("Packages", df["affected_item_name"].nunique())

# =====================================================
# Charts & Insights
# =====================================================
st.markdown('<a id="package-insights"></a>', unsafe_allow_html=True)
st.markdown("<h3>Charts & Insights</h3>", unsafe_allow_html=True)

col1, col2 = st.columns(2)

# =====================================================
# Severity Chart
# =====================================================
st.markdown('<a id="vuln-severity"></a>', unsafe_allow_html=True)
st.markdown("<h3>Charts & Insights</h3>", unsafe_allow_html=True)

col1, col2 = st.columns(2)

# Left: Fixable vulnerabilities bar
with col1:
    st.markdown('<div class="card" style="padding:12px;background:#151922;border-radius:10px">', unsafe_allow_html=True)
    st.markdown("<h4>Fixable vulnerabilities summary</h4>", unsafe_allow_html=True)
    sev_counts = df["severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0)
    bar_fig = go.Figure(go.Bar(
        x=sev_counts.values,
        y=SEVERITY_ORDER,
        orientation='h',
        marker_color=[SEV_COLORS[s] for s in SEVERITY_ORDER]
    ))
    bar_fig.update_layout(height=320, margin=dict(l=0,r=0,t=10,b=10),
                          xaxis_title="Count", yaxis_title="", plot_bgcolor="#151922",
                          paper_bgcolor="#151922", font=dict(color="#e8edf5"))
    st.plotly_chart(bar_fig, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

# Right: Package insights donut
with col2:
    st.markdown('<div class="card" style="padding:12px;background:#151922;border-radius:10px">', unsafe_allow_html=True)
    st.markdown("<h4>Package insights (vulnerable packages only)</h4>", unsafe_allow_html=True)
    donut_fig = go.Figure(go.Pie(
        labels=SEVERITY_ORDER,
        values=sev_counts.values,
        hole=0.6,
        marker_colors=[SEV_COLORS[s] for s in SEVERITY_ORDER]
    ))
    donut_fig.update_layout(height=320, margin=dict(t=10,b=10),
                            paper_bgcolor="#151922", font=dict(color="#e8edf5"))
    st.plotly_chart(donut_fig, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

# Severity badges
st.markdown('<div class="card" style="padding:12px;background:#151922;border-radius:10px;margin-top:12px">', unsafe_allow_html=True)
st.markdown("<h4 style='margin:0 0 8px 0'>Severity counts</h4>", unsafe_allow_html=True)
badges_html = ""
for s in SEVERITY_ORDER:
    count = int((df["severity"]==s).sum())
    color = SEV_COLORS[s]
    badges_html += f"<span style='display:inline-block;background:{color};color:#000;padding:6px 12px;border-radius:999px;margin-right:10px;font-weight:700'>{s}: {count}</span>"
st.markdown(badges_html, unsafe_allow_html=True)
st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# Table
st.markdown('<a id="vuln-tables"></a>', unsafe_allow_html=True)
st.markdown("<h3 style='margin-top:18px'>All vulnerabilities</h3>", unsafe_allow_html=True)
# Build HTML table so we can include buttons with JS hooks for copy prompt
table_html = """
<table style="width:100%;border-collapse:collapse">
<thead style="color:#a7b0c0"><tr>
<th style="padding:8px;text-align:left">ID</th>
<th style="padding:8px;text-align:left">Severity</th>
<th style="padding:8px;text-align:left">Fix</th>
<th style="padding:8px;text-align:left">Type</th>
<th style="padding:8px;text-align:left">Name</th>
<th style="padding:8px;text-align:left">Published</th>
<th style="padding:8px;text-align:left">Summary</th>
</tr></thead><tbody>
"""
for i, r in df.iterrows():
    vid = html.escape(str(r.get("id","")))
    sev = html.escape(str(r.get("severity","")))
    fix = "Yes" if bool(r.get("fix_available",False)) else "No"
    typ = html.escape(str(r.get("affected_item_type","package")))
    name = html.escape(str(r.get("affected_item_name","")))
    pub = html.escape(str(r.get("published_date","")))
    summary_buttons = f"""
      <button onclick="window.dispatchEvent(new CustomEvent('generate_summary',{{detail:{i}}}))" style="margin-right:6px;padding:6px;border-radius:6px;background:#2c73ff;color:#fff;border:none">Generate Summary</button>
      <button onclick="(function(){{navigator.clipboard.writeText('{html.escape(f'Explain {vid} ({name}). Severity: {sev}.')}')}})();" style="padding:6px;border-radius:6px;background:#1b2130;color:#fff;border:1px solid #263047">Copy Prompt</button>
    """
    table_html += f"<tr style='border-bottom:1px solid #263047'><td style='padding:8px'><a href='{r.get('url','')}' target='_blank' style='color:#9db3ff'>{vid}</a></td><td style='padding:8px'>{sev}</td><td style='padding:8px'>{fix}</td><td style='padding:8px'>{typ}</td><td style='padding:8px'>{name}</td><td style='padding:8px'>{pub}</td><td style='padding:8px'>{summary_buttons}</td></tr>"
table_html += "</tbody></table>"
st.markdown(f'<div class="card" style="padding:12px;background:#151922;border-radius:10px">{table_html}</div>', unsafe_allow_html=True)

# JavaScript bridge to notify Streamlit when "Generate Summary" clicked.
# Use window.parent.postMessage to send event, and we parse from Python via st.experimental_get_query_params? Not available.
# Alternative: use st.components.v1.html that registers a window.postMessage listener and posts data to a hidden iframe that Streamlit can read.
# Simpler approach: use a polling hidden text area: when button clicked, JS sets document.title or location.hash - Streamlit cannot reliably read that.
# Instead, we will use a small component that listens for generate_summary events and sends details back via a custom Streamlit component.
# We'll implement a small HTML component that listens and then writes the index into a hidden input element that Streamlit can read using st.experimental_get_query_params shim.
# Easier: We'll have a visible select box "Generate summary for index:" updated by JS. But that's clunky.
# Practical approach: Provide per-row Streamlit buttons too (server-side), which the user can click if they want server-run summary.
# The JS "Generate Summary" buttons above are convenience; we will also render server-side Streamlit buttons below the table for each row (collapsed) to ensure backend calls work.
# =====================================================
# ---- OLLAMA INTELLIGENCE LAYER ----
# =====================================================

def build_sbom_context(df: pd.DataFrame) -> str:
    if df.empty:
        return "No SBOM data is loaded."

    lines = [
        f"Total vulnerabilities: {len(df)}",
        f"Critical: {(df['severity']=='Critical').sum()}",
        f"High: {(df['severity']=='High').sum()}",
        f"Medium: {(df['severity']=='Medium').sum()}",
        f"Low: {(df['severity']=='Low').sum()}",
        "",
        "Sample vulnerabilities:"
    ]

    for _, r in df.head(15).iterrows():
        lines.append(
            f"- {r['id']} | {r['severity']} | {r['affected_item_name']}"
        )

    return "\n".join(lines)

DASHBOARD_UI_CONTEXT = """
Dashboard Navigation (IMPORTANT – exact locations):

- Overview:
  • Located in the LEFT SIDEBAR
  • Button label: "Overview"
  • Clicking it scrolls the page to the Overview section

- Charts & Insights:
  • Located in the LEFT SIDEBAR
  • Button label: "Charts & Insights"

- Severity:
  • Located in the LEFT SIDEBAR
  • Button label: "Severity"

- Vulnerabilities:
  • Located in the LEFT SIDEBAR
  • Button label: "Vulnerabilities"

- Ask Ollama:
  • Located in the LEFT SIDEBAR
  • Blue button labeled "Ask Ollama"
  • Scrolls to the AI assistant section at the bottom

Rule:
- NEVER say "top tab" or "top menu"
- ALWAYS mention "left sidebar" when explaining navigation
"""


def ask_ollama(prompt, model, params):
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        **params
    }
    r = requests.post(OLLAMA_API, json=payload, timeout=60)
    r.raise_for_status()
    return r.json().get("response","")

# =====================================================
# AI Assistant
# =====================================================
st.markdown('<a id="ai-assistant-ollama"></a>', unsafe_allow_html=True)
st.markdown("## 🤖 Ask Ollama")

model = st.selectbox(
    "Model",
    ["llama3:latest","mistral:latest","llama2:latest"]
)

temperature = st.slider("Temperature",0.0,1.5,0.2)
max_tokens = st.slider("Max tokens",100,1500,400)

user_q = st.text_area("Ask a question")

if st.button("Ask"):
    if not user_q.strip():
        st.warning("Enter a question")
    else:
        with st.spinner("Thinking..."):

            sbom_ctx = build_sbom_context(df)

            final_prompt = f"""
You are an assistant for an SBOM vulnerability dashboard.

STRICT UI RULES:
- This dashboard uses ONLY a LEFT SIDEBAR for navigation
- There are NO top tabs
- Navigation buttons scroll the page using anchors
- Do NOT invent UI elements


Dashboard context:
{DASHBOARD_UI_CONTEXT}

SBOM context:
{sbom_ctx}

User question:
{user_q}

Rules:
- If question is about vulnerabilities, answer using SBOM context.
- If question is about dashboard navigation, explain where to click.
- Otherwise answer normally.
"""

            try:
                answer = ask_ollama(
                    final_prompt,
                    model,
                    {
                        "temperature": temperature,
                        "max_tokens": max_tokens
                    }
                )
                st.text_area("Answer", answer, height=220)
            except Exception as e:
                st.error(f"Ollama error: {e}")

# =====================================================
# Footer
# =====================================================
st.markdown(
    "<small>Run with: <code>streamlit run sbom_dashboard_with_ollama.py</code><br>"
    "Ollama must be running locally.</small>",
    unsafe_allow_html=True
)
