
import sys
import time
from pathlib import Path

import streamlit as st
import plotly.graph_objects as go

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from Core.risk_engine import analyze_url

st.set_page_config(
    page_title="Browser Shield",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background: radial-gradient(circle at top right, #153654, #07111f 60%);
    color: #eaf7ff;
}
.block-container {
    padding-top: 2rem;
    max-width: 1400px;
}
.hero {
    padding: 28px;
    border: 1px solid #24506b;
    border-radius: 22px;
    background: linear-gradient(120deg, #10263b, #0b1728);
    box-shadow: 0 0 28px #00cfff18;
    margin-bottom: 24px;
}
.hero h1 {
    color: #68e1ff;
    font-size: 42px;
    margin: 0;
}
.hero p {
    color: #9cbad0;
    margin-bottom: 0;
}
.card {
    padding: 20px;
    border: 1px solid #23445e;
    border-radius: 16px;
    background: linear-gradient(145deg, #142b40, #0c1c2e);
    min-height: 115px;
    box-shadow: 0 0 18px #00cfff0b;
}
.card-label {
    color: #8eacc4;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.card-value {
    color: #6be4ff;
    font-size: 27px;
    font-weight: 700;
    margin-top: 10px;
}
.scanline {
    height: 4px;
    width: 100%;
    border-radius: 5px;
    background: linear-gradient(90deg, transparent, #48ddff, #a7f5ff, transparent);
    box-shadow: 0 0 16px #48ddff;
    animation: pulse 1.2s ease-in-out infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 0.35; }
    50% { opacity: 1; }
}
div.stButton > button {
    border: 1px solid #43cfee;
    background: linear-gradient(90deg, #087ca5, #1555a5);
    color: white;
    border-radius: 10px;
    font-weight: 700;
    padding: 0.65rem 1rem;
    transition: 0.2s ease;
}
div.stButton > button:hover {
    border-color: #a3f3ff;
    box-shadow: 0 0 18px #28d8ff66;
    transform: translateY(-1px);
}
div[data-testid="stMetric"] {
    background: #10263a;
    border: 1px solid #244961;
    border-radius: 14px;
    padding: 16px;
}
h2, h3 {
    color: #72e2ff !important;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
    <h1>🛡️ BROWSER SHIELD</h1>
    <p>Threat Intelligence Interface · URL Risk Analysis · Security Dashboard</p>
</div>
""", unsafe_allow_html=True)

left, right = st.columns([2, 1])

with left:
    st.subheader("🔎 Threat Scanner")
    url = st.text_input(
        "Target URL",
        placeholder="https://example.com"
    )
    page_text = st.text_area(
        "Optional HTML content",
        placeholder="Paste HTML here for additional analysis...",
        height=110
    )

with right:
    st.subheader("⚙️ Scan Options")
    filename = st.text_input("Download filename", placeholder="sample.exe")
    content_type = st.text_input(
        "Content type",
        placeholder="application/octet-stream"
    )
    user_initiated = st.checkbox(
        "Download initiated by user",
        value=True
    )

scan_clicked = st.button(
    "⚡ INITIATE SECURITY SCAN",
    type="primary",
    use_container_width=True
)

if scan_clicked:
    if not url.strip():
        st.warning("Enter a URL before starting the scan.")
    else:
        progress = st.progress(0, text="Initializing scanner...")
        status_text = st.empty()
        animation_area = st.empty()

        stages = [
            (15, "Initializing detection engine..."),
            (35, "Checking phishing indicators..."),
            (55, "Analysing malicious URL patterns..."),
            (75, "Inspecting supplied HTML signals..."),
            (90, "Evaluating download metadata..."),
            (100, "Combining risk results...")
        ]

        for percent, message in stages:
            progress.progress(percent, text=message)
            status_text.info(f"◉ {message}")
            animation_area.markdown(
                '<div class="scanline"></div>',
                unsafe_allow_html=True
            )
            time.sleep(0.25)

        try:
            report = analyze_url(
                url.strip(),
                page_text=page_text,
                download_metadata={
                    "filename": filename.strip(),
                    "content_type": content_type.strip(),
                    "user_initiated": user_initiated,
                }
            )

            progress.empty()
            status_text.empty()
            animation_area.empty()

            score = max(
                0, min(100, int(report.get("risk_score", 0)))
            )
            status = report.get("status", "Unknown")

            st.success("Analysis complete.")
            st.markdown("### 📊 Security Overview")

            c1, c2, c3 = st.columns(3)

            with c1:
                st.markdown(f"""
                <div class="card">
                    <div class="card-label">Combined Risk Score</div>
                    <div class="card-value">{score}/100</div>
                </div>
                """, unsafe_allow_html=True)

            with c2:
                st.markdown(f"""
                <div class="card">
                    <div class="card-label">Threat Status</div>
                    <div class="card-value">{status}</div>
                </div>
                """, unsafe_allow_html=True)

            with c3:
                st.markdown(f"""
                <div class="card">
                    <div class="card-label">Modules Analysed</div>
                    <div class="card-value">{report.get('modules_checked', 0)}/4</div>
                </div>
                """, unsafe_allow_html=True)

            gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                number={"suffix": "/100"},
                title={"text": "THREAT LEVEL"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#57e2ff"},
                    "bgcolor": "#10263a",
                    "bordercolor": "#31516a",
                    "steps": [
                        {"range": [0, 29], "color": "#164c3c"},
                        {"range": [30, 59], "color": "#75551b"},
                        {"range": [60, 100], "color": "#762c3c"}
                    ],
                }
            ))
            gauge.update_layout(
                height=320,
                paper_bgcolor="rgba(0,0,0,0)",
                font={"color": "#eaf7ff"},
                margin={"t": 60, "b": 10, "l": 20, "r": 20}
            )

            st.plotly_chart(gauge, use_container_width=True)

            st.markdown("### 🧩 Detection Modules")

            module_names = {
                "phishing_detection": "Phishing Detection",
                "malicious_url_detection": "Malicious URL Detector",
                "information_stealer_detection": "Information Stealer Analysis",
                "drive_by_download_detection": "Drive-by Download Analysis"
            }

            for key, result in report.get("module_results", {}).items():
                module_status = result.get("status", "Unknown")
                module_score = result.get("risk_score", 0)

                with st.expander(
                    f"{module_names.get(key, key)} · "
                    f"{module_status} · {module_score}/100"
                ):
                    st.write(result.get("explanation", ""))
                    indicators = result.get("indicators", [])
                    if indicators:
                        st.write("**Indicators:**")
                        for item in indicators:
                            st.write(f"- {item}")
                    else:
                        st.write("No indicators returned.")

            st.markdown("### 🧠 Recommendations")
            for recommendation in report.get("recommendations", []):
                st.write(f"✓ {recommendation}")

            with st.expander("View complete technical report"):
                st.json(report)

        except Exception as error:
            progress.empty()
            status_text.empty()
            animation_area.empty()
            st.error(f"Scan failed: {error}")

st.divider()
st.caption(
    "Browser Shield · Academic prototype · "
    "Rule-based analysis, not a guarantee of website safety"
)

