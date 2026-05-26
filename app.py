#!/usr/bin/env python3
"""
AURA: Automated User-Risk Analysis — SOC Dashboard
app.py  |  Streamlit frontend — deterministic rule engine, no AI dependencies.

Design: high-density SOC dashboard using native Streamlit components.
No complex HTML card structures; all data surfaces via st.dataframe /
st.metric / st.expander as per audit directive.
"""

import streamlit as st
import os
import json
import tempfile
import pandas as pd
import time
from datetime import datetime

# event_mapper owns the logging setup (force=True basicConfig).
# Do NOT call logging.basicConfig here — that was the double-config audit bug.
from event_mapper import EventLogParser, RuleEngine, LogSanitizer

# ─── Page Configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AURA | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items=None,
)

# ─── CSS — Minimal Header + Typography Only ────────────────────────────────────
# Intentionally lean: no card/badge HTML. All data shown via native components.
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
}

/* ── Dynamic Theme Variables (injected via Streamlit) ── */
/* ── Dashboard Header Banner ── */
.aura-topbar {
    background: var(--banner-bg, linear-gradient(90deg, #0E1117 0%, #161B27 100%));
    border-bottom: 2px solid #00D1FF;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 1.5rem;
    height: 60px;
    margin-top: -40px;
    margin-bottom: 20px;
    animation: slideDown 0.4s ease-out;
}
@keyframes slideDown {
    from { transform: translateY(-20px); opacity: 0; }
    to   { transform: translateY(0);     opacity: 1; }
}
.aura-topbar h1 {
    font-size: 1.1rem;
    font-weight: 700;
    color: #00D1FF;
    margin: 0;
    letter-spacing: 0.5px;
}
.aura-topbar .engine-pill {
    font-family: 'Roboto Mono', monospace;
    font-size: 0.72rem;
    color: var(--pill-text, #00FF88);
    background: var(--pill-bg, rgba(0,255,136,0.10));
    border: 1px solid var(--pill-border, rgba(0,255,136,0.35));
    padding: 3px 10px;
    border-radius: 20px;
}
.aura-topbar a.gh-link {
    font-size: 0.78rem;
    font-weight: 600;
    color: #0E1117;
    background: #00D1FF;
    padding: 4px 14px;
    border-radius: 20px;
    text-decoration: none;
    margin-left: 12px;
    transition: background 0.2s;
}
.aura-topbar a.gh-link:hover { background: #00B8E6; }

/* Section labels */
.section-label {
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: #00D1FF;
    margin-bottom: 6px;
    margin-top: 4px;
}

/* ── Layout & Sidebar Spacing ── */
.block-container {
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    max-width: 100% !important;
}

/* ── Dataframe row height tweak & Toolbar ── */
.stDataFrame { border-radius: 8px !important; }
/* Force dataframe toolbar to always be visible */
[data-testid="stElementToolbar"] {
    opacity: 1 !important;
    display: flex !important;
}

/* Make default Streamlit header transparent instead of hiding it entirely */
/* This ensures the sidebar toggle button remains clickable and visible */
header[data-testid="stHeader"] { 
    background: transparent !important; 
}
</style>
""", unsafe_allow_html=True)

# ─── Top Bar ──────────────────────────────────────────────────────────────────
st.markdown("""
<div class="aura-topbar">
    <h1>🛡️ AURA &nbsp;|&nbsp; Threat Intelligence</h1>
    <div style="display:flex;align-items:center;gap:8px;">
        <span class="engine-pill">⚙ RULE ENGINE · ONLINE</span>
        <a href="https://github.com/AbhijeetSharma08/AURA" target="_blank" class="gh-link">
            ⬡ GitHub
        </a>
    </div>
</div>
""", unsafe_allow_html=True)

# ─── Session State ─────────────────────────────────────────────────────────────
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = []
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True

# ─── Theme Injection ──────────────────────────────────────────────────────────
if st.session_state.dark_mode:
    # Use native Streamlit dark background variables implicitly, but force our topbar variables
    theme_css = """
    <style>
    :root {
        --banner-bg: linear-gradient(90deg, #0E1117 0%, #161B27 100%);
        --pill-text: #00FF88;
        --pill-bg: rgba(0,255,136,0.10);
        --pill-border: rgba(0,255,136,0.35);
    }
    
    /* ── Dark Mode Metric Delta Colors (matching severity) ── */
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(2) [data-testid="stMetricDelta"] {
        color: #FF4B4B !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(2) [data-testid="stMetricDelta"] svg {
        fill: #FF4B4B !important;
    }
    
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(3) [data-testid="stMetricDelta"] {
        color: #FF8C00 !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(3) [data-testid="stMetricDelta"] svg {
        fill: #FF8C00 !important;
    }
    
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(4) [data-testid="stMetricDelta"] {
        color: #FFD700 !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(4) [data-testid="stMetricDelta"] svg {
        fill: #FFD700 !important;
    }
    
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(5) [data-testid="stMetricDelta"] {
        color: #00D1FF !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(5) [data-testid="stMetricDelta"] svg {
        fill: #00D1FF !important;
    }
    
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(6) [data-testid="stMetricDelta"] {
        color: #00FF88 !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(6) [data-testid="stMetricDelta"] svg {
        fill: #00FF88 !important;
    }
    </style>
    """
else:
    # Override main containers with light colors
    theme_css = """
    <style>
    :root {
        --banner-bg: linear-gradient(90deg, #F0F2F6 0%, #E0E5EC 100%);
        --pill-text: #008A4A;
        --pill-bg: rgba(0,255,136,0.20);
        --pill-border: rgba(0,180,90,0.5);
    }
    [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background-color: #FFFFFF !important;
        color: #000000 !important;
    }
    [data-testid="stSidebar"] {
        background-color: #F8F9FB !important;
        color: #000000 !important;
    }
    p, span, div, h1, h2, h3, h4, h5, h6, label {
        color: #111111;
    }
    .aura-topbar h1 { color: #0055BB; }
    .section-label { color: #0055BB; }
    
    /* ── Light Mode Metric Delta Colors (matching severity) ── */
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(2) [data-testid="stMetricDelta"] {
        color: #DC3545 !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(2) [data-testid="stMetricDelta"] svg {
        fill: #DC3545 !important;
    }
    
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(3) [data-testid="stMetricDelta"] {
        color: #FD7E14 !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(3) [data-testid="stMetricDelta"] svg {
        fill: #FD7E14 !important;
    }
    
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(4) [data-testid="stMetricDelta"] {
        color: #B58900 !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(4) [data-testid="stMetricDelta"] svg {
        fill: #B58900 !important;
    }
    
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(5) [data-testid="stMetricDelta"] {
        color: #0055BB !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(5) [data-testid="stMetricDelta"] svg {
        fill: #0055BB !important;
    }
    
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(6) [data-testid="stMetricDelta"] {
        color: #198754 !important;
    }
    [data-testid="stHorizontalBlock"]:first-of-type [data-testid="column"]:nth-of-type(6) [data-testid="stMetricDelta"] svg {
        fill: #198754 !important;
    }
    </style>
    """
st.markdown(theme_css, unsafe_allow_html=True)

# ─── Shared instances ──────────────────────────────────────────────────────────
_parser = EventLogParser()
_engine = RuleEngine()
_sanitizer = LogSanitizer()


# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def _severity_emoji(severity: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(
        severity, "✅"
    )


def _status_emoji(status: str) -> str:
    return {
        "Isolate": "🔴",
        "Alert": "🚨",
        "Queued": "⏱️",
        "Auto-closed": "✅",
    }.get(status, "ℹ️")


def _build_summary_df(results: list) -> pd.DataFrame:
    """Flatten analysis results into a pandas DataFrame for st.dataframe."""
    rows = []
    for idx, r in enumerate(results, 1):
        event = r["Event"]
        analysis = r.get("Analysis") or {}
        sev = analysis.get("Threat_Severity", "Low")
        status = analysis.get("Status", "Auto-closed")
        rows.append({
            "#": idx,
            "EventID": str(event.get("EventID", "—")),
            "Timestamp": (event.get("TimeCreated") or r.get("ProcessedAt", ""))[:19],
            "Computer": event.get("ComputerName", "—"),
            "Process": event.get("ProcessName", "—"),
            "Tactic": analysis.get("Tactic", "None"),
            "Technique": (
                f"{analysis.get('Technique_ID','—')} · {analysis.get('Technique_Name','—')}"
            ),
            "Confidence": int(analysis.get("Confidence_Score", 0)),
            "Risk": int(analysis.get("Risk_Score", 0)),
            "Severity": f"{_severity_emoji(sev)} {sev}",
            "Status": f"{_status_emoji(status)} {status}",
        })
    return pd.DataFrame(rows)


def _render_metrics(results: list) -> None:
    """Top-row executive metric cards."""
    total = len(results)
    critical = sum(
        1 for r in results
        if (r.get("Analysis") or {}).get("Threat_Severity") == "Critical"
    )
    high = sum(
        1 for r in results
        if (r.get("Analysis") or {}).get("Threat_Severity") == "High"
    )
    medium = sum(
        1 for r in results
        if (r.get("Analysis") or {}).get("Threat_Severity") == "Medium"
    )
    low = sum(
        1 for r in results
        if (r.get("Analysis") or {}).get("Threat_Severity") == "Low"
    )
    clean = sum(
        1 for r in results
        if (r.get("Analysis") or {}).get("Confidence_Score", 0) == 0
    )

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("📊 Total Events", total)
    c2.metric("🔴 Critical", critical,
              delta=f"{critical/total*100:.1f}%" if total else None,
              delta_color="inverse")
    c3.metric("🟠 High", high,
              delta=f"{high/total*100:.1f}%" if total else None,
              delta_color="inverse")
    c4.metric("🟡 Medium", medium,
              delta=f"{medium/total*100:.1f}%" if total else None,
              delta_color="off")
    c5.metric("🔵 Low", low,
              delta=f"{low/total*100:.1f}%" if total else None,
              delta_color="off")
    c6.metric("✅ Clean", clean,
              delta=f"{clean/total*100:.1f}%" if total else None,
              delta_color="normal")


def _render_summary_table(results: list) -> None:
    """Full-width summary dataframe with progress bars for numeric columns."""
    st.markdown('<p class="section-label">📋 Event Summary</p>', unsafe_allow_html=True)
    df = _build_summary_df(results)
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "#": st.column_config.NumberColumn("#", width="small"),
            "Confidence": st.column_config.ProgressColumn(
                "Confidence",
                min_value=0,
                max_value=10,
                format="%d/10",
                width="medium",
            ),
            "Risk": st.column_config.ProgressColumn(
                "Risk Score",
                min_value=0,
                max_value=12,
                format="%d/12",
                width="medium",
            ),
            "Severity": st.column_config.TextColumn("Severity", width="medium"),
            "Status": st.column_config.TextColumn("Status", width="large"),
            "Tactic": st.column_config.TextColumn("Tactic", width="medium"),
            "Technique": st.column_config.TextColumn("Technique", width="large"),
        },
    )


def _render_threat_details(results: list) -> None:
    """
    Expandable deep-dive cards for events with non-zero confidence.
    Uses native st.columns + st.expander — no raw HTML cards.
    Sorted: highest Risk_Score first.
    """
    actionable = [
        r for r in results
        if (r.get("Analysis") or {}).get("Confidence_Score", 0) > 0
    ]
    if not actionable:
        st.info("All events classified as benign / no detectable threats.")
        return

    # Sort by Risk_Score descending
    actionable.sort(
        key=lambda r: r.get("Analysis", {}).get("Risk_Score", 0), reverse=True
    )

    st.markdown(
        '<p class="section-label">🔍 Threat Details (non-benign, highest risk first)</p>',
        unsafe_allow_html=True,
    )

    for r in actionable:
        event = r["Event"]
        analysis = r.get("Analysis") or {}

        # Find the original index in the full results list
        orig_idx = results.index(r) + 1

        sev = analysis.get("Threat_Severity", "Low")
        emoji = _severity_emoji(sev)
        tactic = analysis.get("Tactic", "None")
        risk = analysis.get("Risk_Score", 0)
        process = event.get("ProcessName", "Unknown")

        label = (
            f"{emoji} #{orig_idx} · EventID {event.get('EventID','?')} · "
            f"{tactic} · {sev} (Risk {risk}/12) · {process}"
        )

        with st.expander(label, expanded=(sev == "Critical")):
            left, right = st.columns(2)

            # ── Left: Event Technical Details ─────────────────────────────
            with left:
                st.markdown("**🖥 Event Technical Details**")
                st.markdown(f"**EventID:** `{event.get('EventID','—')}`")
                st.markdown(f"**Timestamp:** `{event.get('TimeCreated','—')}`")
                st.markdown(f"**Computer:** `{event.get('ComputerName','—')}`")
                st.markdown(f"**Process:** `{event.get('ProcessName','—')}`")

                if event.get("ParentProcessName"):
                    st.markdown(f"**Parent:** `{event.get('ParentProcessName')}`")

                # Sanitize principals before display (LogSanitizer routing intact)
                subject = (
                    f"{event.get('SubjectDomainName','')}\\{event.get('SubjectUserName','')}"
                    if event.get("SubjectUserName")
                    else ""
                )
                target = (
                    f"{event.get('TargetDomainName','')}\\{event.get('TargetUserName','')}"
                    if event.get("TargetUserName")
                    else ""
                )
                if subject.strip("\\"):
                    clean_subj = _sanitizer.sanitize_principal(subject.strip("\\"))
                    st.markdown(f"**Subject User:** `{clean_subj}`")
                if target.strip("\\"):
                    clean_tgt = _sanitizer.sanitize_principal(target.strip("\\"))
                    st.markdown(f"**Target User:** `{clean_tgt}`")

                if event.get("CommandLine"):
                    # Sanitize command line for display
                    clean_cmd = _sanitizer.sanitize_all(event["CommandLine"])
                    st.markdown("**Command Line:**")
                    st.code(clean_cmd, language="bash")

            # ── Right: MITRE Analysis ──────────────────────────────────────
            with right:
                st.markdown("**🎯 MITRE ATT&CK Analysis**")
                st.markdown(f"**Tactic:** `{analysis.get('Tactic','—')}`")
                st.markdown(
                    f"**Technique:** `{analysis.get('Technique_ID','—')} — "
                    f"{analysis.get('Technique_Name','—')}`"
                )
                st.markdown(
                    f"**Kill Chain Phase:** `{analysis.get('Kill_Chain_Phase','—')}`"
                )
                st.markdown(
                    f"**Confidence:** `{analysis.get('Confidence_Score', 0)}/10`"
                )
                st.markdown(f"**Risk Score:** `{analysis.get('Risk_Score', 0)}/12`")
                st.markdown(
                    f"**Severity:** {_severity_emoji(sev)} `{sev}`"
                )
                status = analysis.get("Status", "Auto-closed")
                st.markdown(
                    f"**Workflow Status:** {_status_emoji(status)} `{status}`"
                )

            st.divider()

            # ── IOCs ──────────────────────────────────────────────────────
            iocs = analysis.get("IOCs", [])
            if iocs:
                st.markdown("**🔎 Indicators of Compromise (IOCs)**")
                st.code("  |  ".join(iocs), language=None)

            # ── Justification + Mitigation ─────────────────────────────────
            jcol, mcol = st.columns(2)
            with jcol:
                st.markdown("**📄 Justification**")
                st.info(analysis.get("Justification", "—"))
            with mcol:
                st.markdown("**💡 Recommended Mitigations**")
                st.success(
                    analysis.get("Mitigation_Steps", "No mitigation steps available.")
                )


def _build_export_csv(results: list) -> str:
    rows = []
    for r in results:
        event = r["Event"]
        analysis = r.get("Analysis") or {}
        score = analysis.get("Confidence_Score", 0)
        iocs_raw = analysis.get("IOCs", [])
        iocs_str = " | ".join(str(i) for i in iocs_raw) if iocs_raw else "None"
        rows.append({
            "Timestamp": r.get("ProcessedAt", ""),
            "EventID": event.get("EventID", ""),
            "Computer": event.get("ComputerName", ""),
            "Process": event.get("ProcessName", ""),
            "Tactic": analysis.get("Tactic", "None"),
            "Technique_ID": analysis.get("Technique_ID", "None"),
            "Technique_Name": analysis.get("Technique_Name", "None"),
            "Confidence_Score": score,
            "Risk_Score": analysis.get("Risk_Score", 0),
            "Threat_Severity": analysis.get("Threat_Severity", ""),
            "Kill_Chain_Phase": analysis.get("Kill_Chain_Phase", ""),
            "Status": analysis.get("Status", ""),
            "IOCs": iocs_str,
            "Justification": analysis.get("Justification", ""),
            "Mitigation_Steps": analysis.get("Mitigation_Steps", ""),
        })
    return pd.DataFrame(rows).to_csv(index=False)


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR — Input + Controls
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:

    # Engine status
    st.markdown(
        f"""
        <div class="section-label">Engine Status</div>
        <div style="
            background:rgba(0,255,136,0.08);
            border:1px solid rgba(0,255,136,0.35);
            border-radius:8px;padding:10px 14px;margin-bottom:12px;">
            <span style="color:#00FF88;font-weight:600;">⚙ Deterministic Rule Engine</span><br>
            <span style="font-size:0.75rem;color:#A0A0A0;font-family:'Roboto Mono',monospace;">
                {len(__import__('event_mapper').EVENT_ID_RULES)} EventID rules &nbsp;·&nbsp;
                {len(__import__('event_mapper').PROCESS_RULES)} process rules
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.toggle(
        "🌙 Dark Mode",
        value=st.session_state.dark_mode,
        key="dark_mode",
    )
    st.divider()

    st.markdown('<p class="section-label">📂 Telemetry Input</p>', unsafe_allow_html=True)

    # Consolidated input — single radio toggle (cleaner than two separate tabs)
    input_mode = st.radio(
        "Input method",
        ["📁 Upload File", "📂 File Path"],
        horizontal=True,
        label_visibility="collapsed",
        key="input_mode",
    )

    uploaded_file = None
    file_path = ""

    if input_mode == "📁 Upload File":
        uploaded_file = st.file_uploader(
            "Drop a .csv or .json event log",
            type=["csv", "json"],
            label_visibility="collapsed",
            key="file_uploader",
        )
        if uploaded_file:
            st.caption(
                f"📄 `{uploaded_file.name}` — "
                f"{uploaded_file.size / 1024:.1f} KB"
            )
    else:
        file_path = st.text_input(
            "Local file path",
            placeholder=r"C:\logs\security.json",
            label_visibility="collapsed",
            key="file_path_input",
        )
        if file_path:
            # Harden path traversal: resolve real path and check boundary
            base_dir = os.path.abspath(os.getcwd())
            target_path = os.path.abspath(file_path)
            if not target_path.startswith(base_dir):
                st.error("❌ Security Block: Paths must be strictly within the workspace folder.")
            elif os.path.exists(file_path):
                st.success(f"✅ Found: `{os.path.basename(file_path)}`")
            else:
                st.error("❌ File not found — check the path.")

    # Analyze button
    is_safe = True
    if file_path:
        base_dir = os.path.abspath(os.getcwd())
        target_path = os.path.abspath(file_path)
        is_safe = target_path.startswith(base_dir)

    can_analyze = bool(uploaded_file) or bool(
        file_path and os.path.exists(file_path) and is_safe
    )
    analyze = st.button(
        "🔍 Run AURA Analysis",
        type="primary",
        use_container_width=True,
        disabled=not can_analyze,
        key="analyze_btn",
    )

    st.divider()

    # ── Export Controls (only shown after analysis) ────────────────────────
    if st.session_state.analysis_results:
        st.markdown('<p class="section-label">📥 Export</p>', unsafe_allow_html=True)
        fmt = st.radio(
            "Format", ["CSV", "JSON"], horizontal=True, key="export_fmt"
        )

        if fmt == "CSV":
            export_bytes = _build_export_csv(st.session_state.analysis_results).encode()
            mime = "text/csv"
            ext = "csv"
        else:
            export_bytes = json.dumps(
                st.session_state.analysis_results, indent=2
            ).encode()
            mime = "application/json"
            ext = "json"

        fname = f"AURA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
        st.download_button(
            label=f"⬇ Download {fmt} Report",
            data=export_bytes,
            file_name=fname,
            mime=mime,
            use_container_width=True,
            key="download_btn",
        )

        if st.button("🗑 Clear Results", use_container_width=True, key="clear_btn"):
            st.session_state.analysis_results = []
            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# ANALYSIS PROCESSING
# ══════════════════════════════════════════════════════════════════════════════

if analyze:
    with st.status("⚙ AURA Rule Engine processing telemetry…", expanded=True) as status:
        try:
            events = []

            # Parse input
            if uploaded_file:
                suffix = uploaded_file.name.rsplit(".", 1)[-1]
                events = _parser.parse_uploaded(uploaded_file.getvalue(), suffix)
            elif file_path and os.path.exists(file_path):
                ft = _parser.detect_file_type(file_path)
                events = (
                    _parser.parse_csv(file_path)
                    if ft == "csv"
                    else _parser.parse_json(file_path)
                )

            if not events:
                status.update(label="❌ No events found in file.", state="error")
                st.error("No events found. Verify the file contains valid log data.")
                st.stop()

            status.update(
                label=f"🔍 Classifying {len(events)} events against MITRE ATT&CK rules…",
                state="running",
            )

            # Progress bar — deterministic engine is fast; bar gives visual feedback
            progress = st.progress(0, text="Initialising…")
            results = []
            
            start_time = time.time()
            
            for i, event in enumerate(events):
                analysis = _engine.analyze_event(event)
                results.append({
                    "Event": event,
                    "Analysis": analysis,
                    "ProcessedAt": datetime.now().isoformat(),
                })
                # Prevent Streamlit UI from bottlenecking the deterministic engine on massive logs
                if i % max(1, len(events) // 100) == 0 or i == len(events) - 1:
                    pct = int((i + 1) / len(events) * 100)
                    progress.progress(pct, text=f"Classified {i+1}/{len(events)} events")

            end_time = time.time()
            execution_time = end_time - start_time

            progress.empty()
            st.session_state.analysis_results = results
            st.session_state.last_execution_time = execution_time

            # Quick summary counts for status message
            critical_n = sum(
                1 for r in results
                if r["Analysis"].get("Threat_Severity") == "Critical"
            )
            high_n = sum(
                1 for r in results
                if r["Analysis"].get("Threat_Severity") == "High"
            )
            status.update(
                label=(
                    f"✅ Analysis complete in {execution_time:.3f} s — {len(results)} events classified. "
                    f"🔴 {critical_n} Critical · 🟠 {high_n} High"
                ),
                state="complete",
            )

        except Exception as exc:
            status.update(label=f"❌ Analysis failed: {exc}", state="error")
            st.error(f"Analysis failed: {exc}")
            st.stop()


# ══════════════════════════════════════════════════════════════════════════════
# RESULTS DISPLAY
# ══════════════════════════════════════════════════════════════════════════════

if st.session_state.analysis_results:
    results = st.session_state.analysis_results

    _render_metrics(results)
    st.divider()
    _render_summary_table(results)
    st.divider()
    _render_threat_details(results)

else:
    # ── Welcome / Landing State ────────────────────────────────────────────
    st.markdown("## 🛡️ AURA Threat Intelligence Platform")
    st.markdown(
        "Upload a Windows Event Log file in the sidebar and click **Run AURA Analysis** "
        "to begin deterministic MITRE ATT&CK mapping."
    )

    c1, c2, c3 = st.columns(3)
    with c1:
        st.info(
            "**⚙ Deterministic Engine**\n\n"
            "Rule-based MITRE ATT&CK mapping with zero AI/API latency. "
            "Results are instantaneous and fully reproducible."
        )
    with c2:
        st.info(
            "**📋 High-Density Dashboard**\n\n"
            "Executive metrics, filterable event table, and deep-dive "
            "expanders for every actionable threat. Export to CSV or JSON."
        )
    with c3:
        st.info(
            "**🔎 Coverage**\n\n"
            f"Covers **{len(__import__('event_mapper').EVENT_ID_RULES)} Windows Event IDs** "
            f"and **{len(__import__('event_mapper').PROCESS_RULES)} process/command-line patterns** "
            "across 11 MITRE ATT&CK tactics."
        )

    with st.expander("📄 Supported Input Format (JSON example)"):
        st.code(
            json.dumps(
                {
                    "EventID": 4688,
                    "TimeCreated": "2024-03-07T10:15:30Z",
                    "ComputerName": "WIN-SEC01",
                    "ProcessName": "powershell.exe",
                    "CommandLine": "powershell.exe -EncodedCommand <base64>",
                    "ParentProcessName": "explorer.exe",
                    "SubjectUserName": "admin",
                    "SubjectDomainName": "CORP",
                    "TargetUserName": "SYSTEM",
                    "TargetDomainName": "NT AUTHORITY",
                },
                indent=2,
            ),
            language="json",
        )

# ─── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.caption(
    "**AURA** — Automated User-Risk Analysis &nbsp;|&nbsp; "
    "Rule-based MITRE ATT&CK v14 mapping &nbsp;|&nbsp; "
    "No external APIs · No data leaves your machine"
)
