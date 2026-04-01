#!/usr/bin/env python3
"""
AURA: Automated User-Risk Analysis - Web Interface

A professional cybersecurity awareness web application that maps raw telemetry 
to the MITRE ATT&CK framework using GenAI.

Frontend for the AURA threat intelligence system.
"""

import streamlit as st
import tempfile
import os
import logging
import time
import pandas as pd
import json
from datetime import datetime

def get_threat_category(score):
        """Categorize threat level based on confidence score."""
        if score >= 9:
            return "Critical", "#8B0000", "🚨 CRITICAL THREAT DETECTED"
        elif score >= 7:
            return "High", "#FF4500", "⚠️ HIGH THREAT LEVEL"
        elif score >= 4:
            return "Medium", "#FFA500", "⚠️ MEDIUM THREAT LEVEL"
        elif score >= 1:
            return "Low", "#1E40AF", "ℹ️ LOW THREAT LEVEL"
        else:
            return "Negligible", "#228B22", "✅ NO THREAT DETECTED"

def create_trust_gauge(score):
    """Create a visual trust gauge for confidence scores."""
    filled_segments = "█" * score
    empty_segments = "░" * (10 - score)
    return f"[{filled_segments}{empty_segments}] {score}/10"

def get_threat_tier(score):
    """Categorize threat level based on confidence score with color coding."""
    if score >= 8:
        return "Critical", "#FF3131", "🔴"
    elif score >= 5:
        return "Moderate", "#FFA500", "🟠"
    elif score >= 1:
        return "Low", "#FFD700", "🟡"
    else:
        return "None", "#00D1FF", "🔵"

# Configure logging for debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import backend classes from event_mapper.py
from event_mapper import EventLogParser, GenAIAnalyzer

# Page Configuration with menu cleanup
st.set_page_config(
    page_title="AURA | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items=None
)

# Custom CSS for AURA Elite UI - Cyber-Pro Dark Theme
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap');

/* Global Typography & Dark Theme */
body {
    font-family: 'Inter', sans-serif !important;
    background-color: #0E1117 !important;
    color: #E0E0E0 !important;
}

/* Main Content Area */
.stApp {
    background-color: #0E1117 !important;
}

.stApp > div > div > div > div > div > div {
    background-color: #0E1117 !important;
}

/* Card/Container Backgrounds */
.stDataFrame, .stTable, .stMetric, .stAlert, .stInfo, .stSuccess, .stWarning, .stError {
    background-color: #1A1C24 !important;
    border: 1px solid #2A2D3A !important;
}

/* Typography */
.monospace, .stCode, code, pre {
    font-family: 'Roboto Mono', monospace !important;
    background-color: #1A1C24 !important;
    color: #E0E0E0 !important;
}

/* Custom Header Overlay */
.custom-header {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    height: 60px;
    background: linear-gradient(135deg, #0E1117 0%, #1A1C24 100%);
    color: #E0E0E0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 2rem;
    z-index: 9999;
    box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    animation: slideDown 0.6s ease-out;
    border-bottom: 2px solid #00D1FF;
}

.header-left h1 {
    font-family: 'Inter', sans-serif;
    font-size: 1.3rem;
    font-weight: 700;
    margin: 0;
    animation: fadeIn 1s ease-out;
    color: #00D1FF;
}

.header-right {
    display: flex;
    align-items: center;
}

.github-button {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: linear-gradient(135deg, #00D1FF 0%, #00B8E6 100%);
    color: #0E1117;
    text-decoration: none;
    padding: 8px 16px;
    border-radius: 20px;
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    font-size: 0.85rem;
    transition: all 0.2s ease;
    border: 1px solid #00D1FF;
}

.github-button:hover {
    background: linear-gradient(135deg, #00B8E6 0%, #00A8D6 100%);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 209, 255, 0.4);
}

.github-button svg {
    width: 16px;
    height: 16px;
}

/* Header Animations */
@keyframes slideDown {
    from {
        transform: translateY(-100%);
        opacity: 0;
    }
    to {
        transform: translateY(0);
        opacity: 1;
    }
}

@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(-10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* Hide default Streamlit header and menu */
.stApp > div > div > div > div > div > div > header {
    visibility: hidden;
    height: 0px;
}

.stApp > div > div > div > div > div > div > header > div {
    visibility: hidden;
}

/* Hide Deploy button and three-dot menu */
.stDeployButton, .stMainMenu {
    visibility: hidden !important;
    display: none !important;
}

/* Add top padding to account for fixed header */
.stApp > div {
    padding-top: 80px !important;
}

/* Section Headers Styling */
.section-header {
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
    color: #00D1FF !important;
    margin-bottom: 1rem !important;
    background: linear-gradient(135deg, #1A1C24 0%, #2A2D3A 100%) !important;
    padding: 0.75rem !important;
    border-radius: 8px !important;
    border: 1px solid #00D1FF !important;
}

/* Technical Data Styling */
.technical-data {
    font-family: 'Roboto Mono', monospace !important;
    background: #1A1C24 !important;
    padding: 0.5rem !important;
    border-radius: 4px !important;
    border-left: 3px solid #00D1FF !important;
    color: #E0E0E0 !important;
}

/* Button Enhancement - Electric Blue */
.stButton > button {
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    transition: all 0.2s ease !important;
    background-color: #00D1FF !important;
    color: #0E1117 !important;
    border: 1px solid #00D1FF !important;
}

.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 12px rgba(0, 209, 255, 0.4) !important;
    background-color: #00B8E6 !important;
}

.stButton > button:disabled {
    background-color: #2A2D3A !important;
    color: #666 !important;
    border: 1px solid #2A2D3A !important;
}

/* Primary Button Styling */
.stButton > button[data-testid="baseButton-primary"] {
    background: linear-gradient(135deg, #00D1FF 0%, #00B8E6 100%) !important;
    border: none !important;
    color: #0E1117 !important;
}

/* Metric Cards */
.stMetric {
    background: #1A1C24 !important;
    border: 1px solid #2A2D3A !important;
    border-radius: 8px !important;
    padding: 1rem !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.3) !important;
    transition: all 0.2s ease !important;
    color: #E0E0E0 !important;
}

.stMetric:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 4px 12px rgba(0, 209, 255, 0.2) !important;
    border: 1px solid #00D1FF !important;
}

/* File Upload Styling */
.stFileUploader {
    border: 2px dashed #00D1FF !important;
    border-radius: 8px !important;
    background: #1A1C24 !important;
    transition: all 0.2s ease !important;
}

.stFileUploader:hover {
    border-color: #00B8E6 !important;
    background: #2A2D3A !important;
}

.stFileUploader label {
    color: #E0E0E0 !important;
}

/* Radio Button Styling - High Contrast Fix */
.stRadio > div {
    background: #1A1C24 !important;
    border: 1px solid #00D1FF !important;
    border-radius: 8px !important;
    padding: 0.75rem !important;
}

.stRadio > div > label {
    color: #E0E0E0 !important;
    font-weight: 500 !important;
}

.stRadio > div > label > div[data-baseweb="radio"] {
    background: #1A1C24 !important;
    border: 2px solid #00D1FF !important;
}

.stRadio > div > label > div[data-baseweb="radio"]:checked {
    background: #00D1FF !important;
    border-color: #00D1FF !important;
}

/* Force Radio Button Text Visibility */
.st-emotion-cache-1v0g3j9, .st-emotion-cache-1l2z25r, 
.st-emotion-cache-1w3q4h5, .st-emotion-cache-1i8g5v8 {
    color: #E0E0E0 !important;
    background: #1A1C24 !important;
}

/* Expander Styling */
.streamlit-expanderHeader {
    background: linear-gradient(135deg, #1A1C24 0%, #2A2D3A 100%) !important;
    border: 1px solid #2A2D3A !important;
    border-radius: 8px !important;
    font-weight: 500 !important;
    color: #E0E0E0 !important;
}

.streamlit-expanderHeader:hover {
    border: 1px solid #00D1FF !important;
}

/* Sidebar Styling */
.css-1d391kg {
    background: #0E1117 !important;
}

.css-1d391kg > div > div {
    background: #1A1C24 !important;
    border: 1px solid #2A2D3A !important;
}

/* Input Fields */
.stTextInput > div > div > input {
    background: #1A1C24 !important;
    border: 1px solid #2A2D3A !important;
    color: #E0E0E0 !important;
}

.stTextInput > div > div > input:focus {
    border-color: #00D1FF !important;
}

/* Text Area */
.stTextArea > div > div > textarea {
    background: #1A1C24 !important;
    border: 1px solid #2A2D3A !important;
    color: #E0E0E0 !important;
}

/* Select Box */
.stSelectbox > div > div > select {
    background: #1A1C24 !important;
    border: 1px solid #2A2D3A !important;
    color: #E0E0E0 !important;
}

/* Alert Messages */
.stAlert {
    background: #1A1C24 !important;
    border: 1px solid #2A2D3A !important;
    color: #E0E0E0 !important;
}

.stAlert > div {
    color: #E0E0E0 !important;
}

/* Success Message */
.stAlert[data-testid="stAlert-container"]:has([data-testid="stAlert-icon-success"]) {
    border: 1px solid #00D1FF !important;
}

/* Download Button */
.stDownloadButton > button {
    background: #00D1FF !important;
    color: #0E1117 !important;
    border: 1px solid #00D1FF !important;
}

.stDownloadButton > button:hover {
    background: #00B8E6 !important;
    border-color: #00B8E6 !important;
}

/* Status Container */
.stStatus {
    background: #1A1C24 !important;
    border: 1px solid #2A2D3A !important;
    color: #E0E0E0 !important;
}

/* Progress Bar - Red for Active Threat Scanning */
.stProgress > div > div > div {
    background: #FF3131 !important;
    animation: pulse-red 1.5s infinite;
}

/* Red Alert Pulsing for High Confidence Events */
.danger-pulse {
    border: 2px solid #FF3131 !important;
    animation: pulse-red 1.5s infinite !important;
    box-shadow: 0 0 10px rgba(255, 49, 49, 0.5) !important;
}

@keyframes pulse-red {
    0% {
        border-color: #FF3131;
        box-shadow: 0 0 5px rgba(255, 49, 49, 0.5);
    }
    50% {
        border-color: #FF6B6B;
        box-shadow: 0 0 15px rgba(255, 49, 49, 0.8);
    }
    100% {
        border-color: #FF3131;
        box-shadow: 0 0 5px rgba(255, 49, 49, 0.5);
    }
}

/* High Threat Count Badge - Red Background */
.high-threat-badge {
    background: #FF3131 !important;
    color: #FFFFFF !important;
    border: 1px solid #FF3131 !important;
}

/* Force White Text for Radio Buttons */
.stRadio > div > label,
.stRadio > div > label > span,
.st-emotion-cache-1v0g3j9, .st-emotion-cache-1l2z25r, 
.st-emotion-cache-1w3q4h5, .st-emotion-cache-1i8g5v8 {
    color: #FFFFFF !important;
    font-weight: 500 !important;
}

/* Custom Threat Card Styling */
.threat-card {
    background: #1A1C24 !important;
    border: 2px solid #2A2D3A !important;
    border-radius: 8px !important;
    padding: 1rem !important;
    margin-bottom: 1rem !important;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3) !important;
    transition: all 0.2s ease !important;
}

.threat-card:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 4px 8px rgba(0,0,0,0.4) !important;
}

.threat-card table {
    width: 100% !important;
    border-collapse: collapse !important;
    color: #E0E0E0 !important;
    font-family: 'Inter', sans-serif !important;
}

.threat-card td {
    padding: 0.5rem !important;
    vertical-align: top !important;
    border-bottom: 1px solid #2A2D3A !important;
}

.threat-card td:last-child {
    border-bottom: none !important;
}

.threat-card .threat-badge {
    display: inline-block !important;
    padding: 0.25rem 0.75rem !important;
    border-radius: 20px !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    color: #0E1117 !important;
    margin-bottom: 0.5rem !important;
}

.threat-card .event-id {
    font-family: 'Roboto Mono', monospace !important;
    font-weight: 600 !important;
    color: #00D1FF !important;
}

.threat-card .process-name {
    font-family: 'Roboto Mono', monospace !important;
    color: #E0E0E0 !important;
}

.threat-card .mitre-tactic {
    color: #00D1FF !important;
    font-weight: 500 !important;
}

.threat-card .mitre-technique {
    font-family: 'Roboto Mono', monospace !important;
    color: #FFD700 !important;
}

.threat-card .justification {
    color: #E0E0E0 !important;
    font-size: 0.9rem !important;
    line-height: 1.4 !important;
    max-height: 3.6rem !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    display: -webkit-box !important;
    -webkit-line-clamp: 2 !important;
    -webkit-box-orient: vertical !important;
}

.threat-card .command-line {
    background: #0E1117 !important;
    border: 1px solid #2A2D3A !important;
    border-radius: 4px !important;
    padding: 0.75rem !important;
    font-family: 'Roboto Mono', monospace !important;
    font-size: 0.85rem !important;
    color: #00D1FF !important;
    overflow-x: auto !important;
    white-space: pre-wrap !important;
    word-break: break-all !important;
}

.threat-card .column-header {
    font-weight: 600 !important;
    color: #00D1FF !important;
    font-size: 0.85rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
    margin-bottom: 0.25rem !important;
}
</style>
""", unsafe_allow_html=True)

# Custom Header Overlay with GitHub Button
st.markdown("""
<div class="custom-header">
    <div class="header-left">
        <h1>🛡️ AURA | Threat Intelligence</h1>
    </div>
    <div class="header-right">
        <a href="https://github.com/AbhijeetSharma/AURA" target="_blank" class="github-button">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55.17.55.38 0 .19-.01.82-.01 1.49-2.71.25-3.91 1.63-3.91H5.5v1.16h1.77c.09 1.16.49 2.32 1.34 2.32 1.51 0 2.7-1.3 2.7-2.8 0-.5-.1-.9-.25-1.1h-2.7v2.31h3.1c.19.67.49 1.34.89 2 1.34 2.38 0 4.23-2.88 4.23-5.4 0-.34-.02-.7-.05-1.05z"/>
            </svg>
            📂 View on GitHub
        </a>
    </div>
</div>
""", unsafe_allow_html=True)

# Initialize session state
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = []

# Initialize variables
uploaded_file = None
file_path = None

# Sidebar Configuration
with st.sidebar:
    st.markdown('<div class="section-header">🔧 Configuration</div>', unsafe_allow_html=True)
    
    # Compact Badge Styling
    st.markdown("""
    <div style="
        background: linear-gradient(135deg, #1A1C24 0%, #2A2D3A 100%);
        border: 1px solid #00D1FF;
        border-radius: 20px;
        padding: 8px 16px;
        margin-bottom: 10px;
        display: inline-block;
        font-family: 'Inter', sans-serif;
        font-size: 0.85rem;
        font-weight: 500;
        color: #00D1FF;
    ">
        🟢 AURA Engine Status: Online
    </div>
    """, unsafe_allow_html=True)
    
    # Display current model as compact badge
    try:
        analyzer = GenAIAnalyzer()
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #1A1C24 0%, #2A2D3A 100%);
            border: 1px solid #2A2D3A;
            border-radius: 20px;
            padding: 8px 16px;
            margin-bottom: 10px;
            display: inline-block;
            font-family: 'Roboto Mono', monospace;
            font-size: 0.8rem;
            color: #E0E0E0;
        ">
            🤖 Model: {analyzer.model_name}
        </div>
        """, unsafe_allow_html=True)
    except Exception as e:
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #1A1C24 0%, #2A2D3A 100%);
            border: 1px solid #ff4444;
            border-radius: 20px;
            padding: 8px 16px;
            margin-bottom: 10px;
            display: inline-block;
            font-family: 'Inter', sans-serif;
            font-size: 0.85rem;
            color: #ff4444;
        ">
            ❌ Model initialization failed
        </div>
        """, unsafe_allow_html=True)

# Main Interface
col1, col2 = st.columns([2, 1])

with col1:
    st.markdown('<div class="section-header">📊 Telemetry Input</div>', unsafe_allow_html=True)
    
    # Input Method Selection
    input_method = st.radio(
        "Choose input method:",
        ["📁 File Upload", "📂 Direct File Path"],
        horizontal=True,
        key="input_method_radio"
    )
    
    if input_method == "📁 File Upload":
        uploaded_file = st.file_uploader(
            "Upload Windows Event Log file",
            type=['csv', 'json'],
            help="Supported formats: CSV, JSON containing Windows Event Log data",
            label_visibility="collapsed",
            key='file_uploader_main'
        )
        
        if uploaded_file is not None:
            # Compact metadata display - single line with technical styling
            st.markdown(f'<div class="technical-data">📄 {uploaded_file.name} | 💾 {uploaded_file.size / 1024:.1f} KB</div>', unsafe_allow_html=True)
    
    else:  # Direct File Path
        file_path = st.text_input(
            "Enter local file path:",
            placeholder="C:\\path\\to\\your\\eventlog.json",
            key='file_path_input_main'
        )
        
        if file_path and os.path.exists(file_path):
            st.success(f"File found: {os.path.basename(file_path)}")
        elif file_path:
            st.error("File not found. Please check the path.")

# Persistent Action Column (defined after file input)
with col2:
    st.markdown('<div class="section-header">⚡ Quick Actions</div>', unsafe_allow_html=True)
    
    # Ironclad Control Panel - Always Visible
    with st.container():
        # Analyze Button - Always visible
        analyze_button = st.button(
            "🔍 Analyze Telemetry with AURA",
            type="primary",
            key="aura_analyze_final",
            use_container_width=True,
            disabled=(uploaded_file is None and not file_path)
        )
        
        # Export Format Selection - Always visible
        export_format = st.radio(
            "Export Format",
            ["CSV", "JSON"],
            horizontal=True,
            key="aura_format_select"
        )
        
        # Prepare export data before button definition
        if st.session_state.analysis_results:
            if export_format == "CSV":
                # Create CSV data
                export_data_list = []
                for result in st.session_state.analysis_results:
                    event = result['Event']
                    analysis = result['Analysis']
                    
                    if analysis:
                        score = analysis.get('Confidence_Score', 0)
                        category, _, _ = get_threat_category(score)
                        
                        # Format threat status for report
                        if score == 0:
                            threat_status = "No Threat Detected"
                            tactic = "N/A"
                            technique = "N/A"
                        else:
                            threat_status = f"{category} ({score}/10)"
                            tactic = analysis.get('Tactic', 'Unknown')
                            technique = f"{analysis.get('Technique_ID', 'Unknown')} - {analysis.get('Technique_Name', 'Unknown')}"
                        
                        export_data_list.append({
                            'Timestamp': result.get('ProcessedAt', 'Unknown'),
                            'EventID': event.get('EventID', 'Unknown'),
                            'Process': event.get('ProcessName', 'Unknown'),
                            'Computer': event.get('ComputerName', 'Unknown'),
                            'Tactic': tactic,
                            'Technique': technique,
                            'Confidence_Score': score,
                            'Threat_Level': threat_status,
                            'Justification': analysis.get('Justification', 'No justification provided')
                        })
                    else:
                        export_data_list.append({
                            'Timestamp': result.get('ProcessedAt', 'Unknown'),
                            'EventID': event.get('EventID', 'Unknown'),
                            'Process': event.get('ProcessName', 'Unknown'),
                            'Computer': event.get('ComputerName', 'Unknown'),
                            'Tactic': 'Analysis Failed',
                            'Technique': 'Analysis Failed',
                            'Confidence_Score': 0,
                            'Threat_Level': 'Error',
                            'Justification': 'Analysis failed - check logs'
                        })
                
                df = pd.DataFrame(export_data_list)
                export_data = df.to_csv(index=False)
                file_extension = "csv"
                mime_type = "text/csv"
                button_label = "📥 Export CSV Intelligence"
                
            else:  # JSON
                export_data = json.dumps(st.session_state.analysis_results, indent=2)
                file_extension = "json"
                mime_type = "application/json"
                button_label = "📥 Export JSON Intelligence"
            
            fname = f"AURA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_extension}"
        else:
            export_data = ""
            fname = ""
            button_label = "📥 Download Report (No Data)"
        
        # Download Button - Always visible
        st.download_button(
            label=button_label,
            data=export_data,
            file_name=fname,
            mime=mime_type if st.session_state.analysis_results else "text/plain",
            key="aura_download_final",
            use_container_width=True,
            disabled=not st.session_state.analysis_results
        )
        
        # Clear Results Button - Always visible
        if st.button("🗑️ Clear Results", key="aura_clear_final", use_container_width=True):
            st.session_state.analysis_results = []
            st.rerun()

# Analysis Processing
if analyze_button:
    # Use st.status for batch progress tracking
    with st.status("🔄 AURA Engine is analyzing threat telemetry...", expanded=True) as status:
        try:
            # Initialize backend components
            parser = EventLogParser()
            analyzer = GenAIAnalyzer()
            
            # Get input data
            events = []
            
            if uploaded_file:
                # Handle uploaded file
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{uploaded_file.name.split('.')[-1]}") as tmp_file:
                        tmp_file.write(uploaded_file.getvalue())
                        tmp_file_path = tmp_file.name
                    
                    try:
                        # Use the correct method names from EventLogParser class
                        file_type = parser.detect_file_type(tmp_file_path)
                        if file_type == 'csv':
                            events = parser.parse_csv(tmp_file_path)
                        elif file_type == 'json':
                            events = parser.parse_json(tmp_file_path)
                        else:
                            raise ValueError(f"Unsupported file type: {file_type}")
                    finally:
                        os.unlink(tmp_file_path)
                except Exception as e:
                    st.error(f"❌ Error parsing uploaded file: {str(e)}")
                    st.stop()
                    
            elif file_path and os.path.exists(file_path):
                # Handle direct file path
                file_type = parser.detect_file_type(file_path)
                if file_type == 'csv':
                    events = parser.parse_csv(file_path)
                elif file_type == 'json':
                    events = parser.parse_json(file_path)
                else:
                    raise ValueError(f"Unsupported file type: {file_type}")
            
            if not events:
                st.error("❌ No events found in the provided file")
                st.stop()
            
            # Process events with batching for efficiency
            results = []
            batch_size = 25  # Optimized sweet spot for speed without overwhelming API
            total_batches = (len(events) + batch_size - 1) // batch_size
            
            for batch_start in range(0, len(events), batch_size):
                batch_end = min(batch_start + batch_size, len(events))
                batch_events = events[batch_start:batch_end]
                current_batch = batch_start // batch_size + 1
                
                status.update(
                    label=f"🔄 Processing batch {current_batch}/{total_batches} (Events {batch_start+1}-{batch_end})",
                    state="running"
                )
                
                # Get batch analysis
                try:
                    batch_analyses = analyzer.analyze_batch(batch_events)
                    
                    # Combine each event with its analysis
                    for i, (event, analysis) in enumerate(zip(batch_events, batch_analyses)):
                        result = {
                            'Event': event,
                            'Analysis': analysis,
                            'ProcessedAt': datetime.now().isoformat()
                        }
                        results.append(result)
                        
                except Exception as e:
                    error_msg = str(e)
                    if "overloaded" in error_msg.lower() or "retry" in error_msg.lower():
                        st.toast("AURA is retrying due to high demand...")
                        # Continue with next batch instead of stopping completely
                        for event in batch_events:
                            result = {
                                'Event': event,
                                'Analysis': None,
                                'ProcessedAt': datetime.now().isoformat()
                            }
                            results.append(result)
                    else:
                        st.error(f"❌ Batch Analysis Failed for Events {batch_start+1}-{batch_end}: {str(e)}")
                        logger.exception(f"Batch Analysis Failed for Events {batch_start+1}-{batch_end}")
                        # Add failed results as None
                        for event in batch_events:
                            result = {
                                'Event': event,
                                'Analysis': None,
                                'ProcessedAt': datetime.now().isoformat()
                            }
                            results.append(result)
                
                # Add 1-second delay between batches for rate limiting
                if batch_end < len(events):
                    time.sleep(1)
            
            # Store results in session state
            st.session_state.analysis_results = results
            
            status.update(
                label="✅ Analysis complete!",
                state="complete"
            )
            
            st.success(f"✅ Analysis complete! Processed {len(results)} events")
            
        except Exception as e:
            status.update(
                label="❌ Analysis failed",
                state="error"
            )
            st.error(f"❌ Analysis failed: {str(e)}")
            st.stop()

# Results Display
if st.session_state.analysis_results:
    st.markdown('<div class="section-header">🎯 Threat Analysis Results</div>', unsafe_allow_html=True)
    
    # Summary Metrics
    total_events = len(st.session_state.analysis_results)
    critical_count = sum(1 for r in st.session_state.analysis_results 
                        if r['Analysis'] and r['Analysis'].get('Confidence_Score', 0) >= 9)
    high_count = sum(1 for r in st.session_state.analysis_results 
                    if r['Analysis'] and 7 <= r['Analysis'].get('Confidence_Score', 0) <= 8)
    medium_count = sum(1 for r in st.session_state.analysis_results 
                      if r['Analysis'] and 4 <= r['Analysis'].get('Confidence_Score', 0) <= 6)
    low_count = sum(1 for r in st.session_state.analysis_results 
                   if r['Analysis'] and 1 <= r['Analysis'].get('Confidence_Score', 0) <= 3)
    negligible_count = sum(1 for r in st.session_state.analysis_results 
                        if r['Analysis'] and r['Analysis'].get('Confidence_Score', 0) == 0)
    
    col1, col2, col3, col4 = st.columns([1, 1, 1, 1])
    with col1:
        st.metric("📊 Total", total_events)
    with col2:
        # Apply red danger badge for high threats
        if (critical_count + high_count) > 0:
            st.markdown(f"""
            <div class="high-threat-badge" style="
                background: #FF3131 !important;
                color: #FFFFFF !important;
                border: 1px solid #FF3131 !important;
                padding: 1rem;
                border-radius: 8px;
                text-align: center;
                font-family: 'Inter', sans-serif;
                font-weight: 600;
            ">
                🚨 High: {critical_count + high_count}
                <br><small>{(critical_count + high_count)/total_events*100:.1f}%</small>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.metric("🚨 High", critical_count + high_count, delta=f"{(critical_count + high_count)/total_events*100:.1f}%" if total_events > 0 else None)
    with col3:
        st.metric("⚠️ Med", medium_count, delta=f"{medium_count/total_events*100:.1f}%" if total_events > 0 else None)
    with col4:
        st.metric("ℹ️ Low", low_count, delta=f"{low_count/total_events*100:.1f}%" if total_events > 0 else None)
    
    # Executive Summary
    if negligible_count > 0:
        st.success(f"📊 **Executive Summary**: Out of {total_events} logs analyzed, {negligible_count} were found to contain No Detectable Threats.")
    st.markdown("---")
    
    # Detailed Results - Custom HTML Threat Cards
    for idx, result in enumerate(st.session_state.analysis_results, 1):
        event = result['Event']
        analysis = result['Analysis']
        
        # Get threat tier and color coding
        confidence_score = analysis.get('Confidence_Score', 0) if analysis else 0
        threat_label, threat_color, threat_icon = get_threat_tier(confidence_score)
        
        # Extract event data
        event_id = event.get('EventID', 'Unknown')
        process_name = event.get('ProcessName', 'Unknown')
        parent_process = event.get('ParentProcessName', 'Unknown')
        command_line = event.get('CommandLine', '')
        
        # Extract MITRE data
        tactic = analysis.get('Tactic', 'Unknown') if analysis else 'Analysis Failed'
        technique_id = analysis.get('Technique_ID', 'Unknown') if analysis else 'Unknown'
        technique_name = analysis.get('Technique_Name', 'Unknown') if analysis else 'Unknown'
        justification = analysis.get('Justification', 'No justification provided') if analysis else 'Analysis failed - check logs'
        
        # Create HTML threat card
        threat_card_html = f"""
        <div class="threat-card" style="border-color: {threat_color} !important;">
            <table>
                <tr>
                    <td width="25%">
                        <div class="column-header">Identity</div>
                        <div class="event-id">🆔 {event_id}</div>
                        <div class="process-name">⚙️ {process_name}</div>
                        {f'<div class="process-name">📁 {parent_process}</div>' if parent_process != 'Unknown' else ''}
                    </td>
                    <td width="25%">
                        <div class="column-header">MITRE ATT&CK</div>
                        <div class="mitre-tactic">🎯 {tactic}</div>
                        <div class="mitre-technique">🔍 {technique_id}</div>
                        <div class="mitre-technique" style="font-size: 0.8rem;">{technique_name}</div>
                    </td>
                    <td width="50%">
                        <div class="column-header">Threat Analysis</div>
                        <div class="threat-badge" style="background: {threat_color} !important;">
                            {threat_icon} {threat_label} ({confidence_score}/10)
                        </div>
                        <div class="justification">{justification}</div>
                    </td>
                </tr>
                {f'''<tr>
                    <td colspan="3">
                        <div class="column-header">Command Line</div>
                        <div class="command-line">{command_line}</div>
                    </td>
                </tr>''' if command_line else ''}
            </table>
        </div>
        """
        
        # Render the threat card
        st.markdown(threat_card_html, unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown("""
### 🔐 About AURA
AURA (Automated User-Risk Analysis) is an advanced cybersecurity platform that leverages 
Google Gemini AI to analyze Windows Event Logs and map them to the MITRE ATT&CK framework. 
This tool helps security professionals quickly identify potential threats and understand attack patterns.

**Powered by:** Google Gemini 3 Flash Preview | **Framework:** MITRE ATT&CK
""")

# Instructions when no results
if not st.session_state.analysis_results:
    st.info("👆 Upload a file or provide a file path to begin threat analysis with AURA")
    st.markdown("""
### 🛡️ AURA Threat Intelligence Platform

**Professional Features:**
- **Batch Processing**: Analyzes up to 50 events in batches of 10 for optimal performance
- **5-Level Threat Classification**: Critical, High, Medium, Low, Negligible
- **AURA Trust Gauge**: Visual confidence scoring with segmented display
- **Executive Summary**: High-level overview of threat landscape
- **MITRE ATT&CK Mapping**: Advanced technique identification

**Ready to transform your Windows Event Logs into actionable threat intelligence.**
    """)
