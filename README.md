# 🛡️ AURA: Automated User-Risk Analysis

**A lightning-fast, deterministic Threat Intelligence platform and SOC engine.** 
AURA maps massive volumes of Windows Event Logs to the MITRE ATT&CK framework with sub-second latency. Operating entirely locally without external AI/API dependencies, it ensures absolute data privacy and predictable, instantaneous threat detection for enterprise environments.

---

## ✨ Key Features

- **Sub-Second Deterministic Engine:** Capable of parsing, flattening, and classifying 10,000+ deeply nested Windows Event Logs in under a second using compiled regex and highly optimized rule dictionaries.
- **Dynamic STIX 2.1 Ingestion:** Auto-fetches and caches official MITRE ATT&CK STIX 2.1 JSON definitions. Ensures tactics, techniques, descriptions, and mitigations are comprehensively accurate.
- **Production-Grade Containerization:** Packaged via a highly secure, multi-stage Dockerfile adhering to Twelve-Factor App principles. Runs exclusively under a restricted non-root profile and streams all telemetry to standard output.
- **Executive SOC Dashboard:** A high-density Streamlit UI designed for analysts, featuring instantaneous metrics, dynamic severity-matched UI components, and deep-dive IOC threat cards.

---

## 🏗️ Architecture

AURA is powered by a specialized **Two-Stage Engine**:

### Stage 1: Regex & EventID Mapping
The core engine (`event_mapper.py`) rapidly ingests raw JSON/CSV Windows Event Logs. It flattens deeply nested structures and applies static lookup dictionaries for well-known Event IDs (e.g., 4688, 4625, 1102). It simultaneously runs compiled regex heuristics against command lines and processes to assign base classifications and confidence scores.

### Stage 2: STIX Enrichment via Local Cache
The `mitre_ingestor.py` component seamlessly enriches the initial classifications. It securely queries the MITRE Enterprise STIX repository (caching results locally for 24 hours to prevent rate-limiting) and appends authoritative kill-chain phases, technique descriptions, and mitigation strategies. If isolated from the internet, it gracefully relies on a robust embedded fallback database.

---

## 🚀 Installation & Deployment

### Docker Deployment (Recommended)
AURA is fully containerized for secure, immediate deployment.

```bash
# 1. Build the highly optimized production image
docker build -t aura-soc-dashboard:latest .

# 2. Run the secure, detached container
docker run -d -p 8501:8501 --name aura-live aura-soc-dashboard:latest
```
*Access the dashboard at [http://localhost:8501](http://localhost:8501)*

### Local Python Execution
To run AURA directly on your host machine:

```bash
# 1. Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the dashboard
streamlit run app.py
```

---

## 📖 Usage Guide

1. **Access the Dashboard:** Open your browser to the deployed URL (e.g., `http://localhost:8501`).
2. **Upload Telemetry:** Use the sidebar menu to either drag-and-drop a Windows Event Log file (`.json` or `.csv`) or provide a local, path-traversal-protected workspace file path.
3. **Execute Analysis:** Click **Run AURA Analysis**. The deterministic engine will parse and map thousands of logs in milliseconds.
4. **Investigate Threats:** Review the dynamic executive metric blocks. Expand individual high-risk threat cards to extract Indicators of Compromise (IOCs), view sanitized process commands, and read mitigation steps.

---

## 📜 License

This project is licensed under the **MIT License**.
