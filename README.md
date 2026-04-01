# 🛡️ AURA: Automated User-Risk Analysis

A sophisticated cybersecurity platform that leverages Google Gemini AI to analyze Windows Event Logs and automatically map them to the MITRE ATT&CK framework. Features a professional Cyber-Pro Dark theme with custom HTML threat cards and real-time threat visualization.

## 🚀 Features

- **Cyber-Pro Dark Theme**: Professional dark interface with electric blue accents (#00D1FF)
- **Custom HTML Threat Cards**: Dynamic color-coded borders based on threat levels
- **MITRE ATT&CK Integration**: Automatic mapping to attack techniques and tactics
- **Real-time Visualization**: Sequential event numbering with professional headers
- **AI-Powered Analysis**: Google Gemini 3.1 Flash-Lite backend with 25-event batch processing
- **Multi-format Export**: CSV and JSON export with dynamic intelligence labels
- **Threat Intelligence**: 🔴 Critical, 🟠 Moderate, 🟡 Low, 🔵 None tier classification
- **GitHub Integration**: Functional repository link in the header
- **Professional SOC Dashboard**: Enterprise-grade security operations center appearance

## 🛠️ Tech Stack

- **Frontend**: Streamlit with custom CSS injection
- **Backend**: Google Gemini 3.1 Flash-Lite AI
- **Framework**: MITRE ATT&CK v12.0
- **Styling**: Inter headers, Roboto Mono technical data
- **Processing**: Batch optimization for large datasets
- **Security**: Environment variable API key management

## 📋 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/AbhijeetSharma/AURA.git
   cd AURA
   ```

2. Create and activate virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\Activate  # Windows
   source venv/bin/activate  # Linux/Mac
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## ⚙️ Configuration

1. Copy the example environment file:
   ```bash
   copy .env.example .env
   ```

2. Edit `.env` file with your Google Gemini API key:
   ```
   GENAI_API_KEY=your_google_gemini_api_key_here
   ```

## 🎯 Usage

Run the AURA application:
```bash
streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`

## 📊 Features Overview

### Threat Analysis
- **Upload Windows Event Logs** (CSV/JSON format)
- **Real-time AI Analysis** using Gemini 3.1 Flash-Lite
- **MITRE ATT&CK Mapping** with technique identification
- **Confidence Scoring** (0-10 scale with color coding)

### Visual Intelligence
- **Color-Coded Threat Cards**: Red (Critical), Orange (Moderate), Yellow (Low), Blue (None)
- **Sequential Event Numbering**: Event 1, Event 2, Event 3...
- **Professional Dashboard**: SOC-grade interface design
- **Dynamic Export**: CSV/JSON with format-specific labels

### Enterprise Features
- **Batch Processing**: 25-event optimization for large datasets
- **Error Handling**: Comprehensive logging and graceful failures
- **Multi-Format Support**: CSV and JSON event log formats
- **Security**: API key protection via environment variables

## 🎨 UI Features

### Cyber-Pro Dark Theme
- **Electric Blue Accents** (#00D1FF) for primary actions
- **High-Contrast Design** for maximum visibility
- **Professional Typography**: Inter headers, Roboto Mono data
- **Smooth Animations**: Hover effects and transitions

### Threat Visualization
- **Dynamic Borders**: Color changes based on confidence scores
- **Pulsing Red Alerts**: High-confidence threat indicators
- **Summary Metrics**: Real-time threat statistics
- **Command Line Display**: Terminal-style code presentation

## 📈 Sample Threat Analysis

```
Event 1: Event ID 4688
┌─────────────────────────────────────────────────────────────┐
│ 🔴 Critical (9/10)                                          │
├─────────────┬─────────────┬─────────────────────────────────┤
│ Identity    │ MITRE ATT&CK │ Threat Analysis                │
│ 🆔 4688     │ 🎯 Execution│ 🔴 Critical (9/10)             │
│ ⚙️ powershell│ 🔍 T1059.001 │ Suspicious PowerShell activity │
│ 📁 svchost   │ PowerShell  │ detected with network call    │
└─────────────┴─────────────┴─────────────────────────────────┘
Command: powershell.exe -Command "Invoke-Expression..."
```

## 🛡️ Security Considerations

- **API Key Protection**: Stored in environment variables only
- **Input Validation**: Comprehensive file format validation
- **Error Logging**: Detailed audit trail without sensitive data
- **Network Security**: Timeout protection and retry logic

## 📚 Dependencies

- **streamlit**: Web application framework
- **google-generativeai**: Gemini AI API client
- **pandas**: Data manipulation and export
- **python-dotenv**: Environment variable management
- **pydantic**: Data validation and structured responses

## 🎓 Perfect For

- **6th-Semester Cybersecurity Projects**
- **Security Operations Center (SOC) Tools**
- **Threat Intelligence Platforms**
- **Enterprise Security Demonstrations**
- **MITRE ATT&CK Research**

## 📞 Support

This project is designed for educational and professional cybersecurity demonstrations. For questions or issues, please use the GitHub repository.

---

**🛡️ AURA | Automated User-Risk Analysis**
*Advanced threat intelligence powered by Google Gemini AI*
