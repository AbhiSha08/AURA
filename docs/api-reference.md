# AURA API Reference

## EventLogParser Class

Handles parsing of Windows Event Log files in CSV and JSON formats.

### Methods

#### `detect_file_type(file_path: str) -> str`

Detects if file is CSV or JSON based on extension.

**Parameters**:
- `file_path` (str): Path to the file

**Returns**:
- str: 'csv' or 'json'

**Raises**:
- ValueError: If file extension is not supported

**Example**:
```python
from event_mapper import EventLogParser

file_type = EventLogParser.detect_file_type("events.csv")
# Returns: 'csv'
```

#### `parse_csv(file_path: str) -> List[Dict[str, Any]]`

Parses CSV file containing Windows Event Log data.

**Parameters**:
- `file_path` (str): Path to CSV file

**Returns**:
- List[Dict[str, Any]]: List of normalized event dictionaries

**Raises**:
- Exception: If file parsing fails

**Example**:
```python
events = EventLogParser.parse_csv("events.csv")
# Returns: [{'EventID': 4688, 'ProcessName': 'powershell.exe', ...}, ...]
```

#### `parse_json(file_path: str) -> List[Dict[str, Any]]`

Parses JSON file containing Windows Event Log data.

**Parameters**:
- `file_path` (str): Path to JSON file

**Returns**:
- List[Dict[str, Any]]: List of normalized event dictionaries

**Raises**:
- Exception: If file parsing fails

**Example**:
```python
events = EventLogParser.parse_json("events.json")
# Returns: [{'EventID': 4688, 'ProcessName': 'powershell.exe', ...}, ...]
```

#### `_normalize_event(event: Dict[str, Any]) -> Dict[str, Any]`

Normalizes event data to standard schema.

**Parameters**:
- `event` (Dict[str, Any]): Raw event data

**Returns**:
- Dict[str, Any]: Normalized event with standard schema

**Schema**:
```python
{
    'EventID': str/int,
    'TimeCreated': str (ISO 8601),
    'ComputerName': str,
    'ProcessName': str,
    'CommandLine': str,
    'ParentProcessName': str,
    'SubjectUserName': str,
    'SubjectDomainName': str,
    'TargetUserName': str,
    'TargetDomainName': str
}
```

## GenAIAnalyzer Class

Handles communication with Google Gemini API for threat analysis.

### Constructor

```python
GenAIAnalyzer()
```

Initializes the analyzer with environment variables:
- `GEMINI_API_KEY`: Google Gemini API key (required)
- `GENAI_MODEL`: Model identifier (default: gemini-3.1-flash-lite-preview)

### Methods

#### `analyze_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]`

Analyzes a single event using GenAI API.

**Parameters**:
- `event` (Dict[str, Any]): Event dictionary with normalized schema

**Returns**:
- Optional[Dict[str, Any]]: Analysis result or None on failure

**Analysis Result Schema**:
```python
{
    'Tactic': str,
    'Technique_ID': str,
    'Technique_Name': str,
    'Confidence_Score': int (0-10),
    'Justification': str
}
```

**Example**:
```python
from event_mapper import GenAIAnalyzer

analyzer = GenAIAnalyzer()
event = {'EventID': 4688, 'ProcessName': 'powershell.exe', ...}
result = analyzer.analyze_event(event)
# Returns: {'Tactic': 'Execution', 'Technique_ID': 'T1059.001', ...}
```

#### `analyze_batch(events: List[Dict[str, Any]]) -> List[Optional[Dict[str, Any]]]`

Analyzes multiple events in a single API call for efficiency.

**Parameters**:
- `events` (List[Dict[str, Any]]): List of event dictionaries

**Returns**:
- List[Optional[Dict[str, Any]]]: List of analysis results (None for failures)

**Batch Size**: Optimal performance with 25 events per call

**Example**:
```python
events = [{'EventID': 4688, ...}, {'EventID': 4720, ...}, ...]
results = analyzer.analyze_batch(events)
# Returns: [{'Tactic': 'Execution', ...}, {'Tactic': 'Persistence', ...}, ...]
```

#### `_prepare_event_summary(event: Dict[str, Any]) -> str`

Prepares a readable summary of the event for analysis.

**Parameters**:
- `event` (Dict[str, Any]): Event dictionary

**Returns**:
- str: Formatted event summary

**Example Output**:
```
EventID: 4688 | Process: powershell.exe | Command: powershell.exe -Command "..." | Parent Process: explorer.exe | User: admin\CORP
```

#### `_prepare_batch_summary(events: List[Dict[str, Any]]) -> str`

Prepares a readable summary of multiple events for batch analysis.

**Parameters**:
- `events` (List[Dict[str, Any]]): List of event dictionaries

**Returns**:
- str: Formatted batch summary with numbered events

#### `_make_api_request(event_summary: str) -> Any`

Makes request to Gemini API with structured output and retry logic.

**Parameters**:
- `event_summary` (str): Formatted event/batch summary

**Returns**:
- Any: Gemini API response object

**Retry Logic**:
- Max retries: 5 attempts
- Base delay: 2 seconds
- Backoff strategy: Exponential (2, 4, 8, 16, 32 seconds)
- Retryable errors: 503, 429, UNAVAILABLE, RESOURCE_EXHAUSTED

#### `_parse_response(response: Any) -> Dict[str, Any]`

Parses and validates Gemini response with fuzzy mapping.

**Parameters**:
- `response` (Any): Gemini API response object

**Returns**:
- Dict[str, Any]: Validated analysis result

**Fuzzy Mapping**:
- Handles key variations (tactic/tactics/attack_tactic, etc.)
- Converts null/None/empty strings to "None"
- Normalizes confidence scores (percentage to 0-10 scale)
- Adds default values for missing fields

#### `_parse_batch_response(response: Any, expected_count: int) -> List[Optional[Dict[str, Any]]]`

Parses and validates batch Gemini response.

**Parameters**:
- `response` (Any): Gemini API response object
- `expected_count` (int): Expected number of analyses

**Returns**:
- List[Optional[Dict[str, Any]]]: List of validated analysis results

**Behavior**:
- Pads with default analyses if fewer results than expected
- Trims if more results than expected
- Applies same fuzzy mapping as single response parser

#### `_create_default_analysis() -> Dict[str, Any]`

Creates a default analysis when parsing fails.

**Returns**:
- Dict[str, Any]: Default analysis with error message

**Default Values**:
```python
{
    'Tactic': 'None',
    'Technique_ID': 'None',
    'Technique_Name': 'None',
    'Confidence_Score': 0,
    'Justification': 'Analysis failed due to API error'
}
```

## EventMapper Class

Main application class for mapping events to MITRE ATT&CK techniques.

### Constructor

```python
EventMapper()
```

Initializes parser and analyzer components.

### Methods

#### `process_file(file_path: str) -> None`

Processes a file containing Windows Event Log data.

**Parameters**:
- `file_path` (str): Path to the input file (CSV or JSON)

**Behavior**:
1. Detects file type
2. Parses events
3. Analyzes each event
4. Saves results to `mapped_events.json`
5. Logs progress

**Raises**:
- Exception: If file processing fails

**Example**:
```python
from event_mapper import EventMapper

mapper = EventMapper()
mapper.process_file("events.json")
# Saves to mapped_events.json
```

#### `save_results() -> None`

Saves analysis results to JSON file.

**Output File**: `mapped_events.json`

**Format**:
```json
[
  {
    "Event": {...},
    "Analysis": {...},
    "ProcessedAt": "2024-03-07T10:15:30.123456Z"
  },
  ...
]
```

#### `print_results() -> None`

Prints analysis results to console with visual indicators.

**Output Format**:
```
================================================================================
AURA THREAT ANALYSIS RESULTS
================================================================================

Event #1:
  Event ID: 4688
  Process: powershell.exe
  Command: powershell.exe -Command "..."
--------------------------------------------------
Tactic: Execution
Technique: T1059.001 - PowerShell
Confidence: 🔴 CRITICAL (9/10) ███████████
Justification: Suspicious PowerShell activity detected...
```

#### `_create_confidence_meter(score: int) -> str`

Creates a visual confidence meter.

**Parameters**:
- `score` (int): Confidence score (0-10)

**Returns**:
- str: Visual confidence meter with emoji and progress bar

**Output Examples**:
```
🟢 NO THREAT DETECTED
🔵 LOW (2/10) ░░░░░░░░░░
🟡 MEDIUM (5/10) ████░░░░░░░
🟠 HIGH (8/10) ████████░░░
🔴 CRITICAL (10/10) ███████████
```

## Pydantic Models

### MITREAnalysis

Data model for single MITRE ATT&CK analysis result.

```python
from event_mapper import MITREAnalysis

analysis = MITREAnalysis(
    Tactic="Execution",
    Technique_ID="T1059.001",
    Technique_Name="PowerShell",
    Confidence_Score=8,
    Justification="Suspicious activity detected"
)
```

**Fields**:
- `Tactic` (Optional[str]): MITRE ATT&CK tactic
- `Technique_ID` (Optional[str]): MITRE ATT&CK technique ID
- `Technique_Name` (Optional[str]): Human-readable technique name
- `Confidence_Score` (Optional[int]): Analysis confidence (0-10)
- `Justification` (Optional[str]): Detection rationale

### BatchMITREResponse

Data model for batch MITRE ATT&CK analysis results.

```python
from event_mapper import BatchMITREResponse

batch_response = BatchMITREResponse(
    results=[analysis1, analysis2, ...]
)
```

**Fields**:
- `results` (List[MITREAnalysis]): List of analysis results

## System Prompt

The analyzer uses the following system prompt to ensure consistent MITRE ATT&CK mappings:

```
You are an elite Cyber Threat Intelligence Analyst. Analyze the provided 
Windows Event Log telemetry. Map behavior to the MITRE ATT&CK framework. 
You MUST return a JSON object with a key 'results' containing an array of 
objects. Each object MUST strictly use these EXACT keys (case-sensitive): 
'Tactic', 'Technique_ID', 'Technique_Name', 'Confidence_Score', 'Justification'. 
For benign events, use the string 'None' for Tactic and Technique fields, 
and 0 for Confidence_Score. DO NOT omit any required fields. DO NOT use 
lowercase keys.
```

## Input Data Format

### Supported Formats
- CSV Files: Tab or comma-separated with headers
- JSON Files: Object or array of event objects

### Event Log Schema

Each event should contain Windows security event telemetry:

```json
{
  "EventID": 4688,
  "TimeCreated": "2024-03-07T10:15:30.123456Z",
  "ComputerName": "WIN-SEC01",
  "ProcessName": "powershell.exe",
  "CommandLine": "powershell.exe -Command \"Invoke-Expression...\"",
  "ParentProcessName": "explorer.exe",
  "SubjectUserName": "admin",
  "SubjectDomainName": "CORP",
  "TargetUserName": "SYSTEM",
  "TargetDomainName": "NT AUTHORITY"
}
```

### Common Event IDs

| Event ID | Description | Risk Level | MITRE Tactic |
|----------|-------------|-----------|--------------|
| 4688 | Process Creation | Medium | Execution |
| 4689 | Process Termination | Low | Execution |
| 4703 | Token Right Adjusted | High | Privilege Escalation |
| 4720 | User Account Created | Medium | Persistence |
| 4724 | Attempt to Reset Password | High | Credential Access |
| 4624 | Account Logon | Low | Initial Access |
| 4625 | Failed Logon | Medium | Initial Access |

## Output Data Format

### Analysis Result Structure

```json
{
  "Tactic": "Execution",
  "Technique_ID": "T1059.001",
  "Technique_Name": "PowerShell",
  "Confidence_Score": 8,
  "Justification": "Event shows execution of PowerShell with suspicious command..."
}
```

### Field Descriptions

| Field | Type | Description | Example |
|-------|------|-------------|--------|
| Tactic | String | MITRE ATT&CK tactic | "Execution", "Persistence" |
| Technique_ID | String | MITRE ATT&CK technique ID | "T1059.001" |
| Technique_Name | String | Human-readable technique name | "PowerShell" |
| Confidence_Score | Integer | Analysis confidence 0-10 scale | 8 |
| Justification | String | Detailed explanation of detection rationale | "Suspicious PowerShell activity..." |

Benign events return "None" for tactic/technique fields with Confidence_Score of 0.

### Export Formats

**CSV Export**: Structured table with columns:
- Timestamp, EventID, Process, Computer, Tactic, Technique, Confidence_Score, Threat_Level, Justification

**JSON Export**: Complete analysis results with original event data and analysis metadata.

## Threat Classification

Events are classified into five threat tiers based on AI confidence scores:

| Tier | Icon | Confidence Range | Color | Description |
|------|------|-----------------|-------|-------------|
| Critical | 🔴 | 9-10 | #8B0000 | High-priority threat requiring immediate investigation |
| High | 🟠 | 7-8 | #FF4500 | High-priority threat requiring analysis |
| Medium | 🟡 | 4-6 | #FFA500 | Medium-priority threat requiring analysis |
| Low | 🔵 | 1-3 | #1E40AF | Low-priority event with minor risk |
| Negligible | 🟢 | 0 | #228B22 | Benign activity, no threat detected |
