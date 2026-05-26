# AURA Architecture

## Backend Architecture (event_mapper.py)

The backend is built with three core classes that handle parsing, analysis, and orchestration.

### EventLogParser

Handles file parsing and data normalization for Windows Event Logs.

**Responsibilities**:
- Automatic file type detection (CSV/JSON)
- Event data normalization to standard schema
- Support for single events or arrays
- UTF-8 encoding handling
- Field validation and default value assignment

**Methods**:
- `detect_file_type(file_path: str) -> str`: Returns 'csv' or 'json'
- `parse_csv(file_path: str) -> List[Dict[str, Any]]`: Parses CSV files
- `parse_json(file_path: str) -> List[Dict[str, Any]]`: Parses JSON files
- `_normalize_event(event: Dict[str, Any]) -> Dict[str, Any]`: Standardizes event schema

**Event Schema**:
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

### GenAIAnalyzer

Manages AI API communication with Google Gemini for threat analysis.

**Responsibilities**:
- Structured output using Pydantic models
- Tenacious retry logic with exponential backoff (max 5 retries)
- Fuzzy key mapping for robust response parsing
- Smart confidence score normalization
- Batch processing for efficiency (25 events per API call)

**Methods**:
- `analyze_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]`: Analyzes single event
- `analyze_batch(events: List[Dict[str, Any]]) -> List[Optional[Dict[str, Any]]]`: Analyzes batch
- `_prepare_event_summary(event: Dict[str, Any]) -> str`: Formats event for AI
- `_prepare_batch_summary(events: List[Dict[str, Any]]) -> str`: Formats batch for AI
- `_make_api_request(event_summary: str) -> Any`: Executes API call with retry logic
- `_parse_response(response: Any) -> Dict[str, Any]`: Validates and parses AI response
- `_parse_batch_response(response: Any, expected_count: int) -> List[Optional[Dict[str, Any]]]`: Parses batch response
- `_create_default_analysis() -> Dict[str, Any]`: Returns default analysis on failure

**Retry Logic**:
- Max retries: 5 attempts
- Base delay: 2 seconds
- Backoff strategy: Exponential (2, 4, 8, 16, 32 seconds)
- Retryable errors: 503, 429, UNAVAILABLE, RESOURCE_EXHAUSTED

**Fuzzy Response Parsing**:
Handles various AI output formats:
- Key variations: tactic/tactics/attack_tactic, technique_id/techniqueid/technique
- Null handling: Converts null/None/empty strings to "None"
- Score normalization: Handles percentage (85% → 8) and integer scores
- Missing fields: Adds default values for required fields

### EventMapper

Orchestrates the complete analysis workflow.

**Responsibilities**:
- Coordinates parsing and analysis
- Manages result aggregation
- Handles file I/O operations
- Provides console output formatting

**Methods**:
- `process_file(file_path: str) -> None`: Main workflow orchestration
- `save_results() -> None`: Saves results to JSON file
- `print_results() -> None`: Displays formatted console output
- `_create_confidence_meter(score: int) -> str`: Creates visual confidence indicator

## Frontend Architecture (app.py)

The Streamlit interface provides an interactive SOC-style dashboard.

**Components**:

### Custom CSS Framework
- 500+ lines of professional styling
- Cyber-Pro Dark Theme with electric blue accents (#00D1FF)
- Custom threat cards with dynamic color-coded borders
- Animated progress indicators for high-confidence threats
- Responsive two-column layout

### Session State Management
- Persistent analysis results across interactions
- State variables: analysis_results, uploaded_file, file_path
- Automatic state preservation during reruns

### Progress Tracking
- Real-time batch processing status with st.status
- Batch number and event range display
- Visual progress indicators
- Error state handling

### Dynamic UI Components
- Threat cards with severity indicators
- Summary metrics (total, high, medium, low counts)
- File upload with metadata display
- Export format selection (CSV/JSON)
- Download buttons with timestamped filenames

### Error Resilience
- Graceful handling of API failures
- User-friendly error messages
- Toast notifications for retries
- Continues processing remaining events on batch failures

## Data Flow

```
Input File (CSV/JSON)
    ↓
EventLogParser.detect_file_type()
    ↓
EventLogParser.parse_csv() / parse_json()
    ↓
EventLogParser._normalize_event()
    ↓
GenAIAnalyzer.analyze_batch()
    ↓
GenAIAnalyzer._prepare_batch_summary()
    ↓
GenAIAnalyzer._make_api_request() [with retry logic]
    ↓
GenAIAnalyzer._parse_batch_response() [with fuzzy mapping]
    ↓
Validation & Normalization
    ↓
EventMapper.save_results()
    ↓
Visualization (Streamlit) / Export (CSV/JSON)
```

## Error Handling Strategy

### Backend Error Handling
- **API Failures**: Returns default analysis with error message
- **Parse Errors**: Logs error and continues with next event
- **Batch Failures**: Continues processing remaining batches
- **Validation Errors**: Uses Pydantic for type-safe data models

### Frontend Error Handling
- **File Upload Errors**: Displays user-friendly error messages
- **API Overload**: Shows toast notification and retries
- **Parse Failures**: Displays error with file context
- **Export Failures**: Shows error with suggested actions

## Logging Strategy

### File Logging (event_mapper.log)
- Complete operation history
- Timestamped entries with severity levels
- Detailed error messages and stack traces
- Useful for debugging and audit trails

### Console Logging
- Real-time logging during execution
- Progress updates for batch processing
- Model verification on startup
- Error notifications

### Log Levels
- **INFO**: Normal operations, progress updates
- **WARNING**: Non-critical issues, API retries
- **ERROR**: Failures requiring attention
- **DEBUG**: Detailed diagnostic information

## Performance Considerations

### Batch Processing
- Optimal batch size: 25 events per API call
- Rate limiting: 1-second delay between batches
- Memory efficiency: Processes events in streams, not all at once

### Processing Speed Estimates
- Small files (< 100 events): ~10-30 seconds
- Medium files (100-500 events): ~1-3 minutes
- Large files (> 500 events): ~5-10 minutes

*Times vary based on API response times and network conditions.*

### Optimization Tips
1. Use JSON format for faster parsing than CSV
2. Filter events before analysis to remove benign activity
3. Adjust batch size based on API quota
4. Parallel processing not supported (sequential for rate limiting)

## Security Considerations

- **API Key Protection**: Stored in environment variables only, never in code
- **Input Validation**: Comprehensive file format validation before processing
- **Error Logging**: Detailed audit trail without exposing sensitive data
- **Network Security**: Timeout protection and retry logic for API calls
- **Data Sanitization**: Normalization and validation of all input data
- **No Data Persistence**: Analysis results not stored permanently unless exported
