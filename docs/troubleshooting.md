# AURA Troubleshooting Guide

## Common Issues and Solutions

### API Key Not Found

**Error Message**:
```
No API key found in environment variables
```

**Causes**:
- `.env` file does not exist in project root
- `GEMINI_API_KEY` is not set in `.env` file
- `.gitignore` is excluding `.env` file
- Streamlit app needs restart after `.env` changes

**Solutions**:
1. Create `.env` file in project root:
   ```env
   GEMINI_API_KEY=your_actual_api_key_here
   GENAI_MODEL=gemini-3.1-flash-lite-preview
   ```
2. Verify API key is correct (no extra spaces or quotes)
3. Check `.gitignore` doesn't exclude `.env`:
   ```
   .env
   event_mapper.log
   ```
4. Restart Streamlit app after updating `.env`:
   ```bash
   # Stop current app (Ctrl+C)
   streamlit run app.py
   ```

### No Module Named 'google.genai'

**Error Message**:
```
ModuleNotFoundError: No module named 'google.genai'
```

**Causes**:
- Dependencies not installed
- Virtual environment not activated
- Package version conflict

**Solutions**:
```bash
# Activate virtual environment
venv\Scripts\Activate.ps1  # Windows
source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Upgrade specific package
pip install --upgrade google-generativeai
```

### Rate Limiting (429 Error)

**Error Message**:
```
429 Too Many Requests
```

**Causes**:
- Exceeded Google Gemini API quota
- Too many requests in short time period
- Batch size too large

**Solutions**:
1. Reduce batch size in `event_mapper.py`:
   ```python
   batch_size = 15  # Reduce from 25
   ```
2. Increase delay between batches:
   ```python
   time.sleep(2)  # Increase from 1 second
   ```
3. Check API quota at [Google AI Studio](https://ai.google.dev)
4. Wait before retrying (automatic retry handles this with exponential backoff)

### Streamlit Port Already in Use

**Error Message**:
```
Port 8501 is already in use
```

**Causes**:
- Another Streamlit instance running
- Port occupied by another application

**Solutions**:
```bash
# Use different port
streamlit run app.py --server.port 8502

# Or kill existing process (Windows)
netstat -ano | findstr :8501
taskkill /PID <PID> /F

# Or kill existing process (Linux/macOS)
lsof -ti:8501 | xargs kill -9
```

### JSON Parsing Errors

**Error Message**:
```
Failed to parse JSON file
```

**Causes**:
- Invalid JSON syntax
- Missing required fields
- Incorrect file encoding
- Wrong JSON structure

**Solutions**:
1. Validate JSON syntax at [jsonlint.com](https://www.jsonlint.com)
2. Ensure all required fields are present:
   ```json
   {
     "EventID": 4688,
     "ProcessName": "powershell.exe"
   }
   ```
3. Check file encoding is UTF-8:
   ```bash
   file -I events.json
   ```
4. Verify JSON structure (array or single object):
   ```json
   // Valid: Array
   [{"EventID": 4688, ...}, {"EventID": 4720, ...}]
   
   // Valid: Single object
   {"EventID": 4688, ...}
   ```

### API Overload (503 Error)

**Error Message**:
```
503 Service Unavailable
```

**Causes**:
- Google Gemini API temporarily overloaded
- High demand on API service
- Network connectivity issues

**Solutions**:
1. Automatic retry with exponential backoff is built-in (max 5 retries)
2. Wait and retry manually if automatic retry fails:
   ```bash
   # Wait 30 seconds, then retry
   ```
3. Check Google AI status page for service outages
4. Reduce batch size to lower API load:
   ```python
   batch_size = 10  # Reduce from 25
   ```
5. Try during off-peak hours

### Pydantic Validation Errors

**Error Message**:
```
ValidationError
```

**Causes**:
- AI response format unexpected
- Missing required fields in response
- Confidence score not integer 0-10
- Data type mismatch

**Solutions**:
1. Check AI response format in logs:
   ```bash
   cat event_mapper.log
   ```
2. Review fuzzy mapping logic in `_parse_response` method
3. Ensure all required fields are present:
   - Tactic
   - Technique_ID
   - Technique_Name
   - Confidence_Score (integer 0-10)
   - Justification
4. Check confidence score is valid:
   ```python
   # Valid: 0, 1, 2, ..., 10
   # Invalid: 11, -1, 8.5, "high"
   ```

### CSV Parsing Errors

**Error Message**:
```
Failed to parse CSV file
```

**Causes**:
- Invalid CSV format
- Missing headers
- Incorrect delimiter
- Encoding issues

**Solutions**:
1. Validate CSV format:
   - First row must contain headers
   - Use comma or tab delimiter
   - Ensure consistent quoting
2. Check required columns:
   - EventID
   - ProcessName
3. Verify file encoding is UTF-8
4. Use consistent delimiter throughout file

### File Not Found

**Error Message**:
```
File not found: <file_path>
```

**Causes**:
- Incorrect file path
- File in different directory
- File name typo
- Using forward slashes on Windows

**Solutions**:
1. Verify file exists:
   ```bash
   ls events.json  # Linux/macOS
   dir events.json  # Windows
   ```
2. Use absolute path:
   ```bash
   python event_mapper.py "C:/path/to/events.json"
   ```
3. Check current working directory:
   ```bash
   pwd  # Linux/macOS
   cd  # Windows
   ```
4. Use proper path separators:
   - Windows: `C:\path\to\file.json` or `C:/path/to/file.json`
   - Linux/macOS: `/path/to/file.json`

### Memory Issues

**Error Message**:
```
MemoryError
```

**Causes**:
- Processing very large files
- Insufficient system memory
- Memory leak in application

**Solutions**:
1. Process files in smaller chunks
2. Close other applications to free memory
3. Increase system swap space
4. Use batch processing (already implemented)
5. Filter events before analysis to reduce dataset size

### Slow Performance

**Symptoms**:
- Analysis takes longer than expected
- UI becomes unresponsive

**Causes**:
- Large number of events
- Slow API response times
- Network latency
- High batch size

**Solutions**:
1. Reduce batch size:
   ```python
   batch_size = 15  # Reduce from 25
   ```
2. Use JSON format instead of CSV (faster parsing)
3. Filter events before analysis
4. Check network connection speed
5. Process during off-peak hours for API

## Debugging Tips

### Enable Debug Logging

Add to `event_mapper.py`:
```python
logging.basicConfig(level=logging.DEBUG)
```

### Check Application Logs

```bash
# View recent logs
tail -f event_mapper.log  # Linux/macOS
Get-Content event_mapper.log -Wait  # Windows

# Search for errors
grep ERROR event_mapper.log  # Linux/macOS
Select-String "ERROR" event_mapper.log  # Windows
```

### Test with Sample Data

Use provided `test_log.json`:
```bash
python event_mapper.py test_log.json
```

### Verify API Connection

Test API key manually:
```python
import os
from google import genai

api_key = os.getenv('GEMINI_API_KEY')
client = genai.Client()
response = client.models.generate_content(
    model="gemini-3.1-flash-lite-preview",
    contents="Test message"
)
print(response.text)
```

### Check Streamlit Logs

```bash
# Streamlit logs are displayed in terminal
# Look for ERROR or WARNING messages
```

## Getting Help

### Check Documentation

- [Architecture Documentation](./architecture.md)
- [API Reference](./api-reference.md)
- [Main README](../README.md)

### Review Logs

- `event_mapper.log`: Application logs
- Console output: Real-time status

### Common Debugging Commands

```bash
# Check Python version
python --version

# Check installed packages
pip list

# Check environment variables
echo $GEMINI_API_KEY  # Linux/macOS
echo %GEMINI_API_KEY%  # Windows

# Test file accessibility
python -c "import os; print(os.path.exists('events.json'))"
```

### Report Issues

When reporting issues, include:
1. Error message (full stack trace)
2. Steps to reproduce
3. System information (OS, Python version)
4. Relevant log entries
5. Sample data that causes issue

## Performance Optimization

### Batch Size Tuning

Test different batch sizes for optimal performance:
```python
# In event_mapper.py, modify:
batch_size = 25  # Try: 10, 15, 20, 25, 30
```

### Rate Limiting Adjustment

Adjust delay between batches:
```python
# In app.py, modify:
time.sleep(1)  # Try: 0.5, 1, 2, 3 seconds
```

### File Format Selection

- **JSON**: Faster parsing, smaller file size
- **CSV**: Slower parsing, larger file size, more compatible

### Event Filtering

Filter events before analysis to reduce processing time:
```python
# Remove benign events
events = [e for e in events if e['EventID'] in [4688, 4720, 4724]]
```

## Security Considerations

### API Key Protection

- Never commit `.env` file to version control
- Use environment variables for sensitive data
- Rotate API keys regularly
- Use separate API keys for development/production

### Input Validation

- Validate file formats before processing
- Sanitize user inputs
- Limit file sizes to prevent DoS
- Check for malicious file content

### Logging Security

- Avoid logging sensitive data (API keys, passwords)
- Use appropriate log levels
- Secure log file permissions
- Regular log rotation and cleanup
