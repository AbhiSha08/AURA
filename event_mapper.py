#!/usr/bin/env python3
"""
Cyber Event Log to MITRE ATT&CK Mapper

A robust production-ready Python backend module that maps Windows Event Logs 
to MITRE ATT&CK techniques via a Generative AI API.

Author: Elite Cyber Data Analyst
"""

from dotenv import load_dotenv
load_dotenv(override=True)

import json
import csv
import argparse
import os
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import logging
import time
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('event_mapper.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Constants
SYSTEM_PROMPT = (
    "You are an elite Cyber Threat Intelligence Analyst. Analyze the provided "
    "Windows Event Log telemetry. Map behavior to the MITRE ATT&CK framework. "
    "You MUST return a JSON object with a key 'results' containing an array of objects. "
    "Each object MUST strictly use these EXACT keys (case-sensitive): 'Tactic', 'Technique_ID', "
    "'Technique_Name', 'Confidence_Score', 'Justification'. "
    "For benign events, use the string 'None' for Tactic and Technique fields, and 0 for Confidence_Score. "
    "DO NOT omit any required fields. DO NOT use lowercase keys. "
    "Example: {\"results\": [{\"Tactic\": \"Execution\", \"Technique_ID\": \"T1059.001\", "
    "\"Technique_Name\": \"PowerShell\", \"Confidence_Score\": 8, \"Justification\": \"...\"}]}"
)

OUTPUT_FILE = "mapped_events.json"


class MITREAnalysis(BaseModel):
    """Pydantic model for MITRE ATT&CK analysis results."""
    Tactic: Optional[str] = Field(default="None")
    Technique_ID: Optional[str] = Field(default="None")
    Technique_Name: Optional[str] = Field(default="None")
    Confidence_Score: Optional[int] = Field(default=0)
    Justification: Optional[str] = Field(default="No justification provided")


class BatchMITREResponse(BaseModel):
    """Pydantic model for batch MITRE ATT&CK analysis results."""
    results: List[MITREAnalysis]


class EventLogParser:
    """Handles parsing of Windows Event Log files (CSV and JSON formats)."""
    
    @staticmethod
    def detect_file_type(file_path: str) -> str:
        """Detect if file is CSV or JSON based on extension."""
        extension = os.path.splitext(file_path)[1].lower()
        if extension == '.csv':
            return 'csv'
        elif extension == '.json':
            return 'json'
        else:
            raise ValueError(f"Unsupported file type: {extension}")
    
    @staticmethod
    def parse_csv(file_path: str) -> List[Dict[str, Any]]:
        """Parse CSV file containing Windows Event Log data."""
        events = []
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    normalized_event = EventLogParser._normalize_event(row)
                    events.append(normalized_event)
        except Exception as e:
            logger.error(f"Failed to parse CSV file {file_path}: {e}")
            raise
        return events
    
    @staticmethod
    def parse_json(file_path: str) -> List[Dict[str, Any]]:
        """Parse JSON file containing Windows Event Log data."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            # Handle single event or array of events
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                raise ValueError("JSON must contain an object or array of objects")
            
            events = []
            for item in data:
                normalized_event = EventLogParser._normalize_event(item)
                events.append(normalized_event)
                
        except Exception as e:
            logger.error(f"Failed to parse JSON file {file_path}: {e}")
            raise
        return events
    
    @staticmethod
    def _normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize event data to standard format."""
        normalized = {
            'EventID': event.get('EventID'),
            'TimeCreated': event.get('TimeCreated', datetime.now(timezone.utc).isoformat()),
            'ComputerName': event.get('ComputerName', 'Unknown'),
            'ProcessName': event.get('ProcessName', ''),
            'CommandLine': event.get('CommandLine', ''),
            'ParentProcessName': event.get('ParentProcessName', ''),
            'SubjectUserName': event.get('SubjectUserName', ''),
            'SubjectDomainName': event.get('SubjectDomainName', ''),
            'TargetUserName': event.get('TargetUserName', ''),
            'TargetDomainName': event.get('TargetDomainName', '')
        }
        
        # Remove None values and empty strings for cleaner output
        return {k: v for k, v in normalized.items() if v is not None and v != ''}


class GenAIAnalyzer:
    """Handles communication with Google Gemini API for threat analysis."""
    
    def __init__(self):
        self.api_key = os.getenv('GEMINI_API_KEY')
        self.model_name = os.getenv('GENAI_MODEL', 'gemini-3.1-flash-lite-preview')
        
        if not self.api_key:
            logger.warning("No API key found in environment variables")
        else:
            self.client = genai.Client()
            self.model_id = self.model_name
            logger.info(f"VERIFIED MODEL ID: {self.model_id}")
    
    def analyze_batch(self, events: List[Dict[str, Any]]) -> List[Optional[Dict[str, Any]]]:
        """Analyze multiple events in a single API call for efficiency."""
        if not self.api_key:
            logger.error("Cannot analyze events: No API key configured")
            return [None] * len(events)
        
        try:
            # Prepare batch data for analysis
            batch_summary = self._prepare_batch_summary(events)
            
            # Make batch API request
            response = self._make_api_request(batch_summary)
            
            # Parse and validate response
            analyses = self._parse_batch_response(response, len(events))
            
            return analyses
            
        except Exception as e:
            logger.error(f"Batch analysis failed: {e}")
            return [None] * len(events)
    
    def analyze_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze a single event using GenAI API."""
        if not self.api_key:
            logger.error("Cannot analyze event: No API key configured")
            return None
        
        try:
            # Prepare the event data for analysis
            event_summary = self._prepare_event_summary(event)
            
            # Make API request
            response = self._make_api_request(event_summary)
            
            # Parse and validate response
            analysis = self._parse_response(response)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return None
    
    def _prepare_event_summary(self, event: Dict[str, Any]) -> str:
        """Prepare a readable summary of the event for analysis."""
        summary_parts = []
        if event.get('EventID'):
            summary_parts.append(f"EventID: {event['EventID']}")
        if event.get('ProcessName'):
            summary_parts.append(f"Process: {event['ProcessName']}")
        if event.get('CommandLine'):
            summary_parts.append(f"Command: {event['CommandLine']}")
        if event.get('ParentProcessName'):
            summary_parts.append(f"Parent Process: {event['ParentProcessName']}")
        if event.get('SubjectUserName'):
            summary_parts.append(f"User: {event['SubjectUserName']}\\{event.get('SubjectDomainName', '')}")
        
        return " | ".join(summary_parts)
    
    def _prepare_batch_summary(self, events: List[Dict[str, Any]]) -> str:
        """Prepare a readable summary of multiple events for batch analysis."""
        event_summaries = []
        for i, event in enumerate(events, 1):
            summary_parts = []
            if event.get('EventID'):
                summary_parts.append(f"Event {i} ID: {event['EventID']}")
            if event.get('ProcessName'):
                summary_parts.append(f"Process: {event['ProcessName']}")
            if event.get('CommandLine'):
                summary_parts.append(f"Command: {event['CommandLine']}")
            if event.get('ParentProcessName'):
                summary_parts.append(f"Parent Process: {event['ParentProcessName']}")
            if event.get('SubjectUserName'):
                summary_parts.append(f"User: {event['SubjectUserName']}\\{event.get('SubjectDomainName', '')}")
            
            event_summaries.append(" | ".join(summary_parts))
        
        # Create batch prompt with N and events
        batch_prompt = SYSTEM_PROMPT.replace("$N$", str(len(events)))
        return f"{batch_prompt}\n\nEvents to analyze:\n" + "\n".join(event_summaries)
    
    def _make_api_request(self, event_summary: str) -> Any:
        """Make request to Gemini API with structured output and tenacious retry logic."""
        prompt = f"{SYSTEM_PROMPT}\n\nAnalyze this Windows Event Log: {event_summary}"
        
        # Tenacious retry logic with exponential backoff
        max_retries = 5
        base_delay = 2
        
        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model=self.model_id,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=BatchMITREResponse,
                        temperature=0.1
                    )
                )
                return response
                
            except Exception as e:
                error_str = str(e)
                
                # Check for retryable errors
                if ('503' in error_str or '429' in error_str or 
                    'UNAVAILABLE' in error_str or 'RESOURCE_EXHAUSTED' in error_str):
                    
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)  # Exponential backoff: 2, 4, 8, 16, 32
                        logger.warning(f"API overloaded (attempt {attempt + 1}/{max_retries}). Retrying in {delay} seconds...")
                        time.sleep(delay)
                        continue
                    else:
                        logger.error(f"Max retries exceeded. API still unavailable.")
                        raise Exception("Google API is currently overloaded. Please try again later.")
                else:
                    # Non-retryable error
                    logger.error(f"Non-retryable API error: {e}")
                    raise
        
        raise Exception("Failed to complete API request after maximum retries")
    
    def _parse_response(self, response: Any) -> Dict[str, Any]:
        """Parse and validate Gemini response with fuzzy mapping."""
        try:
            # Extract text from response
            content = response.text.strip()
            
            # Parse JSON
            analysis = json.loads(content)
            
            # Handle single object vs array
            if isinstance(analysis, list):
                if len(analysis) > 0:
                    analysis = analysis[0]
                else:
                    return self._create_default_analysis()
            
            # Apply same fuzzy mapping as batch parser
            cleaned_analysis = {}
            for key, value in analysis.items():
                key_lower = key.lower()
                
                # Fuzzy key mapping - handle various AI output formats
                if key_lower in ['tactic', 'tactics', 'attack_tactic']:
                    # Handle null/None values
                    if value is None or value == 'null' or value == '':
                        cleaned_analysis['Tactic'] = 'None'
                    else:
                        cleaned_analysis['Tactic'] = str(value)
                elif key_lower in ['technique_id', 'techniqueid', 'technique', 'attack_technique_id']:
                    if value is None or value == 'null' or value == '':
                        cleaned_analysis['Technique_ID'] = 'None'
                    else:
                        cleaned_analysis['Technique_ID'] = str(value)
                elif key_lower in ['technique_name', 'techniquename', 'attack_technique_name']:
                    if value is None or value == 'null' or value == '':
                        cleaned_analysis['Technique_Name'] = 'None'
                    else:
                        cleaned_analysis['Technique_Name'] = str(value)
                elif key_lower in ['confidence_score', 'confidence', 'score', 'threat_score']:
                    # Convert various score formats to int
                    if value is None or value == 'null' or value == '':
                        cleaned_analysis['Confidence_Score'] = 0
                    else:
                        try:
                            if isinstance(value, str):
                                if value.isdigit():
                                    cleaned_analysis['Confidence_Score'] = int(value)
                                else:
                                    cleaned_analysis['Confidence_Score'] = 0
                            else:
                                cleaned_analysis['Confidence_Score'] = int(value)
                        except (ValueError, TypeError):
                            cleaned_analysis['Confidence_Score'] = 0
                elif key_lower in ['justification', 'reason', 'explanation', 'analysis']:
                    if value is None or value == 'null' or value == '':
                        cleaned_analysis['Justification'] = 'No justification provided'
                    else:
                        cleaned_analysis['Justification'] = str(value)
                else:
                    # Keep unknown keys as-is
                    cleaned_analysis[key] = value
            
            # Ensure all required fields exist
            required_fields = ['Tactic', 'Technique_ID', 'Technique_Name', 'Confidence_Score', 'Justification']
            for field in required_fields:
                if field not in cleaned_analysis:
                    logger.warning(f"Missing field in analysis: {field}")
                    # Add default values for missing fields
                    if field == 'Tactic' or field == 'Technique_ID' or field == 'Technique_Name':
                        cleaned_analysis[field] = 'None'
                    elif field == 'Confidence_Score':
                        cleaned_analysis[field] = 0
                    elif field == 'Justification':
                        cleaned_analysis[field] = 'No justification provided'
            
            # Validate confidence score (Smart Normalization)
            confidence = cleaned_analysis.get('Confidence_Score', 0)
            if not isinstance(confidence, int) or confidence < 0:
                logger.warning(f"Invalid confidence score type/negative: {confidence}, setting to 0")
                cleaned_analysis['Confidence_Score'] = 0
            elif confidence > 10:
                # If the AI treats it as a percentage (e.g., 100), normalize it to 10
                normalized_score = 10 if confidence >= 100 else int(confidence / 10)
                logger.info(f"Normalizing high confidence score {confidence} to {normalized_score}")
                cleaned_analysis['Confidence_Score'] = normalized_score
            
            return cleaned_analysis
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.error(f"Raw response: {response.text if hasattr(response, 'text') else str(response)}")
            return self._create_default_analysis()
        except Exception as e:
            logger.error(f"Failed to parse response: {e}")
            return self._create_default_analysis()
    
    def _create_default_analysis(self) -> Dict[str, Any]:
        """Create a default analysis when parsing fails."""
        return {
            'Tactic': 'None',
            'Technique_ID': 'None',
            'Technique_Name': 'None',
            'Confidence_Score': 0,
            'Justification': 'Analysis failed due to API error'
        }

    def _parse_batch_response(self, response: Any, expected_count: int) -> List[Optional[Dict[str, Any]]]:
        """Parse and validate batch Gemini response."""
        try:
            # Extract text from response
            content = response.text.strip()
            
            # Parse JSON
            try:
                analyses = json.loads(content)
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON, creating default analyses")
                return [self._create_default_analysis() for _ in range(expected_count)]
            
            # Handle various response formats
            if isinstance(analyses, dict):
                # Check if it's a single analysis object
                if 'results' in analyses:
                    analyses = analyses['results']
                else:
                    # Single analysis object, convert to array
                    analyses = [analyses]
            elif not isinstance(analyses, list):
                # Something else, convert to array
                analyses = [analyses]
            
            # Ensure we have a list
            if not isinstance(analyses, list):
                analyses = [analyses]
            
            # Validate we have the right number of results
            if len(analyses) != expected_count:
                logger.warning(f"Expected {expected_count} analyses, got {len(analyses)}")
            
            # Validate each analysis
            validated_analyses = []
            for i, analysis in enumerate(analyses):
                try:
                    if not isinstance(analysis, dict):
                        validated_analyses.append(self._create_default_analysis())
                        continue
                    
                    # Apply same fuzzy mapping as single parser
                    cleaned_analysis = {}
                    for key, value in analysis.items():
                        key_lower = key.lower()
                        
                        # Fuzzy key mapping - handle various AI output formats
                        if key_lower in ['tactic', 'tactics', 'attack_tactic']:
                            # Handle null/None values
                            if value is None or value == 'null' or value == '':
                                cleaned_analysis['Tactic'] = 'None'
                            else:
                                cleaned_analysis['Tactic'] = str(value)
                        elif key_lower in ['technique_id', 'techniqueid', 'technique', 'attack_technique_id']:
                            if value is None or value == 'null' or value == '':
                                cleaned_analysis['Technique_ID'] = 'None'
                            else:
                                cleaned_analysis['Technique_ID'] = str(value)
                        elif key_lower in ['technique_name', 'techniquename', 'attack_technique_name']:
                            if value is None or value == 'null' or value == '':
                                cleaned_analysis['Technique_Name'] = 'None'
                            else:
                                cleaned_analysis['Technique_Name'] = str(value)
                        elif key_lower in ['confidence_score', 'confidence', 'score', 'threat_score']:
                            # Convert various score formats to int
                            if value is None or value == 'null' or value == '':
                                cleaned_analysis['Confidence_Score'] = 0
                            else:
                                try:
                                    if isinstance(value, str):
                                        if value.isdigit():
                                            cleaned_analysis['Confidence_Score'] = int(value)
                                        else:
                                            cleaned_analysis['Confidence_Score'] = 0
                                    else:
                                        cleaned_analysis['Confidence_Score'] = int(value)
                                except (ValueError, TypeError):
                                    cleaned_analysis['Confidence_Score'] = 0
                        elif key_lower in ['justification', 'reason', 'explanation', 'analysis']:
                            if value is None or value == 'null' or value == '':
                                cleaned_analysis['Justification'] = 'No justification provided'
                            else:
                                cleaned_analysis['Justification'] = str(value)
                        else:
                            # Keep unknown keys as-is
                            cleaned_analysis[key] = value
                    
                    # Ensure all required fields exist
                    required_fields = ['Tactic', 'Technique_ID', 'Technique_Name', 'Confidence_Score', 'Justification']
                    for field in required_fields:
                        if field not in cleaned_analysis:
                            logger.warning(f"Missing field in analysis {i}: {field}")
                            # Add default values for missing fields
                            if field == 'Tactic' or field == 'Technique_ID' or field == 'Technique_Name':
                                cleaned_analysis[field] = 'None'
                            elif field == 'Confidence_Score':
                                cleaned_analysis[field] = 0
                            elif field == 'Justification':
                                cleaned_analysis[field] = 'No justification provided'
                    
                    # Validate confidence score (Smart Normalization)
                    confidence = cleaned_analysis.get('Confidence_Score', 0)
                    if not isinstance(confidence, int) or confidence < 0:
                        logger.warning(f"Invalid confidence score type/negative: {confidence}, setting to 0")
                        cleaned_analysis['Confidence_Score'] = 0
                    elif confidence > 10:
                        # If the AI treats it as a percentage (e.g., 100), normalize it to 10
                        normalized_score = 10 if confidence >= 100 else int(confidence / 10)
                        logger.info(f"Normalizing high confidence score {confidence} to {normalized_score}")
                        cleaned_analysis['Confidence_Score'] = normalized_score
                    
                    validated_analyses.append(cleaned_analysis)
                    
                except Exception as e:
                    logger.error(f"Failed to validate analysis {i}: {e}")
                    validated_analyses.append(self._create_default_analysis())
            
            # Pad or trim to expected count
            while len(validated_analyses) < expected_count:
                validated_analyses.append(self._create_default_analysis())
            
            return validated_analyses[:expected_count]
            
        except Exception as e:
            logger.error(f"Failed to parse batch response: {e}")
            return [self._create_default_analysis() for _ in range(expected_count)]


class EventMapper:
    """Main application class for mapping events to MITRE ATT&CK techniques."""
    
    def __init__(self):
        self.parser = EventLogParser()
        self.analyzer = GenAIAnalyzer()
        self.results = []
    
    def process_file(self, file_path: str) -> None:
        """Process a file containing Windows Event Log data."""
        try:
            logger.info(f"Parsing events from {file_path}")
            
            # Detect file type and parse
            file_type = self.parser.detect_file_type(file_path)
            if file_type == 'csv':
                events = self.parser.parse_csv(file_path)
            elif file_type == 'json':
                events = self.parser.parse_json(file_path)
            else:
                raise ValueError(f"Unsupported file type: {file_type}")
            
            if not events:
                logger.warning("No events found in file")
                return
            
            logger.info(f"Found {len(events)} events to analyze")
            
            # Process events
            for idx, event in enumerate(events, 1):
                logger.info(f"Analyzing event {idx}/{len(events)}")
                
                # Get analysis from GenAI
                analysis = self.analyzer.analyze_event(event)
                
                # Combine event data with analysis
                result = {
                    'Event': event,
                    'Analysis': analysis,
                    'ProcessedAt': datetime.now(timezone.utc).isoformat()
                }
                
                self.results.append(result)
            
            # Save results
            self.save_results()
            logger.info("Processing complete. Results saved to mapped_events.json")
            
        except Exception as e:
            logger.error(f"Failed to process file: {e}")
            raise
    
    def save_results(self) -> None:
        """Save analysis results to JSON file."""
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
                json.dump(self.results, file, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            raise
    
    def print_results(self) -> None:
        """Print analysis results to console with visual indicators."""
        if not self.results:
            print("No results to display")
            return
        
        print("\n" + "="*80)
        print("AURA THREAT ANALYSIS RESULTS")
        print("="*80)
        
        for idx, result in enumerate(self.results, 1):
            event = result['Event']
            analysis = result['Analysis']
            
            print(f"\nEvent #{idx}:")
            print(f"  Event ID: {event.get('EventID', 'Unknown')}")
            print(f"  Process: {event.get('ProcessName', 'Unknown')}")
            if event.get('CommandLine'):
                print(f"  Command: {event['CommandLine']}")
            print("-" * 50)
            
            if analysis:
                score = analysis.get('Confidence_Score', 0)
                tactic = analysis.get('Tactic', 'Unknown')
                technique = analysis.get('Technique_Name', 'Unknown')
                justification = analysis.get('Justification', 'No justification provided')
                
                # Visual confidence meter
                meter = self._create_confidence_meter(score)
                print(f"Tactic: {tactic}")
                print(f"Technique: {analysis.get('Technique_ID', 'Unknown')} - {technique}")
                print(f"Confidence: {meter}")
                print(f"Justification: {justification}")
            else:
                print("Analysis failed - check logs for details")
        
        print("\n" + "="*80)
    
    def _create_confidence_meter(self, score: int) -> str:
        """Create a visual confidence meter."""
        if score == 0:
            return "🟢 NO THREAT DETECTED"
        elif score <= 3:
            return f"🔵 LOW ({score}/10) ░░░░░░░░░░"
        elif score <= 6:
            return f"🟡 MEDIUM ({score}/10) ████░░░░░░░"
        elif score <= 8:
            return f"🟠 HIGH ({score}/10) ████████░░░"
        else:
            return f"🔴 CRITICAL ({score}/10) ███████████"


def main():
    """Main function to run the event mapper."""
    parser = argparse.ArgumentParser(description='Map Windows Event Logs to MITRE ATT&CK techniques')
    parser.add_argument('file_path', help='Path to the Windows Event Log file (CSV or JSON)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file_path):
        print(f"Error: File not found: {args.file_path}")
        sys.exit(1)
    
    try:
        mapper = EventMapper()
        mapper.process_file(args.file_path)
        mapper.print_results()
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
