#!/usr/bin/env python3
"""
Splunk HTTP Event Collector (HEC) Integration for NX-OS Compliance Checker v2.5
================================================================================

This module provides Splunk HEC integration capabilities for sending compliance
check results to Splunk for real-time monitoring, dashboards, and alerting.

Features:
- Real-time event streaming to Splunk HEC
- Batch sending of all compliance results
- Device metadata enrichment (hostname, scan time, policy version)
- SSL/TLS support with certificate verification options
- Automatic retry with exponential backoff
- Event batching for improved performance
- Support for custom indexes, sourcetypes, and sources

Usage:
    from splunk_hec_integration import SplunkHECExporter
    
    exporter = SplunkHECExporter(
        hec_url="https://splunk.example.com:8088",
        hec_token="your-hec-token",
        index="network_compliance"
    )
    
    # Send all results in batch
    success = exporter.send_compliance_results(checker)
    
    # Or send individual events
    exporter.send_event(result_dict, metadata_dict)

Version: 1.0
Compatible with: NX-OS Compliance Checker v2.5
Author: Network Automation Team
Last Updated: 2025-11-25
"""

import json
import time
import ssl
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from urllib import request, error
from urllib.parse import urlparse
import logging

# Configure module logger
logger = logging.getLogger(__name__)


class SplunkHECError(Exception):
    """Custom exception for Splunk HEC errors"""
    pass


class SplunkHECExporter:
    """
    Splunk HTTP Event Collector (HEC) integration for compliance results.
    
    This class handles sending compliance check results to Splunk via the
    HTTP Event Collector endpoint. It supports both individual event sending
    and batch operations for efficiency.
    
    Attributes:
        hec_url (str): Base URL for Splunk HEC endpoint
        hec_token (str): HEC authentication token
        index (str): Target Splunk index for events
        sourcetype (str): Splunk sourcetype for events
        source (str): Splunk source identifier
        verify_ssl (bool): Whether to verify SSL certificates
        batch_size (int): Maximum events per batch request
        timeout (int): HTTP request timeout in seconds
        max_retries (int): Maximum retry attempts for failed requests
    """
    
    # Default Splunk HEC endpoint path
    HEC_ENDPOINT = "/services/collector/event"
    HEC_BATCH_ENDPOINT = "/services/collector"
    
    # Default configuration
    DEFAULT_SOURCETYPE = "nxos:compliance"
    DEFAULT_SOURCE = "nxos_compliance_checker"
    DEFAULT_INDEX = "network_compliance"
    DEFAULT_BATCH_SIZE = 50
    DEFAULT_TIMEOUT = 30
    DEFAULT_MAX_RETRIES = 3
    
    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        index: str = None,
        sourcetype: str = None,
        source: str = None,
        verify_ssl: bool = True,
        batch_size: int = None,
        timeout: int = None,
        max_retries: int = None
    ):
        """
        Initialize the Splunk HEC exporter.
        
        Args:
            hec_url: Base URL for Splunk HEC (e.g., https://splunk.example.com:8088)
            hec_token: HEC authentication token (UUID format)
            index: Target Splunk index (default: network_compliance)
            sourcetype: Splunk sourcetype (default: nxos:compliance)
            source: Splunk source identifier (default: nxos_compliance_checker)
            verify_ssl: Whether to verify SSL certificates (default: True)
            batch_size: Maximum events per batch request (default: 50)
            timeout: HTTP request timeout in seconds (default: 30)
            max_retries: Maximum retry attempts for failed requests (default: 3)
            
        Raises:
            ValueError: If required parameters are missing or invalid
        """
        if not hec_url:
            raise ValueError("hec_url is required")
        if not hec_token:
            raise ValueError("hec_token is required")
        
        # Validate and normalize HEC URL
        self.hec_url = self._normalize_url(hec_url)
        self.hec_token = hec_token
        
        # Configuration with defaults
        self.index = index or self.DEFAULT_INDEX
        self.sourcetype = sourcetype or self.DEFAULT_SOURCETYPE
        self.source = source or self.DEFAULT_SOURCE
        self.verify_ssl = verify_ssl
        self.batch_size = batch_size or self.DEFAULT_BATCH_SIZE
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.max_retries = max_retries or self.DEFAULT_MAX_RETRIES
        
        # Statistics tracking
        self._events_sent = 0
        self._events_failed = 0
        self._last_error = None
        
        logger.info(f"Initialized Splunk HEC exporter: {self.hec_url}")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize and validate the HEC URL."""
        url = url.strip().rstrip('/')
        
        # Add https:// if no scheme provided
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        # Validate URL format
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError(f"Invalid HEC URL: {url}")
        
        return url
    
    def _strip_emojis(self, text: str) -> str:
        """
        Remove emoji characters from text for Splunk compatibility.
        
        This prevents encoding issues and ensures clean data in Splunk.
        
        Args:
            text: String potentially containing emojis
            
        Returns:
            String with emojis removed and cleaned up
        """
        if not isinstance(text, str):
            return text
        
        # Remove common status emojis and replace with text equivalents
        emoji_map = {
            '✅': '[PASS]',
            '❌': '[FAIL]',
            '⚠️': '[WARN]',
            'ℹ️': '[INFO]',
            '🌟': '',
            '💥': '',
            '📊': ''
        }
        
        result = text
        for emoji, replacement in emoji_map.items():
            result = result.replace(emoji, replacement)
        
        # Remove any remaining emoji-like characters (Unicode ranges)
        emoji_pattern = re.compile("["
            u"\U0001F600-\U0001F64F"  # emoticons
            u"\U0001F300-\U0001F5FF"  # symbols & pictographs
            u"\U0001F680-\U0001F6FF"  # transport & map symbols
            u"\U0001F1E0-\U0001F1FF"  # flags
            u"\U00002700-\U000027BF"  # dingbats
            u"\U0000FE00-\U0000FE0F"  # variation selectors
            u"\U0001F900-\U0001F9FF"  # supplemental symbols
            "]+", flags=re.UNICODE)
        
        result = emoji_pattern.sub('', result)
        
        # Clean up multiple spaces
        result = ' '.join(result.split())
        
        return result.strip()
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context based on verification settings."""
        if self.verify_ssl:
            context = ssl.create_default_context()
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning("SSL certificate verification disabled - not recommended for production")
        return context
    
    def _build_event(
        self,
        event_data: Dict[str, Any],
        timestamp: float = None,
        host: str = None
    ) -> Dict[str, Any]:
        """
        Build a properly formatted Splunk HEC event.
        
        Args:
            event_data: The event payload data
            timestamp: Unix timestamp (default: current time)
            host: Host identifier (default: from event data)
            
        Returns:
            Dict containing the complete HEC event structure
        """
        # Clean event data of emojis
        clean_data = {}
        for key, value in event_data.items():
            if isinstance(value, str):
                clean_data[key] = self._strip_emojis(value)
            elif isinstance(value, dict):
                clean_data[key] = {k: self._strip_emojis(v) if isinstance(v, str) else v 
                                   for k, v in value.items()}
            else:
                clean_data[key] = value
        
        event = {
            "time": timestamp or time.time(),
            "host": host or clean_data.get('hostname', 'unknown'),
            "source": self.source,
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": clean_data
        }
        
        return event
    
    def _send_request(self, payload: str, endpoint: str = None) -> Tuple[bool, str]:
        """
        Send HTTP request to Splunk HEC with retry logic.
        
        Args:
            payload: JSON payload to send
            endpoint: HEC endpoint path (default: single event endpoint)
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        url = f"{self.hec_url}{endpoint or self.HEC_ENDPOINT}"
        
        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json"
        }
        
        ssl_context = self._create_ssl_context()
        
        for attempt in range(1, self.max_retries + 1):
            try:
                req = request.Request(
                    url,
                    data=payload.encode('utf-8'),
                    headers=headers,
                    method='POST'
                )
                
                with request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
                    response_data = json.loads(response.read().decode('utf-8'))
                    
                    if response_data.get('code') == 0:
                        return True, "Success"
                    else:
                        error_msg = response_data.get('text', 'Unknown error')
                        return False, f"HEC error: {error_msg}"
                        
            except error.HTTPError as e:
                error_body = e.read().decode('utf-8') if e.fp else str(e)
                self._last_error = f"HTTP {e.code}: {error_body}"
                logger.warning(f"HEC request failed (attempt {attempt}/{self.max_retries}): {self._last_error}")
                
            except error.URLError as e:
                self._last_error = f"Connection error: {e.reason}"
                logger.warning(f"HEC connection failed (attempt {attempt}/{self.max_retries}): {self._last_error}")
                
            except Exception as e:
                self._last_error = str(e)
                logger.warning(f"HEC request error (attempt {attempt}/{self.max_retries}): {self._last_error}")
            
            # Exponential backoff before retry
            if attempt < self.max_retries:
                wait_time = 2 ** attempt
                logger.debug(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
        
        return False, self._last_error or "Max retries exceeded"
    
    def send_event(
        self,
        event_data: Dict[str, Any],
        timestamp: float = None,
        host: str = None
    ) -> bool:
        """
        Send a single event to Splunk HEC.
        
        Args:
            event_data: Event payload dictionary
            timestamp: Unix timestamp (optional)
            host: Host identifier (optional)
            
        Returns:
            bool: True if event was sent successfully
        """
        event = self._build_event(event_data, timestamp, host)
        payload = json.dumps(event)
        
        success, message = self._send_request(payload)
        
        if success:
            self._events_sent += 1
            logger.debug(f"Event sent successfully: {event_data.get('id', 'unknown')}")
        else:
            self._events_failed += 1
            logger.error(f"Failed to send event: {message}")
        
        return success
    
    def send_batch(self, events: List[Dict[str, Any]]) -> Tuple[int, int]:
        """
        Send multiple events to Splunk HEC in batch.
        
        Events are sent in chunks according to batch_size setting.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            Tuple of (successful_count, failed_count)
        """
        successful = 0
        failed = 0
        
        # Process events in batches
        for i in range(0, len(events), self.batch_size):
            batch = events[i:i + self.batch_size]
            
            # Build batch payload (newline-delimited JSON)
            payload_lines = []
            for event_data in batch:
                event = self._build_event(event_data)
                payload_lines.append(json.dumps(event))
            
            payload = '\n'.join(payload_lines)
            
            success, message = self._send_request(payload, self.HEC_BATCH_ENDPOINT)
            
            if success:
                successful += len(batch)
                self._events_sent += len(batch)
                logger.debug(f"Batch sent successfully: {len(batch)} events")
            else:
                failed += len(batch)
                self._events_failed += len(batch)
                logger.error(f"Batch failed: {message}")
        
        return successful, failed
    
    def send_compliance_results(
        self,
        checker,
        include_summary: bool = True,
        include_passed: bool = True
    ) -> bool:
        """
        Send all compliance results from a checker instance to Splunk.
        
        This is the main integration method that extracts results from the
        compliance checker and sends them to Splunk HEC.
        
        Args:
            checker: ProductionComplianceChecker instance
            include_summary: Whether to send a summary event (default: True)
            include_passed: Whether to include passed checks (default: True)
            
        Returns:
            bool: True if all events were sent successfully
        """
        timestamp = time.time()
        hostname = checker.device_info.get('hostname', 'unknown')
        
        # Build base metadata for all events
        base_metadata = {
            'hostname': hostname,
            'config_file': str(checker.config_file),
            'policy_name': checker.policy.get('metadata', {}).get('policy_name', 'Unknown'),
            'policy_version': checker.policy.get('metadata', {}).get('version', 'Unknown'),
            'checker_version': '2.5',
            'scan_timestamp': datetime.fromtimestamp(timestamp).isoformat()
        }
        
        events = []
        
        # Send summary event first
        if include_summary:
            summary_event = {
                'event_type': 'compliance_summary',
                **base_metadata,
                'total_score': checker.total_score,
                'max_score': checker.max_score,
                'percentage': (checker.total_score / checker.max_score * 100) if checker.max_score > 0 else 0,
                'grade': checker.get_grade(),
                'passed_count': checker.passed_count,
                'failed_count': checker.failed_count,
                'warning_count': checker.warning_count,
                'error_count': checker.error_count,
                'total_checks': len(checker.results)
            }
            events.append(summary_event)
        
        # Prepare individual check results
        for result in checker.results:
            # Skip passed checks if not requested
            if not include_passed and result['status'] == 'PASS':
                continue
            
            check_event = {
                'event_type': 'compliance_check',
                **base_metadata,
                'check_id': result['id'],
                'check_name': result['name'],
                'category': result['category'],
                'severity': result['severity'],
                'status': result['status'],
                'score': result['score'],
                'max_score': result['max_score'],
                'message': result['message'],
                'remediation': result['remediation'],
                'reference': result['reference']
            }
            events.append(check_event)
        
        # Send all events in batch
        successful, failed = self.send_batch(events)
        
        logger.info(f"Compliance results sent to Splunk: {successful} successful, {failed} failed")
        
        return failed == 0
    
    def test_connection(self) -> Tuple[bool, str]:
        """
        Test the Splunk HEC connection.
        
        Sends a test event to verify connectivity and authentication.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        test_event = {
            'event_type': 'connection_test',
            'message': 'NX-OS Compliance Checker HEC connection test',
            'timestamp': datetime.now().isoformat(),
            'checker_version': '2.5'
        }
        
        event = self._build_event(test_event, host='connection_test')
        payload = json.dumps(event)
        
        success, message = self._send_request(payload)
        
        if success:
            return True, f"Successfully connected to Splunk HEC at {self.hec_url}"
        else:
            return False, f"Connection test failed: {message}"
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get event sending statistics.
        
        Returns:
            Dict containing events_sent, events_failed counts
        """
        return {
            'events_sent': self._events_sent,
            'events_failed': self._events_failed,
            'last_error': self._last_error
        }


def add_splunk_arguments(parser) -> None:
    """
    Add Splunk HEC command-line arguments to an argument parser.
    
    This helper function adds the standard Splunk HEC arguments to your
    existing argparse parser.
    
    Args:
        parser: argparse.ArgumentParser instance
        
    Example:
        parser = argparse.ArgumentParser()
        add_splunk_arguments(parser)
        args = parser.parse_args()
    """
    splunk_group = parser.add_argument_group('Splunk HEC Options')
    
    splunk_group.add_argument(
        '--splunk-url',
        metavar='URL',
        help='Splunk HEC URL (e.g., https://splunk.example.com:8088)'
    )
    
    splunk_group.add_argument(
        '--splunk-token',
        metavar='TOKEN',
        help='Splunk HEC authentication token'
    )
    
    splunk_group.add_argument(
        '--splunk-index',
        metavar='INDEX',
        default='network_compliance',
        help='Splunk index for compliance events (default: network_compliance)'
    )
    
    splunk_group.add_argument(
        '--splunk-sourcetype',
        metavar='SOURCETYPE',
        default='nxos:compliance',
        help='Splunk sourcetype (default: nxos:compliance)'
    )
    
    splunk_group.add_argument(
        '--splunk-source',
        metavar='SOURCE',
        default='nxos_compliance_checker',
        help='Splunk source identifier (default: nxos_compliance_checker)'
    )
    
    splunk_group.add_argument(
        '--splunk-no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification (not recommended for production)'
    )
    
    splunk_group.add_argument(
        '--splunk-batch-size',
        metavar='SIZE',
        type=int,
        default=50,
        help='Number of events per batch request (default: 50)'
    )
    
    splunk_group.add_argument(
        '--splunk-skip-passed',
        action='store_true',
        help='Only send failed/warning checks to Splunk (skip passed checks)'
    )
    
    splunk_group.add_argument(
        '--splunk-test-connection',
        action='store_true',
        help='Test Splunk HEC connection and exit'
    )


def create_exporter_from_args(args) -> Optional[SplunkHECExporter]:
    """
    Create a SplunkHECExporter instance from parsed command-line arguments.
    
    Args:
        args: Parsed argparse namespace with Splunk arguments
        
    Returns:
        SplunkHECExporter instance or None if Splunk options not provided
    """
    # Check if Splunk integration is requested
    if not hasattr(args, 'splunk_url') or not args.splunk_url:
        return None
    
    if not args.splunk_token:
        raise ValueError("--splunk-token is required when using --splunk-url")
    
    return SplunkHECExporter(
        hec_url=args.splunk_url,
        hec_token=args.splunk_token,
        index=getattr(args, 'splunk_index', None),
        sourcetype=getattr(args, 'splunk_sourcetype', None),
        source=getattr(args, 'splunk_source', None),
        verify_ssl=not getattr(args, 'splunk_no_verify_ssl', False),
        batch_size=getattr(args, 'splunk_batch_size', None)
    )


# Example Splunk queries for dashboards
SPLUNK_DASHBOARD_QUERIES = """
# ============================================================================
# SPLUNK DASHBOARD QUERIES FOR NX-OS COMPLIANCE CHECKER
# ============================================================================
# Use these SPL queries to build compliance dashboards in Splunk

# 1. Compliance Summary by Device (Last 24 hours)
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_summary" earliest=-24h
| stats latest(percentage) as compliance_pct latest(grade) as grade 
        latest(passed_count) as passed latest(failed_count) as failed 
        by hostname
| sort -compliance_pct

# 2. Failed Checks Trend (Last 7 days)
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_summary" earliest=-7d
| timechart span=1h avg(failed_count) by hostname

# 3. Critical Failures by Category
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_check" 
    status="FAIL" severity="CRITICAL" earliest=-24h
| stats count by hostname, category, check_id, check_name
| sort -count

# 4. Compliance Grade Distribution
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_summary" earliest=-24h
| stats count by grade
| sort grade

# 5. Top 10 Failing Checks Across All Devices
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_check" 
    status="FAIL" earliest=-24h
| stats count by check_id, check_name, severity
| sort -count
| head 10

# 6. Device Compliance Trend Over Time
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_summary" earliest=-30d
| timechart span=1d avg(percentage) by hostname

# 7. Severity Distribution of Failures
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_check" 
    status="FAIL" earliest=-24h
| stats count by severity
| sort -count

# 8. Real-time Alert: Critical Failures
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_check" 
    status="FAIL" severity="CRITICAL" earliest=-5m
| table _time, hostname, check_id, check_name, message

# 9. Compliance Score Comparison (Current vs 24h ago)
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_summary"
| stats latest(percentage) as current_pct earliest(percentage) as prev_pct by hostname
| eval change = current_pct - prev_pct
| sort -change

# 10. Category-wise Failure Analysis
index=network_compliance sourcetype="nxos:compliance" event_type="compliance_check" 
    status="FAIL" earliest=-24h
| stats count as failures by category
| sort -failures
"""


if __name__ == '__main__':
    # Module self-test
    print("Splunk HEC Integration Module for NX-OS Compliance Checker v2.5")
    print("=" * 70)
    print("\nThis module provides:")
    print("  - SplunkHECExporter class for sending events to Splunk")
    print("  - add_splunk_arguments() to add CLI options to your parser")
    print("  - create_exporter_from_args() to create exporter from CLI args")
    print("\nSee SPLUNK_DASHBOARD_QUERIES for example Splunk queries.")
    print("\nExample usage:")
    print("""
    from splunk_hec_integration import SplunkHECExporter, add_splunk_arguments
    
    # Add to your argument parser
    add_splunk_arguments(parser)
    
    # Create exporter and send results
    exporter = SplunkHECExporter(
        hec_url="https://splunk.example.com:8088",
        hec_token="your-token-here",
        index="network_compliance"
    )
    
    # Test connection
    success, message = exporter.test_connection()
    print(message)
    
    # Send compliance results
    exporter.send_compliance_results(checker)
    """)
