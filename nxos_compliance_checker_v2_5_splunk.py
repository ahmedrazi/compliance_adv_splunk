#!/usr/bin/env python3
"""
Production-Quality Template Compliance Checker v2.5 with Splunk HEC Integration
================================================================================

Enterprise-grade compliance checker with unified value checking approach and
Splunk HTTP Event Collector (HEC) integration for real-time monitoring.

Key Features:
- Unified value checking (equals, greater_than, less_than, range)
- Backward compatible with check_type: value_range
- Enhanced error messages with units
- WARN for advisory range checks, FAIL for mandatory checks
- Support for console, JSON, CSV, and syslog output formats
- NEW: Splunk HEC integration for real-time event streaming

Version: 2.5
Last Updated: 2025-11-25
"""

from ciscoconfparse2 import CiscoConfParse
import yaml
import sys
import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any
import argparse
import re

# Import Splunk HEC integration
try:
    from splunk_hec_integration import (
        SplunkHECExporter, 
        add_splunk_arguments, 
        create_exporter_from_args
    )
    SPLUNK_AVAILABLE = True
except ImportError:
    SPLUNK_AVAILABLE = False


class ProductionComplianceChecker:
    """Production-quality template-driven compliance checker with unified value checking"""
    
    def __init__(self, config_file: str, policy_file: str = None, verbose: bool = False):
        """
        Initialize checker with config and policy files
        
        Args:
            config_file: Path to device configuration file
            policy_file: Path to YAML policy template (optional)
            verbose: Enable verbose output
        """
        self.config_file = config_file
        self.verbose = verbose
        
        # Auto-detect syntax from policy or default to nxos
        if policy_file and Path(policy_file).exists():
            with open(policy_file, 'r') as f:
                temp_policy = yaml.safe_load(f)
                syntax = temp_policy.get('metadata', {}).get('syntax', 'nxos')
        else:
            syntax = 'nxos'
        
        self.parse = CiscoConfParse(config_file, syntax=syntax)
        
        # Load policy template
        if policy_file is None:
            policy_file = Path(__file__).parent / "nxos_compliance_policy_v2_5.yaml"
        
        if not Path(policy_file).exists():
            raise FileNotFoundError(f"Policy file not found: {policy_file}")
        
        with open(policy_file, 'r') as f:
            self.policy = yaml.safe_load(f)
        
        self.results = []
        self.passed_count = 0
        self.failed_count = 0
        self.warning_count = 0
        self.info_count = 0
        self.error_count = 0
        self.total_score = 0
        self.max_score = 0
        self.device_info = self._extract_device_info()
        
    def _extract_device_info(self) -> Dict[str, str]:
        """Extract device information from configuration"""
        info = {
            'hostname': 'Unknown',
            'version': 'Unknown',
            'platform': 'Unknown'
        }
        
        # Extract hostname - NX-OS format with improved pattern
        hostname_objs = self.parse.find_objects(r'^hostname\s+\S+')
        if hostname_objs:
            match = re.search(r'^hostname\s+(\S+)', hostname_objs[0].text)
            if match:
                info['hostname'] = match.group(1)
        
        # Extract version info - try multiple NX-OS patterns
        version_patterns = [
            r'^version\s+\S+',
            r'^kickstart:\s+version\s+\S+',
            r'^system:\s+version\s+\S+',
        ]
        
        for pattern in version_patterns:
            version_objs = self.parse.find_objects(pattern)
            if version_objs:
                info['version'] = version_objs[0].text
                break
        
        return info
    
    def _strip_emojis(self, text: str) -> str:
        """
        Remove emoji characters from text for structured outputs (JSON/CSV/syslog).
        
        This prevents encoding issues and compatibility problems across different
        platforms, parsers, and log aggregation systems.
        
        Args:
            text: String potentially containing emojis
            
        Returns:
            String with emojis removed and cleaned up
        """
        # Remove common emojis used in our output
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
        # Covers most common emojis
        emoji_pattern = re.compile("["
            u"\U0001F600-\U0001F64F"  # emoticons
            u"\U0001F300-\U0001F5FF"  # symbols & pictographs
            u"\U0001F680-\U0001F6FF"  # transport & map symbols
            u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
            u"\U00002700-\U000027BF"  # dingbats
            u"\U0000FE00-\U0000FE0F"  # variation selectors
            u"\U0001F900-\U0001F9FF"  # supplemental symbols
            "]+", flags=re.UNICODE)
        
        result = emoji_pattern.sub('', result)
        
        # Clean up multiple spaces
        result = ' '.join(result.split())
        
        return result.strip()
    
    def check_presence(self, check: Dict) -> Tuple[str, str]:
        """Check if a pattern is present in config"""
        pattern = check['pattern']
        objs = self.parse.find_objects(pattern)
        
        if objs:
            return ('PASS', f'✅ Found: {objs[0].text}')
        else:
            return ('FAIL', f'❌ Required configuration not found: {pattern}')
    
    def check_absence(self, check: Dict) -> Tuple[str, str]:
        """Check if a pattern is absent from config"""
        pattern = check['pattern']
        objs = self.parse.find_objects(pattern)
        
        if not objs:
            return ('PASS', '✅ Insecure configuration correctly absent')
        else:
            return ('FAIL', f'❌ Insecure configuration found: {objs[0].text}')
    
    def check_value(self, check: Dict) -> Tuple[str, str]:
        """
        Unified value checking for absolute values and ranges
        
        Supports:
        - equals: exact value match (FAIL if not matched - mandatory)
        - greater_than: value must be greater than expected (FAIL if not)
        - less_than: value must be less than expected (FAIL if not)
        - range: value should be within min/max range (WARN if not - advisory)
        
        Backward Compatibility:
        - Automatically handles check_type: value_range from old policy files
        - Treats value_range as comparison: range
        
        Args:
            check: Check definition from policy file
            
        Returns:
            Tuple[str, str]: (status, message) where status is PASS/FAIL/WARN
        """
        pattern = check['pattern']
        expected_value = check.get('expected_value', '')
        comparison = check.get('comparison', 'equals')
        unit = check.get('unit', '')
        
        # Backward compatibility: auto-detect range checks from old policy format
        check_type = check.get('check_type', '')
        if check_type == 'value_range':
            comparison = 'range'
            if self.verbose:
                print(f"  [INFO] Auto-detected range check for {check.get('id', 'unknown')} (legacy format)")
        
        objs = self.parse.find_objects(pattern)
        
        if not objs:
            return ('FAIL', f'❌ Configuration not found: {pattern}')
        
        config_line = objs[0].text
        
        # Extract numeric value from config line
        match = re.search(r'\d+', config_line)
        if not match:
            return ('FAIL', f'❌ No numeric value found in: {config_line}')
        
        actual_value = int(match.group())
        
        # Handle different comparison types
        if comparison == 'equals':
            expected = int(expected_value)
            if actual_value == expected:
                return ('PASS', f'✅ Value matches required: {actual_value}{unit}')
            else:
                return ('FAIL', f'❌ Value {actual_value}{unit} does not match required value {expected}{unit}')
        
        elif comparison == 'greater_than':
            expected = int(expected_value)
            if actual_value > expected:
                return ('PASS', f'✅ Value {actual_value}{unit} > {expected}{unit}')
            else:
                return ('FAIL', f'❌ Value {actual_value}{unit} not > {expected}{unit}')
        
        elif comparison == 'less_than':
            expected = int(expected_value)
            if actual_value < expected:
                return ('PASS', f'✅ Value {actual_value}{unit} < {expected}{unit}')
            else:
                return ('FAIL', f'❌ Value {actual_value}{unit} not < {expected}{unit}')
        
        elif comparison == 'range':
            min_val = int(check.get('min_value', 0))
            max_val = int(check.get('max_value', 999999))
            
            if min_val <= actual_value <= max_val:
                return ('PASS', f'✅ Optimal value: {actual_value}{unit} (within {min_val}-{max_val}{unit} range)')
            else:
                # For range checks, use WARN (advisory) instead of FAIL (mandatory)
                if actual_value < min_val:
                    return ('WARN', f'⚠️  Value {actual_value}{unit} below optimal range ({min_val}-{max_val}{unit}). Consider increasing for better performance.')
                else:
                    return ('WARN', f'⚠️  Value {actual_value}{unit} above optimal range ({min_val}-{max_val}{unit}). Consider decreasing for better failover.')
        
        return ('FAIL', f'❌ Unknown comparison type: {comparison}')
    
    def check_vty_lines(self, check: Dict) -> Tuple[str, str]:
        """Check VTY line configurations"""
        parent_pattern = check['parent_pattern']
        child_pattern = check['child_pattern']
        child_not_pattern = check.get('child_not_pattern', None)
        
        vty_lines = self.parse.find_objects(parent_pattern)
        
        if not vty_lines:
            return ('WARN', 'ℹ️  No VTY lines found')
        
        failed_lines = []
        for vty in vty_lines:
            # Check for required child pattern
            children = vty.re_search_children(child_pattern)
            
            if not children:
                failed_lines.append(f'{vty.text}: missing {child_pattern}')
                continue
            
            # Check for forbidden pattern if specified
            if child_not_pattern:
                bad_children = vty.re_search_children(child_not_pattern)
                if bad_children:
                    failed_lines.append(f'{vty.text}: found {child_not_pattern}')
        
        if failed_lines:
            return ('FAIL', f'❌ {"; ".join(failed_lines)}')
        else:
            return ('PASS', f'✅ {len(vty_lines)} VTY line(s) configured correctly')
    
    def check_console_line(self, check: Dict) -> Tuple[str, str]:
        """Check console line configuration"""
        parent_pattern = check['parent_pattern']
        child_pattern = check['child_pattern']
        
        console_lines = self.parse.find_objects(parent_pattern)
        
        if not console_lines:
            return ('WARN', 'ℹ️  No console lines found')
        
        for console in console_lines:
            children = console.re_search_children(child_pattern)
            if not children:
                return ('FAIL', f'❌ {console.text}: missing {child_pattern}')
        
        return ('PASS', '✅ Console configured correctly')
    
    def check_interface(self, check: Dict) -> Tuple[str, str]:
        """Check interface configurations"""
        interface_pattern = check.get('interface_pattern')
        interface_not_pattern = check.get('interface_not_pattern')
        
        interfaces = self.parse.find_objects(r'^interface')
        
        # Skip types specified in policy
        skip_types = check.get('skip_types', ['Loopback', 'Null'])
        skip_pattern = '|'.join(skip_types)
        
        active_interfaces = [
            intf for intf in interfaces 
            if not re.search(skip_pattern, intf.text, re.IGNORECASE)
        ]
        
        if not active_interfaces:
            return ('WARN', 'ℹ️  No active interfaces found')
        
        failed_interfaces = []
        
        for intf in active_interfaces:
            if interface_pattern:
                # Check for required pattern
                children = intf.re_search_children(interface_pattern)
                if not children:
                    failed_interfaces.append(intf.text)
            
            if interface_not_pattern:
                # Check for forbidden pattern
                children = intf.re_search_children(interface_not_pattern)
                if children:
                    failed_interfaces.append(f'{intf.text}: {children[0].text}')
        
        if failed_interfaces:
            count = len(failed_interfaces)
            sample = ', '.join(failed_interfaces[:3])
            suffix = '...' if count > 3 else ''
            return ('FAIL', f'❌ {count} interface(s) failed: {sample}{suffix}')
        else:
            return ('PASS', f'✅ {len(active_interfaces)} interface(s) configured correctly')
    
    def check_bgp_log_neighbor_changes_all_vrfs(self, check: Dict) -> Tuple[str, str]:
        """
        Check if BGP log-neighbor-changes is configured in default VRF and all BGP-enabled VRFs.
        """
        pattern = check.get('pattern', 'log-neighbor-changes')
        
        # Find BGP router configuration
        bgp_objs = self.parse.find_objects(r'^router bgp')
        
        if not bgp_objs:
            return ('FAIL', '❌ BGP not configured on this device')
        
        bgp_obj = bgp_objs[0]
        
        # Check if log-neighbor-changes is in default/global BGP context
        global_log_neighbor = bgp_obj.re_search_children(r'^\s+log-neighbor-changes')
        
        if not global_log_neighbor:
            return ('FAIL', '❌ log-neighbor-changes NOT configured in default/global BGP context')
        
        # Find all VRF configurations under BGP
        vrf_objs = bgp_obj.re_search_children(r'^\s+vrf\s+\S+')
        
        if not vrf_objs:
            return ('PASS', '✅ log-neighbor-changes configured in default BGP VRF (no additional BGP VRFs found)')
        
        # Check each BGP VRF for log-neighbor-changes
        vrfs_missing_log = []
        vrfs_with_log = []
        
        for vrf_obj in vrf_objs:
            vrf_name = vrf_obj.text.strip().split()[1]
            vrf_log_neighbor = vrf_obj.re_search_children(r'^\s+log-neighbor-changes')
            
            if vrf_log_neighbor:
                vrfs_with_log.append(vrf_name)
            else:
                vrfs_missing_log.append(vrf_name)
        
        total_bgp_vrfs = len(vrf_objs)
        
        if vrfs_missing_log:
            missing_list = ', '.join(vrfs_missing_log[:5])
            if len(vrfs_missing_log) > 5:
                missing_list += f' (+{len(vrfs_missing_log) - 5} more)'
            
            return ('FAIL', 
                    f'❌ log-neighbor-changes configured in default BGP VRF but MISSING in {len(vrfs_missing_log)}/{total_bgp_vrfs} BGP VRF(s). '
                    f'Missing in: {missing_list}')
        else:
            return ('PASS', 
                    f'✅ log-neighbor-changes configured in default BGP VRF and all {total_bgp_vrfs} BGP VRF(s): '
                    f'{", ".join(vrfs_with_log[:5])}{"..." if len(vrfs_with_log) > 5 else ""}')
    
    def execute_check(self, check: Dict) -> Dict:
        """Execute a single compliance check"""
        check_type = check.get('check_type', 'unknown')
        
        # Route to appropriate check method
        check_methods = {
            'presence': self.check_presence,
            'absence': self.check_absence,
            'value': self.check_value,
            'value_range': self.check_value,
            'vty_lines': self.check_vty_lines,
            'console_line': self.check_console_line,
            'interface': self.check_interface,
            'complex': self.check_bgp_log_neighbor_changes_all_vrfs,
        }
        
        if check_type not in check_methods:
            status = 'ERROR'
            message = f'❌ Unknown check type: {check_type}'
        else:
            try:
                status, message = check_methods[check_type](check)
            except Exception as e:
                status = 'ERROR'
                message = f'❌ Check failed with error: {str(e)}'
                if self.verbose:
                    import traceback
                    print(f"\nERROR in check {check.get('id', 'unknown')}: {e}")
                    traceback.print_exc()
        
        # Calculate score
        severity = check.get('severity', 'MEDIUM')
        
        if 'scoring' in self.policy and 'weights' in self.policy['scoring']:
            weights = self.policy['scoring']['weights']
        else:
            weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 5, 'LOW': 3}
        
        weight = weights.get(severity, 5)
        
        if status == 'PASS':
            score = weight
            self.passed_count += 1
        elif status == 'FAIL':
            score = 0
            self.failed_count += 1
        elif status == 'WARN':
            score = weight // 2
            self.warning_count += 1
        elif status == 'INFO':
            score = weight
            self.info_count += 1
        else:  # ERROR
            score = 0
            self.error_count += 1
        
        self.total_score += score
        self.max_score += weight
        
        result = {
            'id': check.get('id', 'UNKNOWN'),
            'name': check.get('name', 'Unnamed Check'),
            'category': check.get('category', 'General'),
            'severity': severity,
            'status': status,
            'message': message,
            'remediation': check.get('remediation', 'No remediation guidance provided'),
            'reference': check.get('reference', 'No reference provided'),
            'score': score,
            'max_score': weight
        }
        
        return result
    
    def run_all_checks(self) -> List[Dict]:
        """Run all compliance checks from policy"""
        print(f"\n{'='*80}")
        print(f"Production Compliance Checker v2.5 (with Splunk HEC Integration)")
        print(f"{'='*80}")
        print(f"Device:     {self.device_info['hostname']}")
        print(f"Config:     {Path(self.config_file).name}")
        print(f"Policy:     {self.policy['metadata']['policy_name']} v{self.policy['metadata']['version']}")
        print(f"Scan Time:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}\n")
        
        # Get all check categories from policy
        check_categories = []
        for key in self.policy.keys():
            if key not in ['metadata', 'scoring'] and isinstance(self.policy[key], list):
                check_categories.append((key, self.policy[key]))
        
        # Run checks for each category
        for category_key, checks in check_categories:
            category_name = category_key.replace('_', ' ').title()
            print(f"Running {category_name} checks ({len(checks)} checks)...")
            
            for check in checks:
                result = self.execute_check(check)
                self.results.append(result)
                
                if self.verbose:
                    status_icon = {
                        'PASS': '✅ [PASS]', 
                        'FAIL': '❌ [FAIL]', 
                        'WARN': '⚠️  [WARN]', 
                        'INFO': 'ℹ️  [INFO]', 
                        'ERROR': '❌ [ERROR]'
                    }
                    icon = status_icon.get(result['status'], '[?]')
                    print(f"  {icon} [{result['id']}] {result['name']}: {result['status']}")
        
        print(f"\n{'='*80}")
        print(f"Compliance scan completed")
        print(f"{'='*80}\n")
        
        return self.results
    
    def get_grade(self) -> str:
        """Calculate letter grade based on score"""
        if self.max_score == 0:
            return 'N/A'
        
        percentage = (self.total_score / self.max_score) * 100
        
        if 'scoring' in self.policy and 'thresholds' in self.policy['scoring']:
            thresholds = self.policy['scoring']['thresholds']
        else:
            thresholds = {'excellent': 90, 'good': 80, 'fair': 70, 'poor': 60}
        
        if percentage >= thresholds.get('excellent', 90):
            return 'A'
        elif percentage >= thresholds.get('good', 80):
            return 'B'
        elif percentage >= thresholds.get('fair', 70):
            return 'C'
        elif percentage >= thresholds.get('poor', 60):
            return 'D'
        else:
            return 'F'
    
    def display_results(self):
        """Display comprehensive check results"""
        
        failed = [r for r in self.results if r['status'] == 'FAIL']
        warned = [r for r in self.results if r['status'] == 'WARN']
        errors = [r for r in self.results if r['status'] == 'ERROR']
        passed = [r for r in self.results if r['status'] == 'PASS']
        
        if errors:
            print(f"\n{'='*80}")
            print("❌ CHECK ERRORS (Configuration Issues)")
            print(f"{'='*80}")
            self._print_detailed_results(errors)
        
        if failed:
            print(f"\n{'='*80}")
            print("❌ FAILED CHECKS (Require Immediate Attention)")
            print(f"{'='*80}")
            self._print_detailed_results(failed)
        
        if warned:
            print(f"\n{'='*80}")
            print("⚠️  WARNINGS (Recommended Improvements)")
            print(f"{'='*80}")
            self._print_detailed_results(warned)
        
        print(f"\n{'='*80}")
        print("📊 COMPLIANCE SUMMARY")
        print(f"{'='*80}")
        
        percentage = (self.total_score / self.max_score * 100) if self.max_score > 0 else 0
        grade = self.get_grade()
        
        grade_status = {
            'A': '🌟 EXCELLENT', 'B': '✅ GOOD', 'C': '⚠️  FAIR', 'D': '❌ POOR', 'F': '💥 FAILING'
        }
        grade_label = grade_status.get(grade, 'UNKNOWN')
        
        print(f"\nOverall Score: {self.total_score}/{self.max_score} ({percentage:.1f}%)")
        print(f"Final Grade:   {grade} ({grade_label})")
        
        print(f"\n{'Status':<20} {'Count':<10} {'Percentage'}")
        print(f"{'-'*50}")
        
        total_checks = len(self.results)
        if total_checks > 0:
            print(f"{'✅ [PASS] Passed':<20} {self.passed_count:<10} {(self.passed_count/total_checks*100):.1f}%")
            print(f"{'❌ [FAIL] Failed':<20} {self.failed_count:<10} {(self.failed_count/total_checks*100):.1f}%")
            print(f"{'⚠️  [WARN] Warnings':<20} {self.warning_count:<10} {(self.warning_count/total_checks*100):.1f}%")
            if self.error_count > 0:
                print(f"{'❌ [ERROR] Errors':<20} {self.error_count:<10} {(self.error_count/total_checks*100):.1f}%")
            print(f"{'-'*50}")
            print(f"{'Total':<20} {total_checks:<10} 100.0%")
        
        print(f"\n{'='*80}\n")
    
    def _print_detailed_results(self, results: List[Dict]):
        """Print detailed results with remediation"""
        for idx, result in enumerate(results, 1):
            status_icon = {
                'PASS': '✅ [PASS]',
                'FAIL': '❌ [FAIL]',
                'WARN': '⚠️  [WARN]',
                'INFO': 'ℹ️  [INFO]',
                'ERROR': '❌ [ERROR]'
            }.get(result['status'], '[?]')
            
            print(f"\n{idx}. {status_icon} [{result['id']}] {result['name']}")
            print(f"   Category:   {result['category']}")
            print(f"   Severity:   {result['severity']}")
            print(f"   Status:     {result['status']}")
            print(f"   Message:    {result['message']}")
            
            if result['status'] in ['FAIL', 'WARN', 'ERROR']:
                print(f"\n   Remediation:")
                remediation_lines = result['remediation'].split('\n')
                for line in remediation_lines:
                    print(f"      {line}")
                
                if result['reference'] and result['reference'] != 'No reference provided':
                    print(f"\n   Reference: {result['reference']}")
            
            print(f"   {'-'*76}")
    
    def export_json(self, output_file: str):
        """Export results to JSON (emojis removed for compatibility)"""
        
        clean_results = []
        for result in self.results:
            clean_result = result.copy()
            clean_result['message'] = self._strip_emojis(result['message'])
            clean_result['name'] = self._strip_emojis(result['name'])
            clean_results.append(clean_result)
        
        output = {
            'metadata': {
                'device': self.device_info['hostname'],
                'config_file': str(self.config_file),
                'policy': self.policy['metadata'],
                'timestamp': datetime.now().isoformat(),
                'checker_version': '2.5'
            },
            'summary': {
                'score': self.total_score,
                'max_score': self.max_score,
                'percentage': (self.total_score / self.max_score * 100) if self.max_score > 0 else 0,
                'grade': self.get_grade(),
                'passed': self.passed_count,
                'failed': self.failed_count,
                'warnings': self.warning_count,
                'errors': self.error_count,
                'total': len(self.results)
            },
            'results': clean_results
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ [SUCCESS] JSON report exported to: {output_file}")
    
    def export_csv(self, output_file: str):
        """Export results to CSV (emojis removed for compatibility)"""
        
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['id', 'name', 'category', 'severity', 'status', 'message', 'score', 'max_score', 'remediation', 'reference']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in self.results:
                clean_row = {
                    'id': result['id'],
                    'name': self._strip_emojis(result['name']),
                    'category': result['category'],
                    'severity': result['severity'],
                    'status': result['status'],
                    'message': self._strip_emojis(result['message']),
                    'score': result['score'],
                    'max_score': result['max_score'],
                    'remediation': result['remediation'],
                    'reference': result['reference']
                }
                writer.writerow(clean_row)
        
        print(f"✅ [SUCCESS] CSV report exported to: {output_file}")
    
    def export_structured_log(self, output_file: str = None):
        """Export results in structured log format for syslog/Splunk (emojis removed)"""
        
        def format_log_line(result: Dict) -> str:
            def escape_value(v):
                if v is None:
                    return ""
                v = self._strip_emojis(str(v))
                s = v.replace('"', '\\"').replace('\n', ' ').replace('\r', '')
                return f'"{s}"' if ' ' in s or '=' in s else s
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            hostname = self.device_info.get('hostname', 'Unknown')
            
            log_parts = [
                f'timestamp={timestamp}',
                f'hostname={hostname}',
                f'check_id={escape_value(result["id"])}',
                f'check_name={escape_value(result["name"])}',
                f'category={escape_value(result["category"])}',
                f'severity={result["severity"]}',
                f'status={result["status"]}',
                f'score={result["score"]}',
                f'max_score={result["max_score"]}',
                f'message={escape_value(result["message"])}',
            ]
            
            return ' '.join(log_parts)
        
        lines = [format_log_line(result) for result in self.results]
        
        if output_file:
            with open(output_file, 'w') as f:
                for line in lines:
                    f.write(line + '\n')
            print(f"✅ [SUCCESS] Structured log exported to: {output_file}")
        else:
            for line in lines:
                print(line)
    
    def export_to_splunk(
        self,
        exporter: 'SplunkHECExporter',
        include_passed: bool = True
    ) -> bool:
        """
        Export compliance results to Splunk via HEC.
        
        Args:
            exporter: SplunkHECExporter instance
            include_passed: Whether to include passed checks (default: True)
            
        Returns:
            bool: True if all events were sent successfully
        """
        success = exporter.send_compliance_results(
            self,
            include_summary=True,
            include_passed=include_passed
        )
        
        stats = exporter.get_statistics()
        
        if success:
            print(f"✅ [SUCCESS] Sent {stats['events_sent']} events to Splunk HEC")
        else:
            print(f"❌ [ERROR] Splunk HEC export had {stats['events_failed']} failures")
            if stats['last_error']:
                print(f"   Last error: {stats['last_error']}")
        
        return success


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Production-Quality Template Compliance Checker v2.5 with Splunk HEC Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic compliance check
  python nxos_compliance_checker_v2_5_splunk.py config.txt
  
  # Verbose output
  python nxos_compliance_checker_v2_5_splunk.py config.txt --verbose
  
  # JSON output for analysis
  python nxos_compliance_checker_v2_5_splunk.py config.txt --format json --output results.json
  
  # Send results to Splunk HEC
  python nxos_compliance_checker_v2_5_splunk.py config.txt \\
      --splunk-url https://splunk.example.com:8088 \\
      --splunk-token your-hec-token \\
      --splunk-index network_compliance
  
  # Splunk with only failed checks (skip passed)
  python nxos_compliance_checker_v2_5_splunk.py config.txt \\
      --splunk-url https://splunk.example.com:8088 \\
      --splunk-token your-hec-token \\
      --splunk-skip-passed
  
  # Test Splunk HEC connection
  python nxos_compliance_checker_v2_5_splunk.py config.txt \\
      --splunk-url https://splunk.example.com:8088 \\
      --splunk-token your-hec-token \\
      --splunk-test-connection

Splunk Dashboard:
  After sending data, use these Splunk searches:
  
  # View all compliance events
  index=network_compliance sourcetype="nxos:compliance"
  
  # Failed checks summary
  index=network_compliance event_type="compliance_check" status="FAIL"
  | stats count by hostname, check_id, severity
  
  # Compliance score trend
  index=network_compliance event_type="compliance_summary"
  | timechart avg(percentage) by hostname
        """
    )
    
    parser.add_argument('config_file', help='Device configuration file')
    parser.add_argument('--policy', help='YAML policy template file', default=None)
    parser.add_argument('--format', choices=['console', 'json', 'csv', 'syslog'], 
                       default='console', 
                       help='Output format')
    parser.add_argument('--output', help='Output file path', default=None)
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    # Add Splunk HEC arguments if module is available
    if SPLUNK_AVAILABLE:
        add_splunk_arguments(parser)
    
    args = parser.parse_args()
    
    if not Path(args.config_file).exists():
        print(f"❌ [ERROR] File '{args.config_file}' not found")
        sys.exit(1)
    
    try:
        # Handle Splunk connection test
        if SPLUNK_AVAILABLE and getattr(args, 'splunk_test_connection', False):
            if not args.splunk_url or not args.splunk_token:
                print("❌ [ERROR] --splunk-url and --splunk-token required for connection test")
                sys.exit(1)
            
            exporter = create_exporter_from_args(args)
            success, message = exporter.test_connection()
            print(message)
            sys.exit(0 if success else 1)
        
        # Run compliance checks
        checker = ProductionComplianceChecker(args.config_file, args.policy, args.verbose)
        checker.run_all_checks()
        
        if args.format != 'syslog':
            checker.display_results()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = Path(args.config_file).stem
        
        # Export to file format
        if args.format == 'json':
            output_file = args.output or f"{base_name}_compliance_{timestamp}.json"
            checker.export_json(output_file)
        elif args.format == 'csv':
            output_file = args.output or f"{base_name}_compliance_{timestamp}.csv"
            checker.export_csv(output_file)
        elif args.format == 'syslog':
            output_file = args.output
            checker.export_structured_log(output_file)
        
        # Export to Splunk HEC if configured
        if SPLUNK_AVAILABLE and getattr(args, 'splunk_url', None):
            exporter = create_exporter_from_args(args)
            include_passed = not getattr(args, 'splunk_skip_passed', False)
            checker.export_to_splunk(exporter, include_passed=include_passed)
        
        if checker.failed_count > 0 or checker.error_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except FileNotFoundError as e:
        print(f"❌ [ERROR] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"💥 [FATAL ERROR] {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
