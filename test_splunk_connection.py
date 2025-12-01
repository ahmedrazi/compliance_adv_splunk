#!/usr/bin/env python3
"""
Splunk HEC Connection Tester
============================

A standalone script to test Splunk HEC connectivity before running
the full compliance checker. This helps isolate connection issues.

Usage:
    python test_splunk_connection.py --url http://localhost:8088 --token YOUR_TOKEN
"""

import json
import ssl
import argparse
import sys
from datetime import datetime
from urllib import request, error


def test_hec_connection(hec_url: str, token: str, verify_ssl: bool = True, index: str = "main") -> bool:
    """
    Test Splunk HEC connection by sending a test event.
    
    Args:
        hec_url: Splunk HEC URL (e.g., http://localhost:8088)
        token: HEC authentication token
        verify_ssl: Whether to verify SSL certificates
        index: Target index for test event
        
    Returns:
        bool: True if connection successful
    """
    # Normalize URL
    hec_url = hec_url.rstrip('/')
    if not hec_url.startswith(('http://', 'https://')):
        hec_url = f"https://{hec_url}"
    
    endpoint = f"{hec_url}/services/collector/event"
    
    # Create test event
    test_event = {
        "time": datetime.now().timestamp(),
        "host": "hec_test",
        "source": "splunk_connection_test",
        "sourcetype": "nxos:compliance",
        "index": index,
        "event": {
            "event_type": "connection_test",
            "message": "NX-OS Compliance Checker HEC connection test",
            "timestamp": datetime.now().isoformat(),
            "test_id": f"test_{int(datetime.now().timestamp())}"
        }
    }
    
    payload = json.dumps(test_event).encode('utf-8')
    
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json"
    }
    
    # Create SSL context
    if verify_ssl:
        ssl_context = ssl.create_default_context()
    else:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    
    print(f"\n{'='*60}")
    print("Splunk HEC Connection Test")
    print(f"{'='*60}")
    print(f"URL:        {endpoint}")
    print(f"Index:      {index}")
    print(f"SSL Verify: {verify_ssl}")
    print(f"{'='*60}\n")
    
    try:
        req = request.Request(
            endpoint,
            data=payload,
            headers=headers,
            method='POST'
        )
        
        print("📡 Sending test event...")
        
        with request.urlopen(req, timeout=30, context=ssl_context) as response:
            response_data = json.loads(response.read().decode('utf-8'))
            
            if response_data.get('code') == 0:
                print(f"✅ SUCCESS: {response_data.get('text', 'Event received')}")
                print(f"\n📊 Test event sent successfully!")
                print(f"\nVerify in Splunk with this search:")
                print(f'   index={index} sourcetype="nxos:compliance" event_type="connection_test"')
                return True
            else:
                print(f"❌ FAILED: {response_data.get('text', 'Unknown error')}")
                return False
                
    except error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else str(e)
        print(f"❌ HTTP Error {e.code}")
        print(f"   Response: {error_body}")
        
        if e.code == 401:
            print("\n💡 Tip: Check that your HEC token is correct and not disabled")
        elif e.code == 403:
            print("\n💡 Tip: Check that HEC is enabled globally and token has index permissions")
        elif e.code == 400:
            print("\n💡 Tip: Check event format or index configuration")
            
        return False
        
    except error.URLError as e:
        print(f"❌ Connection Error: {e.reason}")
        
        if "Connection refused" in str(e.reason):
            print("\n💡 Tips:")
            print("   - Is Splunk running? Check: docker ps")
            print("   - Is port 8088 exposed? Check: docker port splunk-test")
            print("   - Is HEC enabled? Settings > Data Inputs > HTTP Event Collector")
        elif "SSL" in str(e.reason) or "certificate" in str(e.reason).lower():
            print("\n💡 Tip: Try using --no-verify-ssl flag")
            
        return False
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Test Splunk HEC Connection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with HTTP (no SSL)
  python test_splunk_connection.py \\
      --url http://localhost:8088 \\
      --token your-hec-token

  # Test with HTTPS (skip SSL verification for self-signed certs)
  python test_splunk_connection.py \\
      --url https://splunk.example.com:8088 \\
      --token your-hec-token \\
      --no-verify-ssl

  # Test with specific index
  python test_splunk_connection.py \\
      --url http://localhost:8088 \\
      --token your-hec-token \\
      --index network_compliance
        """
    )
    
    parser.add_argument(
        '--url', '-u',
        required=True,
        help='Splunk HEC URL (e.g., http://localhost:8088)'
    )
    
    parser.add_argument(
        '--token', '-t',
        required=True,
        help='HEC authentication token'
    )
    
    parser.add_argument(
        '--index', '-i',
        default='main',
        help='Target Splunk index (default: main)'
    )
    
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Skip SSL certificate verification'
    )
    
    args = parser.parse_args()
    
    success = test_hec_connection(
        hec_url=args.url,
        token=args.token,
        verify_ssl=not args.no_verify_ssl,
        index=args.index
    )
    
    print(f"\n{'='*60}")
    if success:
        print("✅ Connection test PASSED")
        print("\nYou can now run the full compliance checker with Splunk export:")
        print(f"  python nxos_compliance_checker_v2_5_splunk.py config.txt \\")
        print(f"      --splunk-url {args.url} \\")
        print(f"      --splunk-token {args.token} \\")
        if args.no_verify_ssl:
            print("      --splunk-no-verify-ssl")
    else:
        print("❌ Connection test FAILED")
        print("\nPlease fix the issues above before running the compliance checker")
    print(f"{'='*60}\n")
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
