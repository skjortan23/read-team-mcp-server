#!/usr/bin/env python3
"""
Demonstration of streaming port scan functionality.

This example shows how to use the new streaming port scan feature
to get real-time progress updates as hosts are discovered.
"""

import sys
import os
import time
from datetime import datetime

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from red_team_mcp.masscan_scanner import port_scan_streaming


def progress_callback(progress_data):
    """Handle progress updates from the streaming port scan."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if progress_data['type'] == 'host_discovered':
        host = progress_data['host']
        ip = host['ip']
        ports = host['ports']
        open_ports = [p for p in ports if p['state'] == 'open']
        
        print(f"[{timestamp}] 🎯 Host discovered: {ip}")
        print(f"           Total progress: {progress_data['total_hosts']} hosts, {progress_data['total_ports']} ports")
        
        if open_ports:
            print(f"           Open ports on {ip}:")
            for port in open_ports:
                service_info = f" ({port['service']})" if port['service'] != 'unknown' else ""
                banner_info = f" - {port['banner'][:50]}..." if port['banner'] else ""
                print(f"             🔓 {port['port']}/{port['protocol']}{service_info}{banner_info}")
        else:
            print(f"           No open ports found on {ip}")
        print()
    
    elif progress_data['type'] == 'scan_complete':
        print(f"[{timestamp}] ✅ Scan completed!")
        print(f"           Final results: {progress_data['total_hosts']} hosts, {progress_data['total_ports']} ports")
        print(f"           Return code: {progress_data['return_code']}")
        print()


def main():
    """Run the streaming port scan demonstration."""
    print("🚀 Streaming Port Scan Demonstration")
    print("=" * 50)
    print()
    
    # Example targets - you can modify these
    targets = [
        {"target": "8.8.8.8", "ports": "53,80,443", "description": "Google DNS"},
        {"target": "1.1.1.1", "ports": "53,80,443", "description": "Cloudflare DNS"},
    ]
    
    for i, target_info in enumerate(targets, 1):
        target = target_info["target"]
        ports = target_info["ports"]
        description = target_info["description"]
        
        print(f"📡 Test {i}: Scanning {description} ({target})")
        print(f"   Ports: {ports}")
        print(f"   Started at: {datetime.now().strftime('%H:%M:%S')}")
        print()
        
        start_time = time.time()
        
        # Run the streaming port scan
        result = port_scan_streaming(
            target=target,
            ports=ports,
            scan_type="tcp_syn",
            rate=1000,  # Faster rate for demo
            progress_callback=progress_callback
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"📊 Scan {i} Results:")
        print(f"   Success: {result['success']}")
        print(f"   Duration: {duration:.2f} seconds")
        print(f"   Scan ID: {result.get('scan_id', 'N/A')}")
        
        if result['success']:
            print(f"   Hosts found: {result.get('total_hosts', 0)}")
            print(f"   Open ports: {result.get('total_open_ports', 0)}")
            
            # Show detailed results
            hosts = result.get('hosts', [])
            for host in hosts:
                open_ports = [p for p in host['ports'] if p['state'] == 'open']
                if open_ports:
                    print(f"   📍 {host['ip']}:")
                    for port in open_ports:
                        service = port.get('service', 'unknown')
                        version = port.get('version', '')
                        banner = port.get('banner', '')
                        
                        service_str = f" ({service}" + (f" {version}" if version else "") + ")"
                        banner_str = f" - {banner[:30]}..." if banner else ""
                        
                        print(f"      🔓 {port['port']}/{port['protocol']}{service_str}{banner_str}")
        else:
            print(f"   Error: {result.get('error', 'Unknown error')}")
        
        print()
        print("-" * 50)
        print()
        
        # Small delay between scans
        if i < len(targets):
            print("⏳ Waiting 2 seconds before next scan...")
            time.sleep(2)
            print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
