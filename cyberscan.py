#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberScan Tool - Advanced Port Scanner & Service Identifier
Purpose: Detect open ports, grab service banners, and highlight common security misconfigurations.
"""

import socket
import threading
import queue
import sys
import argparse
from datetime import datetime
import re

# --- Terminal color settings for a better user interface ---
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# --- Dictionary of well-known ports and their default services ---
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBIND", 135: "MSRPC",
    139: "NETBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB"
}

# --- Security warning mappings for sensitive services ---
VULNERABILITY_WARNINGS = {
    21: "⚠️  FTP is open. Check if Anonymous Access is disabled.",
    22: "⚠️  SSH is open. Enforce public-key authentication and disable weak passwords!",
    3306: "⚠️  MySQL is exposed. Verify that root@'%' is not set with a blank password.",
    6379: "🔥 CRITICAL! Redis without authentication? Run 'CONFIG GET requirepass' immediately.",
    27017: "⚠️  MongoDB is exposed. Ensure authentication (--auth) is enabled.",
    1433: "⚠️  MSSQL is open. Check the status of the 'sa' account.",
}

# --- Main Scanner Class ---
class CyberScanner:
    def __init__(self, target_host, ports, thread_count=100, timeout=2.0):
        self.target_host = target_host
        self.ports = ports
        self.thread_count = thread_count
        self.timeout = timeout
        self.open_ports = []
        self.queue = queue.Queue()
        self.lock = threading.Lock()

    def get_banner(self, host, port):
        """Connect to the service and grab a banner (up to 256 bytes)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Smart probe: if HTTP/HTTPS, send a HEAD request
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                # For other services, send a newline to trigger the banner
                sock.send(b"\n")
            
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip().replace('\n', ' ').replace('\r', '')
            sock.close()
            return banner if banner else "No banner (likely requires a specific protocol)"
        except:
            return "Banner retrieval failed"

    def scan_port(self, port):
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_host, port))
            
            if result == 0:
                service_name = COMMON_SERVICES.get(port, "Unknown")
                # Retrieve the banner
                banner = self.get_banner(self.target_host, port)
                # Check for security warnings
                warning = VULNERABILITY_WARNINGS.get(port, "")
                
                with self.lock:
                    self.open_ports.append((port, service_name, banner, warning))
                    # Real-time display
                    print(f"{Colors.GREEN}[+] Port {port}{Colors.RESET} is open | "
                          f"{Colors.CYAN}Service: {service_name}{Colors.RESET}")
                    if warning:
                        print(f"    {Colors.RED}{warning}{Colors.RESET}")
                    if banner and "No banner" not in banner and "failed" not in banner:
                        print(f"    {Colors.BLUE}📄 Banner: {banner[:100]}{Colors.RESET}")
            sock.close()
        except Exception as e:
            # Silently ignore network errors
            pass

    def worker(self):
        """Thread worker function."""
        while not self.queue.empty():
            port = self.queue.get()
            self.scan_port(port)
            self.queue.task_done()

    def run(self):
        """Execute the main multi-threaded scan."""
        print(f"\n{Colors.BOLD}🚀 Starting scan on {self.target_host}{Colors.RESET}")
        print(f"⏳ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🔍 Total ports to scan: {len(self.ports)}")
        print(f"🧵 Thread count: {self.thread_count}\n")
        print("-" * 70)

        # Fill the queue
        for port in self.ports:
            self.queue.put(port)

        # Create and start threads
        threads = []
        for _ in range(min(self.thread_count, len(self.ports))):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # Wait for completion
        self.queue.join()
        for t in threads:
            t.join()

        # Display the final report
        self.print_report()

    def print_report(self):
        """Generate the final scan report."""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}✅ Final Scan Report{Colors.RESET}")
        print("=" * 70)
        
        if not self.open_ports:
            print(f"{Colors.YELLOW}No open ports found or the host is unreachable.{Colors.RESET}")
            return

        print(f"{Colors.BOLD}Total open ports found: {len(self.open_ports)}{Colors.RESET}\n")
        
        # Simple results table
        print(f"{'Port':<8} {'Service':<12} {'Security Status'}")
        print("-" * 70)
        for port, service, banner, warning in self.open_ports:
            status = "✅ Safe" if not warning else "⚠️  Needs Review"
            print(f"{port:<8} {service:<12} {status}")
            if warning:
                print(f"   └─ {Colors.RED}{warning}{Colors.RESET}")
        print("=" * 70)


# --- Command-line argument parser ---
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="CyberScan Tool - Professional Port Scanner with Service Detection and Security Alerts",
        epilog="Example: python cyberscan.py -t 192.168.1.1 -p 20-1000 -th 200"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address or domain (e.g., 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="1-1024", 
                        help="Port range (e.g., 20-1000 or 80,443,3306). Default: 1-1024")
    parser.add_argument("-th", "--threads", type=int, default=100, 
                        help="Number of concurrent threads (Default: 100)")
    parser.add_argument("-to", "--timeout", type=float, default=2.0, 
                        help="Timeout per port in seconds (Default: 2)")
    
    return parser.parse_args()

def parse_port_string(port_str):
    """Convert the port input string into a sorted list of integers."""
    ports = set()
    try:
        if ',' in port_str:
            parts = port_str.split(',')
            for p in parts:
                if '-' in p:
                    start, end = map(int, p.split('-'))
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(p))
        elif '-' in port_str:
            start, end = map(int, port_str.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(port_str))
    except ValueError:
        print(f"{Colors.RED}❌ Invalid port format! Use formats like 20-1000 or 80,443.{Colors.RESET}")
        sys.exit(1)
    return sorted(ports)


# --- Program Entry Point ---
if __name__ == "__main__":
    args = parse_arguments()
    
    target = args.target.strip()
    port_list = parse_port_string(args.ports)
    thread_count = args.threads
    timeout = args.timeout
    
    # Validate hostname/IP
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{Colors.RED}❌ Error: Host '{target}' could not be resolved. Please check the IP or domain.{Colors.RESET}")
        sys.exit(1)
    
    print(f"""
{Colors.CYAN}┌──────────────────────────────────────────────────────────────┐
│  {Colors.BOLD}🔒 CyberScan v1.0 - Professional Port Scanner{Colors.RESET}{Colors.CYAN}         │
│  📡 Target: {target:<45} │
│  🧵 Threads: {thread_count:<44} │
│  📋 Total Ports: {len(port_list):<42} │
└──────────────────────────────────────────────────────────────┘{Colors.RESET}
""")
    
    # Run the scanner
    scanner = CyberScanner(target, port_list, thread_count, timeout)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⏹️  Scan interrupted by the user.{Colors.RESET}")
        sys.exit(0)
