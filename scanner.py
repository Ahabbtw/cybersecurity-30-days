#!/usr/bin/env python3
"""
Day 1: Multi-Threaded TCP Port Scanner
Cybersecurity 30-Day Sprint
"""
import socket
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Common ports mapping for human-readable output
WELL_KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy"
}

def scan_port(target_ip, port, timeout=1.0):
    """
    Attempts to establish a TCP connection to target_ip:port.
    Returns port and service name if open, otherwise None.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))

            if result == 0:
                service = WELL_KNOWN_PORTS.get(port, "Unknown Service")

                # Optional: Attempt a banner grab
                banner = ""
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    response = s.recv(1024).decode(errors="ignore").strip()
                    if response:
                        banner = f" | Banner: {response.splitlines()[0][:50]}"
                except Exception:
                    pass

                return port, service, banner
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="Fast Multi-Threaded TCP Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target hostname or IP address")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds (default: 1.0)")
    args = parser.parse_args()

    # Resolve target to IP
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{args.target}'")
        sys.exit(1)

    print("="*60)
    print(f"Target:       {args.target} ({target_ip})")
    print(f"Port Range:   {args.start} -> {args.end}")
    print(f"Concurrency:  {args.workers} threads | Timeout: {args.timeout}s")
    print(f"Started at:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    open_ports = []
    start_time = datetime.now()

    # ThreadPoolExecutor distributes ports across threads
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port, args.timeout)
            for port in range(args.start, args.end + 1)
        ]

        for future in futures:
            res = future.result()
            if res:
                port, service, banner = res
                print(f"[+] Port {port:<5} OPEN  ({service}){banner}")
                open_ports.append(port)

    elapsed = datetime.now() - start_time
    print("="*60)
    print(f"Scan completed in {elapsed.total_seconds():.2f} seconds.")
    print(f"Total open ports found: {len(open_ports)}")
    print("="*60)

if __name__ == "__main__":
    main()
