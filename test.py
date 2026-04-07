#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import ipaddress
import platform
import concurrent.futures
import sys
import socket
import argparse
import signal
import time

# Global flag for graceful interrupt
interrupted = False


def signal_handler(sig, frame):
    global interrupted
    interrupted = True
    print("\n[!] Scan interrupted by user. Partial results will be shown.")


def get_local_ip():
    """Get the local intranet IP address used by this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        return ip
    except Exception:
        return '127.0.0.1'


def get_network_cidr():
    """
    Determine the local network CIDR.
    Prefers using netifaces if available, otherwise falls back to /24 based on local IP.
    """
    local_ip = get_local_ip()
    if local_ip == '127.0.0.1':
        return None

    # Try to use netifaces for accurate netmask (optional dependency)
    try:
        import netifaces
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if addr['addr'] == local_ip and 'netmask' in addr:
                        netmask = addr['netmask']
                        # Convert netmask to CIDR prefix length
                        prefix = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                        network = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
                        return str(network)
    except ImportError:
        pass  # netifaces not installed, fallback to /24

    # Fallback: assume /24 (Class C)
    ip_parts = local_ip.split('.')
    fallback_cidr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    print(f"[!] netifaces not installed, assuming /24 network: {fallback_cidr}")
    print("[!] Install netifaces for automatic netmask detection: pip install netifaces")
    return fallback_cidr


def ping(ip, timeout=1):
    """
    Ping the specified IP address.
    Returns True if the host responds, False otherwise.
    """
    system = platform.system().lower()
    if system == 'windows':
        cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
    else:  # Linux / macOS
        cmd = ['ping', '-c', '1', '-W', str(timeout), ip]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout + 1)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def scan_network(network_cidr, timeout=1, max_workers=100, quiet=False):
    """
    Scan all hosts in the given CIDR network.
    Returns a list of active IP addresses.
    """
    global interrupted
    signal.signal(signal.SIGINT, signal_handler)

    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        print(f"Invalid network address: {network_cidr}")
        sys.exit(1)

    hosts = list(network.hosts())
    total = len(hosts)
    if not quiet:
        print(f"Scanning network: {network}, total {total} hosts (timeout={timeout}s, workers={max_workers})")

    active_hosts = []
    scanned = 0
    start_time = time.time()

    # Limit workers to number of hosts
    workers = min(max_workers, total)

    def check_host(ip):
        nonlocal scanned
        ip_str = str(ip)
        if interrupted:
            return None
        alive = ping(ip_str, timeout)
        if alive and not quiet:
            print(f"[+] Active: {ip_str}")
        return ip_str if alive else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            if interrupted:
                executor.shutdown(wait=False, cancel_futures=True)
                break
            scanned += 1
            if not quiet and scanned % 50 == 0:
                elapsed = time.time() - start_time
                rate = scanned / elapsed if elapsed > 0 else 0
                print(f"[*] Progress: {scanned}/{total} hosts scanned ({rate:.1f} hosts/sec)")
            result = future.result()
            if result:
                active_hosts.append(result)

    elapsed = time.time() - start_time
    if not quiet:
        print(f"\n[*] Scan finished in {elapsed:.2f} seconds. Found {len(active_hosts)} active hosts.")
    return active_hosts


def main():
    parser = argparse.ArgumentParser(
        description="Detect active IP addresses on a local network",
        epilog="Examples:\n"
               "  python lan_scanner.py\n"
               "  python lan_scanner.py -n 192.168.1.0/24 -t 2 -w 200\n"
               "  python lan_scanner.py -o active_ips.txt -q"
    )
    parser.add_argument("-n", "--network", help="Network CIDR (e.g., 192.168.1.0/24); auto-detect if omitted")
    parser.add_argument("-t", "--timeout", type=int, default=1, help="Ping timeout in seconds (default: 1)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("-o", "--output", help="Save active IP list to a file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress real-time output, show only final results")
    args = parser.parse_args()

    if args.network:
        network_cidr = args.network
    else:
        network_cidr = get_network_cidr()
        if not network_cidr:
            print("Unable to auto-detect local IP. Please specify network manually with -n.")
            sys.exit(1)

    active_ips = scan_network(network_cidr, args.timeout, args.workers, args.quiet)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                for ip in active_ips:
                    f.write(ip + '\n')
            print(f"[+] Saved {len(active_ips)} IPs to {args.output}")
        except IOError as e:
            print(f"[-] Failed to write output file: {e}")

    if not args.quiet or len(active_ips) == 0:
        print("\n=== Active hosts ===")
        for ip in active_ips:
            print(ip)
        if len(active_ips) == 0:
            print("No active hosts found.")


if __name__ == "__main__":
    main()
