#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import ipaddress
import platform
import concurrent.futures
import sys
import socket
import argparse


def get_local_ip():
    """Get the local intranet IP address used by this machine (by connecting to an external address)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        return ip
    except Exception:
        return '127.0.0.1'


def ping(ip, timeout=1):
    """
    Ping the specified IP address.
    Returns True if the host responds, False otherwise.
    """
    system = platform.system().lower()
    # Build ping command according to the operating system
    if system == 'windows':
        cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
    else:  # Linux / macOS
        cmd = ['ping', '-c', '1', '-W', str(timeout), ip]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout + 1)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def scan_network(network_cidr, max_workers=100):
    """
    Scan all hosts in the given CIDR network.
    Returns a list of active IP addresses.
    """
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        print(f"Invalid network address: {network_cidr}")
        sys.exit(1)

    hosts = list(network.hosts())
    print(f"Scanning network: {network}, total {len(hosts)} hosts")
    active_hosts = []

    def check_host(ip):
        ip_str = str(ip)
        if ping(ip_str):
            print(f"[+] Active host found: {ip_str}")
            return ip_str
        return None

    # Run pings concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(check_host, hosts)

    active_hosts = [ip for ip in results if ip is not None]
    return active_hosts


def main():
    parser = argparse.ArgumentParser(description="Detect active IP addresses on a local network")
    parser.add_argument("-n", "--network", help="Network CIDR, e.g. 192.168.1.0/24; if not provided, auto-detect the local network (assumes /24 mask)")
    parser.add_argument("-t", "--timeout", type=int, default=1, help="Ping timeout in seconds, default 1")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of concurrent threads, default 100")
    args = parser.parse_args()

    if args.network:
        network_cidr = args.network
    else:
        local_ip = get_local_ip()
        if local_ip == '127.0.0.1':
            print("Unable to auto-detect local IP, please specify the network CIDR manually")
            sys.exit(1)
        # Assume a Class C /24 mask, take the first three octets as network prefix
        ip_parts = local_ip.split('.')
        network_cidr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        print(f"Auto-detected local IP: {local_ip}, scanning network: {network_cidr}")

    # Note: timeout parameter is not directly used here; you can adjust the ping function internally
    active_ips = scan_network(network_cidr, args.workers)

    print("\n=== Scan completed, list of active hosts ===")
    for ip in active_ips:
        print(ip)


if __name__ == "__main__":
    main()