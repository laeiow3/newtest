#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import concurrent.futures
import time
import signal
import socket
from typing import List, Dict, Optional, Callable

from network_utils import ping, arp_ping

# Global interrupt flag
_interrupted = False

def _signal_handler(sig, frame):
    global _interrupted
    _interrupted = True
    print("\n[!] Scan interrupted by user. Partial results will be shown.")

def reverse_dns(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup and return hostname or None."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None

def scan_ports(ip: str, ports: List[int], timeout: float = 1) -> List[int]:
    """
    TCP connect scan on specified ports.
    Returns list of open port numbers.
    """
    open_ports = []
    for port in ports:
        if _interrupted:
            break
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return open_ports

def scan_network(
    network_cidr: str,
    timeout: float = 1,
    max_workers: int = 100,
    quiet: bool = False,
    use_arp: bool = False,
    resolve_hostname: bool = False,
    scan_ports_list: Optional[List[int]] = None
) -> List[Dict]:
    """
    Scan network and return list of dicts with host info.
    Each dict contains:
        - 'ip': str
        - 'hostname': str (if resolve_hostname and found)
        - 'open_ports': List[int] (if scan_ports_list and any open)
    """
    global _interrupted
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        print(f"Invalid network address: {network_cidr}")
        return []

    hosts = list(network.hosts())
    total = len(hosts)
    if not quiet:
        method = "ARP" if use_arp else "ICMP"
        print(f"Scanning network: {network} using {method}, total {total} hosts (timeout={timeout}s, workers={max_workers})")

    active_hosts = []
    scanned = 0
    start_time = time.time()
    workers = min(max_workers, total)

    alive_check: Callable[[str, float], bool] = arp_ping if use_arp else ping

    def check_host(ip):
        nonlocal scanned
        ip_str = str(ip)
        if _interrupted:
            return None
        alive = alive_check(ip_str, timeout)
        if not alive:
            return None
        info = {'ip': ip_str}
        if resolve_hostname:
            hostname = reverse_dns(ip_str)
            if hostname:
                info['hostname'] = hostname
        if scan_ports_list:
            open_ports = scan_ports(ip_str, scan_ports_list, timeout)
            if open_ports:
                info['open_ports'] = open_ports
        if not quiet:
            host_info = f" ({info.get('hostname', '')})" if resolve_hostname and info.get('hostname') else ""
            print(f"[+] Active: {ip_str}{host_info}")
        return info

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            if _interrupted:
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