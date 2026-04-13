#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Concurrent network scanner with ICMP/ARP liveness, reverse DNS, and port scanning."""

import ipaddress
import concurrent.futures
import time
import signal
import socket
from typing import List, Dict, Optional, Callable, Any

from network_utils import ping, arp_ping

__all__ = ["scan_network", "reverse_dns", "scan_ports"]


def reverse_dns(ip: str) -> Optional[str]:
    """Return the hostname for a given IP address, or None if lookup fails."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


def scan_ports(ip: str, ports: List[int], timeout: float = 1.0) -> List[int]:
    """
    Perform a TCP connect scan on a list of ports.

    Args:
        ip: Target IPv4 address.
        ports: List of port numbers to scan.
        timeout: Connection timeout per port in seconds.

    Returns:
        Sorted list of open ports.
    """
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return sorted(open_ports)


class NetworkScanner:
    """Handles the concurrent scanning of a network."""

    def __init__(
        self,
        network_cidr: str,
        timeout: float = 1.0,
        max_workers: int = 100,
        quiet: bool = False,
        use_arp: bool = False,
        resolve_hostname: bool = False,
        scan_ports_list: Optional[List[int]] = None,
    ):
        self.network_cidr = network_cidr
        self.timeout = timeout
        self.max_workers = max_workers
        self.quiet = quiet
        self.use_arp = use_arp
        self.resolve_hostname = resolve_hostname
        self.scan_ports_list = scan_ports_list
        self._interrupted = False

        # Register signal handler
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig: int, frame: Any) -> None:
        """Handle Ctrl+C gracefully."""
        self._interrupted = True
        print("\n[!] Scan interrupted by user. Partial results will be shown.")

    def _alive_checker(self) -> Callable[[str, float], bool]:
        """Return the appropriate liveness detection function."""
        return arp_ping if self.use_arp else ping

    def scan(self) -> List[Dict]:
        """Run the scan and return a list of host info dictionaries."""
        try:
            network = ipaddress.ip_network(self.network_cidr, strict=False)
        except ValueError:
            print(f"Invalid network address: {self.network_cidr}")
            return []

        hosts = list(network.hosts())
        total = len(hosts)
        if not self.quiet:
            method = "ARP" if self.use_arp else "ICMP"
            print(
                f"Scanning network: {network} using {method}, total {total} hosts "
                f"(timeout={self.timeout}s, workers={self.max_workers})"
            )

        active_hosts = []
        scanned = 0
        start_time = time.time()
        workers = min(self.max_workers, total)
        alive_check = self._alive_checker()

        def check_host(ip: ipaddress.IPv4Address) -> Optional[Dict]:
            nonlocal scanned
            if self._interrupted:
                return None

            ip_str = str(ip)
            if not alive_check(ip_str, self.timeout):
                return None

            info: Dict = {"ip": ip_str}
            if self.resolve_hostname:
                hostname = reverse_dns(ip_str)
                if hostname:
                    info["hostname"] = hostname
            if self.scan_ports_list:
                open_ports = scan_ports(ip_str, self.scan_ports_list, self.timeout)
                if open_ports:
                    info["open_ports"] = open_ports

            if not self.quiet:
                extra = f" ({info.get('hostname', '')})" if self.resolve_hostname and info.get("hostname") else ""
                print(f"[+] Active: {ip_str}{extra}")
            return info

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_ip = {executor.submit(check_host, ip): ip for ip in hosts}
            for future in concurrent.futures.as_completed(future_to_ip):
                if self._interrupted:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                scanned += 1
                if not self.quiet and scanned % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = scanned / elapsed if elapsed > 0 else 0
                    print(f"[*] Progress: {scanned}/{total} hosts scanned ({rate:.1f} hosts/sec)")

                result = future.result()
                if result:
                    active_hosts.append(result)

        elapsed = time.time() - start_time
        if not self.quiet:
            print(f"\n[*] Scan finished in {elapsed:.2f} seconds. Found {len(active_hosts)} active hosts.")
        return active_hosts


# Backward-compatible function wrapper
def scan_network(
    network_cidr: str,
    timeout: float = 1.0,
    max_workers: int = 100,
    quiet: bool = False,
    use_arp: bool = False,
    resolve_hostname: bool = False,
    scan_ports_list: Optional[List[int]] = None,
) -> List[Dict]:
    """Convenience function that uses the NetworkScanner class."""
    scanner = NetworkScanner(
        network_cidr=network_cidr,
        timeout=timeout,
        max_workers=max_workers,
        quiet=quiet,
        use_arp=use_arp,
        resolve_hostname=resolve_hostname,
        scan_ports_list=scan_ports_list,
    )
    return scanner.scan()
