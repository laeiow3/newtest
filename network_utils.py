#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Network utilities: local IP detection, CIDR calculation, ICMP/ARP ping."""

import subprocess
import ipaddress
import platform
import socket
from typing import Optional

__all__ = [
    "get_local_ip",
    "get_network_cidr",
    "ping",
    "arp_ping",
]


def get_local_ip() -> str:
    """Return the local intranet IP address used to reach external hosts."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connection-less socket to determine route
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def get_network_cidr() -> Optional[str]:
    """
    Determine the local network CIDR.

    Tries to use netifaces for accurate netmask; falls back to /24 if netifaces
    is not installed or detection fails.
    """
    local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        return None

    # Attempt accurate netmask detection via netifaces (optional)
    try:
        import netifaces  # type: ignore

        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                continue
            for addr in addrs[netifaces.AF_INET]:
                if addr.get("addr") == local_ip and "netmask" in addr:
                    netmask = addr["netmask"]
                    prefix = sum(bin(int(octet)).count("1") for octet in netmask.split("."))
                    network = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
                    return str(network)
    except ImportError:
        pass  # netifaces not installed, use fallback

    # Fallback: assume /24 network
    parts = local_ip.split(".")
    fallback = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    print(f"[!] netifaces not installed, assuming /24 network: {fallback}")
    print("[!] Install netifaces for accurate netmask: pip install netifaces")
    return fallback


def ping(ip: str, timeout: float = 1.0) -> bool:
    """
    Send an ICMP echo request using the system ping command.

    Args:
        ip: Target IPv4 address.
        timeout: Timeout in seconds.

    Returns:
        True if the host replies, False otherwise.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 0.5,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def arp_ping(ip: str, timeout: float = 1.0) -> bool:
    """
    Send an ARP request using Scapy.

    Requires root privileges and the 'scapy' package.

    Args:
        ip: Target IPv4 address.
        timeout: Timeout in seconds.

    Returns:
        True if an ARP reply is received, False otherwise.
    """
    try:
        from scapy.all import ARP, Ether, srp, conf  # type: ignore

        conf.verb = 0
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout,
            verbose=False,
        )
        return len(ans) > 0
    except ImportError:
        print("[-] scapy not installed. Please install: pip install scapy")
        return False
    except PermissionError:
        print("[-] ARP scanning requires root/admin privileges.")
        return False
