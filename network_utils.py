#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import ipaddress
import platform
import socket
from typing import Optional

def get_local_ip() -> str:
    """Get the local intranet IP address used by this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        return ip
    except Exception:
        return '127.0.0.1'

def get_network_cidr() -> Optional[str]:
    """
    Determine the local network CIDR.
    Prefers using netifaces if available, otherwise falls back to /24 based on local IP.
    """
    local_ip = get_local_ip()
    if local_ip == '127.0.0.1':
        return None

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
        pass

    # Fallback to /24
    ip_parts = local_ip.split('.')
    fallback_cidr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    print(f"[!] netifaces not installed, assuming /24 network: {fallback_cidr}")
    print("[!] Install netifaces for automatic netmask detection: pip install netifaces")
    return fallback_cidr

def ping(ip: str, timeout: float = 1) -> bool:
    """ICMP ping. Returns True if host responds."""
    system = platform.system().lower()
    if system == 'windows':
        cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
    else:
        cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout + 1)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False

def arp_ping(ip: str, timeout: float = 1) -> bool:
    """
    ARP ping using scapy.
    Requires root privileges and scapy installed.
    Returns True if ARP reply received.
    """
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=timeout, verbose=False)
        return len(ans) > 0
    except ImportError:
        print("[-] scapy not installed. Please install: pip install scapy")
        return False
    except PermissionError:
        print("[-] ARP scanning requires root/admin privileges.")
        return False