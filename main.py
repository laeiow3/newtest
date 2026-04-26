#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Main entry point for the LAN scanner."""

import sys
import argparse
import logging
from typing import Optional, List

from network_utils import get_network_cidr
from scanner import scan_network
from output import output_results

# Configure basic logging (level will be adjusted later)
logging.basicConfig(
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)


def parse_port_list(port_str: Optional[str]) -> Optional[List[int]]:
    """Parse a comma-separated string of ports into a list of integers."""
    if not port_str:
        return None
    try:
        ports = [int(p.strip()) for p in port_str.split(",") if p.strip()]
        if not ports:
            logger.error("No valid ports specified.")
            sys.exit(1)
        return ports
    except ValueError:
        logger.error("Invalid port list. Use comma-separated integers, e.g., 22,80,443")
        sys.exit(1)


def validate_positive_int(value: int, name: str) -> None:
    """Validate that an integer argument is positive."""
    if value <= 0:
        logger.error(f"{name} must be a positive integer (got {value})")
        sys.exit(1)


def create_parser() -> argparse.ArgumentParser:
    """Create and return the argument parser with improved help text."""
    parser = argparse.ArgumentParser(
        description="Detect active IP addresses on a local network with optional reverse DNS and port scanning",
        epilog="""
Examples:
  python main.py
  python main.py -n 192.168.1.0/24 -t 2 -w 200
  python main.py -o active_ips.txt -q
  python main.py --hostname --ports 22,80,443 --format json
  sudo python main.py --arp          # ARP scan requires root
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-n", "--network",
        help="Network CIDR (e.g., 192.168.1.0/24); auto-detect if omitted"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int, default=1,
        help="Ping/port timeout in seconds (default: 1)"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int, default=100,
        help="Number of concurrent threads (default: 100)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save output to a file (format depends on --format)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress real-time output, show only final results"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (debug level)"
    )
    parser.add_argument(
        "--hostname", "-H",
        action="store_true",
        help="Perform reverse DNS lookup for each active host"
    )
    parser.add_argument(
        "--ports", "-p",
        help="Comma-separated list of ports to scan on active hosts (e.g., 22,80,443)"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--arp",
        action="store_true",
        help="Use ARP scanning instead of ICMP ping (requires root and scapy)"
    )
    return parser


def setup_logging(verbose: bool, quiet: bool) -> None:
    """Configure logging level based on verbosity and quiet mode."""
    if quiet:
        # Quiet mode: suppress all logging messages (only final output)
        logging.getLogger().setLevel(logging.ERROR)
    elif verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")
    else:
        logging.getLogger().setLevel(logging.INFO)


def main() -> None:
    """Main function: parse arguments, validate, run scanner, output results."""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose, args.quiet)

    # Validate numeric arguments
    validate_positive_int(args.timeout, "Timeout")
    validate_positive_int(args.workers, "Workers")

    ports_to_scan = parse_port_list(args.ports)

    # Determine network CIDR
    network_cidr: Optional[str] = args.network
    if not network_cidr:
        logger.info("No network specified, auto-detecting...")
        network_cidr = get_network_cidr()
        if not network_cidr:
            logger.error("Unable to auto-detect local IP. Please specify network manually with -n.")
            sys.exit(1)
        logger.debug(f"Auto-detected network CIDR: {network_cidr}")

    # Run scan
    try:
        active_hosts = scan_network(
            network_cidr=network_cidr,
            timeout=args.timeout,
            max_workers=args.workers,
            quiet=args.quiet,
            use_arp=args.arp,
            resolve_hostname=args.hostname,
            scan_ports_list=ports_to_scan,
        )
    except KeyboardInterrupt:
        logger.info("\nScan cancelled by user.")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        logger.exception(f"Unexpected error during scan: {e}")
        sys.exit(1)

    # Output results
    try:
        if active_hosts or args.format != "text" or not args.quiet:
            output_results(active_hosts, args.format, args.output)
        elif not active_hosts and args.output and args.format == "text":
            # Create empty result file for text format with no hosts
            with open(args.output, "w") as f:
                f.write("No active hosts found.")
            logger.info(f"Empty result written to {args.output}")
        elif not active_hosts:
            print("No active hosts found.")
    except IOError as e:
        logger.error(f"Failed to write output: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
