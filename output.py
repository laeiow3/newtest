#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Output formatters for scan results: text, JSON, CSV."""

import csv
import json
import sys
from typing import List, Dict, Optional, TextIO

__all__ = ["output_results"]


def _format_text_line(info: Dict) -> str:
    """Format a single host info dict as a text line."""
    line = info["ip"]
    if "hostname" in info and info["hostname"]:
        line += f" ({info['hostname']})"
    if "open_ports" in info and info["open_ports"]:
        ports_str = ", ".join(map(str, info["open_ports"]))
        line += f" - open ports: {ports_str}"
    return line


def _output_text(hosts_info: List[Dict], output_file: Optional[str]) -> None:
    """Print or save results in plain text."""
    lines = [_format_text_line(info) for info in hosts_info] if hosts_info else ["No active hosts found."]
    content = "\n".join(lines)
    if output_file:
        with open(output_file, "w") as f:
            f.write(content)
    else:
        print("\n=== Active hosts ===")
        print(content)


def _output_json(hosts_info: List[Dict], output_file: Optional[str]) -> None:
    """Print or save results as JSON."""
    json_data = json.dumps(hosts_info, indent=2)
    if output_file:
        with open(output_file, "w") as f:
            f.write(json_data)
    else:
        print(json_data)


def _output_csv(hosts_info: List[Dict], output_file: Optional[str]) -> None:
    """Print or save results as CSV."""
    if not hosts_info:
        return

    # Collect all field names from all entries
    fieldnames = set()
    for info in hosts_info:
        fieldnames.update(info.keys())
    # Ensure 'ip' is the first column
    fieldnames = ["ip"] + [f for f in fieldnames if f != "ip"]

    def _write_csv(file_like: TextIO) -> None:
        writer = csv.DictWriter(file_like, fieldnames=fieldnames)
        writer.writeheader()
        for info in hosts_info:
            row = info.copy()
            if "open_ports" in row and isinstance(row["open_ports"], list):
                row["open_ports"] = ",".join(map(str, row["open_ports"]))
            writer.writerow(row)

    if output_file:
        with open(output_file, "w", newline="") as f:
            _write_csv(f)
    else:
        import io

        output = io.StringIO()
        _write_csv(output)
        print(output.getvalue())


def output_results(hosts_info: List[Dict], output_format: str, output_file: Optional[str] = None) -> None:
    """
    Print or save scan results in the specified format.

    Args:
        hosts_info: List of dictionaries with host information.
        output_format: One of 'text', 'json', 'csv'.
        output_file: Optional file path to save output. If None, prints to stdout.
    """
    format_lower = output_format.lower()
    if format_lower == "text":
        _output_text(hosts_info, output_file)
    elif format_lower == "json":
        _output_json(hosts_info, output_file)
    elif format_lower == "csv":
        _output_csv(hosts_info, output_file)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
