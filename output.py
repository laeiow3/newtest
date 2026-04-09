#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
import sys
from typing import List, Dict, Optional

def output_results(hosts_info: List[Dict], output_format: str, output_file: Optional[str] = None):
    """Print or save results in specified format (text, json, csv)."""
    if output_format == 'text':
        lines = []
        for info in hosts_info:
            line = info['ip']
            if 'hostname' in info and info['hostname']:
                line += f" ({info['hostname']})"
            if 'open_ports' in info and info['open_ports']:
                line += f" - open ports: {', '.join(map(str, info['open_ports']))}"
            lines.append(line)
        text = '\n'.join(lines) if lines else "No active hosts found."
        if output_file:
            with open(output_file, 'w') as f:
                f.write(text)
        else:
            print("\n=== Active hosts ===")
            print(text)
    elif output_format == 'json':
        json_data = json.dumps(hosts_info, indent=2)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_data)
        else:
            print(json_data)
    elif output_format == 'csv':
        if not hosts_info:
            return
        # Collect all possible field names
        fieldnames = set()
        for info in hosts_info:
            fieldnames.update(info.keys())
        # Ensure 'ip' is first column
        fieldnames = ['ip'] + [f for f in fieldnames if f != 'ip']
        if output_file:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for info in hosts_info:
                    row = info.copy()
                    if 'open_ports' in row and isinstance(row['open_ports'], list):
                        row['open_ports'] = ','.join(map(str, row['open_ports']))
                    writer.writerow(row)
        else:
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for info in hosts_info:
                row = info.copy()
                if 'open_ports' in row and isinstance(row['open_ports'], list):
                    row['open_ports'] = ','.join(map(str, row['open_ports']))
                writer.writerow(row)
            print(output.getvalue())