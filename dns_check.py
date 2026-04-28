"""
DNS check utility for `vt_reports/` JSONs

- Scans vt_reports/*.json for `relations.domains` and `relations.ips`.
- Builds a union of domains (stripping URL paths) and the set of reported IPs per domain.
- Resolves each domain (A/AAAA) in parallel and compares resolved IPs to reported IPs.
- Writes results to CSV: domain, exists, matched, reported_ips, resolved_ips, new_ips, missing_reported_ips, reports

Usage:
    python scripts/dns_check.py --reports-dir vt_reports --output dns_domain_check.csv

Requirements: Python 3.7+. Uses only stdlib (socket, concurrent.futures) to avoid extra dependencies.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Set, Tuple
from urllib.parse import urlsplit


def normalize_domain(entry: str) -> str:
    # strip URL path and scheme; handle entries like 'youtube.com/feeds'
    if not entry:
        return entry
    # If it's already an IP, return as-is
    if all(c.isdigit() or c == '.' for c in entry):
        return entry
    try:
        parsed = urlsplit(entry if '://' in entry else '//' + entry)
        host = parsed.hostname or entry.split('/')[0]
        return host.lower()
    except Exception:
        return entry.split('/')[0].lower()


def load_reports(reports_dir: Path) -> Dict[str, Dict]:
    """Return mapping domain -> data: {'reported_ips': set, 'reports': set()}"""
    domain_map: Dict[str, Dict[str, Set[str]]] = {}
    for path in reports_dir.glob('vt_combined_*.json'):
        try:
            with path.open('r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception as e:
            print(f"Warning: failed to parse {path}: {e}")
            continue
        relations = data.get('relations', {})
        domains = relations.get('domains', []) or []
        ips = relations.get('ips', []) or []
        ips_set = set(str(ip).strip() for ip in ips if ip)
        for raw_dom in domains:
            dom = normalize_domain(raw_dom)
            if not dom:
                continue
            if dom not in domain_map:
                domain_map[dom] = {'reported_ips': set(), 'reports': set()}
            domain_map[dom]['reported_ips'].update(ips_set)
            domain_map[dom]['reports'].add(path.name)
    return domain_map


def resolve_domain(domain: str, timeout: float = 5.0) -> Tuple[bool, Set[str]]:
    """Resolve domain to IPs using socket (A/AAAA). Return (exists, set_of_ips)."""
    try:
        # getaddrinfo can return duplicates; collect IPs
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        ips = {info[4][0] for info in infos if info and info[4]}
        return (len(ips) > 0, ips)
    except socket.gaierror:
        return (False, set())
    except Exception as e:
        # unexpected exception; treat as not resolvable
        print(f"Resolve error for {domain}: {e}")
        return (False, set())


def run_checks(domain_map: Dict[str, Dict], max_workers: int = 20) -> Dict[str, Dict]:
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(resolve_domain, dom): dom for dom in domain_map}
        for fut in as_completed(futures):
            dom = futures[fut]
            exists, resolved_ips = fut.result()
            reported_ips = domain_map[dom]['reported_ips']
            new_ips = resolved_ips - reported_ips
            missing_reported = reported_ips - resolved_ips
            matched = len(resolved_ips & reported_ips) > 0
            results[dom] = {
                'exists': exists,
                'resolved_ips': resolved_ips,
                'reported_ips': reported_ips,
                'matched': matched,
                'new_ips': new_ips,
                'missing_reported': missing_reported,
                'reports': sorted(domain_map[dom]['reports']),
            }
    return results


def write_csv(out_path: Path, results: Dict[str, Dict]):
    headers = [
        'domain',
        'exists',
        'matched',
        'reported_ips',
        'resolved_ips',
        'new_ips',
        'missing_reported_ips',
        'num_reports',
        'reports',
    ]
    with out_path.open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()
        for dom, info in sorted(results.items()):
            writer.writerow({
                'domain': dom,
                'exists': int(info['exists']),
                'matched': int(info['matched']),
                'reported_ips': ';'.join(sorted(info['reported_ips'])),
                'resolved_ips': ';'.join(sorted(info['resolved_ips'])),
                'new_ips': ';'.join(sorted(info['new_ips'])),
                'missing_reported_ips': ';'.join(sorted(info['missing_reported'])),
                'num_reports': len(info['reports']),
                'reports': ';'.join(info['reports']),
            })


def main():
    p = argparse.ArgumentParser(description='DNS check for vt_reports domains')
    p.add_argument('--reports-dir', default='vt_reports', help='Directory with vt_combined_*.json files')
    p.add_argument('--output', default='dns_domain_check.csv', help='CSV output file')
    p.add_argument('--max-workers', type=int, default=30)
    args = p.parse_args()

    reports_dir = Path(args.reports_dir)
    if not reports_dir.exists() or not reports_dir.is_dir():
        print(f"Error: reports directory not found: {reports_dir}")
        return

    print(f"Loading reports from {reports_dir} ...")
    domain_map = load_reports(reports_dir)
    print(f"Found {len(domain_map)} unique domains.")

    print(f"Resolving domains with up to {args.max_workers} workers ...")
    results = run_checks(domain_map, max_workers=args.max_workers)

    out_path = Path(args.output)
    write_csv(out_path, results)
    print(f"Results written to {out_path}.")


if __name__ == '__main__':
    main()
